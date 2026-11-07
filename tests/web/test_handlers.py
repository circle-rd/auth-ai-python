import asyncio
import json
import re
import time
from collections.abc import AsyncIterator, Callable, Sequence
from urllib.parse import parse_qs, quote, urlsplit

import httpx2
import pytest
from joserfc import jwe

from auth_ai import AuthAiError
from auth_ai.messages import WebRequest
from auth_ai.web.seal import derive_seal_key
from auth_ai.web.sessions import MemorySessionStore, Session
from tests.support.bff import (
    FORM,
    LOGIN_COOKIE,
    LOGOUT_COOKIE,
    ORIGIN,
    SECRET,
    SESSION_COOKIE,
    BffHarness,
    cookie_header,
    cookies_of,
    get,
    post,
    post_logout_token,
    with_session,
)
from tests.support.mock_idp import (
    ISSUER,
    MockIdp,
    RecordedRequest,
    json_response,
    now_seconds,
)

ACCOUNT = {
    "balance": "9007199254740993",
    "isUnlimited": False,
    "canSpend": True,
    "currency": "eur",
}
GENERIC_FAILURE = {"error": {"code": "SES_005", "message": "Sign-in failed"}}


@pytest.fixture
async def bff(idp: MockIdp) -> AsyncIterator[BffHarness]:
    harness = BffHarness(idp)
    yield harness
    await harness.aclose()


def reported_codes(bff: BffHarness) -> list[str]:
    return [err.code for err in bff.errors if isinstance(err, AuthAiError)]


def rejection(body: dict[str, str]) -> Callable[[RecordedRequest], httpx2.Response]:
    return lambda _request: json_response(body, 401)


def query_of(url: str | None) -> dict[str, list[str]]:
    assert url is not None
    return parse_qs(urlsplit(url).query)


class TestLogin:
    async def test_redirects_to_the_provider_with_a_sealed_hardened_handshake_cookie(
        self, bff: BffHarness
    ) -> None:
        response = await bff.start_login("?next=/a%3Fb%3D1&prompt=login")

        assert response.status == 302
        assert response.header("cache-control") == "no-store"
        location = urlsplit(response.header("location") or "")
        assert f"{location.scheme}://{location.netloc}{location.path}" == f"{ISSUER}/authorize"
        authorize = query_of(response.header("location"))
        assert authorize["prompt"] == ["login"]

        [set_cookie] = response.header_values("set-cookie")
        assert set_cookie.startswith(f"{LOGIN_COOKIE}=")
        for attribute in ("HttpOnly", "Secure", "SameSite=Lax", "Max-Age=600", "Path=/"):
            assert attribute in set_cookie
        # The PKCE material must not be readable from the cookie.
        assert authorize["state"][0] not in set_cookie
        assert authorize["nonce"][0] not in set_cookie

    async def test_seals_the_handshake_under_the_names_of_the_typescript_sdk(
        self, bff: BffHarness
    ) -> None:
        response = await bff.start_login("?next=/a%3Fb%3D1")
        sealed = cookies_of(response)[LOGIN_COOKIE]

        decrypted = jwe.decrypt_compact(
            sealed, derive_seal_key(SECRET), algorithms=["dir", "A256GCM"]
        )
        assert decrypted.plaintext is not None
        claims = json.loads(decrypted.plaintext)
        authorize = query_of(response.header("location"))
        assert claims["data"]["state"] == authorize["state"][0]
        assert claims["data"]["nonce"] == authorize["nonce"][0]
        assert claims["data"]["next"] == "/a?b=1"
        assert len(claims["data"]["codeVerifier"]) >= 43

    async def test_ignores_an_unknown_prompt(self, bff: BffHarness) -> None:
        response = await bff.start_login("?prompt=bogus")
        assert "prompt" not in query_of(response.header("location"))

    async def test_does_not_set_the_login_cookie_when_the_provider_is_unreachable(
        self, bff: BffHarness
    ) -> None:
        bff.idp.discovery_failures = 10
        response = await bff.start_login()
        assert response.status == 502
        assert response.header_values("set-cookie") == []
        assert response.json() == {
            "error": {"code": "OIDC_001", "message": "Identity provider discovery failed"}
        }


class TestCallback:
    async def test_creates_a_session_stores_the_grant_and_lands_on_the_requested_page(
        self, bff: BffHarness
    ) -> None:
        login = await bff.start_login("?next=/dashboard%3Ftab%3D2")
        callback = await bff.handle(bff.callback_request(login))

        assert callback.status == 303
        assert callback.header("location") == "/dashboard?tab=2"
        assert callback.header("cache-control") == "no-store"
        set_cookies = callback.header_values("set-cookie")
        assert any(c.startswith(f"{LOGIN_COOKIE}=;") and "Max-Age=0" in c for c in set_cookies)
        [session] = [c for c in set_cookies if c.startswith(f"{SESSION_COOKIE}=")]
        for attribute in ("HttpOnly", "Secure", "SameSite=Lax", "Max-Age=28800", "Path=/"):
            assert attribute in session

        assert await bff.grants.has("user-1")
        assert await bff.sessions.count_by_user("user-1") == 1
        # The token endpoint was reached on the registered URI, not on a request header.
        token_request = bff.idp.requests_to("/token")[0]
        assert token_request.form.get("redirect_uri") == f"{ORIGIN}/auth/callback"

    async def test_builds_the_callback_url_on_the_registered_origin(self, bff: BffHarness) -> None:
        login = await bff.start_login()
        request = bff.callback_request(login)
        hostile = WebRequest.create(
            "GET",
            request.url.replace(ORIGIN, "https://evil.test"),
            headers={**request.headers, "host": "evil.test"},
        )
        assert (await bff.handle(hostile)).status == 303
        assert all(r.url.host != "evil.test" for r in bff.idp.requests)

    async def test_stores_only_a_hash_of_the_session_cookie(self, bff: BffHarness) -> None:
        cookie = await bff.sign_in()
        [stored] = await bff.sessions.delete_by_provider_session("sid-1")
        assert stored.id != cookie
        assert len(stored.id) == 43

    async def test_falls_back_to_the_default_redirect_for_an_unsafe_target(
        self, bff: BffHarness
    ) -> None:
        bff.build(default_redirect="/home")
        login = await bff.start_login(f"?next={quote('//evil.test', safe='')}")
        callback = await bff.handle(bff.callback_request(login))
        assert callback.header("location") == "/home"

    async def test_refuses_a_callback_without_the_handshake_cookie(self, bff: BffHarness) -> None:
        response = await bff.handle(get("/auth/callback?code=abc&state=x"))

        assert response.status == 403
        assert response.json() == GENERIC_FAILURE
        assert reported_codes(bff) == ["SES_002"]
        assert bff.idp.requests_to("/token") == []

    async def test_refuses_a_tampered_handshake_cookie(self, bff: BffHarness) -> None:
        login = await bff.start_login()
        sealed = cookies_of(login)[LOGIN_COOKIE]
        tail = "BBB" if sealed.endswith("AAA") else "AAA"
        response = await bff.handle(
            get(
                "/auth/callback?code=abc&state=x",
                {"cookie": cookie_header((LOGIN_COOKIE, f"{sealed[:-3]}{tail}"))},
            )
        )
        assert response.status == 403
        assert reported_codes(bff) == ["SES_002"]

    async def test_refuses_a_callback_whose_state_is_not_the_one_of_this_browser(
        self, bff: BffHarness
    ) -> None:
        login = await bff.start_login()
        response = await bff.handle(bff.callback_request(login, state="forged"))

        assert response.status == 403
        assert bff.idp.requests_to("/token") == []
        assert reported_codes(bff) == ["OIDC_002"]
        assert await bff.sessions.count_by_user("user-1") == 0

    async def test_refuses_an_id_token_without_sid_by_default(self, bff: BffHarness) -> None:
        login = await bff.start_login()
        request = bff.callback_request(login)
        id_token = bff.idp.id_token(nonce=bff.nonce)
        bff.idp.token_handler = lambda _request: json_response(
            {
                "access_token": "a",
                "token_type": "Bearer",
                "expires_in": 60,
                "refresh_token": "r",
                "id_token": id_token,
            }
        )

        response = await bff.handle(request)

        assert response.status == 403
        assert response.json()["error"]["code"] == "SES_005"
        # The misconfiguration is for the application's logs, not for the browser.
        assert reported_codes(bff) == ["SES_003"]
        assert not await bff.grants.has("user-1")

    async def test_accepts_an_id_token_without_sid_when_not_required(self, bff: BffHarness) -> None:
        bff.build(require_provider_session=False)
        login = await bff.start_login()
        request = bff.callback_request(login)
        id_token = bff.idp.id_token(nonce=bff.nonce)
        bff.idp.token_handler = lambda _request: json_response(
            {"access_token": "a", "token_type": "Bearer", "expires_in": 60, "id_token": id_token}
        )
        assert (await bff.handle(request)).status == 303

    async def test_answers_the_same_403_whatever_failed_so_a_probe_learns_nothing(
        self, bff: BffHarness
    ) -> None:
        login = await bff.start_login()
        request = bff.callback_request(login)
        answers: list[tuple[int, bytes]] = []
        for rejected in (
            {"error": "invalid_client"},
            {"error": "invalid_grant", "error_description": "code expired"},
            {"error": "server_error"},
        ):
            bff.idp.token_handler = rejection(rejected)
            response = await bff.handle(request)
            answers.append((response.status, response.body))
        denied = await bff.handle(get("/auth/callback?error=access_denied"))

        expected = (403, json.dumps(GENERIC_FAILURE, separators=(",", ":")).encode())
        assert answers == [expected] * 3
        assert denied.status == 403
        assert denied.json() == GENERIC_FAILURE
        assert len(bff.errors) == 4

    async def test_clears_the_handshake_cookie_even_when_the_sign_in_fails(
        self, bff: BffHarness
    ) -> None:
        response = await bff.handle(get("/auth/callback?error=access_denied"))
        [cleared] = response.header_values("set-cookie")
        assert cleared.startswith(f"{LOGIN_COOKIE}=;")
        assert "Max-Age=0" in cleared

    async def test_redirects_to_the_error_page_when_one_is_configured(
        self, bff: BffHarness
    ) -> None:
        bff.build(error_redirect="/signin-error")
        response = await bff.handle(get("/auth/callback?error=access_denied"))
        assert response.status == 303
        assert response.header("location") == "/signin-error?error=SES_005"
        assert response.header("cache-control") == "no-store"
        assert len(response.header_values("set-cookie")) == 1

    async def test_limits_a_session_to_the_id_token_without_a_refresh_token(
        self, bff: BffHarness
    ) -> None:
        login = await bff.start_login()
        request = bff.callback_request(login)
        id_token = bff.idp.id_token(nonce=bff.nonce, sid="s")
        bff.idp.token_handler = lambda _request: json_response(
            {"access_token": "a", "token_type": "Bearer", "expires_in": 60, "id_token": id_token}
        )

        callback = await bff.handle(request)

        assert callback.status == 303
        assert not await bff.grants.has("user-1")
        assert "Max-Age=28800" in "; ".join(callback.header_values("set-cookie"))
        [stored] = await bff.sessions.delete_by_provider_session("s")
        assert stored.expires_at == stored.claims.exp
        assert stored.renew_at == stored.expires_at

    async def test_honours_the_configured_session_lifetime(self, bff: BffHarness) -> None:
        bff.build(session_ttl_seconds=120)
        login = await bff.start_login()
        callback = await bff.handle(bff.callback_request(login))
        assert "Max-Age=120" in callback.header_values("set-cookie")[1]
        [stored] = await bff.sessions.delete_by_provider_session("sid-1")
        assert stored.expires_at - stored.created_at == 120


class TestUserInfo:
    async def test_fills_the_email_from_userinfo_when_the_id_token_omits_it(
        self, bff: BffHarness
    ) -> None:
        login = await bff.start_login()
        request = bff.callback_request(login)
        bff.idp.token_handler = lambda _request: json_response(
            {
                "access_token": "access-0",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-0",
                "id_token": bff.idp.id_token(nonce=bff.nonce, sid="sid-1", name="Ada"),
            }
        )
        bff.idp.userinfo_handler = lambda _request: json_response(
            {
                "sub": "user-1",
                "email": "ada@example.com",
                "email_verified": True,
            }
        )

        callback = await bff.handle(request)

        assert callback.status == 303
        cookie = cookies_of(callback)[SESSION_COOKIE]
        body = (await bff.handle(with_session(cookie))).json()
        assert body["user"]["email"] == "ada@example.com"
        assert body["user"]["emailVerified"] is True
        [userinfo] = bff.idp.requests_to("/userinfo")
        assert userinfo.headers["authorization"] == "Bearer access-0"

    async def test_does_not_replace_id_token_claims_with_userinfo(self, bff: BffHarness) -> None:
        login = await bff.start_login()
        request = bff.callback_request(login)
        bff.idp.token_handler = lambda _request: json_response(
            {
                "access_token": "access-0",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": bff.idp.id_token(nonce=bff.nonce, sid="sid-1", name="From ID token"),
            }
        )
        bff.idp.userinfo_handler = lambda _request: json_response(
            {"sub": "user-1", "name": "From UserInfo"}
        )

        callback = await bff.handle(request)
        cookie = cookies_of(callback)[SESSION_COOKIE]
        body = (await bff.handle(with_session(cookie))).json()

        assert body["user"]["name"] == "From ID token"

    async def test_refuses_userinfo_for_another_subject(self, bff: BffHarness) -> None:
        login = await bff.start_login()
        request = bff.callback_request(login)
        bff.idp.token_handler = lambda _request: json_response(
            {
                "access_token": "access-0",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": bff.idp.id_token(nonce=bff.nonce, sid="sid-1"),
            }
        )
        bff.idp.userinfo_handler = lambda _request: json_response(
            {"sub": "someone-else", "email": "other@example.com"}
        )

        response = await bff.handle(request)

        assert response.status == 403
        assert response.json()["error"]["code"] == "SES_005"
        assert reported_codes(bff) == ["TOK_001"]
        assert await bff.sessions.count_by_user("user-1") == 0


class TestMe:
    async def test_returns_the_user_without_any_token_or_provider_session_id(
        self, bff: BffHarness
    ) -> None:
        cookie = await bff.sign_in()

        response = await bff.handle(with_session(cookie))

        assert response.status == 200
        assert response.header("cache-control") == "no-store"
        body = response.json()
        assert body["user"] == {
            "sub": "user-1",
            "name": "Ada",
            "email": "ada@example.com",
            "emailVerified": True,
            "roles": ["editor"],
            "permissions": ["docs.write"],
            "features": {"maxProjects": 10},
            "plan": "Premium",
            "orgId": "org-1",
        }
        assert not re.search(r"sid|access|refresh|idToken", response.body.decode())
        assert body["expiresAt"] > now_seconds()

    async def test_answers_401_without_a_session_and_with_a_forged_cookie(
        self, bff: BffHarness
    ) -> None:
        signed_out = await bff.handle(get("/auth/me"))
        assert signed_out.status == 401
        assert signed_out.json() == {"error": {"code": "SES_001", "message": "Not signed in"}}
        assert (await bff.handle(with_session("forged"))).status == 401

    async def test_answers_401_after_the_session_expired(
        self, bff: BffHarness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cookie = await bff.sign_in()
        real_time = time.time
        monkeypatch.setattr(time, "time", lambda: real_time() + 29_000)
        assert (await bff.handle(with_session(cookie))).status == 401

    async def test_does_not_renew_the_claims_before_they_are_due(self, bff: BffHarness) -> None:
        cookie = await bff.sign_in()
        bff.roles = ["editor", "admin"]
        body = (await bff.handle(with_session(cookie))).json()
        assert body["user"]["roles"] == ["editor"]
        assert bff.refreshes == 0

    async def test_renews_the_claims_from_the_provider_when_they_are_due(
        self, bff: BffHarness
    ) -> None:
        bff.build(claims_renew_seconds=0)
        cookie = await bff.sign_in()
        bff.roles = ["editor", "admin"]

        body = (await bff.handle(with_session(cookie))).json()

        assert body["user"]["roles"] == ["editor", "admin"]
        assert bff.refreshes == 1
        refresh: RecordedRequest = bff.idp.requests_to("/token")[-1]
        assert refresh.form.get("refresh_token") == "refresh-0"
        assert "resource" not in refresh.form

    async def test_stores_the_renewed_claims_and_schedules_the_next_renewal(
        self, bff: BffHarness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cookie = await bff.sign_in()
        real_time = time.time
        monkeypatch.setattr(time, "time", lambda: real_time() + 901)
        bff.roles = ["admin"]

        session = await bff.handlers.require_session(with_session(cookie))

        assert session.claims.roles == ["admin"]
        assert session.renew_at > real_time() + 901
        assert await bff.sessions.get(session.id) == session
        assert bff.refreshes == 1

    async def test_shares_one_renewal_between_simultaneous_requests(self, bff: BffHarness) -> None:
        bff.build(claims_renew_seconds=0)
        cookie = await bff.sign_in()

        sessions = await asyncio.gather(
            *(bff.handlers.get_session(with_session(cookie)) for _ in range(3))
        )

        assert bff.refreshes == 1
        assert all(
            session is not None and session.claims.roles == ["editor"] for session in sessions
        )

    async def test_renews_again_once_the_previous_renewal_is_done(self, bff: BffHarness) -> None:
        bff.build(claims_renew_seconds=0)
        cookie = await bff.sign_in()
        await bff.handlers.get_session(with_session(cookie))
        await bff.handlers.get_session(with_session(cookie))
        assert bff.refreshes == 2

    async def test_ends_the_session_when_the_provider_rejects_the_grant(
        self, bff: BffHarness
    ) -> None:
        bff.build(claims_renew_seconds=0)
        cookie = await bff.sign_in()
        bff.idp.token_handler = lambda _request: json_response({"error": "invalid_grant"}, 400)

        assert (await bff.handle(with_session(cookie))).status == 401

        assert await bff.sessions.count_by_user("user-1") == 0
        assert len(bff.ended) == 1

    async def test_fails_loudly_keeping_the_session_when_the_provider_is_unreachable(
        self, bff: BffHarness
    ) -> None:
        bff.build(claims_renew_seconds=0)
        cookie = await bff.sign_in()
        bff.idp.token_handler = lambda _request: json_response({"error": "server_error"}, 500)

        response = await bff.handle(with_session(cookie))

        assert response.status == 502
        assert response.json()["error"]["code"] == "OIDC_003"
        assert await bff.sessions.count_by_user("user-1") == 1

    async def test_refuses_a_refreshed_id_token_of_another_user(self, bff: BffHarness) -> None:
        bff.build(claims_renew_seconds=0)
        cookie = await bff.sign_in()
        bff.idp.token_handler = lambda _request: json_response(
            {
                "access_token": "a",
                "token_type": "Bearer",
                "expires_in": 60,
                "id_token": bff.idp.id_token(sub="someone-else", sid="sid-1"),
            }
        )

        assert (await bff.handle(with_session(cookie))).status == 401
        assert await bff.sessions.count_by_user("user-1") == 0

    async def test_refuses_a_refresh_that_returns_no_id_token(self, bff: BffHarness) -> None:
        bff.build(claims_renew_seconds=0)
        cookie = await bff.sign_in()
        bff.idp.token_handler = lambda _request: json_response(
            {"access_token": "a", "token_type": "Bearer", "expires_in": 60}
        )
        assert (await bff.handle(with_session(cookie))).status == 401


class TestSessionAccess:
    async def test_require_session_returns_the_session_or_raises_ses_001(
        self, bff: BffHarness
    ) -> None:
        cookie = await bff.sign_in()

        assert (await bff.handlers.require_session(with_session(cookie))).user_id == "user-1"
        with pytest.raises(AuthAiError) as raised:
            await bff.handlers.require_session(get("/x"))
        assert raised.value.code == "SES_001"

    async def test_get_session_is_none_when_signed_out(self, bff: BffHarness) -> None:
        assert await bff.handlers.get_session(get("/x")) is None
        assert await bff.handlers.get_session(with_session("forged", "/x")) is None


class TestLogout:
    @staticmethod
    def logout(cookie: str | None, **headers: str) -> WebRequest:
        request_headers = dict(headers)
        if cookie:
            request_headers["cookie"] = cookie_header((SESSION_COOKIE, cookie))
        return post("/auth/logout", request_headers)

    async def test_ends_the_session_revokes_the_grant_and_returns_the_provider_logout_url(
        self, bff: BffHarness
    ) -> None:
        cookie = await bff.sign_in()

        response = await bff.handle(self.logout(cookie, origin=ORIGIN, accept="application/json"))

        assert response.status == 200
        logout_url = response.json()["logoutUrl"]
        parts = urlsplit(logout_url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/end-session"
        assert query_of(logout_url)["id_token_hint"][0]
        assert query_of(logout_url)["post_logout_redirect_uri"] == [f"{ORIGIN}/"]
        assert "Max-Age=0" in response.header_values("set-cookie")[0]

        assert await bff.sessions.count_by_user("user-1") == 0
        assert not await bff.grants.has("user-1")
        assert bff.idp.requests_to("/revoke")[0].form.get("token") == "refresh-0"
        assert len(bff.ended) == 1
        assert [s.user_id for s in bff.ended[0]] == ["user-1"]

    async def test_redirects_a_plain_form_post_to_the_provider(self, bff: BffHarness) -> None:
        cookie = await bff.sign_in()
        response = await bff.handle(self.logout(cookie, origin=ORIGIN))
        assert response.status == 303
        assert (response.header("location") or "").startswith(f"{ISSUER}/end-session")
        assert "Max-Age=0" in response.header_values("set-cookie")[0]

    async def test_keeps_the_grant_while_the_user_has_another_session(
        self, bff: BffHarness
    ) -> None:
        first = await bff.sign_in()
        await bff.sign_in()

        await bff.handle(self.logout(first, origin=ORIGIN))

        assert await bff.sessions.count_by_user("user-1") == 1
        assert await bff.grants.has("user-1")
        assert bff.idp.requests_to("/revoke") == []

    @pytest.mark.parametrize(
        "headers",
        [{"origin": "https://evil.test"}, {"sec-fetch-site": "cross-site"}],
    )
    async def test_refuses_a_cross_site_request_and_leaves_the_session_alone(
        self, bff: BffHarness, headers: dict[str, str]
    ) -> None:
        cookie = await bff.sign_in()

        response = await bff.handle(self.logout(cookie, **headers))

        assert response.status == 403
        assert response.json()["error"]["code"] == "SES_004"
        assert response.header_values("set-cookie") == []
        assert await bff.sessions.count_by_user("user-1") == 1

    async def test_is_idempotent_without_a_session_and_still_ends_the_provider_session(
        self, bff: BffHarness
    ) -> None:
        response = await bff.handle(self.logout(None, origin=ORIGIN, accept="application/json"))

        assert response.status == 200
        logout_url = response.json()["logoutUrl"]
        parts = urlsplit(logout_url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/end-session"
        assert "id_token_hint" not in query_of(logout_url)
        assert query_of(logout_url)["post_logout_redirect_uri"] == [f"{ORIGIN}/"]
        assert bff.ended == []
        assert reported_codes(bff) == []

    async def test_redirects_to_the_provider_logout_without_a_session(
        self, bff: BffHarness
    ) -> None:
        response = await bff.handle(self.logout(None, origin=ORIGIN))

        assert response.status == 303
        assert (response.header("location") or "").startswith(f"{ISSUER}/end-session")

    async def test_falls_back_to_the_default_page_without_a_session_and_no_end_session(
        self, bff: BffHarness
    ) -> None:
        del bff.idp.metadata["end_session_endpoint"]
        bff.build(default_redirect="/bye")

        response = await bff.handle(self.logout(None, origin=ORIGIN))

        assert response.status == 303
        assert response.header("location") == "/bye"
        assert reported_codes(bff) == ["OIDC_004"]

    async def test_still_ends_the_local_session_when_the_provider_has_no_end_session_endpoint(
        self, bff: BffHarness
    ) -> None:
        cookie = await bff.sign_in()
        del bff.idp.metadata["end_session_endpoint"]
        bff.build()
        await bff.grants.save("user-1", "refresh-0")

        response = await bff.handle(self.logout(cookie, origin=ORIGIN, accept="application/json"))

        assert response.status == 200
        assert response.json() == {"logoutUrl": None}
        assert await bff.sessions.count_by_user("user-1") == 0
        assert reported_codes(bff) == ["OIDC_004"]

    async def test_reports_an_unreachable_provider_without_blocking_the_sign_out(
        self, bff: BffHarness
    ) -> None:
        cookie = await bff.sign_in()
        bff.idp.revocation_status = 500

        response = await bff.handle(self.logout(cookie, origin=ORIGIN, accept="application/json"))

        assert response.status == 200
        assert await bff.sessions.count_by_user("user-1") == 0
        assert not await bff.grants.has("user-1")
        assert reported_codes(bff) == ["OIDC_003"]

    async def test_awaits_an_asynchronous_sessions_ended_callback(self, bff: BffHarness) -> None:
        ended: list[str] = []

        async def on_ended(sessions: Sequence[Session]) -> None:
            await asyncio.sleep(0)
            ended.extend(s.user_id for s in sessions)

        bff.build(on_sessions_ended=on_ended)
        cookie = await bff.sign_in()
        await bff.handle(self.logout(cookie, origin=ORIGIN))
        assert ended == ["user-1"]


class TestLogoutCallback:
    async def test_sends_state_and_returns_through_the_logout_callback(
        self, bff: BffHarness
    ) -> None:
        bff.build(post_logout_redirect_uri=f"{ORIGIN}/auth/logout/callback")
        cookie = await bff.sign_in()
        response = await bff.handle(self.logout(cookie, origin=ORIGIN, accept="application/json"))
        assert response.status == 200
        logout_url = response.json()["logoutUrl"]
        state = query_of(logout_url)["state"][0]
        assert state
        assert query_of(logout_url)["post_logout_redirect_uri"] == [
            f"{ORIGIN}/auth/logout/callback"
        ]
        sealed = cookies_of(response)[LOGOUT_COOKIE]

        callback = await bff.handle(
            get(
                f"/auth/logout/callback?state={state}",
                {"cookie": cookie_header((LOGOUT_COOKIE, sealed))},
            )
        )

        assert callback.status == 303
        assert callback.header("location") == "/"
        assert "Max-Age=0" in callback.header_values("set-cookie")[0]

    @pytest.mark.parametrize("query", ["", "?state=other"])
    async def test_accepts_a_missing_or_different_state_after_logout(
        self, bff: BffHarness, query: str
    ) -> None:
        bff.build(post_logout_redirect_uri=f"{ORIGIN}/auth/logout/callback")
        cookie = await bff.sign_in()
        response = await bff.handle(self.logout(cookie, origin=ORIGIN, accept="application/json"))
        sealed = cookies_of(response)[LOGOUT_COOKIE]

        callback = await bff.handle(
            get(
                f"/auth/logout/callback{query}",
                {"cookie": cookie_header((LOGOUT_COOKIE, sealed))},
            )
        )

        assert callback.status == 303
        assert callback.header("location") == "/"

    async def test_redirects_to_the_default_page_without_a_logout_cookie(
        self, bff: BffHarness
    ) -> None:
        response = await bff.handle(get("/auth/logout/callback?state=missing"))
        assert response.status == 303
        assert response.header("location") == "/"

    def logout(self, cookie: str, **headers: str) -> WebRequest:
        return post(
            "/auth/logout",
            {**headers, "cookie": cookie_header((SESSION_COOKIE, cookie))},
        )


class TestBackchannelLogout:
    async def test_ends_the_sessions_of_the_provider_session_and_revokes_the_grant(
        self, bff: BffHarness
    ) -> None:
        cookie = await bff.sign_in()

        response = await bff.handle(post_logout_token(bff.logout_token()))

        assert response.status == 204
        assert await bff.sessions.count_by_user("user-1") == 0
        assert not await bff.grants.has("user-1")
        assert len(bff.ended) == 1
        assert (await bff.handle(with_session(cookie))).status == 401

    async def test_ends_every_session_of_the_provider_session(self, bff: BffHarness) -> None:
        await bff.sign_in()
        await bff.sign_in()

        await bff.handle(post_logout_token(bff.logout_token()))

        assert await bff.sessions.count_by_user("user-1") == 0
        assert [len(ended) for ended in bff.ended] == [2]

    async def test_is_idempotent_for_an_unknown_provider_session(self, bff: BffHarness) -> None:
        response = await bff.handle(post_logout_token(bff.logout_token(sid="unknown")))
        assert response.status == 204
        assert bff.ended == []

    async def test_refuses_a_replayed_token(self, bff: BffHarness) -> None:
        await bff.sign_in()
        token = bff.logout_token()
        assert (await bff.handle(post_logout_token(token))).status == 204
        assert (await bff.handle(post_logout_token(token))).status == 400

    async def test_refuses_a_token_for_another_client(self, bff: BffHarness) -> None:
        await bff.sign_in()
        response = await bff.handle(post_logout_token(bff.logout_token(aud="other")))
        assert response.status == 400
        assert response.json() == {"error": "invalid_request"}
        assert await bff.sessions.count_by_user("user-1") == 1
        assert reported_codes(bff) == ["TOK_001"]

    async def test_refuses_a_body_that_is_not_a_form(self, bff: BffHarness) -> None:
        response = await bff.handle(
            post("/auth/backchannel-logout", {"content-type": "application/json"}, b"{}")
        )
        assert response.status == 400

    async def test_refuses_a_form_without_a_logout_token(self, bff: BffHarness) -> None:
        response = await bff.handle(post("/auth/backchannel-logout", FORM, b"other=1"))
        assert response.status == 400


class TestRoutingAndConfiguration:
    async def test_leaves_other_paths_to_the_application(self, bff: BffHarness) -> None:
        for path in ("/", "/auth", "/auth/unknown", "/authx/login", "/other/auth/login"):
            assert await bff.handlers.handle(get(path)) is None

    async def test_answers_405_with_the_allowed_method(self, bff: BffHarness) -> None:
        wrong_get = await bff.handle(get("/auth/logout"))
        assert wrong_get.status == 405
        assert wrong_get.header("allow") == "POST"
        assert wrong_get.header("cache-control") == "no-store"
        assert (await bff.handle(post("/auth/login"))).status == 405
        assert (await bff.handle(post("/auth/me"))).header("allow") == "GET"

    async def test_supports_another_base_path_when_the_redirect_uri_follows_it(
        self, bff: BffHarness
    ) -> None:
        custom = bff.create(
            redirect_uri=f"{ORIGIN}/api/sso/callback", base_path="/api/sso"
        ).handlers

        assert custom.base_path == "/api/sso"
        login = await custom.handle(get("/api/sso/login"))
        assert login is not None
        assert login.status == 302
        assert await custom.handle(get("/auth/login")) is None

    async def test_uses_plain_cookies_for_a_local_http_redirect_uri(self, bff: BffHarness) -> None:
        local = bff.create(redirect_uri="http://localhost:3000/auth/callback").handlers

        assert local.origin == "http://localhost:3000"
        response = await local.handle(WebRequest.create("GET", "http://localhost:3000/auth/login"))
        assert response is not None
        [cookie] = response.header_values("set-cookie")
        assert cookie.startswith("aai_login=")
        assert "Secure" not in cookie

    @pytest.mark.parametrize(
        ("redirect_uri", "base_path", "secret"),
        [
            (f"{ORIGIN}/cb", "/auth", SECRET),
            (f"{ORIGIN}/auth/callback", "/auth/", SECRET),
            (f"{ORIGIN}/auth/callback", "auth", SECRET),
            (f"{ORIGIN}/auth/callback", "/au th", SECRET),
            (f"{ORIGIN}/auth/callback", "/auth", "short"),
        ],
        ids=[
            "redirect_uri not matching the callback route",
            "base path with a trailing slash",
            "base path without a leading slash",
            "base path with an unsafe character",
            "short secret",
        ],
    )
    async def test_rejects_an_invalid_configuration(
        self, bff: BffHarness, redirect_uri: str, base_path: str, secret: str
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            bff.create(redirect_uri=redirect_uri, base_path=base_path, secret=secret)
        assert raised.value.code == "CFG_001"

    async def test_reports_an_unexpected_failure_and_answers_generically(
        self, bff: BffHarness
    ) -> None:
        class FailingStore(MemorySessionStore):
            async def get(self, session_key: str) -> Session | None:
                raise RuntimeError("db down: hunter2")

        bff.build(sessions=FailingStore())

        response = await bff.handle(with_session("any"))

        assert response.status == 500
        assert response.json() == {"error": {"code": "SRV_001", "message": "Internal error"}}
        assert "hunter2" not in response.body.decode()
        assert len(bff.errors) == 1
        assert isinstance(bff.errors[0], RuntimeError)


class TestFrontendDataRoutes:
    @staticmethod
    def stats(request: RecordedRequest) -> httpx2.Response:
        return json_response(
            {
                "days": int(request.url.params.get("days", 30)),
                "total": "0",
                "notBilled": "0",
                "calls": 0,
                "series": [],
                "byApplication": [],
                "byKind": [],
                "byModel": [],
                "daily": [],
            }
        )

    async def test_serves_the_wallet_of_the_signed_in_user_with_the_top_up_link(
        self, bff: BffHarness
    ) -> None:
        bff.build_with_ai()
        cookie = await bff.sign_in()
        bff.idp.api_handler = lambda _request: json_response(ACCOUNT)

        response = await bff.handle(with_session(cookie, "/auth/wallet"))

        assert response.status == 200
        assert response.header("cache-control") == "no-store"
        assert response.json() == {**ACCOUNT, "topupUrl": f"{ISSUER}/profile"}
        call = bff.idp.requests[-1]
        assert call.url.path == "/api/user/wallet"
        assert call.headers["authorization"] == f"Bearer access-r{bff.refreshes}"

    async def test_serves_the_spend_statistics_and_validates_the_window(
        self, bff: BffHarness
    ) -> None:
        bff.build_with_ai()
        cookie = await bff.sign_in()
        bff.idp.api_handler = self.stats

        ok = await bff.handle(with_session(cookie, "/auth/wallet/stats?days=7"))
        assert ok.json()["days"] == 7
        default = await bff.handle(with_session(cookie, "/auth/wallet/stats"))
        assert default.json()["days"] == 30

        for days in ("0", "91", "x", "1.5"):
            invalid = await bff.handle(with_session(cookie, f"/auth/wallet/stats?days={days}"))
            assert invalid.status == 400
            assert invalid.json() == {"error": {"code": "REQ_001", "message": "Invalid request"}}

    async def test_lists_the_gateway_models(self, bff: BffHarness) -> None:
        bff.build_with_ai()
        cookie = await bff.sign_in()
        bff.idp.gateway_handler = lambda _request: json_response({"data": [{"id": "gpt-4o-mini"}]})

        response = await bff.handle(with_session(cookie, "/auth/models"))

        assert response.status == 200
        assert [model["id"] for model in response.json()["models"]] == ["gpt-4o-mini"]

    @pytest.mark.parametrize("path", ["/auth/wallet", "/auth/wallet/stats", "/auth/models"])
    async def test_requires_a_session(self, bff: BffHarness, path: str) -> None:
        bff.build_with_ai()
        response = await bff.handle(get(path))
        assert response.status == 401
        assert response.json()["error"]["code"] == "SES_001"

    @pytest.mark.parametrize("path", ["/auth/wallet", "/auth/wallet/stats", "/auth/models"])
    async def test_does_not_exist_unless_an_ai_client_was_provided(
        self, bff: BffHarness, path: str
    ) -> None:
        cookie = await bff.sign_in()
        assert await bff.handlers.handle(with_session(cookie, path)) is None

    async def test_reports_a_wallet_failure_with_its_public_envelope(self, bff: BffHarness) -> None:
        bff.build_with_ai()
        cookie = await bff.sign_in()
        bff.idp.api_handler = lambda _request: json_response(
            {"error": {"code": "APP_002", "message": "secret detail"}}, 404
        )

        response = await bff.handle(with_session(cookie, "/auth/wallet"))

        assert response.status == 502
        assert response.json() == {
            "error": {"code": "API_001", "message": "auth-service rejected the request"}
        }
        assert "secret detail" not in response.body.decode()
