"""A scripted sign-in against the mock identity provider, shared by the web adapter tests."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import NotRequired, TypedDict, Unpack
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx2

from auth_ai import AiClient, AuthClient, GrantManager, MemoryGrantStore
from auth_ai.messages import WebRequest, WebResponse
from auth_ai.server.backchannel_logout import LOGOUT_EVENT, LOGOUT_TOKEN_TYP
from auth_ai.web.handlers import AuthHandlers
from auth_ai.web.sessions import MemorySessionStore, Session, SessionStore
from tests.support.mock_idp import (
    CLIENT_ID,
    GATEWAY_URL,
    ISSUER,
    MockIdp,
    RecordedRequest,
    create_test_auth,
    json_response,
    now_seconds,
)

ORIGIN = "https://app.test"
SECRET = "0123456789abcdef0123456789abcdef"
SESSION_COOKIE = "__Host-aai_session"
LOGIN_COOKIE = "__Host-aai_login"
LOGOUT_COOKIE = "__Host-aai_logout"
FORM = {"content-type": "application/x-www-form-urlencoded"}


class HandlerOptions(TypedDict):
    sessions: SessionStore
    secret: str
    base_path: NotRequired[str]
    default_redirect: NotRequired[str]
    session_ttl_seconds: NotRequired[int]
    claims_renew_seconds: NotRequired[int]
    require_provider_session: NotRequired[bool]
    error_redirect: NotRequired[str | None]
    on_sessions_ended: NotRequired[Callable[[Sequence[Session]], Awaitable[None] | None] | None]
    on_error: NotRequired[Callable[[BaseException], None] | None]


class OptionOverrides(TypedDict, total=False):
    sessions: SessionStore
    secret: str
    base_path: str
    default_redirect: str
    session_ttl_seconds: int
    claims_renew_seconds: int
    require_provider_session: bool
    error_redirect: str | None
    on_sessions_ended: Callable[[Sequence[Session]], Awaitable[None] | None] | None
    on_error: Callable[[BaseException], None] | None


@dataclass(frozen=True)
class Parts:
    auth: AuthClient
    grants: GrantManager
    handlers: AuthHandlers


def get(path: str, headers: Mapping[str, str] | None = None) -> WebRequest:
    return WebRequest.create("GET", f"{ORIGIN}{path}", headers=headers)


def post(path: str, headers: Mapping[str, str] | None = None, body: bytes = b"") -> WebRequest:
    return WebRequest.create("POST", f"{ORIGIN}{path}", headers=headers, body=body)


def cookies_of(response: WebResponse) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for line in response.header_values("set-cookie"):
        name, _, value = line.split(";", 1)[0].partition("=")
        cookies[name] = value
    return cookies


def cookie_header(*pairs: tuple[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in pairs)


def with_session(cookie: str, path: str = "/auth/me") -> WebRequest:
    return get(path, {"cookie": cookie_header((SESSION_COOKIE, cookie))})


def post_logout_token(token: str) -> WebRequest:
    return post("/auth/backchannel-logout", FORM, urlencode({"logout_token": token}).encode())


class BffHarness:
    """Handlers on a memory session store, and a provider that signs a user in as `user-1`.

    `errors` and `ended` record what the handlers report to `on_error` and
    `on_sessions_ended`. Close it with `aclose()` once the test is over.
    """

    def __init__(self, idp: MockIdp) -> None:
        self.idp = idp
        self.sessions = MemorySessionStore()
        self.errors: list[BaseException] = []
        self.ended: list[Sequence[Session]] = []
        self.refreshes = 0
        self.roles = ["editor"]
        self.nonce = ""
        self._clients: list[AuthClient] = []
        idp.token_handler = self._token
        parts = self.create()
        self.auth, self.grants, self.handlers = parts.auth, parts.grants, parts.handlers

    def _token(self, request: RecordedRequest) -> httpx2.Response:
        base = {"token_type": "Bearer", "expires_in": 3600, "scope": "openid roles"}
        if request.form.get("grant_type") == "refresh_token":
            self.refreshes += 1
            return json_response(
                {
                    **base,
                    "access_token": f"access-r{self.refreshes}",
                    "refresh_token": f"refresh-{self.refreshes}",
                    "id_token": self.idp.id_token(
                        sid="sid-1", roles=self.roles, features={"maxProjects": 10}
                    ),
                }
            )
        return json_response(
            {
                **base,
                "access_token": "access-0",
                "refresh_token": "refresh-0",
                "id_token": self.idp.id_token(
                    nonce=self.nonce,
                    sid="sid-1",
                    name="Ada",
                    email="ada@example.com",
                    email_verified=True,
                    roles=self.roles,
                    permissions=["docs.write"],
                    features={"maxProjects": 10},
                    plan="Premium",
                    org_id="org-1",
                ),
            }
        )

    def _on_sessions_ended(self, ended: Sequence[Session]) -> None:
        self.ended.append(ended)

    def create(
        self,
        *,
        redirect_uri: str = f"{ORIGIN}/auth/callback",
        post_logout_redirect_uri: str | None = None,
        gateway: bool = False,
        **overrides: Unpack[OptionOverrides],
    ) -> Parts:
        """Handlers of their own, on the shared session store and provider."""
        auth_config: dict[str, str] = {
            "redirect_uri": redirect_uri,
            "post_logout_redirect_uri": post_logout_redirect_uri or f"{ORIGIN}/",
        }
        if gateway:
            auth_config["gateway_url"] = GATEWAY_URL
        auth = create_test_auth(self.idp, **auth_config)
        self._clients.append(auth)
        grants = GrantManager(auth=auth, store=MemoryGrantStore())
        options: HandlerOptions = {
            "sessions": self.sessions,
            "secret": SECRET,
            "on_error": self.errors.append,
            "on_sessions_ended": self._on_sessions_ended,
            **overrides,
        }
        ai = AiClient(auth=auth, grants=grants) if gateway else None
        return Parts(auth, grants, AuthHandlers(auth=auth, grants=grants, ai=ai, **options))

    def build(
        self,
        *,
        post_logout_redirect_uri: str | None = None,
        **overrides: Unpack[OptionOverrides],
    ) -> AuthHandlers:
        """Replaces the harness' handlers."""
        parts = self.create(post_logout_redirect_uri=post_logout_redirect_uri, **overrides)
        self.auth, self.grants, self.handlers = parts.auth, parts.grants, parts.handlers
        return parts.handlers

    def build_with_ai(self) -> AuthHandlers:
        parts = self.create(gateway=True)
        self.auth, self.grants, self.handlers = parts.auth, parts.grants, parts.handlers
        return parts.handlers

    async def aclose(self) -> None:
        for client in self._clients:
            await client.http.aclose()

    async def handle(self, request: WebRequest) -> WebResponse:
        response = await self.handlers.handle(request)
        if response is None:
            raise AssertionError("the request was not handled")
        return response

    async def start_login(self, query: str = "") -> WebResponse:
        return await self.handle(get(f"/auth/login{query}"))

    def callback_request(self, login: WebResponse, *, state: str | None = None) -> WebRequest:
        """The provider's redirect back, answering `login`, from the browser that started it."""
        location = login.header("location")
        assert location is not None
        authorize = parse_qs(urlsplit(location).query)
        self.nonce = authorize["nonce"][0]
        return get(
            f"/auth/callback?code=abc&state={state or authorize['state'][0]}"
            f"&iss={quote(ISSUER, safe='')}",
            {"cookie": cookie_header((LOGIN_COOKIE, cookies_of(login)[LOGIN_COOKIE]))},
        )

    async def sign_in(self, next_path: str = "/dashboard") -> str:
        """Runs login then callback and returns the session cookie value."""
        login = await self.start_login(f"?next={quote(next_path, safe='')}")
        callback = await self.handle(self.callback_request(login))
        assert callback.status == 303
        return cookies_of(callback)[SESSION_COOKIE]

    def logout_token(self, **overrides: object) -> str:
        iat = now_seconds()
        return self.idp.sign_jwt(
            {
                "iss": ISSUER,
                "aud": CLIENT_ID,
                "sub": "user-1",
                "sid": "sid-1",
                "iat": iat,
                "exp": iat + 120,
                "jti": str(uuid.uuid4()),
                "events": {LOGOUT_EVENT: {}},
                **overrides,
            },
            typ=LOGOUT_TOKEN_TYP,
        )
