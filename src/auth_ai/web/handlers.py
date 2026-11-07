from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, TypeGuard, get_args
from urllib.parse import parse_qs, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from ..errors import ERR, AuthAiError
from ..messages import WebRequest, WebResponse, json_response, redirect_response
from ..server.backchannel_logout import (
    BackchannelLogoutEvent,
    BackchannelLogoutHandler,
    MemoryReplayStore,
)
from ..session_user import to_session_user
from ..types import LoginHandshake, Prompt
from .ai_routes import create_ai_routes
from .cookies import clear_cookie, cookie_name, parse_cookies, serialize_cookie
from .http import error_response, is_cross_site, safe_redirect_path
from .seal import derive_seal_key, seal, unseal
from .sessions import Session

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from ..ai import AiClient
    from ..claims import IdTokenClaims
    from ..client import AuthClient
    from ..grants import GrantManager
    from ..server.backchannel_logout import ReplayStore
    from .ai_routes import RouteHandler
    from .sessions import SessionStore

HANDSHAKE_TTL_SECONDS: Final = 600
DEFAULT_SESSION_TTL_SECONDS: Final = 8 * 3600
DEFAULT_CLAIMS_RENEW_SECONDS: Final = 900
_PROMPTS: Final = frozenset(get_args(Prompt.__value__))
_BASE_PATH_CHARS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-"
)


class _LogoutCookie(BaseModel):
    """Sealed at sign-out: the state sent to the OP and the page to return to."""

    model_config = ConfigDict(populate_by_name=True)

    state: str
    next: str


class _HandshakeCookie(BaseModel):
    """What the sealed login cookie carries: the wire names are shared with the TypeScript SDK."""

    model_config = ConfigDict(populate_by_name=True)

    state: str
    nonce: str
    code_verifier: str = Field(alias="codeVerifier")
    next: str


_HANDSHAKE_SCHEMA: Final = TypeAdapter(_HandshakeCookie)
_LOGOUT_SCHEMA: Final = TypeAdapter(_LogoutCookie)


def _is_prompt(value: str | None) -> TypeGuard[Prompt]:
    return value in _PROMPTS


def _sha256_base64url(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _query(request: WebRequest) -> dict[str, str]:
    return {name: values[0] for name, values in parse_qs(urlsplit(request.url).query).items()}


@dataclass(frozen=True, slots=True)
class _Route:
    method: Literal["GET", "POST"]
    run: RouteHandler


class AuthHandlers:
    """Backend-for-frontend sign-in: the browser holds an opaque session cookie, never a token.

    Mount `handle` on every request below `base_path`. `redirect_uri` of the client
    must be `<origin><base_path>/callback`.

    - `secret`: at least 32 random characters, seals the sign-in cookie. Keep it out
      of source control.
    - `default_redirect`: where users land after sign-in or sign-out without a target.
    - `session_ttl_seconds`: absolute lifetime of a session.
    - `claims_renew_seconds`: how often claims (roles, features…) are renewed.
    - `require_provider_session`: refuse an ID token without `sid`: no back-channel
      logout could ever reach it.
    - `error_redirect`: redirect target of a failed sign-in, with `?error=<code>`;
      JSON when unset.
    - `ai`: adds `/wallet`, `/wallet/stats` and `/models` for the frontend, read with
      the user's tokens.
    - `on_sessions_ended`: called after sessions end (sign-out or back-channel
      logout): close sockets, drop caches.
    - `on_error`: receives unexpected failures and the ones the response must not detail.
    """

    def __init__(
        self,
        *,
        auth: AuthClient,
        grants: GrantManager,
        sessions: SessionStore,
        secret: str,
        base_path: str = "/auth",
        default_redirect: str = "/",
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        claims_renew_seconds: int = DEFAULT_CLAIMS_RENEW_SECONDS,
        require_provider_session: bool = True,
        error_redirect: str | None = None,
        ai: AiClient | None = None,
        replay_store: ReplayStore | None = None,
        on_sessions_ended: Callable[[Sequence[Session]], Awaitable[None] | None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        if (
            not base_path.startswith("/")
            or base_path.endswith("/")
            or not set(base_path) <= _BASE_PATH_CHARS
        ):
            raise ERR.CFG_001("base_path must look like /auth, with no trailing slash")
        redirect = urlsplit(auth.config.redirect_uri)
        if redirect.path != f"{base_path}/callback":
            raise ERR.CFG_001(f"redirect_uri must end with {base_path}/callback")

        self._auth = auth
        self._grants = grants
        self._sessions = sessions
        self._default_redirect = default_redirect
        self._session_ttl = session_ttl_seconds
        self._renew_seconds = claims_renew_seconds
        self._require_provider_session = require_provider_session
        self._error_redirect = error_redirect
        self._on_sessions_ended = on_sessions_ended
        self.on_error = on_error
        #: Origin the SDK builds URLs on: that of `redirect_uri`, never a request header.
        self.origin = f"{redirect.scheme}://{redirect.netloc}"
        self.base_path = base_path
        self._secure = redirect.scheme == "https"
        self._key = derive_seal_key(secret)
        self._session_cookie = cookie_name("aai_session", self._secure)
        self._login_cookie = cookie_name("aai_login", self._secure)
        self._logout_cookie = cookie_name("aai_logout", self._secure)
        # Two simultaneous requests of one session share a single renewal.
        self._renewing: dict[str, asyncio.Task[Session | None]] = {}

        backchannel = BackchannelLogoutHandler(
            auth=auth,
            replay_store=replay_store or MemoryReplayStore(),
            on_error=on_error,
            on_logout=self._on_backchannel_logout,
        )
        self._routes: dict[str, _Route] = {
            "/login": _Route("GET", self._login),
            "/callback": _Route("GET", self._callback),
            "/me": _Route("GET", self._me),
            "/logout": _Route("POST", self._logout),
            "/logout/callback": _Route("GET", self._logout_callback),
            "/backchannel-logout": _Route("POST", backchannel),
        }
        if ai is not None:
            for path, run in create_ai_routes(ai, self.require_session).items():
                self._routes[path] = _Route("GET", run)

    async def handle(self, request: WebRequest) -> WebResponse | None:
        """Serves the routes below `base_path`; None for any other path."""
        path = urlsplit(request.url).path
        if not path.startswith(f"{self.base_path}/"):
            return None
        route = self._routes.get(path.removeprefix(self.base_path))
        if route is None:
            return None
        if request.method != route.method:
            return WebResponse(405, (("allow", route.method), ("cache-control", "no-store")))
        try:
            return await route.run(request)
        except Exception as err:  # noqa: BLE001
            return error_response(err, self.on_error)

    async def get_session(self, request: WebRequest) -> Session | None:
        """The session of a request, with claims renewed when due; None when signed out."""
        session = await self._read_session(request)
        if session is None or time.time() < session.renew_at:
            return session
        task = self._renewing.get(session.id)
        if task is None:
            task = asyncio.create_task(self._renew_claims(session))
            self._renewing[session.id] = task
            task.add_done_callback(lambda done: self._renewed(session.id, done))
        return await asyncio.shield(task)

    async def require_session(self, request: WebRequest) -> Session:
        """Like `get_session`, raising SES_001 when signed out."""
        session = await self.get_session(request)
        if session is None:
            raise ERR.SES_001()
        return session

    # ── Sessions ──

    async def _read_session(self, request: WebRequest) -> Session | None:
        cookie = parse_cookies(request.header("cookie")).get(self._session_cookie)
        if not cookie:
            return None
        return await self._sessions.get(_sha256_base64url(cookie))

    def _renewed(self, session_id: str, done: asyncio.Task[Session | None]) -> None:
        self._renewing.pop(session_id, None)
        if not done.cancelled():
            # Marks the failure as retrieved when every waiter has already left.
            done.exception()

    async def _renew_claims(self, session: Session) -> Session | None:
        try:
            tokens = await self._grants.refresh_tokens(session.user_id)
        except AuthAiError as err:
            if err.code == "TOK_002":
                await self._end_sessions([session])
                return None
            raise
        if not tokens.id_token:
            raise ERR.TOK_001("The provider returned no ID token on refresh")
        claims = await self._auth.verify_id_token(tokens.id_token)
        if claims.sub != session.user_id:
            await self._end_sessions([session])
            raise ERR.TOK_001("The refreshed ID token belongs to another user")
        claims = await self._auth.apply_userinfo(claims, tokens.access_token)
        renewed = Session(
            id=session.id,
            user_id=session.user_id,
            session_id=session.session_id,
            claims=claims,
            id_token=tokens.id_token,
            created_at=session.created_at,
            expires_at=session.expires_at,
            renew_at=min(int(time.time()) + self._renew_seconds, session.expires_at),
        )
        await self._sessions.update(renewed)
        return renewed

    async def _end_sessions(self, ended: Sequence[Session]) -> None:
        """Ends sessions, and revokes the grant of every user left with none."""
        for session in ended:
            await self._sessions.delete(session.id)
        await self._after_sessions_removed(ended)

    async def _after_sessions_removed(self, ended: Sequence[Session]) -> None:
        for user_id in dict.fromkeys(session.user_id for session in ended):
            if await self._sessions.count_by_user(user_id) > 0:
                continue
            try:
                await self._grants.revoke(user_id)
            except Exception as err:  # noqa: BLE001
                # The grant is already gone locally: the provider will expire it.
                self._report(err)
        if ended and self._on_sessions_ended is not None:
            result = self._on_sessions_ended(ended)
            if result is not None:
                await result

    async def _on_backchannel_logout(self, event: BackchannelLogoutEvent) -> None:
        await self._after_sessions_removed(
            await self._sessions.delete_by_provider_session(event.sid)
        )

    def _report(self, err: BaseException) -> None:
        if self.on_error is not None:
            self.on_error(err)

    def _with_cookies(self, *cookies: str) -> list[tuple[str, str]]:
        return [("set-cookie", cookie) for cookie in cookies]

    # ── Routes ──

    async def _login(self, request: WebRequest) -> WebResponse:
        query = _query(request)
        prompt = query.get("prompt")
        login = await self._auth.start_login(prompt=prompt if _is_prompt(prompt) else None)
        handshake = login.handshake
        sealed = seal(
            self._key,
            {
                "state": handshake.state,
                "nonce": handshake.nonce,
                "codeVerifier": handshake.code_verifier,
                "next": safe_redirect_path(query.get("next"), self._default_redirect),
            },
            HANDSHAKE_TTL_SECONDS,
        )
        return redirect_response(
            login.url,
            302,
            self._with_cookies(
                serialize_cookie(
                    self._login_cookie,
                    sealed,
                    max_age_seconds=HANDSHAKE_TTL_SECONDS,
                    secure=self._secure,
                )
            ),
        )

    async def _create_session(
        self, claims: IdTokenClaims, id_token: str, *, has_refresh_token: bool
    ) -> tuple[Session, str]:
        now = int(time.time())
        expires_at = (
            now + self._session_ttl
            if has_refresh_token
            else min(now + self._session_ttl, int(claims.exp))
        )
        cookie = secrets.token_urlsafe(32)
        session = Session(
            id=_sha256_base64url(cookie),
            user_id=claims.sub,
            session_id=claims.sid,
            claims=claims,
            id_token=id_token,
            created_at=now,
            expires_at=expires_at,
            renew_at=min(now + self._renew_seconds, expires_at)
            if has_refresh_token
            else expires_at,
        )
        await self._sessions.create(session)
        return session, cookie

    async def _callback(self, request: WebRequest) -> WebResponse:
        clear = clear_cookie(self._login_cookie, secure=self._secure)
        try:
            sealed = parse_cookies(request.header("cookie")).get(self._login_cookie)
            if not sealed:
                raise ERR.SES_002()  # noqa: TRY301
            cookie = unseal(self._key, sealed, _HANDSHAKE_SCHEMA)
            handshake = LoginHandshake(
                state=cookie.state,
                nonce=cookie.nonce,
                code_verifier=cookie.code_verifier,
            )

            # Rebuilt on the registered URI: the request's own host is not trusted.
            registered = urlsplit(self._auth.config.redirect_uri)
            callback_url = urlunsplit(
                registered._replace(query=urlsplit(request.url).query, fragment="")
            )
            result = await self._auth.handle_callback(callback_url, handshake)

            if self._require_provider_session and not result.session_id:
                raise ERR.SES_003(  # noqa: TRY301
                    "The ID token carries no sid: enable end session or a "
                    "back-channel logout URI on the application"
                )
            refresh_token = result.tokens.refresh_token
            if refresh_token:
                await self._grants.save(result.claims.sub, refresh_token)
            _, session_cookie = await self._create_session(
                result.claims,
                result.id_token,
                has_refresh_token=refresh_token is not None,
            )
            return redirect_response(
                cookie.next,
                303,
                self._with_cookies(
                    clear,
                    serialize_cookie(
                        self._session_cookie,
                        session_cookie,
                        max_age_seconds=self._session_ttl,
                        secure=self._secure,
                    ),
                ),
            )
        except Exception as err:  # noqa: BLE001
            # Whatever failed (state, code, client credentials, claims), the browser
            # learns one thing: the sign-in failed. Telling a rejected client secret
            # from a forged state would help whoever probes the callback; the cause
            # reaches the application's logs.
            self._report(err)
            failure = ERR.SES_005(cause=err)
            if self._error_redirect:
                return redirect_response(
                    f"{self._error_redirect}?error={failure.code}",
                    303,
                    self._with_cookies(clear),
                )
            return error_response(failure, None, self._with_cookies(clear))

    async def _me(self, request: WebRequest) -> WebResponse:
        session = await self.get_session(request)
        if session is None:
            return error_response(ERR.SES_001(), self.on_error)
        return json_response(
            {
                "user": to_session_user(session.claims).to_json(),
                "expiresAt": session.expires_at,
            }
        )

    async def _logout(self, request: WebRequest) -> WebResponse:
        if is_cross_site(request, self.origin):
            return error_response(ERR.SES_004(), self.on_error)
        session = await self._read_session(request)
        query = _query(request)
        state = secrets.token_urlsafe(32)
        next_path = safe_redirect_path(query.get("next"), self._default_redirect)
        logout_cookie = serialize_cookie(
            self._logout_cookie,
            seal(
                self._key,
                {"state": state, "next": next_path},
                HANDSHAKE_TTL_SECONDS,
            ),
            max_age_seconds=HANDSHAKE_TTL_SECONDS,
            secure=self._secure,
        )
        logout_url: str | None = None
        try:
            # The SSO session is shared by every application: end it even without a local session.
            logout_url = await self._auth.logout_url(
                id_token_hint=session.id_token if session is not None else None,
                state=state,
            )
        except Exception as err:  # noqa: BLE001
            # A provider without end-session still lets the local session end.
            self._report(err)
        if session is not None:
            await self._end_sessions([session])

        headers = self._with_cookies(
            clear_cookie(self._session_cookie, secure=self._secure),
            logout_cookie,
        )
        if "application/json" in (request.header("accept") or ""):
            return json_response({"logoutUrl": logout_url}, 200, headers)
        return redirect_response(logout_url or self._default_redirect, 303, headers)

    async def _logout_callback(self, request: WebRequest) -> WebResponse:
        """Handles the OP's post-logout redirect.

        The signed local session is already gone; the sealed cookie only carries
        the destination and the state hint. A missing or different state must not
        strand the user after the provider has ended the session, so the redirect
        still succeeds.
        """
        target = self._default_redirect
        sealed = parse_cookies(request.header("cookie")).get(self._logout_cookie)
        if sealed:
            try:
                cookie = unseal(self._key, sealed, _LOGOUT_SCHEMA)
                target = safe_redirect_path(cookie.next, self._default_redirect)
            except Exception:  # noqa: BLE001, S110
                pass
        return redirect_response(
            target,
            303,
            self._with_cookies(clear_cookie(self._logout_cookie, secure=self._secure)),
        )
