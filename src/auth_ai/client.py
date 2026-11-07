from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from pydantic import ValidationError

from .claims import IdTokenClaims, UserInfoClaims
from .config import AuthClientConfig
from .errors import ERR
from .id_token import check_id_token_binding
from .introspection import IntrospectionResult
from .provider import Provider, ProviderLoader
from .token_endpoint import ProviderEndpoints
from .transport import build_http_client
from .types import (
    LoginHandshake,
    LoginRequest,
    LoginResult,
    Prompt,
    TokenSet,
    TokenTypeHint,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import TracebackType

    import httpx2

_PKCE_VERIFIER_BYTES = 48
_RANDOM_BYTES = 32


def _s256_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class AuthClient:
    """OIDC relying party for auth-service.

    Authorization-code grant with PKCE, refresh with RFC 8707 resource narrowing,
    logout, revocation and introspection. It keeps no session: callers persist the
    handshake, the tokens and the claims where it suits them.

    `http_client` replaces the default `httpx2.AsyncClient`, e.g. to add a proxy, a
    transport or an observability layer. A client given by the caller is never
    closed by the SDK; otherwise call `aclose()` (or use `async with`).
    """

    def __init__(
        self,
        config: AuthClientConfig | Mapping[str, Any],
        *,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        self.config = (
            config
            if isinstance(config, AuthClientConfig)
            else AuthClientConfig.model_validate(config)
        )
        self._owns_http = http_client is None
        #: The client used for every request, shared with the REST API clients built on this one.
        self.http = http_client or build_http_client(timeout_seconds=self.config.timeout_seconds)
        self._provider = ProviderLoader(self.config, self.http)
        self._endpoints = ProviderEndpoints(self.config, self.http)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self.http.aclose()

    async def start_login(
        self, *, prompt: Prompt | None = None, login_hint: str | None = None
    ) -> LoginRequest:
        provider = await self._provider.get()
        handshake = LoginHandshake(
            state=secrets.token_urlsafe(_RANDOM_BYTES),
            nonce=secrets.token_urlsafe(_RANDOM_BYTES),
            code_verifier=secrets.token_urlsafe(_PKCE_VERIFIER_BYTES),
        )
        parameters: list[tuple[str, str]] = [
            ("response_type", "code"),
            ("client_id", self.config.client_id),
            ("redirect_uri", self.config.redirect_uri),
            ("scope", " ".join(self.config.scopes)),
            ("state", handshake.state),
            ("nonce", handshake.nonce),
            ("code_challenge", _s256_challenge(handshake.code_verifier)),
            ("code_challenge_method", "S256"),
        ]
        if prompt:
            parameters.append(("prompt", prompt))
        if login_hint:
            parameters.append(("login_hint", login_hint))
        parameters.extend(("resource", resource) for resource in self.config.resources)
        url = _with_query(provider.metadata.authorization_endpoint, parameters)
        return LoginRequest(url=url, handshake=handshake)

    async def handle_callback(self, callback_url: str, handshake: LoginHandshake) -> LoginResult:
        """Completes the sign-in from the callback URL.

        `resource` is deliberately not sent on the code exchange: the token is then
        issued for every audience requested at sign-in and each refresh narrows it
        to one.
        """
        provider = await self._provider.get()
        code = _authorization_code(callback_url, handshake, provider)
        tokens = await self._endpoints.token_request(
            provider.metadata.token_endpoint,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.redirect_uri,
                "code_verifier": handshake.code_verifier,
            },
        )
        if tokens.id_token is None:
            raise ERR.OIDC_002("The token response carries no ID token")
        claims = await self._verify_id_token(provider, tokens.id_token, nonce=handshake.nonce)
        claims = await self._apply_userinfo(provider, claims, tokens.access_token)
        return LoginResult(tokens=tokens, claims=claims, session_id=claims.sid)

    async def verify_id_token(self, id_token: str) -> IdTokenClaims:
        return await self._verify_id_token(await self._provider.get(), id_token)

    async def fetch_userinfo(self, access_token: str) -> UserInfoClaims:
        """Reads UserInfo with the access token, for the current provider session."""
        provider = await self._provider.get()
        endpoint = provider.metadata.userinfo_endpoint
        if not endpoint:
            raise ERR.OIDC_004("The provider advertises no userinfo_endpoint")
        body = await self._endpoints.userinfo_request(endpoint, access_token)
        try:
            return UserInfoClaims.model_validate(body)
        except ValidationError as err:
            raise ERR.TOK_001("The UserInfo response has an unexpected shape", cause=err) from err

    async def apply_userinfo(self, claims: IdTokenClaims, access_token: str) -> IdTokenClaims:
        """Fills claims the ID token omits from UserInfo, without replacing values.

        The provider may keep email out of the ID token when it issues an access
        token; UserInfo is then the authoritative source for the profile and
        email claims. Registered and entitlement claims already present in the ID
        token are never overwritten.
        """
        return await self._apply_userinfo(await self._provider.get(), claims, access_token)

    async def refresh(self, refresh_token: str, *, resource: str | None = None) -> TokenSet:
        """Exchanges a refresh token for fresh tokens.

        The provider rotates the refresh token on every use: the returned one
        replaces the presented one, and a replayed stale token revokes the whole
        family. Concurrent callers should go through a grant manager. `scope` is
        never sent: the rotated token would be left with the scopes of that
        request only.
        """
        provider = await self._provider.get()
        form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if resource:
            form["resource"] = resource
        return await self._endpoints.token_request(provider.metadata.token_endpoint, form)

    async def logout_url(
        self, *, id_token_hint: str | None = None, state: str | None = None
    ) -> str:
        """URL ending the provider session (RP-initiated logout)."""
        endpoint = (await self._provider.get()).metadata.end_session_endpoint
        if not endpoint:
            raise ERR.OIDC_004("The provider advertises no end_session_endpoint")
        parameters: list[tuple[str, str]] = [("client_id", self.config.client_id)]
        if self.config.post_logout_redirect_uri:
            parameters.append(("post_logout_redirect_uri", self.config.post_logout_redirect_uri))
        if id_token_hint:
            parameters.append(("id_token_hint", id_token_hint))
        if state:
            parameters.append(("state", state))
        return _with_query(endpoint, parameters)

    async def revoke(self, token: str, hint: TokenTypeHint | None = None) -> None:
        endpoint = (await self._provider.get()).metadata.revocation_endpoint
        if not endpoint:
            raise ERR.OIDC_004("The provider advertises no revocation_endpoint")
        response = await self._endpoints.post(endpoint, _token_form(token, hint))
        if not response.is_success:
            raise ERR.OIDC_003(
                f"Revocation endpoint answered HTTP {response.status_code}",
                details={"status": response.status_code},
            )

    async def introspect(
        self, token: str, hint: TokenTypeHint | None = None
    ) -> IntrospectionResult:
        endpoint = (await self._provider.get()).metadata.introspection_endpoint
        if not endpoint:
            raise ERR.OIDC_004("The provider advertises no introspection_endpoint")
        response = await self._endpoints.post(endpoint, _token_form(token, hint))
        if not response.is_success:
            raise ERR.OIDC_003(
                f"Introspection endpoint answered HTTP {response.status_code}",
                details={"status": response.status_code},
            )
        try:
            return IntrospectionResult.model_validate(response.json())
        except (ValueError, ValidationError) as err:
            raise ERR.OIDC_003(
                "The introspection response has an unexpected shape", cause=err
            ) from err

    async def verify_jwt(
        self, token: str, *, audience: str, typ: str | None = None
    ) -> dict[str, Any]:
        """Verifies the signature, issuer, audience and expiry of a JWT signed by the provider.

        Low-level: prefer the bearer and logout token verifiers. Returns the claims.
        """
        provider = await self._provider.get()
        return (await provider.jwt.verify(token, audience=audience, typ=typ)).claims

    async def client_credentials(
        self, *, scope: str | None = None, resource: str | None = None
    ) -> TokenSet:
        """`client_credentials` grant for the application itself.

        No user is bound to the token. Needs a confidential client.
        """
        if self.config.client_secret is None:
            raise ERR.CFG_001("client_credentials requires a client_secret")
        provider = await self._provider.get()
        form = {"grant_type": "client_credentials"}
        if scope:
            form["scope"] = scope
        if resource:
            form["resource"] = resource
        return await self._endpoints.token_request(provider.metadata.token_endpoint, form)

    async def _apply_userinfo(
        self, provider: Provider, claims: IdTokenClaims, access_token: str
    ) -> IdTokenClaims:
        endpoint = provider.metadata.userinfo_endpoint
        if not endpoint:
            return claims
        body = await self._endpoints.userinfo_request(endpoint, access_token)
        try:
            userinfo = UserInfoClaims.model_validate(body)
        except ValidationError as err:
            raise ERR.TOK_001("The UserInfo response has an unexpected shape", cause=err) from err
        if userinfo.sub != claims.sub:
            raise ERR.TOK_001("The UserInfo response belongs to another user")
        updates = {
            name: value
            for name, value in userinfo.model_dump(exclude_none=True).items()
            if name != "sub" and getattr(claims, name, None) is None
        }
        return claims.model_copy(update=updates) if updates else claims

    async def _verify_id_token(
        self, provider: Provider, id_token: str, *, nonce: str | None = None
    ) -> IdTokenClaims:
        verified = await provider.jwt.verify(id_token, audience=self.config.client_id)
        check_id_token_binding(verified.claims, client_id=self.config.client_id, nonce=nonce)
        try:
            return IdTokenClaims.model_validate(verified.claims)
        except ValidationError as err:
            raise ERR.TOK_001("The ID token claims have an unexpected shape", cause=err) from err


def _with_query(url: str, parameters: Sequence[tuple[str, str]]) -> str:
    """`url` with `parameters` appended to its own query, repeated names kept."""
    parts = urlsplit(url)
    query = "&".join(part for part in (parts.query, urlencode(parameters)) if part)
    return urlunsplit(parts._replace(query=query))


def _token_form(token: str, hint: TokenTypeHint | None) -> dict[str, str]:
    return {"token": token, "token_type_hint": hint} if hint else {"token": token}


def _authorization_code(callback_url: str, handshake: LoginHandshake, provider: Provider) -> str:
    """Checks the authorization response (RFC 6749 §4.1.2, RFC 9207) and returns its code."""
    query = parse_qs(urlsplit(callback_url).query, keep_blank_values=True)
    if any(len(values) != 1 for values in query.values()):
        raise ERR.OIDC_002(details={"reason": "repeated_parameter"})
    params = {name: values[0] for name, values in query.items()}

    error = params.get("error")
    if error is not None:
        raise ERR.OIDC_002(f"Authorization failed: {error}", details={"oauthError": error})

    issuer = params.get("iss")
    if issuer is None and provider.metadata.authorization_response_iss_parameter_supported:
        raise ERR.OIDC_002(details={"reason": "missing_iss"})
    if issuer is not None and issuer != provider.metadata.issuer:
        raise ERR.OIDC_002(details={"reason": "iss_mismatch"})

    state = params.get("state")
    if state is None or not hmac.compare_digest(state.encode(), handshake.state.encode()):
        raise ERR.OIDC_002(details={"reason": "state_mismatch"})
    code = params.get("code")
    if not code:
        raise ERR.OIDC_002(details={"reason": "missing_code"})
    return code
