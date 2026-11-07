from __future__ import annotations

import base64
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus

import httpx2
from pydantic import BaseModel, ConfigDict, ValidationError

from .errors import ERR, AuthAiError
from .types import TokenSet

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from .config import AuthClientConfig

type FormValue = str | Sequence[str]


class TokenResponse(BaseModel):
    """RFC 6749 §5.1 answer of the token endpoint."""

    model_config = ConfigDict(extra="allow", frozen=True)

    access_token: str
    token_type: str
    expires_in: int | float | None = None
    scope: str | None = None
    refresh_token: str | None = None
    id_token: str | None = None


def to_token_set(response: TokenResponse) -> TokenSet:
    if response.token_type.lower() != "bearer":
        raise ERR.OIDC_003("The token response is not a bearer token")
    if response.expires_in is None:
        raise ERR.OIDC_003("The token response carries no expires_in")
    return TokenSet(
        access_token=response.access_token,
        token_type=response.token_type,
        expires_at=int(time.time() + response.expires_in),
        scope=response.scope or None,
        refresh_token=response.refresh_token or None,
        id_token=response.id_token or None,
    )


class ProviderEndpoints:
    """Calls to the provider's token, revocation and introspection endpoints.

    The client authentication follows RFC 6749 §2.3.1: Basic credentials are
    form-urlencoded before the base64 encoding. Stateless, hence safe to share
    between concurrent users.
    """

    def __init__(self, config: AuthClientConfig, http: httpx2.AsyncClient) -> None:
        self._config = config
        self._http = http

    async def post(self, url: str, form: Mapping[str, FormValue]) -> httpx2.Response:
        """POSTs `form` with the client's credentials. Transport errors become OIDC_003."""
        data: dict[str, FormValue] = dict(form)
        headers = {"accept": "application/json"}
        config = self._config
        secret = config.client_secret
        if secret is None:
            data["client_id"] = config.client_id
        elif config.token_endpoint_auth_method == "client_secret_post":
            data["client_id"] = config.client_id
            data["client_secret"] = secret.get_secret_value()
        else:
            credentials = f"{quote_plus(config.client_id)}:{quote_plus(secret.get_secret_value())}"
            headers["authorization"] = f"Basic {base64.b64encode(credentials.encode()).decode()}"
        try:
            return await self._http.post(
                url,
                data=data,
                headers=headers,
                timeout=config.timeout_seconds,
                follow_redirects=False,
            )
        except httpx2.HTTPError as err:
            raise ERR.OIDC_003(cause=err) from err

    async def userinfo_request(self, url: str, access_token: str) -> dict[str, Any]:
        """GETs UserInfo with the access token. The token never enters an error."""
        try:
            response = await self._http.get(
                url,
                headers={
                    "authorization": f"Bearer {access_token}",
                    "accept": "application/json",
                },
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
            )
        except httpx2.HTTPError as err:
            raise ERR.OIDC_003(cause=err) from err
        if not response.is_success:
            raise ERR.OIDC_003(
                f"UserInfo endpoint answered HTTP {response.status_code}",
                details={"status": response.status_code},
            )
        try:
            body = response.json()
        except ValueError as err:
            raise ERR.TOK_001("The UserInfo response is not JSON", cause=err) from err
        if not isinstance(body, dict):
            raise ERR.TOK_001("The UserInfo response has an unexpected shape")
        return body

    async def token_request(self, url: str, form: Mapping[str, FormValue]) -> TokenSet:
        response = await self.post(url, form)
        body = _json_object(response)
        if not response.is_success:
            raise _rejection(response, body)
        try:
            return to_token_set(TokenResponse.model_validate(body))
        except ValidationError as err:
            raise ERR.OIDC_003("The token response has an unexpected shape", cause=err) from err


def _json_object(response: httpx2.Response) -> dict[str, Any] | None:
    try:
        body = response.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _rejection(response: httpx2.Response, body: dict[str, Any] | None) -> AuthAiError:
    """Maps a refusal to OIDC_003, keeping only the RFC 6749 error fields (no credential)."""
    status = response.status_code
    error = body.get("error") if body else None
    if body and isinstance(error, str):
        details: dict[str, str | int] = {"oauthError": error, "status": status}
        description = body.get("error_description")
        if isinstance(description, str):
            details["description"] = description
        return ERR.OIDC_003(f"Token endpoint rejected the request: {error}", details=details)
    if status == 401 and "www-authenticate" in response.headers:
        return ERR.OIDC_003(
            f"Token endpoint challenged the request (HTTP {status}): "
            "check client_id and client_secret",
            details={"status": status},
        )
    return ERR.OIDC_003(f"Token endpoint answered HTTP {status}", details={"status": status})
