from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import httpx2
from pydantic import BaseModel, ConfigDict, ValidationError

from .errors import ERR
from .jwt import JwtVerifier, RemoteJwks

if TYPE_CHECKING:
    from .config import AuthClientConfig

# Discovery and keys change rarely; an hour keeps rotation picked up without a restart.
PROVIDER_TTL_SECONDS: Final = 3600.0

ASYMMETRIC_ALGORITHMS: Final = frozenset(
    {
        "Ed25519",
        "Ed448",
        "ES256",
        "ES384",
        "ES512",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
    }
)


class ProviderMetadata(BaseModel):
    """The members of the discovery document the SDK relies on."""

    model_config = ConfigDict(extra="allow", frozen=True)

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None
    introspection_endpoint: str | None = None
    revocation_endpoint: str | None = None
    end_session_endpoint: str | None = None
    id_token_signing_alg_values_supported: list[str] = []
    authorization_response_iss_parameter_supported: bool = False


@dataclass(frozen=True, slots=True)
class Provider:
    metadata: ProviderMetadata
    jwt: JwtVerifier


async def _discover(config: AuthClientConfig, http: httpx2.AsyncClient) -> Provider:
    url = f"{config.issuer}/.well-known/openid-configuration"
    try:
        response = await http.get(
            url,
            headers={"accept": "application/json"},
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )
        response.raise_for_status()
        metadata = ProviderMetadata.model_validate(response.json())
    except (httpx2.HTTPError, ValueError, ValidationError) as err:
        raise ERR.OIDC_001(cause=err) from err
    if metadata.issuer != config.issuer:
        raise ERR.OIDC_001("The discovery document names another issuer")

    algorithms = [
        alg
        for alg in metadata.id_token_signing_alg_values_supported
        if alg in ASYMMETRIC_ALGORITHMS
    ]
    if not algorithms or not metadata.jwks_uri:
        raise ERR.OIDC_001(
            "The provider advertises no asymmetric ID token algorithm or no jwks_uri"
        )
    return Provider(
        metadata=metadata,
        jwt=JwtVerifier(
            issuer=config.issuer,
            jwks=RemoteJwks(metadata.jwks_uri, http, config.timeout_seconds),
            algorithms=algorithms,
            clock_tolerance_seconds=config.clock_tolerance_seconds,
        ),
    )


class ProviderLoader:
    """Discovers the provider once and again after an hour. A failed load is not cached."""

    def __init__(self, config: AuthClientConfig, http: httpx2.AsyncClient) -> None:
        self._config = config
        self._http = http
        self._cached: tuple[float, Provider] | None = None
        self._lock = asyncio.Lock()

    async def get(self) -> Provider:
        cached = self._cached
        if cached is not None and time.monotonic() - cached[0] < PROVIDER_TTL_SECONDS:
            return cached[1]
        async with self._lock:
            cached = self._cached
            if cached is not None and time.monotonic() - cached[0] < PROVIDER_TTL_SECONDS:
                return cached[1]
            provider = await _discover(self._config, self._http)
            self._cached = (time.monotonic(), provider)
            return provider
