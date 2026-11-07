"""A scripted identity provider and gateway behind an `httpx2.MockTransport`."""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx2
from joserfc import jwt
from joserfc.jwk import ECKey

from auth_ai import AuthClient, AuthClientConfig

ISSUER = "https://idp.test"
CLIENT_ID = "test-app"
CLIENT_SECRET = "test-secret"
REDIRECT_URI = "https://app.test/callback"
GATEWAY_URL = "https://llm.test"


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    url: httpx2.URL
    headers: httpx2.Headers
    body: bytes

    @property
    def form(self) -> httpx2.QueryParams:
        is_form = "application/x-www-form-urlencoded" in self.headers.get("content-type", "")
        return httpx2.QueryParams(self.body.decode() if is_form else "")

    @property
    def json(self) -> Any:
        return httpx2.Response(200, content=self.body).json()


type Handler = Callable[[RecordedRequest], httpx2.Response | Awaitable[httpx2.Response]]


def json_response(body: object, status: int = 200) -> httpx2.Response:
    return httpx2.Response(status, json=body)


def now_seconds() -> int:
    return int(time.time())


def sign(claims: dict[str, Any], key: ECKey, *, typ: str | None = None, kid: str = "key-1") -> str:
    header = {"alg": "ES256", "kid": kid, **({"typ": typ} if typ else {})}
    return jwt.encode(header, claims, key, algorithms=["ES256"])


@dataclass
class MockIdp:
    private_key: ECKey
    metadata: dict[str, Any]
    requests: list[RecordedRequest] = field(default_factory=list)
    token_handler: Handler = lambda _request: json_response({"error": "server_error"}, 500)
    userinfo_handler: Handler = lambda _request: json_response({"sub": "user-1"})
    api_handler: Handler = lambda _request: json_response(
        {"error": {"code": "APP_002", "message": "unhandled"}}, 404
    )
    revocation_status: int = 200
    introspection: dict[str, Any] = field(default_factory=lambda: {"active": False})
    discovery_failures: int = 0
    gateway_handler: Handler = lambda _request: json_response(
        {"error": {"message": "unhandled"}}, 404
    )
    gateway_requests: list[RecordedRequest] = field(default_factory=list)
    jwks_overrides: list[dict[str, Any]] | None = None

    def sign_jwt(
        self,
        claims: dict[str, Any],
        *,
        typ: str | None = None,
        key: ECKey | None = None,
        kid: str = "key-1",
    ) -> str:
        return sign(claims, key or self.private_key, typ=typ, kid=kid)

    def id_token(self, **claims: Any) -> str:
        now = now_seconds()
        return self.sign_jwt(
            {
                "iss": ISSUER,
                "sub": "user-1",
                "aud": CLIENT_ID,
                "iat": now,
                "exp": now + 300,
                **claims,
            }
        )

    @staticmethod
    def generate_foreign_key() -> ECKey:
        return ECKey.generate_key("P-256", parameters={"kid": "key-1"})

    def requests_to(self, path: str) -> list[RecordedRequest]:
        return [request for request in self.requests if request.url.path == path]

    @property
    def jwks(self) -> dict[str, Any]:
        if self.jwks_overrides is not None:
            return {"keys": self.jwks_overrides}
        return {"keys": [self.private_key.as_dict(private=False, alg="ES256")]}

    async def handle(self, request: httpx2.Request) -> httpx2.Response:
        recorded = RecordedRequest(request.method, request.url, request.headers, request.read())
        if request.url.host == httpx2.URL(GATEWAY_URL).host:
            self.gateway_requests.append(recorded)
            return await _call(self.gateway_handler, recorded)
        self.requests.append(recorded)

        match request.url.path:
            case "/.well-known/openid-configuration":
                if self.discovery_failures > 0:
                    self.discovery_failures -= 1
                    return httpx2.Response(503, text="unavailable")
                return json_response(self.metadata)
            case "/jwks":
                return json_response(self.jwks)
            case "/token":
                return await _call(self.token_handler, recorded)
            case "/userinfo":
                return await _call(self.userinfo_handler, recorded)
            case "/revoke":
                return httpx2.Response(self.revocation_status)
            case "/introspect":
                return json_response(self.introspection)
            case path if path.startswith("/api/"):
                return await _call(self.api_handler, recorded)
            case _:
                return httpx2.Response(404, text="not found")

    def http_client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self.handle))


async def _call(handler: Handler, request: RecordedRequest) -> httpx2.Response:
    result = handler(request)
    return await result if inspect.isawaitable(result) else result


def create_mock_idp() -> MockIdp:
    key = ECKey.generate_key("P-256", parameters={"kid": "key-1"})
    metadata = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "introspection_endpoint": f"{ISSUER}/introspect",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "end_session_endpoint": f"{ISSUER}/end-session",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "authorization_response_iss_parameter_supported": True,
    }
    return MockIdp(private_key=key, metadata=metadata)


def create_test_auth(idp: MockIdp, **overrides: Any) -> AuthClient:
    config = {
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        **overrides,
    }
    return AuthClient(AuthClientConfig(**config), http_client=idp.http_client())
