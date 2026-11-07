import json
import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from http import HTTPStatus
from pathlib import Path
from typing import Annotated, Final

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from auth_ai import (
    ERR,
    AiClient,
    AuthAiError,
    AuthClient,
    AuthClientConfig,
    GrantManager,
    MemoryGrantStore,
)
from auth_ai.server import (
    BearerVerifier,
    MachineApi,
    bearer_challenge,
    protected_resource_metadata,
    protected_resource_metadata_path,
)
from auth_ai.starlette import install_auth, require_auth
from auth_ai.web import AuthHandlers, MemorySessionStore, Session

from .config import load_config
from .payloads import EmbeddingAnswer, parse_answer
from .selftest import SelfTestContext, run_self_test

log = logging.getLogger("minimal")

CONTENT_SECURITY_POLICY: Final = "default-src 'self'; frame-ancestors 'none'"
PUBLIC_DIR: Final = Path(__file__).resolve().parent.parent / "public"
STATIC_FILES: Final = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}

config = load_config(os.environ)

auth = AuthClient(
    AuthClientConfig(
        issuer=config.auth_issuer,
        client_id=config.auth_client_id,
        client_secret=config.auth_client_secret,
        redirect_uri=f"{config.public_url}/auth/callback",
        post_logout_redirect_uri=f"{config.public_url}/auth/logout/callback",
        gateway_url=config.gateway_url,
        resources=(config.public_url,),
    )
)

# In memory: a restart signs everyone out. Use a database store beyond a demo.
grants = GrantManager(auth=auth, store=MemoryGrantStore())
ai = AiClient(auth=auth, grants=grants)
machine = MachineApi(auth)
bearer = BearerVerifier(auth, audience=config.public_url)


def _log_handler_error(error: BaseException) -> None:
    log.warning(
        "auth handler error: %s", error.to_json() if isinstance(error, AuthAiError) else error
    )


def _log_sessions_ended(sessions: Sequence[Session]) -> None:
    log.info("sessions ended: %d", len(sessions))


handlers = AuthHandlers(
    auth=auth,
    grants=grants,
    sessions=MemorySessionStore(),
    secret=config.cookie_secret.get_secret_value(),
    ai=ai,
    on_error=_log_handler_error,
    on_sessions_ended=_log_sessions_ended,
)
protect = require_auth(handlers)
SignedIn = Annotated[Session, Depends(protect)]


# ── Cross-cutting HTTP concerns ──


class _NoAccessLog(logging.Filter):
    # uvicorn logs the whole request line and the callback query string carries
    # the authorization code: RequestLogMiddleware logs the method and path instead.
    def filter(self, record: logging.LogRecord) -> bool:
        return False


logging.getLogger("uvicorn.access").addFilter(_NoAccessLog())


class SecurityHeadersMiddleware:
    """The CSP forbids inline script and any other origin."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["content-security-policy"] = CONTENT_SECURITY_POLICY
                headers["x-content-type-options"] = "nosniff"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestLogMiddleware:
    """Logs the method and the path, never the query string."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = HTTPStatus.INTERNAL_SERVER_ERROR.value

        async def send_logging_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_logging_status)
        finally:
            log.info("%s %s -> %d", scope["method"], scope["path"], status)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        await auth.aclose()


# The interactive docs are off: the app serves exactly the routes below.
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLogMiddleware)
install_auth(app, handlers)


async def _invalid_request(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        {"error": ERR.REQ_001().to_public_json()}, status_code=HTTPStatus.BAD_REQUEST
    )


async def _internal_error(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        {"error": ERR.SRV_001().to_public_json()}, status_code=HTTPStatus.INTERNAL_SERVER_ERROR
    )


app.add_exception_handler(RequestValidationError, _invalid_request)
app.add_exception_handler(Exception, _internal_error)


# State-changing API calls must come from this site.
async def same_origin(request: Request) -> None:
    if request.method in {"GET", "HEAD"}:
        return
    origin = request.headers.get("origin")
    if origin is not None and origin != config.public_url:
        raise ERR.SES_004()


api = APIRouter(prefix="/api", dependencies=[Depends(same_origin)])


# ── Static files, health, metadata ──


def _static(file_name: str, media_type: str) -> Callable[[], Awaitable[Response]]:
    body = (PUBLIC_DIR / file_name).read_bytes()

    async def serve() -> Response:
        return Response(body, media_type=media_type)

    return serve


for static_path, (static_file, static_type) in STATIC_FILES.items():
    app.add_api_route(
        static_path,
        _static(static_file, static_type),
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}


METADATA_PATH: Final = protected_resource_metadata_path(config.public_url)
METADATA: Final = protected_resource_metadata(
    auth,
    resource=config.public_url,
    scopes_supported=["openid", "profile", "email", "roles", "features"],
)


@app.get(METADATA_PATH, include_in_schema=False)
async def resource_metadata() -> dict[str, object]:
    return METADATA


# ── Protected API ──


async def _settle(run: Callable[[], Awaitable[Sequence[BaseModel]]]) -> dict[str, object]:
    try:
        items = await run()
    except AuthAiError as err:
        log.warning("gateway listing failed: %s", err.to_json())
        return {"ok": False, "error": err.to_public_json()}
    except Exception:
        log.exception("gateway listing failed")
        return {"ok": False, "error": {"message": "failed"}}
    return {"ok": True, "data": [item.model_dump(mode="json") for item in items]}


def _gateway_error(err: AuthAiError) -> JSONResponse:
    log.warning("call failed: %s", err.to_json())
    status = HTTPStatus.PAYMENT_REQUIRED if err.code == "GW_001" else HTTPStatus.BAD_GATEWAY
    return JSONResponse({"error": err.to_public_json()}, status_code=status)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ChatBody(_Body):
    model: str = Field(min_length=1)
    message: str = Field(min_length=1, max_length=2000)


class EmbedBody(_Body):
    model: str = Field(min_length=1)
    input: str = Field(min_length=1, max_length=2000)


class ConsumeBody(_Body):
    # Same limits as the SDK, so that a bad key is a 400 and not a configuration error.
    key: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9.]+$")
    value: StrictInt | Annotated[StrictFloat, Field(allow_inf_nan=False)]


@api.get("/gateway")
async def gateway(session: SignedIn) -> JSONResponse:
    user_gateway = ai.for_user(session.user_id).gateway
    return JSONResponse(
        {
            "models": await _settle(user_gateway.list_models),
            "agents": await _settle(user_gateway.list_agents),
            "mcpServers": await _settle(user_gateway.list_mcp_servers),
        }
    )


@api.post("/chat")
async def chat(body: ChatBody, session: SignedIn) -> JSONResponse:
    try:
        answer = await ai.for_user(session.user_id).gateway.post_json(
            "/v1/chat/completions",
            {
                "model": body.model,
                "max_tokens": 256,
                "messages": [{"role": "user", "content": body.message}],
                "metadata": {"session_id": session.id},
            },
        )
    except AuthAiError as err:
        return _gateway_error(err)
    return JSONResponse(answer)


@api.post("/embed")
async def embed(body: EmbedBody, session: SignedIn) -> JSONResponse:
    try:
        answer = await ai.for_user(session.user_id).gateway.post_json(
            "/v1/embeddings",
            {**body.model_dump(), "metadata": {"session_id": session.id}},
        )
        embeddings = parse_answer(EmbeddingAnswer, answer)
    except AuthAiError as err:
        return _gateway_error(err)
    dimensions = len(embeddings.data[0].embedding) if embeddings.data else 0
    return JSONResponse({"dimensions": dimensions})


@api.post("/consume")
async def consume(body: ConsumeBody, session: SignedIn) -> JSONResponse:
    try:
        await machine.consumption.report(session.user_id, body.key, body.value)
        aggregates = await machine.consumption.list_aggregates(session.user_id)
    except AuthAiError as err:
        return _gateway_error(err)
    return JSONResponse([aggregate.to_json() for aggregate in aggregates])


@api.post("/selftest")
async def selftest(session: SignedIn) -> JSONResponse:
    checks = await run_self_test(
        SelfTestContext(
            auth=auth,
            grants=grants,
            ai=ai,
            machine=machine,
            public_url=config.public_url,
            gateway_url=config.gateway_url,
            session=session,
        )
    )
    # The log keeps the detailed report for the developer; the browser gets the codes.
    log.info(
        "self-test user=%s checks=%s",
        session.user_id,
        json.dumps([check.to_json() for check in checks]),
    )
    return JSONResponse({"checks": [check.to_public_json() for check in checks]})


# A Bearer-protected route, to exercise token verification and the challenge.
@api.get("/bearer")
async def bearer_route(request: Request) -> JSONResponse:
    try:
        verified = await bearer.verify_header(request.headers.get("authorization"))
    except AuthAiError as err:
        log.warning("bearer verification failed: %s", err.to_json())
        challenge = bearer_challenge(f"{config.public_url}{METADATA_PATH}", error="invalid_token")
        return JSONResponse(
            {"error": err.to_public_json()},
            status_code=HTTPStatus.UNAUTHORIZED,
            headers={"www-authenticate": challenge},
        )
    return JSONResponse({"userId": verified.user_id, "scopes": list(verified.scopes)})


app.include_router(api)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # Behind the shared reverse proxy: trust its forwarded headers, as the TS example does.
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 - the container is reached from the edge network
        port=config.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
