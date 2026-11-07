"""Python SDK for applications relying on a CIRCLE auth-service identity provider."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .ai import AiClient, UserAi
from .claims import (
    AccessTokenClaims,
    FeatureValue,
    IdTokenClaims,
    UserInfoClaims,
    get_feature,
    has_feature,
    has_permission,
    has_role,
)
from .client import AuthClient
from .config import DEFAULT_SCOPES, WALLET_SELF_SCOPE, AuthClientConfig
from .errors import (
    ERR,
    AuthAiError,
    AuthAiErrorCode,
    AuthAiErrorDetails,
    is_auth_ai_error_code,
)
from .gateway import (
    GatewayAgent,
    GatewayAuth,
    GatewayClient,
    GatewayMcpServer,
    GatewayModel,
)
from .gateway_errors import (
    is_insufficient_credit,
    is_insufficient_credit_status,
    to_gateway_error,
)
from .grants import (
    AccessToken,
    GrantLock,
    GrantManager,
    GrantStore,
    InProcessGrantLock,
    MemoryGrantStore,
)
from .introspection import IntrospectionResult
from .session_user import SessionUser, to_session_user
from .transport import build_http_client
from .types import (
    LoginHandshake,
    LoginRequest,
    LoginResult,
    Prompt,
    TokenSet,
    TokenTypeHint,
)
from .wallet import (
    MICRO_PER_EUR,
    TopupOptions,
    WalletAccount,
    WalletClient,
    WalletSessionUsage,
    WalletStats,
    WalletTransaction,
    WalletTransactionPage,
    WalletTransactionType,
    format_euros,
)

try:
    __version__ = version("auth-ai")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "DEFAULT_SCOPES",
    "ERR",
    "MICRO_PER_EUR",
    "WALLET_SELF_SCOPE",
    "AccessToken",
    "AccessTokenClaims",
    "AiClient",
    "AuthAiError",
    "AuthAiErrorCode",
    "AuthAiErrorDetails",
    "AuthClient",
    "AuthClientConfig",
    "FeatureValue",
    "GatewayAgent",
    "GatewayAuth",
    "GatewayClient",
    "GatewayMcpServer",
    "GatewayModel",
    "GrantLock",
    "GrantManager",
    "GrantStore",
    "IdTokenClaims",
    "InProcessGrantLock",
    "IntrospectionResult",
    "LoginHandshake",
    "LoginRequest",
    "LoginResult",
    "MemoryGrantStore",
    "Prompt",
    "SessionUser",
    "TokenSet",
    "TokenTypeHint",
    "TopupOptions",
    "UserAi",
    "UserInfoClaims",
    "WalletAccount",
    "WalletClient",
    "WalletSessionUsage",
    "WalletStats",
    "WalletTransaction",
    "WalletTransactionPage",
    "WalletTransactionType",
    "__version__",
    "build_http_client",
    "format_euros",
    "get_feature",
    "has_feature",
    "has_permission",
    "has_role",
    "is_auth_ai_error_code",
    "is_insufficient_credit",
    "is_insufficient_credit_status",
    "to_gateway_error",
    "to_session_user",
]
