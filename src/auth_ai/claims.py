from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

type FeatureValue = str | int | float | bool
type PermissionAction = Literal["read", "write"]


class _Claims(BaseModel):
    # Unknown claims are kept as is.
    model_config = ConfigDict(extra="allow", frozen=True)

    iss: str
    sub: str
    aud: str | list[str]
    exp: int | float
    iat: int | float
    # Present only when the matching scope was granted.
    roles: list[str] | None = None
    permissions: list[str] | None = None
    features: dict[str, FeatureValue] | None = None
    plan: str | None = None
    org_id: str | None = None
    sid: str | None = None
    azp: str | None = None


class IdTokenClaims(_Claims):
    """Claims of an ID token issued by auth-service."""

    name: str | None = None
    picture: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    company: str | None = None
    updated_at: int | float | None = None
    email: str | None = None
    email_verified: bool | None = None
    phone_number: str | None = None


class UserInfoClaims(BaseModel):
    """Standard claims returned by the UserInfo endpoint.

    UserInfo carries no registered token claims (`iss`, `aud`, `exp`, `iat`),
    so it does not extend `_Claims`; entitlements are repeated because the
    endpoint may return them as well.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    sub: str
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    middle_name: str | None = None
    nickname: str | None = None
    preferred_username: str | None = None
    profile: str | None = None
    picture: str | None = None
    website: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    zoneinfo: str | None = None
    locale: str | None = None
    updated_at: int | float | None = None
    email: str | None = None
    email_verified: bool | None = None
    phone_number: str | None = None
    phone_number_verified: bool | None = None
    roles: list[str] | None = None
    permissions: list[str] | None = None
    features: dict[str, FeatureValue] | None = None
    plan: str | None = None
    org_id: str | None = None


class AccessTokenClaims(_Claims):
    """Claims of a JWT access token.

    `azp` is the OAuth client that obtained the token and `scope` is a
    space-separated list.
    """

    azp: str
    scope: str | None = None


class EntitlementClaims(Protocol):
    @property
    def roles(self) -> list[str] | None: ...
    @property
    def permissions(self) -> list[str] | None: ...
    @property
    def features(self) -> dict[str, FeatureValue] | None: ...


def has_role(claims: EntitlementClaims, role: str) -> bool:
    return role in (claims.roles or ())


def has_permission(
    claims: EntitlementClaims, resource: str, action: PermissionAction = "read"
) -> bool:
    """`resource` grants read access and `resource.write` grants write access,
    which also implies read: auth-service keeps only the highest action."""
    permissions = claims.permissions
    if not permissions:
        return False
    if f"{resource}.write" in permissions:
        return True
    return action == "read" and resource in permissions


def has_feature(claims: EntitlementClaims, key: str) -> bool:
    """A feature is enabled when present and neither `false` nor `0` nor `""`."""
    value = get_feature(claims, key)
    return value is not None and value not in {"", 0}


def get_feature(claims: EntitlementClaims, key: str) -> FeatureValue | None:
    return (claims.features or {}).get(key)
