# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Sections, when present, appear in this order: `Added`, `Changed`, `Removed`,
`Fixed`, `Security`. Per our no-backward-compatibility policy
([CONTRIBUTING.md](CONTRIBUTING.md#2-versioning-and-breaking-changes)) there is no
`Deprecated` section: incompatible changes go straight to `Removed` and bump the version.

## [Unreleased]

<!-- Add user-visible changes here. Move to a dated section at release time. -->

## [0.2.1] - 2026-11-07

### Added

- **UserInfo enrichment**: `AuthClient.fetch_userinfo()` and `AuthClient.apply_userinfo()`.
  The login callback and the claim-renewal path now call the provider's `userinfo_endpoint`
  and fill claims the ID token omits (`email`, `email_verified` and the standard profile
  claims). The UserInfo `sub` is checked against the ID token; claims already present in the
  ID token are never replaced.

### Changed

- **RP-initiated logout state**: `/auth/logout` now generates a `state`, sends it to the
  provider's `end_session_endpoint`, and the new `/auth/logout/callback` route accepts the
  provider's redirect even when the state is missing or different. The reference app registers
  `/auth/logout/callback` as its post-logout URI.

## [0.2.0] - 2026-11-04

### Added

- **`build_http_client(*, timeout_seconds, transport=None, auth=None)`**: the HTTP client every
  SDK call uses. HTTP/2 is negotiated over TLS with HTTP/1.1 as the fallback, gzip and brotli
  responses are decoded (zstd where the runtime provides it, Python 3.14), and redirects are
  never followed. Exported from `auth_ai`.

### Changed

- The HTTP stack moved from `httpx` to `httpx2` (BSD-3-Clause), the transport of the `openai`
  3.x package that the gateway integration relies on. `httpx2[brotli,http2]` is a runtime
  dependency; `GatewayClient.create_http_client()` returns an `httpx2.AsyncClient`, which matches
  the `openai` 3.x annotation and needs no type ignore.
- `POST /logout` answers the provider's logout URL even without a local session, built without
  `id_token_hint`: the provider ends its single sign-on session for every application and asks
  the user to confirm. `logoutUrl` is `null` only when the provider advertises no end-session
  endpoint.

### Removed

- The `httpx` dependency. `AuthClient(http_client=...)`, `auth.http` and
  `GatewayClient.create_http_client()` take and return `httpx2` clients: an `httpx.AsyncClient`
  no longer type-checks as `http_client`. Build the client with `build_http_client()`.

## [0.1.0] - 2026-11-02

First release: the Python port of `@circle-rd/auth-ai` 0.1.1, with the same behaviours,
wire contract and error codes.

### Added

- **Core (`auth_ai`)**: `AuthClient` (discovery cache, PKCE login, callback with
  ID-token verification, refresh with RFC 8707 resource narrowing, logout URL, revoke,
  introspect, `client_credentials`), `GrantManager` (serialized refresh-token rotation,
  per-audience access tokens, pluggable `GrantStore` and `GrantLock`), typed claims with
  `has_role` / `has_permission` / `has_feature` / `get_feature`, the error registry
  (`CFG_`, `OIDC_`, `TOK_`, `API_`, `GW_`, `SES_`, `REQ_`, `SRV_`) with `to_public_json()`.
- **Wallet and gateway**: `WalletClient` (balance, statistics, per-session usage,
  transactions, top-up options and link; `int` micro-euros, `format_euros`),
  `GatewayClient` (origin-locked `httpx` client, OpenAI-compatible base URL, models,
  agents, MCP servers, MCP URLs, `post_json`, gateway error mapping),
  `AiClient.for_user()`, and the `gateway_url` option that adds the gateway and
  auth-service audiences and the `wallet:self:read` scope.
- **Server (`auth_ai.server`)**: Bearer-token verifier, back-channel logout handler with
  replay protection, RFC 9728 protected-resource metadata and `WWW-Authenticate`
  challenges, machine API (subscription, metered usage, invoices, consumption reporting).
- **Backend-for-frontend (`auth_ai.web`, `auth_ai.starlette`)**: `AuthHandlers`
  (`/login`, `/callback`, `/me`, `/logout`, `/backchannel-logout`, optional `/wallet`,
  `/wallet/stats`, `/models`), sealed one-shot login cookie (interoperable with the
  TypeScript SDK), hashed session ids, `SessionStore` contract, scheduled claims
  renewal; Starlette and FastAPI adapter with `install_auth`, `require_auth` and
  `load_session`.
- Example application (`examples/minimal`) with an end-to-end self-test, and the
  Docus documentation site.

### Security

- Every failed sign-in callback answers one generic `403 SES_005`; messages and details
  stay in the application's logs.
- `__Host-` cookies, same-origin redirect targets, refused cross-site logout, URLs built
  on the registered origin, client credentials form-urlencoded per RFC 6749 §2.3.1.
- JWTs signed with `EdDSA` are refused: RFC 9864 deprecates that algorithm name. The
  fully specified `Ed25519` and `Ed448` are accepted, next to the ES\*, RS\* and PS\*
  families (auth-service signs with ES256).
- A server-side failure (5xx answer) of the sign-in routes is reported to `on_error`.

[Unreleased]: https://github.com/circle-rd/auth-ai-py/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/circle-rd/auth-ai-py/releases/tag/v0.1.0
