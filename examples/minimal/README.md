# Minimal example

A FastAPI backend and a vanilla JavaScript page (no build step) that exercise
the SDK end to end against a real auth-service: sign-in with PKCE, the session
cookie, entitlements, the wallet, the LiteLLM gateway (models, agents, MCP
servers, chat, embeddings), back-channel logout, machine tokens, billing and
consumption. **Self-test** runs every check and writes a report, free of any
token or secret, to the server log. It is the Python counterpart of the
TypeScript SDK's `examples/minimal`: same routes, same checks.

| Path                   | Role                                                          |
| ---------------------- | ------------------------------------------------------------- |
| `app/main.py`          | The app: SDK wiring, `/auth` routes, `/api` routes, headers.  |
| `app/config.py`        | Reads and validates the environment; names variables only.    |
| `app/selftest.py`      | The sixteen self-test checks.                                 |
| `app/payloads.py`      | The gateway answer shapes the example reads.                  |
| `public/`              | The page: `index.html`, `app.js` (ES module), `style.css`.    |

## Register the application in auth-service

- Confidential application at `https://<host>`, with **LiteLLM support** on.
- Redirect URI `https://<host>/auth/callback`, post-logout URI `https://<host>/auth/logout/callback`.
- Back-channel logout URI `https://<host>/auth/backchannel-logout`.
- Machine scopes (superadmin): `billing:read`, `consumption:read`, `consumption:write`.

## Configuration

The app refuses to start when a variable is missing or invalid, and names it.

| Variable             | Default  | Description                                                    |
| -------------------- | -------- | -------------------------------------------------------------- |
| `PORT`               | `3000`   | Listening port.                                                |
| `PUBLIC_URL`         | required | Origin of the app, no path or trailing slash.                  |
| `AUTH_ISSUER`        | required | auth-service URL (https, no trailing slash).                   |
| `AUTH_CLIENT_ID`     | required | The application's client id.                                   |
| `AUTH_CLIENT_SECRET` | required | The client secret. A secret: never commit it.                  |
| `GATEWAY_URL`        | required | The LiteLLM gateway URL (no trailing slash).                   |
| `COOKIE_SECRET`      | required | At least 32 random characters. A secret.                       |

## Run

### Locally, from a clone of the repository

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[fastapi]" "uvicorn>=0.30,<1"
cd examples/minimal
export PUBLIC_URL=http://localhost:3000 AUTH_ISSUER=https://auth.example.com \
  AUTH_CLIENT_ID=<client-id> AUTH_CLIENT_SECRET=<client-secret> \
  GATEWAY_URL=https://llm.example.com COOKIE_SECRET="$(openssl rand -base64 48)"
python -m app.main
```

Outside the repository, install the released SDK instead:
`pip install -r requirements.txt`.

### With Docker Compose, behind Traefik

```sh
cp examples/minimal/.env.example examples/minimal/.env   # then fill the placeholders and secrets
docker compose -f examples/minimal/compose.yml up -d --build
```

The image builds from the **repository root** (`SRC_DIR`, `../..` by default)
and installs the SDK from that checkout, so it always runs the code next to it.
To build against the released SDK instead, drop the `/sdk` lines of the
`Dockerfile`: `requirements.txt` then installs `auth-ai[fastapi]` from PyPI.

`compose.yml` expects the shared Traefik setup: an external network named
`edge`, a `websecure` entry point and a `letsencrypt` certificate resolver.
Adapt the labels if your edge differs.

The app silences uvicorn's access log, which would record the callback query
string (the authorization code), and logs the method and path of each request
instead. Start it with `python -m app.main` to get those logs: a bare `uvicorn`
command does not configure the `minimal` logger.

Sessions and grants are kept in memory: a restart signs everyone out. Use a
database-backed `SessionStore` and `GrantStore` in a real application.
