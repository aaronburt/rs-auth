# rs-auth

A small forward-auth login portal for Traefik and Caddy, written in Rust.

rs-auth sits beside your reverse proxy and guards your apps with one login
page. The proxy asks `GET /api/verify` on every request. A valid session gets
`200` with `Remote-User`, `Remote-Groups`, `Remote-Email` and `Remote-Name`
headers; anything else gets a `302` to the login page. After signing in, a
signed JWT cookie shared across your domain lets you open every protected app
without seeing the login page again until it expires.

One binary, one `config.yaml`, no database.

## Quick start

```sh
cargo build --release
cp config.example.yaml config.yaml && chmod 600 config.yaml
./target/release/rs-auth hash-password      # paste the output into users.<name>.password
openssl rand -hex 32 > jwt.secret           # point session.jwt_secret_file at it
./target/release/rs-auth check-config
./target/release/rs-auth serve
```

Then wire up your proxy: see [`examples/traefik`](examples/traefik) or
[`examples/caddy`](examples/caddy).

## Commands

| Command | Does |
| --- | --- |
| `rs-auth serve [-c config.yaml]` | Runs the portal. `RS_AUTH_CONFIG` also sets the path. |
| `rs-auth hash-password [--stdin]` | Prompts twice and prints an Argon2id hash. |
| `rs-auth check-config [-c config.yaml]` | Validates the config without starting. |
| `rs-auth healthcheck [addr]` | Exits 0 if `/healthz` answers. Used by the Docker image. |

Log level follows `RUST_LOG` (default `info`).

## Endpoints

| Method | Path | Called by | Does |
| --- | --- | --- | --- |
| GET | `/api/verify` | The proxy | Valid session: `200` and `Remote-*` headers. Otherwise `302` to `/login?rd=<original URL>` (`303` for non-GET requests). Callers outside `server.trusted_proxies`, or requests missing `X-Forwarded-Proto`/`Host`, get `401`. |
| GET | `/login?rd=<url>` | Browser | The sign-in form. Already signed in: straight to `rd`. |
| POST | `/login` | Form | Checks CSRF, the rate limit and the password. Success sets the cookie and `303`s to `rd`. Wrong password: `401` and an amber message. Locked out: `429` and a red message. |
| GET | `/logout` | Browser | A "Sign out?" page. Apps link here. |
| POST | `/logout` | Form | Clears the cookie (CSRF-checked), then to `/login`. |
| GET | `/logged-in` | Browser | Where a sign-in without `rd` lands. Change with `server.default_redirect_url`. |
| GET | `/healthz` | Monitoring | `ok`. |

## Config

See [`config.example.yaml`](config.example.yaml) for every option. The server
refuses to start on a bad config. The rules:

- Passwords must be Argon2id PHC strings. Plain text is rejected.
- The JWT secret comes from `session.jwt_secret_file`, then the
  `RS_AUTH_JWT_SECRET` env var, then `session.jwt_secret` (warns). It must be at
  least 32 bytes.
- `server.portal_url` must be https, the root of its host, and inside
  `session.domain`.
- `server.trusted_proxies` must list your proxy's address or network.
- Unknown keys are errors, so typos don't silently do nothing.
- Durations look like `30m`, `12h`, `7d`.
- The server warns if the config file is world-readable.

Changes to the config apply on restart.

### Sessions

- The cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, set on
  `session.domain`, and lasts `session.expiry`.
- Verify always uses the user's **current** groups from the config. Removing a
  user from the YAML locks them out on their next request.
- Bump `session.version` to sign everyone out at once.

## Security notes

- Unknown usernames still run a full Argon2 check, and every failure says
  "Invalid username or password", so usernames can't be probed.
- Failed sign-ins are limited per client IP (`login.max_attempts` within
  `login.window`, default 5 in 5 minutes). The page never shows attempts left or
  how long a lockout lasts, and no `Retry-After` is sent. A success clears the
  IP's count.
- The client IP comes from `X-Forwarded-For` only when the direct peer is a
  trusted proxy, reading right to left past trusted hops, so clients can't
  spoof it.
- `rd` must be https and on `session.domain` or a subdomain. Anything else
  falls back to the default page.
- Login and logout use double-submit CSRF tokens on top of `SameSite=Lax`.
- Pages send a strict CSP (only the hashed inline style and script),
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`.
- Argon2 runs on the blocking pool with a cap on concurrent checks. Request
  bodies are capped at 16 KB and requests time out after 15 seconds.
- `#![forbid(unsafe_code)]`. Secrets and hashes never appear in logs.

## Development

```sh
cargo test                       # unit + end-to-end tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

For trying it locally over plain http, set `server.insecure_dev_mode: true`
and use a `*.localhost` portal URL. Never use dev mode in production.

## Not in v1

Per-domain access rules, nginx support, config hot reload, remember-me,
server-side sessions, 2FA, password reset, LDAP or database users, and an
OIDC provider. Token signing sits behind a `TokenSigner` trait and `iss` is
set from day one, so OIDC can be added later without a rewrite.
