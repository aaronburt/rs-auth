# rs-auth

A small forward-auth login portal for Traefik and Caddy, written in Rust.

rs-auth sits beside your reverse proxy and guards your apps with one login
page. The proxy asks `GET /api/verify` on every request. A valid session gets
`200` with `Remote-User`, `Remote-Groups`, `Remote-Email` and `Remote-Name`
headers; anything else gets a `302` to the login page. After signing in, a
signed JWT cookie shared across your domain lets you open every protected app
without seeing the login page again until it expires.

One binary, one `config.toml`, no database.

## Quick start

```sh
cargo build --release
cp config.example.toml config.toml && chmod 600 config.toml
./target/release/rs-auth hash-password      # paste the output into users.<name>.password
openssl rand -hex 32 > jwt.secret           # point session.jwt_secret_file at it
./target/release/rs-auth check-config
./target/release/rs-auth serve
```

To try it in a browser first, run the demo in [`examples/demo`](examples/demo/docker-compose.yml)
(Docker, no hosts-file changes) and open https://whoami.rs-auth.localhost:8443.

Then wire up your proxy: see [`examples/traefik`](examples/traefik) or
[`examples/caddy`](examples/caddy).

## Commands

| Command | Does |
| --- | --- |
| `rs-auth serve [-c config.toml]` | Runs the portal. `RS_AUTH_CONFIG` also sets the path. |
| `rs-auth hash-password [--stdin]` | Prompts twice and prints an Argon2id hash. |
| `rs-auth check-config [-c config.toml]` | Validates the config without starting. |
| `rs-auth healthcheck [addr]` | Exits 0 if `/healthz` answers. Used by the Docker image. |

Log level follows `RUST_LOG`: `error`, `warn`, `info`, `debug` or `trace` (default
`info`). Per-module filters are not supported.

## Endpoints

| Method | Path | Called by | Does |
| --- | --- | --- | --- |
| GET | `/api/verify` | The proxy | Valid session: `200` and `Remote-*` headers. Otherwise `302` to `/login?rd=<original URL>` (`303` for non-GET requests). Callers outside `server.trusted_proxies`, or requests missing `X-Forwarded-Proto`/`Host`, get `401`. |
| GET | `/login?rd=<url>` | Browser | The sign-in form. Already signed in: straight to `rd`. |
| POST | `/login` | Form | Checks CSRF, the rate limit and the password. Success sets the cookie and `303`s to `rd`. Wrong password: `401` and an amber message. Locked out: `429` and a red message. |
| GET | `/logout` | Browser | A "Sign out?" page. Apps link here. |
| POST | `/logout` | Form | Ends the session server-side and clears the cookie (CSRF-checked), then to `/login`. |
| GET | `/logged-in` | Browser | Where a sign-in without `rd` lands. Change with `server.default_redirect_url`. |
| GET | `/healthz` | Monitoring | `ok`. |

## Config

See [`config.example.toml`](config.example.toml) for every option. The server
refuses to start on a bad config. The rules:

- Passwords must be Argon2id PHC strings. Plain text is rejected.
- The JWT secret comes from `session.jwt_secret_file`, then the
  `RS_AUTH_JWT_SECRET` env var, then `session.jwt_secret` (warns). It must be at
  least 32 bytes.
- `server.portal_url` must be https, the root of its host, and inside
  `session.domain`.
- `server.trusted_proxies` must list your proxy's address or network.
- Unknown keys are errors, so typos don't silently do nothing.
- The file is TOML. Durations are strings like `"30m"`, `"12h"`, `"7d"`. Each
  user is a `[users.<name>]` table; put its hash in single quotes
  (`'$argon2id$...'`), a TOML literal string, so nothing in it is read as an
  escape.
- The server warns if the config file is world-readable.

Changes to the config apply on restart.

### Sessions

- The cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, set on
  `session.domain`, and lasts `session.expiry`.
- Verify always uses the user's **current** groups from the config. Removing a
  user from the config locks them out on their next request.
- Bump `session.version` to sign everyone out at once.
- Signing out revokes that session's token ID (`jti`), so a copied cookie stops
  working too. Set `session.revocation_file` to keep the list across restarts.
  The list holds up to 100,000 sign-outs. If it ever fills, it never forgets a
  revoked session: it raises a "not before" line to the start time of the oldest
  listed session and refuses every session that began at or before it. Those
  users sign in again; nobody signed out comes back.
- Each token carries a keyed fingerprint of the user's password hash, so
  changing a password ends that user's existing sessions.

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

For a full check behind a real Traefik or Caddy in Docker, see
[`e2e`](e2e/README.md):

```sh
docker compose -f e2e/traefik/docker-compose.yml up --build --abort-on-container-exit --exit-code-from tester
```

For trying it locally over plain http, set `server.insecure_dev_mode: true`
and use a `*.localhost` portal URL. Never use dev mode in production.

## Not in v1

Per-domain access rules, nginx support, config hot reload, remember-me,
server-side sessions, 2FA, password reset, LDAP or database users, and an
OIDC provider. Token signing sits behind a `TokenSigner` trait and `iss` is
set from day one, so OIDC can be added later without a rewrite.

## Automated security checks

CI runs on every push to `main`, every pull request, and weekly:

- `cargo fmt`, `cargo clippy -D warnings` with lossy casts, `unwrap`, `panic!`
  and string slicing denied (see `[lints.clippy]` in `Cargo.toml`).
- Unit, integration and property tests (`tests/properties.rs`, via proptest).
- `cargo audit` and `cargo deny` (advisories, licenses, banned crates, sources;
  see `deny.toml`).
- A Trivy scan of the built image, plus checks that it runs as non-root and
  has no shell.
- `cargo fuzz` on the hand-written parsers: cookie header, CLI args, redirect
  target and forwarded URL, `X-Forwarded-For`, token verification, and config
  validation (TOML parsing plus every rule above). Each target runs 60 s on
  pull requests and 15 min weekly. Run one locally with
  `cargo +nightly fuzz run cookie_header` from `fuzz/`.
