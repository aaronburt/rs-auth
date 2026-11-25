# rs-auth

A small forward-auth login portal for Traefik, Caddy and nginx, written in Rust.

rs-auth sits beside your reverse proxy and guards your apps with one login
page. The proxy asks `GET /api/verify` on every request. Each host is open only
to the groups listed for it in `[access]`; a host with no entry is closed to
everyone. A signed-in user in one of the host's groups gets `200` with
`Remote-User`, `Remote-Groups`, `Remote-Email` and `Remote-Name` headers; a
user who isn't signed in gets a `302` to the login page; anyone else gets a
`403` "No access" page. After signing in, a
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

Then wire up your proxy: see [`examples/traefik`](examples/traefik),
[`examples/caddy`](examples/caddy) or [`examples/nginx`](examples/nginx).

## Commands

| Command | Does |
| --- | --- |
| `rs-auth serve [-c config.toml]` | Runs the portal. `RS_AUTH_CONFIG` also sets the path. |
| `rs-auth hash-password [--stdin]` | Prompts twice and prints an Argon2id hash. |
| `rs-auth totp-secret [username]` | Prints a new TOTP secret and, with a username, an `otpauth://` link and a terminal QR code for an authenticator app. |
| `rs-auth check-config [-c config.toml]` | Validates the config without starting. |
| `rs-auth healthcheck [addr]` | Exits 0 if `/healthz` answers. Used by the Docker image. |

Log level follows `RUST_LOG`: `error`, `warn`, `info`, `debug` or `trace` (default
`info`). Per-module filters are not supported.

## Endpoints

| Method | Path | Called by | Does |
| --- | --- | --- | --- |
| GET | `/api/verify` | The proxy, internally | Host with no `[access]` entry: `403` for everyone. Not signed in: `302` to `/login?rd=<original URL>` (`303` for non-GET requests). Signed in but not in one of the host's groups: `403` with a "No access" page. Otherwise `200`, `Remote-*` headers, and a `Cookie` header holding the request's other cookies (see [Proxy setup](#proxy-setup)). Two session cookies with different values get `400`. Callers outside `server.trusted_proxies`, or requests missing `X-Forwarded-Proto`/`Host`, get `401`. Never route it publicly. |
| GET | `/api/verify/nginx` | nginx, internally | The same checks and the same answers as `/api/verify`, except that not signed in is a plain `401` with the login address in `Location`, because nginx's `auth_request` accepts only `2xx`, `401` and `403` (see [nginx](#nginx)). Never route it publicly. |
| GET | `/login?rd=<url>` | Browser | The sign-in form. Already signed in: straight to `rd`. |
| POST | `/login` | Form | Checks CSRF, the account lockout, the username, the code (if the user has one) and then the password, cheapest first. Success sets the cookie and `303`s to `rd`. Wrong password: `401` and an amber message. Locked out: `429` and a red message. |
| GET | `/logout` | Browser | A "Sign out?" page. Apps link here. |
| POST | `/logout` | Form | Ends the session server-side and clears the cookie (CSRF-checked), then to `/login`. If `session.revocation_file` can't be written: `503`, the cookie is kept, and the page offers to try again. |
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

### Two-factor codes (TOTP)

Give a user an authenticator-app code by adding a secret to their table:

```sh
rs-auth totp-secret aaron     # prints the secret, an otpauth:// link and a QR code
```

```toml
[users.aaron]
totp_secret = "SWNACFK7XPDGQUMRNNVPJXVG3ICXR3Q4"
```

Type the secret into any authenticator app (or turn the link into a QR code
with any QR tool; rs-auth doesn't draw one). Codes are standard TOTP
(RFC 6238): SHA-1, 6 digits, 30 seconds. A code is accepted one step either
side of the current one, and each code works once per user; a code that is
older than one already used is refused too. The secret must be at least 16
bytes of base32.

- The sign-in form shows an "Authentication code" box when any user has a
  secret. Users without one leave it empty and it is ignored. A user with a
  secret must give the right code *and* the password.
- Anyone who can read `config.toml` can generate codes, so keep it private
  (`chmod 600`).
- Adding, changing or removing a user's secret ends that user's existing
  sessions, the same as changing their password.

Sign-in checks run cheapest first: the username, then the code, then the
Argon2 password hash. A sign-in that fails an earlier check never costs an
Argon2 hash. All failures show the same message ("Invalid username, password
or code" once any user has a secret).

### Access rules

Access is by group and closed by default. Each host that rs-auth guards needs
an `[access."<host>"]` table listing the groups that may open it:

```toml
[access."grafana.example.com"]
groups = ["admins"]

[access."photos.example.com"]
groups = ["family", "admins"]

[access."*.lab.example.com"]
groups = ["admins"]
```

- A user gets in if they are in **any** of the listed groups.
- A host with no entry gets `403` for everyone, signed in or not.
- `*.lab.example.com` covers every subdomain of `lab.example.com`, at any depth,
  but not `lab.example.com` itself. An exact host beats a wildcard, and a longer
  wildcard beats a shorter one, so the order of the tables doesn't matter.
- Hosts are matched without case, port or a trailing dot. They must sit inside
  `session.domain`, can't be the portal's own host, and can't be listed twice.
- Groups come from the config on every request, never from the session token,
  so taking someone out of a group locks them out of its hosts on their next
  request.
- `check-config` warns about a group that no user is in, and about a config
  with no `[access]` entries at all.

### Sessions

- The cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, set on
  `session.domain`, and lasts `session.expiry`.
- Verify always uses the user's **current** groups from the config. Removing a
  user from the config locks them out on their next request.
- Bump `session.version` to sign everyone out at once.
- Signing out revokes that session's token ID (`jti`), so a copied cookie stops
  working too. Set `session.revocation_file` to keep the list across restarts
  (see [Keeping sign-outs across restarts](#keeping-sign-outs-across-restarts)).
  The list holds up to 100,000 sign-outs. If it ever fills, it never forgets a
  revoked session: it raises a "not before" line to the start time of the oldest
  listed session and refuses every session that began at or before it. Those
  users sign in again; nobody signed out comes back.
- Each token carries a keyed fingerprint of the user's password hash, so
  changing a password ends that user's existing sessions.
- The browser sends a cookie set on `session.domain` to **every** host under
  that domain, not only to the apps behind rs-auth. Any host there (a sibling
  app, a staging box, a user-content subdomain) receives the session token and
  can replay it, or set its own cookie of the same name. rs-auth refuses a
  request carrying two different session cookies, and the proxy examples strip
  the cookie before the request reaches a protected app, but neither can stop a
  host outside the proxy from seeing it. Pick a `session.domain` whose hosts are
  all equally trusted, such as a dedicated `apps.example.com`, rather than a
  domain shared with anything you don't control.

### Keeping sign-outs across restarts

`session.revocation_file` must be on persistent, writable storage. rs-auth
checks at startup that it can write the file and refuses to start if not. If a
later write fails, the sign-out still takes effect in memory, but `POST /logout`
answers `503` instead of reporting success, keeps the browser's cookie, and
offers a retry. Every retry, and every later sign-out, rewrites the whole list,
so once the disk is writable again nothing is lost. Without a retry, a restart
forgets the unsaved sign-outs.

The Docker image runs as uid 65532 and has an empty `/data` owned by it, so a
named volume mounted there starts out writable:

```yaml
services:
  rs-auth:
    image: rs-auth
    volumes:
      - ./config.toml:/config/config.toml:ro
      - rs_auth_data:/data
volumes:
  rs_auth_data:
```

```toml
[session]
revocation_file = "/data/revoked.txt"
```

A bind mount works too if the host directory is owned by uid 65532
(`chown 65532:65532 ./data`).

Run **one** instance. Each rs-auth process keeps its own list in memory and
only reads the file at startup, so replicas, even sharing a volume, keep
independent revocation state: a session signed out on one replica keeps working
on the others until it expires. Sharing one file between replicas also lets
them overwrite each other's writes.

## Proxy setup

The examples in [`examples/traefik`](examples/traefik) (file provider, no
Docker socket), [`examples/caddy`](examples/caddy) and
[`examples/nginx`](examples/nginx) follow these rules, and
[`e2e`](e2e/README.md) checks them behind all three proxies:

- **Trust one address.** Give the proxy a fixed IP on a network it shares only
  with rs-auth, and put just that `/32` in `server.trusted_proxies`. Never trust
  a subnet that app containers can join.
- **Keep rs-auth and the apps private.** Only the proxy publishes ports. rs-auth
  and the apps sit on separate `internal` Docker networks, so apps can't reach
  rs-auth and nothing outside can reach either.
- **Don't route `/api/verify` publicly.** The portal route excludes it
  (Traefik: `!PathPrefix(`/api/verify`)`, Caddy: `respond @verify 404`, nginx:
  `location ^~ /api/verify { return 404; }`). The proxy's own forward-auth calls
  go straight to rs-auth and are unaffected.
- **Strip the session cookie.** List `Cookie` in Traefik's
  `authResponseHeaders`, Caddy's `copy_headers`, or nginx's
  `auth_request_set $auth_cookie $upstream_http_cookie` with
  `proxy_set_header Cookie $auth_cookie`. On success rs-auth returns the
  request's cookies minus its own, and the proxy replaces the request's `Cookie`
  header with that (or removes it if nothing is left), so the app keeps its own
  cookies but never sees the session token.
- **Drop header aliases.** Some app stacks treat `Remote_User` as
  `Remote-User`. Traefik's `--entrypoints.websecure.http.aliasHeadersStrategy=delete`
  removes such aliases at the public entry point; the Caddy examples delete
  `Remote_*` request headers; nginx drops headers with underscores unless you
  turn on `underscores_in_headers`, so leave that off.
- **Bound slow and greedy clients.** Traefik: `respondingTimeouts.readTimeout`
  (it has no separate header timeout, so this bounds headers and body together),
  `http.maxHeaderBytes`, and an `inFlightReq` limit per client IP on the entry
  point. Caddy: `timeouts { read_header read_body idle }`, `max_header_size`, and
  `max_conns_per_host` on the transports to rs-auth. nginx: `client_header_timeout`,
  `client_body_timeout`, `large_client_header_buffers` and `limit_conn` per client
  IP. Caddy has no built-in
  per-client connection limit; use a host firewall or a plugin if you need one.
- **Fail closed.** If rs-auth is down, all three proxies answer `5xx` and never pass
  the request to the app. The e2e suite checks this with the app healthy.

## nginx

nginx's `auth_request` is stricter than Traefik's `forwardAuth` and Caddy's
`forward_auth`: it accepts only `2xx`, `401` or `403` from the check and turns
every other status, redirects included, into a `500`. So nginx calls
`/api/verify/nginx`, which answers like `/api/verify` except that a user who
isn't signed in gets a plain `401` with the login address in a `Location`
header, and nginx sends the redirect itself (`302` for `GET` and `HEAD`, `303`
otherwise). The examples in [`examples/nginx`](examples/nginx) are two small
snippets:

- [`rs-auth-server.conf`](examples/nginx/rs-auth-server.conf), included once in
  each `server` block after `set $rs_auth http://rs-auth:9091;`, holds the
  internal address nginx asks and the redirect.
- [`rs-auth.conf`](examples/nginx/rs-auth.conf), included in each `location`
  that proxies to an app, runs the check and sets `Remote-User`,
  `Remote-Groups`, `Remote-Name`, `Remote-Email` and `Cookie` on the request to
  the app. Each `proxy_set_header` replaces whatever the client sent, and an
  empty value removes the header, so forged `Remote-*` headers never get through.

What to know:

- The host rs-auth checks comes from the `X-Forwarded-Host`, `-Proto` and `-Uri`
  headers the internal address sets from nginx's own `$http_host`, `$scheme` and
  `$request_uri`, never from what the client sent. Keep those three lines.
- A signed-in user who isn't allowed on a host gets rs-auth's "No access" page
  with a `403` (nginx asks the same internal address again for it). A `403` the
  app itself sends is passed through untouched.
- Two different session cookies make rs-auth answer `400`; nginx turns that
  into a `500`, so the request is still refused.
- Include `rs-auth.conf` in every `location` that proxies to an app. A location
  without it is not protected.
- `proxy_set_header` lines in a `location` replace the ones from its parent, so
  any you add must sit in the same `location` as the include.
- The examples use Docker's resolver (`resolver 127.0.0.11`) and a variable in
  `proxy_pass`, so nginx looks rs-auth up again when its container is replaced.
  Without Docker, point `resolver` at your DNS server or use a fixed address.
- Needs nginx 1.25.1 or newer for `http2 on;`; drop that line on older versions.

## Security notes

- Every failure shows the same message, so the page doesn't say whether the
  username, code or password was wrong. Sign-ins are checked cheapest first
  (username, code, then Argon2), so a failure before the password check
  answers faster than one after it. Someone timing responses can tell an
  unknown username, or a wrong code, from a wrong password. This is the price
  of never hashing for those requests.
- An account locks after `login.max_attempts` failed sign-ins within
  `login.window` (default 5 in 5 minutes). While it is locked, even the right
  password is refused. Attempts are counted before the password is checked, so
  parallel guesses can't get past the limit, and a successful sign-in doesn't
  count. Anyone who knows a username can use this to keep that account locked
  out, so pick the number with that in mind. Usernames are counted in 4,096
  keyed buckets, so unknown names lock out exactly like real ones and memory
  stays bounded. The page never shows attempts left or how long a lockout
  lasts, and no `Retry-After` is sent. There is no limit per client address:
  rate limiting belongs to your proxy, firewall or Authelia.
- The client IP comes from `X-Forwarded-For` only when the direct peer is a
  trusted proxy, reading right to left past trusted hops, so clients can't
  spoof it.
- `rd` must be https and on `session.domain` or a subdomain. Anything else
  falls back to the default page.
- Login and logout use double-submit CSRF tokens on top of `SameSite=Lax`.
- Pages send a strict CSP (only the hashed inline style and script),
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`.
- Argon2 runs on the blocking pool with at most 4 checks at once. Request
  bodies are capped at 16 KB and requests time out after 15 seconds.
- `#![forbid(unsafe_code)]`. Secrets and hashes never appear in logs.

## Development

```sh
cargo test                       # unit + end-to-end tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

For a full check behind a real Traefik, Caddy or nginx in Docker, see
[`e2e`](e2e/README.md):

```sh
docker compose -f e2e/traefik/docker-compose.yml build && sh e2e/run.sh traefik
```

For trying it locally over plain http, set `server.insecure_dev_mode: true`
and use a `*.localhost` portal URL. Never use dev mode in production.

## Running beside Authelia

rs-auth answers "is this a signed-in user in one of this host's groups". Rules
are per host only, with no path or method rules, and there is no second factor
or OIDC. Keep Authelia (or similar) in front of any route that needs MFA,
path-level rules, or serves OIDC clients.

## Not in v1

Path or method access rules, config hot reload, remember-me,
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
  has no shell. Trivy only inventories the distroless base: the static binary
  carries no package metadata, so the Rust crates are covered by `cargo audit`
  and `cargo deny`, not by the image scan.
- `cargo fuzz` on the hand-written parsers: cookie header, CLI args, redirect
  target and forwarded URL, `X-Forwarded-For`, token verification, and config
  validation (TOML parsing plus every rule above). Each target runs 60 s on
  pull requests and 15 min weekly. Run one locally with
  `cargo +nightly fuzz run cookie_header` from `fuzz/`.
