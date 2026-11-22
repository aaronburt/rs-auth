# End-to-end tests

The same checks, [`test.sh`](test.sh), run against rs-auth behind two real
proxies in Docker:

- [`traefik/`](traefik): Traefik 3.7 with its `forwardAuth` middleware and
  the file provider.
- [`caddy/`](caddy): Caddy 2.11 with `forward_auth` and `copy_headers`.

Each setup runs rs-auth (built from this repo) with its sign-out list on a
volume, a second rs-auth with an edited config
([`config-changed.toml`](config-changed.toml)) to stand in for a restart, a
`whoami` app, and curl containers that run the checks over https, the way a
browser would. The networks match the examples: only the proxy is on `edge`,
rs-auth is on the internal `auth` network where the proxy has the fixed
address 172.30.1.10 (the only trusted proxy), and the app is on the internal
`apps` network.

```sh
docker compose -f e2e/traefik/docker-compose.yml build
sh e2e/run.sh traefik
docker compose -f e2e/traefik/docker-compose.yml --profile phases down -v
# or caddy
```

[`run.sh`](run.sh) runs four phases and exits 0 when every check passes:

- **main**: `test.sh` from a tester that joins all three networks, so it can
  also act as an untrusted neighbour.
- **outside**: `test.sh outside` from a container only on `edge`. rs-auth and
  the app can't be reached; the proxy can, and its portal does not serve
  `/api/verify`.
- **restart**: rs-auth is restarted, then `test.sh restart` checks that a
  cookie signed out before the restart is still refused and a live one still
  works.
- **outage**: rs-auth is stopped while the app stays up, then `test.sh outage`
  checks the app answers when called directly but every protected request
  through the proxy (valid cookie, no cookie, forged `Remote-*` headers) gets a
  `5xx` and no app content.

The first build compiles rs-auth inside Docker, which takes a few minutes.
Both setups use the same subnets, so run one at a time. CI runs both on every
push and pull request in the `e2e` job of
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml), and prints the
container logs if a check fails.

## What it checks

1. Not signed in: apps redirect to the login page with the right `rd`,
   POSTs get 303, a client-sent `X-Forwarded-Host` can't change `rd`, and
   forged `Remote-User` headers don't get you in.
2. The login page loads with its CSP and `no-store`.
3. A wrong password or unknown user gets the same 401 and no cookie.
4. Signing in sets a `Domain=example.test; HttpOnly; Secure; SameSite=Lax`
   cookie and returns to `rd`.
5. Signed in: both apps are served without signing in again, they see the
   `Remote-*` headers, and client-sent `Remote-*` headers are replaced.
6. A user with no email can't smuggle in a forged `Remote-Email`.
7. Calling rs-auth directly, skipping the proxy, is refused even with a valid
   cookie (`trusted_proxies` only lists the proxy's fixed address).
8. Open redirects: about 20 hostile `rd` values (other domains, lookalikes,
   `http`, userinfo, `//evil`, backslashes, encoded tricks, `javascript:`,
   `data:`) all land on the portal, both when already signed in and right
   after signing in. A valid `rd` inside the domain still works.
9. CSRF on sign-in: no token, a wrong token, a token without its cookie, and
   a planted cookie without the `__Host-` prefix are all refused with 403 and
   no session.
10. Config edited and rs-auth restarted: an unchanged user keeps their
    session, a password change ends the old session, and a removed user is
    signed out.
11. `GET /logout` only asks. `POST /logout` needs its CSRF token and then
    signs out. A copied cookie stops working after sign-out.
12. The portal answers `404` for `/api/verify` and ten path variants
    (`//api/verify`, `/api/./verify`, `/api/%76erify`, `/API/verify`, ...)
    with no `Remote-*` headers, while forward-auth through the proxy still works.
13. The app gets its own cookies but never the session cookie or token; with
    only the session cookie it gets no `Cookie` header at all. Two different
    session cookies get `400`. Underscore aliases like `Remote_User` never
    reach the app.
14. Access rules: a host with no `[access]` entry gets 403 for everyone,
    with no sign-in redirect. On `admins.example.test` (admins only) aaron
    gets in and carol (family only) gets the 403 "No access" page, even with
    forged `Remote-Groups`. `*.lab.example.test` lets admins into
    `x.lab.example.test` but not `lab.example.test` itself, and the 403 page
    keeps its CSP through the proxy.
15. Authentication codes: `dave` has a TOTP secret. The password alone, or
    with a wrong code, is refused with the same message as any other failure;
    a right code with a wrong password is refused without using the code up;
    password and code together sign in and reach the app; the same code, or an
    older one, can't sign in again. A user without a secret ignores the code
    box.
16. Ten failed sign-ins lock the client out with a 429 and no `Retry-After`,
    even with a rotating `X-Forwarded-For`.

## Trying it in a browser

Add this to your hosts file
(`C:\Windows\System32\drivers\etc\hosts` or `/etc/hosts`):

```
127.0.0.1 auth.example.test whoami.example.test other.example.test admins.example.test x.lab.example.test
```

Start it with `docker compose -f e2e/traefik/docker-compose.yml up --build rs-auth traefik whoami`,
then open https://whoami.example.test:8443 and accept the self-signed
certificate. Sign in as `aaron` / `aaron-test-pass`, `guest` / `guest-test-pass`,
`carol` / `carol-test-pass` or `dave` / `dave-test-pass` (dave also needs a code:
the secret is in `config.toml`).
