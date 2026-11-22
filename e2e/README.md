# End-to-end tests

The same checks, [`test.sh`](test.sh), run against rs-auth behind two real
proxies in Docker:

- [`traefik/`](traefik): Traefik v3 with its `forwardAuth` middleware.
- [`caddy/`](caddy): Caddy 2 with `forward_auth` and `copy_headers`.

Each setup runs rs-auth (built from this repo), a second rs-auth with an edited
config ([`config-changed.toml`](config-changed.toml)) to stand in for a restart,
a `whoami` app, and a curl container that runs the checks over https, the way a
browser would.

```sh
docker compose -f e2e/traefik/docker-compose.yml up --build --abort-on-container-exit --exit-code-from tester
docker compose -f e2e/traefik/docker-compose.yml down -v
# or e2e/caddy/docker-compose.yml
```

The exit code is 0 when every check passes. The first run compiles rs-auth
inside Docker, which takes a few minutes. Both setups use the same subnet, so
run one at a time. CI runs both on every push and pull request in the `e2e`
job of [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), and prints
the container logs if a check fails.

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
   cookie (`trusted_proxies` only lists the proxy's address).
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
12. Five failed sign-ins lock the client out with a 429 and no `Retry-After`,
    even with a rotating `X-Forwarded-For`.

## Trying it in a browser

Add this to your hosts file
(`C:\Windows\System32\drivers\etc\hosts` or `/etc/hosts`):

```
127.0.0.1 auth.example.test whoami.example.test other.example.test
```

Start it with `docker compose -f e2e/traefik/docker-compose.yml up --build rs-auth traefik whoami`,
then open https://whoami.example.test:8443 and accept the self-signed
certificate. Sign in as `aaron` / `aaron-test-pass`, `guest` / `guest-test-pass`
or `carol` / `carol-test-pass`.
