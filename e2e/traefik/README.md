# Traefik end-to-end test

Spins up Traefik v3, rs-auth (built from this repo) and a `whoami` app in
Docker, then runs [`test.sh`](test.sh) from a curl container against it. Every
request goes through Traefik over https, the way a browser would.

```sh
docker compose -f e2e/traefik/docker-compose.yml up --build --abort-on-container-exit --exit-code-from tester
docker compose -f e2e/traefik/docker-compose.yml down
```

The exit code is 0 when every check passes. The first run compiles rs-auth
inside Docker, which takes a few minutes.

## What it checks

1. Not signed in: apps redirect to the login page with the right `rd`,
   POSTs get 303, a client-sent `X-Forwarded-Host` can't change `rd`, and
   forged `Remote-User` headers don't get you in.
2. The login page loads with its CSP and `no-store`.
3. A wrong password or unknown user gets the same 401 and no cookie.
4. Signing in sets a `Domain=example.test; HttpOnly; Secure; SameSite=Lax`
   cookie and returns to `rd`.
5. Signed in: both apps are served without signing in again, they see the
   `Remote-*` headers, and forged `Remote-*` headers are replaced.
6. A user with no email can't smuggle in a forged `Remote-Email`.
7. Calling rs-auth directly, skipping Traefik, is refused even with a valid
   cookie (`trusted_proxies` only lists Traefik's address).
8. `GET /logout` only asks. `POST /logout` needs its CSRF token and then
   signs out. A copied token keeps working until it expires, because v1
   sessions are stateless; bump `session.version` to cut them all off.
9. Five failed sign-ins lock the client out with a 429 and no `Retry-After`,
   even with a rotating `X-Forwarded-For`.

## Trying it in a browser

Add this to your hosts file
(`C:\Windows\System32\drivers\etc\hosts` or `/etc/hosts`):

```
127.0.0.1 auth.example.test whoami.example.test other.example.test
```

Start it with `docker compose -f e2e/traefik/docker-compose.yml up --build rs-auth traefik whoami`,
then open https://whoami.example.test:8443 and accept the self-signed
certificate. Sign in as `aaron` / `aaron-test-pass` or `guest` / `guest-test-pass`.
