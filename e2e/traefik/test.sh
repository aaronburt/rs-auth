#!/bin/sh
# End-to-end checks of rs-auth behind Traefik. Runs inside the tester
# container; every request goes through Traefik over https, except the
# deliberate direct calls to rs-auth.
set -u

AUTH=https://auth.example.test
APP=https://whoami.example.test
OTHER=https://other.example.test
DIRECT=http://rs-auth:9091
TMP=$(mktemp -d)
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && echo "       $2"; }
check() { # check "name" actual expected
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi
}
contains() { # contains "name" file needle
  if grep -qiF -- "$3" "$2"; then ok "$1"; else bad "$1" "'$3' not found"; fi
}
lacks() { # lacks "name" file needle
  if grep -qiF -- "$3" "$2"; then bad "$1" "'$3' should not be there"; else ok "$1"; fi
}

# req OUT JAR [curl args...]: writes body to OUT.body, headers to OUT.head,
# and prints the status code. JAR may be "-" for no cookie jar.
req() {
  out=$1; jar=$2; shift 2
  if [ "$jar" = "-" ]; then
    curl -sk -o "$TMP/$out.body" -D "$TMP/$out.head" -w '%{http_code}' "$@"
  else
    curl -sk -b "$TMP/$jar" -c "$TMP/$jar" -o "$TMP/$out.body" -D "$TMP/$out.head" -w '%{http_code}' "$@"
  fi
}
header() { # header OUT name
  grep -i "^$2:" "$TMP/$1.head" | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
csrf_of() { # csrf_of OUT
  sed -n 's/.*name="csrf" value="\([0-9a-f]*\)".*/\1/p' "$TMP/$1.body" | head -n1
}

# sign_in JAR USER PASS RD -> prints status of the POST
sign_in() {
  touch "$TMP/$1"
  req loginpage "$1" "$AUTH/login" >/dev/null
  t=$(csrf_of loginpage)
  req signin "$1" -X POST "$AUTH/login" \
    --data-urlencode "username=$2" --data-urlencode "password=$3" \
    --data-urlencode "csrf=$t" --data-urlencode "rd=$4"
}

echo "Waiting for Traefik..."
i=0
until [ "$(curl -sk -o /dev/null -w '%{http_code}' $AUTH/healthz)" = 200 ]; do
  i=$((i + 1)); [ $i -gt 30 ] && { echo "Traefik never became ready"; exit 1; }
  sleep 1
done

echo
echo "1. Not signed in"
s=$(req anon - "$APP/some/path?x=1")
check "app redirects to login (302)" "$s" 302
check "redirect goes to the login page with rd" "$(header anon location)" \
  "$AUTH/login?rd=https%3A%2F%2Fwhoami.example.test%2Fsome%2Fpath%3Fx%3D1"
lacks "app content is not served" "$TMP/anon.body" "Hostname:"

s=$(req anonpost - -X POST "$APP/form")
check "POST to app redirects with 303" "$s" 303

s=$(req spoofhost - -H "X-Forwarded-Host: evil.net" -H "X-Forwarded-Proto: http" "$APP/")
check "spoofed X-Forwarded-Host cannot change rd" "$(header spoofhost location)" \
  "$AUTH/login?rd=https%3A%2F%2Fwhoami.example.test%2F"

s=$(req forged - -H "Remote-User: aaron" -H "Remote-Groups: admins" "$APP/")
check "forged Remote-User without a session is still redirected" "$s" 302

echo
echo "2. Login page"
s=$(req page - "$AUTH/login?rd=https%3A%2F%2Fwhoami.example.test%2F")
check "login page loads" "$s" 200
contains "shows the app being signed in to" "$TMP/page.body" "to continue to <strong>whoami.example.test</strong>"
contains "sends a Content-Security-Policy" "$TMP/page.head" "content-security-policy: default-src 'none'"
contains "is not cached" "$TMP/page.head" "cache-control: no-store"

echo
echo "3. Wrong password"
s=$(sign_in jar_wrong aaron not-the-password "")
check "wrong password is refused (401)" "$s" 401
contains "shows the generic message" "$TMP/signin.body" "Invalid username or password."
lacks "no session cookie is set" "$TMP/signin.head" "rs_auth_session="
s=$(sign_in jar_wrong nobody not-the-password "")
check "unknown user gets the same 401" "$s" 401

echo
echo "4. Sign in"
s=$(sign_in jar_aaron aaron aaron-test-pass "$APP/after-login")
check "correct password is accepted (303)" "$s" 303
check "browser is sent back to rd" "$(header signin location)" "$APP/after-login"
cookie=$(grep -i '^set-cookie: rs_auth_session=' "$TMP/signin.head" | tr -d '\r')
for attr in "Domain=example.test" "HttpOnly" "Secure" "SameSite=Lax" "Max-Age=3600"; do
  case "$cookie" in *"$attr"*) ok "cookie has $attr" ;; *) bad "cookie has $attr" "$cookie" ;; esac
done

echo
echo "5. Signed in"
s=$(req app1 jar_aaron "$APP/")
check "app is served (200)" "$s" 200
contains "app sees Remote-User" "$TMP/app1.body" "Remote-User: aaron"
contains "app sees Remote-Groups" "$TMP/app1.body" "Remote-Groups: admins,family"
contains "app sees Remote-Email" "$TMP/app1.body" "Remote-Email: aaron@example.test"
contains "app sees Remote-Name" "$TMP/app1.body" "Remote-Name: Aaron"

s=$(req app2 jar_aaron "$OTHER/")
check "a second app on another subdomain needs no new sign-in" "$s" 200

s=$(req app3 jar_aaron -H "Remote-User: root" -H "Remote-Groups: superusers" "$APP/")
check "forged headers with a session still pass" "$s" 200
lacks "forged Remote-User is replaced" "$TMP/app3.body" "Remote-User: root"
lacks "forged Remote-Groups is replaced" "$TMP/app3.body" "superusers"

s=$(req again jar_aaron "$AUTH/login?rd=https%3A%2F%2Fother.example.test%2F")
check "login page skips itself when signed in" "$s" 302
check "and goes to rd" "$(header again location)" "$OTHER/"

echo
echo "6. A user without an email cannot forge one"
s=$(sign_in jar_guest guest guest-test-pass "")
check "guest signs in" "$s" 303
s=$(req guestapp jar_guest -H "Remote-Email: boss@example.test" "$APP/")
check "guest sees the app" "$s" 200
contains "app sees guest" "$TMP/guestapp.body" "Remote-User: guest"
lacks "forged Remote-Email is not passed through" "$TMP/guestapp.body" "boss@example.test"

echo
echo "7. Direct calls that skip Traefik"
sess=$(grep rs_auth_session "$TMP/jar_aaron" | awk '{print $7}')
s=$(req direct - -H "Cookie: rs_auth_session=$sess" -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Host: whoami.example.test" -H "X-Forwarded-Uri: /" "$DIRECT/api/verify")
check "verify from an untrusted address is refused even with a valid cookie" "$s" 401
lacks "and leaks no user headers" "$TMP/direct.head" "remote-user"

echo
echo "8. Sign out"
s=$(req logoutpage jar_aaron "$AUTH/logout")
check "GET /logout shows the confirm page" "$s" 200
contains "asks first" "$TMP/logoutpage.body" "Sign out?"
s=$(req stillin jar_aaron "$APP/")
check "GET /logout alone does not sign out" "$s" 200
s=$(req logoutbad jar_aaron -X POST "$AUTH/logout" --data "csrf=")
check "POST /logout without a token is refused" "$s" 403
t=$(csrf_of logoutpage)
s=$(req logout jar_aaron -X POST "$AUTH/logout" --data "csrf=$t")
check "POST /logout with the token signs out" "$s" 303
s=$(req afterlogout jar_aaron "$APP/")
check "app redirects to login again" "$s" 302
s=$(req reuse - -H "Cookie: rs_auth_session=$sess" "$APP/")
check "the old token still works until expiry (stateless, by design)" "$s" 200

echo
echo "9. Rate limit (run last: it locks out this container's IP)"
touch "$TMP/jar_rl"
req rlpage jar_rl "$AUTH/login" >/dev/null
t=$(csrf_of rlpage)
n=1
while [ $n -le 5 ]; do
  req rl jar_rl -X POST "$AUTH/login" -H "X-Forwarded-For: 10.0.0.$n" \
    --data-urlencode "username=aaron" --data-urlencode "password=wrong-$n" --data-urlencode "csrf=$t" >/dev/null
  n=$((n + 1))
done
s=$(req rl jar_rl -X POST "$AUTH/login" -H "X-Forwarded-For: 10.0.0.99" \
  --data-urlencode "username=aaron" --data-urlencode "password=aaron-test-pass" --data-urlencode "csrf=$t")
check "after 5 failures even the right password is refused (429)" "$s" 429
contains "shows the locked-out message" "$TMP/rl.body" "Too many sign-in attempts"
lacks "sends no Retry-After" "$TMP/rl.head" "retry-after"
lacks "sets no session cookie" "$TMP/rl.head" "rs_auth_session="

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
