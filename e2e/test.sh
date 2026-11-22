#!/bin/sh
set -u

MODE=${1:-main}
AUTH=https://auth.example.test
APP=https://whoami.example.test
OTHER=https://other.example.test
DIRECT=http://rs-auth:9091
CHANGED_SITE=https://changed.example.test
BACKEND=http://whoami:80
STATE=/state
TMP=$(mktemp -d)
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && echo "       $2"; }
check() {
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi
}
contains() {
  if grep -qiF -- "$3" "$2"; then ok "$1"; else bad "$1" "'$3' not found"; fi
}
lacks() {
  if grep -qiF -- "$3" "$2"; then bad "$1" "'$3' should not be there"; else ok "$1"; fi
}

req() {
  out=$1; jar=$2; shift 2
  if [ "$jar" = "-" ]; then
    curl -sk -o "$TMP/$out.body" -D "$TMP/$out.head" -w '%{http_code}' "$@"
  else
    curl -sk -b "$TMP/$jar" -c "$TMP/$jar" -o "$TMP/$out.body" -D "$TMP/$out.head" -w '%{http_code}' "$@"
  fi
}
header() {
  grep -i "^$2:" "$TMP/$1.head" | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
csrf_of() {
  sed -n 's/.*name="csrf" value="\([0-9a-f]*\)".*/\1/p' "$TMP/$1.body" | head -n1
}

sign_in() {
  touch "$TMP/$1"
  req loginpage "$1" "$AUTH/login" >/dev/null
  t=$(csrf_of loginpage)
  req signin "$1" -X POST "$AUTH/login" \
    --data-urlencode "username=$2" --data-urlencode "password=$3" \
    --data-urlencode "csrf=$t" --data-urlencode "rd=$4"
}

code() {
  curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$@"
}
finish() {
  echo
  echo "$PASS passed, $FAIL failed"
  [ "$FAIL" -eq 0 ]
  exit
}
wait_ready() {
  i=0
  until [ "$(code $AUTH/healthz)" = 200 ]; do
    i=$((i + 1)); [ $i -gt 30 ] && { echo "The proxy never became ready"; exit 1; }
    sleep 1
  done
}

if [ "$MODE" = outside ]; then
  echo "From a host that is only on the proxy's public network"
  check "rs-auth cannot be reached directly" "$(code $DIRECT/healthz)" 000
  check "the app cannot be reached directly" "$(code $BACKEND/)" 000
  check "the app is reached through the proxy (302 to sign in)" "$(code $APP/)" 302
  check "the portal is reached through the proxy" "$(code $AUTH/login)" 200
  check "the portal does not serve /api/verify" "$(code $AUTH/api/verify)" 404
  finish
fi

if [ "$MODE" = restart ]; then
  echo "After rs-auth restarted"
  wait_ready
  s=$(req rsrevoked - -H "Cookie: rs_auth_session=$(cat $STATE/revoked)" "$APP/")
  check "a cookie signed out before the restart is still refused" "$s" 302
  s=$(req rslive - -H "Cookie: rs_auth_session=$(cat $STATE/live)" "$APP/")
  check "a session that was not signed out still works" "$s" 200
  finish
fi

if [ "$MODE" = outage ]; then
  echo "rs-auth is stopped and the app is healthy"
  check "the app answers when called directly" "$(code $BACKEND/)" 200
  check "rs-auth is down" "$(code $DIRECT/healthz)" 000
  for site in "$APP" "$OTHER" "$CHANGED_SITE"; do
    s=$(req outlive - -H "Cookie: rs_auth_session=$(cat $STATE/live)" "$site/")
    [ "$s" -ge 500 ] && ok "$site with a valid session is refused ($s)" || bad "$site with a valid session is refused" "got $s"
    lacks "and the app content is not served" "$TMP/outlive.body" "Hostname:"
    s=$(req outanon - "$site/")
    [ "$s" -ge 500 ] && ok "$site without a session is refused ($s)" || bad "$site without a session is refused" "got $s"
    lacks "and the app content is not served" "$TMP/outanon.body" "Hostname:"
    s=$(req outforged - -H "Remote-User: aaron" -H "Remote-Groups: admins" "$site/")
    [ "$s" -ge 500 ] && ok "$site with forged Remote-* headers is refused ($s)" || bad "$site with forged Remote-* headers is refused" "got $s"
    lacks "and the app content is not served" "$TMP/outforged.body" "Hostname:"
  done
  finish
fi

echo "Waiting for the proxy..."
wait_ready

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
echo "7. Direct calls that skip the proxy"
sess=$(grep rs_auth_session "$TMP/jar_aaron" | awk '{print $7}')
s=$(req direct - -H "Cookie: rs_auth_session=$sess" -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Host: whoami.example.test" -H "X-Forwarded-Uri: /" "$DIRECT/api/verify")
check "verify from an untrusted address is refused even with a valid cookie" "$s" 401
lacks "and leaks no user headers" "$TMP/direct.head" "remote-user"

echo
echo "8. Open redirects through rd"
LANDING="$AUTH/logged-in"
while IFS= read -r rd; do
  [ -z "$rd" ] && continue
  s=$(req rdbad jar_aaron -G "$AUTH/login" --data-urlencode "rd=$rd")
  check "signed in, rd=$rd lands on the portal" "$(header rdbad location)" "$LANDING"
  s=$(req rdpage - -G "$AUTH/login" --data-urlencode "rd=$rd")
  lacks "login page does not offer rd=$rd" "$TMP/rdpage.body" "to continue to"
done <<'EOF_RD'
https://evil.net/
https://evil.net
https://whoami.example.test.evil.net/
https://evilexample.test/
https://example.test.evil.net/
http://whoami.example.test/
https://aaron@evil.net/
https://whoami.example.test@evil.net/
https://user:pass@whoami.example.test/
//evil.net/
///evil.net/
/\evil.net/
https:evil.net
https://evil.net%2F.example.test/
https://evil.net\.example.test/
https://evil.net#.example.test
https://evil.net?.example.test
javascript:alert(1)//.example.test
data:text/html,<script>alert(1)</script>
 https://evil.net/
https://%65vil.net/
EOF_RD
s=$(sign_in jar_rd carol carol-test-pass "https://evil.net/")
check "sign-in with a foreign rd still succeeds" "$s" 303
check "but lands on the portal, not the foreign site" "$(header signin location)" "$LANDING"
s=$(req rdgood jar_aaron -G "$AUTH/login" --data-urlencode "rd=https://other.example.test/x?y=1")
check "a valid rd inside the domain is still honoured" "$(header rdgood location)" "https://other.example.test/x?y=1"

echo
echo "9. CSRF on sign-in"
touch "$TMP/jar_csrf"
req csrfpage jar_csrf "$AUTH/login" >/dev/null
s=$(req nocsrf jar_csrf -X POST "$AUTH/login" \
  --data-urlencode "username=carol" --data-urlencode "password=carol-test-pass")
check "sign-in without a CSRF token is refused (403)" "$s" 403
lacks "and sets no session cookie" "$TMP/nocsrf.head" "rs_auth_session="
s=$(req badcsrf jar_csrf -X POST "$AUTH/login" \
  --data-urlencode "username=carol" --data-urlencode "password=carol-test-pass" \
  --data-urlencode "csrf=0000000000000000000000000000000000000000000000000000000000000000")
check "sign-in with a wrong CSRF token is refused (403)" "$s" 403
lacks "and sets no session cookie" "$TMP/badcsrf.head" "rs_auth_session="
t=$(csrf_of csrfpage)
s=$(req nocookie - -X POST "$AUTH/login" \
  --data-urlencode "username=carol" --data-urlencode "password=carol-test-pass" \
  --data-urlencode "csrf=$t")
check "a stolen token without its cookie is refused (403)" "$s" 403
s=$(req planted - -X POST "$AUTH/login" -H "Cookie: rs_auth_csrf=$t" \
  --data-urlencode "username=carol" --data-urlencode "password=carol-test-pass" \
  --data-urlencode "csrf=$t")
check "a planted cookie without the __Host- prefix is refused (403)" "$s" 403

echo
echo "10. Config edited and rs-auth restarted"
s=$(sign_in jar_carol carol carol-test-pass "")
check "carol signs in" "$s" 303
s=$(req chcarol jar_carol "$CHANGED_SITE/")
check "an unchanged user keeps their session after the restart" "$s" 200
contains "and is still carol" "$TMP/chcarol.body" "Remote-User: carol"
s=$(req chaaron jar_aaron "$CHANGED_SITE/")
check "a password change ends the old session" "$s" 302
s=$(req chguest jar_guest "$CHANGED_SITE/")
check "removing a user ends their session" "$s" 302
s=$(req stillok jar_aaron "$APP/")
check "the same cookie still works where the password did not change" "$s" 200

echo
echo "11. Sign out"
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
check "a copied cookie stops working after sign-out (revoked)" "$s" 302
mkdir -p "$STATE"
printf '%s' "$sess" > "$STATE/revoked"
grep rs_auth_session "$TMP/jar_carol" | awk '{print $7}' | tr -d '\n' > "$STATE/live"

echo
echo "12. The portal does not expose /api/verify"
live=$(cat "$STATE/live")
for path in /api/verify "/api/verify?x=1" /api/verify/ /API/verify //api/verify /api//verify /api/./verify /api/%76erify /api%2Fverify /x/../api/verify; do
  s=$(req pubverify - -H "Cookie: rs_auth_session=$live" -H "X-Forwarded-Host: whoami.example.test" "$AUTH$path")
  case "$s" in 200|302|303|401) bad "public $path is refused" "got $s" ;; *) ok "public $path is refused ($s)" ;; esac
  lacks "and $path leaks no user headers" "$TMP/pubverify.head" "remote-user"
done
s=$(req pubhead - -I -H "Cookie: rs_auth_session=$live" "$AUTH/api/verify")
check "HEAD /api/verify on the portal is refused" "$s" 404
s=$(req stillworks - -H "Cookie: rs_auth_session=$live" "$APP/")
check "forward-auth through the proxy still works" "$s" 200

echo
echo "13. The session cookie stays out of the app"
s=$(req cookies - -H "Cookie: app_pref=keep; rs_auth_session=$live; app_other=2" "$APP/")
check "signed in with app cookies (200)" "$s" 200
contains "the app gets its own cookies" "$TMP/cookies.body" "Cookie: app_pref=keep; app_other=2"
lacks "the app never sees the session cookie" "$TMP/cookies.body" "rs_auth_session"
lacks "or the token" "$TMP/cookies.body" "$live"
s=$(req onlysession - -H "Cookie: rs_auth_session=$live" "$APP/")
check "signed in with only the session cookie (200)" "$s" 200
lacks "the app gets no Cookie header at all" "$TMP/onlysession.body" "Cookie:"
s=$(req forgedcookie - -H "Cookie: rs_auth_session=$live" -H "Cookie: app_pref=x" "$APP/")
check "two Cookie headers are handled (200)" "$s" 200
lacks "and the session cookie is still removed" "$TMP/forgedcookie.body" "rs_auth_session"
s=$(req dup - -H "Cookie: rs_auth_session=$live; rs_auth_session=planted.by.a.sibling" "$APP/")
check "two different session cookies are refused (400)" "$s" 400
lacks "and the app content is not served" "$TMP/dup.body" "Hostname:"
s=$(req dupsame - -H "Cookie: rs_auth_session=$live; rs_auth_session=$live" "$APP/")
check "the same session cookie twice is fine (200)" "$s" 200
s=$(req alias - -H "Cookie: rs_auth_session=$live" -H "Remote_User: aaron" -H "Remote_Groups: admins" "$APP/")
check "signed in as carol with underscore Remote_* headers (200)" "$s" 200
contains "the app sees carol" "$TMP/alias.body" "Remote-User: carol"
lacks "Remote_User does not reach the app" "$TMP/alias.body" "Remote_User"
lacks "Remote_Groups does not reach the app" "$TMP/alias.body" "Remote_Groups"
lacks "the forged admins group does not reach the app" "$TMP/alias.body" "admins"

echo
echo "14. Access rules: only listed groups, everything else 403"
ADMINS=https://admins.example.test
LAB=https://x.lab.example.test
s=$(req acanon - "https://unlisted.example.test/")
check "a host with no rule is refused without sign-in (403)" "$s" 403
contains "and says it is not open to anyone" "$TMP/acanon.body" "is not open to anyone"
lacks "and the app content is not served" "$TMP/acanon.body" "Hostname:"
contains "the 403 page keeps its Content-Security-Policy" "$TMP/acanon.head" "content-security-policy: default-src 'none'"
s=$(req acanonadm - "$ADMINS/")
check "a listed host sends anonymous users to sign in (302)" "$s" 302
s=$(sign_in jar_admin aaron aaron-test-pass "")
check "aaron (admins, family) signs in" "$s" 303
s=$(req acadm jar_admin "$ADMINS/")
check "admins can open the admins host" "$s" 200
contains "and the app sees aaron" "$TMP/acadm.body" "Remote-User: aaron"
s=$(req aclab jar_admin "$LAB/")
check "admins can open a host under the *.lab wildcard" "$s" 200
s=$(req aclabroot jar_admin "https://lab.example.test/")
check "the wildcard does not cover lab.example.test itself (403)" "$s" 403
s=$(req acunl jar_admin "https://unlisted.example.test/")
check "even admins get 403 on a host with no rule" "$s" 403
contains "the 403 page names the signed-in user" "$TMP/acunl.body" "signed in as <strong>aaron</strong>"
contains "and links to sign out on the portal" "$TMP/acunl.body" "href=\"$AUTH/logout\""
s=$(req acfam - -H "Cookie: rs_auth_session=$live" "$ADMINS/")
check "carol (family only) is refused on the admins host (403)" "$s" 403
contains "with the no-access page" "$TMP/acfam.body" "does not have access to <strong>admins.example.test</strong>"
lacks "and the app content is not served" "$TMP/acfam.body" "Hostname:"
s=$(req acfamforged - -H "Cookie: rs_auth_session=$live" -H "Remote-Groups: admins" -H "Remote-User: aaron" "$ADMINS/")
check "forged Remote-Groups does not get carol in (403)" "$s" 403
s=$(req acfamlab - -H "Cookie: rs_auth_session=$live" "$LAB/")
check "carol is refused under the *.lab wildcard (403)" "$s" 403
s=$(req acfamapp - -H "Cookie: rs_auth_session=$live" "$APP/")
check "carol still opens a family host (200)" "$s" 200

echo
echo "15. Rate limit (run last: it locks out this container's IP)"
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

finish
