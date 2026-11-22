#!/bin/sh
set -eu

proxy=${1:?usage: e2e/run.sh traefik|caddy}
cd "$(dirname "$0")/.."
compose="docker compose -f e2e/$proxy/docker-compose.yml ${E2E_COMPOSE_EXTRA:-}"
status=0

phase() {
  echo
  echo "=== $1"
}

phase "Start $proxy, rs-auth and the app"
$compose up -d --wait "$proxy" rs-auth rs-auth-changed whoami

phase "Main checks"
$compose run --rm --no-deps tester || status=1

phase "From outside: only the proxy is reachable"
$compose run --rm --no-deps outsider || status=1

phase "rs-auth restarted: sign-outs were saved to its volume"
$compose restart rs-auth
$compose up -d --wait rs-auth
$compose run --rm --no-deps tester restart || status=1

phase "rs-auth stopped while the app stays healthy"
$compose stop rs-auth rs-auth-changed
$compose run --rm --no-deps tester outage || status=1

if [ "$status" -ne 0 ]; then
  phase "Logs"
  $compose logs --no-color
fi
exit "$status"
