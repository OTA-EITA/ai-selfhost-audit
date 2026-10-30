#!/usr/bin/env bash
# Live probes against one platform started from its official compose file.
# Meant to run ONLY on a disposable GitHub-hosted runner from
# .github/workflows/ai-lab.yml. Every port is bound to 127.0.0.1 there.
#
# Usage: probe.sh <product> <compose dir> <override file> <results.md>
set -uo pipefail

PRODUCT=$1
DIR=$2
OVERRIDE=$3
OUT=$4
cd "$DIR" || exit 2

dc() { docker compose -p lab -f "$(ls docker-compose.y*ml | head -1)" -f "$OVERRIDE" "$@"; }

{
  echo "| Probe | Expected | Observed | Result |"
  echo "|---|---|---|---|"
} > "$OUT"
row() {
  local mark
  case $4 in pass) mark="as expected" ;; fail) mark="**differs**" ;; *) mark="info" ;; esac
  printf '| %s | %s | `%s` | %s |\n' "$1" "$2" "$3" "$mark" >> "$OUT"
}
check() { if [ "$2" = "$3" ]; then row "$1" "$2" "$3" pass; else row "$1" "$2" "$3" fail; fi; }

# code METHOD URL [curl args...] -> HTTP status; body saved in body.json
code() {
  local m=$1 u=$2
  shift 2
  curl -s -o body.json -w '%{http_code}' --max-time 20 -X "$m" "$u" "$@" || true
}
# snip -> first 80 characters of the last response body, on one line
snip() { tr -d '\n\r|`' < body.json 2>/dev/null | cut -c1-80; }
logs_if_down() { # service: print recent logs to stderr when the service never came up
  echo "--- $1 logs ---" >&2
  dc logs --tail 60 "$1" >&2 2>&1 || true
}
wait_json() { # url jq-filter tries: wait until the URL returns JSON matching the filter
  for _ in $(seq 1 "${3:-60}"); do
    curl -s --max-time 5 "$1" 2>/dev/null | jq -e "$2" >/dev/null 2>&1 && return 0
    sleep 5
  done
  return 1
}
wait_for() { # url expected-code tries
  for _ in $(seq 1 "${3:-60}"); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" || true)" = "$2" ] && return 0
    sleep 5
  done
  return 1
}
psql_as() { # service user password db -> "ok" when a password login over TCP works
  if dc exec -T -e PGPASSWORD="$3" "$1" psql -h 127.0.0.1 -U "$2" -d "$4" -tAc 'select 1' 2>/dev/null | grep -q 1; then echo ok; else echo refused; fi
}
upstream_host_ip() { # service -> host_ip of the first published port in the unmodified compose file
  docker compose -p lab -f "$(ls docker-compose.y*ml | head -1)" config --format json |
    jq -r --arg s "$1" '.services[$s].ports[0].host_ip // "(all interfaces)"'
}

case $PRODUCT in
n8n)
  B=http://127.0.0.1:5678
  row "Upstream compose: n8n port host_ip" "(all interfaces)" "$(upstream_host_ip n8n)" info
  check "Bare '- POSTGRES_PASSWORD' resolved from .env" "changePassword" \
    "$(dc config --format json | jq -r '.services.postgres.environment.POSTGRES_PASSWORD // "unset"')"
  wait_json "$B/rest/settings" '.data' 90 || logs_if_down n8n
  code GET "$B/rest/settings" >/dev/null
  check "GET /rest/settings: showSetupOnFirstLoad (no login)" "true" "$(jq -r '.data.userManagement.showSetupOnFirstLoad' body.json 2>/dev/null)"
  owner='{"email":"lab-owner@example.com","firstName":"Lab","lastName":"Owner","password":"Lab-Owner-Passw0rd"}'
  c=$(code POST "$B/rest/owner/setup" -H 'content-type: application/json' -d "$owner")
  check "POST /rest/owner/setup without login (first visitor)" "200" "$c"
  row "  response" "owner user" "$(jq -r '.data.role // .data.email // empty' body.json 2>/dev/null) $(snip | cut -c1-40)" info
  c=$(code POST "$B/rest/owner/setup" -H 'content-type: application/json' -d "$owner")
  check "POST /rest/owner/setup again" "400" "$c"
  row "  response" "already set up" "$(snip)" info
  c=$(code GET "$B/rest/workflows")
  check "GET /rest/workflows without login" "401" "$c"
  row "  response" "Unauthorized" "$(snip)" info
  check "Postgres login with the example password changePassword" "ok" "$(psql_as postgres changeUser changePassword n8n)"
  ;;
openwebui)
  B=http://127.0.0.1:3000
  row "Upstream compose: open-webui port host_ip" "(all interfaces)" "$(upstream_host_ip open-webui)" info
  wait_for "$B/health" 200 90 || echo "open-webui did not become healthy" >&2
  code GET "$B/api/config" >/dev/null
  check "GET /api/config: onboarding (no login)" "true" "$(jq -r '.onboarding' body.json 2>/dev/null)"
  c=$(code POST "$B/api/v1/auths/signup" -H 'content-type: application/json' -d '{"name":"first","email":"first@example.com","password":"Lab-First-Passw0rd"}')
  check "POST /api/v1/auths/signup (first visitor): role" "admin" "$(jq -r '.role' body.json 2>/dev/null)"
  check "POST /api/v1/auths/signup (second visitor)" "403" "$(code POST "$B/api/v1/auths/signup" -H 'content-type: application/json' -d '{"name":"second","email":"second@example.com","password":"Lab-Second-Passw0rd"}')"
  row "First signup HTTP status" "200" "$c" info
  ;;
flowise)
  B=http://127.0.0.1:3000
  row "Upstream compose: flowise port host_ip" "(all interfaces)" "$(upstream_host_ip flowise)" info
  wait_for "$B/api/v1/ping" 200 90 || logs_if_down flowise
  code POST "$B/api/v1/auth/resolve" >/dev/null
  check "POST /api/v1/auth/resolve (no login)" "/organization-setup" "$(jq -r '.redirectUrl' body.json 2>/dev/null)"
  reg() { code POST "$B/api/v1/account/register" -H 'content-type: application/json' -d "{\"user\":{\"name\":\"$1\",\"email\":\"$1@example.com\",\"credential\":\"Lab-$1-Passw0rd!\"}}"; }
  check "POST /api/v1/account/register (first visitor)" "201" "$(reg first)"
  c=$(reg second)
  row "POST /api/v1/account/register (second visitor)" "4xx" "$c $(jq -r '.message // .error // empty' body.json 2>/dev/null | head -c 80)" info
  code GET "$B/api/v1/ip" -H 'X-Forwarded-For: 203.0.113.9' >/dev/null
  check "GET /api/v1/ip with X-Forwarded-For (TRUST_PROXY unset)" "203.0.113.9" "$(jq -r '.ip' body.json 2>/dev/null)"
  ;;
langflow)
  B=http://127.0.0.1:7860
  row "Upstream compose: langflow port host_ip" "(all interfaces)" "$(upstream_host_ip langflow)" info
  row "Upstream compose: postgres port host_ip" "(all interfaces)" "$(upstream_host_ip postgres)" info
  wait_for "$B/health" 200 90 || echo "langflow did not become healthy" >&2
  check "GET /api/v1/auto_login (image default)" "403" "$(code GET "$B/api/v1/auto_login")"
  check "Postgres login with the example password langflow" "ok" "$(psql_as postgres langflow langflow langflow)"
  printf 'services:\n  langflow:\n    environment:\n      - LANGFLOW_AUTO_LOGIN=true\n' > auto-login.yaml
  docker compose -p lab -f "$(ls docker-compose.y*ml | head -1)" -f "$OVERRIDE" -f auto-login.yaml up -d --no-deps --force-recreate langflow >/dev/null 2>&1
  wait_for "$B/health" 200 90
  c=$(code GET "$B/api/v1/auto_login")
  check "GET /api/v1/auto_login with LANGFLOW_AUTO_LOGIN=true" "200" "$c"
  row "auto_login returned an access token" "yes" "$(jq -r 'if .access_token then "yes" else "no" end' body.json 2>/dev/null)" info
  ;;
litellm)
  B=http://127.0.0.1:4000
  row "Upstream compose: litellm port host_ip" "(all interfaces)" "$(upstream_host_ip litellm)" info
  row "Upstream compose: db port host_ip" "(all interfaces)" "$(upstream_host_ip db)" info
  sleep 20
  row "litellm with the .env.example as is (empty master key)" "refuses to start" \
    "$(dc logs litellm 2>&1 | grep 'refused to start:' | grep -v '{' | grep -o -m1 'refused to start: [^.]*' || dc ps -a litellm --format '{{.State}}')" info
  check "Postgres login with the example password dbpassword9090" "ok" "$(psql_as db llmproxy dbpassword9090 litellm)"
  key="sk-$(openssl rand -hex 24)"
  sed -i 's/^LITELLM_MASTER_KEY *=.*/LITELLM_MASTER_KEY='"$key"'/' .env
  dc up -d --no-deps --force-recreate litellm >/dev/null 2>&1
  wait_for "$B/health/liveliness" 200 60
  check "GET /health/liveliness with a master key set" "200" "$(code GET "$B/health/liveliness")"
  check "GET /health without a key" "401" "$(code GET "$B/health")"
  check "GET /metrics without a key" "401" "$(code GET "$B/metrics")"
  ;;
*)
  echo "unknown product $PRODUCT" >&2
  exit 2
  ;;
esac
echo "probe.sh $PRODUCT done" >&2
