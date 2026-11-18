#!/usr/bin/env bash
# Run on the deployment server, from the deploy/ folder's parent:
#   deploy/server/bootstrap.sh full|connect
# Generates deploy/.env on first run (random passwords, never committed),
# starts the stack and publishes the Elasticsearch CA for local clients.
set -euo pipefail

MODE="${1:-full}"
DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"
ETC_DIR=/etc/praxis

rand() { openssl rand -hex "$1"; }

# Add any setting that is missing; never change one that exists.
umask 077
touch "$ENV_FILE"
ensure() { grep -q "^$1=" "$ENV_FILE" || { echo "$1=$2" >> "$ENV_FILE"; echo "Generated $1"; }; }
ensure STACK_VERSION 9.5.5
ensure ES_HEAP 4g
ensure ES_BIND 127.0.0.1
ensure KIBANA_BIND 127.0.0.1
ensure PG_BIND 127.0.0.1
ensure API_BIND 127.0.0.1
ensure WEB_BIND 127.0.0.1
ensure ELASTIC_PASSWORD "$(rand 16)"
ensure KIBANA_PASSWORD "$(rand 16)"
ensure KIBANA_KEY_SECURITY "$(rand 24)"
ensure KIBANA_KEY_SAVED_OBJECTS "$(rand 24)"
ensure KIBANA_KEY_REPORTING "$(rand 24)"
ensure POSTGRES_PASSWORD "$(rand 16)"
ensure PRAXIS_API_TOKEN "$(rand 24)"

case "$MODE" in
  full) PROFILES=(--profile core --profile elk) ;;
  connect) PROFILES=(--profile core) ;;
  *) echo "mode must be full or connect" >&2; exit 2 ;;
esac

# The content the API serves. CD refreshes it after every merge; seed it once
# from this checkout so a new server has something to show.
CONTENT=/var/lib/praxis/content
sudo install -d -m 755 "$(dirname "$CONTENT")"
sudo chmod 755 "$(dirname "$CONTENT")"   # the runner and the API must be able to enter it
if [ ! -d "$CONTENT" ]; then
  sudo install -d -m 755 "$CONTENT"
  sudo cp -a "$DEPLOY_DIR/../content/." "$CONTENT/"
fi
id ghrunner >/dev/null 2>&1 && sudo chown -R ghrunner "$CONTENT"
sudo chmod -R a+rX "$CONTENT"   # the API container reads it as an unprivileged user
sudo install -d -m 755 "$ETC_DIR"
[ -e "$ETC_DIR/ca.crt" ] || sudo touch "$ETC_DIR/ca.crt"

cd "$DEPLOY_DIR"
docker compose "${PROFILES[@]}" up -d --build --remove-orphans
# `up --wait` fails when a one-shot container exits, so wait here.
wait_healthy() {
  local id; id="$(docker compose ps -q "$1")"
  [ -n "$id" ] || return 0
  echo -n "Waiting for $1"
  for _ in $(seq 1 120); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$id")" = healthy ] && { echo " ok"; return 0; }
    echo -n .; sleep 5
  done
  echo " timed out"; return 1
}
if [ "$MODE" = full ]; then wait_healthy es01; wait_healthy kibana; fi
wait_healthy postgres; wait_healthy praxis-api

if [ "$MODE" = full ]; then
  sudo install -d -m 755 "$ETC_DIR"
  docker compose cp es01:/usr/share/elasticsearch/config/certs/ca/ca.crt /tmp/praxis-ca.crt >/dev/null
  sudo install -m 644 /tmp/praxis-ca.crt "$ETC_DIR/ca.crt" && rm -f /tmp/praxis-ca.crt
  echo "Elasticsearch CA at $ETC_DIR/ca.crt"
fi
docker compose "${PROFILES[@]}" ps --format 'table {{.Service}}\t{{.Status}}'
