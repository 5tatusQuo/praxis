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

if [ ! -f "$ENV_FILE" ]; then
  umask 077
  cat > "$ENV_FILE" <<ENV
STACK_VERSION=9.5.5
ES_HEAP=4g
ES_BIND=127.0.0.1
KIBANA_BIND=127.0.0.1
ELASTIC_PASSWORD=$(rand 16)
KIBANA_PASSWORD=$(rand 16)
KIBANA_KEY_SECURITY=$(rand 24)
KIBANA_KEY_SAVED_OBJECTS=$(rand 24)
KIBANA_KEY_REPORTING=$(rand 24)
ENV
  echo "Generated $ENV_FILE"
fi

case "$MODE" in
  full) PROFILES=(--profile core --profile elk) ;;
  connect) PROFILES=(--profile core) ;;
  *) echo "mode must be full or connect" >&2; exit 2 ;;
esac

cd "$DEPLOY_DIR"
docker compose "${PROFILES[@]}" up -d
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

if [ "$MODE" = full ]; then
  sudo install -d -m 755 "$ETC_DIR"
  docker compose cp es01:/usr/share/elasticsearch/config/certs/ca/ca.crt /tmp/praxis-ca.crt >/dev/null
  sudo install -m 644 /tmp/praxis-ca.crt "$ETC_DIR/ca.crt" && rm -f /tmp/praxis-ca.crt
  echo "Elasticsearch CA at $ETC_DIR/ca.crt"
fi
docker compose "${PROFILES[@]}" ps --format 'table {{.Service}}\t{{.Status}}'
