#!/usr/bin/env bash
# Run a command on your workstation against the server's stack.
#   deploy/with-server.sh uv run praxis coverage acme
#   deploy/with-server.sh uv run praxis pack plan acme --month 2026-12
#
# Opens SSH tunnels to Elasticsearch, Kibana, Postgres and the API on the server named
# in .env (PRAXIS_SERVER), and passes the lab and read keys to the command
# through its environment only. Nothing secret is written to this machine, and
# deploy keys are never fetched. This is how agents run from a workstation:
# they can read, test and backtest, and they open a pull request with your own
# GitHub login.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
set -a; . "$ROOT/.env"; set +a
: "${PRAXIS_SERVER:?set PRAXIS_SERVER in .env}"
[ $# -gt 0 ] || { echo "usage: deploy/with-server.sh <command...>" >&2; exit 2; }

WORK="$(mktemp -d)"
SOCKET="$WORK/ssh.sock"
cleanup() { ssh -S "$SOCKET" -O exit "$PRAXIS_SERVER" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

# Each run picks its own free local ports, so several ./px commands can run at once.
free_port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
ES_PORT=$(free_port); KIBANA_PORT=$(free_port); PG_PORT=$(free_port); API_PORT=$(free_port)

# -n on every ssh call: the wrapped command owns stdin (`praxis mcp` speaks on it).
if ! ssh -n -M -S "$SOCKET" -f -N -o ExitOnForwardFailure=yes -o ConnectTimeout=15 \
  -L "$ES_PORT:localhost:9200" -L "$KIBANA_PORT:localhost:5601" -L "$PG_PORT:localhost:5432" \
  -L "$API_PORT:localhost:8000" "$PRAXIS_SERVER"; then
  echo "error: cannot reach the PRAXIS server ($PRAXIS_SERVER from .env) over ssh. Check that 'ssh $PRAXIS_SERVER' works without a password." >&2
  exit 1
fi
ssh -n -S "$SOCKET" "$PRAXIS_SERVER" 'cat /etc/praxis/ca.crt' > "$WORK/ca.crt"

export PRAXIS_ELASTIC_LAB_ES_URL=https://localhost:$ES_PORT
export PRAXIS_ELASTIC_LAB_KIBANA_URL=http://localhost:$KIBANA_PORT
export PRAXIS_ELASTIC_LAB_CA_CERT="$WORK/ca.crt"
export PRAXIS_API_URL=http://localhost:$API_PORT   # agents get their ChatGPT token here
while IFS='=' read -r name value; do
  [ -n "$name" ] && export "$name=$value"
done < <(ssh -n -S "$SOCKET" "$PRAXIS_SERVER" \
  "cat /opt/praxis/api.env; grep '^PRAXIS_API_TOKEN=' /opt/praxis/app/deploy/.env; printf 'PRAXIS_DATABASE_URL=postgresql://praxis:%s@localhost:$PG_PORT/praxis\n' \"\$(grep '^POSTGRES_PASSWORD=' /opt/praxis/app/deploy/.env | cut -d= -f2)\"")

cd "$ROOT"
"$@"
