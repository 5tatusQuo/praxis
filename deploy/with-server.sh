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

# -n on every ssh call: the wrapped command owns stdin (`praxis mcp` speaks on it).
ssh -n -M -S "$SOCKET" -f -N -o ExitOnForwardFailure=yes \
  -L 19200:localhost:9200 -L 15601:localhost:5601 -L 15432:localhost:5432 \
  -L 18000:localhost:8000 "$PRAXIS_SERVER"
ssh -n -S "$SOCKET" "$PRAXIS_SERVER" 'cat /etc/praxis/ca.crt' > "$WORK/ca.crt"

export PRAXIS_ELASTIC_LAB_ES_URL=https://localhost:19200
export PRAXIS_ELASTIC_LAB_KIBANA_URL=http://localhost:15601
export PRAXIS_ELASTIC_LAB_CA_CERT="$WORK/ca.crt"
export PRAXIS_API_URL=http://localhost:18000   # agents get their ChatGPT token here
while IFS='=' read -r name value; do
  [ -n "$name" ] && export "$name=$value"
done < <(ssh -n -S "$SOCKET" "$PRAXIS_SERVER" \
  "cat /opt/praxis/api.env; grep '^PRAXIS_API_TOKEN=' /opt/praxis/app/deploy/.env; printf 'PRAXIS_DATABASE_URL=postgresql://praxis:%s@localhost:15432/praxis\n' \"\$(grep '^POSTGRES_PASSWORD=' /opt/praxis/app/deploy/.env | cut -d= -f2)\"")

cd "$ROOT"
"$@"
