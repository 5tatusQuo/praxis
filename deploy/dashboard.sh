#!/usr/bin/env bash
# Open the PRAXIS dashboard from your workstation.
#   deploy/dashboard.sh
# Forwards the server's dashboard to http://127.0.0.1:3000 over SSH and opens
# it in your browser. Use this address (not "localhost") when you sign in with
# ChatGPT: the sign-in can only return to 127.0.0.1. Press Ctrl-C to close.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
set -a; . "$ROOT/.env"; set +a
: "${PRAXIS_SERVER:?set PRAXIS_SERVER in .env}"
PORT="${1:-3000}"
URL="http://127.0.0.1:$PORT"
echo "Dashboard: $URL  (Ctrl-C to close the tunnel)"
( sleep 2; command -v open >/dev/null && open "$URL" || command -v xdg-open >/dev/null && xdg-open "$URL" || true ) &
exec ssh -N -o ExitOnForwardFailure=yes -L "127.0.0.1:$PORT:localhost:3000" "$PRAXIS_SERVER"
