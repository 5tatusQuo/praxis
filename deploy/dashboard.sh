#!/usr/bin/env bash
# Open the PRAXIS dashboard from your workstation.
#   deploy/dashboard.sh
# Forwards the server's dashboard to http://127.0.0.1:3000 over SSH, opens it
# in your browser and prints the sign-in details. Use this address (not "localhost") when you sign in with
# ChatGPT: the sign-in can only return to 127.0.0.1. Press Ctrl-C to close.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
set -a; . "$ROOT/.env"; set +a
: "${PRAXIS_SERVER:?set PRAXIS_SERVER in .env}"
# Sign-in only works at this exact address, so the port is fixed.
PORT=3000
URL="http://127.0.0.1:$PORT"
PASSWORD="$(ssh -n "$PRAXIS_SERVER" "grep '^DASHBOARD_PASSWORD=' /opt/praxis/app/deploy/.env | cut -d= -f2" || true)"
echo "Dashboard: $URL  (Ctrl-C to close the tunnel)"
echo "Sign in as: operator"
echo "Password:   ${PASSWORD:-see DASHBOARD_PASSWORD in deploy/.env on the server}"
( sleep 2; command -v open >/dev/null && open "$URL" || command -v xdg-open >/dev/null && xdg-open "$URL" || true ) &
exec ssh -N -o ExitOnForwardFailure=yes -L "127.0.0.1:$PORT:localhost:3000" "$PRAXIS_SERVER"
