#!/usr/bin/env bash
# Run from your workstation. Copies this repo to the deployment server named in
# .env (PRAXIS_SERVER=user@host, gitignored) and runs a command there.
#   deploy/remote.sh sync                 # copy the repo to /opt/praxis/app
#   deploy/remote.sh up [full|connect]    # sync, then start the stack
#   deploy/remote.sh run <command...>     # run a command in /opt/praxis/app
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
set -a; . "$ROOT/.env"; set +a
: "${PRAXIS_SERVER:?set PRAXIS_SERVER in .env}"
APP=/opt/praxis/app

sync_repo() {
  ssh "$PRAXIS_SERVER" "sudo install -d -o \$(id -un) -g \$(id -gn) /opt/praxis $APP"
  rsync -az --delete \
    --exclude .git --exclude .venv --exclude .env --exclude 'deploy/.env' \
    --exclude node_modules --exclude .next --exclude __pycache__ \
    --exclude .pytest_cache --exclude .ruff_cache \
    "$ROOT/" "$PRAXIS_SERVER:$APP/"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  sync) sync_repo ;;
  up) sync_repo; ssh "$PRAXIS_SERVER" "cd $APP && sg docker -c 'deploy/server/bootstrap.sh ${1:-full}'" ;;
  run) ssh "$PRAXIS_SERVER" "cd $APP && $*" ;;
  *) echo "usage: deploy/remote.sh sync|up [mode]|run <command>" >&2; exit 2 ;;
esac
