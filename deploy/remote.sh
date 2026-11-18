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

# Run praxis on the server with its keys loaded. $1 = "admin" also loads the admin identity.
on_server() {
  local identity="$1"; shift
  ssh "$PRAXIS_SERVER" "cd $APP && export PATH=\$HOME/.local/bin:\$PATH && . deploy/server/env.sh $identity && $*"
}
# The API reads its keys when it starts, so new keys need a restart (about 15 seconds).
restart_stack() { ssh "$PRAXIS_SERVER" "cd $APP && sg docker -c 'deploy/server/bootstrap.sh full' >/dev/null 2>&1" && echo "API restarted so it can use the new keys"; }

cmd="${1:-}"; shift || true
case "$cmd" in
  sync) sync_repo ;;
  up) sync_repo; ssh "$PRAXIS_SERVER" "cd $APP && sg docker -c 'deploy/server/bootstrap.sh ${1:-full}'" ;;
  run) ssh "$PRAXIS_SERVER" "cd $APP && $*" ;;
  provision)
    # Connect a client to its SIEM: space, scoped keys, keys handed to the runner
    # and the API, then proof that both identities work. Safe to repeat.
    client="${1:?usage: deploy/remote.sh provision <client> [--rotate]}"; rotate="${2:-}"
    sync_repo
    on_server admin "uv run --quiet praxis admin provision $client --env-out /opt/praxis/keys.env $rotate && deploy/server/publish-keys.sh"
    restart_stack
    on_server "" "uv run praxis connection $client"
    ;;
  dashboard-user)
    # Create or update a dashboard user: <username> <password> [--admin] [--client <id>]...
    ssh "$PRAXIS_SERVER" "cd $APP && sg docker -c 'deploy/server/dashboard-user.sh $*'"
    ;;
  check)
    client="${1:?usage: deploy/remote.sh check <client>}"
    sync_repo
    on_server "" "uv run praxis connection $client"
    ;;
  deprovision)
    # Remove a client from its SIEM. Cannot be undone. Use `praxis client offboard`.
    client="${1:?usage: deploy/remote.sh deprovision <client> [--delete-space] [--delete-data]}"; shift
    sync_repo
    on_server admin "uv run praxis admin deprovision $client --yes $* && deploy/server/forget-keys.sh $client && deploy/server/publish-keys.sh"
    restart_stack
    ;;
  *) echo "usage: deploy/remote.sh sync | up [mode] | provision <client> | check <client> | deprovision <client> | dashboard-user <name> <password> [--admin|--client <id>] | run <command>" >&2; exit 2 ;;
esac
