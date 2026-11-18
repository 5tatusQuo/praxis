#!/usr/bin/env bash
# Run on the server. Create or update a dashboard user in Keycloak.
#   deploy/server/dashboard-user.sh <username> <password> --admin
#   deploy/server/dashboard-user.sh <username> <password> --client acme --client globex
# An administrator sees everything. Anyone else sees only the clients named.
set -euo pipefail
user="${1:?usage: dashboard-user.sh <username> <password> [--admin] [--client <id>]...}"
password="${2:?give a password}"; shift 2
DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEPLOY_DIR"
admin_password="$(grep '^KEYCLOAK_ADMIN_PASSWORD=' .env | cut -d= -f2)"
kc() { docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"; }

for _ in $(seq 1 60); do
  kc config credentials --server http://localhost:8080/kc --realm master \
    --user admin --password "$admin_password" >/dev/null 2>&1 && break
  sleep 5
done
kc get realms/praxis >/dev/null 2>&1 || { echo "Keycloak is not ready, or the praxis realm is missing" >&2; exit 1; }

if ! kc get users -r praxis -q "username=$user" -q exact=true --fields username | grep -q "\"$user\""; then
  kc create users -r praxis -s "username=$user" -s enabled=true -s emailVerified=true \
    -s "email=$user@praxis.invalid" -s "firstName=$user" -s lastName=PRAXIS >/dev/null
  echo "created dashboard user $user"
fi
kc set-password -r praxis --username "$user" --new-password "$password"

roles=()
while [ $# -gt 0 ]; do
  case "$1" in
    --admin) roles+=("praxis-admin"); shift ;;
    --client) roles+=("client:$2"); shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
for role in "${roles[@]}"; do
  kc get "roles/$role" -r praxis >/dev/null 2>&1 || kc create roles -r praxis -s "name=$role" >/dev/null
  kc add-roles -r praxis --uusername "$user" --rolename "$role"
  echo "$user has role $role"
done
