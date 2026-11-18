# Source this on the deployment server to point `praxis` at the bundled Elastic:
#   . deploy/server/env.sh            # lab, read and deploy keys
#   . deploy/server/env.sh admin      # also the admin identity, for provisioning
# Keys created by `praxis admin provision` live in /opt/praxis/keys.env (mode 600).
_praxis_deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PRAXIS_ELASTIC_LAB_ES_URL=https://localhost:9200
export PRAXIS_ELASTIC_LAB_KIBANA_URL=http://localhost:5601
export PRAXIS_ELASTIC_LAB_CA_CERT=/etc/praxis/ca.crt
if [ -f /opt/praxis/keys.env ]; then
  set -a; . /opt/praxis/keys.env; set +a
fi
if [ "${1:-}" = admin ]; then
  export PRAXIS_ELASTIC_LAB_ADMIN_USERNAME=elastic
  PRAXIS_ELASTIC_LAB_ADMIN_PASSWORD="$(grep '^ELASTIC_PASSWORD=' "$_praxis_deploy_dir/.env" | cut -d= -f2)"
  export PRAXIS_ELASTIC_LAB_ADMIN_PASSWORD
fi
unset _praxis_deploy_dir
