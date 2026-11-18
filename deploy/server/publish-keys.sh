#!/usr/bin/env bash
# Run on the deployment server after `praxis admin provision`. Splits
# /opt/praxis/keys.env into the env files the self-hosted runner reads:
#   /etc/praxis/lab.env             lab key (pull-request lab staging)
#   /etc/praxis/deploy/<client>.env that client's deploy key (CD only)
# SIEM credentials stay on this machine; they are never stored in GitHub.
set -euo pipefail
KEYS=/opt/praxis/keys.env
GROUP=ghrunner
CONNECTION='PRAXIS_ELASTIC_LAB_ES_URL=https://localhost:9200
PRAXIS_ELASTIC_LAB_KIBANA_URL=http://localhost:5601
PRAXIS_ELASTIC_LAB_CA_CERT=/etc/praxis/ca.crt'

write() { # write <path> <content>
  printf '%s\n' "$2" | sudo tee "$1" >/dev/null
  sudo chown "root:$GROUP" "$1"
  sudo chmod 640 "$1"
  echo "wrote $1"
}

sudo install -d -m 750 -o root -g "$GROUP" /etc/praxis/deploy
write /etc/praxis/lab.env "$CONNECTION
$(grep '^PRAXIS_ELASTIC_LAB_LAB_API_KEY=' "$KEYS")"

grep -o '^PRAXIS_ELASTIC_LAB_DEPLOY_API_KEY_[A-Z0-9_]*' "$KEYS" | while read -r name; do
  client="$(echo "${name#PRAXIS_ELASTIC_LAB_DEPLOY_API_KEY_}" | tr 'A-Z_' 'a-z-')"
  write "/etc/praxis/deploy/$client.env" "$CONNECTION
$(grep "^$name=" "$KEYS")"
done
