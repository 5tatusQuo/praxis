#!/usr/bin/env bash
# Runs inside the elk-certs container. Creates the CA and the es01 node
# certificate once; later runs find them and do nothing.
set -euo pipefail
cd /usr/share/elasticsearch
CERTS=config/certs

if [ ! -f "$CERTS/ca/ca.crt" ]; then
  bin/elasticsearch-certutil ca --silent --pem -out "$CERTS/ca.zip"
  unzip -q "$CERTS/ca.zip" -d "$CERTS"
fi

if [ ! -f "$CERTS/es01/es01.crt" ]; then
  cat > "$CERTS/instances.yml" <<'YAML'
instances:
  - name: es01
    dns: [es01, localhost]
    ip: [127.0.0.1]
YAML
  bin/elasticsearch-certutil cert --silent --pem -out "$CERTS/certs.zip" \
    --in "$CERTS/instances.yml" \
    --ca-cert "$CERTS/ca/ca.crt" --ca-key "$CERTS/ca/ca.key"
  unzip -q "$CERTS/certs.zip" -d "$CERTS"
fi

chown -R root:root "$CERTS"
find "$CERTS" -type d -exec chmod 750 {} +
find "$CERTS" -type f -exec chmod 640 {} +
echo "Certificates ready"
