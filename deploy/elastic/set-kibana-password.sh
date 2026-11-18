#!/usr/bin/env bash
# Runs inside the elk-init container once Elasticsearch is healthy.
set -euo pipefail
cd /usr/share/elasticsearch
until curl -s -X POST --cacert config/certs/ca/ca.crt \
  -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  https://es01:9200/_security/user/kibana_system/_password \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q "^{}"; do
  sleep 5
done
echo "kibana_system password set"
