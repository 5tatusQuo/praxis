#!/usr/bin/env bash
# Run on the server when a client is offboarded: drop its keys from the files
# the runner and the API read. The keys themselves are already invalidated.
set -euo pipefail
client="${1:?usage: forget-keys.sh <client>}"
suffix="$(echo "$client" | tr 'a-z-' 'A-Z_')"
sed -i "/_API_KEY_${suffix}=/d" /opt/praxis/keys.env
sudo rm -f "/etc/praxis/deploy/$client.env"
echo "forgot keys for $client"
