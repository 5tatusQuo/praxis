#!/usr/bin/env bash
# Run on the deployment server. Installs a GitHub Actions self-hosted runner as
# a systemd service under its own unprivileged user. Anything that touches a
# SIEM runs here, so SIEM credentials and traffic stay on your network.
#   RUNNER_TOKEN=<registration token> deploy/server/install-runner.sh <owner/repo>
set -euo pipefail
REPO="${1:?usage: install-runner.sh <owner/repo>}"
: "${RUNNER_TOKEN:?set RUNNER_TOKEN to a runner registration token}"
VERSION="${RUNNER_VERSION:-2.338.2}"
RUNNER_USER=ghrunner
RUNNER_HOME=/opt/praxis/runner

id "$RUNNER_USER" >/dev/null 2>&1 || sudo useradd --system --create-home --shell /bin/bash "$RUNNER_USER"
sudo install -d -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME"
cd "$RUNNER_HOME"
if [ ! -x ./config.sh ]; then
  sudo -u "$RUNNER_USER" curl -fsSL -o runner.tar.gz \
    "https://github.com/actions/runner/releases/download/v${VERSION}/actions-runner-linux-x64-${VERSION}.tar.gz"
  sudo -u "$RUNNER_USER" tar xzf runner.tar.gz
  sudo ./bin/installdependencies.sh >/dev/null
fi
if [ ! -f .runner ]; then
  sudo -u "$RUNNER_USER" ./config.sh --unattended --replace \
    --url "https://github.com/${REPO}" --token "$RUNNER_TOKEN" \
    --name praxis-runner --labels praxis --work _work
fi
sudo ./svc.sh install "$RUNNER_USER" >/dev/null 2>&1 || true
sudo ./svc.sh start >/dev/null
sudo ./svc.sh status | head -5
