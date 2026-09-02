#!/bin/sh
# Daily lab bring-up (run inside WSL): Wazuh 4.9.2 stack -> agent containers.
# Everything has restart:unless-stopped, so this is only needed after a full
# shutdown. From PowerShell:  wsl bash scripts/lab-up.sh
set -eu

WAZUH_DIR="${WAZUH_DIR:-$HOME/wazuh-docker-4.9.2/single-node}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

echo ">> Wazuh 4.9.2 stack"
( cd "$WAZUH_DIR" && COMPOSE_PROJECT_NAME=wazuh49 docker compose up -d )

echo ">> waiting for the indexer to answer"
until curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health >/dev/null 2>&1; do
  sleep 3
done

echo ">> zuumb agent containers"
docker compose -f "$REPO/docker-compose.agents.yml" up -d --build

sleep 8
echo ">> agents known to the manager"
docker exec wazuh49-wazuh.manager-1 /var/ossec/bin/agent_control -l || true

cat <<'EOF'

Stack + agents are up. Start the zuumb poller/dashboard in the repo:
  .venv/Scripts/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
EOF
