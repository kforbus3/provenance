#!/usr/bin/env bash
# Install the Provenance user-CA public key into the local test-fabric nodes
# (jump host + managed hosts) so they trust certificates issued by the backend.
#
# In production this trust is established during enrollment over a bootstrap
# credential; in the local fabric we seed it directly from the database. Run once
# after `make up`, then enroll hosts from the UI.
set -euo pipefail

COMPOSE=(docker compose --env-file .env -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.testfabric.yml)
NODES=(jumphost host-ubuntu host-rocky)

echo "Reading active user CA from the database…"
CA="$("${COMPOSE[@]}" exec -T postgres psql -U prov -d prov -tAc \
  "SELECT public_key FROM ca_keys WHERE kind='user' AND active=true ORDER BY created_at DESC LIMIT 1")"

if [[ -z "${CA// }" ]]; then
  echo "No active CA found. Is the backend running and initialized?" >&2
  exit 1
fi

for n in "${NODES[@]}"; do
  printf '%s\n' "$CA" | "${COMPOSE[@]}" exec -T "$n" sh -c \
    "cat > /etc/ssh/prov_ca.pub && chmod 644 /etc/ssh/prov_ca.pub && (pkill -HUP sshd 2>/dev/null || true)"
  echo "  installed CA on $n"
done

echo "Done. The fabric now trusts the Provenance CA; enroll hosts from the UI."
