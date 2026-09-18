#!/usr/bin/env bash
# siem-home-lab :: daily audit runner
#
# The alert feed lives inside the manager container, so this exports it first,
# then runs the digest on the host. Invoked by siem-daily-audit.timer.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CTR="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
HOURS="${AUDIT_HOURS:-24}"

cd "$REPO" || exit 1
mkdir -p .data

# Export the live alert file. Ownership is reset so the digest can run as a
# non-root user even though docker cp writes as root.
docker cp "$CTR:/var/ossec/logs/alerts/alerts.json" .data/alerts.json >/dev/null 2>&1 || {
    echo "could not export alerts from $CTR" >&2
    exit 1
}
chown "$(stat -c '%U:%G' "$REPO")" .data/alerts.json 2>/dev/null || true

exec python3 automation/daily_audit.py \
    --hours "$HOURS" \
    --alert-file .data/alerts.json \
    --output-dir analysis/reports \
    --env-file .env \
    --slack
