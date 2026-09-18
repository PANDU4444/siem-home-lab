#!/usr/bin/env bash
# siem-home-lab :: install the daily audit timer.
#
# The committed unit file carries a __REPO_PATH__ placeholder so the repository
# does not hardcode one machine's layout. This substitutes the real path.
#
# Run as root:  sudo bash scripts/install_timer.sh
set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"

echo "==> Installing timer for repo at: $REPO"
sed "s|__REPO_PATH__|${REPO}|g" \
    "$REPO/automation/systemd/siem-daily-audit.service" > "$UNIT_DIR/siem-daily-audit.service"
install -m 644 "$REPO/automation/systemd/siem-daily-audit.timer" "$UNIT_DIR/siem-daily-audit.timer"
chmod 644 "$UNIT_DIR/siem-daily-audit.service"

systemctl daemon-reload
systemctl enable --now siem-daily-audit.timer

echo "==> Installed. Next run:"
systemctl list-timers siem-daily-audit.timer --no-pager | head -3
echo ""
echo "Run it now with:  sudo systemctl start siem-daily-audit.service"
echo "Read the output:  journalctl -u siem-daily-audit.service -n 20"
