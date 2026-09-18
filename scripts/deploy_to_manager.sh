#!/usr/bin/env bash
# siem-home-lab :: deploy detection content into the Wazuh manager container.
#
# The manager owns rules, decoders, integrations and the active-response
# definition. YARA itself runs on the agent (see deploy_to_agent.sh) because
# that is where the files being scanned actually live.
#
# Safe by construction: backs up the current config, validates the new one
# with wazuh-analysisd -t, and restores the backup if validation fails.
#
# Run as root:  sudo bash scripts/deploy_to_manager.sh
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CTR="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
STAMP="$(date +%Y%m%d-%H%M%S)"
RENDERED="$REPO/.rendered/ossec.conf"

d() { docker exec "$CTR" "$@"; }
dcp() { docker cp "$1" "$CTR:$2"; }

echo "==> 1. Backing up current manager config"
d cp /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.bak-${STAMP}" \
  && echo "    backup: /var/ossec/etc/ossec.conf.bak-${STAMP}"

echo "==> 2. Copying detection content"
d mkdir -p /var/ossec/etc/yara/rules
dcp "$REPO/wazuh/rules/local_rules.xml"        /var/ossec/etc/rules/local_rules.xml
dcp "$REPO/wazuh/decoders/local_decoder.xml"   /var/ossec/etc/decoders/local_decoder.xml
dcp "$REPO/yara/rules/siem_home_lab.yar"       /var/ossec/etc/yara/rules/siem_home_lab.yar
dcp "$REPO/integrations/slack/custom-slack"    /var/ossec/integrations/custom-slack
dcp "$REPO/integrations/slack/custom-slack.py" /var/ossec/integrations/custom-slack.py

echo "==> 3. Ownership and permissions"
d chown root:wazuh /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml
d chmod 660        /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml
d chown -R root:wazuh /var/ossec/etc/yara
d chmod -R 750        /var/ossec/etc/yara
d chown root:wazuh /var/ossec/integrations/custom-slack /var/ossec/integrations/custom-slack.py
d chmod 750        /var/ossec/integrations/custom-slack /var/ossec/integrations/custom-slack.py

echo "==> 4. Rendering ossec.conf from template + .env"
mkdir -p "$REPO/.rendered"
python3 "$REPO/scripts/render_config.py" \
        "$REPO/wazuh/config/ossec.conf" "$RENDERED" "$REPO/.env" || exit 1
dcp "$RENDERED" /var/ossec/etc/ossec.conf
d chown root:wazuh /var/ossec/etc/ossec.conf
d chmod 660        /var/ossec/etc/ossec.conf

echo "==> 5. Validating with wazuh-analysisd -t"
VALIDATION="$(d /var/ossec/bin/wazuh-analysisd -t 2>&1)"
echo "$VALIDATION" | tail -15
if echo "$VALIDATION" | grep -qiE "\(120[0-9]\)|critical|ERROR"; then
  echo "    VALIDATION FAILED - restoring backup, manager NOT restarted"
  d cp "/var/ossec/etc/ossec.conf.bak-${STAMP}" /var/ossec/etc/ossec.conf
  exit 1
fi
echo "    configuration is valid"

echo "==> 6. Restarting the manager"
d /var/ossec/bin/wazuh-control restart 2>&1 | tail -12

echo "==> 7. Post-restart verification"
sleep 10
echo "--- daemons ---"
d /var/ossec/bin/wazuh-control status 2>&1 | head -10
echo "--- custom rule count loaded from local_rules.xml ---"
d bash -c 'grep -c "<rule id=\"1001" /var/ossec/etc/rules/local_rules.xml'
echo "--- errors since restart ---"
d bash -c 'tail -60 /var/ossec/logs/ossec.log | grep -iE "error|critical" | tail -8 || true'
