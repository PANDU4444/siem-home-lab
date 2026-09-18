#!/usr/bin/env bash
# siem-home-lab :: deploy YARA + tuned FIM onto the Wazuh agent.
#
# The agent is where files actually live, so this is where YARA runs and where
# the tuned <syscheck> block belongs. The manager only parses what comes back.
#
# The committed FIM fragment uses an __AGENT_HOME__ placeholder rather than a
# real home directory, so the repository stays portable. It is substituted
# here with the home directory of the account being monitored.
#
# Run as root:  sudo bash scripts/deploy_to_agent.sh
#   AGENT_HOME=/home/alice sudo -E bash scripts/deploy_to_agent.sh
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OSSEC="${OSSEC:-/var/ossec}"
STAMP="$(date +%Y%m%d-%H%M%S)"

# Monitor the invoking user's home, not root's, when run under sudo.
if [ -z "${AGENT_HOME:-}" ]; then
    if [ -n "${SUDO_USER:-}" ]; then
        AGENT_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    else
        AGENT_HOME="$HOME"
    fi
fi
[ -d "$AGENT_HOME" ] || { echo "AGENT_HOME '$AGENT_HOME' does not exist" >&2; exit 1; }
echo "==> Monitoring agent home: $AGENT_HOME"

echo "==> 1. Installing YARA on the agent host"
if command -v yara >/dev/null 2>&1; then
    echo "    already installed: $(yara --version)"
else
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq yara >/dev/null 2>&1
    command -v yara >/dev/null 2>&1 || { echo "    ERROR: yara install failed"; exit 1; }
    echo "    installed: $(yara --version)"
fi

echo "==> 2. Installing auditd (required by FIM whodata)"
if systemctl is-active --quiet auditd 2>/dev/null; then
    echo "    auditd already active"
else
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd audispd-plugins >/dev/null 2>&1
fi
if [ -f "$REPO/wazuh/audit/siem-home-lab.rules" ]; then
    sed "s|__AGENT_HOME__|${AGENT_HOME}|g" \
        "$REPO/wazuh/audit/siem-home-lab.rules" > /etc/audit/rules.d/siem-home-lab.rules
    chmod 640 /etc/audit/rules.d/siem-home-lab.rules
    systemctl enable auditd >/dev/null 2>&1
    service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1
    sleep 2
    echo "    auditd active: $(systemctl is-active auditd), rules loaded: $(auditctl -l 2>/dev/null | wc -l)"
fi

echo "==> 3. Installing YARA rules"
mkdir -p "$OSSEC/etc/yara/rules"
cp "$REPO/yara/rules/siem_home_lab.yar" "$OSSEC/etc/yara/rules/siem_home_lab.yar"
chown -R root:wazuh "$OSSEC/etc/yara"
chmod -R 750 "$OSSEC/etc/yara"
if yara -w "$OSSEC/etc/yara/rules/siem_home_lab.yar" /etc/hostname >/dev/null 2>&1; then
    echo "    ruleset compiles: $(grep -c '^rule ' "$OSSEC/etc/yara/rules/siem_home_lab.yar") rules"
else
    echo "    ERROR: YARA ruleset failed to compile"; exit 1
fi

echo "==> 4. Installing the active-response script"
cp "$REPO/yara/active-response/yara.sh" "$OSSEC/active-response/bin/yara.sh"
chown root:wazuh "$OSSEC/active-response/bin/yara.sh"
chmod 750 "$OSSEC/active-response/bin/yara.sh"
echo "    $OSSEC/active-response/bin/yara.sh"

echo "==> 5. Applying the tuned FIM configuration"
cp "$OSSEC/etc/ossec.conf" "$OSSEC/etc/ossec.conf.bak-${STAMP}"
echo "    backup: $OSSEC/etc/ossec.conf.bak-${STAMP}"

python3 - "$REPO" "$OSSEC" "$AGENT_HOME" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

repo, ossec, agent_home = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
fragment = (repo / "wazuh/config-fragments/10-syscheck-fim.xml").read_text()

# Anchor on a line-start <syscheck> so a mention inside the header comment
# cannot be mistaken for the element itself.
match = re.search(r"^<syscheck>.*?^</syscheck>", fragment, re.S | re.M)
if not match:
    sys.exit("no line-anchored <syscheck> element in the fragment")

body = match.group(0).replace("__AGENT_HOME__", agent_home)
body = "\n".join("  " + line if line.strip() else line for line in body.splitlines())

# Validate before touching the live config - a malformed block stops the agent.
try:
    ET.fromstring(body)
except ET.ParseError as exc:
    sys.exit("generated syscheck block is not well-formed XML: {}".format(exc))

conf_path = ossec / "etc/ossec.conf"
conf = conf_path.read_text()
conf, count = re.subn(r"[ \t]*<syscheck>.*?</syscheck>", body, conf, count=1, flags=re.DOTALL)
if count != 1:
    sys.exit("could not find a <syscheck> block in the agent config")

try:
    ET.fromstring("<root>" + conf + "</root>")
except ET.ParseError as exc:
    sys.exit("resulting ossec.conf is not well-formed XML: {}".format(exc))

conf_path.write_text(conf)
print("    syscheck block replaced and validated")
PY
if [ $? -ne 0 ]; then
    echo "    ERROR: config edit failed, restoring backup"
    cp "$OSSEC/etc/ossec.conf.bak-${STAMP}" "$OSSEC/etc/ossec.conf"
    exit 1
fi

echo "==> 6. Restarting the agent"
systemctl restart wazuh-agent
sleep 8
if systemctl is-active --quiet wazuh-agent; then
    echo "    agent is active"
else
    echo "    agent failed to start - restoring previous config"
    cp "$OSSEC/etc/ossec.conf.bak-${STAMP}" "$OSSEC/etc/ossec.conf"
    systemctl restart wazuh-agent
    exit 1
fi

echo "==> 7. Verification"
"$OSSEC/bin/wazuh-control" status 2>&1 | head -8
echo "--- FIM settings now in effect ---"
grep -E "<frequency>|whodata=|realtime=" "$OSSEC/etc/ossec.conf" | head -6 | sed 's/^/    /'
echo "--- recent agent errors ---"
tail -40 "$OSSEC/logs/ossec.log" | grep -iE "error|critical" | tail -6 || echo "    none"
