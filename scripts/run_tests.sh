#!/usr/bin/env bash
# siem-home-lab :: verification suite
#
#   make test        (or)   bash scripts/run_tests.sh
#
# Every check runs even if an earlier one fails, because a partial report is
# more useful than stopping at the first problem. A check that cannot run
# (no sudo, stack not started) reports SKIP rather than FAIL - conflating
# "could not test" with "test failed" sends people debugging the wrong thing.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

MANAGER="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
PASS=0; FAIL=0; SKIP=0

pass() { printf '  \033[32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33m[SKIP]\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }

# Can we reach docker without an interactive password prompt?
if docker info >/dev/null 2>&1; then
    DOCKER="docker"
elif sudo -n true 2>/dev/null; then
    DOCKER="sudo docker"
else
    DOCKER=""
fi

echo "=============================================================================="
echo " siem-home-lab :: verification"
echo "=============================================================================="
echo ""

# ---------------------------------------------------------------- static
echo "Static checks (no running stack needed)"

if command -v yara >/dev/null 2>&1; then
    if yara -w yara/rules/siem_home_lab.yar /etc/hostname >/dev/null 2>&1; then
        pass "YARA ruleset compiles ($(grep -c '^rule ' yara/rules/siem_home_lab.yar) rules)"
    else
        fail "YARA ruleset does not compile"
    fi
else
    skip "YARA not installed (sudo apt install -y yara)"
fi

if python3 - <<'PY' >/dev/null 2>&1
import xml.etree.ElementTree as ET
from pathlib import Path
for f in ["wazuh/rules/local_rules.xml", "wazuh/decoders/local_decoder.xml",
          "wazuh/config/ossec.conf", "wazuh/config-fragments/10-syscheck-fim.xml"]:
    ET.fromstring("<root>" + Path(f).read_text() + "</root>")
PY
then pass "XML files are well-formed"
else fail "an XML file is malformed"
fi

if python3 -m py_compile automation/*.py analysis/*.py scripts/*.py \
     integrations/slack/custom-slack.py 2>/dev/null; then
    pass "Python modules compile"
else
    fail "a Python module has a syntax error"
fi

SHELL_ERR=0
for s in scripts/*.sh automation/*.sh scripts/attack-simulation/*.sh \
         yara/active-response/*.sh integrations/slack/custom-slack; do
    [ -f "$s" ] || continue
    bash -n "$s" 2>/dev/null || { SHELL_ERR=1; echo "        offending file: $s"; }
done
[ "$SHELL_ERR" -eq 0 ] && pass "shell scripts parse" || fail "a shell script has a syntax error"

if git rev-parse --git-dir >/dev/null 2>&1; then
    if python3 scripts/leakscan.py . HEAD >/dev/null 2>&1; then
        pass "secret scan clean (no CRITICAL or HIGH findings)"
    else
        fail "secret scan found something - run 'make scan' for detail"
    fi
else
    skip "secret scan (not a git repository)"
fi

if python3 -c "import requests" >/dev/null 2>&1; then
    if python3 scripts/test_slack.py >/dev/null 2>&1; then
        pass "Slack payload builds correctly (11 checks)"
    else
        fail "Slack payload test failed"
    fi
else
    skip "Slack payload test (python3 requests not installed)"
fi

# ------------------------------------------------------------ live stack
echo ""
echo "Live checks (require the running stack)"

if [ -z "$DOCKER" ]; then
    skip "manager configuration (docker needs sudo; run: sudo bash scripts/run_tests.sh)"
    skip "detection rules (same reason)"
elif ! $DOCKER ps --format '{{.Names}}' 2>/dev/null | grep -q "$MANAGER"; then
    skip "manager configuration (container '$MANAGER' is not running - try 'make up')"
    skip "detection rules (same reason)"
else
    if $DOCKER exec "$MANAGER" /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
        pass "manager configuration is valid"
    else
        fail "manager rejected its configuration"
    fi

    RESULT="$(bash scripts/test_rules.sh 2>/dev/null | grep -oE '[0-9]+ passed, [0-9]+ failed')"
    if [ -n "$RESULT" ]; then
        if echo "$RESULT" | grep -q '^[0-9]* passed, 0 failed'; then
            pass "detection rules fire ($RESULT)"
        else
            fail "detection rules: $RESULT"
        fi
    else
        skip "detection rules (logtest produced no result)"
    fi
fi

if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    pass "wazuh-agent is running"
else
    skip "wazuh-agent not running on this host (expected if the agent is elsewhere)"
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    pass "auditd is running (required by FIM whodata)"
else
    skip "auditd not running (needed only on the agent host)"
fi

echo ""
echo "=============================================================================="
printf " %d passed, %d failed, %d skipped\n" "$PASS" "$FAIL" "$SKIP"
echo "=============================================================================="
[ "$FAIL" -eq 0 ]
