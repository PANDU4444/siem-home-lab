#!/usr/bin/env bash
# siem-home-lab :: verify the custom ruleset fires, using the manager's own
# wazuh-logtest. Each case feeds a synthetic log and reports which rule won.
#
# Run as root:  sudo bash scripts/test_rules.sh
set -u
CTR="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
PASS=0
FAIL=0

run_case() {
    local desc="$1" expect="$2"; shift 2
    # A fixed /tmp path breaks the moment the script is run once under sudo:
    # the root-owned file is then unwritable by a normal user, because
    # fs.protected_regular blocks writes to another user's file in a sticky
    # world-writable directory. mktemp avoids the whole class of problem.
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "$@" > "$tmp"
    docker cp "$tmp" "$CTR:/tmp/logtest_case.log" >/dev/null 2>&1
    rm -f "$tmp"

    local out
    out="$(docker exec "$CTR" bash -c '/var/ossec/bin/wazuh-logtest < /tmp/logtest_case.log' 2>&1)"

    # The last "id: 'N'" in the output is the rule that finally matched.
    local all_ids got
    all_ids="$(echo "$out" | grep -oP "^\s+id: '\K[0-9]+" | sort -u | tr '
' ' ')"
    if echo " $all_ids " | grep -q " $expect "; then got="$expect"; else got="$(echo "$out" | grep -oP "^\s+id: '\K[0-9]+" | tail -1)"; fi
    local level desc_line mitre
    level="$(echo "$out" | grep -oP "^\s+level: '\K[0-9]+" | tail -1)"
    desc_line="$(echo "$out" | grep -oP "^\s+description: '\K[^']+" | tail -1)"
    mitre="$(echo "$out" | grep -oP "^\s+mitre\.id: '\K[^']+" | tail -1)"

    if [ "$got" = "$expect" ]; then
        PASS=$((PASS + 1))
        printf '  [PASS] %-58s rule %s (level %s)\n' "$desc" "$got" "$level"
    else
        FAIL=$((FAIL + 1))
        printf '  [FAIL] %-58s expected %s, got %s\n' "$desc" "$expect" "${got:-none}"
    fi
    [ -n "$desc_line" ] && printf '         -> %s\n' "$desc_line"
    [ -n "$mitre" ] && printf '         -> ATT&CK %s\n' "$mitre"
}

echo "=============================================================================="
echo " siem-home-lab :: custom rule verification"
echo "=============================================================================="

run_case "Single SSH auth failure" 100101 \
  "Sep 18 00:50:01 pandu sshd[12345]: Failed password for invalid user admin from 10.0.2.99 port 52344 ssh2"

BURST=()
for i in $(seq 1 12); do
    BURST+=("Sep 18 00:50:$(printf '%02d' $i) pandu sshd[1234$i]: Failed password for invalid user admin from 10.0.2.77 port 5234$i ssh2")
done
run_case "SSH brute force burst (12 failures, one source)" 100102 "${BURST[@]}"

run_case "Successful SSH login as root" 100104 \
  "Sep 18 00:51:11 pandu sshd[12399]: Accepted password for root from 10.0.2.99 port 52399 ssh2"

run_case "New user account created" 100110 \
  "Sep 18 00:52:00 pandu useradd[13000]: new user: name=backdoor, UID=1099, GID=1099, home=/home/backdoor, shell=/bin/bash"

run_case "YARA active-response match" 100141 \
  "wazuh-yara: INFO - Scan result: SHL_Linux_Reverse_Shell /tmp/payload.sh"

echo "------------------------------------------------------------------------------"
printf ' %d passed, %d failed\n' "$PASS" "$FAIL"
echo "=============================================================================="
[ "$FAIL" -eq 0 ]
