#!/bin/bash
# siem-home-lab :: YARA active response
#
# Triggered by the Wazuh agent when FIM reports a new or modified file in a
# write-heavy directory. Scans that single file with the lab YARA ruleset and
# writes any match to active-responses.log, where local_decoder.xml parses it
# and rule 100141 raises the alert.
#
# Deliberately scans ONE file per invocation (not a directory walk) so the
# response stays cheap enough to run inline on every FIM event.

set -u

YARA_PATH="${YARA_PATH:-/usr/bin}"
YARA_RULES="${YARA_RULES:-/var/ossec/etc/yara/rules/siem_home_lab.yar}"
LOG_FILE="/var/ossec/logs/active-responses.log"
MAX_SIZE_BYTES=$((50 * 1024 * 1024))   # skip anything over 50MB

read -r INPUT_JSON

# The FIM path lives at .parameters.alert.syscheck.path
FILENAME=$(echo "$INPUT_JSON" | sed -n 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)

log() { echo "wazuh-yara: $*" >> "$LOG_FILE"; }

[ "$COMMAND" = "delete" ] && exit 0
[ -z "$FILENAME" ] && { log "ERROR - no file path in active response input"; exit 1; }
[ ! -f "$FILENAME" ] && exit 0
[ ! -r "$FILENAME" ] && { log "ERROR - cannot read $FILENAME"; exit 1; }

SIZE=$(stat -c%s "$FILENAME" 2>/dev/null || echo 0)
[ "$SIZE" -gt "$MAX_SIZE_BYTES" ] && { log "INFO - skipped $FILENAME (size ${SIZE}B exceeds limit)"; exit 0; }

[ ! -x "${YARA_PATH}/yara" ] && { log "ERROR - yara binary not found at ${YARA_PATH}/yara"; exit 1; }
[ ! -r "$YARA_RULES" ] && { log "ERROR - yara rules not readable at ${YARA_RULES}"; exit 1; }

# -w suppress warnings, -f fast mode, -r recurse not needed for a single file
MATCHES=$("${YARA_PATH}/yara" -w -f "$YARA_RULES" "$FILENAME" 2>/dev/null)

if [ -n "$MATCHES" ]; then
    while read -r line; do
        [ -z "$line" ] && continue
        RULE_NAME=$(echo "$line" | awk '{print $1}')
        log "INFO - Scan result: ${RULE_NAME} ${FILENAME}"
    done <<< "$MATCHES"
fi

exit 0
