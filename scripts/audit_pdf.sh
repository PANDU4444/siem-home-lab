#!/usr/bin/env bash
# siem-home-lab :: audit a PDF write-up before publishing it.
#
# Security write-ups are mostly terminal screenshots, and screenshots are the
# most common way a credential ends up in a public repository - no text scanner
# will ever see them. This extracts the text layer AND OCRs every embedded
# image, then greps both for secrets.
#
# Usage:  bash scripts/audit_pdf.sh "docs/My Write-up.pdf"
#
# Requires: poppler-utils (pdftotext, pdfimages) and tesseract-ocr.
set -uo pipefail

PDF="${1:-}"
[ -n "$PDF" ] && [ -f "$PDF" ] || {
    echo "usage: audit_pdf.sh <file.pdf>" >&2
    exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing '$1'. Install with: sudo apt install -y $2" >&2
        exit 1
    }
}
need pdftotext poppler-utils
need pdfimages poppler-utils
need tesseract tesseract-ocr

echo "=============================================================================="
echo " PDF publication audit: $PDF"
echo "=============================================================================="

# ---------------------------------------------------------------- text layer
pdftotext -layout "$PDF" "$WORK/text.txt" 2>/dev/null
echo ""
echo "Text layer: $(wc -c < "$WORK/text.txt") chars"

# ------------------------------------------------------------------- images
pdfimages -png "$PDF" "$WORK/img" 2>/dev/null
count=$(find "$WORK" -name 'img-*.png' | wc -l)
echo "Embedded images: $count (OCR in progress...)"

: > "$WORK/ocr.txt"
for img in "$WORK"/img-*.png; do
    [ -f "$img" ] || continue
    tesseract "$img" - --psm 6 2>/dev/null >> "$WORK/ocr.txt"
done

cat "$WORK/text.txt" "$WORK/ocr.txt" > "$WORK/all.txt"
echo "Combined text for analysis: $(wc -c < "$WORK/all.txt") chars"

FINDINGS=0
report() {
    local label="$1" pattern="$2"
    local hits
    hits="$(grep -inE "$pattern" "$WORK/all.txt" 2>/dev/null | head -12)"
    echo ""
    echo "--- $label ---"
    if [ -n "$hits" ]; then
        echo "$hits" | sed 's/^/    /'
        FINDINGS=1
    else
        echo "    none"
    fi
}

report "Credential-shaped tokens" \
  'gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|hooks\.slack\.com/services/T|BEGIN [A-Z ]*PRIVATE KEY'

report "Password assignments" \
  '(password|passwd|api[_ -]?key|token|secret)[[:space:]]*[:=][[:space:]]*[^[:space:]]{6,}'

echo ""
echo "--- Routable IP addresses ---"
ips="$(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$WORK/all.txt" 2>/dev/null | sort -u)"
found_ip=0
for ip in $ips; do
    python3 - "$ip" <<'PY'
import ipaddress, sys
try:
    a = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
cgnat = ipaddress.ip_network("100.64.0.0/10")  # leakscan:allow
sensitive = a in cgnat or not (a.is_private or a.is_loopback or a.is_link_local
                               or a.is_multicast or a.is_reserved or a.is_unspecified)
sys.exit(0 if sensitive else 1)
PY
    if [ $? -eq 0 ]; then
        echo "    $ip"
        found_ip=1; FINDINGS=1
    fi
done
[ "$found_ip" -eq 0 ] && echo "    none"

echo ""
echo "--- Email addresses ---"
emails="$(grep -oE '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' "$WORK/all.txt" 2>/dev/null | sort -u | head -10)"
if [ -n "$emails" ]; then
    echo "$emails" | sed 's/^/    /'
else
    echo "    none"
fi

echo ""
echo "=============================================================================="
if [ "$FINDINGS" -ne 0 ]; then
    echo " REVIEW REQUIRED - potential disclosures above."
    echo " OCR is imperfect; treat this as a prompt to look, not a verdict."
else
    echo " No credential patterns or routable addresses detected."
    echo " OCR is imperfect - a visual skim of screenshots is still worthwhile."
fi
echo "=============================================================================="
