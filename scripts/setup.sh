#!/usr/bin/env bash
# siem-home-lab :: first-run setup
#
# Checks prerequisites and generates a working .env with strong random
# secrets, so a fresh clone can reach a running stack without the reader
# having to invent passwords or read the whole README first.
#
# Safe to re-run: an existing .env is never overwritten.
#
#   bash scripts/setup.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
ok()   { printf '  %s[ ok ]%s %s\n'   "$GREEN"  "$OFF" "$1"; }
bad()  { printf '  %s[fail]%s %s\n'   "$RED"    "$OFF" "$1"; }
warn() { printf '  %s[warn]%s %s\n'   "$YELLOW" "$OFF" "$1"; }

echo "=============================================================================="
echo " siem-home-lab :: setup"
echo "=============================================================================="
echo ""
echo "Checking prerequisites"

MISSING=0

check_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        ok "$1 $( "$@" --version 2>/dev/null | head -1 | cut -c1-40 )"
    else
        bad "$1 not found - install with: sudo apt install -y $2"
        MISSING=1
    fi
}

check_cmd docker docker.io
check_cmd python3 python3
check_cmd git git

if docker compose version >/dev/null 2>&1; then
    ok "docker compose $(docker compose version --short 2>/dev/null)"
elif command -v docker-compose >/dev/null 2>&1; then
    ok "docker-compose (v1) - 'docker compose' v2 is recommended"
else
    bad "docker compose not found - install with: sudo apt install -y docker-compose-v2"
    MISSING=1
fi

if python3 -c "import requests" 2>/dev/null; then
    ok "python3 requests module"
else
    warn "python3 'requests' missing - Slack and threat-intel features need it"
    echo "        install with: sudo apt install -y python3-requests"
fi

if docker info >/dev/null 2>&1; then
    ok "docker daemon reachable"
else
    bad "cannot talk to the docker daemon"
    echo "        try: sudo usermod -aG docker \$USER   (then log out and back in)"
    MISSING=1
fi

CURRENT_MAP_COUNT="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
if [ "$CURRENT_MAP_COUNT" -ge 262144 ]; then
    ok "vm.max_map_count = $CURRENT_MAP_COUNT"
else
    warn "vm.max_map_count is $CURRENT_MAP_COUNT - the indexer needs 262144"
    echo "        sudo sysctl -w vm.max_map_count=262144"
    echo "        echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf"
fi

echo ""
echo "Configuring secrets"

random_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

if [ -f .env ]; then
    ok ".env already exists - leaving it untouched"
else
    if [ ! -f .env.example ]; then
        bad ".env.example is missing; cannot generate .env"
        exit 1
    fi
    cp .env.example .env
    # Generate the values that must never be left at a default.
    for key in CLUSTER_KEY INDEXER_PASSWORD API_PASSWORD DASHBOARD_PASSWORD; do
        value="$(random_secret)"
        if grep -q "^${key}=" .env; then
            sed -i "s|^${key}=.*|${key}=${value}|" .env
        else
            printf '%s=%s\n' "$key" "$value" >> .env
        fi
    done
    chmod 600 .env
    ok "generated .env with random cluster key and passwords (mode 600)"
    echo "        ${DIM}optional keys (Slack, VirusTotal, OTX) stay REPLACE_ME until you add them;${OFF}"
    echo "        ${DIM}those integrations are simply omitted rather than shipped broken.${OFF}"
fi

echo ""
if [ "$MISSING" -ne 0 ]; then
    echo "=============================================================================="
    echo " Setup incomplete - resolve the failures above, then re-run."
    echo "=============================================================================="
    exit 1
fi

cat <<'NEXT'
==============================================================================
 Ready. Next steps:

   make up        start the Wazuh stack (wait ~2 min for the indexer)
   make deploy    install the detection content into manager and agent
   make test      verify rules fire and nothing leaks

 Dashboard: https://localhost  (self-signed certificate)
 Login:     admin / the INDEXER_PASSWORD value in your .env
==============================================================================
NEXT
