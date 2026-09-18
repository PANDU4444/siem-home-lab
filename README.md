# SIEM Home Lab

A working Wazuh 4.14 detection lab: custom ATT&CK-mapped rules, YARA malware
scanning wired to file-integrity monitoring, tiered Slack alerting, and a daily
audit digest that turns a noisy alert feed into a short list of real incidents.

Everything here has been deployed and verified on a live stack, not just
written down. The numbers in this README come from that deployment.

---

## Contents

- [What this demonstrates](#what-this-demonstrates)
- [Verified results](#verified-results)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Full installation](#full-installation)
- [Detection content](#detection-content)
- [Integrations](#integrations)
- [Automation](#automation)
- [Analysis and reporting](#analysis-and-reporting)
- [Verifying it works](#verifying-it-works)
- [Repository layout](#repository-layout)
- [Lessons learned](#lessons-learned)

---

## What this demonstrates

| Capability | What was built |
|---|---|
| **Detection engineering** | 18 custom Wazuh rules, every one mapped to MITRE ATT&CK, covering brute force, privilege escalation, persistence, credential access and defense evasion |
| **Malware detection** | 7 YARA rules driven by an active-response hook, so any file written to a monitored path is scanned the moment it lands |
| **File integrity monitoring** | Stock FIM retuned: 12-hour scans dropped to 1 hour, `whodata` enabled so alerts name *who* changed a file, realtime watches on write-heavy paths |
| **Alert routing** | Custom Slack integration with severity tiers, ATT&CK context in the message, and a dedup window that collapses alert storms |
| **Audit reporting** | A daily digest that deduplicates the feed into incidents and reports ATT&CK techniques rather than raw rule counts |
| **Threat intelligence** | Enrichment across VirusTotal, AlienVault OTX, ThreatFox and URLhaus, with caching and client-side rate limiting |
| **Log analysis** | A SOC report generated from 28,838 real alerts spanning 69 days |
| **Safe-by-default reporting** | Reports redact routable addresses and host hashes automatically, so they can be shared or committed without leaking lab internals |

---

## Verified results

These are measured outputs from the running lab, reproducible with the scripts
in this repository.

**Rule verification** — `sudo bash scripts/test_rules.sh`

```
  [PASS] Single SSH auth failure                      rule 100101 (level 5)
  [PASS] SSH brute force burst (12 failures)          rule 100102 (level 12)
  [PASS] Successful SSH login as root                 rule 100104 (level 10)
  [PASS] New user account created                     rule 100110 (level 10)
  [PASS] YARA active-response match                   rule 100141 (level 12)
  5 passed, 0 failed
```

**End-to-end detection** — files dropped on disk produced real alerts:

| Rule | Detection | ATT&CK | Alerts |
|---|---|---|---:|
| `100141` | YARA malware match | T1204.002, T1059 | 4 |
| `100112` | Privilege escalation to root via sudo | T1548.003 | 15 |
| `100101` | SSH authentication failure | T1110.001 | 11 |
| `100133` | System binary modified | T1565.001 | 4 |
| `100102` | SSH brute force (correlated) | T1110.001 | 1 |
| `100171` | Security tooling modified | T1562.001 | 1 |

**Deduplication** — the core value of the daily digest:

| Dataset | Raw alerts | Distinct incidents | Noise removed |
|---|---:|---:|---:|
| Last 24 hours | 4,974 | 472 | **90.5%** |
| Full 69-day archive | 28,838 | 1,986 | **93.1%** |

A SOC triaging raw alerts would read 28,838 items to find the handful that
mattered. Figures come from a single generated run; the lab keeps producing
telemetry, so re-running the scripts gives slightly different totals.

**Slack payload** — `python3 scripts/test_slack.py` runs the integration
against a local receiver and asserts the Block Kit structure. 11/11 checks pass
without needing a Slack workspace.

---

## Architecture

```
                        ┌──────────────────────────────────────┐
                        │   Ubuntu host  (Wazuh agent 001)     │
                        │                                      │
   file written  ──────▶│  syscheck (realtime + whodata)       │
                        │        │                             │
                        │        ▼                             │
                        │  active response ──▶ yara.sh         │
                        │        │              (7 rules)      │
                        │        ▼                             │
                        │  active-responses.log                │
                        │  auditd (24 rules)                   │
                        └──────────────┬───────────────────────┘
                                       │  agent channel :1514
                                       ▼
   ┌───────────────────────────────────────────────────────────┐
   │        Wazuh manager  (Docker, Amazon Linux 2023)         │
   │                                                           │
   │   local_decoder.xml  ──▶  local_rules.xml (18 rules)      │
   │                                │                          │
   │              ┌─────────────────┼──────────────────┐       │
   │              ▼                 ▼                  ▼       │
   │      custom-slack        custom-n8n         virustotal    │
   │      (level 10+)         (level 3+)         (FIM events)  │
   └───────────────────────────────┬───────────────────────────┘
                                   │
                ┌──────────────────┼───────────────────┐
                ▼                  ▼                   ▼
        wazuh-indexer       alerts.json          daily_audit.py
        + dashboard          archive          (dedup + ATT&CK digest)
```

**Why YARA runs on the agent, not the manager.** Active response executes where
the event originated. Files live on the endpoint, so scanning belongs there.
The manager only needs the decoder and rule to interpret what comes back. (The
manager image is Amazon Linux 2023, which has no YARA package anyway.)

---

## Quick start

Requires Docker, Docker Compose, and a Linux host for the agent.

```bash
git clone https://github.com/PANDU4444/siem-home-lab.git
cd siem-home-lab
cp .env.example .env
```

Edit `.env` and set at minimum `INDEXER_PASSWORD`, `API_PASSWORD` and
`DASHBOARD_PASSWORD`. Then:

```bash
docker compose -f docker/single-node/docker-compose.yml --env-file .env up -d
```

Wait about two minutes for the indexer to become healthy, then deploy the
detection content:

```bash
sudo bash scripts/deploy_to_manager.sh
sudo bash scripts/deploy_to_agent.sh
```

Verify:

```bash
sudo bash scripts/test_rules.sh
```

The dashboard is at `https://localhost` (self-signed certificate).

---

## Full installation

### 1. Prerequisites

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 git python3 python3-requests
sudo usermod -aG docker "$USER"   # log out and back in
```

Raise the map count the indexer needs:

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

### 2. Configuration

```bash
cp .env.example .env
```

Every value is optional except the three stack passwords. Integrations whose
secrets are still `REPLACE_ME` are **removed from the generated config** by
`scripts/render_config.py` rather than shipped in a broken state, so you can
deploy now and add keys later.

| Variable | Needed for | Where to get it |
|---|---|---|
| `CLUSTER_KEY` | Wazuh cluster auth (**required**) | `openssl rand -hex 16` |
| `INDEXER_PASSWORD` | Wazuh indexer | you choose |
| `API_PASSWORD` | Wazuh API | you choose |
| `DASHBOARD_PASSWORD` | Dashboard login | you choose |
| `SLACK_WEBHOOK_URL` | Slack alerting | Slack → Incoming Webhooks |
| `VIRUSTOTAL_API_KEY` | Hash reputation | virustotal.com (free: 4/min) |
| `OTX_API_KEY` | OTX pulses | otx.alienvault.com (free) |
| `ABUSECH_AUTH_KEY` | ThreatFox + URLhaus | auth.abuse.ch (free) |

### 3. Certificates and stack

```bash
docker compose -f docker/single-node/docker-compose.yml --env-file .env \
  run --rm generator
docker compose -f docker/single-node/docker-compose.yml --env-file .env up -d
docker compose -f docker/single-node/docker-compose.yml ps
```

### 4. Deploy detection content to the manager

```bash
sudo bash scripts/deploy_to_manager.sh
```

This backs up the existing config, copies rules/decoders/integrations in,
renders `ossec.conf` from `.env`, validates with `wazuh-analysisd -t`, and
**only restarts if validation passes** — otherwise it restores the backup.

### 5. Install the agent

On the machine you want monitored:

```bash
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_amd64.deb
sudo WAZUH_MANAGER='<manager-ip>' dpkg -i ./wazuh-agent_4.14.0-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

Then deploy YARA and the tuned FIM:

```bash
sudo bash scripts/deploy_to_agent.sh
```

This installs YARA, installs the ruleset and active-response script, swaps in
the tuned `syscheck` block, and rolls back automatically if the agent fails to
restart.

> **auditd is required.** `whodata="yes"` will not start without it. The script
> installs `auditd` and the 24 lab audit rules from
> `wazuh/audit/siem-home-lab.rules`.

### 6. Schedule the daily digest

```bash
sudo bash scripts/install_timer.sh
```

The committed unit file carries a `__REPO_PATH__` placeholder rather than any
one machine's layout; the installer substitutes the real path.

---

## Detection content

Custom rules occupy `100100–100199`. Full source:
[`wazuh/rules/local_rules.xml`](wazuh/rules/local_rules.xml).

| Rule | Level | Detection | ATT&CK |
|---|---:|---|---|
| 100101 | 5 | SSH authentication failure | T1110.001 |
| 100102 | 12 | SSH brute force — 8+ failures from one IP in 120s | T1110.001 |
| 100103 | 14 | Successful login **after** brute force — likely compromise | T1110.001, T1078 |
| 100104 | 10 | Direct SSH login as root | T1078.003 |
| 100110 | 10 | New user account created | T1136.001 |
| 100111 | 12 | Account added to a privileged group | T1098 |
| 100112 | 12 | Privilege escalation to root via sudo | T1548.003 |
| 100130 | 12 | Credential file modified (`passwd`/`shadow`/`sudoers`) | T1003.008, T1098 |
| 100131 | 12 | Cron or systemd unit changed | T1053.003, T1543.002 |
| 100132 | 12 | SSH key material changed | T1098.004 |
| 100133 | 10 | System binary modified | T1565.001 |
| 100141 | 12 | YARA malware match | T1204.002, T1059 |
| 100150 | 12 | Web exploitation attempt | T1190 |
| 100151 | 10 | Path traversal / LFI | T1083, T1190 |
| 100170 | 12 | Log cleared — anti-forensics | T1070.002 |
| 100171 | 12 | Security tooling removed or modified | T1562.001 |
| 100180 | 10 | Encoded or inline interpreter command via sudo | T1027, T1059 |

Rule 100103 is the one worth pointing at: it fires only when a *successful*
login follows a brute-force burst **from the same IP**, which is the difference
between "someone is knocking" and "someone got in".

### YARA ruleset

[`yara/rules/siem_home_lab.yar`](yara/rules/siem_home_lab.yar) — 7 rules:
EICAR test file, Linux reverse shells, PHP webshells, obfuscated
download-and-execute payloads, cryptominer configs, cron downloaders, and
Meterpreter/msfvenom ELF markers.

### FIM tuning

| Setting | Stock | Tuned | Why |
|---|---|---|---|
| Scan frequency | 43200s (12h) | 3600s (1h) | A change is caught within the hour |
| `whodata` | off | on for `/etc`, cron, SSH keys | Alerts name the user and process, not just the file |
| `realtime` | off | on for `/tmp`, `/var/www`, `/home`, binaries | YARA fires the moment a payload lands |
| `nodiff` | `/etc/ssl/private.key` | + `shadow`, `gshadow`, `*.key`, `*.pem` | Stops credential hashes being written into alert diffs |
| Ignores | minimal | 12 patterns | Suppresses caches, editor swap files, VM churn |

---

## Integrations

### Slack — [`integrations/slack/custom-slack.py`](integrations/slack/custom-slack.py)

The stock Wazuh Slack integration posts a flat text blob. This one builds Block
Kit messages with the agent, source IP, file and ATT&CK technique as separate
fields, so an analyst can triage from the notification itself.

- **Severity tiers** decide colour and icon: CRITICAL (15+), HIGH (12+),
  MEDIUM (8+), LOW (5+), INFO.
- **Escalation** at level 12+ adds a channel mention — this is what pages the SOC.
- **Deduplication** collapses repeats of the same `(rule, agent, source)` inside
  a 5-minute window, so a brute-force burst is one message rather than eighty.
  Escalation-tier alerts always bypass the dedup window.

Test it without a workspace:

```bash
python3 scripts/test_slack.py
```

### n8n and VirusTotal

`custom-n8n` forwards level 3+ alerts for automation/ticketing. The stock
`virustotal` integration is scoped to `syscheck` events only, keeping lookups
inside the free tier's 500/day.

---

## Automation

### Daily audit digest — [`automation/daily_audit.py`](automation/daily_audit.py)

```bash
python3 automation/daily_audit.py --hours 24 --stdout
```

Deduplicates the feed into incidents, groups by ATT&CK tactic and technique,
ranks the noisiest rules as tuning candidates, and extracts indicators for
enrichment. Writes Markdown and JSON to `analysis/reports/`.

The grouping key is `(rule_id, agent, source, target)`. One IP brute-forcing
two hosts stays two incidents; eighty attempts against one host become one.

### Threat intelligence — [`automation/threat_intel_enrich.py`](automation/threat_intel_enrich.py)

```bash
python3 automation/threat_intel_enrich.py --from-alerts .data/alerts.json --hours 24
python3 automation/threat_intel_enrich.py --ip 192.0.2.10 --hash <sha256>
```

Queries VirusTotal, OTX, ThreatFox and URLhaus, then combines them into one
verdict (`MALICIOUS` / `SUSPICIOUS` / `LOW CONFIDENCE` / `NO DATA`) with the
evidence that produced it. Results cache for 24h; VirusTotal is rate-limited
client-side to 4/min so a re-run never burns the free-tier budget.

Missing keys disable a source cleanly — it reports `skipped`, never fails.

---

## Analysis and reporting

```bash
python3 analysis/analyze_alerts.py --archive-dir .data/alerts
```

Reads the full rotated archive and produces a SOC report: severity
distribution, ATT&CK coverage, day-by-day timeline, notable incidents, rule
volume ranking, and analyst findings.

Sample output from this lab: [`analysis/reports/soc-report.md`](analysis/reports/soc-report.md)
— 28,838 alerts, 69 days, 17 ATT&CK techniques.

One finding it surfaced: a single rule (`23502`, a dnsmasq CVE notice) produced
**27% of all alerts** in the dataset — the highest-value tuning target in the
deployment, and not something visible from a dashboard.

---

## Verifying it works

| Check | Command |
|---|---|
| Rules fire correctly | `sudo bash scripts/test_rules.sh` |
| Slack payload is valid | `python3 scripts/test_slack.py` |
| YARA ruleset compiles | `yara -w yara/rules/siem_home_lab.yar /etc/hostname` |
| Manager config is valid | `docker exec <manager> /var/ossec/bin/wazuh-analysisd -t` |
| Full detection chain | `sudo bash scripts/attack-simulation/attack_sim.sh` |
| Repo contains no secrets | `python3 scripts/leakscan.py . HEAD` |
| A PDF write-up is safe to publish | `bash scripts/audit_pdf.sh <file.pdf>` |

The attack simulation drops inert files (EICAR, reverse-shell text, a PHP
webshell, a miner config), generates SSH failure telemetry, and reports which
YARA rules matched and which alerts were produced. Nothing it writes is
executed.

---

## Security and privacy

This repository is public, so nothing in it may carry live credentials or
identify the lab's network. Three mechanisms enforce that.

**Secrets never enter version control.** `wazuh/config/ossec.conf` is a
template: the Wazuh cluster key, Slack webhook, and API keys are
`__PLACEHOLDER__` tokens that `scripts/render_config.py` substitutes from
`.env` at deploy time. `CLUSTER_KEY` is treated as fatal if unset, because a
manager cannot start without one and a silent default would be worse than a
loud failure. Integrations whose key is still unset are *removed* from the
rendered config rather than shipped broken.

**Reports are anonymised by default.** Raw Wazuh output contains routable
source addresses and a hash of every file that changed on the host — neither
belongs in a public repo. `automation/anonymize.py` redacts them, and opting
out (`--no-anonymize`) is the explicit choice. Redaction is *stable*, so
"the same source hit us 35 times" survives it. Private RFC1918 addresses are
deliberately preserved: they describe lab topology and nothing more.

**The repo is scanned, not assumed clean.** `scripts/leakscan.py` reads what
git actually has committed on a ref and classifies findings by severity.
`scripts/audit_pdf.sh` goes further for write-ups: it OCRs every embedded
screenshot, because a credential in a terminal screenshot is invisible to any
text-based scanner and is the most common way one leaks.

```bash
python3 scripts/leakscan.py . HEAD        # scan committed content
bash scripts/audit_pdf.sh report.pdf      # scan a PDF, screenshots included
```

---

## Repository layout

```
siem-home-lab/
├── docker/single-node/      Compose stack, secrets via .env
├── wazuh/
│   ├── rules/               18 custom ATT&CK-mapped rules
│   ├── decoders/            YARA output decoder
│   ├── audit/               24 auditd rules
│   ├── config/              Generated ossec.conf template
│   └── config-fragments/    Tuned FIM block
├── yara/
│   ├── rules/               7 YARA detection rules
│   └── active-response/     FIM-triggered scan hook
├── integrations/slack/      Custom Slack integration
├── automation/
│   ├── wazuh_alerts.py      Shared alert loading + dedup
│   ├── anonymize.py         Redaction applied to reports by default
│   ├── daily_audit.py       Daily MITRE-mapped digest
│   ├── threat_intel_enrich.py
│   └── systemd/             Timer units
├── analysis/
│   ├── analyze_alerts.py    Historical SOC report
│   └── reports/             Generated reports
└── scripts/
    ├── deploy_to_*.sh       Validated deploys with automatic rollback
    ├── render_config.py     Secret substitution into the config template
    ├── leakscan.py          Committed-content secret scanner
    ├── audit_pdf.sh         OCR audit of a PDF before publishing
    ├── install_timer.sh     Installs the systemd timer for this checkout
    └── test_*.sh | .py      Verification suite
```

---

## Lessons learned

Things that went wrong during the build, and what they taught:

1. **`dstuser` is a static field in Wazuh.** Writing
   `<field name="dstuser">` fails validation with *"Field 'dstuser' is
   static"*; the correct tag is `<user>`. Caught by `wazuh-analysisd -t` before
   any restart — which is exactly why every deploy script validates first.

2. **Invalid-user SSH failures are SID 5710, not 5716.** The brute-force rule
   originally chained off 5716 only and silently never fired for
   `invalid user` attempts — the most common brute-force pattern. Found with
   `wazuh-logtest`, not by reading config.

3. **`whodata` will not start without auditd.** The agent refused to boot with
   no useful error beyond a config failure. Installing `auditd` fixed it, and
   turned into a feature: 24 audit rules now provide execve and privilege
   telemetry.

4. **New subdirectories are not covered by existing inotify watches.** Files
   written into a directory created *after* the agent started were not picked
   up in realtime until the next scheduled scan. Worth knowing before trusting
   realtime FIM for arbitrary paths.

5. **Installing YARA tripped the trojanised-binary rule.** Rule 100133 fired on
   `/usr/bin/yara.dpkg-new` during `apt install`. The detection was correct —
   the lesson is that FIM on binary directories needs a package-manager
   suppression window, or it will alert on every legitimate upgrade.

6. **A committed config file leaked a real credential.** The generated
   `ossec.conf` carried the Wazuh `<cluster><key>` verbatim. It survived the
   first review because it looks like an ordinary hash, not a password — the
   scanner initially rated it "MEDIUM: hash". Two lessons: a secret scanner
   must understand *context*, not just shape; and the same file had a second
   `<key>` holding an SSL certificate *path*, so a naive blanket redaction
   would have silently broken Filebeat.

7. **The riskiest file was the one nobody thought to scan.** A 10 MB PDF
   write-up sat in the repo containing 101 terminal screenshots. No text
   scanner could see inside them. OCRing all 101 found no credentials but did
   surface routable VPS addresses — which is exactly the check that would
   otherwise never have happened.

8. **Deduplication is the whole game.** 93% of this lab's alert volume was
   repetition. Any triage process that reads raw alerts instead of grouped
   incidents spends almost all of its time re-reading events it has already seen.

---

## Credits

Built on [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker) (GPLv2).
Detection content, integrations, automation and analysis tooling in this
repository are original work.
