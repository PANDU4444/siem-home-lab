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

Requires Docker, Docker Compose and Python 3 on a Linux host.

```bash
git clone https://github.com/PANDU4444/siem-home-lab.git
cd siem-home-lab
make setup     # checks prerequisites, generates .env with random secrets
make up        # starts the Wazuh stack (~2 min for the indexer)
make deploy    # installs detection content into manager and agent
make test      # verifies everything
```

Expected output from `make test`:

```
  [PASS] YARA ruleset compiles (7 rules)
  [PASS] XML files are well-formed
  [PASS] Python modules compile
  [PASS] shell scripts parse
  [PASS] Slack payload builds correctly (11 checks)
  [PASS] manager configuration is valid
  [PASS] detection rules fire (5 passed, 0 failed)
  [PASS] wazuh-agent is running
  [PASS] auditd is running (required by FIM whodata)
 9 passed, 0 failed, 0 skipped
```

Dashboard: `https://localhost` (self-signed certificate). Log in as `admin`
with the `INDEXER_PASSWORD` that `make setup` generated into your `.env`.

`make setup` never overwrites an existing `.env`, and no API keys are needed to
get a working stack — integrations whose keys are unset are simply left out.

Run `make` on its own to list every target.

| Target | What it does |
|---|---|
| `make setup` | Check prerequisites, generate `.env` |
| `make up` / `make down` | Start / stop the stack |
| `make deploy` | Install rules, YARA, FIM and auditd config |
| `make test` | Full verification suite |
| `make simulate` | Controlled end-to-end attack simulation |
| `make report` | Daily audit digest |
| `make soc-report` | Full historical SOC report |
| `make timer` | Install the daily audit systemd timer |
| `make clean` | Remove exported data and caches |

## Full installation

`make setup` covers most of this. The detail below is for anyone who wants to
know what those targets actually do, or needs to deviate from them.

### 1. Prerequisites

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 git python3 python3-requests yara
sudo usermod -aG docker "$USER"    # log out and back in
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

### 2. Configuration

`make setup` copies `.env.example` to `.env` and fills in a random
`CLUSTER_KEY`, `INDEXER_PASSWORD`, `API_PASSWORD` and `DASHBOARD_PASSWORD`.
Everything else is optional:

| Variable | Needed for | Where to get it |
|---|---|---|
| `CLUSTER_KEY` | Wazuh cluster auth (**required**) | generated by `make setup` |
| `INDEXER_PASSWORD` | Wazuh indexer | generated by `make setup` |
| `API_PASSWORD` | Wazuh API | generated by `make setup` |
| `DASHBOARD_PASSWORD` | Dashboard login | generated by `make setup` |
| `SLACK_WEBHOOK_URL` | Slack alerting | Slack → Incoming Webhooks |
| `VIRUSTOTAL_API_KEY` | Hash reputation | virustotal.com (free: 4/min) |
| `OTX_API_KEY` | OTX pulses | otx.alienvault.com (free) |
| `ABUSECH_AUTH_KEY` | ThreatFox + URLhaus | auth.abuse.ch (free) |

An integration whose key is still `REPLACE_ME` is **removed** from the
generated config rather than shipped in a broken state, so you can deploy now
and add keys later. `CLUSTER_KEY` is the exception: it fails loudly, because a
manager cannot start without one and a silent default would be worse.

### 3. Start the stack

```bash
make up
make status
```

### 4. Deploy detection content

```bash
make deploy
```

`deploy-manager` backs up the existing config, copies in rules, decoders and
integrations, renders `ossec.conf` from `.env`, validates with
`wazuh-analysisd -t`, and **only restarts if validation passes** — otherwise it
restores the backup.

`deploy-agent` installs YARA, auditd and the tuned FIM block, and rolls back
automatically if the agent fails to restart. The committed FIM config uses an
`__AGENT_HOME__` placeholder, substituted with the real home directory at
deploy time, so nothing in the repository is tied to one machine.

> **auditd is required.** FIM `whodata="yes"` will not start without it, and
> the agent then fails with no useful error. `make deploy` installs it.

### 5. Add an agent on another machine

```bash
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_amd64.deb
sudo WAZUH_MANAGER='<manager-ip>' dpkg -i ./wazuh-agent_4.14.0-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

Then run `make deploy-agent` on that machine.

### 6. Schedule the daily digest

```bash
make timer
```

The committed unit file carries a `__REPO_PATH__` placeholder; the installer
substitutes the real checkout path.

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

```bash
make test        # everything below, in one command
make simulate    # full detection chain, end to end
```

`make test` runs each check independently and reports all results rather than
stopping at the first failure. A check that *cannot* run — no Docker
permission, stack not started — reports `SKIP`, not `FAIL`, because conflating
"could not test" with "test failed" sends people debugging the wrong thing.

`make simulate` drops inert files (EICAR, reverse-shell text, a PHP webshell,
a miner config, an obfuscated downloader), generates SSH failure telemetry, and
reports which YARA rules matched and which alerts were produced. Nothing it
writes is executed. A recent run:

```
SHL_EICAR_Test_File          /tmp/shl-attack-sim/eicar_test.txt
SHL_Linux_Reverse_Shell      /tmp/shl-attack-sim/rev_shell.sh
SHL_PHP_Webshell             /tmp/shl-attack-sim/shell.php
SHL_Obfuscated_Shell_Payload /tmp/shl-attack-sim/dropper.sh
SHL_Cryptominer_Config       /tmp/shl-attack-sim/miner.json
```

## Repository layout

```
siem-home-lab/
├── Makefile                 Single entry point - run `make` to list targets
├── .env.example             Config template; `make setup` generates .env
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
│   └── reports/             Generated reports (sample output committed)
└── scripts/
    ├── setup.sh             Prerequisite check + .env generation
    ├── deploy_to_*.sh       Validated deploys with automatic rollback
    ├── render_config.py     Secret substitution into the config template
    ├── run_tests.sh         Verification suite
    └── install_timer.sh     Installs the systemd timer for this checkout
```

The whole repository is about 180 KB. It holds no binaries, no screenshots and
no captured data — `make` regenerates anything that can be regenerated.

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

7. **The riskiest file was the one nobody thought to scan.** This repository
   used to ship a 10 MB PDF write-up: 77 pages, 101 terminal screenshots, and
   97% of the repository's total size. No text scanner could see inside those
   images. OCRing them found no credentials, but did surface the lab's public
   cloud addresses in shell prompts and dashboards.

   Redacting it proved harder than expected. Drawing a black box over an image
   is not redaction — the original pixels remain in the file. Destroying the
   pixels worked, but OCR at 300 DPI and at 400 DPI recognised *different*
   subsets of the same page, so raising the resolution never converged. Two
   passes reported "clean" while the address was plainly legible on screen;
   only opening the page and looking caught it.

   The conclusion: OCR-based redaction cannot honestly be called a guarantee.
   The PDF was removed rather than patched, which is also why a clone is about
   208 KB instead of 10 MB.

8. **Deduplication is the whole game.** 93% of this lab's alert volume was
   repetition. Any triage process that reads raw alerts instead of grouped
   incidents spends almost all of its time re-reading events it has already seen.

---

## Credits

Built on [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker) (GPLv2).
Detection content, integrations, automation and analysis tooling in this
repository are original work.
