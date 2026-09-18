# SOC Analysis Report

_siem-home-lab - Wazuh 4.14 single-node deployment_

| | |
|---|---|
| **Report generated** | 2026-09-18 01:39:30Z |
| **Data window** | 2026-07-11 03:58:13Z to 2026-09-18 01:39:27Z |
| **Span** | 69 day(s) |
| **Archive files read** | 28 |
| **Raw alerts analysed** | 28,838 |
| **Distinct incidents** | 1,986 |
| **Noise removed by dedup** | 93.1% |

## 1. Executive summary

Across 28,838 alerts spanning 69 days, deduplication reduced the feed to **1,986 distinct incidents** - 93.1% of raw alert volume was repetition of activity already accounted for.

**9** incident(s) reached high severity or above and would warrant analyst review in a production SOC.

The single most important operational finding is the signal-to-noise ratio: a SOC that triages raw alerts would process 28,838 items to find the same 9 that matter.

## 2. Severity distribution

| Severity | Incidents | Share |
|---|---:|---|
| HIGH | 9 | `#` 0.5% |
| MEDIUM | 33 | `#` 1.7% |
| LOW | 1,890 | `###########################` 95.2% |
| INFO | 54 | `#` 2.7% |

## 3. MITRE ATT&CK coverage

### 3.1 Tactics exercised

| Tactic | Alert volume | Share |
|---|---:|---|
| Impact | 2,611 | `##########` |
| Defense Evasion | 1,739 | `#######` |
| Privilege Escalation | 975 | `####` |
| Persistence | 800 | `###` |
| Initial Access | 793 | `###` |
| Credential Access | 343 | `#` |
| Lateral Movement | 68 | `#` |
| Execution | 18 | `#` |

### 3.2 Techniques observed

| Technique | Name | Alert volume |
|---|---|---:|
| `T1565.001` | Stored Data Manipulation | 1,857 |
| `T1078` | Valid Accounts | 793 |
| `T1070.004` | File Deletion | 754 |
| `T1485` | Data Destruction | 740 |
| `T1110.001` | Password Guessing | 303 |
| `T1548.003` | Sudo and Sudo Caching | 176 |
| `T1021.004` | SSH | 49 |
| `T1110` | Brute Force | 40 |
| `T1021` | Remote Services | 19 |
| `T1562.001` | Disable or Modify Tools | 14 |
| `T1561.001` | Disk Content Wipe | 14 |
| `T1204.002` | Malicious File | 12 |
| `T1059` | Command and Scripting Interpreter | 12 |
| `T1053.003` | Cron | 6 |
| `T1543.002` | Systemd Service | 6 |
| `T1014` | Rootkit | 2 |
| `T1136` | Create Account | 1 |

_17 distinct ATT&CK techniques were observed in this dataset._

## 4. Activity timeline

| Date | Alerts | |
|---|---:|---|
| 2026-07-11 | 736 | `##` |
| 2026-07-12 | 551 | `##` |
| 2026-07-13 | 123 | `#` |
| 2026-07-14 | 81 | `#` |
| 2026-07-15 | 4,360 | `############` |
| 2026-07-16 | 100 | `#` |
| 2026-07-17 | 3,671 | `##########` |
| 2026-07-18 | 110 | `#` |
| 2026-07-22 | 34 | `#` |
| 2026-07-23 | 79 | `#` |
| 2026-07-24 | 341 | `#` |
| 2026-07-28 | 34 | `#` |
| 2026-08-04 | 79 | `#` |
| 2026-08-05 | 54 | `#` |
| 2026-08-07 | 7 | `#` |
| 2026-08-13 | 380 | `#` |
| 2026-08-19 | 30 | `#` |
| 2026-08-20 | 49 | `#` |
| 2026-08-31 | 29 | `#` |
| 2026-09-08 | 77 | `#` |
| 2026-09-09 | 62 | `#` |
| 2026-09-10 | 276 | `#` |
| 2026-09-12 | 70 | `#` |
| 2026-09-13 | 58 | `#` |
| 2026-09-14 | 7,441 | `#####################` |
| 2026-09-17 | 58 | `#` |
| 2026-09-18 | 9,948 | `############################` |

Busiest day was **2026-09-18** with 9,948 alerts.

## 5. Notable incidents

| Sev | Rule | Description | Agent | Source | Count | First seen | Last seen |
|---|---|---|---|---|---:|---|---|
| HIGH | `23506` | CVE-2021-3773 affects linux-image-6.17.0-40-generic | kali2 | - | 297 | 2026-07-15 15:23:00Z | 2026-09-14 20:36:27Z |
| HIGH | `100112` | Privilege escalation to root via sudo by pandu | kali2 | pandu | 66 | 2026-09-18 00:49:20Z | 2026-09-18 01:39:27Z |
| HIGH | `40112` | Multiple authentication failures followed by a success. | kali2 | redacted-ip-1 | 35 | 2026-07-12 23:31:48Z | 2026-07-12 23:32:07Z |
| HIGH | `100141` | YARA match: rule SHL_Linux_Reverse_Shell matched file /home/<user> | kali2 | - | 12 | 2026-09-18 01:07:00Z | 2026-09-18 01:34:21Z |
| HIGH | `100171` | Security tooling package removed or modified - possible defense e | kali2 | - | 2 | 2026-09-18 01:01:38Z | 2026-09-18 01:01:38Z |
| HIGH | `100102` | SSH brute force: 8+ failed logins from 10.0.2.99 within 120s | kali2 | 10.0.2.99 | 2 | 2026-09-18 01:06:46Z | 2026-09-18 01:06:46Z |
| HIGH | `100131` | Scheduled task or unit file changed: /etc/systemd/system/timers.t | kali2 | - | 2 | 2026-09-18 01:38:00Z | 2026-09-18 01:38:00Z |
| HIGH | `100131` | Scheduled task or unit file changed: /etc/systemd/system/siem-dai | kali2 | - | 2 | 2026-09-18 01:38:00Z | 2026-09-18 01:38:00Z |
| HIGH | `100131` | Scheduled task or unit file changed: /etc/systemd/system/siem-dai | kali2 | - | 2 | 2026-09-18 01:38:00Z | 2026-09-18 01:38:00Z |
| MEDIUM | `521` | Possible kernel level rootkit | kali2 | - | 2 | 2026-09-18 00:52:03Z | 2026-09-18 00:52:03Z |
| MEDIUM | `23505` | CVE-2025-12198 affects dnsmasq-base | kali2 | - | 2260 | 2026-07-15 15:22:45Z | 2026-09-14 20:36:27Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yara.dpkg-new - possible trojani | kali2 | - | 2 | 2026-09-18 00:58:29Z | 2026-09-18 00:58:29Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yarac.dpkg-new - possible trojan | kali2 | - | 2 | 2026-09-18 00:58:29Z | 2026-09-18 00:58:29Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yara - possible trojanised binar | kali2 | - | 2 | 2026-09-18 00:58:29Z | 2026-09-18 00:58:29Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yarac - possible trojanised bina | kali2 | - | 2 | 2026-09-18 00:58:30Z | 2026-09-18 00:58:30Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/ambiguous_words.dpkg-new - possi | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/classifier_tester.dpkg-new - pos | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/ambiguous_words - possible troja | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/classifier_tester - possible tro | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/cntraining - possible trojanised | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/combine_lang_model - possible tr | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/combine_tessdata - possible troj | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/dawg2wordlist - possible trojani | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/lstmeval - possible trojanised b | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/lstmtraining - possible trojanis | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/merge_unicharsets - possible tro | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/mftraining - possible trojanised | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/set_unicharset_properties - poss | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/shapeclustering - possible troja | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/tesseract - possible trojanised  | kali2 | - | 2 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |

## 6. Rule volume and tuning candidates

Rules are ranked by raw alert volume. High-volume, low-severity rules are tuning candidates: they cost triage time without changing outcomes.

| Rank | Rule | Description | Alerts |
|---:|---|---|---:|
| 1 | `23502` | The CVE-2026-12969 that affected dnsmasq-base was solved due to an upd | 6,688 |
| 2 | `87915` | Docker: Volume mounted on /var/lib/wazuh-indexer | 4,075 |
| 3 | `87916` | Docker: Volume unmounted from local | 4,029 |
| 4 | `23505` | CVE-2025-12198 affects dnsmasq-base | 2,260 |
| 5 | `23504` | CVE-2026-14324 affects gstreamer1.0-pipewire | 2,049 |
| 6 | `550` | Integrity checksum changed. | 1,813 |
| 7 | `554` | File added to the system. | 1,261 |
| 8 | `23508` | CVE-2026-47709 affects heif-gdk-pixbuf (Missing information, CVE await | 1,016 |
| 9 | `2904` | Dpkg (Debian Package) half configured. | 748 |
| 10 | `553` | File deleted. | 739 |
| 11 | `5501` | PAM: Login session opened. | 739 |
| 12 | `2902` | New dpkg (Debian Package) installed. | 481 |
| 13 | `86003` | Docker: Error message | 317 |
| 14 | `23506` | CVE-2021-3773 affects linux-image-6.17.0-40-generic | 297 |
| 15 | `5502` | PAM: Login session closed. | 260 |
| 16 | `5503` | PAM: User login failed. | 230 |
| 17 | `533` | Listened ports status (netstat) changed (new port opened or closed). | 178 |
| 18 | `19007` | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure all AppArmor Prof | 127 |
| 19 | `19008` | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure mounting of cramf | 118 |
| 20 | `5402` | Successful sudo to ROOT executed. | 100 |

## 7. Activity by agent

| Agent | Alerts | Share |
|---|---:|---|
| kali2 | 28,351 | `############################` |
| wazuh.manager | 259 | `#` |
| agent-kalinew | 228 | `#` |

## 8. Indicators extracted

- **file_hash** (4206): `00032ccb...[24 chars redacted]`, `000943de...[56 chars redacted]`, `004a650f...[32 chars redacted]`, `004ddcfc...[32 chars redacted]`, `0052ad74...[56 chars redacted]`, `0053d3b5...[24 chars redacted]`, `005519d9...[24 chars redacted]`, `005e306b...[32 chars redacted]`, `007638ca...[32 chars redacted]`, `0091b6d3...[24 chars redacted]`, `00990f71...[56 chars redacted]`, `00a54905...[32 chars redacted]`, `00ab5fc6...[56 chars redacted]`, `00b1b170...[56 chars redacted]`, `00b2e2ef...[56 chars redacted]`
- **ip** (2): `redacted-ip-1`, `198.51.100.150`

Run `automation/threat_intel_enrich.py` to score these against VirusTotal, OTX, ThreatFox and URLhaus.

## 9. Analyst findings

1. **Alert volume is dominated by repetition.** 93.1% of alerts were duplicates of an incident already counted. Any triage process that reads raw alerts rather than grouped incidents will spend almost all of its time re-reading the same events.

2. **One rule produces 23% of all alerts** (`23502` - The CVE-2026-12969 that affected dnsmasq-base was solved due to an update in the). This single rule is the highest-value tuning target in the deployment.

3. **7 custom rules fired**, confirming the lab's own detection content is active and not merely installed.

4. **No level-15 critical incidents.** The highest observed severity was level 12-14, consistent with simulated rather than live intrusion.

---

_Generated by siem-home-lab `analysis/analyze_alerts.py`. All figures derive from the Wazuh alert archive; none are synthetic._

> Anonymisation enabled. 17 value(s) redacted, including 1 distinct routable address(es). Private addresses are shown as-is because they describe lab topology only. Redaction is stable, so repeated indicators remain correlatable.
