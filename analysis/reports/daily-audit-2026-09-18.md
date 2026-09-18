# Daily Security Audit

| | |
|---|---|
| **Window** | 2026-09-17 01:39:30Z to 2026-09-18 01:39:30Z (24h) |
| **Generated** | 2026-09-18 01:39:31Z |
| **Raw alerts** | 4,974 |
| **Distinct incidents** | 472 |
| **Noise removed by dedup** | 90.5% |

## Executive summary

**7 incident(s) at high severity or above require review.**

4,974 raw alerts collapsed into 472 distinct incidents (90.5% of the feed was repetition of activity already counted).

## Severity breakdown

| Severity | Incidents |
|---|---:|
| HIGH | 7 |
| MEDIUM | 25 |
| LOW | 425 |
| INFO | 15 |

## MITRE ATT&CK coverage

### Tactics observed

| Tactic | Alert volume |
|---|---:|
| Defense Evasion | 327 |
| Privilege Escalation | 287 |
| Impact | 278 |
| Persistence | 244 |
| Initial Access | 241 |
| Credential Access | 12 |
| Execution | 9 |

### Techniques observed

| Technique | Name | Alert volume |
|---|---|---:|
| `T1565.001` | Stored Data Manipulation | 242 |
| `T1078` | Valid Accounts | 241 |
| `T1548.003` | Sudo and Sudo Caching | 43 |
| `T1070.004` | File Deletion | 36 |
| `T1485` | Data Destruction | 36 |
| `T1110.001` | Password Guessing | 12 |
| `T1204.002` | Malicious File | 6 |
| `T1059` | Command and Scripting Interpreter | 6 |
| `T1562.001` | Disable or Modify Tools | 6 |
| `T1053.003` | Cron | 3 |
| `T1543.002` | Systemd Service | 3 |
| `T1014` | Rootkit | 1 |

## Incidents (deduplicated)

| Sev | Rule | Description | Agent | Source | Count | First seen | Last seen |
|---|---|---|---|---|---:|---|---|
| HIGH | `100112` | Privilege escalation to root via sudo by pandu | kali2 | pandu | 33 | 2026-09-18 00:49:20Z | 2026-09-18 01:39:27Z |
| HIGH | `100141` | YARA match: rule SHL_Linux_Reverse_Shell matched file /home/<user>/siem | kali2 | - | 6 | 2026-09-18 01:07:00Z | 2026-09-18 01:34:21Z |
| HIGH | `100171` | Security tooling package removed or modified - possible defense evasio | kali2 | - | 1 | 2026-09-18 01:01:38Z | 2026-09-18 01:01:38Z |
| HIGH | `100102` | SSH brute force: 8+ failed logins from 10.0.2.99 within 120s | kali2 | 10.0.2.99 | 1 | 2026-09-18 01:06:46Z | 2026-09-18 01:06:46Z |
| HIGH | `100131` | Scheduled task or unit file changed: /etc/systemd/system/timers.target | kali2 | - | 1 | 2026-09-18 01:38:00Z | 2026-09-18 01:38:00Z |
| HIGH | `100131` | Scheduled task or unit file changed: /etc/systemd/system/siem-daily-au | kali2 | - | 1 | 2026-09-18 01:38:00Z | 2026-09-18 01:38:00Z |
| HIGH | `100131` | Scheduled task or unit file changed: /etc/systemd/system/siem-daily-au | kali2 | - | 1 | 2026-09-18 01:38:00Z | 2026-09-18 01:38:00Z |
| MEDIUM | `521` | Possible kernel level rootkit | kali2 | - | 1 | 2026-09-18 00:52:03Z | 2026-09-18 00:52:03Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yara.dpkg-new - possible trojanised b | kali2 | - | 1 | 2026-09-18 00:58:29Z | 2026-09-18 00:58:29Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yarac.dpkg-new - possible trojanised  | kali2 | - | 1 | 2026-09-18 00:58:29Z | 2026-09-18 00:58:29Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yara - possible trojanised binary | kali2 | - | 1 | 2026-09-18 00:58:29Z | 2026-09-18 00:58:29Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/yarac - possible trojanised binary | kali2 | - | 1 | 2026-09-18 00:58:30Z | 2026-09-18 00:58:30Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/ambiguous_words.dpkg-new - possible t | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/classifier_tester.dpkg-new - possible | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/ambiguous_words - possible trojanised | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/classifier_tester - possible trojanis | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/cntraining - possible trojanised bina | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/combine_lang_model - possible trojani | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/combine_tessdata - possible trojanise | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/dawg2wordlist - possible trojanised b | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/lstmeval - possible trojanised binary | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/lstmtraining - possible trojanised bi | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/merge_unicharsets - possible trojanis | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/mftraining - possible trojanised bina | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |
| MEDIUM | `100133` | System binary modified: /usr/bin/set_unicharset_properties - possible  | kali2 | - | 1 | 2026-09-18 01:30:34Z | 2026-09-18 01:30:34Z |

## Top sources

| Source | Alert volume |
|---|---:|
| `pandu` | 47 |
| `10.0.2.99` | 12 |

## Activity by agent

| Agent | Alert volume |
|---|---:|
| kali2 | 4,969 |
| wazuh.manager | 5 |

## Noisiest rules (tuning candidates)

| Rule | Description | Alert volume |
|---|---|---:|
| `87915` | Docker: Volume mounted on /var/lib/filebeat | 1,980 |
| `87916` | Docker: Volume unmounted from local | 1,958 |
| `554` | File added to the system. | 294 |
| `5501` | PAM: Login session opened. | 241 |
| `550` | Integrity checksum changed. | 220 |
| `5502` | PAM: Login session closed. | 46 |
| `553` | File deleted. | 36 |
| `100112` | Privilege escalation to root via sudo by pandu | 33 |
| `19014` | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit logs are no | 22 |
| `2904` | Dpkg (Debian Package) half configured. | 16 |

## Indicators for enrichment

Public indicators extracted from this window. Feed them to `automation/threat_intel_enrich.py` for reputation lookup.

- **file_hash** (768): `0091b6d3...[24 chars redacted]`, `01862c92...[24 chars redacted]`, `01aa3c5f...[56 chars redacted]`, `01ba384e...[32 chars redacted]`, `0232192e...[24 chars redacted]`, `02358e14...[56 chars redacted]`, `02e4fb1a...[24 chars redacted]`, `02f4dd17...[32 chars redacted]`, `046216b1...[32 chars redacted]`, `0516d493...[32 chars redacted]` ...

---

_Generated by siem-home-lab `automation/daily_audit.py`._

> Anonymisation enabled. 10 value(s) redacted, including 0 distinct routable address(es). Private addresses are shown as-is because they describe lab topology only. Redaction is stable, so repeated indicators remain correlatable.
