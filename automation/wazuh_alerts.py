#!/usr/bin/env python3
"""
siem-home-lab :: shared Wazuh alert loading and deduplication.

Both the daily audit digest and the historical SOC report read alerts through
this module, so "one incident" means the same thing in both.

The deduplication model is the point of this file. A Wazuh alert stream is
mostly repetition: one brute-force burst is eighty near-identical alerts, one
package upgrade is hundreds of FIM events. Counting raw alerts therefore tells
you how noisy a rule is, not what happened. Grouping on
(rule_id, agent, source, target) collapses each burst into a single incident
that carries first_seen, last_seen and a count.
"""

import gzip
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_ALERT_FILE = Path("/var/ossec/logs/alerts/alerts.json")
DEFAULT_ARCHIVE_DIR = Path("/var/ossec/logs/alerts")

SEVERITY_BANDS = [
    (15, "critical"),
    (12, "high"),
    (8, "medium"),
    (5, "low"),
    (0, "info"),
]


def severity_of(level):
    for threshold, name in SEVERITY_BANDS:
        if level >= threshold:
            return name
    return "info"


def parse_timestamp(value):
    """Wazuh timestamps look like 2026-09-18T01:07:00.601+0000."""
    if not value:
        return None
    text = value.strip()
    # Normalise +0000 into +00:00 so fromisoformat accepts it.
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iter_alert_files(alert_file=None, archive_dir=None, include_archives=False):
    """Yield every file worth reading, newest live file first."""
    alert_file = Path(alert_file or DEFAULT_ALERT_FILE)
    if alert_file.exists():
        yield alert_file
    if not include_archives:
        return
    archive_dir = Path(archive_dir or DEFAULT_ARCHIVE_DIR)
    if not archive_dir.exists():
        return
    for path in sorted(archive_dir.rglob("*.json*")):
        if path.suffix == ".sum" or path == alert_file:
            continue
        yield path


def load_alerts(alert_file=None, archive_dir=None, include_archives=False,
                since=None, until=None):
    """Load alerts, optionally bounded by time. Malformed lines are skipped."""
    alerts = []
    malformed = 0
    files_read = 0

    for path in iter_alert_files(alert_file, archive_dir, include_archives):
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
                files_read += 1
                for line in handle:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        alert = json.loads(line)
                    except ValueError:
                        malformed += 1
                        continue
                    when = parse_timestamp(alert.get("timestamp"))
                    if since and (when is None or when < since):
                        continue
                    if until and (when is None or when > until):
                        continue
                    alert["_when"] = when
                    alerts.append(alert)
        except OSError:
            continue

    alerts.sort(key=lambda a: a.get("_when") or datetime.min.replace(tzinfo=timezone.utc))
    return {"alerts": alerts, "files_read": files_read, "malformed": malformed}


def mitre_of(alert):
    """Return (ids, tactics, techniques) as lists, tolerating scalars."""
    mitre = (alert.get("rule") or {}).get("mitre") or {}

    def listify(value):
        if value is None:
            return []
        return [value] if isinstance(value, str) else list(value)

    return listify(mitre.get("id")), listify(mitre.get("tactic")), listify(mitre.get("technique"))


def incident_key(alert):
    """
    What makes two alerts "the same incident".

    Source and target are included so that one IP brute-forcing two hosts is
    two incidents, and one FIM rule touching two files is two incidents -
    but eighty attempts from one IP against one host collapse into one.
    """
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    syscheck = alert.get("syscheck") or {}
    agent = alert.get("agent") or {}

    source = data.get("srcip") or data.get("srcuser") or ""
    target = syscheck.get("path") or data.get("dstuser") or data.get("url") or ""
    return (str(rule.get("id", "?")), str(agent.get("name", "manager")), source, target)


def deduplicate(alerts):
    """Collapse alerts into incidents, preserving first/last seen and count."""
    incidents = {}
    for alert in alerts:
        key = incident_key(alert)
        rule = alert.get("rule") or {}
        when = alert.get("_when")
        ids, tactics, techniques = mitre_of(alert)

        entry = incidents.get(key)
        if entry is None:
            incidents[key] = {
                "rule_id": key[0],
                "agent": key[1],
                "source": key[2],
                "target": key[3],
                "level": int(rule.get("level") or 0),
                "severity": severity_of(int(rule.get("level") or 0)),
                "description": rule.get("description", ""),
                "groups": list(rule.get("groups") or []),
                "mitre_ids": list(ids),
                "mitre_tactics": list(tactics),
                "mitre_techniques": list(techniques),
                "count": 1,
                "first_seen": when,
                "last_seen": when,
                "sample": alert.get("full_log", "")[:300],
            }
        else:
            entry["count"] += 1
            if when:
                if entry["first_seen"] is None or when < entry["first_seen"]:
                    entry["first_seen"] = when
                if entry["last_seen"] is None or when > entry["last_seen"]:
                    entry["last_seen"] = when
            # Keep the highest level seen for this grouping.
            level = int(rule.get("level") or 0)
            if level > entry["level"]:
                entry["level"] = level
                entry["severity"] = severity_of(level)

    ordered = sorted(incidents.values(),
                     key=lambda i: (-i["level"], -i["count"]))
    return ordered


def summarise(alerts, incidents):
    """Aggregate counts used by both report formats."""
    severity_counts = Counter()
    technique_counts = Counter()
    technique_names = {}
    tactic_counts = Counter()
    agent_counts = Counter()
    source_counts = Counter()
    rule_counts = Counter()

    for incident in incidents:
        severity_counts[incident["severity"]] += 1
        agent_counts[incident["agent"]] += incident["count"]
        if incident["source"]:
            source_counts[incident["source"]] += incident["count"]
        rule_counts[(incident["rule_id"], incident["description"])] += incident["count"]
        for index, technique_id in enumerate(incident["mitre_ids"]):
            technique_counts[technique_id] += incident["count"]
            if index < len(incident["mitre_techniques"]):
                technique_names[technique_id] = incident["mitre_techniques"][index]
        for tactic in incident["mitre_tactics"]:
            tactic_counts[tactic] += incident["count"]

    return {
        "raw_alerts": len(alerts),
        "incidents": len(incidents),
        "dedup_ratio": (1 - len(incidents) / len(alerts)) if alerts else 0.0,
        "severity": severity_counts,
        "techniques": technique_counts,
        "technique_names": technique_names,
        "tactics": tactic_counts,
        "agents": agent_counts,
        "sources": source_counts,
        "rules": rule_counts,
    }


def extract_iocs(alerts):
    """Pull indicators worth enriching against threat-intel sources."""
    iocs = defaultdict(set)
    private = re.compile(
        r"^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0|::1$)")

    for alert in alerts:
        data = alert.get("data") or {}
        syscheck = alert.get("syscheck") or {}

        srcip = data.get("srcip")
        if srcip and not private.match(str(srcip)):
            iocs["ip"].add(str(srcip))

        # FIM records a hash for every changed file, which on a busy host is
        # thousands of hashes of the host's own legitimate files. Those are not
        # threat indicators and would exhaust a VirusTotal quota instantly, so
        # only hashes attached to a notable alert are treated as enrichable.
        if int((alert.get("rule") or {}).get("level") or 0) >= 7:
            for field in ("sha256_after", "sha1_after", "md5_after"):
                value = syscheck.get(field)
                if value:
                    iocs["file_hash"].add(str(value))

        url = data.get("url")
        if url and str(url).startswith("http"):
            iocs["url"].add(str(url))

    return {kind: sorted(values) for kind, values in iocs.items()}
