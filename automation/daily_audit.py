#!/usr/bin/env python3
"""
siem-home-lab :: daily audit digest

Answers one question: what actually happened in the last 24 hours?

A raw Wazuh alert feed cannot answer that, because it is dominated by
repetition - one brute-force burst is eighty alerts, one apt upgrade is
hundreds of FIM events. This digest deduplicates the feed into incidents,
maps each to MITRE ATT&CK, and reports the techniques exercised rather than
the rules that happened to be noisy.

Run manually:
    python3 automation/daily_audit.py --hours 24
Or on a timer:
    automation/systemd/siem-daily-audit.timer
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wazuh_alerts import (  # noqa: E402
    load_alerts, deduplicate, summarise, extract_iocs, severity_of,
)
from anonymize import Anonymizer  # noqa: E402

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_ICON = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}


def fmt_time(value):
    return value.strftime("%Y-%m-%d %H:%M:%SZ") if value else "-"


def build_markdown(summary, incidents, window_start, window_end, iocs, hours):
    counts = summary["severity"]
    lines = []
    add = lines.append

    add("# Daily Security Audit")
    add("")
    add("| | |")
    add("|---|---|")
    add("| **Window** | {} to {} ({}h) |".format(
        fmt_time(window_start), fmt_time(window_end), hours))
    add("| **Generated** | {} |".format(
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")))
    add("| **Raw alerts** | {:,} |".format(summary["raw_alerts"]))
    add("| **Distinct incidents** | {:,} |".format(summary["incidents"]))
    add("| **Noise removed by dedup** | {:.1%} |".format(summary["dedup_ratio"]))
    add("")

    # ---- executive summary -------------------------------------------------
    add("## Executive summary")
    add("")
    if summary["raw_alerts"] == 0:
        add("No alerts were recorded in this window.")
        add("")
        return "\n".join(lines)

    critical_high = counts.get("critical", 0) + counts.get("high", 0)
    if critical_high:
        add("**{} incident(s) at high severity or above require review.**".format(
            critical_high))
    else:
        add("No high-severity incidents. All activity was informational or low severity.")
    add("")
    add("{:,} raw alerts collapsed into {:,} distinct incidents "
        "({:.1%} of the feed was repetition of activity already counted)."
        .format(summary["raw_alerts"], summary["incidents"], summary["dedup_ratio"]))
    add("")

    # ---- severity ----------------------------------------------------------
    add("## Severity breakdown")
    add("")
    add("| Severity | Incidents |")
    add("|---|---:|")
    for name in SEVERITY_ORDER:
        if counts.get(name):
            add("| {} | {} |".format(SEVERITY_ICON[name], counts[name]))
    add("")

    # ---- ATT&CK ------------------------------------------------------------
    add("## MITRE ATT&CK coverage")
    add("")
    if summary["tactics"]:
        add("### Tactics observed")
        add("")
        add("| Tactic | Alert volume |")
        add("|---|---:|")
        for tactic, count in summary["tactics"].most_common():
            add("| {} | {:,} |".format(tactic, count))
        add("")
    if summary["techniques"]:
        add("### Techniques observed")
        add("")
        add("| Technique | Name | Alert volume |")
        add("|---|---|---:|")
        for tid, count in summary["techniques"].most_common(15):
            add("| `{}` | {} | {:,} |".format(
                tid, summary["technique_names"].get(tid, ""), count))
        add("")
    if not summary["tactics"] and not summary["techniques"]:
        add("_No ATT&CK-mapped rules fired in this window._")
        add("")

    # ---- incidents ---------------------------------------------------------
    add("## Incidents (deduplicated)")
    add("")
    notable = [i for i in incidents if i["level"] >= 7][:25]
    if not notable:
        notable = incidents[:15]
    if notable:
        add("| Sev | Rule | Description | Agent | Source | Count | First seen | Last seen |")
        add("|---|---|---|---|---|---:|---|---|")
        for inc in notable:
            desc = inc["description"][:70].replace("|", "\\|")
            add("| {} | `{}` | {} | {} | {} | {} | {} | {} |".format(
                SEVERITY_ICON[inc["severity"]], inc["rule_id"], desc,
                inc["agent"], inc["source"] or "-", inc["count"],
                fmt_time(inc["first_seen"]), fmt_time(inc["last_seen"])))
        add("")

    # ---- sources -----------------------------------------------------------
    if summary["sources"]:
        add("## Top sources")
        add("")
        add("| Source | Alert volume |")
        add("|---|---:|")
        for source, count in summary["sources"].most_common(10):
            add("| `{}` | {:,} |".format(source, count))
        add("")

    # ---- agents ------------------------------------------------------------
    if summary["agents"]:
        add("## Activity by agent")
        add("")
        add("| Agent | Alert volume |")
        add("|---|---:|")
        for agent, count in summary["agents"].most_common():
            add("| {} | {:,} |".format(agent, count))
        add("")

    # ---- noisiest rules ----------------------------------------------------
    add("## Noisiest rules (tuning candidates)")
    add("")
    add("| Rule | Description | Alert volume |")
    add("|---|---|---:|")
    for (rule_id, desc), count in summary["rules"].most_common(10):
        add("| `{}` | {} | {:,} |".format(rule_id, desc[:70].replace("|", "\\|"), count))
    add("")

    # ---- IOCs --------------------------------------------------------------
    total_iocs = sum(len(v) for v in iocs.values())
    if total_iocs:
        add("## Indicators for enrichment")
        add("")
        add("Public indicators extracted from this window. Feed them to "
            "`automation/threat_intel_enrich.py` for reputation lookup.")
        add("")
        for kind, values in sorted(iocs.items()):
            add("- **{}** ({}): {}".format(
                kind, len(values),
                ", ".join("`{}`".format(v) for v in values[:10]) +
                (" ..." if len(values) > 10 else "")))
        add("")

    add("---")
    add("")
    add("_Generated by siem-home-lab `automation/daily_audit.py`._")
    return "\n".join(lines)


def post_to_slack(summary, incidents, hours, webhook):
    try:
        import requests
    except ImportError:
        return False, "requests not installed"
    if not webhook or "REPLACE_ME" in webhook:
        return False, "no webhook configured"

    counts = summary["severity"]
    top = [i for i in incidents if i["level"] >= 10][:5]
    lines = ["*Daily security audit* - last {}h".format(hours),
             "{:,} raw alerts -> *{:,} incidents* ({:.0%} noise removed)".format(
                 summary["raw_alerts"], summary["incidents"], summary["dedup_ratio"])]
    sev = " | ".join("{}: {}".format(n, counts[n]) for n in SEVERITY_ORDER if counts.get(n))
    if sev:
        lines.append(sev)
    if summary["techniques"]:
        lines.append("Top techniques: " + ", ".join(
            "`{}`".format(t) for t, _ in summary["techniques"].most_common(5)))
    if top:
        lines.append("")
        lines.append("*Needs review:*")
        for inc in top:
            lines.append("- `{}` {} (x{}) on {}".format(
                inc["rule_id"], inc["description"][:80], inc["count"], inc["agent"]))

    try:
        resp = requests.post(webhook, json={"text": "\n".join(lines)}, timeout=10)
        return resp.status_code < 300, "HTTP {}".format(resp.status_code)
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        return False, str(exc)


def load_env(path):
    values = {}
    p = Path(path)
    if not p.exists():
        return values
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def main():
    parser = argparse.ArgumentParser(description="Daily MITRE-mapped audit digest")
    parser.add_argument("--hours", type=int, default=24,
                        help="look-back window in hours (default 24)")
    parser.add_argument("--alert-file", default="/var/ossec/logs/alerts/alerts.json")
    parser.add_argument("--archive-dir", default="/var/ossec/logs/alerts")
    parser.add_argument("--include-archives", action="store_true",
                        help="also read rotated archives (slower, needed for long windows)")
    parser.add_argument("--output-dir", default="analysis/reports")
    parser.add_argument("--stdout", action="store_true", help="print the report instead of writing it")
    parser.add_argument("--slack", action="store_true", help="post a summary to Slack")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--no-anonymize", action="store_true",
                        help="include raw IPs, hashes and home paths "
                             "(reports are anonymised by default)")
    args = parser.parse_args()

    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=args.hours)

    loaded = load_alerts(args.alert_file, args.archive_dir,
                         include_archives=args.include_archives,
                         since=since, until=until)
    alerts = loaded["alerts"]
    incidents = deduplicate(alerts)
    summary = summarise(alerts, incidents)
    iocs = extract_iocs(alerts)

    report = build_markdown(summary, incidents, since, until, iocs, args.hours)

    # Reports are written to be shared, so redaction is the default and
    # opting out is explicit. Applied to the rendered text so nothing
    # slips through an un-anonymised field.
    anon = Anonymizer(enabled=not args.no_anonymize)
    report = anon.text(report) + "\n\n> {}\n".format(anon.legend())

    if args.stdout:
        print(report)
    else:
        outdir = Path(args.output_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        stamp = until.strftime("%Y-%m-%d")
        md_path = outdir / "daily-audit-{}.md".format(stamp)
        json_path = outdir / "daily-audit-{}.json".format(stamp)
        md_path.write_text(report)
        json_path.write_text(json.dumps({
            "window_start": since.isoformat(),
            "window_end": until.isoformat(),
            "raw_alerts": summary["raw_alerts"],
            "incidents": summary["incidents"],
            "dedup_ratio": summary["dedup_ratio"],
            "severity": dict(summary["severity"]),
            "tactics": dict(summary["tactics"]),
            "techniques": dict(summary["techniques"]),
            "iocs": {k: [anon.text(v) for v in vals] for k, vals in iocs.items()},
            "anonymized": not args.no_anonymize,
        }, indent=2))
        print("wrote {}".format(md_path))
        print("wrote {}".format(json_path))

    print("  files read       : {}".format(loaded["files_read"]))
    print("  raw alerts       : {:,}".format(summary["raw_alerts"]))
    print("  incidents        : {:,}".format(summary["incidents"]))
    print("  noise removed    : {:.1%}".format(summary["dedup_ratio"]))
    print("  ATT&CK techniques: {}".format(len(summary["techniques"])))
    print("  redactions       : {}".format(anon.stats["redactions"]))
    if loaded["malformed"]:
        print("  malformed lines  : {}".format(loaded["malformed"]))

    if args.slack:
        env = load_env(args.env_file)
        webhook = os.environ.get("SLACK_WEBHOOK_URL") or env.get("SLACK_WEBHOOK_URL", "")
        ok, detail = post_to_slack(summary, incidents, args.hours, webhook)
        print("  slack            : {}".format("posted" if ok else "skipped ({})".format(detail)))


if __name__ == "__main__":
    main()
