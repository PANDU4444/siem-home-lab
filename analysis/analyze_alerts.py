#!/usr/bin/env python3
"""
siem-home-lab :: historical alert analysis / SOC report

Reads the full rotated alert archive rather than the last 24 hours, and
produces the report an analyst would write after reviewing a period: what
fired, how much of it was real, which ATT&CK techniques were exercised, and
which rules are just noisy.

Usage:
    python3 analysis/analyze_alerts.py --archive-dir .data/alerts \\
        --output analysis/reports/soc-report.md
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "automation"))
from wazuh_alerts import (  # noqa: E402
    load_alerts, deduplicate, summarise, extract_iocs, severity_of,
)
from anonymize import Anonymizer  # noqa: E402

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def fmt(value):
    return value.strftime("%Y-%m-%d %H:%M:%SZ") if value else "-"


def bar(value, total, width=28):
    if not total:
        return ""
    filled = int(round(width * value / total))
    return "#" * max(filled, 1 if value else 0)


def build_report(loaded, incidents, summary, iocs):
    alerts = loaded["alerts"]
    lines = []
    add = lines.append

    first = alerts[0].get("_when") if alerts else None
    last = alerts[-1].get("_when") if alerts else None
    span_days = ((last - first).days + 1) if (first and last) else 0

    add("# SOC Analysis Report")
    add("")
    add("_siem-home-lab - Wazuh 4.14 single-node deployment_")
    add("")
    add("| | |")
    add("|---|---|")
    add("| **Report generated** | {} |".format(
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")))
    add("| **Data window** | {} to {} |".format(fmt(first), fmt(last)))
    add("| **Span** | {} day(s) |".format(span_days))
    add("| **Archive files read** | {} |".format(loaded["files_read"]))
    add("| **Raw alerts analysed** | {:,} |".format(len(alerts)))
    add("| **Distinct incidents** | {:,} |".format(len(incidents)))
    add("| **Noise removed by dedup** | {:.1%} |".format(summary["dedup_ratio"]))
    add("")

    # ---------------------------------------------------------------- summary
    add("## 1. Executive summary")
    add("")
    counts = summary["severity"]
    crit_high = counts.get("critical", 0) + counts.get("high", 0)
    add("Across {:,} alerts spanning {} days, deduplication reduced the feed to "
        "**{:,} distinct incidents** - {:.1%} of raw alert volume was repetition "
        "of activity already accounted for.".format(
            len(alerts), span_days, len(incidents), summary["dedup_ratio"]))
    add("")
    add("**{}** incident(s) reached high severity or above and would warrant "
        "analyst review in a production SOC.".format(crit_high))
    add("")
    add("The single most important operational finding is the signal-to-noise "
        "ratio: a SOC that triages raw alerts would process {:,} items to find "
        "the same {} that matter.".format(len(alerts), crit_high))
    add("")

    # --------------------------------------------------------------- severity
    add("## 2. Severity distribution")
    add("")
    add("| Severity | Incidents | Share |")
    add("|---|---:|---|")
    total_inc = max(len(incidents), 1)
    for name in SEVERITY_ORDER:
        value = counts.get(name, 0)
        if value:
            add("| {} | {:,} | `{}` {:.1%} |".format(
                name.upper(), value, bar(value, total_inc), value / total_inc))
    add("")

    # ------------------------------------------------------------------ ATT&CK
    add("## 3. MITRE ATT&CK coverage")
    add("")
    if summary["tactics"]:
        add("### 3.1 Tactics exercised")
        add("")
        add("| Tactic | Alert volume | Share |")
        add("|---|---:|---|")
        tactic_total = sum(summary["tactics"].values())
        for tactic, count in summary["tactics"].most_common():
            add("| {} | {:,} | `{}` |".format(tactic, count, bar(count, tactic_total)))
        add("")
    if summary["techniques"]:
        add("### 3.2 Techniques observed")
        add("")
        add("| Technique | Name | Alert volume |")
        add("|---|---|---:|")
        for tid, count in summary["techniques"].most_common(20):
            add("| `{}` | {} | {:,} |".format(
                tid, summary["technique_names"].get(tid, ""), count))
        add("")
        add("_{} distinct ATT&CK techniques were observed in this dataset._".format(
            len(summary["techniques"])))
        add("")
    else:
        add("_No ATT&CK-mapped rules fired in this dataset._")
        add("")

    # --------------------------------------------------------------- timeline
    add("## 4. Activity timeline")
    add("")
    by_day = Counter()
    for alert in alerts:
        when = alert.get("_when")
        if when:
            by_day[when.strftime("%Y-%m-%d")] += 1
    if by_day:
        peak = max(by_day.values())
        add("| Date | Alerts | |")
        add("|---|---:|---|")
        for day in sorted(by_day):
            add("| {} | {:,} | `{}` |".format(day, by_day[day], bar(by_day[day], peak)))
        add("")
        busiest = max(by_day.items(), key=lambda kv: kv[1])
        add("Busiest day was **{}** with {:,} alerts.".format(busiest[0], busiest[1]))
        add("")

    # -------------------------------------------------------------- incidents
    add("## 5. Notable incidents")
    add("")
    notable = [i for i in incidents if i["level"] >= 10][:30]
    if notable:
        add("| Sev | Rule | Description | Agent | Source | Count | First seen | Last seen |")
        add("|---|---|---|---|---|---:|---|---|")
        for inc in notable:
            add("| {} | `{}` | {} | {} | {} | {} | {} | {} |".format(
                inc["severity"].upper(), inc["rule_id"],
                inc["description"][:65].replace("|", "\\|"),
                inc["agent"], inc["source"] or "-", inc["count"],
                fmt(inc["first_seen"]), fmt(inc["last_seen"])))
        add("")
    else:
        add("_No incidents at level 10 or above in this dataset._")
        add("")

    # ------------------------------------------------------------------ rules
    add("## 6. Rule volume and tuning candidates")
    add("")
    add("Rules are ranked by raw alert volume. High-volume, low-severity rules "
        "are tuning candidates: they cost triage time without changing outcomes.")
    add("")
    add("| Rank | Rule | Description | Alerts |")
    add("|---:|---|---|---:|")
    for rank, ((rule_id, desc), count) in enumerate(summary["rules"].most_common(20), 1):
        add("| {} | `{}` | {} | {:,} |".format(
            rank, rule_id, desc[:70].replace("|", "\\|"), count))
    add("")

    # ----------------------------------------------------------------- agents
    if summary["agents"]:
        add("## 7. Activity by agent")
        add("")
        add("| Agent | Alerts | Share |")
        add("|---|---:|---|")
        agent_total = sum(summary["agents"].values())
        for agent, count in summary["agents"].most_common():
            add("| {} | {:,} | `{}` |".format(agent, count, bar(count, agent_total)))
        add("")

    # ------------------------------------------------------------------- IOCs
    add("## 8. Indicators extracted")
    add("")
    total_iocs = sum(len(v) for v in iocs.values())
    if total_iocs:
        for kind, values in sorted(iocs.items()):
            add("- **{}** ({}): {}".format(
                kind, len(values), ", ".join("`{}`".format(v) for v in values[:15])))
        add("")
        add("Run `automation/threat_intel_enrich.py` to score these against "
            "VirusTotal, OTX, ThreatFox and URLhaus.")
    else:
        add("No public indicators were present. All observed source addresses were "
            "RFC1918 or loopback, which is expected for a closed lab where the "
            "attacker and target share a host-only network.")
    add("")

    # --------------------------------------------------------------- findings
    add("## 9. Analyst findings")
    add("")
    findings = []

    if summary["dedup_ratio"] > 0.9:
        findings.append(
            "**Alert volume is dominated by repetition.** {:.1%} of alerts were "
            "duplicates of an incident already counted. Any triage process that "
            "reads raw alerts rather than grouped incidents will spend almost all "
            "of its time re-reading the same events.".format(summary["dedup_ratio"]))

    noisiest = summary["rules"].most_common(1)
    if noisiest:
        (rid, rdesc), rcount = noisiest[0]
        share = rcount / max(len(alerts), 1)
        if share > 0.2:
            findings.append(
                "**One rule produces {:.0%} of all alerts** (`{}` - {}). This "
                "single rule is the highest-value tuning target in the deployment."
                .format(share, rid, rdesc[:80]))

    custom = {rid for (rid, _), _ in summary["rules"].items() if str(rid).startswith("1001")}
    if custom:
        findings.append(
            "**{} custom rules fired**, confirming the lab's own detection content "
            "is active and not merely installed.".format(len(custom)))

    if counts.get("critical", 0) == 0 and counts.get("high", 0) > 0:
        findings.append(
            "**No level-15 critical incidents.** The highest observed severity was "
            "level 12-14, consistent with simulated rather than live intrusion.")

    if not findings:
        findings.append("No structural findings; the dataset is small or uniform.")

    for index, finding in enumerate(findings, 1):
        add("{}. {}".format(index, finding))
        add("")

    add("---")
    add("")
    add("_Generated by siem-home-lab `analysis/analyze_alerts.py`. "
        "All figures derive from the Wazuh alert archive; none are synthetic._")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Historical SOC analysis over the alert archive")
    parser.add_argument("--archive-dir", default="/var/ossec/logs/alerts")
    parser.add_argument("--alert-file", default="/var/ossec/logs/alerts/alerts.json")
    parser.add_argument("--output", default="analysis/reports/soc-report.md")
    parser.add_argument("--json-output", default="analysis/reports/soc-report.json")
    parser.add_argument("--no-anonymize", action="store_true",
                        help="include raw IPs, hashes and home paths "
                             "(reports are anonymised by default)")
    args = parser.parse_args()

    print("reading archive: {}".format(args.archive_dir), file=sys.stderr)
    loaded = load_alerts(args.alert_file, args.archive_dir, include_archives=True)
    alerts = loaded["alerts"]
    if not alerts:
        print("no alerts found - check --archive-dir", file=sys.stderr)
        return 1

    incidents = deduplicate(alerts)
    summary = summarise(alerts, incidents)
    iocs = extract_iocs(alerts)
    report = build_report(loaded, incidents, summary, iocs)

    # This report is committed to a public repository, so redaction is
    # the default. See automation/anonymize.py for what is preserved.
    anon = Anonymizer(enabled=not args.no_anonymize)
    report = anon.text(report) + "\n\n> {}\n".format(anon.legend())

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report)
    print("wrote {}".format(out), file=sys.stderr)

    if args.json_output:
        Path(args.json_output).write_text(json.dumps({
            "files_read": loaded["files_read"],
            "raw_alerts": len(alerts),
            "incidents": len(incidents),
            "dedup_ratio": summary["dedup_ratio"],
            "severity": dict(summary["severity"]),
            "tactics": dict(summary["tactics"]),
            "techniques": dict(summary["techniques"]),
            "agents": dict(summary["agents"]),
            "iocs": {k: [anon.text(v) for v in vals] for k, vals in iocs.items()},
            "anonymized": not args.no_anonymize,
        }, indent=2))
        print("wrote {}".format(args.json_output), file=sys.stderr)

    print("  raw alerts : {:,}".format(len(alerts)), file=sys.stderr)
    print("  incidents  : {:,}".format(len(incidents)), file=sys.stderr)
    print("  dedup      : {:.1%}".format(summary["dedup_ratio"]), file=sys.stderr)
    print("  techniques : {}".format(len(summary["techniques"])), file=sys.stderr)
    print("  redactions : {}".format(anon.stats["redactions"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
