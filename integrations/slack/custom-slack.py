#!/usr/bin/env python3
"""
siem-home-lab :: Wazuh -> Slack integration

Wazuh invokes integrations as:
    <script> <alert_file> <api_key> <hook_url> [options]

Why this exists instead of the stock `slack` integration:
  * The stock integration posts a flat text blob. This one builds Block Kit
    messages with the ATT&CK technique, agent and source IP as separate
    fields, so an analyst can triage from the notification itself.
  * Severity tiers decide the colour, the icon, and whether the message is
    escalated with a group mention. Level 12+ is what pages the SOC.
  * A short dedup window collapses alert storms (a brute-force burst, say)
    into one message instead of eighty. Escalation-tier alerts bypass it.
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.stderr.write("custom-slack: python3 'requests' module is required\n")
    sys.exit(1)

DEDUP_WINDOW_SECONDS = int(os.environ.get("SLACK_DEDUP_WINDOW", "300"))
DEDUP_STATE_FILE = Path(os.environ.get("SLACK_DEDUP_STATE", "/var/ossec/tmp/slack_dedup.json"))
ESCALATE_AT_LEVEL = int(os.environ.get("SLACK_ESCALATE_LEVEL", "12"))
ESCALATION_MENTION = os.environ.get("SLACK_ESCALATION_MENTION", "<!channel>")
DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "https://localhost")

SEVERITY_TIERS = [
    (15, "CRITICAL", "#8B0000", ":rotating_light:"),
    (12, "HIGH", "#D00000", ":red_circle:"),
    (8, "MEDIUM", "#E85D04", ":large_orange_diamond:"),
    (5, "LOW", "#FFBA08", ":large_yellow_circle:"),
    (0, "INFO", "#4895EF", ":white_circle:"),
]


def tier_for(level):
    for threshold, name, colour, icon in SEVERITY_TIERS:
        if level >= threshold:
            return name, colour, icon
    return "INFO", "#4895EF", ":white_circle:"


def as_list(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def mitre_from(rule):
    """Wazuh stores ATT&CK data under rule.mitre as parallel id/technique/tactic lists."""
    mitre = rule.get("mitre") or {}
    ids = as_list(mitre.get("id"))
    techniques = as_list(mitre.get("technique"))
    tactics = as_list(mitre.get("tactic"))
    if not ids:
        return None
    parts = []
    for index, technique_id in enumerate(ids):
        name = techniques[index] if index < len(techniques) else ""
        parts.append("`{}`{}".format(technique_id, " " + name if name else ""))
    return " / ".join(parts), ", ".join(sorted(set(tactics)))


def dedup_key(alert):
    rule_id = str((alert.get("rule") or {}).get("id", "?"))
    agent = str((alert.get("agent") or {}).get("name", "?"))
    srcip = str((alert.get("data") or {}).get("srcip", ""))
    return hashlib.sha256("{}|{}|{}".format(rule_id, agent, srcip).encode()).hexdigest()[:20]


def should_suppress(key):
    """Collapse repeats of the same rule/agent/IP inside the dedup window."""
    now = time.time()
    try:
        state = json.loads(DEDUP_STATE_FILE.read_text()) if DEDUP_STATE_FILE.exists() else {}
    except (OSError, ValueError):
        state = {}

    # Prune expired entries so the state file cannot grow without bound.
    state = {
        k: v for k, v in state.items()
        if isinstance(v, dict) and now - v.get("first", 0) < DEDUP_WINDOW_SECONDS
    }

    entry = state.get(key)
    if entry:
        entry["count"] = entry.get("count", 1) + 1
        suppress = True
    else:
        state[key] = {"first": now, "count": 1}
        suppress = False

    try:
        DEDUP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEDUP_STATE_FILE.write_text(json.dumps(state))
    except OSError:
        pass
    return suppress


def build_payload(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    syscheck = alert.get("syscheck") or {}

    level = int(rule.get("level") or 0)
    tier, colour, icon = tier_for(level)
    description = rule.get("description", "No description")
    rule_id = rule.get("id", "?")

    headline = "{}  {} - {}".format(icon, tier, description)
    if level >= ESCALATE_AT_LEVEL:
        headline = "{} {}".format(ESCALATION_MENTION, headline)

    fields = [
        {"type": "mrkdwn", "text": "*Agent*\n{} (`{}`)".format(
            agent.get("name", "manager"), agent.get("id", "000"))},
        {"type": "mrkdwn", "text": "*Rule*\n`{}` - level {}".format(rule_id, level)},
    ]
    if data.get("srcip"):
        fields.append({"type": "mrkdwn", "text": "*Source IP*\n`{}`".format(data["srcip"])})
    user = data.get("dstuser") or data.get("srcuser")
    if user:
        fields.append({"type": "mrkdwn", "text": "*User*\n`{}`".format(user)})
    if syscheck.get("path"):
        fields.append({"type": "mrkdwn", "text": "*File*\n`{}`".format(syscheck["path"])})

    blocks = [
        {"type": "header",
         "text": {"type": "plain_text", "text": "{} security alert".format(tier)[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": headline[:3000]}},
        {"type": "section", "fields": fields[:10]},
    ]

    mitre = mitre_from(rule)
    if mitre:
        technique_str, tactic_str = mitre
        text = "*MITRE ATT&CK*\n" + technique_str
        if tactic_str:
            text += "\n_Tactic:_ " + tactic_str
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text[:3000]}})

    context = [{"type": "mrkdwn", "text": "`{}`".format(alert.get("timestamp", ""))}]
    groups = rule.get("groups") or []
    if groups:
        context.append({"type": "mrkdwn",
                        "text": " ".join("`{}`".format(g) for g in groups[:6])})
    blocks.append({"type": "context", "elements": context})

    if alert.get("full_log"):
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": "```{}```".format(alert["full_log"][:600])}})

    blocks.append({"type": "actions", "elements": [{
        "type": "button",
        "text": {"type": "plain_text", "text": "Open Wazuh dashboard"},
        "url": DASHBOARD_URL,
    }]})

    return {"attachments": [{
        "color": colour,
        "blocks": blocks,
        "fallback": "[{}] {} (rule {}, level {})".format(tier, description, rule_id, level),
    }]}


def main():
    if len(sys.argv) < 4:
        sys.stderr.write("usage: custom-slack.py <alert_file> <api_key> <hook_url>\n")
        sys.exit(1)

    alert_file, hook_url = sys.argv[1], sys.argv[3]

    if not hook_url or "REPLACE_ME" in hook_url:
        sys.stderr.write("custom-slack: hook_url not configured yet; skipping\n")
        sys.exit(0)

    try:
        with open(alert_file, "r", encoding="utf-8", errors="replace") as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("custom-slack: cannot read alert file: {}\n".format(exc))
        sys.exit(1)

    level = int((alert.get("rule") or {}).get("level") or 0)

    # Never silence an escalation-tier alert, however noisy the rule is.
    if level < ESCALATE_AT_LEVEL and should_suppress(dedup_key(alert)):
        sys.exit(0)

    try:
        response = requests.post(hook_url, json=build_payload(alert), timeout=10)
    except requests.RequestException as exc:
        sys.stderr.write("custom-slack: POST failed: {}\n".format(exc))
        sys.exit(1)

    if response.status_code >= 300:
        sys.stderr.write("custom-slack: Slack returned {}: {}\n".format(
            response.status_code, response.text[:200]))
        sys.exit(1)


if __name__ == "__main__":
    main()
