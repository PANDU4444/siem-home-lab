#!/usr/bin/env python3
"""
Generate wazuh/config/ossec.conf from the stock Wazuh manager config.

Kept as a script rather than a hand-edited file so the delta against upstream
stays reviewable: everything this lab changes is visible right here.
"""
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = Path(os.environ.get(
    "WAZUH_MANAGER_CONF",
    Path.home() / "wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"))
TARGET = REPO / "wazuh/config/ossec.conf"

INTEGRATIONS = """
  <!-- ===================================================================
       siem-home-lab :: alerting and enrichment integrations
       Placeholders are substituted from .env by scripts/render_config.py.
       =================================================================== -->

  <!-- Level 10+ reaches the SOC channel. custom-slack.py applies its own
       severity tiering and dedup window on top of this threshold. -->
  <integration>
    <name>custom-slack</name>
    <hook_url>__SLACK_WEBHOOK_URL__</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>

  <!-- Lower-severity feed into n8n for automation/ticketing. -->
  <integration>
    <name>custom-n8n</name>
    <hook_url>__N8N_WEBHOOK_URL__</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>

  <!-- Hash reputation on FIM events only, to stay inside the free-tier quota. -->
  <integration>
    <name>virustotal</name>
    <api_key>__VIRUSTOTAL_API_KEY__</api_key>
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
"""

YARA_AR = """
  <!-- ===================================================================
       siem-home-lab :: YARA active response
       FIM reports a new/modified file (rules 550/554) -> yara.sh scans that
       one file -> matches land in active-responses.log -> local_decoder.xml
       parses them -> rule 100141 raises a level 12 alert.
       =================================================================== -->
  <command>
    <name>yara_scan</name>
    <executable>yara.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>yara_scan</command>
    <location>local</location>
    <rules_id>550,554</rules_id>
  </active-response>
"""


def redact_cluster_key(config):
    """
    Replace only the <cluster> block's <key>, which is a shared secret.

    This must not touch <key> elements elsewhere: the <indexer><ssl> section
    also has a <key>, but that one holds a certificate *file path*
    (/etc/ssl/filebeat.key) and redacting it would break Filebeat.
    """
    def replace_in_cluster(match):
        block = match.group(0)
        return re.sub(r"(<key>)[^<]*(</key>)", r"\g<1>__CLUSTER_KEY__\g<2>", block)

    config, count = re.subn(r"<cluster>.*?</cluster>", replace_in_cluster,
                            config, flags=re.DOTALL)
    return config, count


def main():
    if not SOURCE.exists():
        sys.exit("source config not found: {}".format(SOURCE))

    config = SOURCE.read_text()

    # The manager keeps the stock <syscheck>. The tuned FIM configuration
    # belongs on the agent, which is the endpoint actually being watched;
    # scripts/deploy_to_agent.sh applies it there.

    config, key_count = redact_cluster_key(config)
    print("  cluster block(s) with key redacted: {}".format(key_count))

    # Append integrations and the YARA active response to the first
    # </ossec_config>, which is where the manager's own settings end.
    marker = "</ossec_config>"
    index = config.index(marker)
    config = config[:index] + INTEGRATIONS + YARA_AR + "\n" + config[index:]

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(config)
    print("wrote {} ({} lines)".format(TARGET, len(config.splitlines())))

    checks = [
        ("custom-slack", True),
        ("custom-n8n", True),
        ("yara_scan", True),
        ("__SLACK_WEBHOOK_URL__", True),
        ("<key>__CLUSTER_KEY__</key>", True),
        ("<key>/etc/ssl/filebeat.key</key>", True),   # must survive redaction
    ]
    failed = False
    for probe, expected in checks:
        present = probe in config
        status = "present" if present else "MISSING"
        if present != expected:
            failed = True
            status = "UNEXPECTED ({})".format(status)
        print("  {:<40} {}".format(probe, status))

    # Nothing that looks like a bare 32-hex secret should survive.
    leftovers = [m for m in re.findall(r"<key>([^<]*)</key>", config)
                 if re.fullmatch(r"[a-f0-9]{32}", m or "")]
    if leftovers:
        failed = True
        print("  FAIL: raw key value still present in output")

    if failed:
        sys.exit("generation produced unexpected output")


if __name__ == "__main__":
    main()
