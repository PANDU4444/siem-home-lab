#!/usr/bin/env python3
"""
siem-home-lab :: verify the Slack integration without a Slack workspace.

Stands up a local HTTP receiver, points custom-slack.py at it with a real
alert taken from the lab, and asserts the Block Kit payload is well formed.
This is what lets the integration be committed as "working" before a webhook
URL exists.

Run:  python3 scripts/test_slack.py
"""
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

RECEIVED = []


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            RECEIVED.append(json.loads(body))
        except ValueError:
            RECEIVED.append({"_raw": body.decode("utf-8", "replace")})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


SAMPLE_ALERT = {
    "timestamp": "2026-09-18T01:07:00.601+0000",
    "rule": {
        "id": "100141",
        "level": 12,
        "description": "YARA match: rule SHL_Linux_Reverse_Shell matched file /tmp/payload.sh",
        "groups": ["siem-home-lab", "yara", "malware", "yara_match"],
        "mitre": {
            "id": ["T1204.002", "T1059"],
            "tactic": ["Execution"],
            "technique": ["Malicious File", "Command and Scripting Interpreter"],
        },
    },
    "agent": {"id": "001", "name": "kali2"},
    "data": {"srcip": "10.0.2.99", "dstuser": "root"},
    "syscheck": {"path": "/tmp/payload.sh"},
    "full_log": "wazuh-yara: INFO - Scan result: SHL_Linux_Reverse_Shell /tmp/payload.sh",
}


def main():
    repo = Path(__file__).resolve().parent.parent
    integration = repo / "integrations/slack/custom-slack.py"
    if not integration.exists():
        sys.exit("missing {}".format(integration))

    server = HTTPServer(("127.0.0.1", 0), Receiver)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    alert_path = Path("/tmp/shl_test_alert.json")
    alert_path.write_text(json.dumps(SAMPLE_ALERT))

    hook = "http://127.0.0.1:{}/services/TEST".format(port)
    result = subprocess.run(
        [sys.executable, str(integration), str(alert_path), "", hook],
        capture_output=True, text=True, timeout=30)

    time.sleep(0.5)
    server.shutdown()

    print("exit code        :", result.returncode)
    if result.stderr.strip():
        print("stderr           :", result.stderr.strip())
    if not RECEIVED:
        sys.exit("FAIL: nothing was posted to the receiver")

    payload = RECEIVED[0]
    attachment = (payload.get("attachments") or [{}])[0]
    blocks = attachment.get("blocks") or []
    text = json.dumps(payload)

    checks = [
        ("payload has an attachment", bool(attachment)),
        ("attachment has blocks", len(blocks) >= 3),
        ("colour set for HIGH tier", attachment.get("color") == "#D00000"),
        ("fallback text present", bool(attachment.get("fallback"))),
        ("rule id in payload", "100141" in text),
        ("agent name in payload", "kali2" in text),
        ("source IP in payload", "10.0.2.99" in text),
        ("file path in payload", "/tmp/payload.sh" in text),
        ("ATT&CK technique in payload", "T1204.002" in text),
        ("tactic in payload", "Execution" in text),
        ("level 12 escalates with mention", "<!channel>" in text),
    ]

    print()
    failures = 0
    for label, ok in checks:
        print("  [{}] {}".format("PASS" if ok else "FAIL", label))
        failures += 0 if ok else 1

    print()
    print("--- fallback line as Slack would show it ---")
    print("   ", attachment.get("fallback"))

    if failures:
        sys.exit("{} check(s) failed".format(failures))
    print("\nAll Slack payload checks passed.")


if __name__ == "__main__":
    main()
