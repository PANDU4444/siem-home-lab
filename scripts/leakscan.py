#!/usr/bin/env python3
"""
siem-home-lab :: leak scanner

Scans what git has *actually committed* on a ref (not the working tree, so an
untracked file is never mistaken for safe) for material that must not be public.

Severity reflects the response required:
  CRITICAL - credentials, keys, tokens. Never publish.
  HIGH     - routable or CGNAT addresses, inline credentials in URLs.
  MEDIUM   - host file hashes, emails, absolute home paths.
  INFO     - private RFC1918 addresses, binaries skipped.

Environment-specific literals (your own passwords, your own IPs) deliberately
live OUTSIDE this file, in a gitignored `.leakscan-secrets`, one per line.
Hardcoding them here would make the scanner itself the leak - which is exactly
what an earlier version of this file did.

Usage:
    python3 scripts/leakscan.py . HEAD
    python3 scripts/leakscan.py . origin/feat/my-branch
"""

import ipaddress
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# RFC 6598 CGNAT - Tailscale and similar overlays allocate here, so these are
# sensitive even though Python does not classify them as private.
CGNAT = ipaddress.ip_network("100.64.0.0/10")  # leakscan:allow

PATTERNS = {
    "CRITICAL": [
        ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        ("certificate block", re.compile(r"-----BEGIN CERTIFICATE-----")),  # leakscan:allow
        ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
        ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
        ("slack webhook", re.compile(r"hooks\.slack\.com/services/T[A-Za-z0-9/]+")),
        ("slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
        ("wazuh agent key", re.compile(r"^\d{3}\s+\S+\s+\S+\s+[a-f0-9]{60,}", re.M)),
        # A <key> holding a bare hex blob is a shared secret. A <key> holding a
        # path (e.g. /etc/ssl/filebeat.key) is not - hence the hex-only match.
        ("xml <key> secret", re.compile(r"<key>\s*[A-Fa-f0-9]{16,}\s*</key>")),
        ("assigned credential", re.compile(
            r"(?i)\b(password|passwd|secret|api_?key|auth_?key|token)\s*[=:]\s*"
            r"['\"]?(?!REPLACE_ME|CHANGEME|\$\{|__|<|\s|$)[^\s'\"#$<>{}]{8,}")),
    ],
    "HIGH": [
        ("inline credential in URL", re.compile(r"[a-z]+://[^/\s:@]+:[^/\s@]+@")),
        ("authorization header", re.compile(r"(?i)\bauthorization\s*:\s*(bearer|basic)\s+\S+")),
    ],
    "MEDIUM": [
        ("file hash", re.compile(r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b")),
        ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        ("absolute home path", re.compile(r"/home/[a-z][a-z0-9_-]*")),
    ],
}

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Strings that are documentation, not disclosure.
ALLOW = [
    "REPLACE_ME", "CHANGEME", "__CLUSTER_KEY__", "__SLACK_WEBHOOK_URL__",
    "__N8N_WEBHOOK_URL__", "__VIRUSTOTAL_API_KEY__", "__AGENT_HOME__",
    "__REPO_PATH__", "example.invalid", "example.com", "example.wazuh.com",
    "noreply@anthropic.com", "X5O!P%@AP", "/home/<user>", "/home/alice",
    "/home/backdoor", "packages.wazuh.com", "virustotal.com",
    "otx.alienvault.com", "abuse.ch", "github.com", "cve@mitre.org",
    "192.0.2.",   # RFC 5737 documentation range
    "198.51.100.", "203.0.113.",
]


def load_local_literals(repo):
    """Extra environment-specific strings, kept out of version control."""
    path = Path(repo) / ".leakscan-secrets"
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")]


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, check=False)


def classify_ip(text):
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr in CGNAT:
        return "cgnat"
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
        return "private"
    return "public"


def scan(repo, ref):
    findings = defaultdict(list)
    listing = git(repo, "ls-tree", "-r", "--name-only", ref)
    if listing.returncode != 0:
        sys.exit("cannot read ref {!r}: {}".format(
            ref, listing.stderr.decode("utf-8", "replace").strip()))
    files = [f for f in listing.stdout.decode("utf-8", "replace").splitlines() if f.strip()]
    literals = load_local_literals(repo)

    print("scanning {} committed file(s) on {}".format(len(files), ref))
    print("local literal list: {}\n".format(
        "{} entries".format(len(literals)) if literals
        else "absent (.leakscan-secrets not present)"))

    for path in files:
        blob = git(repo, "show", "{}:{}".format(ref, path)).stdout
        if path.lower().endswith((".pdf", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz")):
            findings["INFO"].append((path, 0, "binary skipped",
                                     "binary content is not text-scanned"))
            continue
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            findings["INFO"].append((path, 0, "binary skipped", "not utf-8"))
            continue

        for number, line in enumerate(text.splitlines(), 1):
            # A detector must be able to describe what it detects without
            # tripping over itself. An explicit per-line marker is safer than
            # exempting whole files, which would hide real findings.
            if "leakscan:allow" in line:
                continue
            for literal in literals:
                if literal in line:
                    findings["CRITICAL"].append(
                        (path, number, "known local secret", "[redacted literal match]"))

            if any(a in line for a in ALLOW):
                continue

            for severity, patterns in PATTERNS.items():
                for label, regex in patterns:
                    match = regex.search(line)
                    if match:
                        findings[severity].append(
                            (path, number, label, match.group(0)[:80]))

            for candidate in IPV4.findall(line):
                kind = classify_ip(candidate)
                if kind == "public":
                    findings["HIGH"].append((path, number, "routable public IP", candidate))
                elif kind == "cgnat":
                    findings["HIGH"].append((path, number, "CGNAT/overlay IP", candidate))
                elif kind == "private":
                    findings["INFO"].append((path, number, "private IP", candidate))

    return findings


def main():
    repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    ref = sys.argv[2] if len(sys.argv) > 2 else "HEAD"
    findings = scan(repo, ref)

    blocking = 0
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        items = findings.get(severity, [])
        grouped = defaultdict(list)
        for path, number, label, snippet in items:
            grouped[(path, label)].append((number, snippet))

        print("=" * 78)
        print(" {}  ({} occurrence(s), {} file/pattern pair(s))".format(
            severity, len(items), len(grouped)))
        print("=" * 78)
        if not grouped:
            print("  none\n")
            continue
        for (path, label), hits in sorted(grouped.items()):
            numbers = ", ".join(str(n) for n, _ in hits[:5])
            print("  {:<46} {}".format(path, label))
            print("      x{:<4} lines {}   e.g. {}".format(
                len(hits), numbers, hits[0][1][:60]))
        print()
        if severity in ("CRITICAL", "HIGH"):
            blocking += len(grouped)

    print("=" * 78)
    if blocking:
        print(" RESULT: {} blocking finding(s) - do NOT publish".format(blocking))
    else:
        print(" RESULT: clean - no CRITICAL or HIGH findings")
    print("=" * 78)
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
