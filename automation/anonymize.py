#!/usr/bin/env python3
"""
siem-home-lab :: report anonymisation

Alert reports are meant to be shared - pasted into a ticket, attached to a
write-up, committed to a public repository. Raw Wazuh data is not safe for
that: it carries routable source addresses, hashes of every file on the host,
and real home directory paths.

This module makes a report shareable while keeping it analytically useful.
Anonymisation is applied **by default** in the report generators; disabling it
is the explicit choice, not enabling it.

What is preserved on purpose:
  * RFC1918 / loopback addresses stay readable - they describe lab topology,
    not anything sensitive, and redacting them would make reports unreadable.
  * Redaction is *stable*: the same input maps to the same token for the life
    of the process, so "the same attacker hit us 35 times" survives redaction.
  * Hashes keep a short prefix, which is enough to correlate against a local
    copy of the data without publishing the full value.
"""

import ipaddress
import re

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
HOME_RE = re.compile(r"/home/[A-Za-z_][A-Za-z0-9_-]*")

# RFC 6598 carrier-grade NAT. Python's ipaddress does not report these as
# private, but Tailscale and similar overlays allocate from here, so treating
# them as public-and-sensitive is the safe reading.
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_sensitive_ip(text):
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if addr in CGNAT:
        return True
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


class Anonymizer:
    """Stable, reversible-by-the-owner redaction of report text."""

    def __init__(self, enabled=True, keep_hash_prefix=8):
        self.enabled = enabled
        self.keep_hash_prefix = keep_hash_prefix
        self._ip_map = {}
        self._redactions = 0

    # -- individual values ------------------------------------------------
    def ip(self, value):
        if not self.enabled or not value or not is_sensitive_ip(str(value)):
            return value
        key = str(value)
        if key not in self._ip_map:
            self._ip_map[key] = "redacted-ip-{}".format(len(self._ip_map) + 1)
        self._redactions += 1
        return self._ip_map[key]

    def hash(self, value):
        if not self.enabled or not value:
            return value
        text = str(value)
        if not HASH_RE.fullmatch(text):
            return value
        self._redactions += 1
        return "{}...[{} chars redacted]".format(
            text[:self.keep_hash_prefix], len(text) - self.keep_hash_prefix)

    # -- whole strings ----------------------------------------------------
    def text(self, value):
        """Redact every sensitive token inside an arbitrary string."""
        if not self.enabled or not value:
            return value
        out = str(value)
        out = IPV4_RE.sub(lambda m: self.ip(m.group(0)), out)
        out = HASH_RE.sub(lambda m: self.hash(m.group(0)), out)
        out = HOME_RE.sub("/home/<user>", out)
        return out

    @property
    def stats(self):
        return {"redactions": self._redactions, "unique_ips": len(self._ip_map)}

    def legend(self):
        """A short note explaining what was redacted, for the report footer."""
        if not self.enabled:
            return "Anonymisation disabled - this report contains raw host data."
        if not self._redactions:
            return ("Anonymisation enabled. Nothing required redaction: all "
                    "observed addresses were private and no host hashes appeared.")
        return ("Anonymisation enabled. {} value(s) redacted, including {} distinct "
                "routable address(es). Private addresses are shown as-is because "
                "they describe lab topology only. Redaction is stable, so repeated "
                "indicators remain correlatable.".format(
                    self._redactions, len(self._ip_map)))
