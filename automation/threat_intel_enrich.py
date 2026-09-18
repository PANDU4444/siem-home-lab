#!/usr/bin/env python3
"""
siem-home-lab :: threat intelligence enrichment

Takes indicators (IPs, domains, hashes, URLs) - either passed on the command
line or extracted straight from the Wazuh alert feed - and looks them up
against four sources:

    VirusTotal   reputation across ~70 AV engines        (needs VT_API_KEY)
    AlienVault OTX  community pulses and related samples (needs OTX_API_KEY)
    ThreatFox    abuse.ch IOC database, malware families (optional auth key)
    URLhaus      abuse.ch malicious URL database         (optional auth key)

Design notes:
  * Every source is optional. A missing key disables that source and is
    reported as "skipped", never as a failure - the tool stays useful with
    zero credentials because it still correlates and reports.
  * Results are cached on disk. VirusTotal's free tier allows 4 requests per
    minute, so re-running a report must not re-spend that budget.
  * Rate limiting is enforced client-side rather than relying on HTTP 429.

Usage:
    python3 automation/threat_intel_enrich.py --ip 192.0.2.10
    python3 automation/threat_intel_enrich.py --from-alerts .data/alerts.json --hours 24
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wazuh_alerts import load_alerts, extract_iocs  # noqa: E402

try:
    import requests
except ImportError:
    sys.stderr.write("threat_intel_enrich: python3 'requests' module is required\n")
    sys.exit(1)

CACHE_DIR = Path(os.environ.get("TI_CACHE_DIR", ".cache/threat-intel"))
CACHE_TTL_HOURS = int(os.environ.get("TI_CACHE_TTL_HOURS", "24"))

VT_RATE_PER_MIN = 4          # free tier
ABUSECH_RATE_PER_MIN = 30
OTX_RATE_PER_MIN = 30

HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class RateLimiter:
    """Simple client-side spacing so we never trip a provider's limit."""

    def __init__(self, per_minute):
        self.interval = 60.0 / max(per_minute, 1)
        self.last = 0.0

    def wait(self):
        delta = time.time() - self.last
        if delta < self.interval:
            time.sleep(self.interval - delta)
        self.last = time.time()


def cache_path(source, indicator):
    digest = hashlib.sha256("{}:{}".format(source, indicator).encode()).hexdigest()[:24]
    return CACHE_DIR / source / "{}.json".format(digest)


def cache_get(source, indicator):
    path = cache_path(source, indicator)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    cached_at = payload.get("_cached_at", 0)
    if time.time() - cached_at > CACHE_TTL_HOURS * 3600:
        return None
    return payload.get("data")


def cache_put(source, indicator, data):
    path = cache_path(source, indicator)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"_cached_at": time.time(), "data": data}))
    except OSError:
        pass


def classify(indicator):
    if HASH_RE.match(indicator):
        return "hash"
    if IP_RE.match(indicator):
        return "ip"
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    return "domain"


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def query_virustotal(indicator, kind, api_key, limiter):
    if not api_key or "REPLACE_ME" in api_key:
        return {"status": "skipped", "reason": "VT_API_KEY not set"}

    cached = cache_get("virustotal", indicator)
    if cached is not None:
        cached["cached"] = True
        return cached

    endpoint = {
        "ip": "ip_addresses", "domain": "domains",
        "hash": "files", "url": "urls",
    }[kind]
    target = indicator
    if kind == "url":
        import base64
        target = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")

    limiter.wait()
    try:
        resp = requests.get(
            "https://www.virustotal.com/api/v3/{}/{}".format(endpoint, target),
            headers={"x-apikey": api_key}, timeout=20)
    except requests.RequestException as exc:
        return {"status": "error", "reason": str(exc)}

    if resp.status_code == 404:
        result = {"status": "not_found"}
    elif resp.status_code == 401:
        return {"status": "error", "reason": "VirusTotal rejected the API key"}
    elif resp.status_code == 429:
        return {"status": "error", "reason": "VirusTotal rate limit reached"}
    elif resp.status_code >= 300:
        return {"status": "error", "reason": "HTTP {}".format(resp.status_code)}
    else:
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "meaningful_name": attrs.get("meaningful_name"),
        }
    cache_put("virustotal", indicator, result)
    return result


def query_otx(indicator, kind, api_key, limiter):
    if not api_key or "REPLACE_ME" in api_key:
        return {"status": "skipped", "reason": "OTX_API_KEY not set"}

    cached = cache_get("otx", indicator)
    if cached is not None:
        cached["cached"] = True
        return cached

    section = {
        "ip": "IPv4", "domain": "domain", "hash": "file", "url": "url",
    }[kind]

    limiter.wait()
    try:
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/indicators/{}/{}/general".format(
                section, indicator),
            headers={"X-OTX-API-KEY": api_key}, timeout=20)
    except requests.RequestException as exc:
        return {"status": "error", "reason": str(exc)}

    if resp.status_code == 404:
        result = {"status": "not_found"}
    elif resp.status_code >= 300:
        return {"status": "error", "reason": "HTTP {}".format(resp.status_code)}
    else:
        body = resp.json()
        pulses = body.get("pulse_info", {}).get("pulses", [])
        result = {
            "status": "found",
            "pulse_count": len(pulses),
            "pulse_names": [p.get("name", "")[:80] for p in pulses[:5]],
            "malware_families": sorted({
                m for p in pulses for m in (p.get("malware_families") or [])
            })[:5],
            "country": body.get("country_name"),
            "asn": body.get("asn"),
        }
    cache_put("otx", indicator, result)
    return result


def query_threatfox(indicator, auth_key, limiter):
    cached = cache_get("threatfox", indicator)
    if cached is not None:
        cached["cached"] = True
        return cached

    headers = {}
    if auth_key and "REPLACE_ME" not in auth_key:
        headers["Auth-Key"] = auth_key

    limiter.wait()
    try:
        resp = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                             json={"query": "search_ioc", "search_term": indicator},
                             headers=headers, timeout=20)
    except requests.RequestException as exc:
        return {"status": "error", "reason": str(exc)}

    if resp.status_code in (401, 403):
        return {"status": "skipped",
                "reason": "ThreatFox now requires an Auth-Key (ABUSECH_AUTH_KEY)"}
    if resp.status_code >= 300:
        return {"status": "error", "reason": "HTTP {}".format(resp.status_code)}

    try:
        body = resp.json()
    except ValueError:
        return {"status": "error", "reason": "non-JSON response"}

    if body.get("query_status") != "ok" or not body.get("data"):
        result = {"status": "not_found"}
    else:
        entries = body["data"]
        result = {
            "status": "found",
            "match_count": len(entries),
            "malware": sorted({e.get("malware_printable", "") for e in entries if e.get("malware_printable")})[:5],
            "threat_types": sorted({e.get("threat_type", "") for e in entries if e.get("threat_type")})[:5],
            "confidence": max((int(e.get("confidence_level") or 0) for e in entries), default=0),
            "first_seen": min((e.get("first_seen", "") for e in entries if e.get("first_seen")), default=""),
        }
    cache_put("threatfox", indicator, result)
    return result


def query_urlhaus(indicator, kind, auth_key, limiter):
    if kind not in ("url", "domain", "ip"):
        return {"status": "skipped", "reason": "URLhaus covers URLs, domains and IPs"}

    cached = cache_get("urlhaus", indicator)
    if cached is not None:
        cached["cached"] = True
        return cached

    headers = {}
    if auth_key and "REPLACE_ME" not in auth_key:
        headers["Auth-Key"] = auth_key

    if kind == "url":
        endpoint, payload = "https://urlhaus-api.abuse.ch/v1/url/", {"url": indicator}
    else:
        endpoint, payload = "https://urlhaus-api.abuse.ch/v1/host/", {"host": indicator}

    limiter.wait()
    try:
        resp = requests.post(endpoint, data=payload, headers=headers, timeout=20)
    except requests.RequestException as exc:
        return {"status": "error", "reason": str(exc)}

    if resp.status_code in (401, 403):
        return {"status": "skipped",
                "reason": "URLhaus now requires an Auth-Key (ABUSECH_AUTH_KEY)"}
    if resp.status_code >= 300:
        return {"status": "error", "reason": "HTTP {}".format(resp.status_code)}

    try:
        body = resp.json()
    except ValueError:
        return {"status": "error", "reason": "non-JSON response"}

    if body.get("query_status") != "ok":
        result = {"status": "not_found"}
    else:
        urls = body.get("urls") or []
        result = {
            "status": "found",
            "url_count": int(body.get("url_count") or len(urls)),
            "threat": body.get("threat") or (urls[0].get("threat") if urls else ""),
            "tags": sorted({t for u in urls for t in (u.get("tags") or [])})[:8],
            "first_seen": body.get("firstseen", ""),
        }
    cache_put("urlhaus", indicator, result)
    return result


# ---------------------------------------------------------------------------
# Scoring and reporting
# ---------------------------------------------------------------------------

def verdict_for(results):
    """Combine the sources into one verdict an analyst can act on."""
    score = 0
    reasons = []

    vt = results.get("virustotal", {})
    if vt.get("status") == "found":
        malicious = vt.get("malicious", 0)
        if malicious >= 5:
            score += 60; reasons.append("VirusTotal: {} engines flag it".format(malicious))
        elif malicious >= 1:
            score += 30; reasons.append("VirusTotal: {} engine(s) flag it".format(malicious))

    otx = results.get("otx", {})
    if otx.get("status") == "found" and otx.get("pulse_count", 0) > 0:
        score += min(otx["pulse_count"] * 5, 25)
        reasons.append("OTX: referenced in {} pulse(s)".format(otx["pulse_count"]))

    tf = results.get("threatfox", {})
    if tf.get("status") == "found":
        score += 40
        reasons.append("ThreatFox: known IOC" +
                       (" ({})".format(", ".join(tf["malware"])) if tf.get("malware") else ""))

    uh = results.get("urlhaus", {})
    if uh.get("status") == "found":
        score += 40
        reasons.append("URLhaus: {} malicious URL(s)".format(uh.get("url_count", 1)))

    score = min(score, 100)
    if score >= 60:
        label = "MALICIOUS"
    elif score >= 30:
        label = "SUSPICIOUS"
    elif score > 0:
        label = "LOW CONFIDENCE"
    else:
        label = "NO DATA"
    return {"score": score, "label": label, "reasons": reasons}


def enrich(indicators, keys, verbose=True):
    limiters = {
        "vt": RateLimiter(VT_RATE_PER_MIN),
        "otx": RateLimiter(OTX_RATE_PER_MIN),
        "abusech": RateLimiter(ABUSECH_RATE_PER_MIN),
    }
    out = []
    for index, indicator in enumerate(indicators, 1):
        kind = classify(indicator)
        if verbose:
            print("  [{}/{}] {} ({})".format(index, len(indicators), indicator, kind),
                  file=sys.stderr)
        results = {
            "virustotal": query_virustotal(indicator, kind, keys.get("vt", ""), limiters["vt"]),
            "otx": query_otx(indicator, kind, keys.get("otx", ""), limiters["otx"]),
            "threatfox": query_threatfox(indicator, keys.get("abusech", ""), limiters["abusech"]),
            "urlhaus": query_urlhaus(indicator, kind, keys.get("abusech", ""), limiters["abusech"]),
        }
        out.append({
            "indicator": indicator,
            "type": kind,
            "sources": results,
            "verdict": verdict_for(results),
        })
    return out


def build_markdown(enriched):
    lines = ["# Threat Intelligence Enrichment", "",
             "Generated {}".format(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")),
             "", "## Verdict summary", "",
             "| Indicator | Type | Verdict | Score | Evidence |",
             "|---|---|---|---:|---|"]
    for item in sorted(enriched, key=lambda i: -i["verdict"]["score"]):
        verdict = item["verdict"]
        lines.append("| `{}` | {} | **{}** | {} | {} |".format(
            item["indicator"], item["type"], verdict["label"], verdict["score"],
            "; ".join(verdict["reasons"]) or "no source returned data"))
    lines += ["", "## Source availability", ""]

    availability = {}
    for item in enriched:
        for source, result in item["sources"].items():
            availability.setdefault(source, set()).add(result.get("status", "unknown"))
    lines += ["| Source | Statuses seen |", "|---|---|"]
    for source, statuses in sorted(availability.items()):
        lines.append("| {} | {} |".format(source, ", ".join(sorted(statuses))))
    lines += ["", "_Generated by siem-home-lab `automation/threat_intel_enrich.py`._"]
    return "\n".join(lines)


def load_env(path):
    values = {}
    p = Path(path)
    if p.exists():
        for raw in p.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def main():
    parser = argparse.ArgumentParser(description="Enrich indicators against threat-intel sources")
    parser.add_argument("indicators", nargs="*", help="indicators to look up")
    parser.add_argument("--ip", action="append", default=[])
    parser.add_argument("--hash", action="append", default=[])
    parser.add_argument("--domain", action="append", default=[])
    parser.add_argument("--from-alerts", help="extract indicators from a Wazuh alerts.json")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--limit", type=int, default=25, help="max indicators to look up")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--output", help="write a markdown report here")
    parser.add_argument("--json-output", help="write raw results here")
    args = parser.parse_args()

    env = load_env(args.env_file)
    keys = {
        "vt": os.environ.get("VIRUSTOTAL_API_KEY") or env.get("VIRUSTOTAL_API_KEY", ""),
        "otx": os.environ.get("OTX_API_KEY") or env.get("OTX_API_KEY", ""),
        "abusech": os.environ.get("ABUSECH_AUTH_KEY") or env.get("ABUSECH_AUTH_KEY", ""),
    }

    indicators = list(args.indicators) + args.ip + args.hash + args.domain
    if args.from_alerts:
        until = datetime.now(timezone.utc)
        since = until - timedelta(hours=args.hours)
        loaded = load_alerts(args.from_alerts, since=since, until=until)
        found = extract_iocs(loaded["alerts"])
        for values in found.values():
            indicators.extend(values)
        print("extracted {} indicator(s) from {} alert(s)".format(
            sum(len(v) for v in found.values()), len(loaded["alerts"])), file=sys.stderr)

    indicators = list(dict.fromkeys(i for i in indicators if i))[:args.limit]
    if not indicators:
        print("No indicators to enrich. Public IPs/hashes/URLs are needed - a lab "
              "that only ever sees RFC1918 traffic will produce none.", file=sys.stderr)
        return 0

    configured = [name for name, value in keys.items() if value and "REPLACE_ME" not in value]
    print("keys configured: {}".format(", ".join(configured) or "none (ThreatFox/URLhaus "
          "may still answer without one)"), file=sys.stderr)

    enriched = enrich(indicators, keys)
    report = build_markdown(enriched)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(report)
        print("wrote {}".format(args.output), file=sys.stderr)
    else:
        print(report)

    if args.json_output:
        Path(args.json_output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_output).write_text(json.dumps(enriched, indent=2, default=str))
        print("wrote {}".format(args.json_output), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
