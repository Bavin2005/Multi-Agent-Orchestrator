"""Threat Intelligence agent (Stage 7b) + the local knowledge base it reads.

The TI agent is a *stage*, not an owner: every incident's external IPs, domains, URLs and file
hashes are looked up before dispatch and attached to the bundle as citable evidence. Internal
entities resolve against the asset inventory and allowlists (scanner, service account, pentest).
Results are cached per entity (24 h of simulated time).
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from .util import parse_ts

SCORE = {"known_malicious": 2, "suspicious": 1, "unknown": 0, "benign_allowlisted": 0, "internal_asset": 0}
INTERNAL_HOSTNAMES = {"web-server", "internal-web-server", "docs.internal"}


class KnowledgeBase:
    """JSON-backed indicator + asset knowledge. `available` is False if loading fails."""

    def __init__(self, kdir: Path):
        self.dir = kdir
        self.available = True
        try:
            self.ioc = self._load("ioc.json")
            self.assets = self._load("assets.json")
            self.allow = self._load("allowlists.json")
            self.reference = self._load("reference_attacks.json").get("attacks", [])
        except (OSError, json.JSONDecodeError):
            self.available = False
            self.ioc, self.assets, self.allow, self.reference = {}, {}, {}, []
        self._cmd = [(p, re.compile(p["regex"])) for p in
                     self.ioc.get("suspicious_artifacts", {}).get("command_patterns", [])]
        self._benign_cmd = [(p, re.compile(p["regex"])) for p in
                            self.ioc.get("suspicious_artifacts", {}).get("benign_command_patterns", [])]
        self._path = [(p, re.compile(p["regex"])) for p in
                      self.ioc.get("suspicious_artifacts", {}).get("path_patterns", [])]
        self._url = [(p, re.compile(p["regex"])) for p in
                     self.ioc.get("suspicious_artifacts", {}).get("url_patterns", [])]

    def _load(self, name: str) -> dict:
        return json.loads((self.dir / name).read_text(encoding="utf-8"))

    # ---- allowlists / assets ------------------------------------------------------------------
    def scanner(self, ip: str | None) -> dict | None:
        return next((s for s in self.allow.get("internal_scanners", []) if s["src_ip"] == ip), None)

    def pentest(self, ip: str | None, ts: str | datetime | None) -> dict | None:
        if not ip or ts is None:
            return None
        t = parse_ts(ts)
        for p in self.allow.get("pentest_schedule", []):
            if p["src_ip"] == ip and parse_ts(p["window_start"]) <= t <= parse_ts(p["window_end"]):
                return p
        return None

    def internal_site(self, host: str | None) -> dict | None:
        return next((s for s in self.allow.get("internal_sites", []) if s["host"] == host), None)

    def host_info(self, host: str | None) -> dict:
        h = self.assets.get("hosts", {}).get(host or "", None)
        if h is None:  # unknown host defaults to "internal"
            return {"host": host, "criticality": 1, "tier": "internal (not in inventory)", "admin_host": False,
                    "in_inventory": False}
        return {"host": host, **h, "in_inventory": True}

    def user_info(self, user: str | None) -> dict:
        u = self.assets.get("users", {}).get(user or "")
        if u is None:
            return {"user": user, "type": "user", "known_ips": [], "in_inventory": False}
        return {"user": user, **u, "in_inventory": True}

    # ---- indicator matching -------------------------------------------------------------------
    def match_command(self, cmd: str | None) -> list[dict]:
        return [p for p, rx in self._cmd if cmd and rx.search(cmd)]

    def is_benign_command(self, cmd: str | None) -> dict | None:
        return next((p for p, rx in self._benign_cmd if cmd and rx.search(cmd)), None)

    def match_path(self, path: str | None) -> list[dict]:
        return [p for p, rx in self._path if path and rx.search(path)]

    def match_url(self, url: str | None) -> list[dict]:
        return [p for p, rx in self._url if url and rx.search(url)]

    def port(self, port: int | str | None) -> dict | None:
        return self.ioc.get("ports", {}).get(str(port)) if port is not None else None

    def reference_cves_for_port(self, port: int | None) -> list[str]:
        info = self.port(port) or {}
        return info.get("cves", [])


def is_private(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return False


def domain_of(event: dict) -> str | None:
    ext = event.get("ext", {})
    host = ext.get("host")
    url = ext.get("url") or ""
    if url.startswith("http"):
        host = urlparse(url).hostname or host
    return host


def is_external_domain(d: str | None) -> bool:
    return bool(d) and d not in INTERNAL_HOSTNAMES and "." in d and not d.endswith(".internal")


class ThreatIntelAgent:
    name = "threat_intel_agent"

    def __init__(self, kb: KnowledgeBase, cache_hours: float = 24):
        self.kb = kb
        self.ttl = timedelta(hours=cache_hours)
        self._cache: dict[tuple[str, str], tuple[datetime, dict]] = {}
        self.stats = {"lookups": 0, "cache_hits": 0}

    @property
    def available(self) -> bool:
        return self.kb.available

    # ------------------------------------------------------------------------------------------
    def lookup(self, etype: str, value: str, as_of: datetime | None = None, ts: str | None = None) -> dict:
        key = (etype, value)
        now = as_of or datetime(2000, 1, 1)
        hit = self._cache.get(key)
        if hit and now - hit[0] < self.ttl and etype != "ip_ctx":
            self.stats["cache_hits"] += 1
            return hit[1]
        self.stats["lookups"] += 1
        fn = {"ip": self._ip, "domain": self._domain, "url": self._url, "hash": self._hash,
              "user": self._user, "host": self._host}[etype]
        v = fn(value, ts)
        v["score"] = SCORE.get(v["verdict"], 0)
        if etype != "ip":      # ip verdicts depend on the event time (pentest window): do not cache by IP alone
            self._cache[key] = (now, v)
        return v

    def _ip(self, ip: str, ts: str | None) -> dict:
        base = {"entity": ip, "type": "ip", "sources": [], "mitre": [], "notes": ""}
        pt = self.kb.pentest(ip, ts)
        if pt:
            return {**base, "verdict": "benign_allowlisted", "category": "authorised penetration test",
                    "sources": ["pentest_schedule"], "ticket": pt["ticket"],
                    "notes": f"Listed in pentest schedule {pt['ticket']} ({pt['window_start'][11:19]}-{pt['window_end'][11:19]} UTC)."}
        sc = self.kb.scanner(ip)
        if sc:
            return {**base, "verdict": "benign_allowlisted", "category": "internal vulnerability scanner",
                    "sources": ["asset_inventory"], "notes": f"Enterprise scanner owned by {sc['owner']}."}
        for feed in self.kb.ioc.get("ip_feeds", []):
            e = feed["entries"].get(ip)
            if e:
                return {**base, "verdict": e["verdict"], "category": e["category"], "sources": [feed["name"]],
                        "notes": f"Listed in {feed['name']}."}
        n = len(self.kb.ioc.get("ip_feeds", []))
        scope = "private address" if is_private(ip) else "public address"
        return {**base, "verdict": "unknown", "category": scope, "sources": ["local indicator feeds"],
                "notes": f"No match in {n} local reputation feed(s)."}

    def _domain(self, d: str, ts: str | None) -> dict:
        e = self.kb.ioc.get("domains", {}).get(d)
        if e:
            return {"entity": d, "type": "domain", "verdict": e["verdict"], "category": e["category"],
                    "sources": e["sources"], "mitre": e.get("mitre", []), "notes": e.get("notes", "")}
        return {"entity": d, "type": "domain", "verdict": "unknown", "category": "uncategorised",
                "sources": ["local indicator feeds"], "mitre": [], "notes": "No match in local domain feeds."}

    def _url(self, url: str, ts: str | None) -> dict:
        dom = urlparse(url).hostname if url.startswith("http") else None
        dv = self._domain(dom, ts) if dom else None
        pats = self.kb.match_url(url)
        verdict = dv["verdict"] if dv else "unknown"
        if verdict == "unknown" and pats:
            verdict = "suspicious"
        return {"entity": url, "type": "url", "verdict": verdict,
                "category": (dv["category"] if dv and dv["verdict"] != "unknown" else
                             (pats[0]["desc"] if pats else "uncategorised")),
                "sources": (dv["sources"] if dv else []) + (["url_patterns"] if pats else []),
                "mitre": sorted({m for p in pats for m in p.get("mitre", [])} | set(dv["mitre"] if dv else [])),
                "notes": "; ".join(p["desc"] for p in pats)}

    def _hash(self, h: str, ts: str | None) -> dict:
        e = self.kb.ioc.get("file_hashes", {}).get(h)
        if e:
            return {"entity": h, "type": "hash", "verdict": "known_malicious", "category": e.get("family", "malware"),
                    "sources": ["hash feed"], "mitre": [], "notes": e.get("notes", "")}
        return {"entity": h, "type": "hash", "verdict": "unknown", "category": "no known family",
                "sources": ["local hash feed"], "mitre": [], "notes": "Hash not present in the local malware-hash feed."}

    def _user(self, u: str, ts: str | None) -> dict:
        info = self.kb.user_info(u)
        if info["in_inventory"]:
            return {"entity": u, "type": "user", "verdict": "internal_asset", "category": info["type"],
                    "sources": ["asset_inventory"], "mitre": [],
                    "notes": f"Service account owned by {info.get('owner_team', '?')}; {len(info['known_ips'])} known source IP(s)."}
        return {"entity": u, "type": "user", "verdict": "internal_asset", "category": "user account",
                "sources": ["asset_inventory"], "mitre": [], "notes": "Interactive user account."}

    def _host(self, h: str, ts: str | None) -> dict:
        info = self.kb.host_info(h)
        return {"entity": h, "type": "host", "verdict": "internal_asset",
                "category": f"{info['tier']} (criticality {info['criticality']})", "sources": ["asset_inventory"],
                "mitre": [], "notes": "In inventory." if info["in_inventory"] else "Not in inventory; defaulted to internal."}

    # ------------------------------------------------------------------------------------------
    def enrich(self, events: list[dict], as_of: datetime | None = None) -> dict:
        """Stage 7b. Returns {'available', 'verdicts': [..], 'artifacts': [..]}."""
        if not self.available:
            return {"available": False, "verdicts": [], "artifacts": []}
        seen: set[tuple[str, str]] = set()
        out: list[dict] = []
        arts: list[dict] = []

        def add(etype: str, value: str | None, ts: str | None = None):
            if value is None or (etype, value) in seen:
                return
            seen.add((etype, value))
            out.append(self.lookup(etype, str(value), as_of, ts))

        for e in sorted(events, key=lambda x: x["timestamp"]):
            ext = e.get("ext", {})
            add("ip", e.get("src_ip"), e["timestamp"])
            if e.get("dst_ip") and not is_private(e["dst_ip"]):
                add("ip", e["dst_ip"], e["timestamp"])
            d = domain_of(e)
            if is_external_domain(d):
                add("domain", d)
            url = ext.get("url")
            if url and str(url).startswith("http"):
                add("url", url)
            if ext.get("file_hash"):
                add("hash", ext["file_hash"])
            if e.get("user"):
                add("user", e["user"])
            if e.get("host"):
                add("host", e["host"])
            for p in self.kb.match_command(ext.get("command_line")):
                arts.append({"event_id": e["event_id"], "kind": "command", "id": p["id"], "desc": p["desc"], "mitre": p["mitre"]})
            for p in self.kb.match_path(ext.get("file_path")):
                arts.append({"event_id": e["event_id"], "kind": "path", "id": p["desc"], "desc": p["desc"], "mitre": p.get("mitre", [])})
            for p in self.kb.match_url(url):
                arts.append({"event_id": e["event_id"], "kind": "url", "id": p["desc"], "desc": p["desc"], "mitre": p.get("mitre", [])})
        return {"available": True, "verdicts": out, "artifacts": arts}


def best_ti_score(verdicts: list[dict]) -> tuple[int, dict | None]:
    """TI_score term: strongest verdict among EXTERNAL indicators (ip/domain/url/hash)."""
    ext = [v for v in verdicts if v["type"] in ("ip", "domain", "url", "hash")]
    if not ext:
        return 0, None
    top = max(ext, key=lambda v: v["score"])
    return top["score"], top if top["score"] else None
