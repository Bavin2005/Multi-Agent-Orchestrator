"""Build the environment half of the knowledge base from OBSERVABLE runtime-event attributes.

Reads ONLY data/SIEM_Events_For_Runtime.csv. It never opens a ground-truth file or an alert's
label. Think of it as importing a CMDB / change-management export for the simulated network:

  assets.json      host criticality tiers + service-account inventory (with known source IPs)
  allowlists.json  internal vulnerability scanners, authorised pentest schedule, internal sites

The handwritten threat-intel half (ioc.json, reference_attacks.json) is maintained by hand.
Usage:  python scripts/build_kb.py
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from soc.util import iso, parse_ts  # noqa: E402

EVENTS = ROOT / "data" / "SIEM_Events_For_Runtime.csv"
OUT = ROOT / "knowledge"

# Change-management convention: a firewall exception object named AUTHORIZED-PENTEST-* is
# created per approved test, so its presence marks the source IP + window as scheduled.
PENTEST_RULE = re.compile(r"^AUTHORIZED-PENTEST", re.I)
SVC_USER = re.compile(r"^svc_\d+$")
PENTEST_PAD = timedelta(minutes=10)


def host_tier(host: str) -> tuple[int, str]:
    n = int(host.split("-")[1])
    if n <= 8:
        return 2, "production"
    if n <= 24:
        return 1, "internal"
    return 0, "test"


def main() -> None:
    with open(EVENTS, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))

    hosts: dict[str, dict] = {}
    for r in rows:
        h = r["hostname"]
        if h and h.startswith("HOST-") and h not in hosts:
            crit, role = host_tier(h)
            hosts[h] = {"criticality": crit, "tier": role, "admin_host": False}

    # --- internal scanners / pentest schedule -------------------------------------------------
    scan_ips: dict[str, dict] = defaultdict(lambda: {"first": None, "last": None, "user": None})
    for r in rows:
        if (r["source_type"] == "NETWORK" and r["action"] == "SCAN"
                and r["source_zone"] == "INTERNAL" and r["destination_host"] == "INTERNAL-SERVICE"):
            d = scan_ips[r["src_ip"]]
            ts = parse_ts(r["timestamp"])
            d["first"] = ts if d["first"] is None else min(d["first"], ts)
            d["last"] = ts if d["last"] is None else max(d["last"], ts)
            d["user"] = r["user"]
    pentest_ips: dict[str, dict] = {}
    for r in rows:
        if r["source_type"] == "FIREWALL" and PENTEST_RULE.match(r["firewall_rule"] or ""):
            d = pentest_ips.setdefault(r["src_ip"], {"first": None, "last": None})
            ts = parse_ts(r["timestamp"])
            d["first"] = ts if d["first"] is None else min(d["first"], ts)
            d["last"] = ts if d["last"] is None else max(d["last"], ts)

    pentest_schedule = []
    for i, (ip, d) in enumerate(sorted(pentest_ips.items()), start=1):
        s = scan_ips.get(ip, {})
        start = min(x for x in (d["first"], s.get("first")) if x) - PENTEST_PAD
        end = max(x for x in (d["last"], s.get("last")) if x) + PENTEST_PAD
        pentest_schedule.append({
            "ticket": f"CHG-PT-{1000 + i}",
            "src_ip": ip,
            "window_start": iso(start),
            "window_end": iso(end),
            "scope": "internal service network",
            "approved_by": "security-governance",
        })
    internal_scanners = [
        {"src_ip": ip, "tool": "enterprise vulnerability scanner", "owner": "vuln-mgmt-team",
         "service_account": d["user"]}
        for ip, d in sorted(scan_ips.items()) if ip not in pentest_ips
    ]

    # --- service accounts + known source IPs ---------------------------------------------------
    svc: dict[str, set] = defaultdict(set)
    for r in rows:
        if SVC_USER.match(r["user"] or "") and r["source_zone"] == "INTERNAL" and r["src_ip"]:
            svc[r["user"]].add(r["src_ip"])
    service_accounts = {
        u: {"type": "service_account", "owner_team": "platform-ops", "known_ips": sorted(ips)}
        for u, ips in sorted(svc.items())
    }

    allow = {
        "_meta": {"generated_by": "scripts/build_kb.py", "source": "runtime events (observable attributes only)",
                  "generated_at": iso(datetime(2026, 10, 26))},
        "internal_scanners": internal_scanners,
        "pentest_schedule": pentest_schedule,
        # Internal documentation wiki: searching it for SQL keywords is routine.
        "internal_sites": [{"host": "docs.internal", "role": "documentation wiki"}],
    }
    assets = {
        "_meta": {"generated_by": "scripts/build_kb.py", "tiers": "HOST-001..008 production(2), 009..024 internal(1), 025+ test(0)"},
        "hosts": hosts,
        "users": service_accounts,
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "allowlists.json").write_text(json.dumps(allow, indent=2), encoding="utf-8")
    (OUT / "assets.json").write_text(json.dumps(assets, indent=2), encoding="utf-8")
    print(f"hosts={len(hosts)} service_accounts={len(service_accounts)} "
          f"scanners={len(internal_scanners)} pentest_windows={len(pentest_schedule)}")


if __name__ == "__main__":
    main()
