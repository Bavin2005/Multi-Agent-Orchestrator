"""Stage 6 - readiness triggers + minimum-evidence rules, and Stage 7a - owner selection.

Triggers (any one): severity >= threshold, an end-signal action, a met evidence rule. There is
no "wait for the 10/30 min window to expire" trigger: the orchestrator dispatches after a short
quiet period (dispatch.debounce_s once a trigger fired, dispatch.idle_s otherwise) and caps total
holding at dispatch.max_wait_s.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .incidents import Incident
from .patterns import is_payload_success
from .util import Config, parse_ts


def _field(event: dict, path: str):
    cur = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def eval_rule(rule: dict, events: list[dict]) -> bool:
    """One evidence check (count / distinct / sequence / match) over a list of events."""
    if "count" in rule:
        c = rule["count"]
        groups: dict[tuple, int] = defaultdict(int)
        for e in events:
            if e["action"] == c["action"]:
                groups[tuple(e.get(f) for f in c.get("same", []))] += 1
        return any(n >= c["min"] for n in groups.values())
    if "distinct" in rule:
        c = rule["distinct"]
        groups2: dict[tuple, set] = defaultdict(set)
        for e in events:
            if e["action"] in ("SCAN", "BLOCK", "DROP", "SCAN_DETECTED", "CONNECTION_FAILED"):
                groups2[tuple(e.get(f) for f in c.get("same", []))].add(_field(e, c["field"]))
        return any(len({v for v in s if v is not None}) >= c["min"] for s in groups2.values())
    if "sequence" in rule:
        want = rule["sequence"]
        i = 0
        for e in sorted(events, key=lambda x: x["timestamp"]):
            if e["action"] == want[i]:
                i += 1
                if i == len(want):
                    return True
        return False
    if "match" in rule:
        m = rule["match"]
        rx = re.compile(m["regex"])
        return any(rx.search(str(_field(e, m["field"]) or "")) for e in events)
    return False


def evidence_rules_met(inc: Incident, rules: dict, extra: list[dict] | None = None) -> list[str]:
    groups = {g for a in inc.alerts for g in a["siem_groups"]}
    events = [a["event"] for a in inc.alerts] + list(extra or [])
    met: list[str] = []
    for name, spec in rules.items():
        if groups & set(spec["when_groups"]) and any(eval_rule(r, events) for r in spec["ready_if_any"]):
            met.append(name)
    return met


def end_signal(inc: Incident, cfg: Config, extra: list[dict] | None = None) -> str | None:
    evs = sorted({e["event_id"]: e for e in [a["event"] for a in inc.alerts] + list(extra or [])}.values(),
                 key=lambda e: e["timestamp"])
    actions = set(cfg["dispatch"]["end_signal_actions"])
    failed = False
    for e in evs:
        if e["action"] == "LOGIN_FAILED":
            failed = True
        if e["action"] == "LOGIN_SUCCESS" and failed:
            return "end signal: LOGIN_SUCCESS after failures"
        if e["action"] in actions:
            return f"end signal: {e['action']}"
        if is_payload_success(e):
            return "end signal: HTTP 200 on a payload"
    return None


def ready_reasons(inc: Incident, cfg: Config, extra: list[dict] | None = None) -> list[str]:
    """`extra` = runtime events for this incident's entity already visible at 'now' (log store)."""
    reasons: list[str] = []
    thr = cfg["dispatch"]["severity_threshold"]
    if inc.max_severity >= thr:
        reasons.append(f"severity {inc.max_severity} >= {thr}")
    sig = end_signal(inc, cfg, extra)
    if sig:
        reasons.append(sig)
    met = evidence_rules_met(inc, cfg["evidence_rules"], extra)
    if met:
        reasons.append("evidence rule met: " + ", ".join(met))
    return reasons


def owner_for(inc: Incident, cfg: Config) -> tuple[str, int, dict]:
    """Stage 7a. The domain with the furthest attack stage owns the incident.
    Ties -> higher severity, then the later alert."""
    rank_by_src = cfg["owner_rank"]
    domain_of_rank = {int(k): v for k, v in cfg["owner_domain"].items()}
    best = None
    for a in inc.alerts:
        r = rank_by_src.get(a["event"]["source_type"], 1)
        key = (r, a["siem_severity"], a["event"]["timestamp"])
        if best is None or key > best[0]:
            best = (key, a)
    rank = best[0][0]
    domain = domain_of_rank[rank]
    return domain, rank, {"alert_id": best[1]["alert_id"], "rank": rank, "domain": domain,
                          "reason": f"furthest stage rank {rank} ({best[1]['event']['source_type']})"}
