"""Stage 11 - fixed-formula risk score (same evidence always gets the same risk).

    risk = base(attack_type) + success_bonus + TI_score + asset_criticality - FP_evidence

A FALSE_POSITIVE verdict additionally caps the level at LOW (config risk.cap_low_when_false_positive).
"""
from __future__ import annotations

from collections import Counter

from .patterns import is_payload_success
from .ti import KnowledgeBase, best_ti_score
from .util import Config


def level_for(score: int, levels: dict) -> str:
    for name in ("CRITICAL", "HIGH", "MEDIUM"):
        if score >= levels[name]:
            return name
    return "LOW"


def compromise_reached(findings: dict, index: dict) -> str | None:
    """Did the attack reach a compromise stage? (LOGIN_SUCCESS, HTTP 200 on a payload, PROCESS_EXECUTION)."""
    for st in findings["stages"]:
        for i in st["evidence"]:
            e = index.get(i, {}).get("event")
            if not e:
                continue
            if e["action"] == "LOGIN_SUCCESS":
                return f"LOGIN_SUCCESS ({i})"
            if e["action"] == "PROCESS_EXECUTION":
                return f"PROCESS_EXECUTION ({i})"
            if is_payload_success(e):
                return f"HTTP 200 on payload ({i})"
    return None


def score_risk(findings: dict, bundle: dict, index: dict, kb: KnowledgeBase, cfg: Config) -> dict:
    r = cfg["risk"]
    is_fp = findings["verdict"] == "FALSE_POSITIVE"
    atype = findings["suspected_attack_type"] if is_fp else findings["attack_type"]
    base = r["base"].get(atype, r["base"]["UNMAPPED_SUSPICIOUS_ACTIVITY"])
    hit = compromise_reached(findings, index)
    success = r["success_bonus"] if hit else 0
    ti_score, ti_ent = best_ti_score(bundle["ti"]["verdicts"])
    hosts = Counter(a["event"]["host"] for a in bundle["alerts"] if a["event"].get("host"))
    host = hosts.most_common(1)[0][0] if hosts else None
    asset = kb.host_info(host)
    passed = findings["fp_assessment"]["checks_passed"]
    fp_term = r["fp_evidence_per_check"] * passed
    score = base + success + ti_score + asset["criticality"] - fp_term
    level = level_for(score, r["levels"])
    capped = False
    if is_fp and r["cap_low_when_false_positive"] and level != "LOW":
        level, capped = "LOW", True
    return {
        "score": score, "level": level, "capped_low_for_false_positive": capped,
        "formula": f"{base} + {success} + {ti_score} + {asset['criticality']} - {fp_term} = {score}",
        "terms": {
            "base": {"value": base, "why": f"base({atype})"},
            "success_bonus": {"value": success, "why": hit or "no compromise stage reached"},
            "ti_score": {"value": ti_score, "why": (f"{ti_ent['entity']} is {ti_ent['verdict']}" if ti_ent else "no external indicator matched")},
            "asset_criticality": {"value": asset["criticality"], "why": f"{host}: {asset['tier']}"},
            "fp_evidence": {"value": -fp_term, "why": f"{passed} benign-twin check(s) passed x {r['fp_evidence_per_check']}"},
        },
    }
