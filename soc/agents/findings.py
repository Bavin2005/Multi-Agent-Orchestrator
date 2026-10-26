"""Turn a playbook match + decision (or an LLM draft) into the structured findings the orchestrator
consumes, and validate citations (Stage 9 step 6)."""
from __future__ import annotations

from .engine import Decision, PlaybookEngine, PlaybookMatch, render, stage_vars
from ..util import hms, iso, parse_ts

AGENT_NAME = {"network": "network_agent", "app_endpoint": "app_endpoint_agent"}
KNOWN_ATTACK_TYPES = {
    "PORT_SCAN", "BRUTE_FORCE", "SQL_INJECTION", "XSS", "FIREWALL_POLICY_VIOLATION",
    "SUSPICIOUS_ENDPOINT_EXECUTION", "MALICIOUS_IP_DOMAIN", "MALWARE_DOWNLOAD_EXECUTION",
    "MULTI_STAGE_ATTACK", "UNMAPPED_SUSPICIOUS_ACTIVITY",
}


def _range(events: list[dict]) -> dict:
    ts = sorted(e["timestamp"] for e in events)
    if not ts:
        return {}
    label = f"{hms(ts[0])} UTC" if hms(ts[0]) == hms(ts[-1]) else f"{hms(ts[0])}-{hms(ts[-1])} UTC"
    return {"start": ts[0], "end": ts[-1], "label": label}


def _uniq(details: list[str]) -> str:
    return " ".join(dict.fromkeys(details))


def fingerprint(attack_type: str, stage_names: list[str], events: list[dict]) -> dict:
    ports = sorted({e["dst_port"] for e in events if e.get("dst_port") is not None})
    return {"attack_type": attack_type, "stages": stage_names, "ports": ports}


def playbook_findings(m: PlaybookMatch, d: Decision, engine: PlaybookEngine, *, judge: dict | None,
                      incident_id: str, version: int, domain: str) -> dict:
    spec = m.spec
    verdict = d.verdict
    label = d.label
    if verdict == "AMBIGUOUS":                       # resolved by the LLM judge (or conservative default)
        verdict = (judge or {}).get("verdict", "TRUE_POSITIVE")
    attack_events = m.attack_events
    checks = d.checks
    passed = [c for c in checks if c["passed"]]
    failed = [c for c in checks if not c["passed"]]
    hypo = engine.fp_labels[label or (checks[0]["label"] if checks else "FP_AUTHORIZED_PENTEST")]["benign_hypothesis"] \
        if (label or checks) else "No benign explanation applies."
    confidence = d.confidence if d.verdict != "AMBIGUOUS" else float((judge or {}).get("confidence", 0.5))

    if verdict == "FALSE_POSITIVE":
        label = label or (passed[0]["label"] if passed else "FP_AUTHORIZED_PENTEST")
        fl = engine.fp_labels[label]
        fv = {**m.vars, **stage_vars(attack_events, [], engine.kb)}
        pt = engine.kb.pentest(m.vars["src_ip"], attack_events[0]["timestamp"])
        fv.update({"ticket": pt["ticket"] if pt else "?", "window_end": pt["window_end"][11:19] if pt else "?"})
        stages = [{"name": fl["stage"], "evidence": [e["event_id"] for e in attack_events],
                   "time_range": _range(attack_events), "mitre": [],
                   "what_happened": render(fl["stage_desc"], fv)}]
        summary = render(fl["summary"], fv)
        impact = ["No malicious impact: the benign explanation is supported by inventory/allowlist evidence."]
        gaps = ["The verdict depends on the allowlist / inventory entries being current; an analyst should confirm before closing."]
        actions = [render(a, fv) for a in fl["actions"]]
        attack_type, mitre = label, []
        title = fl["title"]
        outcome = "accepted"
        reasoning = "Accepted: " + _uniq([c["detail"] for c in passed]) if passed else (judge or {}).get("reasoning", "")
        hypo = fl["benign_hypothesis"]
    else:
        stages = []
        for name, sr in m.stages.items():
            stages.append({"name": name, "evidence": sr.ids, "time_range": _range(sr.events + sr.support),
                           "mitre": sr.mitre, "what_happened": sr.desc})
        summary = render(spec["summary"], m.vars)
        impact = engine.render_list(spec.get("impact", []), m)
        gaps = engine.render_list(spec.get("gaps", []), m)
        actions = engine.render_list(spec.get("actions", []), m)
        attack_type = spec["attack_type"]
        title = spec["title"]
        mitre = list(dict.fromkeys(t for s in stages for t in s["mitre"]))
        outcome = "rejected" if not passed else "inconclusive"
        if failed:
            reasoning = "Rejected: " + _uniq([c["detail"] for c in failed])
        else:
            reasoning = ""
        if d.verdict == "AMBIGUOUS" and judge:
            reasoning = f"Benign and attack evidence disagreed; judge: {judge.get('reasoning', '')}"
            outcome = "inconclusive"
        if not checks:
            reasoning = "No benign-twin checks are configured for this playbook."

    return {
        "incident_id": incident_id, "version": version, "agent": AGENT_NAME[domain],
        "playbook": m.name, "attack_type": attack_type,
        "suspected_attack_type": spec["attack_type"], "title": title,
        "verdict": verdict, "confidence": round(confidence, 2),
        "summary": summary, "stages": stages,
        "fp_assessment": {"checks_run": len(checks), "checks_passed": len(passed), "checks": checks,
                          "benign_explanation": hypo, "outcome": outcome, "reasoning": reasoning,
                          "fp_label": label if verdict == "FALSE_POSITIVE" else None},
        "mitre": mitre, "impact": impact, "gaps": gaps, "recommended_actions": actions,
        "context_events": {k: [e["event_id"] for e in v] for k, v in m.context_events.items()},
        "playbook_stages": list(m.stages),
    }


def llm_findings(out: dict, index: dict, *, incident_id: str, version: int, domain: str) -> dict:
    attack_type = out.get("attack_type") if out.get("attack_type") in KNOWN_ATTACK_TYPES else "UNMAPPED_SUSPICIOUS_ACTIVITY"
    stages = []
    for s in out.get("stages", []) or []:
        ids = [i for i in s.get("evidence", []) if i in index]
        evs = [index[i]["event"] for i in ids]
        top = out.get("mitre", []) if len(out.get("stages") or []) == 1 else []
        stages.append({"name": s.get("name", "unnamed_stage"), "evidence": list(s.get("evidence", [])),
                       "time_range": _range(evs), "mitre": s.get("mitre") or top,
                       "what_happened": s.get("what_happened", "")})
    verdict = out.get("verdict") if out.get("verdict") in ("TRUE_POSITIVE", "FALSE_POSITIVE") else "UNDETERMINED"
    return {
        "incident_id": incident_id, "version": version, "agent": AGENT_NAME[domain],
        "playbook": None, "attack_type": attack_type, "suspected_attack_type": attack_type,
        "title": "Unmatched activity (LLM reconstruction)", "verdict": verdict,
        "confidence": round(float(out.get("confidence", 0.5)), 2), "summary": out.get("summary", ""),
        "stages": stages,
        "fp_assessment": {"checks_run": 0, "checks_passed": 0, "checks": [],
                          "benign_explanation": out.get("benign_explanation", ""),
                          "outcome": "rejected" if verdict == "TRUE_POSITIVE" else "accepted",
                          "reasoning": out.get("rejected_because", ""), "fp_label": None},
        "mitre": out.get("mitre", []), "impact": out.get("impact", []) or [out.get("summary", "")],
        "gaps": out.get("gaps", []), "recommended_actions": out.get("recommended_actions", []),
        "context_events": {}, "playbook_stages": [st["name"] for st in stages],
    }


def validate_findings(f: dict, index: dict) -> list[str]:
    """Every cited id must exist in the evidence index and every stage must cite >= 1 event."""
    errs: list[str] = []
    if f["verdict"] != "FALSE_POSITIVE" and not f["stages"]:
        errs.append("no stages were reconstructed for a non-benign verdict")
    for s in f["stages"]:
        if not s["evidence"]:
            errs.append(f"stage '{s['name']}' cites no event id")
        for i in s["evidence"]:
            if i not in index:
                errs.append(f"stage '{s['name']}' cites unknown event id '{i}'")
    return errs
