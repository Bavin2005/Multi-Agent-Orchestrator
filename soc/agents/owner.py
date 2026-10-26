"""Owner agents (Network Security, Application & Endpoint) - Stage 9 as a LangGraph pipeline:

  preprocess -> playbook -> memory -> (llm) -> fp_check -> validate -> (llm retry) -> finalize

Known attacks take the cheap playbook path; the LLM is used only when no playbook matches, or the
always-on false-positive check is ambiguous. Every cited event id is validated in code.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from ..llm import LLM, LLMError
from ..memory import CaseMemory
from ..sanitize import SYSTEM_RULES, wrap_data
from ..tools import BudgetExceeded, ToolBox
from ..ti import KnowledgeBase
from ..util import Config, hms
from .engine import Ctx, Decision, PlaybookEngine, decide
from .findings import (AGENT_NAME, fingerprint, llm_findings, playbook_findings, validate_findings)

SCHEMA = """{
 "attack_type": "one of PORT_SCAN|BRUTE_FORCE|SQL_INJECTION|XSS|FIREWALL_POLICY_VIOLATION|SUSPICIOUS_ENDPOINT_EXECUTION|MALICIOUS_IP_DOMAIN|MALWARE_DOWNLOAD_EXECUTION|MULTI_STAGE_ATTACK|UNMAPPED_SUSPICIOUS_ACTIVITY",
 "verdict": "TRUE_POSITIVE | FALSE_POSITIVE",
 "confidence": 0.0-1.0,
 "summary": "one sentence: what happened and whether it is a real attack",
 "stages": [{"name": "snake_case_stage", "evidence": ["<event_id from the evidence>"], "what_happened": "...", "mitre": ["T...."]}],
 "benign_explanation": "the strongest benign explanation",
 "rejected_because": "why it fails or holds",
 "impact": ["what is confirmed"], "gaps": ["what the evidence does not show"],
 "recommended_actions": ["ordered analyst steps"],
 "tool_requests": [{"tool": "get_related_logs|ti_lookup|get_asset_info|consult_agent|get_playbook", "args": {}}]
}"""


class AgentState(TypedDict, total=False):
    bundle: dict
    tools: ToolBox
    events: list
    index: dict
    match: Any
    decision: Decision
    judge: dict
    hints: list
    related: list
    llm_out: dict
    draft: dict
    errors: list
    retries: int
    first_pass_valid: bool
    path: str
    needs_human: str
    consultations: list
    findings: dict


def compress(events: list[dict], over: int) -> list[dict]:
    """Repeats become one line with a range and a few ids (the full id list stays in the index)."""
    groups: dict[tuple, list[dict]] = {}
    for e in events:
        key = (e["source_type"], e["action"], e.get("src_ip"), e.get("user"))
        groups.setdefault(key, []).append(e)
    out = []
    for (st, act, ip, user), evs in groups.items():
        if len(evs) > over:
            out.append({"repeat": f"{len(evs)}x {st} {act}", "src_ip": ip, "user": user,
                        "range": f"{hms(evs[0]['timestamp'])}-{hms(evs[-1]['timestamp'])}",
                        "sample_event_ids": [e["event_id"] for e in evs[:3]]})
        else:
            out.extend(evs)
    return out


class OwnerAgent:
    def __init__(self, domain: str, cfg: Config, engine: PlaybookEngine, kb: KnowledgeBase, llm: LLM,
                 memory: CaseMemory):
        self.domain, self.cfg, self.engine, self.kb, self.llm, self.memory = domain, cfg, engine, kb, llm, memory
        self.name = AGENT_NAME[domain]
        self.max_retries = cfg["agent"]["citation_retries"]
        self.graph = self._build()

    # ---------------------------------------------------------------- graph
    def _build(self):
        g = StateGraph(AgentState)
        for name, fn in [("preprocess", self.n_preprocess), ("playbook", self.n_playbook), ("memory", self.n_memory),
                         ("llm", self.n_llm), ("fp_check", self.n_fp_check), ("validate", self.n_validate),
                         ("finalize", self.n_finalize)]:
            g.add_node(name, fn)
        g.set_entry_point("preprocess")
        g.add_edge("preprocess", "playbook")
        g.add_edge("playbook", "memory")
        g.add_conditional_edges("memory", lambda s: "fp_check" if s.get("match") else "llm",
                                {"fp_check": "fp_check", "llm": "llm"})
        g.add_edge("llm", "fp_check")
        g.add_edge("fp_check", "validate")
        g.add_conditional_edges("validate", self._after_validate, {"llm": "llm", "finalize": "finalize"})
        g.add_edge("finalize", END)
        return g.compile()

    def run(self, bundle: dict, tools: ToolBox) -> tuple[dict, dict]:
        """Returns (findings, evidence_index)."""
        out = self.graph.invoke({"bundle": bundle, "tools": tools, "retries": 0, "errors": [], "consultations": []})
        return out["findings"], out["index"]

    # ---------------------------------------------------------------- nodes
    def n_preprocess(self, s: AgentState) -> dict:
        b = s["bundle"]
        events = sorted({e["event_id"]: e for e in b["events"]}.values(), key=lambda e: (e["timestamp"], e["event_id"]))
        alert_ids = set(b["alert_event_ids"])
        index = {e["event_id"]: {"event": e, "via": "alert" if e["event_id"] in alert_ids else "log_store",
                                 "domain": b["event_domain"].get(e["event_id"])} for e in events}
        return {"events": events, "index": index}

    def n_playbook(self, s: AgentState) -> dict:
        b, tools = s["bundle"], s["tools"]
        m = self.engine.match(s["events"], b["ti"]["verdicts"])
        if not m:
            return {"match": None}
        self.engine.build_vars(m, s["events"])
        consults = []
        try:
            tools.get_asset_info(m.vars["host"])
            cons = m.spec.get("consult")
            other = cons["domain"] if cons else None
            if other and other in b["domains"] and other != self.domain:
                evs = m.stages[cons["stage"]].ids
                consults.append({"domain": other, "stage": cons["stage"], **tools.consult_agent(other, evs)})
        except BudgetExceeded as exc:
            return {"match": m, "needs_human": str(exc), "consultations": consults}
        return {"match": m, "consultations": consults}

    def n_memory(self, s: AgentState) -> dict:
        m = s.get("match")
        if m:
            fp = fingerprint(m.spec["attack_type"], list(m.stages), m.attack_events)
        else:
            fp = fingerprint("UNMAPPED_SUSPICIOUS_ACTIVITY", ["unclassified_suspicious_activity"],
                             [a for a in s["events"] if a["event_id"] in set(s["bundle"]["alert_event_ids"])])
        thr = self.cfg["memory"]["similarity_threshold"]
        hints = self.memory.lookup(fp, thr)
        related = [c for c in self.memory.lookup(fp, 0.5, k=6) if c["similarity"] < thr][:2]
        return {"hints": hints, "related": related}

    def n_llm(self, s: AgentState) -> dict:
        b, tools = s["bundle"], s["tools"]
        alert_events = [s["index"][i]["event"] for i in b["alert_event_ids"] if i in s["index"]]
        shown = compress(s["events"], self.cfg["agent"]["compress_repeats_over"])[:60]
        digest = {"incident": b["incident_id"], "version": b["version"], "owner_domain": self.domain,
                  "entities": b["entities"], "ready_because": b["ready_reasons"],
                  "alert_events": [e["event_id"] for e in alert_events],
                  "siem_rules": sorted({a["siem_rule_name"] for a in b["alerts"]}),
                  "events": shown, "threat_intel": b["ti"]["verdicts"],
                  "ti_available": b["ti"]["available"], "case_memory_hints": s.get("hints", [])}
        retry = ""
        if s.get("errors"):
            retry = "\nYour previous answer failed validation: " + "; ".join(s["errors"]) + ". Fix exactly these problems."
        prompt = ("Reconstruct the incident from the evidence below and decide whether it is a real attack.\n"
                  "Reply with ONE JSON object of this shape:\n" + SCHEMA + retry + "\n" + wrap_data("incident", digest))
        payload = {"alert_event_ids": [e["event_id"] for e in alert_events],
                   "events": [e for e in s["events"]][:60]}
        index = dict(s["index"])
        try:
            out = self.llm.chat_json("reconstruct", "recon", SYSTEM_RULES, prompt, payload=payload)
            rounds = 0
            while out.get("tool_requests") and rounds < 2 and tools.remaining > 0:
                results = []
                for tr in out["tool_requests"][: tools.remaining]:
                    try:
                        res = tools.dispatch(tr["tool"], tr.get("args", {}))
                        if tr["tool"] == "get_related_logs":
                            for e in res:
                                index.setdefault(e["event_id"], {"event": e, "via": "tool:get_related_logs", "domain": None})
                        results.append({"request": tr, "result": res})
                    except (BudgetExceeded, ValueError, TypeError, KeyError) as exc:
                        results.append({"request": tr, "error": str(exc)})
                out = self.llm.chat_json("reconstruct", "recon", SYSTEM_RULES,
                                         prompt + "\n" + wrap_data("tool_results", results), payload=payload)
                rounds += 1
        except (LLMError, BudgetExceeded) as exc:
            return {"llm_out": {"verdict": "UNDETERMINED", "stages": [], "summary": "LLM reconstruction failed."},
                    "needs_human": f"LLM reconstruction failed: {exc}", "path": "llm", "index": index}
        return {"llm_out": out, "path": "llm", "index": index}

    def n_fp_check(self, s: AgentState) -> dict:
        b = s["bundle"]
        if s.get("match"):
            m: Any = s["match"]
            ctx = Ctx(self.kb, {(v["type"], v["entity"]): v for v in b["ti"]["verdicts"]}, self.cfg)
            d = decide(m, self.engine, ctx, self.cfg["agent"]["fp_min_pass"])
            judge = None
            if d.verdict == "AMBIGUOUS":
                judge = self._judge(m, d, b)
            f = playbook_findings(m, d, self.engine, judge=judge, incident_id=b["incident_id"],
                                  version=b["version"], domain=self.domain)
            path = "playbook" + ("+llm_judge" if judge else "")
            return {"decision": d, "judge": judge, "draft": f, "path": path}
        f = llm_findings(s["llm_out"], s["index"], incident_id=b["incident_id"], version=b["version"], domain=self.domain)
        self._llm_path_fp_override(f, s)
        return {"draft": f}

    def _judge(self, m, d: Decision, b: dict) -> dict:
        sides = {"attack_evidence": [{"stage": n, "what_happened": sr.desc, "events": sr.ids} for n, sr in m.stages.items()],
                 "benign_checks": [{"check": c["check"], "passed": c["passed"], "detail": c["detail"]} for c in d.checks],
                 "strong_attack_indicators": d.confirmed_by}
        prompt = ("Benign-twin rules and attack evidence disagree. Weigh both sides and decide.\n"
                  'Reply {"verdict": "TRUE_POSITIVE|FALSE_POSITIVE", "confidence": 0-1, "reasoning": "..."}\n'
                  + wrap_data("both_sides", sides))
        try:
            return self.llm.chat_json("judge_fp", "recon", SYSTEM_RULES, prompt, payload=sides)
        except LLMError as exc:
            return {"verdict": "TRUE_POSITIVE", "confidence": 0.5, "reasoning": f"judge unavailable ({exc}); defaulted to the safe side"}

    def _llm_path_fp_override(self, f: dict, s: AgentState) -> None:
        """Allowlists are authoritative even on the LLM path (the always-on FP check)."""
        b = s["bundle"]
        src = next(iter({a["event"]["src_ip"] for a in b["alerts"] if a["event"].get("src_ip")}), None)
        first = b["alerts"][0]["event"]["timestamp"]
        checks = []
        pt = self.kb.pentest(src, first)
        sc = self.kb.scanner(src)
        checks.append({"check": "in_pentest_schedule", "passed": bool(pt), "label": "FP_AUTHORIZED_PENTEST",
                       "detail": f"{src} is in pentest schedule {pt['ticket']}." if pt else f"{src} is not in the pentest schedule."})
        checks.append({"check": "src_ip_in_scanner_allowlist", "passed": bool(sc), "label": "FP_AUTHORIZED_PORT_SCANNER",
                       "detail": f"{src} is an allow-listed scanner." if sc else f"{src} is not on the scanner allowlist."})
        f["fp_assessment"]["checks"] = checks
        f["fp_assessment"]["checks_run"] = len(checks)
        f["fp_assessment"]["checks_passed"] = sum(c["passed"] for c in checks)
        if f["verdict"] == "TRUE_POSITIVE" and any(c["passed"] for c in checks):
            f["verdict"] = "FALSE_POSITIVE"
            f["fp_assessment"]["outcome"] = "accepted"
            f["fp_assessment"]["reasoning"] = "Allowlist/pentest schedule overrides the model verdict: " + \
                " ".join(c["detail"] for c in checks if c["passed"])

    def n_validate(self, s: AgentState) -> dict:
        errs = validate_findings(s["draft"], s["index"])
        upd: dict = {"errors": errs}
        if "first_pass_valid" not in s:
            upd["first_pass_valid"] = not errs
        if errs:
            upd["retries"] = s.get("retries", 0) + 1
        return upd

    def _after_validate(self, s: AgentState) -> str:
        if s["errors"] and s.get("path") == "llm" and s["retries"] <= self.max_retries and not s.get("needs_human"):
            return "llm"
        return "finalize"

    def n_finalize(self, s: AgentState) -> dict:
        f = s["draft"]
        needs = s.get("needs_human")
        if s.get("errors"):
            needs = needs or f"citations invalid after {s['retries']} attempt(s): " + "; ".join(s["errors"])
            # keep only citations that really exist
            for st in f["stages"]:
                st["evidence"] = [i for i in st["evidence"] if i in s["index"]]
            f["stages"] = [st for st in f["stages"] if st["evidence"]]
        f["needs_human"] = bool(needs)
        f["needs_human_reason"] = needs
        f["path"] = s.get("path", "playbook")
        benign = f["verdict"] == "FALSE_POSITIVE"
        keep = lambda c: c["kind"] == "confirmed" or not benign   # historical attacks do not belong in a benign report
        cols = ("id", "kind", "name", "year", "similarity", "cves", "summary", "verdict")
        f["memory_hints"] = [{k: h[k] for k in cols + ("lesson",)} for h in s.get("hints", []) if keep(h)]
        f["related_cases"] = [{k: h[k] for k in cols} for h in s.get("related", []) if keep(h)]
        f["consultations"] = s.get("consultations", [])
        f["tool_calls"] = s["tools"].log
        f["first_pass_valid"] = s.get("first_pass_valid", True)
        f["retries"] = min(s.get("retries", 0), self.max_retries)
        f["evidence_ids"] = sorted({i for st in f["stages"] for i in st["evidence"]} |
                                   {i for v in f.get("context_events", {}).values() for i in v})
        evs = [s["index"][i]["event"] for i in f["evidence_ids"] if i in s["index"]]
        f["fingerprint"] = fingerprint(f["suspected_attack_type"], f.get("playbook_stages", []), evs)
        return {"findings": f}

    # ---------------------------------------------------------------- consult support
    def analyze_slice(self, events: list[dict], ti_verdicts: list[dict]) -> dict:
        """What another owner calls through consult_agent: playbook-only analysis of a slice."""
        m = self.engine.match(events, ti_verdicts, agents={self.domain})
        if not m:
            return {"agent": self.name, "matched": False, "note": "no playbook of this domain matches the slice"}
        self.engine.build_vars(m, events)
        ctx = Ctx(self.kb, {(v["type"], v["entity"]): v for v in ti_verdicts}, self.cfg)
        d = decide(m, self.engine, ctx, self.cfg["agent"]["fp_min_pass"])
        return {"agent": self.name, "matched": True, "playbook": m.name, "attack_type": m.spec["attack_type"],
                "verdict_hint": d.verdict, "benign_checks_passed": d.n_pass,
                "stages": {n: sr.ids for n, sr in m.stages.items()},
                "note": " ".join(sr.desc for sr in m.stages.values())}
