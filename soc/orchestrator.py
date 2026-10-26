"""The orchestrator: deterministic code around the agents.

  ingest(alert)  Stage 3 validate/dedupe -> 4 classify -> 5 group -> 6 ready check
  tick(now)      background sweep: dispatch quiet incidents (Stages 7-8) -> agent (9) -> 10-12 report
Everything here is code and config; the LLM is only reachable through classifier / agent fallbacks.
The ground-truth files are never opened by this module.
"""
from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from .adapter import LogStore
from .agents.engine import PlaybookEngine
from .agents.owner import OwnerAgent
from .classify import Classifier
from .incidents import Incident, IncidentManager
from .llm import LLM
from .memory import CaseMemory
from .readiness import owner_for, ready_reasons
from .report import assemble, to_html, to_markdown
from .risk import score_risk
from .store import StateStore
from .ti import KnowledgeBase, ThreatIntelAgent
from .tools import ToolBox
from .util import Config, iso, jdump, parse_ts, resolve
from .validate import Validator


class Orchestrator:
    def __init__(self, cfg: Config, run_dir: Path, *, llm: LLM, logstore: LogStore,
                 kb: KnowledgeBase | None = None, memory_path: Path | None = None):
        self.cfg, self.run_dir, self.llm, self.logstore = cfg, run_dir, llm, logstore
        run_dir.mkdir(parents=True, exist_ok=True)
        self.kb = kb or KnowledgeBase(resolve(cfg, "knowledge_dir"))
        self.validator = Validator(cfg)
        self.classifier = Classifier(cfg, llm)
        self.manager = IncidentManager(cfg)
        self.store = StateStore(run_dir / "state.db")
        self.ti = ThreatIntelAgent(self.kb, cfg["ti"]["cache_hours"])
        self.engine = PlaybookEngine(cfg, self.kb)
        self.memory = CaseMemory(memory_path or (resolve(cfg, "state_dir") / "case_memory.db"), self.kb.reference)
        self.agents = {d: OwnerAgent(d, cfg, self.engine, self.kb, llm, self.memory) for d in ("network", "app_endpoint")}
        self.clock: datetime | None = None
        self.metrics: Counter = Counter()
        self.reports: list[dict] = []
        self.timings: list[dict] = []
        self.dispatch_log: list[dict] = []
        self._domain_by_source = {st: d for d, p in cfg["routing_patterns"].items() for st in p["source_types"]}

    # ------------------------------------------------------------------ Stages 3-6
    def ingest(self, alert: dict, arrival: datetime | None = None) -> None:
        now = arrival or parse_ts(alert["alert_time"])
        self.clock = max(self.clock, now) if self.clock else now
        self.metrics["received"] += 1
        ok, reason = self.validator.check(alert)
        if not ok:
            if reason == "duplicate":
                self.metrics["duplicates_dropped"] += 1
            else:
                self.metrics["dead_lettered"] += 1
                self.store.dead_letter(alert, reason)
            return
        cls = self.classifier.classify(alert)
        if cls["domain"] is None:
            self.metrics["human_review"] += 1
            self.store.human_review(alert, cls["reason"])
            return
        inc, created, revision = self.manager.attach_or_open(alert, cls["domain"], now)
        self.metrics["alerts_grouped"] += 1
        self.metrics["revisions_triggered"] += int(revision)
        self._check_ready(inc, now)
        self.store.save_incident(inc.to_dict())

    def _entity(self, inc: Incident) -> tuple[str, str]:
        kind, _, value = inc.key.partition(":")
        return {"src_ip": "ip", "user": "user", "host": "host"}.get(kind, "ip"), value

    def _visible(self, inc: Incident, now: datetime) -> list[dict]:
        """Runtime events for this incident's entity that exist at 'now' (never the future)."""
        kind, value = self._entity(inc)
        lo = inc.first_seen - timedelta(minutes=self.cfg["dispatch"]["log_lookback_min"])
        return self.logstore.query(value, lo, now, kind=kind, as_of=now)

    def _check_ready(self, inc: Incident, now: datetime) -> None:
        if inc.status not in ("OPEN", "READY") or inc.ready_reasons and inc.status == "READY":
            return
        reasons = ready_reasons(inc, self.cfg, self._visible(inc, now))
        if reasons:
            inc.ready_reasons, inc.status = reasons, "READY"
            inc.ready_at = inc.ready_at or now

    # ------------------------------------------------------------------ sweep + dispatch
    def tick(self, now: datetime) -> None:
        self.clock = now
        d = self.cfg["dispatch"]
        for inc in list(self.manager.incidents.values()):
            if inc.status == "OPEN":
                self._check_ready(inc, now)
            if inc.status in ("OPEN", "READY"):
                quiet = (now - inc.last_attach).total_seconds()
                held = (now - inc.hold_start).total_seconds()
                need = d["debounce_s"] if inc.status == "READY" else d["idle_s"]
                if quiet >= need or held >= d["max_wait_s"]:
                    self._dispatch(inc, now)
        self.manager.close_stale(now)

    def pending(self) -> int:
        return sum(1 for i in self.manager.incidents.values() if i.status in ("OPEN", "READY"))

    def flush(self) -> None:
        """End of stream: keep sweeping until every incident has been dispatched."""
        step = timedelta(seconds=self.cfg["dispatch"]["sweep_interval_s"])
        t = self.clock
        for _ in range(10_000):
            if not self.pending():
                break
            t += step
            self.tick(t)

    def _dispatch(self, inc: Incident, now: datetime) -> None:
        cfg = self.cfg
        inc.status, inc.dispatched_at = "DISPATCHED", now
        inc.dispatched_versions.append(inc.version)
        t_wall = time.time()
        llm_before = len(self.llm.calls)
        domain, rank, owner = owner_for(inc, cfg)
        kind, value = self._entity(inc)
        alerts = sorted(inc.alerts, key=lambda a: (a["event"]["timestamp"], a["alert_id"]))
        alert_events = [a["event"] for a in alerts]
        events = {e["event_id"]: e for e in self._visible(inc, now)}
        events.update({e["event_id"]: e for e in alert_events})
        ev_list = sorted(events.values(), key=lambda e: (e["timestamp"], e["event_id"]))
        ti = self.ti.enrich(ev_list, as_of=now)
        bundle = {
            "incident_id": inc.incident_id, "version": inc.version, "domains": sorted(inc.domains),
            "alerts": alerts, "alert_event_ids": [e["event_id"] for e in alert_events], "events": ev_list,
            "event_domain": {e["event_id"]: self._domain_by_source.get(e["source_type"]) for e in ev_list},
            "entities": sorted(inc.entities), "ready_reasons": inc.ready_reasons, "ti": ti,
            "primary_entity": value, "owner": owner, "dispatched_at": iso(now),
        }

        def consult(dom: str, ids: list[str]) -> dict:
            sl = [events[i] for i in ids if i in events]
            return self.agents[dom].analyze_slice(sl, ti["verdicts"])

        tools = ToolBox(logstore=self.logstore, ti=self.ti, kb=self.kb, engine=self.engine, consult=consult,
                        as_of=now, max_calls=cfg["agent"]["tool_budget_calls"],
                        max_seconds=cfg["agent"]["tool_budget_seconds"])
        findings, index = self.agents[domain].run(bundle, tools)
        risk = score_risk(findings, bundle, index, self.kb, cfg)
        wall = time.time() - t_wall
        processing = {
            "path": findings["path"], "playbook": findings["playbook"], "tool_calls": findings["tool_calls"],
            "retries": findings["retries"], "first_pass_valid": findings["first_pass_valid"],
            "llm_calls": self.llm.calls[llm_before:], "consultations": findings["consultations"],
            "ready_reasons": inc.ready_reasons, "owner_reason": owner["reason"], "dispatched_at": iso(now),
            "wall_seconds": round(wall, 3),
        }
        report = assemble(findings, bundle, risk, index, processing=processing)
        self._write(report)
        self.reports.append(report)
        self.store.save_report(report)
        self.store.save_incident(inc.to_dict())
        self.metrics["dispatches"] += 1
        self.timings.append({"incident_id": inc.incident_id, "version": inc.version, "wall_seconds": wall})

    def _write(self, report: dict) -> None:
        h = report["header"]
        stem = f"{h['incident_id']}_v{h['version']}"
        out = self.run_dir / "reports"
        jdump(report, out / f"{stem}.json")
        md = to_markdown(report)
        (out / f"{stem}.md").write_text(md, encoding="utf-8")
        (out / f"{stem}.html").write_text(to_html(md, f"{stem} PoC report"), encoding="utf-8")

    # ------------------------------------------------------------------ results for the grader / index
    def final_reports(self) -> dict[str, dict]:
        """Highest version per incident."""
        best: dict[str, dict] = {}
        for r in self.reports:
            h = r["header"]
            if h["incident_id"] not in best or h["version"] > best[h["incident_id"]]["header"]["version"]:
                best[h["incident_id"]] = r
        return best

    def results(self) -> list[dict]:
        out = []
        for iid, r in sorted(self.final_reports().items()):
            h, inc = r["header"], self.manager.incidents[iid]
            out.append({
                "incident_id": iid, "version": h["version"], "alert_ids": inc.alert_ids,
                "owner_domain": next(d for d, a in {"network": "network_agent", "app_endpoint": "app_endpoint_agent"}.items() if a == h["owner_agent"]),
                "verdict": h["verdict"], "risk_level": h["risk_level"], "risk_score": h["risk_score"],
                "attack_type": h["attack_type"], "stages": [t["stage"] for t in r["timeline"]],
                "path": r["processing_path"]["path"], "first_pass_valid": r["processing_path"]["first_pass_valid"],
                "needs_human": h["needs_human"], "confidence": h["confidence"],
                "wall_seconds": r["processing_path"]["wall_seconds"],
            })
        return out

    def write_index(self) -> None:
        res = self.results()
        jdump({"metrics": dict(self.metrics), "classifier": self.classifier.stats, "ti": self.ti.stats,
               "dead_letter": self.store.count("dead_letter"), "human_review": self.store.count("human_review"),
               "llm_provider": self.llm.name, "llm_calls": len(self.llm.calls), "incidents": res},
              self.run_dir / "results.json")
        L = ["# Run index\n", f"LLM provider: **{self.llm.name}** · incidents: **{len(res)}** · reports: **{len(self.reports)}**\n",
             "| Incident | v | Owner | Verdict | Risk | Attack type | Stages | Path |\n|---|---|---|---|---|---|---|---|"]
        for r in res:
            L.append(f"| [{r['incident_id']}](reports/{r['incident_id']}_v{r['version']}.md) | {r['version']} | {r['owner_domain']} | "
                     f"{r['verdict']} | {r['risk_level']} | {r['attack_type']} | {' → '.join(r['stages'])} | {r['path']} |")
        (self.run_dir / "index.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    def close(self) -> None:
        self.store.close()
        self.memory.close()
