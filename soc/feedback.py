"""Stage 13 - SOC verdict and feedback.

The analyst marks a report CONFIRMED_ATTACK / CONFIRMED_FALSE_POSITIVE / NEEDS_INVESTIGATION.
Only confirmed reports feed back:
  * case memory - the incident's fingerprint, verdict and stage list (used as a *hint* later)
  * allowlists  - a confirmed false positive may add its source (scanner / pentest window /
                  service-account IP) - only with --approve-allowlist
  * playbooks   - repeated LLM-path cases are a signal to write a new playbook by hand
Unconfirmed agent verdicts are never stored, so one wrong verdict cannot spread.
"""
from __future__ import annotations

import json
import shutil
from datetime import timedelta
from pathlib import Path

from .memory import CaseMemory
from .ti import KnowledgeBase
from .util import Config, iso, jdump, parse_ts, resolve


def _latest_report(run_dir: Path, incident_id: str) -> dict:
    files = sorted((run_dir / "reports").glob(f"{incident_id}_v*.json"),
                   key=lambda p: int(p.stem.rsplit("_v", 1)[1]))
    if not files:
        raise SystemExit(f"no report for {incident_id} in {run_dir}")
    return json.loads(files[-1].read_text(encoding="utf-8"))


def record_verdict(cfg: Config, run_dir: Path, incident_id: str, verdict: str, *, note: str = "",
                   approve_allowlist: bool = False, quiet: bool = False) -> dict:
    report = _latest_report(run_dir, incident_id)
    h = report["header"]
    entry = {"incident_id": incident_id, "report_version": h["version"], "agent_verdict": h["verdict"],
             "analyst_verdict": verdict, "note": note}
    out: dict = {"recorded": entry, "memory": None, "allowlist": None}
    vfile = run_dir / "verdicts.json"
    allv = json.loads(vfile.read_text(encoding="utf-8")) if vfile.exists() else []
    allv.append(entry)
    jdump(allv, vfile)

    if verdict == "NEEDS_INVESTIGATION":
        out["memory"] = "not stored (only confirmed verdicts feed back)"
    else:
        kb = KnowledgeBase(resolve(cfg, "knowledge_dir"))
        mem = CaseMemory(resolve(cfg, "state_dir") / "case_memory.db", kb.reference)
        truth = "TRUE_POSITIVE" if verdict == "CONFIRMED_ATTACK" else "FALSE_POSITIVE"
        mem.add_confirmed(f"CONF-{run_dir.name}-{incident_id}", f"{h['title']} ({h['src_ip']})",
                          report["fingerprint"], truth, report["summary"])
        mem.close()
        out["memory"] = f"stored as confirmed {truth} case"
        if verdict == "CONFIRMED_FALSE_POSITIVE":
            out["allowlist"] = _allowlist(cfg, report, incident_id, approve_allowlist)
    if not quiet:
        print(json.dumps(out, indent=2))
    return out


def _allowlist(cfg: Config, report: dict, incident_id: str, approved: bool) -> str:
    label = report["false_positive_assessment"].get("fp_label")
    h = report["header"]
    src = h["src_ip"]
    kdir = resolve(cfg, "knowledge_dir")
    if label not in ("FP_AUTHORIZED_PORT_SCANNER", "FP_AUTHORIZED_PENTEST", "FP_PASSWORD_MISTYPING"):
        return "no allowlist change applies to this false-positive type"
    proposal = {"FP_AUTHORIZED_PORT_SCANNER": f"add {src} to internal_scanners",
                "FP_AUTHORIZED_PENTEST": f"add a pentest window for {src}",
                "FP_PASSWORD_MISTYPING": f"add {src} to the known source IPs of the account"}[label]
    if not approved:
        return f"PROPOSED (not applied; re-run with --approve-allowlist): {proposal}"
    if label == "FP_PASSWORD_MISTYPING":
        path = kdir / "assets.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        user = report["timeline"][0].get("user") or next(
            (t["what_happened"].split("'")[1] for t in report["timeline"] if "'" in t["what_happened"]), None)
        if not user or user not in data["users"]:
            return "account not found in inventory; nothing changed"
        shutil.copy(path, path.with_suffix(".json.bak"))
        if src not in data["users"][user]["known_ips"]:
            data["users"][user]["known_ips"].append(src)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return f"APPLIED: {src} added to known IPs of {user}"
    path = kdir / "allowlists.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    shutil.copy(path, path.with_suffix(".json.bak"))
    if label == "FP_AUTHORIZED_PORT_SCANNER":
        data["internal_scanners"].append({"src_ip": src, "tool": "analyst-approved", "owner": "soc", "service_account": None})
    else:
        t0, t1 = parse_ts(h["time_range"]["start"]), parse_ts(h["time_range"]["end"])
        data["pentest_schedule"].append({"ticket": f"SOC-APPROVED-{incident_id}", "src_ip": src,
                                         "window_start": iso(t0 - timedelta(minutes=10)),
                                         "window_end": iso(t1 + timedelta(minutes=10)),
                                         "scope": "analyst-approved", "approved_by": "soc-analyst"})
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return f"APPLIED: {src} added ({label})"
