"""Stages 10 + 12 - evidence assembly and the PoC report.

Evidence lines are pulled from the evidence index by event id (the real log line, never the
model's paraphrase). One template, no extra LLM call. Output: JSON (grader/UI), Markdown and HTML.
"""
from __future__ import annotations

import html
import re
from collections import defaultdict

from .util import hms, iso


def _ids_cell(ids: list[str], keep: int = 4) -> str:
    if len(ids) <= keep + 1:
        return ", ".join(ids)
    return ", ".join(ids[:keep]) + f" … (+{len(ids) - keep} more, see appendix)"


def assemble(findings: dict, bundle: dict, risk: dict, index: dict, *, processing: dict) -> dict:
    cited_by: dict[str, list[str]] = defaultdict(list)
    for st in findings["stages"]:
        for i in st["evidence"]:
            cited_by[i].append(st["name"])
    for label, ids in findings.get("context_events", {}).items():
        for i in ids:
            cited_by[i].append(f"context:{label}")
    alerts_by_event = {a["event"]["event_id"]: a for a in bundle["alerts"]}
    appendix = []
    for eid in sorted(cited_by, key=lambda i: (index[i]["event"]["timestamp"], i) if i in index else ("", i)):
        if eid not in index:
            continue
        e = index[eid]["event"]
        a = alerts_by_event.get(eid)
        appendix.append({
            "event_id": eid, "timestamp": e["timestamp"], "source_type": e["source_type"], "action": e["action"],
            "domain": index[eid].get("domain"), "via": index[eid]["via"], "cited_in": cited_by[eid],
            "alert_id": a["alert_id"] if a else None, "siem_rule": a["siem_rule_name"] if a else None,
            "siem_severity": a["siem_severity_label"] if a else None, "line": e["raw"],
        })
    allts = [x["timestamp"] for x in appendix]
    header = {
        "incident_id": findings["incident_id"], "version": findings["version"],
        "revision": findings["version"] > 1, "owner_agent": findings["agent"], "verdict": findings["verdict"],
        "confidence": findings["confidence"], "risk_level": risk["level"], "risk_score": risk["score"],
        "attack_type": findings["attack_type"], "title": findings["title"],
        "needs_human": findings["needs_human"], "needs_human_reason": findings["needs_human_reason"],
        "alerts": [a["alert_id"] for a in bundle["alerts"]],
        "time_range": {"start": min(allts), "end": max(allts)} if allts else {},
        "src_ip": bundle["primary_entity"],
    }
    ti = bundle["ti"]
    return {
        "header": header,
        "summary": findings["summary"],
        "timeline": [{"stage": s["name"], "time_range": s["time_range"].get("label", ""), "what_happened": s["what_happened"],
                      "event_ids": s["evidence"], "mitre": s["mitre"]} for s in findings["stages"]],
        "false_positive_assessment": findings["fp_assessment"],
        "threat_intel": {
            "available": ti["available"],
            "verdicts": [v for v in ti["verdicts"]],
            "artifacts": ti.get("artifacts", []),
            "case_memory_hints": findings.get("memory_hints", []),
            "related_reference_cases": findings.get("related_cases", []),
        },
        "impact_and_gaps": {"impact": findings["impact"], "gaps": findings["gaps"]},
        "recommended_actions": findings["recommended_actions"],
        "mitre": findings["mitre"],
        "fingerprint": findings["fingerprint"],
        "risk": risk,
        "evidence_appendix": appendix,
        "processing_path": processing,
    }


# ------------------------------------------------------------------------------------------------
def to_markdown(r: dict) -> str:
    h = r["header"]
    L: list[str] = []
    rev = f" — REVISION v{h['version']}" if h["revision"] else ""
    L.append(f"# PoC Incident Report — {h['incident_id']}{rev}\n")
    L.append(f"**{h['title']}** · source `{h['src_ip']}` · {h['time_range'].get('start', '')[:19].replace('T', ' ')} → "
             f"{h['time_range'].get('end', '')[11:19]} UTC\n")
    L.append("| Field | Value |\n|---|---|")
    L.append(f"| Incident / version | {h['incident_id']} / v{h['version']}{' (revision)' if h['revision'] else ''} |")
    L.append(f"| Owner agent | {h['owner_agent']} |")
    L.append(f"| **Verdict** | **{h['verdict'].replace('_', ' ')}** (confidence {h['confidence']:.2f}) |")
    L.append(f"| **Risk** | **{h['risk_level']}** (score {h['risk_score']}) |")
    L.append(f"| Attack type | {h['attack_type']} |")
    L.append(f"| SIEM alerts | {', '.join(h['alerts'])} |")
    if h["needs_human"]:
        L.append(f"| ⚠ Needs analyst | {h['needs_human_reason']} |")
    L.append("")
    L.append("## Summary\n")
    L.append(r["summary"] + "\n")

    L.append("## Attack timeline\n" if h["verdict"] != "FALSE_POSITIVE" else "## Activity timeline (benign)\n")
    L.append("| # | Stage | Time (UTC) | What happened | Evidence | MITRE |\n|---|---|---|---|---|---|")
    for n, t in enumerate(r["timeline"], 1):
        L.append(f"| {n} | `{t['stage']}` | {t['time_range']} | {t['what_happened']} | {_ids_cell(t['event_ids'])} | "
                 f"{', '.join(t['mitre']) or '—'} |")
    L.append("")

    fp = r["false_positive_assessment"]
    L.append("## False-positive assessment\n")
    L.append(f"- **Benign explanation considered:** {fp['benign_explanation'] or '—'}")
    outcome = {"rejected": "REJECTED — the evidence does not support it", "accepted": "ACCEPTED — the evidence supports it",
               "inconclusive": "INCONCLUSIVE"}.get(fp["outcome"], fp["outcome"])
    L.append(f"- **Outcome:** {outcome}  ({fp['checks_passed']}/{fp['checks_run']} benign-twin checks passed)")
    if fp["reasoning"]:
        L.append(f"- **Reasoning:** {fp['reasoning']}")
    if fp["checks"]:
        L.append("\n| Check | Result | Detail |\n|---|---|---|")
        for c in fp["checks"]:
            L.append(f"| `{c['check']}` | {'✔ passed' if c['passed'] else '✘ failed'} | {c['detail']} |")
    L.append("")

    ti = r["threat_intel"]
    L.append("## Threat intelligence\n")
    if not ti["available"]:
        L.append("> **Threat-intel data was unavailable for this incident; reputation verdicts are missing.**\n")
    else:
        L.append("| Entity | Type | Verdict | Category | Source / notes |\n|---|---|---|---|---|")
        for v in ti["verdicts"]:
            L.append(f"| `{v['entity']}` | {v['type']} | {v['verdict'].replace('_', ' ')} | {v.get('category', '')} | "
                     f"{', '.join(v.get('sources', []))}{' — ' + v['notes'] if v.get('notes') else ''} |")
        if ti["artifacts"]:
            L.append("\n**Suspicious artifacts in the logs:**\n")
            for a in ti["artifacts"]:
                L.append(f"- `{a['event_id']}` — {a['desc']} ({', '.join(a['mitre'])})")
    if ti["case_memory_hints"] or ti["related_reference_cases"]:
        L.append("\n**Similar historical attacks / CVEs (reference memory — context only, never the verdict):**\n")
        for c in ti["case_memory_hints"] + ti["related_reference_cases"]:
            cve = f" · {', '.join(c['cves'])}" if c.get("cves") else ""
            tag = f"**SOC-confirmed {c['verdict'].replace('_', ' ')}** — " if c["kind"] == "confirmed" else ""
            L.append(f"- {tag}**{c['name']}** ({c.get('year') or 'n/a'}{cve}) — structural similarity {c['similarity']:.2f}. {c['summary']}")
    L.append("")

    ig = r["impact_and_gaps"]
    L.append("## Impact and gaps\n")
    L.append("**Confirmed by the evidence:**\n")
    for x in ig["impact"]:
        L.append(f"- {x}")
    L.append("\n**What the evidence does not show:**\n")
    for x in ig["gaps"]:
        L.append(f"- {x}")
    L.append("")

    L.append("## Recommended actions\n")
    for n, a in enumerate(r["recommended_actions"], 1):
        L.append(f"{n}. {a}")
    L.append("")

    rk = r["risk"]
    L.append("## Risk scoring\n")
    L.append(f"`risk = base + success_bonus + TI_score + asset_criticality − FP_evidence` → **{rk['formula']}** → **{rk['level']}**"
             + (" (capped to LOW by the false-positive verdict)" if rk["capped_low_for_false_positive"] else "") + "\n")
    L.append("| Term | Value | Why |\n|---|---|---|")
    for k, t in rk["terms"].items():
        L.append(f"| {k} | {t['value']:+d} | {t['why']} |")
    L.append("")

    L.append("## Evidence appendix\n")
    L.append("Real log lines, pulled by event id.\n")
    for a in r["evidence_appendix"]:
        tag = f" · alert {a['alert_id']} · rule “{a['siem_rule']}” ({a['siem_severity']})" if a["alert_id"] else " · log store"
        L.append(f"**{a['event_id']}** · {a['timestamp'][:23]} · {a['source_type']} {a['action']}{tag} · cited in: "
                 f"{', '.join(a['cited_in'])}")
        L.append(f"```\n{a['line']}\n```")
    L.append("")

    p = r["processing_path"]
    L.append("## Processing path\n")
    L.append(f"- **Path:** {p['path']}" + (f" (playbook `{p['playbook']}`)" if p.get("playbook") else ""))
    L.append(f"- **Owner selection:** {p['owner_reason']}; dispatched because: {'; '.join(p['ready_reasons']) or 'quiet-period timer'}")
    L.append(f"- **Tool calls:** {len(p['tool_calls'])} — " + (", ".join(f"{t['tool']}({list(t['args'].values())[0] if t['args'] else ''})" for t in p['tool_calls']) or "none"))
    for c in p.get("consultations", []):
        L.append(f"- **Consulted {c['domain']} agent:** {'matched ' + c.get('playbook', '') + ' → ' + c.get('verdict_hint', '') if c.get('matched') else c.get('note', '')}")
    L.append(f"- **Citation validation:** first pass {'ok' if p['first_pass_valid'] else 'failed'}; retries {p['retries']}")
    L.append(f"- **LLM calls:** {len(p['llm_calls'])}" + (f" ({', '.join(c['task'] for c in p['llm_calls'])})" if p["llm_calls"] else " (none — playbook path)"))
    L.append(f"- **Dispatched at (simulated):** {p['dispatched_at']}")
    L.append("\n*Data is synthetic: results demonstrate orchestration and reasoning logic, not detection of unseen real-world attacks. A SOC analyst makes the final call.*")
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------------------------------------
_CSS = """body{font:15px/1.5 system-ui,Segoe UI,Arial;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1d2330}
h1{border-bottom:3px solid #1d2330;padding-bottom:.3rem}h2{margin-top:2rem;border-bottom:1px solid #ccd}
table{border-collapse:collapse;width:100%;margin:.6rem 0}td,th{border:1px solid #ccd;padding:.35rem .6rem;vertical-align:top;text-align:left}
th{background:#eef}pre{background:#f5f6fa;padding:.5rem;overflow:auto;border-left:3px solid #99a;font-size:12px}
code{background:#f0f1f7;padding:0 .25rem;border-radius:3px}blockquote{border-left:4px solid #e0a000;background:#fff7e0;margin:.5rem 0;padding:.4rem .8rem}"""


def _inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return re.sub(r"\*(.+?)\*", r"<i>\1</i>", s)


def to_html(md: str, title: str) -> str:
    out, in_table, in_code, in_ul, in_ol = [], False, False, False, False
    lines = md.split("\n")
    def close_lists():
        nonlocal in_ul, in_ol
        if in_ul: out.append("</ul>"); in_ul = False
        if in_ol: out.append("</ol>"); in_ol = False
    for ln in lines:
        if ln.startswith("```"):
            close_lists()
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(ln)); continue
        if ln.startswith("|"):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if not in_table:
                out.append("<table>"); in_table = True
                out.append("<tr>" + "".join(f"<th>{_inline(c)}</th>" for c in cells) + "</tr>")
            else:
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>"); in_table = False
        if ln.startswith("# "): close_lists(); out.append(f"<h1>{_inline(ln[2:])}</h1>")
        elif ln.startswith("## "): close_lists(); out.append(f"<h2>{_inline(ln[3:])}</h2>")
        elif ln.startswith("> "): close_lists(); out.append(f"<blockquote>{_inline(ln[2:])}</blockquote>")
        elif ln.startswith("- "):
            if not in_ul: close_lists(); out.append("<ul>"); in_ul = True
            out.append(f"<li>{_inline(ln[2:])}</li>")
        elif re.match(r"\d+\. ", ln):
            if not in_ol: close_lists(); out.append("<ol>"); in_ol = True
            out.append(f"<li>{_inline(re.sub(r'^\d+\. ', '', ln))}</li>")
        elif ln.strip() == "":
            close_lists()
        else:
            close_lists(); out.append(f"<p>{_inline(ln)}</p>")
    if in_table: out.append("</table>")
    close_lists()
    return f"<!doctype html><meta charset=utf-8><title>{html.escape(title)}</title><style>{_CSS}</style>\n" + "\n".join(out)
