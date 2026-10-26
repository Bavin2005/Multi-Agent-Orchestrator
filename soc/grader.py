"""Evaluation. This is the ONLY module that opens the ground-truth files.

Compares a finished run (runs/<id>/results.json) with the answer key:
grouping, routing, FP detection precision/recall, risk, stages, attack type, citation validity,
path mix and time per incident. Writes evaluation.json + evaluation.md next to the run.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from .util import Config, jdump, resolve

OWNER_MAP = {"Network Security Agent": "network", "Application + Endpoint Agent": "app_endpoint"}
STAGE_ARROW = " → "


def _read(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def grade(cfg: Config, run_dir: Path, quiet: bool = False) -> dict:
    data = Path(cfg["_root"]) / "data"
    alert_gt = _read(data / cfg["grader_only"]["alert_ground_truth"])
    inc_gt = {r["incident_id"]: r for r in _read(data / cfg["grader_only"]["incident_ground_truth"])}
    res = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    incidents = res["incidents"]

    gt_alerts: dict[str, set] = defaultdict(set)
    alert_to_gt: dict[str, str] = {}
    for r in alert_gt:
        gt_alerts[r["incident_id"]].add(r["alert_id"])
        alert_to_gt[r["alert_id"]] = r["incident_id"]

    rows = []
    for inc in incidents:
        votes = Counter(alert_to_gt.get(a) for a in inc["alert_ids"])
        gid = votes.most_common(1)[0][0]
        g = inc_gt[gid]
        exp_stages = g["expected_stages"].split(STAGE_ARROW)
        rows.append({
            "orc": inc["incident_id"], "gt": gid, "gt_type": g["attack_type"],
            "group_exact": set(inc["alert_ids"]) == gt_alerts[gid],
            "owner_ok": inc["owner_domain"] == OWNER_MAP.get(g["expected_owner"]),
            "verdict": inc["verdict"], "truth": g["truth_label"], "verdict_ok": inc["verdict"] == g["truth_label"],
            "risk": inc["risk_level"], "exp_risk": g["expected_final_risk"], "risk_ok": inc["risk_level"] == g["expected_final_risk"],
            "stages": inc["stages"], "exp_stages": exp_stages,
            "stages_ok": inc["stages"] == exp_stages,
            "type": inc["attack_type"], "type_ok": inc["attack_type"] == g["attack_type"],
            "path": inc["path"], "first_pass_valid": inc["first_pass_valid"], "wall": inc["wall_seconds"],
            "needs_human": inc["needs_human"], "version": inc["version"],
        })

    n = len(rows)
    def rate(k): return round(sum(r[k] for r in rows) / n, 4) if n else 0.0

    tp = sum(r["truth"] == "FALSE_POSITIVE" and r["verdict"] == "FALSE_POSITIVE" for r in rows)
    fp_pred = sum(r["verdict"] == "FALSE_POSITIVE" for r in rows)
    fp_true = sum(r["truth"] == "FALSE_POSITIVE" for r in rows)
    att_tp = sum(r["truth"] == "TRUE_POSITIVE" and r["verdict"] == "TRUE_POSITIVE" for r in rows)
    att_pred = sum(r["verdict"] == "TRUE_POSITIVE" for r in rows)
    att_true = sum(r["truth"] == "TRUE_POSITIVE" for r in rows)

    pairs_gt = {(a, b) for s in gt_alerts.values() for a in s for b in s if a < b}
    pairs_pred = {(a, b) for i in incidents for a in i["alert_ids"] for b in i["alert_ids"] if a < b}
    paths = Counter(r["path"] for r in rows)
    manual = cfg["evaluation"]["manual_minutes_per_incident"]
    out = {
        "run": run_dir.name, "incidents_graded": n, "ground_truth_incidents_with_alerts": len(gt_alerts),
        "grouping": {"exact_incident_match": rate("group_exact"),
                     "pairwise_precision": round(len(pairs_gt & pairs_pred) / len(pairs_pred), 4) if pairs_pred else 0,
                     "pairwise_recall": round(len(pairs_gt & pairs_pred) / len(pairs_gt), 4) if pairs_gt else 0},
        "routing_accuracy": rate("owner_ok"),
        "fp_detection": {"fp_precision": round(tp / fp_pred, 4) if fp_pred else None,
                         "fp_recall": round(tp / fp_true, 4) if fp_true else None,
                         "attack_precision": round(att_tp / att_pred, 4) if att_pred else None,
                         "attack_recall": round(att_tp / att_true, 4) if att_true else None,
                         "verdict_accuracy": rate("verdict_ok"),
                         "confusion": {"FP_as_FP": tp, "FP_as_attack": fp_true - tp, "attack_as_attack": att_tp,
                                       "attack_as_FP": att_true - att_tp}},
        "risk_level_accuracy": rate("risk_ok"),
        "stage_accuracy_exact_sequence": rate("stages_ok"),
        "attack_type_accuracy": rate("type_ok"),
        "citation_validity_first_pass": rate("first_pass_valid"),
        "needs_human": sum(r["needs_human"] for r in rows),
        "path_mix": {k: round(v / n, 4) for k, v in paths.items()},
        "revisions": sum(r["version"] > 1 for r in rows),
        "time_per_incident": {"pipeline_seconds_mean": round(sum(r["wall"] for r in rows) / n, 3) if n else 0,
                              "manual_estimate_minutes": manual,
                              "note": "pipeline time excludes simulated quiet-period waits (event time)"},
        "synthetic_data_notice": "Data is synthetic: results demonstrate the orchestration and reasoning logic, "
                                 "not detection of unseen real-world attacks.",
        "mismatches": [r for r in rows if not (r["group_exact"] and r["owner_ok"] and r["verdict_ok"] and r["risk_ok"]
                                               and r["stages_ok"] and r["type_ok"])],
    }
    jdump(out, run_dir / "evaluation.json")
    (run_dir / "evaluation.md").write_text(_md(out), encoding="utf-8")
    if not quiet:
        print(_md(out))
    return out


def _md(o: dict) -> str:
    pct = lambda x: "n/a" if x is None else f"{x * 100:.1f}%"
    fp = o["fp_detection"]
    L = [f"# Evaluation — {o['run']}\n", f"Incidents graded: **{o['incidents_graded']}** (ground-truth incidents with alerts: {o['ground_truth_incidents_with_alerts']})\n",
         "| Metric | Result |\n|---|---|",
         f"| Grouping — exact incident match | {pct(o['grouping']['exact_incident_match'])} |",
         f"| Grouping — pairwise precision / recall | {pct(o['grouping']['pairwise_precision'])} / {pct(o['grouping']['pairwise_recall'])} |",
         f"| Routing accuracy (owner agent) | {pct(o['routing_accuracy'])} |",
         f"| **FP detection — precision / recall (false-positive class)** | **{pct(fp['fp_precision'])} / {pct(fp['fp_recall'])}** |",
         f"| Attack class — precision / recall | {pct(fp['attack_precision'])} / {pct(fp['attack_recall'])} |",
         f"| Verdict accuracy | {pct(fp['verdict_accuracy'])} |",
         f"| Risk-level accuracy | {pct(o['risk_level_accuracy'])} |",
         f"| Stage accuracy (exact sequence) | {pct(o['stage_accuracy_exact_sequence'])} |",
         f"| Attack-type accuracy | {pct(o['attack_type_accuracy'])} |",
         f"| Citation validity (first pass) | {pct(o['citation_validity_first_pass'])} |",
         f"| Path mix | {', '.join(f'{k}: {pct(v)}' for k, v in o['path_mix'].items())} |",
         f"| Needs analyst / revisions | {o['needs_human']} / {o['revisions']} |",
         f"| Time per incident | {o['time_per_incident']['pipeline_seconds_mean']}s pipeline vs ~{o['time_per_incident']['manual_estimate_minutes']} min manual |",
         f"\nConfusion: {fp['confusion']}\n"]
    if o["mismatches"]:
        L.append("## Mismatches\n\n| Orc | GT | Type (exp) | Verdict (exp) | Risk (exp) | Owner | Stages | Group |\n|---|---|---|---|---|---|---|---|")
        for r in o["mismatches"]:
            L.append(f"| {r['orc']} | {r['gt']} | {r['type']} ({r['gt_type']}) | {r['verdict']} ({r['truth']}) | {r['risk']} ({r['exp_risk']}) | "
                     f"{'ok' if r['owner_ok'] else 'WRONG'} | {' → '.join(r['stages'])} (exp {' → '.join(r['exp_stages'])}) | {'ok' if r['group_exact'] else 'WRONG'} |")
    else:
        L.append("**No mismatches.**")
    L.append(f"\n*{o['synthetic_data_notice']}*")
    return "\n".join(L) + "\n"
