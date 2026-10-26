"""End-to-end: the full replay of the supplied dataset graded against the answer key."""
from __future__ import annotations

import json
import re
from pathlib import Path

from soc.grader import grade

ROOT = Path(__file__).resolve().parent.parent


def test_validation_accepts_every_dataset_alert(full_run):
    orch, _ = full_run
    assert orch.store.count("dead_letter") == 0
    assert orch.metrics["received"] == 103


def test_every_alert_became_exactly_one_incident_member(full_run):
    orch, _ = full_run
    ids = [a for i in orch.manager.incidents.values() for a in i.alert_ids]
    assert len(ids) == len(set(ids)) == 103


def test_graded_against_ground_truth(cfg, full_run):
    _, run_dir = full_run
    ev = grade(cfg, run_dir)
    assert ev["grouping"]["exact_incident_match"] == 1.0
    assert ev["routing_accuracy"] == 1.0
    fp = ev["fp_detection"]
    assert fp["fp_precision"] == 1.0 and fp["fp_recall"] == 1.0
    assert fp["verdict_accuracy"] == 1.0
    assert ev["risk_level_accuracy"] == 1.0
    assert ev["stage_accuracy_exact_sequence"] == 1.0
    assert ev["attack_type_accuracy"] == 1.0
    assert ev["citation_validity_first_pass"] == 1.0
    assert ev["needs_human"] == 0


def test_path_mix_is_playbook_dominated(cfg, full_run):
    _, run_dir = full_run
    ev = json.loads((run_dir / "evaluation.json").read_text(encoding="utf-8"))
    assert ev["path_mix"].get("playbook", 0) >= 0.9
    assert ev["path_mix"].get("llm", 0) == 3 / 83 or abs(ev["path_mix"].get("llm", 0) - 3 / 83) < 1e-3


def test_owner_agent_matches_playbook_domain(full_run):
    orch, _ = full_run
    for r in orch.reports:
        pb = r["processing_path"]["playbook"]
        if pb:
            want = orch.engine.get(pb)["agent"]
            got = "network" if r["header"]["owner_agent"] == "network_agent" else "app_endpoint"
            assert got == want, (r["header"]["incident_id"], pb)


def test_reports_have_every_section_and_valid_citations(full_run):
    orch, _ = full_run
    for r in orch.reports:
        for key in ("header", "summary", "timeline", "false_positive_assessment", "threat_intel",
                    "impact_and_gaps", "recommended_actions", "risk", "evidence_appendix", "processing_path"):
            assert key in r, key
        appendix = {a["event_id"] for a in r["evidence_appendix"]}
        for t in r["timeline"]:
            assert t["event_ids"], "every stage must cite evidence"
            assert set(t["event_ids"]) <= appendix
            assert all(i in orch.logstore.events for i in t["event_ids"])
        # the appendix line is the real log line, not a paraphrase
        for a in r["evidence_appendix"]:
            assert a["line"] == orch.logstore.events[a["event_id"]]["raw"]


def test_no_unrendered_template_placeholders(full_run):
    _, run_dir = full_run
    for f in (run_dir / "reports").glob("*.md"):
        text = f.read_text(encoding="utf-8")
        assert "⟨?⟩" not in text, f.name
        assert not re.search(r"(?<![\w$])\{[a-z_0-9]+\}", re.sub(r"```.*?```", "", text, flags=re.S)), f.name


def test_true_positive_reports_explain_impact_and_actions(full_run):
    orch, _ = full_run
    tps = [r for r in orch.reports if r["header"]["verdict"] == "TRUE_POSITIVE"]
    assert len(tps) == 58
    for r in tps:
        assert r["impact_and_gaps"]["impact"] and r["impact_and_gaps"]["gaps"]
        assert len(r["recommended_actions"]) >= 2
        assert r["header"]["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_false_positive_reports_name_the_benign_explanation(full_run):
    orch, _ = full_run
    fps = [r for r in orch.reports if r["header"]["verdict"] == "FALSE_POSITIVE"]
    assert len(fps) == 25
    for r in fps:
        fa = r["false_positive_assessment"]
        assert fa["outcome"] == "accepted" and fa["checks_passed"] >= 1 and fa["fp_label"]
        assert r["header"]["risk_level"] == "LOW"
        assert not r["threat_intel"]["related_reference_cases"]     # no "similar attacks" on a benign verdict


def test_multi_stage_chain_is_fully_evidenced(full_run):
    orch, _ = full_run
    ms = [r for r in orch.reports if r["header"]["attack_type"] == "MULTI_STAGE_ATTACK"]
    assert len(ms) == 5
    for r in ms:
        assert [t["stage"] for t in r["timeline"]] == ["credential_attack", "suspicious_download", "endpoint_execution"]
        assert r["header"]["risk_level"] == "CRITICAL"
        assert r["processing_path"]["consultations"], "owner should consult the network agent for the auth slice"
        assert len(r["processing_path"]["tool_calls"]) <= 5


def test_ground_truth_files_are_only_opened_by_the_grader():
    """Principle 5: the answer key stays outside the pipeline."""
    offenders = []
    for py in (ROOT / "soc").rglob("*.py"):
        if py.name in ("grader.py",):
            continue
        txt = py.read_text(encoding="utf-8")
        if re.search(r"Ground_Truth|grader_only|truth_label|expected_owner", txt):
            offenders.append(py.name)
    assert offenders == []


def test_alert_records_carry_no_label(runtime):
    _, alerts = runtime
    banned = {"truth_label", "incident_id", "expected_owner", "attack_type", "expected_stages"}
    for a in alerts:
        assert not banned & set(a) and not banned & set(a["event"])


def test_malware_reports_do_not_overclaim_the_download_to_drop_link(full_run):
    orch, _ = full_run
    mw = [r for r in orch.reports if r["header"]["attack_type"] == "MALWARE_DOWNLOAD_EXECUTION"]
    assert len(mw) == 5
    for r in mw:
        impact = " ".join(r["impact_and_gaps"]["impact"])
        gaps = " ".join(r["impact_and_gaps"]["gaps"])
        assert "equals the hash of the file the browser wrote to disk" in impact   # drop -> exec is proven by hash
        assert "not by content" in gaps                                              # download -> drop is only timing/user
