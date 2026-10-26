"""Stage 13 feedback, risk formula, case memory, and the LLM client."""
from __future__ import annotations

import copy
import json
import sys
import types
from pathlib import Path

import pytest

from soc.feedback import record_verdict
from soc.llm import LLMError, MockLLM, OpenAICompatLLM, extract_json, make_llm
from soc.memory import CaseMemory, similarity
from soc.replay import replay
from soc.risk import level_for, score_risk
from soc.ti import KnowledgeBase

from conftest import brute_force_events, mk_alert, mk_event, mk_orch


# ------------------------------------------------------------------------------- risk formula
def test_risk_levels_follow_the_cutoffs(cfg):
    L = cfg["risk"]["levels"]
    assert [level_for(s, L) for s in (-5, 3, 4, 7, 8, 10, 11, 20)] == \
        ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


def _findings(verdict, atype, passed, stages):
    return {"verdict": verdict, "attack_type": atype, "suspected_attack_type": atype, "stages": stages,
            "fp_assessment": {"checks_passed": passed}}


def test_risk_terms_and_false_positive_cap(cfg):
    kb = KnowledgeBase(Path(cfg["_root"]) / "knowledge")
    ex = mk_event("R1", "PROCESS_EXECUTION", "ENDPOINT", host="HOST-001", process_name="x.exe")
    index = {"R1": {"event": ex, "via": "alert", "domain": "app_endpoint"}}
    bundle = {"alerts": [{"event": ex}], "ti": {"verdicts": [{"type": "domain", "entity": "bad.test", "verdict": "known_malicious", "score": 2}]}}
    tp = score_risk(_findings("TRUE_POSITIVE", "MALWARE_DOWNLOAD_EXECUTION", 0, [{"name": "s", "evidence": ["R1"]}]), bundle, index, kb, cfg)
    assert tp["score"] == 6 + 3 + 2 + 2 - 0 == 13 and tp["level"] == "CRITICAL"       # prod host, TI hit, execution
    fp = score_risk(_findings("FALSE_POSITIVE", "SQL_INJECTION", 1, [{"name": "s", "evidence": ["R1"]}]), bundle, index, kb, cfg)
    assert fp["level"] == "LOW" and fp["capped_low_for_false_positive"] and fp["score"] > 3
    same = score_risk(_findings("TRUE_POSITIVE", "MALWARE_DOWNLOAD_EXECUTION", 0, [{"name": "s", "evidence": ["R1"]}]), bundle, index, kb, cfg)
    assert same == tp, "same evidence must always get the same risk"


# ------------------------------------------------------------------------------- case memory
def test_similarity_weights_and_threshold(cfg):
    case = {"attack_types": ["SQL_INJECTION"], "stages": ["web_input_injection"], "ports": []}
    assert similarity({"attack_type": "SQL_INJECTION", "stages": ["web_input_injection"], "ports": []}, case) == 1.0
    assert similarity({"attack_type": "XSS", "stages": ["web_input_injection"], "ports": []}, case) < 0.85
    kb = KnowledgeBase(Path(cfg["_root"]) / "knowledge")


def test_reference_memory_is_a_hint_and_confirmed_cases_are_separate(cfg, tmp_path):
    kb = KnowledgeBase(Path(cfg["_root"]) / "knowledge")
    mem = CaseMemory(tmp_path / "m.db", kb.reference)
    assert mem.count("reference") == len(kb.reference) >= 12 and mem.count("confirmed") == 0
    fp = {"attack_type": "FIREWALL_POLICY_VIOLATION", "stages": ["restricted_service_access_attempt"], "ports": [23, 135, 139, 445, 3389]}
    hits = mem.lookup(fp, 0.85)
    assert hits and all(h["kind"] == "reference" for h in hits)
    assert any("CVE-2017-0144" in h["cves"] for h in mem.lookup(fp, 0.5, k=6))
    mem.add_confirmed("C1", "case", {**fp, "attack_type": "FIREWALL_POLICY_VIOLATION"}, "TRUE_POSITIVE", "s")
    assert mem.lookup(fp, 0.85)[0]["kind"] == "confirmed", "confirmed cases outrank reference on ties"
    mem.close()


# ------------------------------------------------------------------------------- stage 13
def _finished_run(cfg, tmp_path, events, alerts):
    orch = mk_orch(cfg, tmp_path, events)
    replay(orch, alerts)
    orch.write_index()
    return orch


def test_only_confirmed_verdicts_reach_memory(kb_copy, tmp_path):
    cfg, _ = kb_copy
    evs = brute_force_events()
    orch = _finished_run(cfg, tmp_path, evs, [mk_alert(1, evs[3])])
    run = tmp_path / "run"
    assert orch.memory.count("confirmed") == 0, "an agent verdict alone is never stored"
    r = record_verdict(cfg, run, "ORC-0001", "NEEDS_INVESTIGATION", note="check with owner", quiet=True)
    assert "not stored" in r["memory"]
    r = record_verdict(cfg, run, "ORC-0001", "CONFIRMED_ATTACK", note="yes", quiet=True)
    assert "confirmed TRUE_POSITIVE" in r["memory"]
    from soc.util import resolve
    mem = CaseMemory(resolve(cfg, "state_dir") / "case_memory.db", [])
    assert mem.count("confirmed") == 1
    mem.close()
    assert len(json.loads((run / "verdicts.json").read_text(encoding="utf-8"))) == 2


def test_allowlist_changes_need_explicit_approval(kb_copy, tmp_path):
    cfg, kdir = kb_copy
    kb = KnowledgeBase(kdir)
    scanner = kb.allow["internal_scanners"][0]["src_ip"]
    probes = [mk_event(f"S{i}", "SCAN", "NETWORK", t=i, src_ip=scanner, dst_port=20 + i, user="svc_02", host="HOST-019",
                       source_zone="INTERNAL", destination_zone="INTERNAL", destination_host="INTERNAL-SERVICE") for i in range(10)]
    orch = _finished_run(cfg, tmp_path, probes, [mk_alert(1, probes[-1], groups=("network", "port_scan"), sev=6)])
    assert orch.reports[0]["header"]["verdict"] == "FALSE_POSITIVE"
    run = tmp_path / "run"
    before = (kdir / "allowlists.json").read_text(encoding="utf-8")
    r = record_verdict(cfg, run, "ORC-0001", "CONFIRMED_FALSE_POSITIVE", quiet=True)
    assert r["allowlist"].startswith("PROPOSED") and (kdir / "allowlists.json").read_text(encoding="utf-8") == before
    r = record_verdict(cfg, run, "ORC-0001", "CONFIRMED_FALSE_POSITIVE", approve_allowlist=True, quiet=True)
    assert r["allowlist"].startswith("APPLIED")
    after = json.loads((kdir / "allowlists.json").read_text(encoding="utf-8"))
    assert len(after["internal_scanners"]) == len(kb.allow["internal_scanners"]) + 1
    assert (kdir / "allowlists.json.bak").exists(), "a backup is kept before any allowlist edit"


def test_confirmed_case_shows_up_as_a_hint_in_later_reports(kb_copy, tmp_path):
    cfg, _ = kb_copy
    evs = brute_force_events()
    _finished_run(cfg, tmp_path / "a", evs, [mk_alert(1, evs[3])])
    record_verdict(cfg, tmp_path / "a" / "run", "ORC-0001", "CONFIRMED_ATTACK", quiet=True)
    from soc.util import resolve
    mem_path = resolve(cfg, "state_dir") / "case_memory.db"
    evs2 = brute_force_events(prefix="Z", ip="203.0.113.99", user="dave")
    orch = mk_orch(cfg, tmp_path / "b", evs2)
    orch.memory.close()
    from soc.memory import CaseMemory as CM
    orch.memory = CM(mem_path, orch.kb.reference)
    for ag in orch.agents.values():
        ag.memory = orch.memory
    replay(orch, [mk_alert(1, evs2[3])])
    hints = orch.reports[0]["threat_intel"]["case_memory_hints"]
    assert any(h["kind"] == "confirmed" for h in hints)
    assert orch.reports[0]["header"]["verdict"] == "TRUE_POSITIVE"   # a hint, never the verdict


# ------------------------------------------------------------------------------- LLM client
def test_extract_json_handles_think_blocks_and_fences():
    assert extract_json('<think>hmm {"x": 1}</think>\n```json\n{"a": 1, "b": [2]}\n```') == {"a": 1, "b": [2]}
    assert extract_json('Sure! Here you go: {"a": 2} hope that helps') == {"a": 2}
    with pytest.raises(LLMError):
        extract_json("no json here")


def test_make_llm_falls_back_to_mock_without_a_key(cfg, monkeypatch):
    for k in ("LLM_PROVIDER", "OPENROUTER_API_KEY", "NVIDIA_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    c = copy.deepcopy(cfg); c["_root"] = str(Path(cfg["_root"]) / "tests")      # no .env there
    assert isinstance(make_llm(c), MockLLM)
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    assert isinstance(make_llm(c), MockLLM), "provider chosen but key missing -> stay runnable offline"


def test_openai_compatible_client_request_shape_and_retry(cfg, monkeypatch):
    seen = []

    class _Msg:  content = '```json\n{"verdict": "TRUE_POSITIVE"}\n```'
    class _Choice: message = _Msg()
    class _Usage: total_tokens = 42
    class _Resp: choices = [_Choice()]; usage = _Usage()

    class _Completions:
        n = 0
        def create(self, **kw):
            _Completions.n += 1
            seen.append(kw)
            if _Completions.n == 1:
                raise RuntimeError("429 rate limited")
            return _Resp()

    class _Client:
        def __init__(self, **kw): seen.append(kw); self.chat = types.SimpleNamespace(completions=_Completions())

    fake = types.ModuleType("openai"); fake.OpenAI = _Client
    monkeypatch.setitem(sys.modules, "openai", fake)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    pc = cfg["llm"]["providers"]["openrouter"]
    llm = OpenAICompatLLM("openrouter", pc, cfg["llm"])
    out = llm.chat_json("reconstruct", "recon", "SYS", "USER")
    assert out == {"verdict": "TRUE_POSITIVE"}
    assert seen[0]["base_url"] == "https://openrouter.ai/api/v1" and seen[0]["api_key"] == "sk-test"
    assert seen[1]["model"] == pc["recon_model"] and seen[1]["messages"][0] == {"role": "system", "content": "SYS"}
    assert len(seen) == 3, "one retry after a transient failure"
    llm.chat_json("classify", "classifier", "S", "U")
    assert seen[-1]["model"] == pc["classifier_model"]
    assert llm.calls[-1]["tokens"] == 42
