"""Shared fixtures + tiny builders for synthetic alerts/events used by the edge-case tests."""
from __future__ import annotations

import copy
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soc.adapter import LogStore, load_runtime  # noqa: E402
from soc.llm import MockLLM  # noqa: E402
from soc.orchestrator import Orchestrator  # noqa: E402
from soc.replay import replay  # noqa: E402
from soc.util import iso, load_config  # noqa: E402


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def runtime(cfg):
    return load_runtime(cfg)          # (LogStore, alerts)


@pytest.fixture(scope="session")
def full_run(cfg, runtime, tmp_path_factory):
    """One complete replay of the real dataset, shared by the end-to-end tests."""
    store, alerts = runtime
    run_dir = tmp_path_factory.mktemp("full") / "run"
    mem = tmp_path_factory.mktemp("mem") / "case_memory.db"
    orch = Orchestrator(cfg, run_dir, llm=MockLLM(), logstore=store, memory_path=mem)
    replay(orch, copy.deepcopy(alerts))
    orch.write_index()
    yield orch, run_dir
    orch.close()


# ---------------------------------------------------------------------------- builders
T0 = datetime(2026, 10, 21, 20, 0, 0)


def mk_event(eid: str, action: str, source_type: str, *, t: float = 0, src_ip: str | None = "203.0.113.50",
             user: str | None = "alice", host: str | None = "HOST-005", dst_port: int | None = None, **ext) -> dict:
    ts = iso(T0 + timedelta(seconds=t))
    return {"event_id": eid, "timestamp": ts, "source_type": source_type, "src_ip": src_ip, "dst_ip": "10.0.0.5",
            "src_port": None, "dst_port": dst_port, "user": user, "host": host, "action": action,
            "ext": dict(ext), "raw": f"event_id={eid} action={action} src_ip={src_ip} user={user} {ext}"}


def mk_alert(n: int, event: dict, *, groups=("authentication", "brute_force"), sev: int = 10, rule="TEST-RULE",
             at: float | None = None) -> dict:
    t = datetime.fromisoformat(event["timestamp"].replace("Z", "")) + timedelta(seconds=1 if at is None else at)
    return {"alert_id": f"ALR-{n:06d}", "alert_time": iso(t), "siem_rule_id": rule, "siem_rule_name": rule,
            "siem_groups": list(groups), "siem_severity": sev, "siem_severity_label": "HIGH",
            "description": "", "event": event}


def mk_orch(cfg, tmp_path, events: list[dict], *, llm=None, cfg_patch=None, kb=None):
    c = copy.deepcopy(cfg)
    for k, v in (cfg_patch or {}).items():
        c[k] = {**c[k], **v} if isinstance(v, dict) else v
    store = LogStore({e["event_id"]: e for e in events})
    return Orchestrator(c, tmp_path / "run", llm=llm or MockLLM(), logstore=store, kb=kb,
                        memory_path=tmp_path / "mem.db")


def brute_force_events(prefix="BF", ip="203.0.113.50", user="alice", n_fail=4, success=True, t0=0.0):
    evs = [mk_event(f"{prefix}{i}", "LOGIN_FAILED", "AUTH", t=t0 + 8 * i, src_ip=ip, user=user, service="ssh",
                    source_zone="INTERNET", destination_zone="INTERNAL") for i in range(n_fail)]
    if success:
        evs.append(mk_event(f"{prefix}S", "LOGIN_SUCCESS", "AUTH", t=t0 + 8 * n_fail + 16, src_ip=ip, user=user,
                            service="ssh", source_zone="INTERNET", destination_zone="INTERNAL"))
    return evs


@pytest.fixture()
def kb_copy(cfg, tmp_path):
    """A private copy of the knowledge base so feedback tests can modify allowlists safely."""
    dst = tmp_path / "knowledge"
    shutil.copytree(ROOT / "knowledge", dst)
    c = copy.deepcopy(cfg)
    c["paths"]["knowledge_dir"] = str(dst)
    c["paths"]["state_dir"] = str(tmp_path / "state")
    return c, dst
