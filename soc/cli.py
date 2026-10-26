"""Command line: run a replay, grade it, record SOC verdicts (Stage 13)."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .adapter import load_runtime
from .llm import make_llm
from .orchestrator import Orchestrator
from .replay import replay
from .util import jdump, load_config, resolve


def cmd_run(a) -> Path:
    cfg = load_config()
    store, alerts = load_runtime(cfg)
    llm = make_llm(cfg)
    run_id = a.run_id or datetime.now().strftime("run_%Y%m%d_%H%M%S")
    run_dir = resolve(cfg, "runs_dir") / run_id
    orch = Orchestrator(cfg, run_dir, llm=llm, logstore=store,
                        memory_path=(run_dir / "case_memory.db") if a.fresh_memory else None)
    print(f"[run] {run_id}  alerts={len(alerts)}  llm={llm.name}  speed={a.speed or cfg['replay']['speed']}")
    replay(orch, alerts, speed=a.speed if a.speed is not None else cfg["replay"]["speed"],
           shuffle_within=a.shuffle_within if a.shuffle_within is not None else cfg["replay"]["shuffle_within_s"],
           seed=cfg["replay"]["seed"], limit=a.limit)
    orch.write_index()
    print(f"[run] incidents={len(orch.manager.incidents)} reports={len(orch.reports)} "
          f"dead_letter={orch.store.count('dead_letter')} human_review={orch.store.count('human_review')}")
    print(f"[run] output: {run_dir}")
    orch.close()
    if a.grade:
        from .grader import grade
        grade(cfg, run_dir)
    return run_dir


def cmd_grade(a) -> None:
    from .grader import grade
    cfg = load_config()
    run = Path(a.run) if a.run else sorted(resolve(cfg, "runs_dir").glob("run_*"))[-1]
    grade(cfg, run)


def cmd_verdict(a) -> None:
    from .feedback import record_verdict
    cfg = load_config()
    run = Path(a.run) if a.run else sorted(resolve(cfg, "runs_dir").glob("run_*"))[-1]
    record_verdict(cfg, run, a.incident, a.verdict, note=a.note, approve_allowlist=a.approve_allowlist)


def main(argv=None) -> None:
    for stream in (sys.stdout, sys.stderr):      # Windows consoles default to cp1252; reports use → and —
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="soc")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="replay the alert stream through the orchestrator")
    r.add_argument("--speed", type=float, default=None, help="x real time (0 = as fast as possible)")
    r.add_argument("--shuffle-within", type=float, default=None, help="delay ~30%% of alerts by up to N seconds")
    r.add_argument("--limit", type=int, default=None)
    r.add_argument("--run-id", default=None)
    r.add_argument("--grade", action="store_true", help="grade after the run")
    r.add_argument("--fresh-memory", action="store_true", help="use an empty per-run case memory (reproducible; ignores SOC-confirmed cases)")
    g = sub.add_parser("grade", help="compare a run with the ground truth")
    g.add_argument("--run", default=None)
    v = sub.add_parser("verdict", help="Stage 13: record the SOC analyst's verdict on a report")
    v.add_argument("incident")
    v.add_argument("verdict", choices=["CONFIRMED_ATTACK", "CONFIRMED_FALSE_POSITIVE", "NEEDS_INVESTIGATION"])
    v.add_argument("--note", default="")
    v.add_argument("--run", default=None)
    v.add_argument("--approve-allowlist", action="store_true", help="add the source to the allowlist (confirmed FP only)")
    a = p.parse_args(argv)
    {"run": cmd_run, "grade": cmd_grade, "verdict": cmd_verdict}[a.cmd](a)


if __name__ == "__main__":
    main()
