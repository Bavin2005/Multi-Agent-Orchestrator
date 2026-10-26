"""How much does each knowledge-base component contribute?  Re-runs the full replay with parts removed.

  python scripts/ablation.py

Why this exists: the allowlists / pentest schedule / service-account inventory are derived from the
same simulated environment as the logs, so a perfect score with the full KB says little about
generalisation. This shows what the *logic* does when that context is missing.
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from soc.adapter import load_runtime            # noqa: E402
from soc.grader import grade                    # noqa: E402
from soc.llm import MockLLM                     # noqa: E402
from soc.orchestrator import Orchestrator       # noqa: E402
from soc.replay import replay                   # noqa: E402
from soc.ti import KnowledgeBase                # noqa: E402
from soc.util import load_config                # noqa: E402


def variant(name: str, kdir: Path) -> None:
    allow = json.loads((kdir / "allowlists.json").read_text(encoding="utf-8"))
    assets = json.loads((kdir / "assets.json").read_text(encoding="utf-8"))
    ioc = json.loads((kdir / "ioc.json").read_text(encoding="utf-8"))
    if name in ("no_allowlists", "no_kb_context"):
        allow["internal_scanners"], allow["pentest_schedule"], allow["internal_sites"] = [], [], []
    if name in ("no_service_accounts", "no_kb_context"):
        assets["users"] = {}
    if name in ("no_ioc", "no_kb_context"):
        ioc["domains"] = {}
    (kdir / "allowlists.json").write_text(json.dumps(allow), encoding="utf-8")
    (kdir / "assets.json").write_text(json.dumps(assets), encoding="utf-8")
    (kdir / "ioc.json").write_text(json.dumps(ioc), encoding="utf-8")


def main() -> None:
    cfg = load_config()
    store, alerts = load_runtime(cfg)
    rows = []
    for name in ("full_kb", "no_allowlists", "no_service_accounts", "no_ioc", "no_kb_context"):
        tmp = Path(tempfile.mkdtemp())
        shutil.copytree(ROOT / "knowledge", tmp / "k")
        variant(name, tmp / "k")
        orch = Orchestrator(cfg, tmp / "run", llm=MockLLM(), logstore=store, kb=KnowledgeBase(tmp / "k"),
                            memory_path=tmp / "m.db")
        replay(orch, copy.deepcopy(alerts))
        orch.write_index()
        ev = grade(cfg, tmp / "run", quiet=True)
        fp = ev["fp_detection"]
        rows.append((name, fp["verdict_accuracy"], fp["fp_recall"], fp["fp_precision"], ev["risk_level_accuracy"],
                     ev["stage_accuracy_exact_sequence"], ev["path_mix"], ev["needs_human"]))
        orch.close()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{'variant':<22}{'verdict':>9}{'FP rec':>9}{'FP prec':>9}{'risk':>8}{'stages':>8}  path mix")
    for n, v, r, p, k, s, pm, nh in rows:
        print(f"{n:<22}{v:>9.1%}{r:>9.1%}{(p if p is not None else 0):>9.1%}{k:>8.1%}{s:>8.1%}  {pm}  needs_human={nh}")


if __name__ == "__main__":
    main()
