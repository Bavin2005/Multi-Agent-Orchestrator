"""Stage 2 - stream replay.

Sends alerts one at a time, in alert_time order, to orchestrator.ingest(alert). Simulated time
advances in `sweep_interval_s` steps between alerts so the orchestrator's quiet-period timers
fire exactly as they would live. --shuffle-within delays a share of alerts by a few seconds to
exercise out-of-order arrival. Input is the alerts only: no ground-truth file is opened here.
"""
from __future__ import annotations

import random
import time
from datetime import timedelta

from .orchestrator import Orchestrator
from .util import parse_ts


def replay(orch: Orchestrator, alerts: list[dict], *, speed: float = 0.0, shuffle_within: float = 0.0,
           seed: int = 7, limit: int | None = None, progress=None) -> None:
    rng = random.Random(seed)
    stream = []
    for a in alerts[: limit or len(alerts)]:
        t = parse_ts(a["alert_time"])
        if shuffle_within > 0 and rng.random() < 0.3:
            t = t + timedelta(seconds=rng.uniform(1, shuffle_within))
        stream.append((t, a))
    stream.sort(key=lambda x: (x[0], x[1]["alert_id"]))
    step = timedelta(seconds=orch.cfg["dispatch"]["sweep_interval_s"])
    clock = stream[0][0] if stream else None
    for n, (arrival, alert) in enumerate(stream, 1):
        while clock + step <= arrival:                      # sweeps between alerts
            clock += step
            orch.tick(clock)
            if speed > 0:
                time.sleep(step.total_seconds() / speed)
        if speed > 0 and arrival > clock:
            time.sleep((arrival - clock).total_seconds() / speed)
        clock = max(clock, arrival)
        orch.ingest(alert, arrival)
        if progress:
            progress(n, len(stream))
    orch.flush()
