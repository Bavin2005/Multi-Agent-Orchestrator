"""Stage 5 - incident grouping.

Match rule (this build): attach when the alert has the same grouping key (src_ip; falling back to
user, then host, when src_ip is missing) as an incident AND its event time is inside that
incident's correlation window. Otherwise open a new incident. Shared service accounts and hosts
are deliberately NOT grouping keys (they are reused across unrelated scenarios).

Timelines are always ordered by event timestamp, never by arrival order.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .util import Config, parse_ts, iso


@dataclass
class Incident:
    incident_id: str
    key: str
    alerts: list[dict] = field(default_factory=list)       # sorted by event timestamp
    domains: set[str] = field(default_factory=set)
    entities: set[str] = field(default_factory=set)
    max_severity: int = 0
    first_seen: datetime | None = None                     # event time
    last_seen: datetime | None = None
    first_attach: datetime | None = None                   # simulated arrival time
    last_attach: datetime | None = None
    status: str = "OPEN"                                   # OPEN | READY | DISPATCHED | CLOSED
    version: int = 1
    ready_reasons: list[str] = field(default_factory=list)
    ready_at: datetime | None = None
    dispatched_at: datetime | None = None
    hold_start: datetime | None = None                     # when the current hold began (creation or revision)
    dispatched_versions: list[int] = field(default_factory=list)

    @property
    def alert_ids(self) -> list[str]:
        return [a["alert_id"] for a in self.alerts]

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id, "key": self.key, "alerts": self.alert_ids,
            "domains": sorted(self.domains), "entities": sorted(self.entities),
            "max_severity": self.max_severity,
            "first_seen": iso(self.first_seen) if self.first_seen else None,
            "last_seen": iso(self.last_seen) if self.last_seen else None,
            "status": self.status, "version": self.version, "ready_reasons": self.ready_reasons,
            "dispatched_versions": self.dispatched_versions,
        }


def grouping_key(alert: dict, order: list[str]) -> str | None:
    ev = alert["event"]
    for f in order:
        if ev.get(f):
            return f"{f}:{ev[f]}"
    return None


class IncidentManager:
    def __init__(self, cfg: Config):
        self.windows = {k: timedelta(minutes=v) for k, v in cfg["grouping"]["window_minutes"].items()}
        self.order = [cfg["grouping"]["key"], *cfg["grouping"]["fallback"]]
        self.incidents: dict[str, Incident] = {}
        self._by_key: dict[str, list[Incident]] = {}
        self._n = 0

    def window_for(self, domains: set[str]) -> timedelta:
        return max((self.windows[d] for d in domains if d in self.windows), default=max(self.windows.values()))

    def attach_or_open(self, alert: dict, domain: str, now: datetime) -> tuple[Incident, bool, bool]:
        """Returns (incident, created, is_revision)."""
        key = grouping_key(alert, self.order) or f"alert:{alert['alert_id']}"
        ts = parse_ts(alert["event"]["timestamp"])
        for inc in self._by_key.get(key, []):
            w = self.window_for(inc.domains | {domain})
            if inc.first_seen - w <= ts <= inc.last_seen + w:
                revision = inc.status in ("DISPATCHED", "CLOSED")
                self._add(inc, alert, domain, ts, now)
                if revision:
                    inc.version += 1
                    inc.status, inc.ready_at, inc.hold_start = "READY", now, now
                    inc.ready_reasons = ["revision: late alert after dispatch"]
                return inc, False, revision
        self._n += 1
        inc = Incident(incident_id=f"ORC-{self._n:04d}", key=key)
        inc.first_seen = inc.last_seen = ts
        inc.first_attach = inc.hold_start = now
        self._by_key.setdefault(key, []).append(inc)
        self.incidents[inc.incident_id] = inc
        self._add(inc, alert, domain, ts, now)
        return inc, True, False

    @staticmethod
    def _add(inc: Incident, alert: dict, domain: str, ts: datetime, now: datetime) -> None:
        alert = {**alert, "domain": domain}
        inc.alerts.append(alert)
        inc.alerts.sort(key=lambda a: (a["event"]["timestamp"], a["alert_id"]))
        inc.domains.add(domain)
        ev = alert["event"]
        inc.entities |= {v for v in (ev.get("src_ip"), ev.get("user"), ev.get("host")) if v}
        inc.max_severity = max(inc.max_severity, alert["siem_severity"])
        inc.first_seen = min(inc.first_seen, ts)
        inc.last_seen = max(inc.last_seen, ts)
        inc.last_attach = now

    def close_stale(self, now: datetime) -> None:
        for inc in self.incidents.values():
            if inc.status == "DISPATCHED" and now - inc.last_seen > self.window_for(inc.domains):
                inc.status = "CLOSED"
