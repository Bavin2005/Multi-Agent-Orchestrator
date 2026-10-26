"""Stage 3 - validate and dedupe. Failures go to the dead-letter list with a reason."""
from __future__ import annotations

from .util import Config, parse_ts


class Validator:
    def __init__(self, cfg: Config):
        self.allowed = {k: set(v) for k, v in cfg["allowed_actions"].items()}
        self.core = cfg["required_core_fields"]
        self.event_fields = cfg["required_event_fields"]
        self.seen: set[str] = set()

    def check(self, alert: dict) -> tuple[bool, str]:
        """Returns (ok, reason). reason is 'duplicate' for dropped repeats (not dead-lettered)."""
        if not isinstance(alert, dict):
            return False, "alert is not an object"
        for f in self.core:
            if alert.get(f) in (None, "", []):
                return False, f"missing required field: {f}"
        ev = alert["event"]
        if not isinstance(ev, dict):
            return False, "event is not an object"
        for f in self.event_fields:
            if ev.get(f) in (None, ""):
                return False, f"missing required event field: {f}"
        for label, value in (("alert_time", alert["alert_time"]), ("timestamp", ev["timestamp"])):
            try:
                parse_ts(value)
            except (ValueError, TypeError):
                return False, f"{label} does not parse: {value!r}"
        st, action = ev["source_type"], ev["action"]
        if st not in self.allowed:
            return False, f"unknown source_type: {st}"
        if action not in self.allowed[st]:
            return False, f"action {action} not allowed for source_type {st}"
        if not isinstance(alert["siem_severity"], (int, float)):
            return False, "siem_severity is not numeric"
        if alert["alert_id"] in self.seen:
            return False, "duplicate"
        self.seen.add(alert["alert_id"])
        return True, "ok"
