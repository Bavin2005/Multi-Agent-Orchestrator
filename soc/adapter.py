"""CSV adapter + log store.

The supplied dataset is flat CSV (one runtime-event file, one SIEM-alert file). This adapter
rebuilds the design doc's alert shape (core fields + source-specific ext block) and provides a
queryable log store that the orchestrator exposes to agents as `get_related_logs`.

It never touches the ground-truth files.
"""
from __future__ import annotations

import csv
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from .util import Config, iso, num, parse_ts, resolve

# ext fields per source type (doc table) + dataset extras that are useful evidence.
EXT_FIELDS = {
    "NETWORK": ["protocol", "bytes_sent", "bytes_received", "packets_sent", "packets_received",
                "flow_duration", "tcp_flags", "direction", "connection_status", "source_zone",
                "destination_zone", "source_host", "destination_host", "application_protocol",
                "packet_rate", "bytes_rate"],
    "FIREWALL": ["firewall_rule", "protocol", "source_zone", "destination_zone", "direction",
                 "source_host", "destination_host", "connection_status", "application_protocol",
                 "bytes_sent", "bytes_received"],
    "AUTH": ["service", "auth_method", "direction", "source_zone", "destination_zone",
             "source_host", "destination_host", "connection_status", "application_protocol"],
    "HTTP": ["method", "url", "status_code", "user_agent", "session_id", "request_body",
             "response_size", "request_size", "content_type", "host", "referrer", "http_version"],
    "ENDPOINT": ["process_id", "process_name", "parent_process", "command_line", "file_hash",
                 "file_path", "file_name", "file_action", "process_action", "registry_action",
                 "registry_key"],
}
# CSV column -> ext key renames
RENAME = {"http_method": "method", "hostname": None, "host": "host"}


def _row_to_event(row: dict) -> dict:
    st = row["source_type"]
    ext: dict = {}
    for col in EXT_FIELDS.get(st, []):
        src = {"method": "http_method"}.get(col, col)
        val = num(row.get(src))
        if val is not None:
            ext[col] = val
    if st == "AUTH":
        proto = (row.get("application_protocol") or "").upper()
        ext["service"] = "ssh" if proto == "SSH" else "web"
        ext["auth_method"] = "password"
    if st == "NETWORK" and row.get("protocol"):
        ext["protocol"] = row["protocol"]
    if st == "FIREWALL" and row.get("protocol"):
        ext["protocol"] = row["protocol"]
    if row.get("device_id"):
        ext["device_id"] = row["device_id"]
    raw = " ".join(f"{k}={v}" for k, v in row.items() if v not in ("", None) and k != "event_id")
    return {
        "event_id": row["event_id"],
        "timestamp": iso(parse_ts(row["timestamp"])),
        "source_type": st,
        "src_ip": row.get("src_ip") or None,
        "dst_ip": row.get("dst_ip") or None,
        "src_port": num(row.get("src_port")),
        "dst_port": num(row.get("dst_port")),
        "user": row.get("user") or None,
        "host": row.get("hostname") or None,
        "action": row["action"],
        "ext": ext,
        "raw": raw,
    }


def load_events(path: Path) -> dict[str, dict]:
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return {r["event_id"]: _row_to_event(r) for r in csv.DictReader(fh)}


def load_alerts(path: Path, events: dict[str, dict], severity_map: dict[str, int]) -> list[dict]:
    """Join SIEM alert rows to their events -> doc-shaped alert records.

    alert_time is clamped to >= the event timestamp (the CSV truncates seconds, so a few
    alerts would otherwise appear to precede their own event).
    """
    out: list[dict] = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            ev = events.get(r["event_id"])
            at = parse_ts(r["alert_time"])
            if ev is not None:
                at = max(at, parse_ts(ev["timestamp"]))
            label = (r.get("siem_severity") or "").strip().upper()
            out.append({
                "alert_id": r["alert_id"],
                "alert_time": iso(at),
                "siem_rule_id": r["siem_rule_id"],
                "siem_rule_name": r["siem_rule_name"],
                "siem_groups": [g.strip() for g in r["siem_groups"].split(",") if g.strip()],
                "siem_severity": severity_map.get(label, 0),
                "siem_severity_label": label,
                "description": r.get("description", ""),
                "event": ev,
            })
    out.sort(key=lambda a: (a["alert_time"], a["alert_id"]))
    return out


class LogStore:
    """Time-indexed runtime event store. Queries are bounded by `as_of` so agents can never
    see events from the simulated future."""

    def __init__(self, events: dict[str, dict]):
        self.events = events
        self._by_ip: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._by_user: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._by_host: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for e in events.values():
            for idx, key in ((self._by_ip, e["src_ip"]), (self._by_user, e["user"]),
                             (self._by_host, e["host"])):
                if key:
                    idx[key].append((e["timestamp"], e["event_id"]))
        for idx in (self._by_ip, self._by_user, self._by_host):
            for v in idx.values():
                v.sort()

    def get(self, event_id: str) -> dict | None:
        return self.events.get(event_id)

    def query(self, entity: str, start: datetime, end: datetime, kind: str | None = None,
              as_of: datetime | None = None) -> list[dict]:
        """Events for an IP / user / host with start <= ts <= min(end, as_of)."""
        if as_of is not None:
            end = min(end, as_of)
        kinds = [kind] if kind else ["ip", "user", "host"]
        seen: dict[str, dict] = {}
        for k in kinds:
            idx = {"ip": self._by_ip, "user": self._by_user, "host": self._by_host}[k]
            rows = idx.get(entity, [])
            lo = bisect_left(rows, (iso(start), ""))
            hi = bisect_right(rows, (iso(end), "￿"))
            for _, eid in rows[lo:hi]:
                seen[eid] = self.events[eid]
        return sorted(seen.values(), key=lambda e: (e["timestamp"], e["event_id"]))


def load_runtime(cfg: Config) -> tuple[LogStore, list[dict]]:
    data = resolve(cfg, "data_dir") if "data_dir" in cfg["paths"] else Path(cfg["_root"]) / "data"
    events = load_events(data / cfg["data_files"]["events"])
    alerts = load_alerts(data / cfg["data_files"]["alerts"], events, cfg["severity_map"])
    return LogStore(events), alerts


def iter_window(start: datetime, minutes: int) -> tuple[datetime, datetime]:
    return start - timedelta(minutes=minutes), start + timedelta(minutes=minutes)
