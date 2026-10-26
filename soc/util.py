"""Small shared helpers: time parsing, config loading, JSON-safe dumps."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def parse_ts(value: str | datetime) -> datetime:
    """Parse '2026-10-21 20:08:14.281874' or ISO 'Z' timestamps to a naive UTC datetime."""
    if isinstance(value, datetime):
        return value
    s = str(value).strip().replace("Z", "")
    return datetime.fromisoformat(s)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def hms(dt: datetime | str) -> str:
    return parse_ts(dt).strftime("%H:%M:%S")


def seconds(td: timedelta) -> float:
    return td.total_seconds()


class Config(dict):
    """dict with attribute access plus the extra yaml files merged under their own keys."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_config(root: Path | None = None) -> Config:
    root = root or ROOT
    cfg = Config(load_yaml(root / "config" / "config.yaml"))
    for extra in ("routing", "evidence_rules", "playbooks"):
        p = root / "config" / f"{extra}.yaml"
        if p.exists():
            cfg.update(load_yaml(p))
    cfg["_root"] = str(root)
    return cfg


def resolve(cfg: Config, key: str) -> Path:
    return Path(cfg["_root"]) / cfg["paths"][key]


_NUM = re.compile(r"^-?\d+(\.\d+)?$")


def num(value: Any) -> Any:
    """CSV cells -> int/float/None ('200.0' -> 200, '' -> None)."""
    if value is None:
        return None
    s = str(value).strip()
    if s == "":
        return None
    if _NUM.match(s):
        f = float(s)
        return int(f) if f.is_integer() else f
    return s


def jdump(obj: Any, path: Path | None = None) -> str:
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=_default)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _default(o: Any) -> Any:
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, datetime):
        return iso(o)
    raise TypeError(f"not JSON serialisable: {type(o)}")
