"""Orchestrator-as-resource-provider: the read-only tools an agent may call while it runs.

Capped at 5 calls / 60 s per agent run (config agent.tool_budget_*). Exceeding the budget raises
BudgetExceeded and the agent returns partial findings marked needs_human.
"""
from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime, timedelta
from typing import Callable

from .adapter import LogStore
from .ti import KnowledgeBase, ThreatIntelAgent
from .util import parse_ts


class BudgetExceeded(RuntimeError):
    pass


def entity_type(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.startswith("http"):
        return "url"
    if re.fullmatch(r"[0-9a-fA-F]{32,64}", value):
        return "hash"
    if value.startswith("HOST-"):
        return "host"
    if "." in value and " " not in value:
        return "domain"
    return "user"


class ToolBox:
    def __init__(self, *, logstore: LogStore, ti: ThreatIntelAgent, kb: KnowledgeBase, engine,
                 consult: Callable[[str, list[str]], dict], as_of: datetime, max_calls: int, max_seconds: float):
        self.logstore, self.ti, self.kb, self.engine = logstore, ti, kb, engine
        self._consult, self.as_of = consult, as_of
        self.max_calls, self.max_seconds = max_calls, max_seconds
        self.t0 = time.monotonic()
        self.log: list[dict] = []

    @property
    def remaining(self) -> int:
        return self.max_calls - len(self.log)

    def _spend(self, tool: str, args: dict) -> None:
        if len(self.log) >= self.max_calls:
            raise BudgetExceeded(f"tool budget of {self.max_calls} calls exhausted (wanted {tool})")
        if time.monotonic() - self.t0 > self.max_seconds:
            raise BudgetExceeded(f"tool time budget of {self.max_seconds}s exhausted (wanted {tool})")
        self.log.append({"tool": tool, "args": args})

    # -- the five tools ------------------------------------------------------------------------
    def get_related_logs(self, entity: str, window_min: int = 30) -> list[dict]:
        self._spend("get_related_logs", {"entity": entity, "window_min": window_min})
        t = self.as_of
        return self.logstore.query(entity, t - timedelta(minutes=window_min), t, as_of=self.as_of)

    def ti_lookup(self, entity: str) -> dict:
        self._spend("ti_lookup", {"entity": entity})
        return self.ti.lookup(entity_type(entity), entity, self.as_of, self.as_of.isoformat())

    def get_asset_info(self, host_or_user: str) -> dict:
        self._spend("get_asset_info", {"entity": host_or_user})
        if host_or_user.startswith("HOST-"):
            return self.kb.host_info(host_or_user)
        return self.kb.user_info(host_or_user)

    def consult_agent(self, domain: str, event_ids: list[str]) -> dict:
        self._spend("consult_agent", {"domain": domain, "events": len(event_ids)})
        return self._consult(domain, event_ids)

    def get_playbook(self, name: str) -> dict | None:
        self._spend("get_playbook", {"name": name})
        return self.engine.get(name)

    def dispatch(self, name: str, args: dict):
        allowed = {"get_related_logs", "ti_lookup", "get_asset_info", "consult_agent", "get_playbook"}
        if name not in allowed:
            raise ValueError(f"unknown tool {name}")
        return getattr(self, name)(**args)
