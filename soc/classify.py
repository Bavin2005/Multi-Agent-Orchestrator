"""Stage 4 - classify each alert to a domain: routing patterns -> LLM fallback -> human review."""
from __future__ import annotations

from .llm import LLM, LLMError
from .sanitize import SYSTEM_RULES, wrap_data
from .util import Config

LABELS = ["network", "app_endpoint", "unknown"]


class Classifier:
    def __init__(self, cfg: Config, llm: LLM):
        self.patterns = cfg["routing_patterns"]
        self.threshold = cfg["classifier"]["confidence_threshold"]
        self.llm = llm
        self.stats = {"pattern": 0, "llm": 0, "human_review": 0}

    def _by_pattern(self, alert: dict) -> str | None:
        st = alert["event"]["source_type"]
        for domain, p in self.patterns.items():           # source_type is the strongest signal
            if st in p["source_types"]:
                return domain
        groups = set(alert["siem_groups"])
        for domain, p in self.patterns.items():
            if groups & set(p["siem_groups"]):
                return domain
        return None

    def classify(self, alert: dict) -> dict:
        domain = self._by_pattern(alert)
        if domain:
            self.stats["pattern"] += 1
            return {"domain": domain, "method": "pattern", "confidence": 1.0}
        ev = alert["event"]
        digest = {"source_type": ev["source_type"], "action": ev["action"], "siem_groups": alert["siem_groups"],
                  "rule": alert["siem_rule_name"]}
        user = (f"Classify this alert into exactly one label from {LABELS}. "
                'Reply {"label": <label>, "confidence": <0..1>}.\n' + wrap_data("alert", digest))
        try:
            out = self.llm.chat_json("classify", "classifier", SYSTEM_RULES, user, payload=digest)
            label, conf = out.get("label", "unknown"), float(out.get("confidence", 0))
        except (LLMError, ValueError, TypeError):
            label, conf = "unknown", 0.0
        if label not in ("network", "app_endpoint") or conf < self.threshold:
            self.stats["human_review"] += 1
            return {"domain": None, "method": "human_review", "confidence": conf,
                    "reason": f"LLM label={label!r} confidence={conf:.2f} below {self.threshold}"}
        self.stats["llm"] += 1
        return {"domain": label, "method": "llm", "confidence": conf}
