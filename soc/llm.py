"""LLM access: an OpenAI-compatible client (OpenRouter / NVIDIA) and a deterministic offline mock.

Tasks: 'classify' (Stage 4 fallback), 'reconstruct' (Stage 9 step 4), 'judge_fp' (Stage 9 step 5).
The orchestrator and agents depend only on `LLM.chat_json`, so the provider is a config change.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from .util import Config


class LLMError(RuntimeError):
    pass


def load_env(root: Path) -> None:
    """Minimal .env loader (no dependency). Existing environment variables win."""
    p = root / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def extract_json(text: str) -> dict:
    """Tolerant JSON extraction: strips <think> blocks and ``` fences."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S | re.I).strip()
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        a, b = text.find("{"), text.rfind("}")
        if a != -1 and b > a:
            return json.loads(text[a:b + 1])
        raise LLMError(f"model did not return JSON: {text[:200]!r}")


class LLM:
    name = "base"
    is_mock = False

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def chat_json(self, task: str, role: str, system: str, user: str, payload: dict | None = None) -> dict:
        raise NotImplementedError

    def _log(self, task: str, role: str, t0: float, **extra) -> None:
        self.calls.append({"task": task, "role": role, "seconds": round(time.time() - t0, 3), **extra})


class OpenAICompatLLM(LLM):
    def __init__(self, provider: str, pcfg: dict, llm_cfg: dict):
        super().__init__()
        from openai import OpenAI  # lazy import: mock mode needs no network libs
        key = os.environ.get(pcfg["key_env"], "")
        if not key:
            raise LLMError(f"{pcfg['key_env']} is not set")
        self.name = f"{provider}"
        self.client = OpenAI(base_url=pcfg["base_url"], api_key=key, timeout=llm_cfg["timeout_s"])
        self.models = {"recon": os.environ.get("LLM_RECON_MODEL") or pcfg["recon_model"],
                       "classifier": os.environ.get("LLM_CLASSIFIER_MODEL") or pcfg["classifier_model"]}
        self.max_tokens, self.temperature = llm_cfg["max_tokens"], llm_cfg["temperature"]

    def chat_json(self, task, role, system, user, payload=None) -> dict:
        t0 = time.time()
        model = self.models["classifier" if role == "classifier" else "recon"]
        last: Exception | None = None
        for attempt in range(2):
            try:
                resp = self.client.chat.completions.create(
                    model=model, temperature=self.temperature, max_tokens=self.max_tokens,
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
                out = extract_json(resp.choices[0].message.content or "")
                self._log(task, role, t0, model=model,
                          tokens=getattr(getattr(resp, "usage", None), "total_tokens", None))
                return out
            except Exception as exc:  # network / parse: one retry then surface
                last = exc
        self._log(task, role, t0, model=model, error=str(last)[:120])
        raise LLMError(f"{task} failed: {last}")


class MockLLM(LLM):
    """Deterministic offline stand-in. It reasons only over the payload it is handed (never any
    label), so it is a placeholder for the real model, not an answer key."""
    name = "mock"
    is_mock = True

    def chat_json(self, task, role, system, user, payload=None) -> dict:
        t0 = time.time()
        payload = payload or {}
        out = getattr(self, f"_{task}")(payload)
        self._log(task, role, t0, model="mock")
        return out

    # -- Stage 4 fallback --------------------------------------------------------------------
    def _classify(self, p: dict) -> dict:
        st = p.get("source_type")
        if st in ("NETWORK", "FIREWALL", "AUTH"):
            return {"label": "network", "confidence": 0.8}
        if st in ("HTTP", "ENDPOINT"):
            return {"label": "app_endpoint", "confidence": 0.8}
        return {"label": "unknown", "confidence": 0.2}

    # -- Stage 9 step 4: reconstruction (generic anomaly heuristics) -------------------------------
    def _reconstruct(self, p: dict) -> dict:
        alerts = p.get("alert_event_ids", [])
        evs = p.get("events", [])
        anomalous = [e for e in evs if (e.get("ext", {}).get("bytes_sent") or 0) >= 100_000
                     or (e.get("ext", {}).get("packet_rate") or 0) >= 1000]
        cite = [e["event_id"] for e in anomalous] or alerts[:1]
        if not cite:
            return {"attack_type": "UNMAPPED_SUSPICIOUS_ACTIVITY", "verdict": "FALSE_POSITIVE", "confidence": 0.5,
                    "summary": "No evidence to cite.", "stages": [], "benign_explanation": "no evidence",
                    "rejected_because": "n/a", "mitre": [], "recommended_actions": [], "gaps": ["no events"]}
        verdict = "TRUE_POSITIVE" if anomalous else "FALSE_POSITIVE"
        e0 = next((e for e in evs if e["event_id"] == cite[0]), {})
        ext = e0.get("ext", {})
        return {
            "attack_type": "UNMAPPED_SUSPICIOUS_ACTIVITY", "verdict": verdict,
            "confidence": 0.62 if anomalous else 0.55,
            "summary": ("Unexplained high-volume traffic on an uncommon port with no matching playbook."
                        if anomalous else "Activity looks routine."),
            "stages": [{"name": "unclassified_suspicious_activity", "evidence": cite,
                        "what_happened": f"{ext.get('bytes_sent', '?')} bytes in {ext.get('flow_duration', '?')}s "
                                         f"to port {e0.get('dst_port')} at packet rate {ext.get('packet_rate', '?')}/s."}],
            "benign_explanation": "A legitimate bulk transfer or backup job to an internal service.",
            "rejected_because": "No owner or change record explains traffic of this volume on this port; "
                                "rate and volume are far above the host's other flows." if anomalous else "holds",
            "mitre": ["T1571", "T1048"] if anomalous else [],
            "recommended_actions": ["Identify the owner of the destination service", "Capture packets for the flow",
                                    "Review the host's recent outbound volume baseline"],
            "gaps": ["Payload content is not visible in flow records",
                     "No follow-on activity confirms exfiltration or compromise"],
        }

    # -- Stage 9 step 5: FP judge when playbook rules disagree with the attack evidence ---------------
    def _judge_fp(self, p: dict) -> dict:
        return {"verdict": "TRUE_POSITIVE", "confidence": 0.55,
                "reasoning": "Offline mock judge defaults to the conservative side when benign and attack "
                             "evidence disagree; route to an analyst."}


def make_llm(cfg: Config) -> LLM:
    load_env(Path(cfg["_root"]))
    lcfg = cfg["llm"]
    provider = (os.environ.get("LLM_PROVIDER") or lcfg["provider"]).lower()
    if provider == "auto":
        provider = next((p for p in ("openrouter", "nvidia")
                         if os.environ.get(lcfg["providers"][p]["key_env"])), "mock")
    if provider == "mock":
        return MockLLM()
    if provider not in lcfg["providers"]:
        raise LLMError(f"unknown provider {provider}")
    try:
        return OpenAICompatLLM(provider, lcfg["providers"][provider], lcfg)
    except LLMError as exc:                      # requested a provider but cannot use it: stay runnable, but say so
        fallback = MockLLM()
        fallback.name = f"mock (FALLBACK - {provider} unavailable: {exc})"
        return fallback
