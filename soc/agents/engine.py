"""Playbook engine: pattern-first reconstruction (Stage 9 steps 2 and 5).

Given the bundle's events it
  1. matches a configured playbook and builds the timeline IN CODE (which events form which stage),
  2. runs the playbook's benign-twin (FP) checks - always, on every match,
  3. decides TRUE_POSITIVE / FALSE_POSITIVE / ambiguous (ambiguous goes to the LLM judge),
  4. renders summary, impact, gaps and actions from templates (no LLM needed for known attacks).
Every cited event id comes from the evidence index, so citations are valid by construction.
"""
from __future__ import annotations

import string
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from ..patterns import (RESTRICTED_PORTS, is_exec_download, is_sql_like, is_sqli_strict, is_xss)
from ..ti import KnowledgeBase, domain_of, is_external_domain
from ..util import Config, hms, parse_ts

SCRIPT_PROCS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe"}


MISSING = "⟨?⟩"   # unmistakable marker; tests assert it never appears in a rendered report


class SafeDict(dict):
    def __missing__(self, key):
        return MISSING


def render(tpl: str, vars_: dict) -> str:
    return string.Formatter().vformat(tpl, (), SafeDict(vars_))


# ---------------------------------------------------------------------------------------------
@dataclass
class Ctx:
    kb: KnowledgeBase
    ti: dict[tuple[str, str], dict]          # (type, entity) -> TI verdict
    cfg: Config

    def ioc_domain(self, event: dict) -> bool:
        d = domain_of(event)
        v = self.ti.get(("domain", d)) if d else None
        return bool(v and v["verdict"] == "known_malicious")


def _p_scan_probe(e, c): return (e["source_type"] == "NETWORK" and e["action"] == "SCAN") or e["action"] == "SCAN_DETECTED"
def _p_recon_probe(e, c): return _p_scan_probe(e, c) or (e["source_type"] == "FIREWALL" and e["action"] in ("BLOCK", "DROP"))
def _p_restricted_block(e, c): return e["source_type"] == "FIREWALL" and e["action"] == "BLOCK" and e.get("dst_port") in RESTRICTED_PORTS
def _p_endpoint_script(e, c): return (e["source_type"] == "ENDPOINT" and e["action"] == "PROCESS_EXECUTION"
                                      and str(e["ext"].get("process_name", "")).lower() in SCRIPT_PROCS)
def _p_suspicious_command(e, c): return bool(c.kb.match_command(e.get("ext", {}).get("command_line")))
def _p_ioc_contact(e, c): return e["source_type"] == "HTTP" and c.ioc_domain(e)


PREDICATES = {
    "scan_probe": _p_scan_probe, "recon_probe": _p_recon_probe, "restricted_block": _p_restricted_block,
    "endpoint_script": _p_endpoint_script, "suspicious_command": _p_suspicious_command,
    "ioc_contact": _p_ioc_contact,
    "exec_download": lambda e, c: is_exec_download(e), "sql_like": lambda e, c: is_sql_like(e),
    "sqli_strict": lambda e, c: is_sqli_strict(e), "xss": lambda e, c: is_xss(e),
}


# ---------------------------------------------------------------------------------------------
@dataclass
class StageResult:
    name: str
    events: list[dict]
    support: list[dict] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    desc: str = ""

    @property
    def ids(self) -> list[str]:
        return [e["event_id"] for e in sorted(self.events + self.support, key=lambda x: (x["timestamp"], x["event_id"]))]


@dataclass
class PlaybookMatch:
    name: str
    spec: dict
    stages: dict[str, StageResult]
    vars: dict = field(default_factory=dict)
    flags: dict = field(default_factory=dict)
    context_events: dict[str, list[dict]] = field(default_factory=dict)

    @property
    def attack_events(self) -> list[dict]:
        seen: dict[str, dict] = {}
        for s in self.stages.values():
            for e in s.events + s.support:
                seen[e["event_id"]] = e
        return sorted(seen.values(), key=lambda e: (e["timestamp"], e["event_id"]))


def _ts(e: dict) -> datetime:
    return parse_ts(e["timestamp"])


def _select(events: list[dict], sel: dict, ctx: Ctx) -> list[dict]:
    out = []
    pred = PREDICATES.get(sel.get("predicate")) if sel.get("predicate") else None
    for e in events:
        if sel.get("source_type") and e["source_type"] not in sel["source_type"]:
            continue
        if sel.get("action") and e["action"] not in sel["action"]:
            continue
        if pred and not pred(e, ctx):
            continue
        out.append(e)
    return sorted(out, key=lambda e: (e["timestamp"], e["event_id"]))


def _largest_group(events: list[dict], fields: list[str]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in events:
        groups[tuple(e.get(f) for f in fields)].append(e)
    return max(groups.values(), key=len) if groups else []


def _distinct_window(events: list[dict], mode: str, n: int) -> list[dict]:
    seen: set = set()
    before: list[dict] = []
    frm: list[dict] = []
    reached = False
    for e in sorted(events, key=lambda x: (x["timestamp"], x["event_id"])):
        seen.add(e.get("dst_port"))
        if not reached and len(seen) >= n:
            reached = True
        (frm if reached else before).append(e)
    return before if mode == "before" else frm


# ---------------------------------------------------------------------------------------------
def _short(s: str, n: int = 60) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _join(vals, k: int = 3, sep: str = "; ") -> str:
    vals = list(dict.fromkeys(v for v in vals if v not in (None, "")))
    more = f" (+{len(vals) - k} more)" if len(vals) > k else ""
    return sep.join(str(v) for v in vals[:k]) + more


def stage_vars(events: list[dict], support: list[dict], kb: KnowledgeBase) -> dict:
    ev = sorted(events, key=lambda e: e["timestamp"])
    if not ev:
        return {"n": 0}
    ports = sorted({e["dst_port"] for e in ev if e.get("dst_port") is not None})
    gaps = [(_ts(b) - _ts(a)).total_seconds() for a, b in zip(ev, ev[1:])]
    sup = sorted(support, key=lambda e: e["timestamp"])
    ext = [e.get("ext", {}) for e in ev]
    payloads = []
    for e in ev:
        x = e.get("ext", {})
        if e["source_type"] == "HTTP":
            body = x.get("request_body") or ""
            q = urlparse(str(x.get("url") or "")).query
            payloads.append(_short(body or q or x.get("url") or "", 55))
    return {
        "n": len(ev), "t0": hms(ev[0]["timestamp"]), "t1": hms(ev[-1]["timestamp"]),
        "ports": _join(ports, 14, ", "), "ports_n": len(ports), "ports_list": ports,
        "urls": _join([(f"{x['host']}{x['url']}" if str(x.get("url", "")).startswith("/") and x.get("host") else x.get("url"))
                       for x in ext], 3), "domains": _join([domain_of(e) for e in ev if domain_of(e)], 4, ", "),
        "payloads": _join([f"“{p}”" for p in payloads], 4),
        "methods": _join([x.get("method") for x in ext], 3, "/"),
        "statuses": _join([x.get("status_code") for x in ext], 4, ", "),
        "content_types": _join([x.get("content_type") for x in ext], 2, ", "),
        "sizes": _join([x.get("response_size") for x in ext], 3, ", "),
        "cmds": _join([x.get("command_line") for x in ext], 3),
        "procs": _join([x.get("process_name") for x in ext], 3, ", "),
        "parents": _join([x.get("parent_process") for x in ext], 2, ", "),
        "files": _join([x.get("file_path") for x in ext], 2),
        "hashes": _join([x.get("file_hash") for x in ext], 2, ", "),
        "gap": round(sum(gaps) / len(gaps)) if gaps else 0,
        "support_t0": hms(sup[0]["timestamp"]) if sup else "",
        "support_files": _join([e.get("ext", {}).get("file_path") for e in sup], 2),
        "support_n": len(sup),
    }


# ---------------------------------------------------------------------------------------------
class PlaybookEngine:
    def __init__(self, cfg: Config, kb: KnowledgeBase):
        self.cfg, self.kb = cfg, kb
        self.playbooks: dict[str, dict] = cfg["playbooks"]
        self.fp_labels: dict[str, dict] = cfg["fp_labels"]
        self.order = sorted(self.playbooks, key=lambda n: -self.playbooks[n].get("priority", 0))

    def get(self, name: str) -> dict | None:
        return self.playbooks.get(name)

    # ---- matching -----------------------------------------------------------------------------
    def match(self, events: list[dict], ti_verdicts: list[dict], agents: set[str] | None = None) -> PlaybookMatch | None:
        ctx = Ctx(self.kb, {(v["type"], v["entity"]): v for v in ti_verdicts}, self.cfg)
        for name in self.order:
            spec = self.playbooks[name]
            if agents and spec["agent"] not in agents:
                continue
            m = self._try(name, spec, events, ctx)
            if m:
                return m
        return None

    def _try(self, name: str, spec: dict, events: list[dict], ctx: Ctx) -> PlaybookMatch | None:
        results: dict[str, StageResult] = {}
        deferred = []
        for st in spec["stages"]:
            if st.get("before"):
                deferred.append(st)
                continue
            if not self._stage(st, events, ctx, results):
                if not st.get("optional"):
                    return None
        for st in deferred:
            if not self._stage(st, events, ctx, results, results.get(st["before"])):
                if not st.get("optional"):
                    return None
        if "min_distinct_ports" in spec:
            ports = {e.get("dst_port") for r in results.values() for e in r.events}
            if len(ports - {None}) < spec["min_distinct_ports"]:
                return None
        ordered = {st["name"]: results[st["name"]] for st in spec["stages"] if st["name"] in results}
        return PlaybookMatch(name, spec, ordered)

    def _stage(self, st: dict, events: list[dict], ctx: Ctx, results: dict, before_stage=None) -> bool:
        evs = _select(events, st["select"], ctx)
        if st.get("distinct_ports"):
            evs = _distinct_window(evs, st["distinct_ports"]["mode"], st["distinct_ports"]["n"])
        if st.get("after") and st["after"] in results:
            ref_end = max(_ts(e) for e in results[st["after"]].events)
            evs = [e for e in evs if _ts(e) >= ref_end]
        elif st.get("after"):
            return False
        if before_stage is not None:
            ref_start = min(_ts(e) for e in before_stage.events)
            evs = [e for e in evs if _ts(e) <= ref_start]
        if st.get("same"):
            evs = _largest_group(evs, st["same"])
        if st.get("first_only"):
            evs = evs[:1]
        if len(evs) < st.get("min", 1):
            return False
        support: list[dict] = []
        if st.get("supporting"):
            sp = st["supporting"]
            cand = _select(events, sp["select"], ctx)
            ref_end = max(_ts(e) for e in evs)
            cand = [e for e in cand if _ts(e) >= ref_end]
            if sp.get("same_user", True) and evs and evs[0].get("user"):
                same_user = [e for e in cand if e.get("user") == evs[0]["user"]]
                cand = same_user or cand
            support = cand[:1] if sp.get("first_only", True) else cand
        results[st["name"]] = StageResult(st["name"], evs, support, st.get("mitre", []))
        return True

    # ---- variables / templating ---------------------------------------------------------------
    def build_vars(self, m: PlaybookMatch, bundle_events: list[dict]) -> None:
        ev = m.attack_events
        base = self._base(ev)
        per_stage: dict[str, dict] = {}
        for sname, sr in m.stages.items():
            sv = stage_vars(sr.events, sr.support, self.kb)
            per_stage[sname] = sv
            base.update({f"{sname}_{k}": val for k, val in sv.items()})
        # cross-stage derived variables
        ports = sorted({e["dst_port"] for e in ev if e.get("dst_port") is not None})
        notes = []
        for p in ports:
            info = self.kb.port(p)
            if info and info.get("note") and (p in RESTRICTED_PORTS or p == 8448):
                cve = f" ({', '.join(info['cves'])})" if info.get("cves") else ""
                notes.append(f"Port {p} ({info['service']}): {info['note']}{cve}.")
        base["port_notes"] = " ".join(notes) or "No restricted-service associations in the local port intelligence."
        base["risky_ports"] = ", ".join(str(p) for p in ports if p in RESTRICTED_PORTS) or "the probed ports"
        if ev:
            base["t0"], base["t1"] = hms(ev[0]["timestamp"]), hms(ev[-1]["timestamp"])
        base["n_ports"] = len(ports)
        base["all_ports"] = _join(ports, 12, ", ")
        if ev:
            d = (_ts(ev[-1]) - _ts(ev[0])).total_seconds()
            base["duration"] = f"{int(d // 60)}m {int(d % 60)}s" if d >= 60 else f"{int(d)}s"
        ac, cf = m.stages.get("account_compromise"), m.stages.get("credential_attack")
        base["success_short"] = ""
        if ac:
            base["success_short"] = f", then a successful login at {base['account_compromise_t0']} UTC"
        elif cf and cf.support:
            base["success_short"] = f", then a successful login at {base['credential_attack_support_t0']} UTC"
        if ac and cf:
            base["lag"] = round((_ts(ac.events[0]) - _ts(cf.events[-1])).total_seconds())
        base["n_domains"] = len({domain_of(e) for e in ev if is_external_domain(domain_of(e))})
        m.vars = base
        m.flags = self._flags(m, bundle_events)
        for sname, sr in m.stages.items():
            st = next(s for s in m.spec["stages"] if s["name"] == sname)
            sv = dict(per_stage[sname])
            sv["support_clause"] = render(st["support_text"], sv) if sr.support and st.get("support_text") else ""
            sr.desc = render(st["desc"], {**m.vars, **sv})

    def _base(self, ev: list[dict]) -> dict:
        src = Counter(e.get("src_ip") for e in ev if e.get("src_ip")).most_common(1)
        usr = Counter(e.get("user") for e in ev if e.get("user")).most_common(1)
        hst = Counter(e.get("host") for e in ev if e.get("host")).most_common(1)
        dst = Counter(e.get("dst_ip") for e in ev if e.get("dst_ip")).most_common(1)
        svc = next((e["ext"].get("service") for e in ev if e["source_type"] == "AUTH"), None)
        return {"src_ip": src[0][0] if src else "?", "user": usr[0][0] if usr else "?",
                "host": hst[0][0] if hst else "?", "dst_ip": dst[0][0] if dst else "?",
                "service": (svc.upper() if svc == "ssh" else svc or "login")}

    def _flags(self, m: PlaybookMatch, bundle_events: list[dict]) -> dict:
        inj = m.stages.get("web_input_injection") or m.stages.get("script_injection_attempt")
        flags = {"injection_succeeded": bool(inj and any(
            e["ext"].get("status_code") == 200 and (is_sqli_strict(e) or is_xss(e)) for e in inj.events))}
        self._link_flags(m, flags)
        ac = m.stages.get("account_compromise")
        if ac:
            t_ok = _ts(ac.events[0])
            post = [e for e in bundle_events if e.get("src_ip") == m.vars.get("src_ip") and _ts(e) > t_ok
                    and e["event_id"] not in {x["event_id"] for x in m.attack_events}]
            if post:
                m.context_events["post_login"] = post
                cnt = Counter(f"{e['source_type']} {e['action']}" for e in post)
                m.vars["post_login_n"] = len(post)
                m.vars["post_login_summary"] = ", ".join(f"{n}x {k}" for k, n in cnt.most_common(4))
                flags["post_login_activity"] = True
        return flags

    def _link_flags(self, m: PlaybookMatch, flags: dict) -> None:
        """How strongly is the execution tied to the download? (never claim more than the logs show)"""
        dl = m.stages.get("malware_download") or m.stages.get("suspicious_download")
        ex = m.stages.get("endpoint_execution")
        if not (dl and ex):
            return
        url = str(dl.events[0]["ext"].get("url") or "")
        url_file = urlparse(url).path.rsplit("/", 1)[-1]
        m.vars["url_file"] = url_file
        run_names = {str(e["ext"].get("process_name", "")).lower() for e in ex.events}
        flags["name_match"] = url_file.lower() in run_names
        drops = [e for e in dl.support if e["action"] == "FILE_CREATED"]
        if drops:
            drop_file = str(drops[0]["ext"].get("file_name") or drops[0]["ext"].get("file_path") or "")
            drop_file = drop_file.replace("\\", "/").rsplit("/", 1)[-1]
            m.vars["drop_file"] = drop_file
            flags["name_mismatch"] = url_file.lower() != drop_file.lower()
            dh = {e["ext"].get("file_hash") for e in drops} - {None}
            xh = {e["ext"].get("file_hash") for e in ex.events} - {None}
            flags["hash_match"] = bool(dh & xh)

    def cond_ok(self, when: str | None, m: PlaybookMatch) -> bool:
        if not when:
            return True
        neg = when.startswith("!")
        key = when.lstrip("!")
        val = key in m.stages or bool(m.flags.get(key))
        return (not val) if neg else val

    def render_list(self, items: list, m: PlaybookMatch) -> list[str]:
        out = []
        for it in items:
            text, when = (it, None) if isinstance(it, str) else (it["text"], it.get("when"))
            if self.cond_ok(when, m):
                out.append(render(text, m.vars))
        return out


# ---------------------------------------------------------------------------------------------
# FP / benign-twin checks. Each returns (passed, detail). A passing check is POSITIVE evidence of
# a benign explanation (not mere absence of attack evidence).
def _first_ts(m: PlaybookMatch) -> str:
    return m.attack_events[0]["timestamp"]


def chk_in_pentest_schedule(m, kb, ctx):
    src = m.vars["src_ip"]
    p = kb.pentest(src, _first_ts(m))
    if p:
        return True, f"{src} is in pentest schedule {p['ticket']} and the activity falls inside its window ({p['window_start'][11:19]}-{p['window_end'][11:19]} UTC)."
    return False, f"{src} is not in the pentest schedule for this time."


def chk_scanner_allowlist(m, kb, ctx):
    s = kb.scanner(m.vars["src_ip"])
    return (True, f"{m.vars['src_ip']} is on the internal-scanner allowlist (owner {s['owner']}).") if s else \
           (False, f"{m.vars['src_ip']} is not on the internal-scanner allowlist.")


def chk_internal_scan(m, kb, ctx):
    evs = [e for s in m.stages.values() for e in s.events]
    ok = bool(evs) and all(e["ext"].get("source_zone") == "INTERNAL" and e["ext"].get("destination_zone") == "INTERNAL"
                           and e["ext"].get("destination_host") == "INTERNAL-SERVICE" for e in evs)
    return ok, ("All probes are internal-zone to INTERNAL-SERVICE traffic." if ok else
                "Probes arrive from the INTERNET zone against exposed hosts, not internal-to-internal.")


def chk_known_service_account_ip(m, kb, ctx):
    user, src = m.vars["user"], m.vars["src_ip"]
    info = kb.user_info(user)
    recon = "reconnaissance" in m.stages
    if info["in_inventory"] and src in info["known_ips"] and not recon:
        return True, f"{src} is one of {len(info['known_ips'])} known source IPs for service account '{user}' and no recon preceded the logins."
    why = ("'%s' is not an inventoried service account" % user) if not info["in_inventory"] else \
          (f"{src} is not a known source for '{user}'" if src not in info["known_ips"] else "reconnaissance preceded the logins")
    return False, why + "."


def chk_internal_source_zone(m, kb, ctx):
    evs = m.stages["credential_attack"].events if "credential_attack" in m.stages else []
    ok = bool(evs) and all(e["ext"].get("source_zone") == "INTERNAL" for e in evs)
    return ok, ("The failed logins originate from the INTERNAL zone." if ok else
                "The failed logins originate from the INTERNET zone (external source).")


def chk_service_account(m, kb, ctx):
    user = m.vars["user"]
    info = kb.user_info(user)
    return (info["in_inventory"], (f"'{user}' is an inventoried service account." if info["in_inventory"]
                                   else f"'{user}' is an interactive user, not an inventoried service account."))


def chk_internal_docs_site(m, kb, ctx):
    evs = [e for s in m.stages.values() for e in s.events]
    ok = bool(evs) and all(kb.internal_site(e["ext"].get("host")) for e in evs)
    return ok, ("Requests target the internal documentation wiki (docs.internal)." if ok else
                f"Requests target {_join([e['ext'].get('url') for e in evs], 2)}, a business application endpoint, not the docs wiki.")


def chk_benign_query_response(m, kb, ctx):
    evs = [e for s in m.stages.values() for e in s.events]
    ok = bool(evs) and all(e["ext"].get("method") == "GET" and e["ext"].get("status_code") == 200
                           and (e["ext"].get("response_size") or 0) < 5000 for e in evs)
    return ok, ("Every request is a GET with HTTP 200 and a normal-sized response." if ok else
                f"Requests are {_join([e['ext'].get('method') for e in evs], 2, '/')} with HTTP "
                f"{_join([e['ext'].get('status_code') for e in evs], 3, ', ')} (errors/odd responses), not ordinary page loads.")


def chk_no_sql_syntax(m, kb, ctx):
    evs = [e for s in m.stages.values() for e in s.events]
    hits = [e for e in evs if is_sqli_strict(e)]
    return (not hits and bool(evs)), (f"No tautology, UNION SELECT, comment terminator or time-delay syntax in {len(evs)} request(s); the keyword stands alone."
                                      if not hits else f"{len(hits)} request(s) carry SQL injection syntax.")


def chk_read_only_admin(m, kb, ctx):
    evs = [e for s in m.stages.values() for e in s.events]
    ok = bool(evs) and all(kb.is_benign_command(e["ext"].get("command_line")) for e in evs)
    return ok, ("Every command is a read-only inventory cmdlet (Get-Process/Service/HotFix), no encoding or script host."
                if ok else f"Commands include non-inventory / obfuscated execution: {_join([e['ext'].get('command_line') for e in evs], 3)}.")


def chk_no_malicious_artifacts(m, kb, ctx):
    evs = [e for s in m.stages.values() for e in s.events]
    bad = [e for e in evs if kb.match_command(e["ext"].get("command_line")) or kb.match_path(e["ext"].get("file_path"))
           or e["ext"].get("file_hash")]
    return (not bad and bool(evs)), ("No malicious command pattern, staging path or file hash is associated with these executions."
                                     if not bad else f"{len(bad)} execution(s) match malicious patterns or carry a file hash/staging path.")


FP_CHECKS = {
    "in_pentest_schedule": chk_in_pentest_schedule, "src_ip_in_scanner_allowlist": chk_scanner_allowlist,
    "internal_to_internal_scan": chk_internal_scan, "known_service_account_ip": chk_known_service_account_ip,
    "internal_source_zone": chk_internal_source_zone, "service_account": chk_service_account,
    "internal_docs_site": chk_internal_docs_site, "benign_query_response": chk_benign_query_response,
    "no_sql_syntax": chk_no_sql_syntax, "read_only_admin_commands": chk_read_only_admin,
    "no_malicious_artifacts": chk_no_malicious_artifacts,
}


DECISIVE = {"in_pentest_schedule", "src_ip_in_scanner_allowlist"}


@dataclass
class Decision:
    verdict: str                 # TRUE_POSITIVE | FALSE_POSITIVE | AMBIGUOUS
    confidence: float
    label: str | None            # FP label when FALSE_POSITIVE
    checks: list[dict]
    n_pass: int
    strong: bool
    confirmed_by: list[str]


def decide(m: PlaybookMatch, engine: PlaybookEngine, ctx: Ctx, fp_min_pass: int) -> Decision:
    kb = engine.kb
    checks = []
    for spec in m.spec.get("fp_checks", []):
        ok, detail = FP_CHECKS[spec["check"]](m, kb, ctx)
        checks.append({"check": spec["check"], "passed": ok, "detail": detail, "label": spec["label"]})
    n_pass = sum(c["passed"] for c in checks)
    # authoritative evidence (change-managed pentest window / owned scanner) is decisive on its own
    decisive = any(c["passed"] and c["check"] in DECISIVE for c in checks)
    n_eff = n_pass + (fp_min_pass if decisive else 0)
    confirmed_by = [c for c in m.spec.get("confirm", []) if any(PREDICATES[c](e, ctx) for s in m.stages.values() for e in s.events)]
    strong = bool(confirmed_by)
    passed_labels = [c["label"] for c in checks if c["passed"]]
    label = None
    if passed_labels:
        # pentest wins over scanner when both apply; else the most frequent label
        label = "FP_AUTHORIZED_PENTEST" if "FP_AUTHORIZED_PENTEST" in passed_labels else Counter(passed_labels).most_common(1)[0][0]
    if n_eff >= fp_min_pass and not strong:
        return Decision("FALSE_POSITIVE", min(0.95, 0.60 + 0.10 * n_pass), label, checks, n_pass, strong, confirmed_by)
    if n_pass == 0:
        conf = 0.75 + (0.08 if strong else 0.0) + (0.04 if "account_compromise" in m.stages else 0.0)
        ti_bad = any(v["verdict"] == "known_malicious" for v in ctx.ti.values())
        conf += 0.04 if ti_bad else 0.0
        return Decision("TRUE_POSITIVE", min(0.95, conf), None, checks, n_pass, strong, confirmed_by)
    return Decision("AMBIGUOUS", 0.5, label, checks, n_pass, strong, confirmed_by)
