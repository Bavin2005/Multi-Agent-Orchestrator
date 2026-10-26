# Multi-Agent SIEM Orchestrator — Detailed Implementation

Status as of 26 Oct 2026. This document describes what is **actually built** in this repository, how each part
works, and where it differs from the two design documents (`SIEM_Orchestrator_Technical_System_Flow.pdf`,
`SIEM_Full_System_Implementation_Plan.pdf`). `README.md` is the short usage guide; this is the reference.

Contents: 1 Scope · 2 Architecture · 3 Layout · 4 Data layer · 5 Orchestrator (Stages 2–8) · 6 Agent layer (Stage 9) ·
7 Playbook catalogue · 8 Risk scoring · 9 Reporting · 10 Feedback · 11 Knowledge base · 12 LLM layer · 13 Configuration ·
14 Evaluation · 15 Testing · 16 Plan-phase status · 17 Limitations · 18 Operating and extending

---

## 1. Scope

**Input:** a stream of SIEM alerts (`data/SIEM_Alerts.csv`) plus the runtime event log they point into
(`data/SIEM_Events_For_Runtime.csv`).
**Output:** one cited PoC report per incident version stating *real attack or false alarm*, the reconstructed attack
timeline, threat intel, impact, gaps, recommended actions, a risk level, and the real log lines as evidence.
**Human in the loop:** a SOC analyst confirms or rejects each report (Stage 13); only confirmed outcomes are reused.

Fixed design principles (all enforced in code or tests):

1. The orchestrator is deterministic code + config; the LLM is only a fallback.
2. Agents are pattern-first: configured playbooks build the timeline; the LLM runs only when no playbook matches or the
   false-positive (FP) check is ambiguous.
3. Every claim cites event IDs that exist in the evidence index, or it is rejected/retried.
4. The FP check always runs, on every playbook match.
5. Ground-truth files are opened only by `soc/grader.py` (a test fails if any other module references them).

## 2. Architecture

```
 SIEM_Alerts.csv ─┐                                   ┌──────────── knowledge/ (TI, assets, allowlists, reference attacks)
 Events CSV ──────┤ adapter ──► alerts (doc shape)    │
                  │          └► LogStore (time-indexed, as_of bounded)
                  ▼
        replay (simulated clock, 1 alert at a time, sweep every 15 s)
                  ▼
 ┌────────────────────────── ORCHESTRATOR (deterministic) ───────────────────────────┐
 │ ingest: 3 validate/dedupe → 4 classify → 5 group (src_ip) → 6 ready check          │
 │ tick:   quiet-period timers → 7a owner → 7b TI enrich → 8 dispatch bundle          │
 └───────────────────────────────────────┬────────────────────────────────────────────┘
                                         ▼
 ┌───────────── OWNER AGENT (LangGraph) — network_agent | app_endpoint_agent ──────────┐
 │ preprocess → playbook → memory → [llm] → fp_check → validate ⟲(retry ≤2) → finalize│
 │      tools (read-only, 5 calls / 60 s): get_related_logs, ti_lookup, get_asset_info,│
 │                                          consult_agent, get_playbook                 │
 └───────────────────────────────────────┬────────────────────────────────────────────┘
                                         ▼
 ┌──────────────── ORCHESTRATOR (reporting, code only) ───────────────────┐
 │ 10 evidence assembly → 11 risk score → 12 PoC report (JSON/MD/HTML)     │
 └───────────────────────────────────────┬─────────────────────────────────┘
                                         ▼
        SOC analyst (Stage 13) → case memory / allowlists      grader (separate) → scorecard
```

The system is one synchronous Python process. Time is **log time**: the clock is driven by alert/event timestamps,
never wall-clock, so runs are deterministic and fast-forwardable.

## 3. Repository layout

```
config/
  config.yaml          all tunable parameters
  routing.yaml         domain routing patterns, allowed actions per source, required fields
  evidence_rules.yaml  Stage 6 minimum-evidence rules
  playbooks.yaml       playbooks + FP labels (the attack/benign knowledge)
knowledge/             assets.json  allowlists.json  ioc.json  reference_attacks.json
data/                  the four supplied CSVs
soc/
  util.py adapter.py validate.py classify.py incidents.py readiness.py ti.py
  orchestrator.py replay.py tools.py memory.py risk.py report.py feedback.py
  llm.py sanitize.py patterns.py store.py grader.py cli.py
  agents/ engine.py (playbooks) owner.py (LangGraph) findings.py
scripts/               build_kb.py  ablation.py
tests/                 conftest.py test_pipeline.py test_edge_cases.py test_feedback_llm.py
run.py                 CLI entry         runs/ outputs        state/ case_memory.db
```

## 4. Data layer

### 4.1 Adapter (`soc/adapter.py`)

The dataset is flat CSV, not the doc's JSONL. The adapter rebuilds the doc's alert shape:

```
alert = {alert_id, alert_time, siem_rule_id, siem_rule_name, siem_groups[], siem_severity(int),
         siem_severity_label, description, event}
event = {event_id, timestamp, source_type, src_ip, dst_ip, src_port, dst_port, user, host, action, ext{…}, raw}
```

* `ext` is built per `source_type` (NETWORK flow fields, FIREWALL rule/zones, AUTH service/zones, HTTP method/url/
  status/body/size, ENDPOINT process/command/hash/path) with CSV numbers normalised (`"200.0"` → `200`).
* `raw` is the compact `k=v` line of every non-empty CSV column — this is what the evidence appendix prints.
* **Severity text → number** via `severity_map` (LOW 3, MEDIUM 6, HIGH 10, CRITICAL 13) so the doc's `>= 8` trigger works.
* **`alert_time` is clamped to ≥ the event timestamp** (the CSV truncates seconds, so some alerts precede their own event).
* Alerts are sorted by `(alert_time, alert_id)`.

### 4.2 LogStore

Events indexed by `src_ip`, `user`, `host` (sorted `(timestamp, event_id)` lists, bisect lookups).
`query(entity, start, end, kind, as_of)` clamps `end` to `as_of`, so **no component can see events from the simulated
future** (tested). This is how agents read raw events that never produced an alert (e.g. the `LOGIN_SUCCESS` 16 s after a
brute-force alert, the other three SQLi payloads, the malware `FILE_CREATED`).

## 5. Orchestrator (`soc/orchestrator.py`)

### 5.1 `ingest(alert, arrival)` — Stages 3–6

| Step | Module | Behaviour |
|---|---|---|
| 3 validate | `validate.py` | required core/event fields, timestamps parse, `source_type` known, `action` allowed for it, numeric severity. Failure → dead-letter row with reason (never raises). Repeated `alert_id` → dropped and counted (not dead-lettered). |
| 4 classify | `classify.py` | (1) `routing.yaml` patterns: `source_type` first, then `siem_groups`; (2) LLM classifier only if no pattern matches (fixed labels + confidence); (3) confidence < 0.7 or `unknown` → human-review queue, **never forced onto an agent**. AUTH is network-domain. |
| 5 group | `incidents.py` | key = `src_ip` (fallback `user`, then `host`, else the alert itself). Attach if the event time is inside `[first_seen − w, last_seen + w]`, `w` = max window of the incident's domains (network 30 min, app_endpoint 10 min). Shared users/hosts never merge incidents. Attaching to a DISPATCHED/CLOSED incident → `version += 1`, status READY (revision). |
| 6 ready | `readiness.py` | triggers: **severity ≥ 8**; **end signal** (LOGIN_SUCCESS after failures, PROCESS_EXECUTION, FILE_DOWNLOAD, HTTP 200 on a payload); **evidence rule met** (count / distinct / sequence / match from `evidence_rules.yaml`). Rules are evaluated over the incident's alert events **plus runtime events already visible at "now"** (so a port sweep's 10 probes count even though only the 10th raised an alert). |

Timelines are always ordered by event timestamp, never arrival order (tested with reversed arrival).

### 5.2 `tick(now)` — dispatch timing (Stages 7–8)

The doc's "wait for the 10/30-minute window" is replaced (per your decision "don't wait for logs to fill") by quiet-period
timers, measured in event time and checked every `sweep_interval_s` (15 s):

| Situation | Dispatch when |
|---|---|
| a ready trigger fired | no new alert for **60 s** (`debounce_s`) |
| no trigger | no new alert for **120 s** (`idle_s`) |
| alerts keep arriving | `hold_start + 300 s` (`max_wait_s`) regardless |
| alert arrives after dispatch | new version READY; dispatched after another 60 s (`hold_start` resets) |

Measured: HIGH-severity incidents dispatch in < 120 s of the first event; no-trigger incidents in ≤ 150 s (a test asserts a fixed bound
so config changes can't make it vacuous).

### 5.3 `_dispatch(inc, now)` — Stages 7a, 7b, 8

1. **Owner (`owner_for`)**: each alert scores a stage rank by source (`ENDPOINT 3 > HTTP 2 > AUTH/NETWORK/FIREWALL 1`); the
   highest rank wins (ties → higher severity, then later alert). Rank → domain: 3,2 → `app_endpoint`, 1 → `network`.
   Other-domain alerts stay in the bundle tagged with their domain.
2. **Evidence set**: the incident's alert events ∪ `LogStore.query(entity, first_seen − 30 min, now, as_of=now)`.
3. **TI enrichment** (`ThreatIntelAgent.enrich`): every external IP/domain/URL/hash plus users and hosts; internal entities resolve
   against inventory/allowlists. Results cached 24 h (log time). If the KB fails to load, the bundle records
   `ti.available = false` and the report states it.
4. **Bundle** passed to the agent: `incident_id, version, domains, alerts (event-time order, domain-tagged), alert_event_ids, events,
   event_domain, entities, ready_reasons, ti{available, verdicts, artifacts}, primary_entity, owner, dispatched_at`.
5. A fresh `ToolBox` (budget 5 calls / 60 s) and the owner agent run; then Stages 10–12 run in the orchestrator.

State persists to `runs/<id>/state.db` (SQLite: `incidents`, `dead_letter`, `human_review`, `reports`). Counters live in
`orch.metrics` and are written to `results.json`.

### 5.4 Replay (`soc/replay.py`)

Feeds alerts one at a time in arrival order, advancing the simulated clock in 15 s steps between alerts so timers fire exactly as
live. `--speed N` sleeps `Δt/N`; `--shuffle-within S` delays ~30% of alerts by 1–S s (seeded) to test out-of-order arrival;
`--limit N` truncates. At end of stream `flush()` keeps sweeping until nothing is pending. The replayer receives alerts only.

## 6. Agent layer (`soc/agents/`)

Two `OwnerAgent` instances (`network` → `network_agent`, `app_endpoint` → `app_endpoint_agent`) share one engine; the Threat
Intelligence agent is an enrichment stage in `ti.py`, never an owner.

### 6.1 LangGraph pipeline (`owner.py`)

```
preprocess → playbook → memory ─┬─(match)──────────────► fp_check → validate ─┬─► finalize
                                └─(no match)► llm ──────►     ▲              │
                                                              └── llm ◄───────┘ (errors, path=llm, retries ≤ 2)
```

| Node | What it does |
|---|---|
| `preprocess` | sort by time, dedupe, build the **evidence index** `event_id → {event, via(alert/log_store), domain}` |
| `playbook` | `PlaybookEngine.match` over all events; build variables/templated text; tool calls: `get_asset_info(host)` always; `consult_agent(other_domain, slice)` when the playbook declares `consult` and the incident spans both domains (multi-stage → network agent analyses the auth events) |
| `memory` | fingerprint `{attack_type, stages, ports}`; hints with similarity ≥ 0.85 (top 3) and "related" 0.5–0.85 (top 2) |
| `llm` | only if no playbook; prompt = rules + schema + sanitised data fence; optional bounded tool-request loop (≤ 2 rounds, within the 5-call budget); tool-returned events join the index so they are citable |
| `fp_check` | playbook path: run the playbook's checks and `decide()`; ambiguous → LLM judge. LLM path: allowlist/pentest override (authoritative evidence beats the model) |
| `validate` | every stage must cite ≥ 1 event; every cited id must be in the index; failures loop back to `llm` with the reason, max 2 retries, then `needs_human` |
| `finalize` | adds memory hints, consultations, tool log, fingerprint, `needs_human`, `first_pass_valid`, `retries` |

Failure handling: tool budget exceeded → partial findings, `needs_human`; LLM error → verdict `UNDETERMINED`, `needs_human`;
citations still invalid after 2 retries → invalid citations stripped, `needs_human`. None crash the run.

### 6.2 Playbook engine (`engine.py`)

A playbook (YAML) is an ordered list of stages. Per-stage keys:

| Key | Meaning |
|---|---|
| `select` | `source_type` list, `action` list, `predicate` (named function) — all must hold |
| `min` / `optional` | minimum events; optional stages may be absent |
| `same: [fields]` | keep only the largest group sharing those fields (e.g. `[src_ip, user]`) |
| `after: stage` / `before: stage` | event time ≥ end of / ≤ start of the referenced stage |
| `first_only` | keep just the earliest event (e.g. the first `LOGIN_SUCCESS`) |
| `supporting` | extra events cited under the stage (e.g. login success after the failures; `FILE_CREATED` after a download) |
| `distinct_ports: {mode: before/from, n}` | split a scan at the n-th distinct port (reconnaissance vs port_discovery) |

A playbook matches only if **all non-optional stages** are satisfied; the highest-`priority` match wins
(multi_stage 100 > malware 80 > port_scan 70 > sql_injection 60 > xss 55 > brute_force 50 > firewall 45 > endpoint 40 > ioc 30).
The timeline is built in code, so citations are valid by construction.

**Predicates** (`PREDICATES`): `scan_probe`, `recon_probe`, `restricted_block` (ports 23/135/139/445/3389), `endpoint_script`
(powershell/cmd/wscript/cscript/mshta/rundll32/regsvr32), `suspicious_command` (KB patterns), `ioc_contact` (domain TI =
known_malicious), `exec_download` (HTTP 200 + executable extension in URL), `sql_like` (broad), `sqli_strict`, `xss`.
`soc/patterns.py` holds the regexes; **SQL syntax is searched only in the query string and request body, never the URL path**
(a path like `/update` is not SQL — this was a real bug found during grading).

**Link flags** (`_link_flags`): reports never claim more than the logs show. For downloads: `name_match` (executed file name = URL file
name), `name_mismatch` (URL file ≠ dropped file), `hash_match` (dropped file hash = executed file hash). Malware reports state the
drop→execution link is proven by hash and the download→drop link is only timing/user/parent process when names differ.

**Templating**: stage descriptions, summary, impact, gaps and actions are `{variables}` rendered from the matched events
(`<stage>_n/_t0/_t1/_ports/_urls/_domains/_payloads/_cmds/_files/_hashes/…`, plus `src_ip user host service duration port_notes …`).
List items may carry `when: stage | !stage | flag` so text reflects what was actually seen (e.g. "No successful login observed" vs
"valid session obtained"). Missing variables render as `⟨?⟩`; a test asserts that marker never appears in any report.

### 6.3 FP checks and the verdict rule

Each check returns `(passed, detail)`; a pass is **positive** evidence of a benign explanation, and the detail sentence is written
for both outcomes (it becomes the report's reasoning).

| Check | Passes when |
|---|---|
| `in_pentest_schedule` *(decisive)* | src_ip listed in the pentest schedule and the first event is inside its window |
| `src_ip_in_scanner_allowlist` *(decisive)* | src_ip is an inventoried internal scanner |
| `internal_to_internal_scan` | all probes are INTERNAL zone → `INTERNAL-SERVICE` |
| `known_service_account_ip` | user is an inventoried service account, src_ip is one of its known IPs, and no recon preceded |
| `internal_source_zone` | failures originate from the INTERNAL zone |
| `service_account` | user is an inventoried service account |
| `internal_docs_site` | all requests target `docs.internal` |
| `benign_query_response` | all requests GET, HTTP 200, response < 5000 bytes |
| `no_sql_syntax` | no strict SQL-injection syntax in the requests |
| `read_only_admin_commands` | every command is a read-only inventory cmdlet (`Get-Process/Service/HotFix/…`) |
| `no_malicious_artifacts` | no malicious command/path pattern and no file hash |

`decide()` (n = passing checks; *decisive* adds `fp_min_pass` to n):

```
if n_eff >= fp_min_pass (2) and not strong_attack_evidence  → FALSE_POSITIVE   confidence = min(.95, .60 + .10·n)
elif n == 0                                                  → TRUE_POSITIVE    confidence = min(.95, .75 + .08·strong + .04·compromise + .04·TI-malicious)
else                                                         → AMBIGUOUS → LLM judge (both sides in the prompt)
```
`strong_attack_evidence` = a playbook `confirm` predicate hit (strict SQLi syntax, XSS markup, malicious command). A pentest
source running real attack syntax is therefore ambiguous, not auto-cleared.

FP findings use the benign stage name from `fp_labels` (`network_discovery`, `authentication_anomaly`, `web_request_review`,
`administrative_script_execution`, `unclassified_suspicious_activity`) and report `attack_type` as the FP label.

### 6.4 Tools (`tools.py`)

`get_related_logs(entity, window_min)`, `ti_lookup(entity)`, `get_asset_info(host_or_user)`, `consult_agent(domain, event_ids)`,
`get_playbook(name)`. All read-only, as-of-bounded. `ToolBox` enforces **5 calls and 60 s**; the 6th call raises `BudgetExceeded`.
`consult_agent` runs the other domain's playbook match + FP decision on the slice and returns `{playbook, verdict_hint, stages, note}`.

### 6.5 Case memory (`memory.py`)

SQLite `state/case_memory.db`, table `cases`, two kinds: **reference** (15 historical attacks/CVEs seeded from the KB) and **confirmed**
(SOC-confirmed incidents from Stage 13). Similarity = `0.5·[attack type] + 0.3·Jaccard(stages) + 0.2·Jaccard(ports)`; if either side has
no ports, that term is dropped and the rest renormalised. Both kinds are **hints only** — shown in the report and passed to the LLM,
never the verdict. Reference cases are hidden on benign verdicts; confirmed cases are shown on both.

## 7. Playbook catalogue (`config/playbooks.yaml`)

| Playbook | Owner | Stages (names match ground truth) | MITRE | FP checks |
|---|---|---|---|---|
| `multi_stage` | app | credential_attack → suspicious_download → endpoint_execution | T1110.001, T1105, T1204.002, T1059.003 | pentest |
| `malware_download_execution` | app | malware_download → endpoint_execution | T1105, T1204.002 | pentest |
| `port_scan` | network | reconnaissance → port_discovery | T1595.001, T1046 | pentest, scanner, internal-scan |
| `sql_injection` | app | web_input_injection | T1190 | docs site, benign response, no SQL syntax, pentest |
| `xss` | app | script_injection_attempt | T1059.007 | pentest |
| `brute_force` | network | (reconnaissance) → credential_attack → account_compromise | T1110.001, T1078 | known svc IP, internal zone, svc account, pentest |
| `firewall_policy_violation` | network | restricted_service_access_attempt | T1046, T1021 | pentest, scanner |
| `suspicious_endpoint_execution` | app | suspicious_process_execution | T1059.001/.003/.005, T1027 | read-only cmds, svc account, no artifacts, pentest |
| `malicious_indicator_contact` | app | malicious_indicator_contact | T1071.001, T1105 | pentest |
| *(none)* | either | LLM reconstruction → `unclassified_suspicious_activity` | — | pentest, scanner |

Thresholds differ from the doc because the data demands it: brute force **≥ 3** failures (the SIEM rule fires on 4; multi-stage has 3);
port scan **≥ 10** distinct ports; firewall violation **≥ 3** restricted-port blocks.

## 8. Risk scoring (`risk.py`)

```
risk = base(attack_type) + success_bonus + TI_score + asset_criticality − 4 × passing_FP_checks
levels: ≥ 11 CRITICAL · 8–10 HIGH · 4–7 MEDIUM · ≤ 3 LOW        (FALSE_POSITIVE verdict ⇒ capped at LOW)
```

| Term | Rule |
|---|---|
| base | PORT_SCAN 4 · BRUTE_FORCE 5 · SQL_INJECTION 7 · XSS 5 · FIREWALL_POLICY_VIOLATION 7 · SUSPICIOUS_ENDPOINT_EXECUTION 5 · MALICIOUS_IP_DOMAIN 6 · MALWARE_DOWNLOAD_EXECUTION 6 · MULTI_STAGE_ATTACK 8 · UNMAPPED 4 |
| success_bonus | +3 if a cited event is `LOGIN_SUCCESS`, `PROCESS_EXECUTION`, or HTTP 200 on a payload (executable download / XSS / strict SQLi) |
| TI_score | strongest external-indicator verdict: known malicious +2, suspicious +1, else 0 |
| asset_criticality | host inventory: production 2 (HOST-001…008), internal 1 (009…024; unknown hosts default 1), test 0 |

Worked example (brute force on a production host, login succeeded): `5 + 3 + 0 + 2 − 0 = 10 → HIGH`.
The bases were **calibrated so every class lands in the band the ground truth expects**; that is fitting to the answer key (see §14.3).
Same evidence always yields the same score (tested).

## 9. Reporting (`report.py`)

Stage 10 pulls each cited event's real `raw` line from the evidence index; Stage 12 fills one template with no extra LLM call.
Outputs per incident version: `reports/ORC-xxxx_vN.json | .md | .html`.

Sections: **Header** (incident/version/revision flag, owner agent, verdict, confidence, risk, attack type, alerts, `needs_human`) ·
**Summary** (one sentence) · **Attack timeline** (stage, UTC range, what happened, evidence ids, MITRE) ·
**False-positive assessment** (benign explanation, outcome, per-check table) · **Threat intelligence** (entity verdicts, suspicious
artifacts, historical attacks/CVEs, SOC-confirmed cases) · **Impact and gaps** (confirmed vs not shown) · **Recommended actions** (ordered) ·
**Risk scoring** (formula + per-term reasons) · **Evidence appendix** (real log lines, flagged alert vs log-store, cited-in stages) ·
**Processing path** (playbook/LLM, owner reason, dispatch reason, tool calls, consultations, citation first-pass/retries, LLM calls).

`runs/<id>/index.md` and `results.json` summarise the run.

## 10. Stage 13 feedback (`feedback.py`)

`python run.py verdict ORC-0002 CONFIRMED_ATTACK|CONFIRMED_FALSE_POSITIVE|NEEDS_INVESTIGATION [--note …] [--approve-allowlist]`

* Every call is appended to `runs/<id>/verdicts.json`.
* `CONFIRMED_*` → stored in case memory (fingerprint, verdict, summary) and surfaced as a hint on similar later incidents.
* `NEEDS_INVESTIGATION` → recorded, **not** reused.
* `CONFIRMED_FALSE_POSITIVE` → allowlist change is only **proposed** unless `--approve-allowlist`; applying edits `knowledge/*.json` (scanner list,
  pentest window, or a service account's known IPs) and keeps a `.bak`.
* Unconfirmed agent verdicts are never stored.

## 11. Knowledge base (`knowledge/`)

| File | Source | Content |
|---|---|---|
| `assets.json`, `allowlists.json` | **generated** by `scripts/build_kb.py` from observable event attributes only (never labels) | host tiers; 13 service accounts + known IPs; 5 internal scanners; 5 pentest windows (tickets CHG-PT-100x); `docs.internal` |
| `ioc.json` | hand-written | 3 simulated IOC domains with category/MITRE; suspicious command/path/URL patterns; benign read-only command pattern; port intelligence (e.g. 445 → SMB, CVE-2017-0144) |
| `reference_attacks.json` | hand-written, summary-level | WannaCry, BlueKeep, Blaster, Mirai, Colonial Pipeline, Heartland, TalkTalk, MOVEit, Equifax/Struts, Samy, TweetDeck, Emotet, QakBot, SolarWinds, Log4Shell |

**Caveat:** the derived allowlists share a source with the logs, and the pentest rule name in the data (`AUTHORIZED-PENTEST-*`) is how the
schedule is reconstructed. Real deployments would import these from a CMDB / change-management system. Verify reference-attack details
before citing externally.

## 12. LLM layer

* **`llm.py`** — `make_llm(cfg)`: provider from `LLM_PROVIDER` or config (`auto` picks OpenRouter/NVIDIA if a key exists, else mock).
  `OpenAICompatLLM` (OpenAI SDK, `base_url` per provider, models per role `recon`/`classifier`, one retry, token/latency logging);
  `extract_json` strips `<think>` blocks and code fences. A requested-but-unavailable provider yields a mock whose name says `FALLBACK`.
* **`MockLLM`** — deterministic, offline: classifies by source type; reconstructs only volume anomalies (≥ 100 kB or ≥ 1000 pkt/s);
  FP judge defaults to the safe side (TRUE_POSITIVE). It is a placeholder, not a model.
* **Tasks:** `classify` (Stage 4 fallback), `reconstruct` (Stage 9 step 4, JSON schema with stages/evidence/benign explanation/gaps/actions),
  `judge_fp` (Stage 9 step 5).
* **Prompt-injection defence (`sanitize.py`)**: log fields only enter prompts as JSON inside `<<<ALERT_DATA … ALERT_DATA>>>`; control characters
  and fence tokens are neutralised, strings truncated to 400 chars, system rules state the fence is untrusted data; output must match a schema and
  citations are validated in code. Tested with a forged-fence payload.

## 13. Configuration reference (`config/config.yaml`)

| Key | Default | Meaning |
|---|---|---|
| `severity_map` | L3 M6 H10 C13 | text → numeric severity |
| `classifier.confidence_threshold` | 0.7 | below → human review |
| `grouping.key / fallback / window_minutes` | src_ip / [user, host] / 30, 10 | Stage 5 |
| `dispatch.severity_threshold` | 8 | severity trigger |
| `dispatch.debounce_s / idle_s / max_wait_s / sweep_interval_s` | 60 / 120 / 300 / 15 | dispatch timers (log time) |
| `dispatch.log_lookback_min` | 30 | how far back raw events are pulled |
| `owner_rank`, `owner_domain` | ENDPOINT 3, HTTP 2, others 1 | Stage 7a |
| `ti.cache_hours` | 24 | TI cache |
| `agent.tool_budget_calls / _seconds` | 5 / 60 | tool budget |
| `agent.citation_retries` | 2 | validation retries |
| `agent.fp_min_pass` | 2 | passes needed to call a false positive |
| `memory.similarity_threshold` | 0.85 | hint threshold |
| `risk.*` | §8 | bases, bonus, TI, FP term, levels, LOW cap |
| `llm.*` | providers, models, timeout 60 s, max_tokens 1800, temperature 0 | LLM |
| `evaluation.manual_minutes_per_incident` | 20 | manual-time estimate |

## 14. Evaluation (`grader.py`)

### 14.1 What is measured

Grouping (exact incident match, pairwise precision/recall) · owner/routing accuracy · FP precision/recall + attack precision/recall + confusion ·
risk-level accuracy · stage-sequence accuracy · attack-type accuracy · citation validity (first pass) · path mix · `needs_human` count ·
revisions · pipeline seconds per incident vs the manual estimate · full mismatch table. Output: `evaluation.md/.json` (one command:
`python run.py run --grade`).

### 14.2 Result on the supplied dataset (83 alerted incidents: 58 attacks, 25 false positives; mock LLM)

All metrics 100%; path mix 96.4% playbook / 3.6% LLM (the 3 unmapped anomalies); 0 needs-human; 0 revisions; identical results under
`--shuffle-within 25`.

### 14.3 What that number does and does not mean

`scripts/ablation.py` re-runs the full pipeline with parts of the KB removed:

| Variant | Verdict acc. | FP recall | FP precision |
|---|---|---|---|
| full KB | 100% | 100% | 100% |
| no allowlists / pentest schedule | 87.9% | 60% | 100% |
| no service-account inventory | 94.0% | 80% | 100% |
| no IOC domains | 94.0% | 100% | 83% |
| no KB context at all | 75.9% | 40% | 67% |

The score is a **tuning score**: allowlists derive from the same simulated environment, risk bases were fitted to the key, the data leaks
(pentest rule name, `svc_*` on every FP twin), and the fall-through cases are handled by the mock. Treat it as proof the *logic and plumbing*
work, not as a detection-rate estimate. A fresh, unseen dataset is still required (Phase 7).

## 15. Testing

`python -m pytest tests -q` → **48 tests** (~9 s).

| File | Covers |
|---|---|
| `test_pipeline.py` | full replay graded against the key; every alert validates; 1:1 incident membership; owner/playbook domain consistency; every report section; citations exist and appendix lines equal the real log lines; no unrendered placeholders; TP reports have impact+actions; FP reports name the benign explanation; multi-stage chain + consult; malware link wording; **ground truth only read by the grader**; alerts carry no labels |
| `test_edge_cases.py` | dead-letter (wrong action, bad timestamp, missing field, unknown source); duplicates; human review; AUTH→network; grouping ignores shared user/host; window split; missing `src_ip` fallback; out-of-order arrival; dispatch never waits for the window; late alert → revision v2; no look-ahead; port-scan readiness via log store; tool budget (partial + cap); citation retry then success / `needs_human`; LLM outage; prompt injection fence; TI unavailable; ambiguous FP → judge; pentest window decides the verdict; conditional report text; consult slice; shuffled-arrival equivalence |
| `test_feedback_llm.py` | risk levels, terms, FP cap, determinism; similarity and memory kinds; only confirmed verdicts reach memory; allowlist needs approval and keeps a backup; confirmed case appears as a hint but not a verdict; JSON extraction; provider fallback; OpenAI-compatible request shape and retry (fake client) |

Mutation checks performed: routing AUTH back to app (5 tests failed ✔), dispatch waiting for the window (initially **survived** a tautological
assertion → fixed → now fails ✔).

## 16. Status against the Full System Implementation Plan

| Phase | Status | Notes |
|---|---|---|
| 0 Setup | **Partial** | repo/config/pytest ✔; **qwen/LLM endpoint never reached** (no key); Python 3.13 vs plan's 3.11 |
| 1 Data + reference files | **Mostly** | IOC/asset/pentest files exist and every referenced IOC, host and service account resolves (checked); ground truth is in `data/` not `eval/ground_truth/`; no explicit checklist script |
| 2 Orchestrator core | **Done** | grouping and owner 100% (gate ≥ 95%); built with real agents rather than stubs; the separate Orchestrator Implementation Plan checklist was not provided |
| 3 Playbook path | **Done** | 9 playbooks, citations valid first pass 100%, stage accuracy 100% |
| 4 Judgment | **Partial** | FP checks, TI agent, LangGraph graph, `consult_agent`, budgets ✔; **LLM paths verified only with mock/scripted/fake clients** |
| 5 Reporting | **Done** | JSON + Markdown + HTML per incident version |
| 6 Full grading | **Mostly** | one-command scorecard ✔; lacks "grouping purity/splits" wording, a separate "memory" path-mix bucket, and an explicit "FP clearance" metric |
| 7 Tuning + demo | **Not done** | no fresh dataset; no demo script; optional FastAPI review page not built |

Open decisions from the plan: grouping key → `src_ip` only (passed); windows → 30/10 kept; demo surface → undecided; system-flow doc routing table
→ still needs AUTH moved under Network Security.

## 17. Known limitations

* Real LLM path unproven against a live endpoint; model IDs in config are unverified.
* The 100% result depends on KB context derived from the same synthetic data (§14.3); risk bases are fitted.
* Dataset mix is 58 / 25 / 3 (not 65 / 25 / 10) and has no log generator, so no fresh-data test yet.
* One synchronous process; incident state is persisted but not reloaded after restart; no concurrency, no live ingest, no SOC web page.
* Mock LLM only reasons about volume anomalies; without KB context, fall-through cases are mishandled (ablation).
* Reference-attack facts are summary-level.
* Evidence "compression" of repeats is applied in LLM prompts and timeline ID cells, not by rewriting stored events.

## 18. Operating and extending

```bash
pip install -r requirements.txt
python run.py run --grade [--speed 60] [--shuffle-within 25] [--limit N] [--fresh-memory] [--run-id NAME]
python run.py grade [--run runs/NAME]
python run.py verdict ORC-0002 CONFIRMED_ATTACK [--note "…"]
python scripts/build_kb.py        # regenerate assets/allowlists from the event file
python scripts/ablation.py        # KB contribution study
python -m pytest tests -q
```

**Add a playbook:** add an entry to `config/playbooks.yaml` (agent, attack_type, priority, stages, optional `confirm`/`fp_checks`, summary/impact/gaps/
actions templates), add a base score under `risk.base`, add any new predicate to `PREDICATES` and FP check to `FP_CHECKS`, then add a test.
**Add an FP check:** implement `chk_*(match, kb, ctx) → (passed, detail)` with a detail sentence for both outcomes, register it in `FP_CHECKS`,
reference it from a playbook with a `label` defined under `fp_labels`.
**Add an LLM provider:** add a block under `llm.providers` (`base_url`, `key_env`, `recon_model`, `classifier_model`) and set `LLM_PROVIDER`.
**Go live:** replace `replay()` with a service calling `Orchestrator.ingest()` per alert and `tick()` on a timer (the planned FastAPI layer).
