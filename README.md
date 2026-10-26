# Multi-Agent SIEM Orchestrator

Takes SIEM-flagged alerts, groups them into incidents, has one specialist agent reconstruct each attack from
the evidence, and writes a **cited PoC report** that says whether the incident is a real attack or a false
alarm. A SOC analyst makes the final call. Built from `SIEM_Orchestrator_Technical_System_Flow.pdf`, adapted to
the supplied dataset (see [Deviations](#deviations-from-the-design-doc)).

> **The data is synthetic.** Results demonstrate the orchestration and reasoning logic, not detection of unseen
> real-world attacks. See [Results and limits](#results-and-limits) before quoting any number.

## Quick start

```bash
pip install -r requirements.txt
python run.py run --grade            # replay the 103 alerts, write reports, grade against the answer key
python -m pytest tests -q            # 48 tests
python scripts/ablation.py           # how much does each knowledge-base part contribute?
```

Output goes to `runs/<run_id>/`:

| File | What |
|---|---|
| `reports/ORC-0002_v1.md / .html / .json` | the PoC report (Markdown + HTML for the analyst, JSON for the grader/UI) |
| `index.md`, `results.json` | one row per incident |
| `evaluation.md / .json` | grader output (after `--grade` or `python run.py grade`) |
| `state.db` | SQLite: incidents, dead-letter list, human-review queue, reports |

Other options: `--speed 60` (60x real time), `--shuffle-within 25` (out-of-order arrival), `--limit N`,
`--fresh-memory` (ignore SOC-confirmed cases for a reproducible run).

### Stage 13 - SOC verdict

```bash
python run.py verdict ORC-0002 CONFIRMED_ATTACK --note "confirmed with host owner"
python run.py verdict ORC-0026 CONFIRMED_FALSE_POSITIVE            # proposes an allowlist change
python run.py verdict ORC-0026 CONFIRMED_FALSE_POSITIVE --approve-allowlist   # applies it (backup kept)
```
Only confirmed verdicts feed case memory / allowlists. Unconfirmed agent verdicts are never reused.

## Using a real LLM

The offline run uses a deterministic **mock** (it only handles volume anomalies; it is a stand-in, not a model).
For real reasoning copy `.env.example` to `.env`:

```
LLM_PROVIDER=openrouter          # or nvidia
OPENROUTER_API_KEY=sk-or-...
```
If a provider is requested but its key is missing, the run says `mock (FALLBACK - ...)` in its header.
Model ids live in `config/config.yaml` (`llm.providers.*`) or `LLM_RECON_MODEL` / `LLM_CLASSIFIER_MODEL`.
**Confirm the exact ids in your provider console** - they could not be verified from here.

Recommended: a strong instruction model for reconstruction (Claude Sonnet-class, or Qwen3-235B / gpt-oss-120b),
and any small model for the classifier. `qwen3-coder` (the doc's pick) is tuned for code, not log reasoning.
On this dataset the LLM is reached for only ~4% of incidents (the 3 unmapped anomalies) plus ambiguous FP checks.
**The real-LLM path is covered by tests with scripted/fake clients but has not been run against a live API.**

## Pipeline map

| Stage | Module | Notes |
|---|---|---|
| 1 data | `soc/adapter.py` | CSV -> doc-shaped alert (core + `ext`); `LogStore` = runtime events indexed by IP/user/host |
| 2 replay | `soc/replay.py` | one alert at a time in `alert_time` order; simulated clock; `--shuffle-within` |
| 3 validate/dedupe | `soc/validate.py` | schema, allowed action per source, duplicate ids; failures -> dead-letter |
| 4 classify | `soc/classify.py`, `config/routing.yaml` | patterns -> LLM (confidence >= 0.7) -> human review |
| 5 group | `soc/incidents.py` | key = `src_ip` (fallback user, host) inside a 30 min network / 10 min app window |
| 6 ready | `soc/readiness.py`, `config/evidence_rules.yaml` | severity >= 8, end signal, evidence rule; checks the log store as of "now" |
| 7 owner + TI | `soc/readiness.py`, `soc/ti.py` | furthest stage wins; TI agent enriches every incident |
| 8 dispatch | `soc/orchestrator.py` | quiet-period timer; locks the version; later alerts = revisions |
| 9 agents | `soc/agents/` (LangGraph) | preprocess -> playbook -> memory -> (llm) -> FP check -> validate -> finalize |
| 10-12 report | `soc/risk.py`, `soc/report.py` | fixed formula; one template; no LLM call |
| 13 feedback | `soc/feedback.py`, `soc/memory.py` | confirmed cases only |
| eval | `soc/grader.py` | the **only** module that opens the ground-truth files (a test enforces this) |

## Deviations from the design doc

Every one of these was forced by the real data or chosen with you:

| Doc says | Data / decision | What this build does |
|---|---|---|
| AUTH belongs to App & Endpoint | you: brute force goes to **Network Security** | AUTH is network-domain; owner rank: ENDPOINT 3 > HTTP 2 > network/auth 1 |
| Group on shared IP, user **or host** | `svc_02` and `HOST-003/011` are reused across unrelated scenarios | group on **`src_ip` only** (verified 1:1 with the incidents in the data) |
| Wait for the 10/30 min window | you: don't wait for logs to fill | dispatch after **60 s** of quiet once a trigger fires, **120 s** otherwise, hard cap 300 s; later evidence = **version N+1** |
| Brute force needs >= 5 failures | the data's SIEM rule fires on 4; multi-stage has 3 | threshold **3** |
| `FILE_DOWNLOAD` action | downloads are `HTTP_REQUEST` 200 + `.exe` URL | defined from URL + status |
| SQLi regex `UNION\|' OR\|SLEEP` | misses `admin'--`, `OR 1=1` | broader case-insensitive strict pattern; keyword-only searches stay "SQL-like", not injection |
| FP checks: slow failures, business hours, signed script | no such signal in the data (all events are ~8-9 PM; mistyping gaps are *faster*) | replaced by checks the data supports: service-account inventory + known IP, source zone, docs-site allowlist, read-only cmdlets, pentest schedule, scanner allowlist |
| Alerts carry the whole attack | each alert points at one event; the rest is only in the runtime events | agents read the **log store** (bounded to the simulated "now" - no look-ahead) |
| Stage names `recon...` | ground truth uses `reconnaissance -> port_discovery`, `web_input_injection`, ... | playbooks use the ground-truth names; port scan = probes before / from the 10th distinct port |
| `base` risk 2/4/4/5/6/6 | cannot reach the expected bands | recalibrated (below) |

## Playbooks (`config/playbooks.yaml`)

| Playbook | Owner | Stages | Benign twin it must rule out |
|---|---|---|---|
| multi_stage | app | credential_attack -> suspicious_download -> endpoint_execution (consults network agent) | pentest schedule |
| malware_download_execution | app | malware_download -> endpoint_execution | pentest schedule |
| port_scan | network | reconnaissance -> port_discovery | pentest, scanner allowlist, internal-to-internal |
| sql_injection | app | web_input_injection | docs-wiki keyword search |
| xss | app | script_injection_attempt | pentest |
| brute_force | network | (reconnaissance) -> credential_attack -> account_compromise | service-account mistype |
| firewall_policy_violation | network | restricted_service_access_attempt | pentest, scanner |
| suspicious_endpoint_execution | app | suspicious_process_execution | admin read-only PowerShell |
| malicious_indicator_contact | app | malicious_indicator_contact | pentest |
| *(no match)* | either | LLM reconstruction | - |

The FP check **always runs**. Pentest schedule / scanner allowlist are *decisive*; other checks need >= 2 passes;
anything in between (or strong attack evidence plus benign evidence) goes to the LLM judge.

## Risk calibration

`risk = base + success_bonus(+3) + TI_score + asset_criticality - 4 x passing_FP_checks`; a FALSE_POSITIVE verdict caps at LOW.
Bases (`config/config.yaml`): port scan 4, brute force 5, SQLi 7, XSS 5, firewall violation 7, suspicious execution 5,
malicious IP/domain 6, malware 6, multi-stage 8, unmapped 4. They were tuned so each class lands in the band the ground
truth expects - that is the doc's "tuned once against ground truth", but it **is fitting to the answer key**.

## Knowledge base (`knowledge/`)

* `assets.json`, `allowlists.json` - **derived by `scripts/build_kb.py` from observable event attributes only**
  (internal-to-internal scan traffic, `AUTHORIZED-PENTEST-*` firewall exceptions, `svc_*` accounts). It never reads a label.
* `ioc.json` - simulated IOC domains, suspicious command/path/URL patterns, port intelligence (e.g. 445 -> SMB, CVE-2017-0144).
* `reference_attacks.json` - 15 historical attacks/CVEs (WannaCry, BlueKeep, Mirai, MOVEit, Equifax/Struts, Heartland,
  TalkTalk, Samy, TweetDeck, Emotet, QakBot, SolarWinds, Log4Shell, Colonial Pipeline, Blaster). Seeded into case memory as
  **reference** cases: shown as "similar historical attacks" and passed to the LLM as hints, **never** deciding a verdict.
  Summary-level facts - verify before citing externally.

## Results and limits

Full dataset, 83 alerted incidents (58 attacks, 25 false positives), mock LLM:

| Metric | Result |
|---|---|
| Grouping exact match / routing | 100% / 100% |
| FP precision / recall | 100% / 100% |
| Risk level / stage sequence / attack type | 100% / 100% / 100% |
| Citation validity (first pass) | 100% |
| Path mix | 96.4% playbook, 3.6% LLM |
| Out-of-order (`--shuffle-within 25`) | identical results |

**Read this before trusting the table.** The ablation (`scripts/ablation.py`) removes parts of the knowledge base:

| Variant | Verdict acc. | FP recall | FP precision |
|---|---|---|---|
| full KB | 100% | 100% | 100% |
| no allowlists / pentest schedule | 87.9% | 60% | 100% |
| no service-account inventory | 94.0% | 80% | 100% |
| no IOC domains | 94.0% | 100% | 83% |
| **no KB context at all** | **75.9%** | **40%** | **67%** |

So the headline FP result depends on allowlist/inventory context that was derived from the same simulated
environment, and the risk bases were fitted to the answer key. The *mock* LLM is what handles the no-context fall-through
cases (it defaults to the safe side), so those numbers reflect the mock, not a real model. The data also leaks
(pentest traffic literally carries a rule named `AUTHORIZED-PENTEST-TEST`; every FP twin uses `svc_*` accounts), which makes
FP detection easier than it would be on real traffic. The one-shot data has no concurrent activity from a single IP across
scenarios, no real analyst feedback loop, and no live SIEM. It is one long-running **synchronous** process; incident state
is persisted to SQLite but is not reloaded after a restart.

## Edge cases -> tests (`tests/test_edge_cases.py`)

Malformed / wrong-action alert -> dead-letter - duplicates - out-of-order arrival - late alert -> revision v2 - no look-ahead
into the log store - never waiting for the window - missing `src_ip` -> user fallback - low-confidence classification -> human
review - tool budget (5 calls) -> `needs_human` - invalid citations -> retry x2 -> `needs_human` - LLM outage - prompt injection
stays inside the data fence - TI unavailable stated in the report - ambiguous FP -> LLM judge - pentest window decides the verdict.

## Layout

```
config/    config.yaml  routing.yaml  evidence_rules.yaml  playbooks.yaml
knowledge/ assets  allowlists  ioc  reference_attacks  (json)
soc/       pipeline modules;  soc/agents/ = engine (playbooks), owner (LangGraph), findings
scripts/   build_kb.py  ablation.py
tests/     48 tests   data/  the four supplied CSVs   runs/  outputs   state/  case memory
```
