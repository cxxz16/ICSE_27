# ICSE_27

Research artifact: LLM-augmented directed fuzzing for reaching and validating
defects in PHP web applications, built on top of a directed greybox fuzzer.

## Layout

```
instrumentation/            PHP interpreter hooks (coverage + blocker-event tracing)
  php7/, php8/              zend_witcher_trace.{c,h} + build patch
  db_fault_escalator.c     DB-layer fault escalation
  fault_tosser.c
module1_static_analysis/    Static analysis: sink -> entry URL + dispatch decisions
  dispatch_resolver/        Dynamic-dispatch resolution (file-include graph, LLM resolver)
  framework_routing/        Framework route modeling + reverse lookup
module2_runtime_feedback/   Runtime feedback: blocker events, distance-guided branch search
module3_differential_oracle/ Differential oracle + the closed-loop driver (m3_driver)
common/                     Shared utilities (LLM client, metrics, tester)
eval/                       Evaluation and analysis scripts
```

## Prerequisites

- **Docker** — each target application runs in its own container.
- **Python 3.10+** with `openai`, plus the packages imported by the modules.
- **An LLM API key** (see *Environment variables* below).
- **A code-property graph (CPG)** for the target application. The pipeline
  consumes `nodes.csv`, `rels.csv`, `cpg_edges.csv`, and `call_graph.csv`
  produced by an external static-analysis frontend (php-ast -> CPG). That
  frontend is **not** part of this release; point `--working-dir` at a
  directory containing those CSVs.
- The instrumented PHP interpreter (build `instrumentation/` into the target's
  PHP with the provided patch) so runtime blocker events are emitted.

## End-to-end workflow

For one target defect, the pipeline runs five stages (mirrors the internal
`run_one` harness). Inputs per case: the sink location (`file:line`), the app
container image, and its served webroot URL.

```
[1] Start container            docker run the target image; run its init/DB seed
[2] Static analysis (external) produce the CPG CSVs for the app version, once,
                               then cache them (reused across cases of that app)
[3] Module 1: pipeline.py      sink -> entry URL + dispatch constraints
    3a webroot_calibrator      map the derived entry file to the real served URL
    3b bootstrap login         acquire + validate a session cookie (if stateful)
[4] Module 3: m3_driver        Phase A (reach the sink) + Phase B (bug oracle 
                               confirms the defect), under a wallclock cap
[5] Finalize verdict           write final_trigger.json (CONFIRMED / REACH_FAIL /
                               ... ) + timing breakdown
```

### Stage 3 — Module 1 static pipeline

Derives the entry URL and the dispatch/guard constraints on the path to the sink:

```bash
python -m module1_static_analysis.pipeline \
    --working-dir  <CPG_DIR>            # dir holding nodes.csv/rels.csv/cpg_edges.csv/call_graph.csv
    --sink-file    <ABS_PATH_TO_SINK_FILE> \
    --sink-line    <SINK_LINE_NO> \
    --output-dir   <INSTR_DIR>          # where pipeline_result.json is written
    --project-root <APP_SOURCE_ROOT_ON_HOST> \
    --webroot-url  http://localhost:<PORT>/<app-subpath> \
    --method       POST
```

Optionally project the derived entry file onto the live container's real served
path:

```bash
python -m module1_static_analysis.webroot_calibrator \
    --container       <CONTAINER_NAME> \
    --pipeline-result <INSTR_DIR>/pipeline_result.json \
    --webroot-url     http://localhost:<PORT>/<app-subpath>
```

### Stage 4 — Module 3 reach + differential oracle

Consumes `pipeline_result.json` and drives the instrumented container: Phase A
guides the request to the sink (distance-guided branch search + LLM guidance),
Phase B confirms exploitability with the differential oracle.

```bash
python -m module3_differential_oracle.m3_driver \
    --pipeline-result   <INSTR_DIR>/pipeline_result.json \
    --container         <CONTAINER_NAME> \
    --output-dir        <OUT_DIR> \
    --working-dir       <CPG_DIR> \
    --container-root    <APP_ROOT_INSIDE_CONTAINER> \
    --project-root-host <APP_SOURCE_ROOT_ON_HOST> \
    --max-iters         30 \
    --wallclock-cap     3600 \
    --llm-log           <OUT_DIR>/llm_chats.jsonl \
    --vuln-type         sqli \
    --oracle-mode       predator \
    --bootstrap-url     <LOGIN_URL>       # optional; omit for unauthenticated apps
    --bootstrap-body    <LOGIN_POST_BODY> \
    --p6-dry-run                          # skip full-CPG distance recompute (large apps)
    --cookie-jar        <OUT_DIR>/cookies.txt   # optional; from bootstrap login
    --auth-header       "Authorization: Basic ..."  # optional; HTTP Basic / bearer apps
```

The final verdict is written to `<OUT_DIR>/final_trigger.json`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `VIPER_LLM_API_KEYS` / `OPENAI_API_KEY` | — | LLM API key(s), comma-separated for rotation |
| `VIPER_LLM_BASE_URL` | `https://api.openai.com/v1` | LLM endpoint |
| `VIPER_LLM_MODEL` | `gpt-4o` | model name |
| `VIPER_WALLCLOCK_CAP` | `3600` | per-case wallclock cap (seconds) |
| `VIPER_MAX_ITERS` | `30` | max reach/confirm iterations |
| `VIPER_P6_DRY_RUN` | `1` | skip per-iter full-CPG distance recompute (needed on large apps) |
| `VIPER_BOOTSTRAP_MAX_ATTEMPTS` | `3` | login bootstrap retries |
| `VIPER_TEARDOWN` | `0` | stop+remove the container after the run |

Per-app extension files (optional, if present) tune static and runtime behavior:
extra sink/source registries (`WRAPPER_SINKS_CSV` / `WRAPPER_SOURCES_CSV`),
per-request CSRF token refresh (`VIPER_CSRF_CONFIG`), and a static auth header.
