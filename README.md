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

## Configuration

The LLM client reads credentials from the environment:

```
export VIPER_LLM_API_KEYS="key1,key2"     # or OPENAI_API_KEY
export VIPER_LLM_BASE_URL="https://api.openai.com/v1"
export VIPER_LLM_MODEL="gpt-4o"
```

## Notes

This is a cleaned research release: comments and docstrings have been removed and
paths anonymized. The modules are organized by role; cross-module imports are
qualified against the top-level package directories.
