from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


def _load_json(p: Path):
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _load_jsonl(p: Path):
    rows = []
    if not p.exists():
        return rows
    for ln in p.read_text().splitlines():
        try:
            rows.append(json.loads(ln))
        except Exception:
            continue
    return rows


def _llm_breakdown(jsonl_path: Path) -> dict:
    by_stage: dict[str, dict] = defaultdict(lambda: {
        "calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0,
        "elapsed_sec": 0.0,
    })
    total = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
             "cost_usd": 0.0, "elapsed_sec": 0.0}
    for r in _load_jsonl(jsonl_path):
        stage = r.get("stage", "?")
        bs = by_stage[stage]
        bs["calls"] += 1
        bs["prompt_tokens"]     += int(r.get("prompt_tokens",     0) or 0)
        bs["completion_tokens"] += int(r.get("completion_tokens", 0) or 0)
        bs["cost_usd"]          += float(r.get("cost_usd",        0) or 0)
        bs["elapsed_sec"]       += float(r.get("elapsed_sec",     0) or 0)
        total["calls"]             += 1
        total["prompt_tokens"]     += int(r.get("prompt_tokens",     0) or 0)
        total["completion_tokens"] += int(r.get("completion_tokens", 0) or 0)
        total["cost_usd"]          += float(r.get("cost_usd",        0) or 0)
        total["elapsed_sec"]       += float(r.get("elapsed_sec",     0) or 0)
    return {"by_stage": dict(by_stage), "total": total}


def _probe_stats(jsonl_path: Path) -> dict:
    rows = _load_jsonl(jsonl_path)
    if not rows:
        return {"n_probes": 0, "n_confirmed": 0, "elapsed_total_sec": 0.0}
    return {
        "n_probes":          len(rows),
        "n_confirmed":       sum(1 for r in rows if r.get("verdict") == "CONFIRMED"),
        "elapsed_total_sec": round(sum(float(r.get("elapsed_sec", 0)) for r in rows), 3),
    }


def _failure_subclass(ft: dict, m3_log_path: Path) -> str:
    v = ft.get("verdict", "")
    reason = (ft.get("reason") or "").lower()
    if v == "REACH_FAIL":
        if "timeout" in reason:
            return "wallclock_timeout"
        if ft.get("max_iters_used") and ft.get("max_iters_cap") \
           and ft["max_iters_used"] >= ft["max_iters_cap"]:
            return "max_iters_exhausted"
        return "reach_fail_other"
    if v == "INFRA_FAIL":
        if "disk_guard" in reason:
            return "disk_low_free"
        if ft.get("m3_exit") == 124:
            return "wallclock_timeout"
        return "m3_crash"
    if v == "ENV_FAIL":
        return "init_sh_failed"
    if v == "STATIC_FAIL":
        return "pipeline_failed"
    return ""


def _row_for_cve(cve_dir: Path) -> dict:
    ft = _load_json(cve_dir / "final_trigger.json") or {}
    timings = _load_json(cve_dir / "timings.json") or {}
    tsec = timings.get("timings_sec", {}) or {}
    counts = timings.get("counts", {}) or {}
    llm = _llm_breakdown(cve_dir / "llm_chats.jsonl")
    probes = _probe_stats(cve_dir / "phase_b_probes.jsonl")
    verdict = ft.get("verdict", "INFRA_FAIL")

    return {
        "cve_id":               cve_dir.name,
        "verdict":              verdict,
        "failure_subclass":     _failure_subclass(ft, cve_dir / "m3_driver.log"),
        "elapsed_sec":          ft.get("elapsed_sec"),
        "static_tchecker_sec":  tsec.get("static/tchecker"),
        "static_pipeline_sec":  tsec.get("static/pipeline"),
        "phase_a_sec":          tsec.get("phase_a/total"),
        "phase_b_sec":          tsec.get("phase_b/total"),
        "tchecker_cache_hit":   counts.get("static/tchecker_cache_hit"),
        "pipeline_cache_hit":   counts.get("static/pipeline_cache_hit"),
        "phase_a_iters":        counts.get("phase_a/iters"),
        "phase_b_probes":       probes["n_probes"],
        "phase_b_confirmed":    probes["n_confirmed"],
        "reach_iter":           ft.get("trigger_iter") if verdict == "CONFIRMED" else None,
        "trigger_param":        ft.get("param"),
        "trigger_payload":      ft.get("payload"),
        "baseline_body":        ft.get("baseline_body"),
        "mal_body":             ft.get("mal_body"),
        "llm_calls":            llm["total"]["calls"],
        "llm_prompt_tokens":    llm["total"]["prompt_tokens"],
        "llm_completion_tokens":llm["total"]["completion_tokens"],
        "llm_cost_usd":         round(llm["total"]["cost_usd"], 4),
        "llm_elapsed_sec":      round(llm["total"]["elapsed_sec"], 2),
        "llm_by_stage":         {s: {"calls": d["calls"],
                                     "in":  d["prompt_tokens"],
                                     "out": d["completion_tokens"],
                                     "usd": round(d["cost_usd"], 4),
                                     "sec": round(d["elapsed_sec"], 2)}
                                  for s, d in llm["by_stage"].items()},
        "reason":               ft.get("reason"),
    }


def collect(batch_dir: Path) -> tuple[list[dict], dict]:
    rows = []
    for cve_dir in sorted(batch_dir.iterdir()):
        if not cve_dir.is_dir() and not cve_dir.is_symlink():
            continue
        if cve_dir.name.startswith("_") or cve_dir.name in {
                "summary.csv", "summary.md", "failures.log",
                "cve_index.csv", "env_lock.txt"}:
            continue
        if not (cve_dir / "final_trigger.json").exists() and not cve_dir.is_symlink():
            continue
        rows.append(_row_for_cve(cve_dir))

    by_v: dict[str, int] = defaultdict(int)
    for r in rows:
        by_v[r["verdict"]] += 1

    def _safe_sum(field):
        return sum(float(r[field] or 0) for r in rows)

    summary = {
        "total":               len(rows),
        "confirmed":           by_v["CONFIRMED"],
        "reach_not_confirmed": by_v["REACH_NOT_CONFIRMED"],
        "reach_fail":          by_v["REACH_FAIL"],
        "static_fail":         by_v["STATIC_FAIL"],
        "env_fail":            by_v["ENV_FAIL"],
        "infra_fail":          by_v["INFRA_FAIL"],
        "total_llm_calls":     sum(r["llm_calls"]            for r in rows),
        "total_llm_prompt":    sum(r["llm_prompt_tokens"]    for r in rows),
        "total_llm_completion":sum(r["llm_completion_tokens"]for r in rows),
        "total_llm_cost_usd":  round(_safe_sum("llm_cost_usd"), 4),
        "total_static_sec":    round(_safe_sum("static_tchecker_sec")
                                   + _safe_sum("static_pipeline_sec"), 1),
        "total_phase_a_sec":   round(_safe_sum("phase_a_sec"), 1),
        "total_phase_b_sec":   round(_safe_sum("phase_b_sec"), 1),
        "total_probes":        sum(r["phase_b_probes"] for r in rows),
    }
    return rows, summary


def write_csv(rows: list[dict], path: Path):
    if not rows:
        path.write_text("")
        return
    columns = [k for k in rows[0].keys() if k != "llm_by_stage"] + ["llm_by_stage_json"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        for r in rows:
            rr = {k: r.get(k) for k in columns if k != "llm_by_stage_json"}
            rr["llm_by_stage_json"] = json.dumps(r.get("llm_by_stage", {}),
                                                  ensure_ascii=False)
            w.writerow(rr)


def write_md(rows: list[dict], summary: dict, manifest: dict, batch_dir: Path):
    failures = (batch_dir / "failures.log").read_text() \
        if (batch_dir / "failures.log").exists() else ""
    lines = []
    lines.append(f"# Batch `{manifest.get('batch_tag','?')}` — eval summary")
    lines.append("")
    if failures.strip():
        lines.append("> ⚠ **failures detected** — see top section below; per-CVE artifacts")
        lines.append("> for failures stayed on the main disk for debugging.")
        lines.append("")
    lines.append(f"- started: `{manifest.get('started_at','?')}`")
    lines.append(f"- git_commit: `{manifest.get('git_commit','?')}` "
                 f"({manifest.get('git_dirty','?')})")
    lines.append(f"- witcher .so sha256[:12]: `{manifest.get('witcher_sha256_12','?')}`")
    lines.append(f"- openai SDK: `{manifest.get('openai_sdk_version','?')}`")
    lines.append(f"- wallclock_cap_sec: {manifest.get('wallclock_cap_sec','?')}  "
                 f"max_iters: {manifest.get('max_iters','?')}  "
                 f"model: {manifest.get('llm_model','?')}")
    lines.append("")

    if failures.strip():
        lines.append("## Failures (debug on main disk)")
        lines.append("```")
        lines.append(failures.rstrip())
        lines.append("```")
        lines.append("")

    lines.append("## Aggregate")
    lines.append("")
    lines.append(f"- **CONFIRMED**: {summary['confirmed']}/{summary['total']}")
    for k in ("reach_not_confirmed", "reach_fail", "static_fail",
              "env_fail", "infra_fail"):
        if summary[k]:
            lines.append(f"- {k.upper()}: {summary[k]}")
    lines.append("")
    lines.append("### Time breakdown (s, sum across CVEs)")
    lines.append(f"- static: **{summary['total_static_sec']}**  "
                 f"(TChecker + pipeline.py)")
    lines.append(f"- phase_a (reach): **{summary['total_phase_a_sec']}**")
    lines.append(f"- phase_b (oracle): **{summary['total_phase_b_sec']}**")
    lines.append("")
    lines.append("### LLM (sum across CVEs)")
    lines.append(f"- calls: **{summary['total_llm_calls']}**")
    lines.append(f"- tokens: **{summary['total_llm_prompt']}** in / "
                 f"**{summary['total_llm_completion']}** out")
    lines.append(f"- cost: **USD {summary['total_llm_cost_usd']}**")
    lines.append(f"- total Phase B probes: **{summary['total_probes']}**")
    lines.append("")

    stage_agg: dict[str, dict] = defaultdict(lambda: {"calls":0, "in":0, "out":0,
                                                       "usd":0.0, "sec":0.0})
    for r in rows:
        for s, d in r.get("llm_by_stage", {}).items():
            sa = stage_agg[s]
            sa["calls"] += d["calls"]; sa["in"] += d["in"]; sa["out"] += d["out"]
            sa["usd"]   += d["usd"];   sa["sec"] += d["sec"]
    if stage_agg:
        lines.append("### LLM by stage")
        lines.append("| Stage | Calls | In tok | Out tok | USD | Sec |")
        lines.append("|-------|------:|-------:|--------:|----:|----:|")
        for s, d in sorted(stage_agg.items(), key=lambda kv: -kv[1]["calls"]):
            lines.append(f"| `{s}` | {d['calls']} | {d['in']} | {d['out']} | "
                         f"{round(d['usd'],4)} | {round(d['sec'],1)} |")
        lines.append("")

    lines.append("## Per-CVE")
    lines.append("")
    lines.append("| CVE | V | Elapsed | Static / Reach / Oracle | "
                 "Iters/Probes | LLM calls / USD | Payload |")
    lines.append("|-----|---|--------:|------------------------:|"
                 "-------------:|-----------------|---------|")
    for r in rows:
        v_emoji = {"CONFIRMED":           "✅",
                   "REACH_NOT_CONFIRMED": "🟡",
                   "REACH_FAIL":          "❌",
                   "STATIC_FAIL":         "🔧",
                   "ENV_FAIL":            "📦",
                   "INFRA_FAIL":          "💥"}.get(r["verdict"], "?")
        sec = lambda k: ("—" if r.get(k) is None else f"{r[k]:.0f}")
        breakdown = f"{sec('static_tchecker_sec')}+{sec('static_pipeline_sec')} / " \
                    f"{sec('phase_a_sec')} / {sec('phase_b_sec')}"
        iters_probes = f"{r.get('phase_a_iters') or 0}/{r.get('phase_b_probes') or 0}"
        es = r.get("elapsed_sec")
        es_s = f"{es}s" if es is not None else "—"
        payload = (r.get("trigger_payload") or "")[:40]
        lines.append(f"| {r['cve_id']} | {v_emoji} | {es_s} | {breakdown} | "
                     f"{iters_probes} | {r['llm_calls']} / "
                     f"{r['llm_cost_usd']} | `{payload}` |")
    (batch_dir / "summary.md").write_text("\n".join(lines) + "\n")


def main():
    if len(sys.argv) < 2:
        print("usage: collect_results.py <batch_tag>", file=sys.stderr)
        sys.exit(2)
    batch_tag = sys.argv[1]
    batch_dir = Path("VIPER/eval/results") / batch_tag
    if not batch_dir.is_dir():
        print(f"no such batch dir: {batch_dir}", file=sys.stderr)
        sys.exit(2)
    manifest = _load_json(batch_dir / "manifest.json") or {}
    rows, summary = collect(batch_dir)
    write_csv(rows, batch_dir / "summary.csv")
    write_md(rows, summary, manifest, batch_dir)
    print(f"summary.csv + summary.md written to {batch_dir}")
    print()
    print(f"CONFIRMED {summary['confirmed']}/{summary['total']}")
    for k in ("reach_not_confirmed", "reach_fail", "static_fail",
              "env_fail", "infra_fail"):
        if summary[k]:
            print(f"  {k}: {summary[k]}")
    print(f"  total_cost_usd: {summary['total_llm_cost_usd']}  "
          f"({summary['total_llm_calls']} LLM calls)")
    print(f"  total_static_sec: {summary['total_static_sec']}  "
          f"phase_a_sec: {summary['total_phase_a_sec']}  "
          f"phase_b_sec: {summary['total_phase_b_sec']}")


if __name__ == "__main__":
    main()
