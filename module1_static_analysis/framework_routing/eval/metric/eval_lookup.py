from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

VIPER_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(VIPER_ROOT))

from VIPER.framework_routing import extract_routes, load_schema, lookup


def _norm(method: str, pattern: str) -> tuple[str, str]:
    m = (method or "").strip().upper()
    p = "/" + (pattern or "").lstrip("/")
    return (m, p)


def evaluate(project: Path, schema_path: Path, gt: list[dict]) -> dict:
    schema = load_schema(schema_path)
    print(f"[*] Extracting routes from {project} ...", file=sys.stderr)
    routes = extract_routes(project, schema)
    print(f"[*] {len(routes)} routes extracted", file=sys.stderr)

    per_probe: list[dict] = []
    total_tp = total_fp = total_fn = 0
    sum_p = sum_r = 0.0

    for h in gt:
        probe_line = h["line_start"]
        expected = {_norm(e["method"], e["matched_pattern"]) for e in h["entries"]}
        cands = lookup(h["file"], probe_line, routes)
        predicted = {_norm(c.http_method, c.url_pattern) for c in cands}

        tp = expected & predicted
        fp = predicted - expected
        fn = expected - predicted
        p = len(tp) / len(predicted) if predicted else 0.0
        r = len(tp) / len(expected) if expected else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0

        per_probe.append({
            "file": h["file"],
            "line_start": h["line_start"],
            "line_end": h["line_end"],
            "kind": h["kind"],
            "class_short": (h["class"] or "").split("\\")[-1],
            "function": h["function"],
            "hit_count": h["hit_count"],
            "n_expected": len(expected),
            "n_predicted": len(predicted),
            "tp": len(tp), "fp": len(fp), "fn": len(fn),
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3),
            "expected": sorted(expected),
            "predicted": sorted(predicted),
            "missing_in_predicted": sorted(fn),
            "extra_in_predicted": sorted(fp),
        })
        total_tp += len(tp); total_fp += len(fp); total_fn += len(fn)
        sum_p += p; sum_r += r

    n = len(per_probe)
    macro_p = sum_p / n if n else 0.0
    macro_r = sum_r / n if n else 0.0
    macro_f1 = 2 * macro_p * macro_r / (macro_p + macro_r) if (macro_p + macro_r) else 0.0
    micro_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    micro_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0

    perfect = sum(1 for p in per_probe if p["fp"] == 0 and p["fn"] == 0)
    zero_recall = sum(1 for p in per_probe if p["recall"] == 0.0)

    return {
        "summary": {
            "n_handlers": n,
            "n_routes_in_ir": len(routes),
            "perfect_match": perfect,
            "zero_recall": zero_recall,
            "macro": {"precision": round(macro_p, 3), "recall": round(macro_r, 3), "f1": round(macro_f1, 3)},
            "micro": {"precision": round(micro_p, 3), "recall": round(micro_r, 3), "f1": round(micro_f1, 3),
                       "tp": total_tp, "fp": total_fp, "fn": total_fn},
        },
        "per_probe": per_probe,
    }


def print_report(result: dict) -> None:
    s = result["summary"]
    print()
    print(f"{'Handlers probed':32s} = {s['n_handlers']}")
    print(f"{'Routes in IR':32s} = {s['n_routes_in_ir']}")
    print(f"{'Perfect match (no fp, no fn)':32s} = {s['perfect_match']}")
    print(f"{'Zero recall (none predicted)':32s} = {s['zero_recall']}")
    print()
    m = s["macro"]; mi = s["micro"]
    print(f"{'Macro':10s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}")
    print(f"{'Micro':10s}  P={mi['precision']:.3f}  R={mi['recall']:.3f}  F1={mi['f1']:.3f}  "
          f"(TP={mi['tp']} FP={mi['fp']} FN={mi['fn']})")
    print()
    sorted_probes = sorted(result["per_probe"], key=lambda p: (p["f1"], p["recall"]))
    if sorted_probes:
        print("[*] Worst 10 probes by F1:")
        for p in sorted_probes[:10]:
            print(f"  {p['file']}:{p['line_start']}  {p['class_short'] or '~'}::{p['function']}  "
                  f"P={p['precision']:.2f} R={p['recall']:.2f}  "
                  f"missing={p['missing_in_predicted']}  extra={p['extra_in_predicted']}")


def main():
    ap = argparse.ArgumentParser(__doc__)
    ap.add_argument("--project", required=True, type=Path)
    ap.add_argument("--schema", required=True, type=Path)
    ap.add_argument("--ground-truth", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    gt = json.loads(args.ground_truth.read_text())
    result = evaluate(args.project, args.schema, gt)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print_report(result)
    print(f"\nFull result -> {args.output}")


if __name__ == "__main__":
    main()
