from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def build(dispatch_path: Path, exclude_file_prefixes: list[str] | None = None) -> list[dict]:
    by_handler: dict[tuple, dict] = defaultdict(lambda: {
        "kind": None, "class": None, "function": None,
        "patterns": defaultdict(int),
        "hit_count": 0,
    })

    skipped = 0
    filtered = 0
    excludes = tuple(exclude_file_prefixes or ())
    with dispatch_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if not e.get("file") or e.get("line_start") is None:
                skipped += 1
                continue
            if excludes and any((e["file"] or "").startswith(p) for p in excludes):
                filtered += 1
                continue
            key = (e["file"], e["line_start"], e["line_end"])
            bucket = by_handler[key]
            bucket["kind"] = e.get("kind")
            bucket["class"] = e.get("class")
            bucket["function"] = e.get("function")
            pat = (e.get("method", "").upper(), e.get("matched_pattern", ""))
            bucket["patterns"][pat] += 1
            bucket["hit_count"] += 1

    out: list[dict] = []
    for (file, ls, le), bucket in by_handler.items():
        entries = [
            {"method": m, "matched_pattern": p, "count": c}
            for (m, p), c in sorted(bucket["patterns"].items())
        ]
        out.append({
            "file": file,
            "line_start": ls,
            "line_end": le,
            "kind": bucket["kind"],
            "class": bucket["class"],
            "function": bucket["function"],
            "hit_count": bucket["hit_count"],
            "entries": entries,
        })
    out.sort(key=lambda r: (r["file"], r["line_start"]))
    return out, skipped, filtered


def main():
    ap = argparse.ArgumentParser(__doc__)
    ap.add_argument("--dispatch", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument(
        "--exclude-file-prefix",
        action="append",
        default=[],
        help="Drop dispatch rows whose `file` starts with this prefix (repeatable). "
             "Use to filter framework/vendor entries that the IR doesn't claim to cover, "
             "e.g. --exclude-file-prefix vendor/",
    )
    args = ap.parse_args()

    if not args.dispatch.exists():
        raise SystemExit(f"dispatch ndjson not found: {args.dispatch}")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    handlers, skipped, filtered = build(args.dispatch, args.exclude_file_prefix)
    with args.output.open("w") as f:
        json.dump(handlers, f, indent=2, ensure_ascii=False)

    total_hits = sum(h["hit_count"] for h in handlers)
    distinct_patterns = {(m, p) for h in handlers
                         for e in h["entries"]
                         for m, p in [(e["method"], e["matched_pattern"])]}
    print(f"input  : {args.dispatch}")
    print(f"output : {args.output}")
    print(f"handlers (distinct file+line_range)  : {len(handlers)}")
    print(f"distinct (method, matched_pattern)   : {len(distinct_patterns)}")
    print(f"total dispatched requests covered    : {total_hits}")
    print(f"skipped (no file/line)               : {skipped}")
    if args.exclude_file_prefix:
        print(f"filtered by --exclude-file-prefix    : {filtered}  (prefixes={args.exclude_file_prefix})")


if __name__ == "__main__":
    main()
