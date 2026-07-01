
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .fig_builder import FIG, _normpath, _read_nodes


@dataclass
class CandidateDispatchSite:
    site_id: int
    category: str
    callable_arg_positions: str
    data_arg_positions_hint: str
    file: str
    lineno: int


def _containing_file(node_funcid: int, fig: FIG, nodes: dict[int, dict]) -> str:
    seen: set[int] = set()
    cur = node_funcid
    while cur and cur not in seen:
        seen.add(cur)
        f = fig.file_by_funcid(cur)
        if f:
            return f.path
        node = nodes.get(cur)
        if not node:
            return ""
        try:
            cur = int(node.get("funcid") or 0)
        except (ValueError, TypeError):
            return ""
    return ""


def narrow(
    sink_file: str,
    fig: FIG,
    dispatch_sinks_csv: str | Path,
    nodes_csv: str | Path,
) -> list[CandidateDispatchSite]:
    f = fig.file_by_path(sink_file)
    sink_path = f.path if f else _normpath(sink_file)
    transitive_includers = fig.transitive_includers(sink_path)
    parents = transitive_includers - {sink_path}

    nodes = _read_nodes(Path(nodes_csv))

    out: list[CandidateDispatchSite] = []
    with open(dispatch_sinks_csv, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                sid = int(row["site_id"])
            except (ValueError, KeyError):
                continue
            n = nodes.get(sid)
            if not n:
                continue
            file = _containing_file(int(n["funcid"]), fig, nodes)
            if file in parents:
                out.append(CandidateDispatchSite(
                    site_id=sid,
                    category=row.get("category", ""),
                    callable_arg_positions=row.get("callable_arg_positions", ""),
                    data_arg_positions_hint=row.get("data_arg_positions_hint", ""),
                    file=file,
                    lineno=int(n.get("lineno") or 0),
                ))
    return out


def _main():
    import argparse
    import json
    from .fig_builder import build_fig

    ap = argparse.ArgumentParser(description="Narrow dispatch sites for entry-URL resolution.")
    ap.add_argument("-w", "--working-dir", required=True,
                    help="Dir with nodes.csv + rels.csv + dispatch_sinks.csv")
    ap.add_argument("-s", "--sink-file", required=True,
                    help="Sink file (absolute or suffix-match)")
    ap.add_argument("--show-fig-stats", action="store_true",
                    help="Also print the file-include graph stats")
    args = ap.parse_args()

    wd = Path(args.working_dir)
    fig = build_fig(wd)

    if args.show_fig_stats:
        print(f"[fig] {len(fig.files)} files, {len(fig.edges)} include edges")
        for e in fig.edges:
            print(f"  {Path(e.from_file).name:35s} --[{e.kind:14s}]--> "
                  f"{Path(e.to_file).name if e.to_file else '<' + e.resolution + '>'}")
        print()

    sink_path = _normpath(args.sink_file)
    transitive_parents = sorted(fig.transitive_includers(sink_path) - {sink_path})
    print(f"[sink] {sink_path}")
    print(f"[parents (transitively-include the sink file)] {len(transitive_parents)} file(s):")
    for p in transitive_parents:
        print(f"  - {p}")
    print()

    cands = narrow(args.sink_file, fig, wd / "dispatch_sinks.csv", wd / "nodes.csv")
    print(f"[candidate dispatch sites] {len(cands)}:")
    for c in cands:
        print(f"  site_id={c.site_id:<5} category={c.category:<22} "
              f"@ {c.file}:{c.lineno}")


if __name__ == "__main__":
    _main()
