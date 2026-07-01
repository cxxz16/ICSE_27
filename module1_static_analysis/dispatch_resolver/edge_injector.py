
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .entry_finder import EntryDiscovery
from .fig_builder import _read_nodes


@dataclass
class SyntheticEdge:
    site_id: int
    callee_node_id: int
    callee_label: str
    site_category: str

    def __str__(self) -> str:
        return f"({self.site_id} → {self.callee_node_id} | {self.callee_label})"


def _build_callee_index(nodes: dict[int, dict]) -> dict[str, int]:
    idx: dict[str, int] = {}
    for nid, n in nodes.items():
        typ = n.get("type", "")
        name = n.get("name", "")
        if not name:
            continue
        if typ == "AST_METHOD":
            cls = n.get("classname", "")
            key = f"{cls}::{name}" if cls else name
            idx.setdefault(key, nid)
            idx.setdefault(name, nid)
        elif typ == "AST_FUNC_DECL":
            idx.setdefault(name, nid)
    return idx


def derive_synthetic_edges(
    discovery: EntryDiscovery, working_dir: str | Path
) -> list[SyntheticEdge]:
    wd = Path(working_dir)
    nodes = _read_nodes(wd / "nodes.csv")
    idx = _build_callee_index(nodes)

    out: list[SyntheticEdge] = []
    seen: set[tuple[int, int]] = set()
    for d in discovery.dispatch_decisions:
        site_id = d.site_id
        site_node = nodes.get(site_id)
        if site_node and site_node.get("type") == "AST_NEW":
            continue
        for r in d.resolved_callees:
            if not r.reaches_sink:
                continue
            callee = r.callee
            if "::" not in callee and callee in {n.get("name", "") for n in nodes.values()
                                                  if n.get("type") == "AST_TOPLEVEL"
                                                  and n.get("flags") == "TOPLEVEL_CLASS"}:
                continue
            target = idx.get(callee)
            if target is None and "::" in callee:
                target = idx.get(callee.rsplit("::", 1)[1])
            if target is None:
                continue
            key = (site_id, target)
            if key in seen:
                continue
            seen.add(key)
            out.append(SyntheticEdge(
                site_id=site_id, callee_node_id=target,
                callee_label=callee, site_category=d.method,
            ))

    for h in getattr(discovery, "hops", []) or []:
        if getattr(h, "kind", "") != "include_dispatch":
            continue
        site = int(getattr(h, "site_node_id", 0) or 0)
        callee_fid = int(getattr(h, "from_funcid", 0) or 0)
        if not site or not callee_fid:
            continue
        key = (site, callee_fid)
        if key in seen:
            continue
        seen.add(key)
        out.append(SyntheticEdge(
            site_id=site, callee_node_id=callee_fid,
            callee_label=getattr(h, "from_label", "") or "include_dispatch",
            site_category="include_dispatch",
        ))
    return out


def write_augmented_cpg_edges(
    working_dir: str | Path, edges: list[SyntheticEdge],
    *, src_name: str = "cpg_edges.csv", dst_name: str = "cpg_edges_augmented.csv",
) -> Path:
    wd = Path(working_dir)
    src = wd / src_name
    dst = wd / dst_name
    if not src.exists():
        raise FileNotFoundError(src)

    with src.open("r", encoding="utf-8") as fin, dst.open("w", encoding="utf-8") as fout:
        for line in fin:
            fout.write(line)
        for e in edges:
            fout.write(f"{e.site_id}\t{e.callee_node_id}\tCALLS\t\n")
    return dst


def inject(
    discovery: EntryDiscovery, working_dir: str | Path
) -> tuple[Path, list[SyntheticEdge]]:
    edges = derive_synthetic_edges(discovery, working_dir)
    path  = write_augmented_cpg_edges(working_dir, edges)
    return path, edges


def _main():
    import argparse
    import json
    from .entry_finder import discover_entry

    ap = argparse.ArgumentParser(
        description="Inject synthetic CALLS edges from dispatch resolution.")
    ap.add_argument("-w", "--working-dir", required=True)
    ap.add_argument("-s", "--sink-file", required=True)
    ap.add_argument("-l", "--sink-line", required=True, type=int)
    ap.add_argument("--entry-suffix", default="")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print edges without writing.")
    args = ap.parse_args()

    predicate = (lambda _: True) if not args.entry_suffix \
        else (lambda p, sfx=args.entry_suffix: p.endswith(sfx) or p.endswith("/" + sfx))

    discovery = discover_entry(
        sink_file=args.sink_file, sink_line=args.sink_line,
        working_dir=args.working_dir, webroot_predicate=predicate,
    )
    if not discovery.found:
        print(f"✗ entry not found: {discovery.failure_reason}")
        return 2

    edges = derive_synthetic_edges(discovery, args.working_dir)
    print(f"Derived {len(edges)} synthetic CALLS edge(s):")
    for e in edges:
        print(f"  {e}")

    if not args.dry_run and edges:
        path = write_augmented_cpg_edges(args.working_dir, edges)
        print(f"\nWrote augmented graph: {path}")


if __name__ == "__main__":
    _main()
