from __future__ import annotations

import csv
from pathlib import Path

from .fig_builder import _read_nodes
from .orphan_dispatch import resolve_dynamic_method_callees, _read_child_to_parent


def _read_cuf_site_ids(dispatch_csv: Path) -> list[int]:
    out: list[int] = []
    if not dispatch_csv.exists():
        return out
    with open(dispatch_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("category") == "DYN_CUF":
                try:
                    out.append(int(row["site_id"]))
                except (ValueError, KeyError):
                    pass
    return out


def refine_dynamic_dispatch_edges(working_dir, *, write: bool = True,
                                   src_edges: str = "cpg_edges.csv",
                                   dst_edges: str = "cpg_edges_refined.csv",
                                   write_call_graph: bool = True) -> dict:
    wd = Path(working_dir)
    nodes = _read_nodes(wd / "nodes.csv")
    p2c, c2p = _read_child_to_parent(wd / "rels.csv")

    site_precise: dict[int, set] = {}
    site_meta: dict[int, dict] = {}
    for sid in _read_cuf_site_ids(wd / "dispatch_sinks.csv"):
        cands = resolve_dynamic_method_callees(sid, nodes, p2c, c2p)
        if cands:
            site_precise[sid] = {c.callee_node_id for c in cands}
            site_meta[sid] = {
                "literal": cands[0].literal,
                "precise_callees": sorted({c.callee_key for c in cands}),
            }

    funcid_of = {nid: int(n.get("funcid") or 0) for nid, n in nodes.items()}
    refined_rows: list[list[str]] = []
    pruned_per_site: dict[int, int] = {sid: 0 for sid in site_precise}
    kept_per_site: dict[int, int] = {sid: 0 for sid in site_precise}
    calls_before = 0
    cg_rows: list[tuple[int, int]] = []
    with open(wd / src_edges, encoding="latin-1") as f:
        r = csv.reader(f, delimiter="\t")
        header = next(r)
        refined_rows.append(header)
        for row in r:
            if len(row) >= 3 and row[2] == "CALLS":
                calls_before += 1
                try:
                    s, e = int(row[0]), int(row[1])
                except ValueError:
                    refined_rows.append(row)
                    continue
                if s in site_precise and e not in site_precise[s]:
                    pruned_per_site[s] += 1
                    continue
                if s in site_precise:
                    kept_per_site[s] += 1
                refined_rows.append(row)
                cg_rows.append((funcid_of.get(s, 0), e))
            else:
                refined_rows.append(row)

    report = {
        "refined_sites": [],
        "total_pruned": sum(pruned_per_site.values()),
        "total_calls_before": calls_before,
        "total_calls_after": calls_before - sum(pruned_per_site.values()),
    }
    for sid in site_precise:
        n = nodes.get(sid, {})
        report["refined_sites"].append({
            "site": sid,
            "line": n.get("lineno"),
            "over_approx": kept_per_site[sid] + pruned_per_site[sid],
            "kept": kept_per_site[sid],
            "pruned": pruned_per_site[sid],
            "literal": site_meta[sid]["literal"],
            "precise_callees": site_meta[sid]["precise_callees"],
        })

    if write:
        cpg_out = wd / dst_edges
        with open(cpg_out, "w", encoding="latin-1", newline="") as f:
            csv.writer(f, delimiter="\t").writerows(refined_rows)
        report["cpg_refined_path"] = str(cpg_out)
        if write_call_graph:
            cg_out = wd / "call_graph_refined.csv"
            with open(cg_out, "w", encoding="latin-1", newline="") as f:
                w = csv.writer(f, delimiter="\t")
                w.writerow(["start", "end", "type", "var"])
                for s, e in cg_rows:
                    w.writerow([s, e, "CALLS", ""])
            report["call_graph_refined_path"] = str(cg_out)
    return report


if __name__ == "__main__":
    import sys, json
    wd = sys.argv[1] if len(sys.argv) > 1 else \
        "working/tchecker-results/eval-ampache-3.9.0"
    rep = refine_dynamic_dispatch_edges(wd, write=True)
    print(f"call_user_func sites refined: {len(rep['refined_sites'])}")
    print(f"CALLS edges: {rep['total_calls_before']} → {rep['total_calls_after']} "
          f"(pruned {rep['total_pruned']})")
    for s in rep["refined_sites"]:
        print(f"  site {s['site']} @line {s['line']}: over-approx {s['over_approx']} "
              f"→ kept {s['kept']} (pruned {s['pruned']}), lit={s['literal']!r}")
        print(f"      precise: {s['precise_callees']}")
