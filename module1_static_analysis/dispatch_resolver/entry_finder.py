
from __future__ import annotations

import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

from .fig_builder import FIG, build_fig, _read_nodes, _read_rels, _normpath
from .narrow import narrow, _containing_file, CandidateDispatchSite
from .context_extractor import build_context
from .llm_resolver import resolve, ResolutionResult, ResolvedCallee


@dataclass
class CallGraph:
    callers_of: dict[int, list[int]] = field(default_factory=lambda: defaultdict(list))
    callees_of: dict[int, list[int]] = field(default_factory=lambda: defaultdict(list))

    @classmethod
    def load(cls, path: Path) -> "CallGraph":
        cg = cls()
        if not path.exists():
            return cg
        with path.open("r", encoding="utf-8") as f:
            first = True
            for raw in f:
                cells = raw.rstrip("\n").split("\t")
                if len(cells) < 2:
                    continue
                if first:
                    first = False
                    if not cells[0].lstrip("-").isdigit():
                        continue
                try:
                    s, e = int(cells[0]), int(cells[1])
                except ValueError:
                    continue
                cg.callers_of[e].append(s)
                cg.callees_of[s].append(e)
        return cg


@dataclass
class EntryHop:
    kind: str
    from_funcid: int
    from_label: str
    to_funcid: int
    to_label: str
    note: str
    site_line: int = 0
    site_node_id: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EntryDiscovery:
    sink_file: str
    sink_line: int
    sink_enclosing_funcid: int
    sink_enclosing_label: str

    found: bool = False
    entry_file: str = ""
    entry_funcid: int = 0
    entry_query: str = ""
    dispatch_param_sources: dict = field(default_factory=dict)
    hops: list[EntryHop] = field(default_factory=list)
    dispatch_decisions: list[ResolutionResult] = field(default_factory=list)
    failure_reason: str = ""
    framework_entry_url: str = ""

    def to_dict(self) -> dict:
        return {
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_enclosing_funcid": self.sink_enclosing_funcid,
            "sink_enclosing_label": self.sink_enclosing_label,
            "found": self.found,
            "entry_file": self.entry_file,
            "entry_funcid": self.entry_funcid,
            "entry_query": self.entry_query,
            "dispatch_param_sources": self.dispatch_param_sources,
            "hops": [h.to_dict() for h in self.hops],
            "dispatch_decisions": [d.to_dict() for d in self.dispatch_decisions],
            "failure_reason": self.failure_reason,
            "framework_entry_url": self.framework_entry_url,
        }


def _enclosing_function_of(
    file: str, lineno: int, nodes: dict[int, dict], fig: FIG
) -> int:
    target_path = fig.file_by_path(file)
    target = target_path.path if target_path else _normpath(file)
    for nid, n in nodes.items():
        try:
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if ln != lineno:
            continue
        try:
            funcid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if not funcid:
            continue
        cf = _containing_file(funcid, fig, nodes)
        if cf == target:
            return funcid
    return 0


def _funcid_label(funcid: int, nodes: dict[int, dict], fig: FIG) -> str:
    n = nodes.get(funcid)
    if not n:
        return f"#{funcid}"
    typ = n.get("type", "")
    if typ == "AST_TOPLEVEL":
        path = n.get("name") or fig.file_by_funcid(funcid).path if fig.file_by_funcid(funcid) else ""
        return f"<toplevel {Path(_normpath(path)).name}>"
    name = n.get("name", "") or "<anon>"
    cls = n.get("classname", "")
    qual = f"{cls}::{name}" if cls else name
    f = _containing_file(funcid, fig, nodes)
    fbase = Path(f).name if f else "?"
    ln = n.get("lineno") or "?"
    return f"{qual} @ {fbase}:{ln}"


def _name_is_ambiguous(funcid: int, nodes: dict[int, dict]) -> bool:
    n = nodes.get(funcid)
    if not n:
        return True
    name = n.get("name")
    if not name:
        return True
    cnt = 0
    for m in nodes.values():
        if m.get("type") in ("AST_FUNC_DECL", "AST_METHOD") and m.get("name") == name:
            cnt += 1
            if cnt > 1:
                return True
    return False


def _is_toplevel_file(funcid: int, fig: FIG) -> bool:
    return fig.file_by_funcid(funcid) is not None


def _is_include_target(fig: FIG, path: str, nodes: dict, p2c: dict) -> bool:
    if fig.transitive_includers(path):
        return True
    import os as _os
    target_base = _os.path.basename(path)
    for inc_path, edge, _val in fig.dynamic_includers(path):
        if not edge.dyn_hole_node:
            continue
        inc_node = fig.file_by_path(inc_path)
        inc_funcid = inc_node.funcid if inc_node else 0
        if _discriminator_request_source(edge.dyn_hole_node, inc_funcid, nodes, p2c):
            return True
        suf_tail = (edge.dyn_suffix or "").rsplit("/", 1)[-1]
        if suf_tail and suf_tail == target_base:
            return True
    return False


_SUPERGLOBAL_CHANNEL = {
    "_GET": "GET", "_POST": "POST", "_REQUEST": "REQUEST", "_COOKIE": "COOKIE",
}


def _string_child(nodes: dict, p2c: dict, nid: int):
    for c in p2c.get(nid, []):
        cn = nodes.get(c)
        if cn and cn["type"] == "string":
            return cn["code"]
    return None


def _superglobal_dim(nodes: dict, p2c: dict, nid: int):
    n = nodes.get(nid)
    if not n or n["type"] != "AST_DIM":
        return None
    kids = sorted(p2c.get(nid, []), key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
    if len(kids) < 2:
        return None
    base = nodes.get(kids[0])
    if not base or base["type"] != "AST_VAR":
        return None
    sg = _string_child(nodes, p2c, kids[0])
    if sg not in _SUPERGLOBAL_CHANNEL:
        return None
    kn = nodes.get(kids[1])
    if kn and kn["type"] == "string" and kn["code"]:
        return (_SUPERGLOBAL_CHANNEL[sg], kn["code"])
    return None


def _base_var_name(nodes: dict, p2c: dict, nid: int):
    n = nodes.get(nid)
    if not n:
        return None
    if n["type"] == "AST_VAR":
        return _string_child(nodes, p2c, nid)
    if n["type"] == "AST_DIM":
        kids = sorted(p2c.get(nid, []), key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
        if kids:
            return _base_var_name(nodes, p2c, kids[0])
    return None


def _subtree_ids(p2c: dict, root: int) -> list:
    seen = {root}; stack = [root]
    while stack:
        cur = stack.pop()
        for c in p2c.get(cur, []):
            if c not in seen:
                seen.add(c); stack.append(c)
    return list(seen)


def _discriminator_request_source(
    hole_node: int, funcid: int, nodes: dict, p2c: dict
):
    direct = _superglobal_dim(nodes, p2c, hole_node)
    if direct:
        return direct
    base_var = _base_var_name(nodes, p2c, hole_node)
    if not base_var:
        return None
    for nid, n in nodes.items():
        if n["type"] not in ("AST_ASSIGN", "AST_ASSIGN_REF"):
            continue
        try:
            if int(n["funcid"] or 0) != funcid:
                continue
        except (ValueError, TypeError):
            continue
        kids = sorted(p2c.get(nid, []), key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
        if len(kids) < 2:
            continue
        lhs, rhs = kids[0], kids[-1]
        if _base_var_name(nodes, p2c, lhs) != base_var:
            continue
        for sub in _subtree_ids(p2c, rhs):
            res = _superglobal_dim(nodes, p2c, sub)
            if res:
                return res
    return None


def _reconstruct_path(entry_key, parent: dict) -> list:
    hops = []
    cur = entry_key
    seen = set()
    while cur in parent and cur not in seen:
        seen.add(cur)
        pf, pr, hop = parent[cur]
        hops.append(hop)
        cur = (pf, pr)
    return list(reversed(hops))


def preload_cpg(working_dir: str | Path) -> dict:
    wd = Path(working_dir)
    return {
        "fig": build_fig(wd),
        "nodes": _read_nodes(wd / "nodes.csv"),
        "p2c": _read_rels(wd / "rels.csv"),
        "cg": CallGraph.load(wd / "call_graph.csv"),
    }


def discover_entry(
    sink_file: str,
    sink_line: int,
    working_dir: str | Path,
    *,
    llm_call: Optional[Callable[[str], str]] = None,
    webroot_predicate: Callable[[str], bool] = lambda _: True,
    max_iterations: int = 64,
    verbose: bool = False,
    cpg: Optional[dict] = None,
    collect_all: bool = False,
):
    wd = Path(working_dir)
    _c = cpg or {}
    fig = _c.get("fig") or build_fig(wd)
    nodes = _c.get("nodes") if _c.get("nodes") is not None else _read_nodes(wd / "nodes.csv")
    parent2children = _c.get("p2c") if _c.get("p2c") is not None else _read_rels(wd / "rels.csv")
    cg = _c.get("cg") or CallGraph.load(wd / "call_graph.csv")
    dispatch_csv = wd / "dispatch_sinks.csv"
    nodes_csv = wd / "nodes.csv"

    def vlog(msg: str):
        if verbose:
            print(f"[entry_finder] {msg}", file=sys.stderr)

    page_local_fallback = None
    page_local_fallback_funcid = 0
    sink_file_node = fig.file_by_path(sink_file)
    if sink_file_node and webroot_predicate(sink_file_node.path):
        sink_toplevel_fn = sink_file_node.funcid if sink_file_node.funcid else None
        if sink_toplevel_fn and _is_toplevel_file(sink_toplevel_fn, fig):
            sink_fn_short = _enclosing_function_of(sink_file, sink_line, nodes, fig)
            if (sink_fn_short is None or sink_fn_short == sink_toplevel_fn) \
                    and not _is_include_target(fig, sink_file_node.path, nodes, parent2children):
                discovery = EntryDiscovery(
                    sink_file=sink_file, sink_line=sink_line,
                    sink_enclosing_funcid=sink_fn_short or sink_toplevel_fn,
                    sink_enclosing_label=_funcid_label(
                        sink_fn_short or sink_toplevel_fn, nodes, fig),
                )
                discovery.found = True
                discovery.entry_file = sink_file_node.path
                discovery.entry_funcid = sink_toplevel_fn
                vlog(f"sink-file shortcut: {sink_file_node.path} is a "
                     f"TOPLEVEL_FILE and sink is in script body")
                return discovery
            elif (sink_fn_short is None or sink_fn_short == sink_toplevel_fn):
                vlog(f"sink-file is TOPLEVEL_FILE with body sink, but it is an "
                     f"INCLUDE TARGET (included by another file) — not a standalone "
                     f"entry; walking back to includer(s)")
            elif not _is_include_target(fig, sink_file_node.path, nodes, parent2children) \
                    and (nodes.get(sink_fn_short) or {}).get("type") != "AST_METHOD" \
                    and _name_is_ambiguous(sink_fn_short, nodes):
                d = EntryDiscovery(
                    sink_file=sink_file, sink_line=sink_line,
                    sink_enclosing_funcid=sink_fn_short,
                    sink_enclosing_label=_funcid_label(sink_fn_short, nodes, fig),
                    found=True,
                )
                d.entry_file = sink_file_node.path
                d.entry_funcid = sink_toplevel_fn
                d.hops.append(EntryHop(
                    kind="page_local", from_funcid=sink_fn_short,
                    from_label=_funcid_label(sink_fn_short, nodes, fig),
                    to_funcid=sink_toplevel_fn,
                    to_label=Path(sink_file_node.path).name,
                    note="sink fn defined in web-reachable non-included page; "
                         "page-local entry (preferred over name-based caller walk)"))
                vlog(f"ENTRY via page-local (sink fn in web page): "
                     f"{sink_file_node.path}")
                return d
            else:
                vlog(f"sink-file is TOPLEVEL_FILE but sink is inside a "
                     f"named function (funcid={sink_fn_short}) AND the file is "
                     f"an include target; skipping shortcut, walking callers")

    sink_fn = _enclosing_function_of(sink_file, sink_line, nodes, fig)
    if not sink_fn:
        if page_local_fallback is not None:
            d = EntryDiscovery(
                sink_file=sink_file, sink_line=sink_line,
                sink_enclosing_funcid=page_local_fallback_funcid,
                sink_enclosing_label=_funcid_label(page_local_fallback_funcid, nodes, fig),
                found=True,
            )
            d.entry_file = page_local_fallback
            d.entry_funcid = page_local_fallback_funcid
            d.hops.append(EntryHop(
                kind="page_local_fallback", from_funcid=0,
                from_label="<sink body, funcid unresolved>",
                to_funcid=page_local_fallback_funcid,
                to_label=Path(page_local_fallback).name,
                note="sink-fn unresolved; page-local to web entry"))
            vlog(f"ENTRY via page-local fallback (no enclosing fn): {page_local_fallback}")
            return d
        return EntryDiscovery(
            sink_file=sink_file, sink_line=sink_line,
            sink_enclosing_funcid=0, sink_enclosing_label="<not found>",
            found=False,
            failure_reason="could not locate enclosing function for sink",
        )

    discovery = EntryDiscovery(
        sink_file=sink_file, sink_line=sink_line,
        sink_enclosing_funcid=sink_fn,
        sink_enclosing_label=_funcid_label(sink_fn, nodes, fig),
    )
    vlog(f"sink enclosing fn: {discovery.sink_enclosing_label} (id={sink_fn})")

    _sink_direct_callers = cg.callers_of.get(sink_fn, []) if collect_all else []
    _multi_caller = len(set(_sink_direct_callers)) > 1
    visited: set = set()
    queue: deque = deque([(sink_fn, None)])
    iters = 0
    parent: dict = {}
    collected: list[tuple] = []
    collected_files: set = set()

    while queue and iters < max_iterations:
        iters += 1
        cur, root = queue.popleft()
        if (cur, root) in visited:
            continue
        visited.add((cur, root))

        if _is_toplevel_file(cur, fig):
            f = fig.file_by_funcid(cur)
            assert f is not None
            if webroot_predicate(f.path) and not _is_include_target(fig, f.path, nodes, parent2children):
                if collect_all:
                    if (f.path, root) not in collected_files:
                        collected_files.add((f.path, root))
                        collected.append((f.path, cur, "", root))
                        vlog(f"ENTRY COLLECTED: {f.path}" + (f" [root={root}]" if root else ""))
                    continue
                discovery.found = True
                discovery.entry_file = f.path
                discovery.entry_funcid = cur
                vlog(f"ENTRY FOUND: {f.path}")
                return discovery
            static_incs = fig.transitive_includers(f.path) or []
            dyn_incs = fig.dynamic_includers(f.path) or []
            vlog(f"reached TOPLEVEL {Path(f.path).name} (include target); [C] "
                 f"{len(static_incs)} static + {len(dyn_incs)} dynamic includer(s)")
            for inc_path in static_incs:
                if webroot_predicate(inc_path) and not _is_include_target(fig, inc_path, nodes, parent2children):
                    inc_node = fig.file_by_path(inc_path)
                    inc_funcid = inc_node.funcid if inc_node else 0
                    _ihop = EntryHop(
                        kind="include_reverse", from_funcid=cur,
                        from_label=_funcid_label(cur, nodes, fig),
                        to_funcid=inc_funcid, to_label=Path(inc_path).name,
                        note=f"require chain {Path(f.path).name} <- {Path(inc_path).name}")
                    discovery.hops.append(_ihop)
                    if collect_all:
                        if (inc_path, root) not in collected_files:
                            collected_files.add((inc_path, root))
                            if (inc_funcid, root) not in parent:
                                parent[(inc_funcid, root)] = (cur, root, _ihop)
                            collected.append((inc_path, inc_funcid, "", root))
                            vlog(f"ENTRY COLLECTED via reverse-include: {inc_path}")
                        continue
                    discovery.found = True
                    discovery.entry_file = inc_path
                    discovery.entry_funcid = inc_funcid
                    vlog(f"ENTRY FOUND via reverse-include: {inc_path}")
                    return discovery
            for inc_path, edge, hole_value in dyn_incs:
                if not (webroot_predicate(inc_path) and not _is_include_target(fig, inc_path, nodes, parent2children)):
                    continue
                inc_node = fig.file_by_path(inc_path)
                inc_funcid = inc_node.funcid if inc_node else 0
                src = (_discriminator_request_source(
                    edge.dyn_hole_node, inc_funcid, nodes, parent2children)
                    if edge.dyn_hole_node else None)
                if not src:
                    vlog(f"[C-dyn] {Path(inc_path).name} dynamically includes "
                         f"{Path(f.path).name} but discriminator not request-"
                         f"controlled — skip")
                    continue
                channel, key = src
                _dhop = EntryHop(
                    kind="include_dispatch", from_funcid=cur,
                    from_label=_funcid_label(cur, nodes, fig),
                    to_funcid=inc_funcid, to_label=Path(inc_path).name,
                    note=f"dynamic include {Path(inc_path).name} -> {Path(f.path).name} "
                         f"via ${channel}['{key}']='{hole_value}'",
                    site_line=edge.site_lineno,
                    site_node_id=edge.site_node_id)
                discovery.hops.append(_dhop)
                discovery.dispatch_param_sources[key] = channel
                discovery.dispatch_decisions.append(ResolutionResult(
                    site_id=edge.site_node_id, file=inc_path, lineno=edge.site_lineno,
                    method="static_full", confidence=0.9,
                    discriminator_origin="fully_input",
                    resolved_callees=[ResolvedCallee(
                        callee=Path(f.path).name, file=f.path, line=sink_line,
                        reaches_sink=True,
                        condition=f"{key}={hole_value} selects {Path(f.path).name}",
                        structured_condition={"param": key, "equals": hole_value})]))
                _dquery = f"{key}={hole_value}" if channel in ("GET", "REQUEST") else ""
                if collect_all:
                    if (inc_path, root) not in collected_files:
                        collected_files.add((inc_path, root))
                        if (inc_funcid, root) not in parent:
                            parent[(inc_funcid, root)] = (cur, root, _dhop)
                        collected.append((inc_path, inc_funcid, _dquery, root))
                        vlog(f"ENTRY COLLECTED via dynamic include: "
                             f"{Path(inc_path).name}?{key}={hole_value}")
                    continue
                if _dquery:
                    discovery.entry_query = _dquery
                discovery.found = True
                discovery.entry_file = inc_path
                discovery.entry_funcid = inc_funcid
                vlog(f"ENTRY FOUND via dynamic include: {Path(inc_path).name}?{key}={hole_value}")
                return discovery
            enq = 0
            for inc_path in static_incs:
                inc_node = fig.file_by_path(inc_path)
                if inc_node and (inc_node.funcid, root) not in visited:
                    if (inc_node.funcid, root) not in parent:
                        parent[(inc_node.funcid, root)] = (cur, root, EntryHop(
                            kind="include_reverse", from_funcid=cur,
                            from_label=_funcid_label(cur, nodes, fig),
                            to_funcid=inc_node.funcid, to_label=Path(inc_path).name,
                            note=f"require chain {Path(f.path).name} <- {Path(inc_path).name}"))
                    queue.append((inc_node.funcid, root)); enq += 1
            vlog(f"[C] no standalone includer of {Path(f.path).name}; "
                 f"enqueued {enq} for deeper walk")
            continue

        callers = cg.callers_of.get(cur, [])
        cur_label = _funcid_label(cur, nodes, fig)
        if callers:
            for caller in callers:
                _newroot = caller if (_multi_caller and cur == sink_fn) else root
                if (caller, _newroot) in visited:
                    continue
                _hop = EntryHop(
                    kind="callgraph",
                    from_funcid=cur, from_label=cur_label,
                    to_funcid=caller,
                    to_label=_funcid_label(caller, nodes, fig),
                    note="static CALLS edge",
                )
                discovery.hops.append(_hop)
                if (caller, _newroot) not in parent:
                    parent[(caller, _newroot)] = (cur, root, _hop)
                queue.append((caller, _newroot))
            vlog(f"[A] {cur_label}: {len(callers)} caller(s)")
            continue

        cur_file = _containing_file(cur, fig, nodes)
        if not cur_file:
            vlog(f"[B] cannot locate file of fn {cur}; skipping")
            continue
        sites = narrow(cur_file, fig, dispatch_csv, nodes_csv)
        vlog(f"[B] {cur_label} has no static callers; "
             f"{len(sites)} dispatch site(s) target file {Path(cur_file).name}")
        for site in sites:
            ctx = build_context(site, fig, wd, sink_file, sink_line=sink_line)
            res = resolve(ctx, llm_call=llm_call)
            discovery.dispatch_decisions.append(res)

            relevant = [r for r in res.resolved_callees if r.reaches_sink]
            if not relevant:
                continue
            site_fn = _enclosing_function_of(site.file, site.lineno, nodes, fig)
            if not site_fn or (site_fn, root) in visited:
                continue
            note_callees = ", ".join(r.callee for r in relevant[:3])
            _ehop = EntryHop(
                kind="dispatch_escape",
                from_funcid=cur, from_label=cur_label,
                to_funcid=site_fn,
                to_label=_funcid_label(site_fn, nodes, fig),
                note=f"dispatch {site.category} @ "
                     f"{Path(site.file).name}:{site.lineno} → {note_callees}",
            )
            discovery.hops.append(_ehop)
            if (site_fn, root) not in parent:
                parent[(site_fn, root)] = (cur, root, _ehop)
            queue.append((site_fn, root))

    if collect_all:
        results: list = []
        for _ef, _efid, _eq, _root in collected:
            _d = EntryDiscovery(
                sink_file=sink_file, sink_line=sink_line,
                sink_enclosing_funcid=sink_fn,
                sink_enclosing_label=discovery.sink_enclosing_label)
            _d.found = True
            _d.entry_file = _ef
            _d.entry_funcid = _efid
            _d.entry_query = _eq
            _d.hops = _reconstruct_path((_efid, _root), parent)
            _d.dispatch_param_sources = dict(discovery.dispatch_param_sources)
            results.append(_d)
        if not results and page_local_fallback is not None:
            _d = EntryDiscovery(
                sink_file=sink_file, sink_line=sink_line,
                sink_enclosing_funcid=sink_fn,
                sink_enclosing_label=discovery.sink_enclosing_label)
            _d.found = True
            _d.entry_file = page_local_fallback
            _d.entry_funcid = page_local_fallback_funcid
            results.append(_d)
        vlog(f"collect_all: {len(results)} entry(ies) collected")
        return results

    if not discovery.found and page_local_fallback is not None:
        discovery.found = True
        discovery.entry_file = page_local_fallback
        discovery.entry_funcid = page_local_fallback_funcid
        discovery.hops.append(EntryHop(
            kind="page_local_fallback", from_funcid=sink_fn,
            from_label=_funcid_label(sink_fn, nodes, fig),
            to_funcid=page_local_fallback_funcid,
            to_label=Path(page_local_fallback).name,
            note="sink-fn page-local to web entry; call-graph lacked toplevel->fn edge"))
        vlog(f"ENTRY via page-local fallback: {page_local_fallback} "
             f"(sink-fn page-local; call-graph lacked toplevel->fn edge)")
        return discovery

    if not discovery.found:
        discovery.failure_reason = (
            f"exhausted backward walk after {iters} iteration(s); "
            f"no TOPLEVEL_FILE satisfying webroot_predicate reached "
            f"(visited {len(visited)} fn(s))"
        )
    return discovery


def _main():
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description="Walk back from a sink to a script entry, "
                    "alternating callgraph + dispatch escape.")
    ap.add_argument("-w", "--working-dir", required=True,
                    help="Dir with nodes.csv/rels.csv/call_graph.csv/dispatch_sinks.csv")
    ap.add_argument("-s", "--sink-file", required=True)
    ap.add_argument("-l", "--sink-line", required=True, type=int)
    ap.add_argument("--entry-suffix", default="",
                    help="Optional path suffix the entry script must match "
                         "(e.g. 'index.php'). Default: accept any TOPLEVEL_FILE.")
    ap.add_argument("--llm-backend", choices=["none", "anthropic"], default="none")
    ap.add_argument("--model", default="claude-opus-4-7")
    ap.add_argument("--json", action="store_true",
                    help="Print full JSON discovery record")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    backend = None
    if args.llm_backend == "anthropic":
        from .llm_resolver import make_anthropic_backend
        backend = make_anthropic_backend(model=args.model)

    predicate = (lambda p: True) if not args.entry_suffix \
        else (lambda p, sfx=args.entry_suffix: p.endswith(sfx) or p.endswith("/" + sfx))

    d = discover_entry(
        sink_file=args.sink_file,
        sink_line=args.sink_line,
        working_dir=args.working_dir,
        llm_call=backend,
        webroot_predicate=predicate,
        verbose=args.verbose,
    )

    if args.json:
        print(json.dumps(d.to_dict(), indent=2, ensure_ascii=False))
        return

    print(f"\n  sink:    {d.sink_file}:{d.sink_line}")
    print(f"  encloser: {d.sink_enclosing_label}  (fn id={d.sink_enclosing_funcid})")
    if d.found:
        print(f"\n  ★ ENTRY FOUND: {d.entry_file}  (fn id={d.entry_funcid})")
    else:
        print(f"\n  ✗ NO ENTRY: {d.failure_reason}")
    print(f"\n  backward walk ({len(d.hops)} hop(s)):")
    for i, h in enumerate(d.hops, 1):
        arrow = "─[callgraph]──>" if h.kind == "callgraph" else "─[dispatch ]──>"
        print(f"   {i:>2}. {h.from_label}")
        print(f"       {arrow} {h.to_label}")
        print(f"       note: {h.note}")
    if d.dispatch_decisions:
        print(f"\n  dispatch decisions ({len(d.dispatch_decisions)}):")
        for r in d.dispatch_decisions:
            print(f"   - site {r.site_id} ({Path(r.file).name}:{r.lineno})  "
                  f"origin={r.discriminator_origin}  method={r.method}")
            for rc in r.resolved_callees:
                tag = "★ reaches sink" if rc.reaches_sink else ""
                print(f"       → {rc.callee:<30} {tag}  cond: {rc.condition[:80]}")


if __name__ == "__main__":
    _main()
