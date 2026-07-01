
from __future__ import annotations

import os.path as osp
import sys
from typing import Optional

_VIPER_ROOT = osp.dirname(osp.abspath(__file__))
if _VIPER_ROOT not in sys.path:
    sys.path.insert(0, _VIPER_ROOT)


_SUPERGLOBAL_CHANNEL = {
    "_GET": "GET", "_POST": "POST", "_REQUEST": "REQUEST", "_COOKIE": "COOKIE",
}


def _load_wrapper_channels() -> dict:
    import os
    from pathlib import Path
    out: dict = {}
    base = (Path(__file__).resolve().parent / "TChecker-VIPER" / "projects"
            / "extensions" / "jpanlib" / "src" / "main" / "resources"
            / "wrapper_sources.csv")
    paths = [base]
    extra = os.environ.get("WRAPPER_SOURCES_CSV", "")
    if extra:
        paths.append(Path(extra))
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[0].strip() == "-":
                        fname = parts[1].strip()
                        chan = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else "REQUEST"
                        if fname:
                            out[fname] = chan
        except OSError:
            continue
    return out


def _childnum(nodes, nid):
    try:
        return int(nodes.get(nid, {}).get("childnum") or 0)
    except (ValueError, TypeError):
        return 0


def _kids(parent2children, nid):
    return parent2children.get(nid, [])


def _string_child(nodes, parent2children, nid):
    for c in _kids(parent2children, nid):
        n = nodes.get(c)
        if n and n.get("type") == "string":
            return (n.get("code") or "").strip("'\"")
    return None


def _callee_name(nodes, parent2children, call_nid):
    n = nodes.get(call_nid)
    if not n:
        return None
    t = n.get("type")
    if t == "AST_CALL":
        for c in _kids(parent2children, call_nid):
            cn = nodes.get(c)
            if cn and cn.get("type") == "AST_NAME":
                return _string_child(nodes, parent2children, c)
    elif t in ("AST_METHOD_CALL", "AST_STATIC_CALL"):
        for c in sorted(_kids(parent2children, call_nid), key=lambda c: _childnum(nodes, c)):
            cn = nodes.get(c)
            if cn and cn.get("type") == "string":
                return (cn.get("code") or "").strip("'\"")
    return None


def _first_string_arg(nodes, parent2children, call_nid):
    for c in _kids(parent2children, call_nid):
        cn = nodes.get(c)
        if cn and cn.get("type") == "AST_ARG_LIST":
            for a in sorted(_kids(parent2children, c), key=lambda x: _childnum(nodes, x)):
                an = nodes.get(a)
                if an and an.get("type") == "string":
                    return (an.get("code") or "").strip("'\"")
                return None
    return None


def _superglobal_dim_key(nodes, parent2children, dim_nid):
    n = nodes.get(dim_nid)
    if not n or n.get("type") != "AST_DIM":
        return None
    kids = sorted(_kids(parent2children, dim_nid), key=lambda c: _childnum(nodes, c))
    if len(kids) < 2:
        return None
    base = nodes.get(kids[0])
    if not base or base.get("type") != "AST_VAR":
        return None
    sg = _string_child(nodes, parent2children, kids[0])
    if sg not in _SUPERGLOBAL_CHANNEL:
        return None
    keyn = nodes.get(kids[1])
    if keyn and keyn.get("type") == "string":
        k = (keyn.get("code") or "").strip("'\"")
        if k:
            return (_SUPERGLOBAL_CHANNEL[sg], k)
    return None


def _enclosing_assign(nodes, parent2children, child2parent, nid):
    cur = nid
    seen = set()
    while cur and cur not in seen:
        seen.add(cur)
        n = nodes.get(cur)
        if n and n.get("type") in ("AST_ASSIGN", "AST_ASSIGN_OP", "AST_ASSIGN_REF"):
            return cur
        cur = child2parent.get(cur)
    return None


def discover_sources(
    working_dir: str,
    sink_file: str,
    sink_line: int,
    *,
    trace=None,
    terminal_line: Optional[int] = None,
    known_keys=frozenset(),
    max_candidates: int = 12,
) -> list[dict]:
    from module1_static_analysis.dispatch_resolver.superglobal_keys import _load_cpg, _load_wrapper_funcs
    from module1_static_analysis.dispatch_resolver.narrow import _containing_file

    bundle = _load_cpg(working_dir)
    if bundle is None:
        return []
    nodes, reaches_rev, parent2children, fig = bundle

    reaches_fwd: dict = {}
    for e, srcs in reaches_rev.items():
        for s in srcs:
            reaches_fwd.setdefault(s, []).append(e)
    child2parent: dict = {}
    for p, cs in parent2children.items():
        for c in cs:
            child2parent[c] = p

    wrapper_funcs = _load_wrapper_funcs()
    wrapper_chan = _load_wrapper_channels()
    sink_basename = osp.basename(sink_file)

    sink_funcids: set = set()
    sink_node_ids: set = set()
    for nid, n in nodes.items():
        try:
            if int(n.get("lineno") or 0) != sink_line:
                continue
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        cf = _containing_file(fid, fig, nodes) if fid else ""
        if cf and osp.basename(cf) == sink_basename:
            sink_funcids.add(fid)
            sink_node_ids.add(nid)

    def _reaches_sink(read_nid: int) -> bool:
        assign = _enclosing_assign(nodes, parent2children, child2parent, read_nid)
        seed = assign if assign is not None else read_nid
        closure = {seed}
        stack = [seed]
        while stack:
            cur = stack.pop()
            if cur in sink_node_ids:
                return True
            for e in reaches_fwd.get(cur, []):
                if e not in closure:
                    closure.add(e)
                    stack.append(e)
        for nid in closure:
            n = nodes.get(nid)
            if not n:
                continue
            try:
                if int(n.get("lineno") or 0) == sink_line and int(n.get("funcid") or 0) in sink_funcids:
                    return True
            except (ValueError, TypeError):
                continue
        return False

    raw: dict = {}

    def _consider(read_nid, line, channel, key, via):
        if not key or key in known_keys:
            return
        reaches = _reaches_sink(read_nid)
        prev = raw.get(key)
        cand = {"key": key, "channel": channel or "REQUEST", "site_line": line,
                "via": via, "reaches_sink": reaches}
        if prev is None:
            raw[key] = cand
        else:
            if (reaches and not prev["reaches_sink"]) or \
               (reaches == prev["reaches_sink"] and via == "runtime" and prev["via"] != "runtime"):
                raw[key] = cand

    if trace is not None:
        observed_lines: set = set()
        for b in getattr(trace, "blocker_events", []) or []:
            if b.kind != "dispatch_observed":
                continue
            callee = (b.raw.get("dispatch", {}) or {}).get("callee_function", "")
            if callee not in wrapper_funcs:
                continue
            loc = b.location or {}
            if osp.basename(loc.get("file", "")) != sink_basename:
                continue
            try:
                observed_lines.add(int(loc.get("line", 0)))
            except (ValueError, TypeError):
                continue
        for line in observed_lines:
            for nid, n in nodes.items():
                if n.get("type") != "AST_CALL":
                    continue
                try:
                    if int(n.get("lineno") or 0) != line:
                        continue
                    fid = int(n.get("funcid") or 0)
                except (ValueError, TypeError):
                    continue
                if fid not in sink_funcids:
                    continue
                cn = _callee_name(nodes, parent2children, nid)
                if cn in wrapper_funcs:
                    key = _first_string_arg(nodes, parent2children, nid)
                    _consider(nid, line, wrapper_chan.get(cn, "REQUEST"), key, "runtime")

    for nid, n in nodes.items():
        try:
            ln = int(n.get("lineno") or 0)
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if fid not in sink_funcids or ln <= 0 or ln > sink_line:
            continue
        t = n.get("type")
        if t == "AST_CALL":
            cn = _callee_name(nodes, parent2children, nid)
            if cn in wrapper_funcs:
                key = _first_string_arg(nodes, parent2children, nid)
                via = "lookahead" if (terminal_line and ln > terminal_line) else "in-path"
                _consider(nid, ln, wrapper_chan.get(cn, "REQUEST"), key, via)
        elif t == "AST_DIM":
            res = _superglobal_dim_key(nodes, parent2children, nid)
            if res:
                chan, key = res
                via = "lookahead" if (terminal_line and ln > terminal_line) else "in-path"
                _consider(nid, ln, chan, key, via)

    out = sorted(raw.values(),
                 key=lambda c: (not c["reaches_sink"], c["via"] != "runtime", c["site_line"]))
    return out[:max_candidates]


def _main():
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description="Discover NEW request-source params reaching a sink "
                    "(static M2 lookahead; M1 needs a trace, not via CLI).")
    ap.add_argument("--working-dir", required=True)
    ap.add_argument("--sink-file", required=True, help="sink source-file basename")
    ap.add_argument("--sink-line", type=int, required=True)
    ap.add_argument("--terminal-line", type=int, default=None,
                    help="current stuck line; reads past it are tagged 'lookahead'")
    ap.add_argument("--known", default="",
                    help="comma-separated keys already collected (excluded)")
    args = ap.parse_args()
    known = {k.strip() for k in args.known.split(",") if k.strip()}
    cands = discover_sources(
        args.working_dir, args.sink_file, args.sink_line,
        terminal_line=args.terminal_line, known_keys=known)
    print(json.dumps(cands, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _main()
