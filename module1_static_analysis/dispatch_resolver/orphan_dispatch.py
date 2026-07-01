from __future__ import annotations

import csv
import os.path as osp
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from .fig_builder import _read_nodes


@dataclass
class DynCalleeCandidate:
    callee_key: str
    callee_node_id: int
    method_name: str
    classname: str
    match_kind: str
    literal: str


def _children(nid: int, p2c: dict, nodes: dict) -> list[int]:
    return sorted(p2c.get(nid, []),
                  key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))


def _string_child(nid: int, p2c: dict, nodes: dict) -> str:
    for c in _children(nid, p2c, nodes):
        cn = nodes.get(c)
        if cn and cn.get("type") == "string":
            return (cn.get("code") or "").strip().strip('"').strip("'")
    return ""


def _enclosing_classname(site_id: int, child2parent: dict, nodes: dict) -> str:
    cur = site_id
    for _ in range(60):
        n = nodes.get(cur) or {}
        if n.get("type") in ("AST_METHOD",) and n.get("classname"):
            return n.get("classname")
        if n.get("type") == "AST_CLASS" and n.get("name"):
            return n.get("name")
        par = child2parent.get(cur)
        if par is None:
            break
        cur = par
    return ""


def _call_fname(call_id: int, p2c: dict, nodes: dict) -> str:
    kids = _children(call_id, p2c, nodes)
    if not kids:
        return ""
    name_node = nodes.get(kids[0])
    if name_node and name_node.get("type") == "AST_NAME":
        return _string_child(kids[0], p2c, nodes)
    return ""


def _concat_literal_and_side(name_expr_id: int, p2c: dict, nodes: dict
                              ) -> tuple[str, str]:
    n = nodes.get(name_expr_id) or {}
    t = n.get("type")
    if t == "string":
        return (n.get("code") or "").strip().strip('"').strip("'"), "exact"
    if t == "AST_BINARY_OP":
        kids = _children(name_expr_id, p2c, nodes)
        if len(kids) >= 2:
            l, r = nodes.get(kids[0]) or {}, nodes.get(kids[1]) or {}
            if r.get("type") == "string":
                lit = (r.get("code") or "").strip().strip('"').strip("'")
                if lit:
                    return lit, "suffix"
            if l.get("type") == "string":
                lit = (l.get("code") or "").strip().strip('"').strip("'")
                if lit:
                    return lit, "prefix"
    return "", ""


@dataclass
class _CallableDesc:
    recv_kind: str = ""
    recv_class: str = ""
    name_literal: str = ""
    name_side: str = ""


def _describe_array_callable(arr_id: int, site_id: int,
                              p2c: dict, child2parent: dict, nodes: dict
                              ) -> Optional[_CallableDesc]:
    elems = [c for c in _children(arr_id, p2c, nodes)
             if (nodes.get(c) or {}).get("type") == "AST_ARRAY_ELEM"]
    if len(elems) != 2:
        return None
    recv_val = _children(elems[0], p2c, nodes)
    name_val = _children(elems[1], p2c, nodes)
    if not recv_val or not name_val:
        return None
    recv_node = nodes.get(recv_val[0]) or {}
    desc = _CallableDesc()
    if recv_node.get("type") == "AST_VAR":
        vname = _string_child(recv_val[0], p2c, nodes)
        if vname == "this":
            desc.recv_kind = "this"
            desc.recv_class = _enclosing_classname(site_id, child2parent, nodes)
        else:
            desc.recv_kind = "var"
    elif recv_node.get("type") == "AST_NEW":
        desc.recv_kind = "newclass"
    elif recv_node.get("type") == "string":
        desc.recv_kind = "static"
        desc.recv_class = (recv_node.get("code") or "").strip().strip('"').strip("'")
    desc.name_literal, desc.name_side = _concat_literal_and_side(
        name_val[0], p2c, nodes)
    if not desc.name_side:
        return None
    return desc


def _name_matches(method_name: str, literal: str, side: str) -> bool:
    if side == "exact":
        return method_name == literal
    if side == "suffix":
        return method_name.endswith(literal) and len(method_name) > len(literal)
    if side == "prefix":
        return method_name.startswith(literal) and len(method_name) > len(literal)
    return False


def resolve_dynamic_method_callees(
    site_id: int,
    nodes: dict,
    p2c: dict,
    child2parent: dict,
    *,
    restrict_to: Optional[set[int]] = None,
) -> list[DynCalleeCandidate]:
    site = nodes.get(site_id) or {}
    if site.get("type") != "AST_CALL":
        return []
    if _call_fname(site_id, p2c, nodes) != "call_user_func":
        return []
    arg_list_kids = _children(site_id, p2c, nodes)
    if len(arg_list_kids) < 2:
        return []
    arg_list = arg_list_kids[1]
    args = _children(arg_list, p2c, nodes)
    if not args:
        return []
    callable_node = nodes.get(args[0]) or {}
    if callable_node.get("type") != "AST_ARRAY":
        return []
    desc = _describe_array_callable(args[0], site_id, p2c, child2parent, nodes)
    if desc is None or not desc.name_side:
        return []

    out: list[DynCalleeCandidate] = []
    for nid, n in nodes.items():
        if n.get("type") != "AST_METHOD":
            continue
        mname = n.get("name") or ""
        if not mname:
            continue
        if not _name_matches(mname, desc.name_literal, desc.name_side):
            continue
        cls = n.get("classname") or ""
        if desc.recv_class and cls and cls != desc.recv_class:
            continue
        if restrict_to is not None and nid not in restrict_to:
            continue
        match_kind = ("class_any" if not desc.recv_class
                      else f"concat_{desc.name_side}" if desc.name_side != "exact"
                      else "exact")
        out.append(DynCalleeCandidate(
            callee_key=f"{cls}::{mname}" if cls else mname,
            callee_node_id=nid, method_name=mname, classname=cls,
            match_kind=match_kind, literal=desc.name_literal,
        ))
    return out


@dataclass
class RoutingSite:
    site_id: int
    site_file: str
    site_line: int
    site_funcid: int
    candidates: list = field(default_factory=list)


def _read_dispatch_site_ids(dispatch_sinks_csv: Path) -> set[int]:
    out: set[int] = set()
    if not dispatch_sinks_csv.exists():
        return out
    with open(dispatch_sinks_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                out.add(int(row["site_id"]))
            except (ValueError, KeyError):
                continue
    return out


def find_routing_dispatch_sites(
    sink_file: str,
    orphan_fn_node: int,
    working_dir: str | Path,
    fig,
    nodes: dict,
    p2c: dict,
    child2parent: dict,
    *,
    enclosing_fn_of,
) -> list[RoutingSite]:
    wd = Path(working_dir)
    site_ids = _read_dispatch_site_ids(wd / "dispatch_sinks.csv")
    if not site_ids:
        return []

    try:
        search_files = set(fig.transitive_includers(sink_file))
    except Exception:
        search_files = set()
    search_files.add(sink_file)
    search_bn = {osp.basename(p) for p in search_files}

    out: list[RoutingSite] = []
    restrict = {orphan_fn_node}
    for sid in site_ids:
        sn = nodes.get(sid)
        if not sn:
            continue
        site_file = _node_file(sid, child2parent, nodes, fig)
        if not site_file or osp.basename(site_file) not in search_bn \
                or site_file not in search_files:
            continue
        cands = resolve_dynamic_method_callees(
            sid, nodes, p2c, child2parent, restrict_to=restrict)
        if not cands:
            continue
        try:
            line = int(sn.get("lineno") or 0)
        except (ValueError, TypeError):
            line = 0
        site_fn = enclosing_fn_of(site_file, line)
        out.append(RoutingSite(
            site_id=sid, site_file=site_file, site_line=line,
            site_funcid=site_fn or 0, candidates=cands))
    return out


def _node_file(nid: int, child2parent: dict, nodes: dict, fig) -> str:
    from .narrow import _containing_file
    n = nodes.get(nid) or {}
    try:
        fid = int(n.get("funcid") or 0)
    except (ValueError, TypeError):
        fid = 0
    if fid:
        return _containing_file(fid, fig, nodes) or ""
    return ""


def _read_child_to_parent(rels_csv: Path) -> tuple[dict, dict]:
    p2c: dict = {}
    c2p: dict = {}
    with open(rels_csv, encoding="latin-1") as f:
        next(f, None)
        for raw in f:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) >= 3 and parts[2] == "PARENT_OF":
                try:
                    s, e = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                p2c.setdefault(s, []).append(e)
                c2p[e] = s
    return p2c, c2p


if __name__ == "__main__":
    import sys
    wd = Path(sys.argv[1] if len(sys.argv) > 1 else
              "working/tchecker-results/eval-ampache-3.9.0")
    site = int(sys.argv[2]) if len(sys.argv) > 2 else 325277
    nodes = _read_nodes(wd / "nodes.csv")
    p2c, c2p = _read_child_to_parent(wd / "rels.csv")
    cands = resolve_dynamic_method_callees(site, nodes, p2c, c2p)
    print(f"site {site}: {len(cands)} candidate callee method(s)")
    for c in cands:
        print(f"  {c.callee_key}  (node {c.callee_node_id}, {c.match_kind}, lit={c.literal!r})")
