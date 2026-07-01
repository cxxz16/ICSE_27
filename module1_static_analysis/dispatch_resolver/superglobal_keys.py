
from __future__ import annotations

import os.path as osp
from pathlib import Path


_SUPERGLOBALS = {"_REQUEST", "_POST", "_GET", "_COOKIE"}


_CACHE: dict[str, tuple] = {}


_WRAPPER_FUNCS_CACHE: set | None = None


def _wrapper_baseline_path() -> Path:
    return (Path(__file__).resolve().parents[1]
            / "TChecker-VIPER" / "projects" / "extensions" / "jpanlib"
            / "src" / "main" / "resources" / "wrapper_sources.csv")


def _load_wrapper_funcs() -> set:
    global _WRAPPER_FUNCS_CACHE
    if _WRAPPER_FUNCS_CACHE is not None:
        return _WRAPPER_FUNCS_CACHE
    import os
    funcs: set = set()
    paths: list = [_wrapper_baseline_path()]
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
                        if fname:
                            funcs.add(fname)
        except OSError:
            continue
    _WRAPPER_FUNCS_CACHE = funcs
    return funcs


def _load_cpg(working_dir: str):
    wd_key = str(Path(working_dir).resolve())
    if wd_key in _CACHE:
        return _CACHE[wd_key]
    wd = Path(working_dir)
    cpg_csv = wd / "cpg_edges.csv"
    nodes_csv = wd / "nodes.csv"
    rels_csv = wd / "rels.csv"
    if not (cpg_csv.exists() and nodes_csv.exists() and rels_csv.exists()):
        _CACHE[wd_key] = None
        return None

    from .fig_builder import _read_nodes, build_fig
    from .context_extractor import _read_reaches_edges

    nodes = _read_nodes(nodes_csv)
    reaches = _read_reaches_edges(cpg_csv)
    fig = build_fig(wd)

    parent2children: dict[int, list[int]] = {}
    child2parent: dict[int, int] = {}
    try:
        with open(rels_csv, encoding="latin-1") as f:
            next(f, None)
            for raw in f:
                parts = raw.rstrip("\n").split("\t")
                if len(parts) < 3 or parts[2] != "PARENT_OF":
                    continue
                try:
                    p, c = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                parent2children.setdefault(p, []).append(c)
                child2parent[c] = p
    except OSError:
        _CACHE[wd_key] = None
        return None

    reaches_rev: dict[int, list[int]] = {}
    reaches_rev_var: dict[int, list[tuple[int, str]]] = {}
    for s, e, _v in reaches:
        reaches_rev.setdefault(e, []).append(s)
        reaches_rev_var.setdefault(e, []).append((s, _v))

    bundle = (nodes, reaches_rev, parent2children, fig,
              child2parent, reaches_rev_var)
    _CACHE[wd_key] = bundle
    return bundle


def superglobal_keys_reaching_line(
    target_file: str, target_line: int, working_dir: str,
) -> set[str]:
    bundle = _load_cpg(working_dir)
    if bundle is None:
        return set()
    nodes, rev, parent2children, fig, _c2p, _rrv = bundle

    from .narrow import _containing_file

    target_basename = osp.basename(target_file)
    _BODY_LIST_TYPES = {"AST_STMT_LIST", "AST_SWITCH_LIST"}
    target_line_nodes: set[int] = set()
    for nid, n in nodes.items():
        try:
            if int(n.get("lineno") or 0) != target_line:
                continue
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if not fid:
            continue
        if n.get("type") in _BODY_LIST_TYPES:
            continue
        cf = _containing_file(fid, fig, nodes)
        if cf and osp.basename(cf) == target_basename:
            target_line_nodes.add(nid)
    if not target_line_nodes:
        return set()

    _CALL_BOUNDARY = {"AST_CALL", "AST_METHOD_CALL",
                       "AST_STATIC_CALL", "AST_NEW"}
    closure = set(target_line_nodes)
    queue = list(target_line_nodes)
    while queue:
        cur = queue.pop()
        cur_n = nodes.get(cur)
        if (cur not in target_line_nodes
                and cur_n and cur_n.get("type") in _CALL_BOUNDARY):
            continue
        for s in rev.get(cur, []):
            if s not in closure:
                closure.add(s)
                queue.append(s)

    _BODY_BARRIERS = {"AST_STMT_LIST", "AST_SWITCH_LIST"}

    def _subtree(root: int) -> set[int]:
        seen = {root}
        q = [root]
        while q:
            cur = q.pop()
            cur_n = nodes.get(cur)
            if cur_n and cur_n.get("type") in _BODY_BARRIERS and cur != root:
                continue
            for c in parent2children.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    q.append(c)
        return seen

    wrapper_funcs = _load_wrapper_funcs()
    keys: set[str] = set()
    for nid in closure:
        for sub in _subtree(nid):
            n = nodes.get(sub)
            if not n:
                continue
            ntype = n.get("type")
            if ntype == "AST_DIM":
                kids = sorted(parent2children.get(sub, []),
                              key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
                if len(kids) < 2:
                    continue
                c0 = nodes.get(kids[0])
                if not c0 or c0.get("type") != "AST_VAR":
                    continue
                c0_kids = parent2children.get(kids[0], [])
                var_name = None
                for vk in c0_kids:
                    vn = nodes.get(vk)
                    if vn and vn.get("type") == "string":
                        var_name = (vn.get("code") or "").strip().strip('"').strip("'")
                        break
                if var_name not in _SUPERGLOBALS:
                    continue
                c1 = nodes.get(kids[1])
                if not c1 or c1.get("type") != "string":
                    continue
                key_str = (c1.get("code") or "").strip().strip('"').strip("'")
                if key_str:
                    keys.add(key_str)
            elif ntype == "AST_CALL" and wrapper_funcs:
                kids = sorted(parent2children.get(sub, []),
                              key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
                if len(kids) < 2:
                    continue
                name_node = nodes.get(kids[0])
                if not name_node or name_node.get("type") != "AST_NAME":
                    continue
                name_kids = parent2children.get(kids[0], [])
                fname = None
                for nk in name_kids:
                    nn = nodes.get(nk)
                    if nn and nn.get("type") == "string":
                        fname = (nn.get("code") or "").strip().strip('"').strip("'")
                        break
                if fname not in wrapper_funcs:
                    continue
                arglist = nodes.get(kids[1])
                if not arglist or arglist.get("type") != "AST_ARG_LIST":
                    continue
                arg_kids = sorted(parent2children.get(kids[1], []),
                                  key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
                if not arg_kids:
                    continue
                first_arg = nodes.get(arg_kids[0])
                if not first_arg or first_arg.get("type") != "string":
                    continue
                key_str = (first_arg.get("code") or "").strip().strip('"').strip("'")
                if key_str:
                    keys.add(key_str)
    return keys


def _refers_to_param(node_id: int, param: str, nodes: dict,
                       p2c: dict, max_depth: int = 5) -> bool:
    stack = [(node_id, 0)]
    seen: set = set()
    while stack:
        cur, depth = stack.pop()
        if cur in seen or depth > max_depth:
            continue
        seen.add(cur)
        n = nodes.get(cur)
        if not n:
            continue
        t = n.get("type")
        if t == "AST_VAR":
            for vk in p2c.get(cur, []):
                vn = nodes.get(vk)
                if vn and vn.get("type") == "string":
                    code = (vn.get("code") or "").strip().strip('"').strip("'")
                    if code == param:
                        return True
        elif t == "AST_DIM":
            kids = sorted(p2c.get(cur, []),
                          key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
            if len(kids) >= 2:
                k1 = nodes.get(kids[1])
                if k1 and k1.get("type") == "string":
                    code = (k1.get("code") or "").strip().strip('"').strip("'")
                    if code == param:
                        return True
        elif t == "AST_CALL":
            kids = sorted(p2c.get(cur, []),
                          key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
            if len(kids) >= 2:
                al = p2c.get(kids[1], [])
                if al:
                    a0 = nodes.get(al[0])
                    if a0 and a0.get("type") == "string":
                        code = (a0.get("code") or "").strip().strip('"').strip("'")
                        if code == param:
                            return True
        for c in p2c.get(cur, []):
            stack.append((c, depth + 1))
    return False


def _ast_var_name(var_node: int, nodes: dict, p2c: dict) -> str:
    for c in p2c.get(var_node, []):
        cn = nodes.get(c)
        if cn and cn.get("type") == "string":
            return (cn.get("code") or "").strip().strip('"').strip("'")
    return ""


def _extract_literals(node_id: int, nodes: dict, p2c: dict, rev: dict,
                        scope_funcid: int, max_depth: int = 8,
                        follow_var: bool = True,
                        child2parent=None, reaches_rev_var=None) -> list:
    if max_depth <= 0:
        return []
    n = nodes.get(node_id)
    if not n:
        return []
    t = n.get("type")
    if t == "string":
        return [(n.get("code") or "").strip().strip('"').strip("'")]
    if t in ("integer", "double"):
        return [(n.get("code") or "").strip()]
    if t == "AST_ARRAY":
        out: list = []
        for c in p2c.get(node_id, []):
            cn = nodes.get(c)
            if cn and cn.get("type") == "AST_ARRAY_ELEM":
                ekids = sorted(p2c.get(c, []),
                               key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
                if ekids:
                    out.extend(_extract_literals(ekids[0], nodes, p2c, rev,
                                                  scope_funcid, max_depth - 1,
                                                  follow_var, child2parent,
                                                  reaches_rev_var))
            else:
                out.extend(_extract_literals(c, nodes, p2c, rev,
                                              scope_funcid, max_depth - 1,
                                              follow_var, child2parent,
                                              reaches_rev_var))
        return out
    if t in ("AST_CALL", "AST_METHOD_CALL",
              "AST_STATIC_CALL", "AST_NEW"):
        return []
    if t == "AST_VAR" and follow_var:
        results: list = []
        seen_def_rhs: set = set()
        def_sources = list(rev.get(node_id, []))
        if not def_sources and child2parent is not None \
                and reaches_rev_var is not None:
            vname = _ast_var_name(node_id, nodes, p2c)
            cur = node_id
            for _ in range(8):
                par = child2parent.get(cur)
                if par is None:
                    break
                for s, v in reaches_rev_var.get(par, []):
                    if not vname or v == vname:
                        def_sources.append(s)
                if def_sources:
                    break
                if (nodes.get(par) or {}).get("type") == "AST_STMT_LIST":
                    break
                cur = par
        for up in def_sources:
            up_n = nodes.get(up)
            if not up_n:
                continue
            if scope_funcid:
                try:
                    if int(up_n.get("funcid") or 0) != scope_funcid:
                        continue
                except (ValueError, TypeError):
                    continue
            if up_n.get("type") == "AST_ASSIGN":
                kids = sorted(p2c.get(up, []),
                              key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
                if len(kids) >= 2 and kids[1] not in seen_def_rhs:
                    seen_def_rhs.add(kids[1])
                    results.extend(_extract_literals(
                        kids[1], nodes, p2c, rev, scope_funcid,
                        max_depth - 1, follow_var=False,
                        child2parent=child2parent,
                        reaches_rev_var=reaches_rev_var))
        return results
    return []


def strong_target_values_at(
    target_file: str, target_line: int, param: str,
    working_dir: str, scope_funcid: int = 0,
) -> list:
    bundle = _load_cpg(working_dir)
    if bundle is None or target_line <= 0:
        return []
    nodes, rev, p2c, fig, child2parent, reaches_rev_var = bundle

    from .narrow import _containing_file

    target_bn = osp.basename(target_file)

    condition_roots: list = []
    case_literals: list = []
    for nid, n in nodes.items():
        try:
            if int(n.get("lineno") or 0) != target_line:
                continue
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        cf = _containing_file(fid, fig, nodes)
        if not cf or osp.basename(cf) != target_bn:
            continue
        ntype = n.get("type")
        if ntype == "AST_IF_ELEM":
            kids = sorted(p2c.get(nid, []),
                          key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
            if kids:
                condition_roots.append(kids[0])
        elif ntype == "AST_SWITCH_CASE":
            kids = sorted(p2c.get(nid, []),
                          key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
            if kids:
                case_literals.append(kids[0])

    out: set = set()
    for lit_node in case_literals:
        for v in _extract_literals(lit_node, nodes, p2c, rev,
                                     scope_funcid, follow_var=False,
                                     child2parent=child2parent,
                                     reaches_rev_var=reaches_rev_var):
            out.add(v)

    for root in condition_roots:
        stack = [root]
        seen_walk: set = set()
        while stack:
            cur = stack.pop()
            if cur in seen_walk:
                continue
            seen_walk.add(cur)
            n = nodes.get(cur)
            if not n:
                continue
            t = n.get("type")
            if t == "AST_BINARY_OP":
                flags = n.get("flags") or ""
                if "NOT_EQUAL" in flags or "NOT_IDENTICAL" in flags:
                    pass
                elif "EQUAL" in flags or "IDENTICAL" in flags:
                    kids = sorted(p2c.get(cur, []),
                                  key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
                    if len(kids) >= 2:
                        l, r = kids[0], kids[1]
                        l_has = _refers_to_param(l, param, nodes, p2c)
                        r_has = _refers_to_param(r, param, nodes, p2c)
                        target = None
                        if l_has and not r_has:
                            target = r
                        elif r_has and not l_has:
                            target = l
                        if target is not None:
                            for v in _extract_literals(target, nodes, p2c, rev,
                                                         scope_funcid,
                                                         child2parent=child2parent,
                                                         reaches_rev_var=reaches_rev_var):
                                out.add(v)
            elif t == "AST_CALL":
                kids = sorted(p2c.get(cur, []),
                              key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
                if len(kids) >= 2:
                    name_node = nodes.get(kids[0])
                    if name_node and name_node.get("type") == "AST_NAME":
                        fname = None
                        for nk in p2c.get(kids[0], []):
                            nn = nodes.get(nk)
                            if nn and nn.get("type") == "string":
                                fname = (nn.get("code") or "").strip().strip('"').strip("'")
                                break
                        if fname == "in_array":
                            arglist_kids = sorted(p2c.get(kids[1], []),
                                                   key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
                            if len(arglist_kids) >= 2 and _refers_to_param(
                                    arglist_kids[0], param, nodes, p2c):
                                for v in _extract_literals(
                                        arglist_kids[1], nodes, p2c, rev,
                                        scope_funcid,
                                        child2parent=child2parent,
                                        reaches_rev_var=reaches_rev_var):
                                    out.add(v)
            for c in p2c.get(cur, []):
                stack.append(c)

    return sorted(out)
