
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .fig_builder import _resolve_rel_prefix, _const_value


Seg = tuple


@dataclass
class RecoveredShape:
    glob_base: str
    suffix: str
    hole_node: int
    hole_funcid: int


@dataclass
class FuncIndex:
    name2decl: dict
    params_of: dict
    returns_of: dict
    foreach_of: dict
    assigns_of: dict


def build_func_index(nodes: dict, p2c: dict) -> FuncIndex:
    name2decl: dict = {}
    params_of: dict = {}
    returns_of: dict = {}
    foreach_of: dict = {}
    assigns_of: dict = {}

    for nid, n in nodes.items():
        typ = n.get("type")
        if typ in ("AST_FUNC_DECL", "AST_METHOD"):
            name = (n.get("name") or "").strip()
            if name:
                name2decl.setdefault(name.lower(), nid)
            continue
        fid = _ival(n.get("funcid"))
        if fid < 0:
            continue
        if typ == "AST_PARAM":
            params_of.setdefault(fid, []).append(nid)
        elif typ == "AST_RETURN":
            returns_of.setdefault(fid, []).append(nid)
        elif typ == "AST_FOREACH":
            foreach_of.setdefault(fid, []).append(nid)
        elif typ in ("AST_ASSIGN", "AST_ASSIGN_REF"):
            kids = _children_sorted(nid, nodes, p2c)
            if len(kids) < 2:
                continue
            lhs = _base_lhs_name(kids[0], nodes, p2c)
            if lhs:
                assigns_of.setdefault(fid, []).append((lhs, kids[-1]))

    for fid, plist in params_of.items():
        plist.sort(key=lambda x: _ival(nodes.get(x, {}).get("childnum")))
    return FuncIndex(name2decl=name2decl, params_of=params_of,
                     returns_of=returns_of, foreach_of=foreach_of,
                     assigns_of=assigns_of)


def _ival(x) -> int:
    try:
        return int(x)
    except (ValueError, TypeError):
        return -1


def _var_name(nid: int, nodes: dict, p2c: dict) -> Optional[str]:
    n = nodes.get(nid)
    if not n or n.get("type") != "AST_VAR":
        return None
    for c in p2c.get(nid, []):
        cn = nodes.get(c)
        if cn and cn.get("type") == "string":
            return cn.get("code") or None
    return None


def _param_name(param_id: int, nodes: dict, p2c: dict) -> Optional[str]:
    for c in p2c.get(param_id, []):
        cn = nodes.get(c)
        if cn and cn.get("type") == "string":
            return cn.get("code") or None
    return None


def _children_sorted(nid: int, nodes: dict, p2c: dict) -> list:
    return sorted(p2c.get(nid, []),
                  key=lambda x: _ival(nodes.get(x, {}).get("childnum")))


def _call_name(call_id: int, nodes: dict, p2c: dict) -> Optional[str]:
    n = nodes.get(call_id)
    if not n or n.get("type") != "AST_CALL":
        return None
    kids = _children_sorted(call_id, nodes, p2c)
    if not kids:
        return None
    name_node = nodes.get(kids[0])
    if not name_node or name_node.get("type") != "AST_NAME":
        return None
    for c in p2c.get(kids[0], []):
        cn = nodes.get(c)
        if cn and cn.get("type") == "string":
            return cn.get("code") or None
    return None


def _call_args(call_id: int, nodes: dict, p2c: dict) -> list:
    kids = _children_sorted(call_id, nodes, p2c)
    for k in kids:
        kn = nodes.get(k)
        if kn and kn.get("type") == "AST_ARG_LIST":
            return _children_sorted(k, nodes, p2c)
    return []


def _all_var_names_in(nid: int, nodes: dict, p2c: dict, depth: int = 0) -> set:
    if depth > 40:
        return set()
    out: set = set()
    n = nodes.get(nid)
    if not n:
        return out
    if n.get("type") == "AST_VAR":
        vn = _var_name(nid, nodes, p2c)
        if vn:
            out.add(vn)
        return out
    for c in p2c.get(nid, []):
        out |= _all_var_names_in(c, nodes, p2c, depth + 1)
    return out


def _enclosing_foreach_binding(
    var_node: int, var_funcid: int, nodes: dict, p2c: dict, fidx: "FuncIndex"
) -> Optional[int]:
    vname = _var_name(var_node, nodes, p2c)
    if not vname:
        return None
    for nid in fidx.foreach_of.get(var_funcid, ()):
        kids = _children_sorted(nid, nodes, p2c)
        if len(kids) < 2:
            continue
        array_expr, value_var = kids[0], kids[1]
        if _var_name(value_var, nodes, p2c) != vname:
            continue
        if _node_in_subtree(var_node, nid, p2c):
            return array_expr
    return None


def _node_in_subtree(target: int, root: int, p2c: dict, depth: int = 0) -> bool:
    if depth > 60:
        return False
    if root == target:
        return True
    for c in p2c.get(root, []):
        if _node_in_subtree(target, c, p2c, depth + 1):
            return True
    return False


def _assignments_rhs(
    var_name: str, funcid: int, fidx: "FuncIndex"
) -> list:
    return [rhs for (lhs, rhs) in fidx.assigns_of.get(funcid, ())
            if lhs == var_name]


def _params_reaching_return(
    decl_id: int, nodes: dict, p2c: dict, fidx: FuncIndex
) -> Optional[int]:
    returns = fidx.returns_of.get(decl_id, [])
    if not returns:
        return None
    params = fidx.params_of.get(decl_id, [])
    pname2idx = {}
    for i, pid in enumerate(params):
        pn = _param_name(pid, nodes, p2c)
        if pn:
            pname2idx[pn] = i

    def_map: dict = {}
    for lhs, rhs in fidx.assigns_of.get(decl_id, ()):
        def_map.setdefault(lhs, set()).update(_all_var_names_in(rhs, nodes, p2c))
    for fe in fidx.foreach_of.get(decl_id, ()):
        kids = _children_sorted(fe, nodes, p2c)
        if len(kids) < 2:
            continue
        val_name = _var_name(kids[1], nodes, p2c)
        if val_name:
            def_map.setdefault(val_name, set()).update(
                _all_var_names_in(kids[0], nodes, p2c))

    seed: set = set()
    for r in returns:
        seed |= _all_var_names_in(r, nodes, p2c)

    seen: set = set()
    work = list(seed)
    reached_params: set = set()
    while work:
        v = work.pop()
        if v in seen:
            continue
        seen.add(v)
        if v in pname2idx:
            reached_params.add(pname2idx[v])
        for nxt in def_map.get(v, ()):
            if nxt not in seen:
                work.append(nxt)

    if len(reached_params) == 1:
        return next(iter(reached_params))
    return None


def _base_lhs_name(nid: int, nodes: dict, p2c: dict) -> Optional[str]:
    n = nodes.get(nid)
    if not n:
        return None
    if n.get("type") == "AST_VAR":
        return _var_name(nid, nodes, p2c)
    if n.get("type") == "AST_DIM":
        kids = _children_sorted(nid, nodes, p2c)
        if kids:
            return _base_lhs_name(kids[0], nodes, p2c)
    return None


@dataclass
class _Env:
    bindings: dict
    parent: Optional["_Env"] = None


def _fold(
    node_id: int,
    funcid: int,
    env: Optional[_Env],
    includer_path: str,
    nodes: dict,
    p2c: dict,
    fidx: FuncIndex,
    define_map: dict,
    visited: set,
    depth: int,
) -> list:
    if depth > 24:
        return [("hole", node_id, funcid)]
    n = nodes.get(node_id)
    if not n:
        return [("hole", node_id, funcid)]
    typ = n.get("type")

    if typ == "string":
        return [("str", n.get("code") or "")]

    if typ == "AST_MAGIC_CONST":
        if n.get("flags") == "MAGIC_DIR":
            return [("str", str(Path(includer_path).parent) if includer_path else "")]
        if n.get("flags") == "MAGIC_FILE":
            return [("str", includer_path or "")]
        return [("hole", node_id, funcid)]

    if typ == "AST_CONST":
        v = _const_value(node_id, includer_path, define_map, nodes, p2c)
        return [("str", v)] if v is not None else [("hole", node_id, funcid)]

    if typ == "AST_BINARY_OP" and n.get("flags") == "BINARY_CONCAT":
        out: list = []
        for c in _children_sorted(node_id, nodes, p2c):
            out.extend(_fold(c, funcid, env, includer_path, nodes, p2c,
                             fidx, define_map, visited, depth + 1))
        return out

    if typ == "AST_VAR":
        vname = _var_name(node_id, nodes, p2c)
        if not vname:
            return [("hole", node_id, funcid)]
        if env is not None and vname in env.bindings:
            arg_id, caller_fid, caller_env = env.bindings[vname]
            return _fold(arg_id, caller_fid, caller_env, includer_path, nodes,
                         p2c, fidx, define_map, visited, depth + 1)
        key = ("var", node_id, funcid)
        if key in visited:
            return [("hole", node_id, funcid)]
        visited.add(key)
        bind = _enclosing_foreach_binding(node_id, funcid, nodes, p2c, fidx)
        if bind is not None:
            return _fold(bind, funcid, env, includer_path, nodes, p2c,
                         fidx, define_map, visited, depth + 1)
        asgns = _assignments_rhs(vname, funcid, fidx)
        if len(asgns) == 1:
            rn = nodes.get(asgns[0])
            if rn and (rn.get("type") == "AST_CALL" or
                       (rn.get("type") == "AST_BINARY_OP"
                        and rn.get("flags") == "BINARY_CONCAT")):
                return _fold(asgns[0], funcid, env, includer_path, nodes, p2c,
                             fidx, define_map, visited, depth + 1)
        return [("hole", node_id, funcid)]

    if typ == "AST_CALL":
        cname = _call_name(node_id, nodes, p2c)
        if cname:
            decl = fidx.name2decl.get(cname.lower())
            if decl is not None:
                pidx = _params_reaching_return(decl, nodes, p2c, fidx)
                args = _call_args(node_id, nodes, p2c)
                if pidx is not None and 0 <= pidx < len(args):
                    return _fold(args[pidx], funcid, env, includer_path, nodes,
                                 p2c, fidx, define_map, visited, depth + 1)
        return [("hole", node_id, funcid)]

    return [("hole", node_id, funcid)]


def recover_include_shape(
    operand_id: int,
    includer_funcid: int,
    includer_path: str,
    nodes: dict,
    p2c: dict,
    fidx: FuncIndex,
    define_map: dict,
) -> Optional[RecoveredShape]:
    segs = _fold(operand_id, includer_funcid, None, includer_path,
                 nodes, p2c, fidx, define_map, set(), 0)

    holes = [s for s in segs if s[0] == "hole"]
    if len(holes) != 1:
        return None

    prefix = ""
    i = 0
    while i < len(segs) and segs[i][0] == "str":
        prefix += segs[i][1]
        i += 1
    suffix = ""
    j = len(segs) - 1
    while j >= 0 and segs[j][0] == "str":
        suffix = segs[j][1] + suffix
        j -= 1
    if not (i == j and segs[i][0] == "hole"):
        return None

    hole_node, hole_funcid = segs[i][1], segs[i][2]
    glob_base = _resolve_rel_prefix(includer_path, prefix)
    return RecoveredShape(
        glob_base=glob_base, suffix=suffix,
        hole_node=hole_node, hole_funcid=hole_funcid,
    )


_SUPERGLOBALS = {"_GET", "_POST", "_REQUEST", "_COOKIE"}


@dataclass
class PackageDispatch:
    param: str
    value: str
    prefix: str


def _var_base_of(node_id: int, nodes: dict, p2c: dict) -> Optional[str]:
    n = nodes.get(node_id)
    if not n:
        return None
    t = n.get("type")
    if t == "AST_VAR":
        return _var_name(node_id, nodes, p2c)
    if t in ("AST_PROP", "AST_DIM"):
        kids = _children_sorted(node_id, nodes, p2c)
        return _var_base_of(kids[0], nodes, p2c) if kids else None
    return None


def _hole_expr_key(node_id: int, nodes: dict, p2c: dict) -> Optional[str]:
    n = nodes.get(node_id)
    if not n:
        return None
    t = n.get("type")
    if t == "AST_VAR":
        vn = _var_name(node_id, nodes, p2c)
        return ("$" + vn) if vn else None
    if t == "AST_PROP":
        kids = _children_sorted(node_id, nodes, p2c)
        base = _hole_expr_key(kids[0], nodes, p2c) if kids else None
        prop = None
        if len(kids) > 1:
            pn = nodes.get(kids[1])
            if pn and pn.get("type") == "string":
                prop = pn.get("code")
        return f"{base}->{prop}" if base and prop else None
    if t == "AST_DIM":
        kids = _children_sorted(node_id, nodes, p2c)
        base = _hole_expr_key(kids[0], nodes, p2c) if kids else None
        k = None
        if len(kids) > 1:
            kn = nodes.get(kids[1])
            if kn and kn.get("type") == "string":
                k = kn.get("code")
        return f"{base}[{k}]" if base and k is not None else None
    return None


def _superglobal_key_in_subtree(node_id: int, nodes: dict, p2c: dict,
                                depth: int = 0) -> Optional[str]:
    if depth > 40:
        return None
    n = nodes.get(node_id)
    if not n:
        return None
    if n.get("type") == "AST_DIM":
        kids = _children_sorted(node_id, nodes, p2c)
        if kids:
            base = nodes.get(kids[0])
            if base and base.get("type") == "AST_VAR":
                bn = _var_name(kids[0], nodes, p2c)
                if bn in _SUPERGLOBALS and len(kids) > 1:
                    kn = nodes.get(kids[1])
                    if kn and kn.get("type") == "string" and kn.get("code"):
                        return kn.get("code")
    for c in p2c.get(node_id, []):
        r = _superglobal_key_in_subtree(c, nodes, p2c, depth + 1)
        if r:
            return r
    return None


def _trace_request_key(var_name: str, funcid: int, nodes: dict, p2c: dict,
                       fidx: FuncIndex, visited: set, depth: int = 0) -> Optional[str]:
    if depth > 8 or (var_name, funcid) in visited:
        return None
    visited.add((var_name, funcid))
    for rhs in _assignments_rhs(var_name, funcid, fidx):
        key = _superglobal_key_in_subtree(rhs, nodes, p2c)
        if key:
            return key
        for v in _all_var_names_in(rhs, nodes, p2c):
            if v != var_name:
                r = _trace_request_key(v, funcid, nodes, p2c, fidx, visited, depth + 1)
                if r:
                    return r
    return None


def recover_package_dispatch_fid(
    sink_file: str, nodes: dict, p2c: dict, fidx: FuncIndex, define_map: dict,
) -> Optional[PackageDispatch]:
    sink_abs = str(Path(sink_file).resolve())
    for nid, n in nodes.items():
        if n.get("type") != "AST_INCLUDE_OR_EVAL":
            continue
        kids = _children_sorted(nid, nodes, p2c)
        if not kids:
            continue
        inc_funcid = _ival(n.get("funcid"))
        if inc_funcid < 0:
            continue
        segs = _fold(kids[0], inc_funcid, None, "", nodes, p2c,
                     fidx, define_map, set(), 0)
        holes = [s for s in segs if s[0] == "hole"]
        if not holes:
            continue
        keys = {_hole_expr_key(h[1], nodes, p2c) for h in holes}
        if len(keys) != 1 or next(iter(keys)) is None:
            continue
        prefix = ""
        for s in segs:
            if s[0] == "str":
                prefix += s[1]
            else:
                break
        if not prefix or "/" not in prefix:
            continue
        pos = sink_abs.find(prefix)
        if pos < 0:
            continue
        rest = sink_abs[pos + len(prefix):]
        seg = rest.split("/")[0] if rest else ""
        if not seg or "." in seg:
            continue
        base = _var_base_of(holes[0][1], nodes, p2c)
        if not base:
            continue
        key = _trace_request_key(base, inc_funcid, nodes, p2c, fidx, set(), 0)
        if not key:
            continue
        return PackageDispatch(param=key, value=seg, prefix=prefix)
    return None


def recover_package_dispatch_for_sink(
    working_dir, sink_file: str,
) -> Optional[PackageDispatch]:
    try:
        from .fig_builder import _read_nodes, _read_rels, _build_define_map, _normpath
        wd = Path(working_dir)
        nodes = _read_nodes(wd / "nodes.csv")
        p2c = _read_rels(wd / "rels.csv")
        fidx = build_func_index(nodes, p2c)
        funcid2path = {
            int(nid): _normpath(n.get("name", ""))
            for nid, n in nodes.items()
            if n.get("type") == "AST_TOPLEVEL" and n.get("flags") == "TOPLEVEL_FILE"
        }
        define_map = _build_define_map(nodes, p2c, funcid2path)
        return recover_package_dispatch_fid(sink_file, nodes, p2c, fidx, define_map)
    except Exception:
        return None
