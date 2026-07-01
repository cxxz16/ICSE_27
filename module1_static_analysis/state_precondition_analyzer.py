
from __future__ import annotations

import os.path as osp
import sys
from typing import Optional

_VIPER_ROOT = osp.dirname(osp.abspath(__file__))
if _VIPER_ROOT not in sys.path:
    sys.path.insert(0, _VIPER_ROOT)


DB_IO_READ_FUNCS: frozenset = frozenset({
    "db_fetch_cell", "db_fetch_cell_prepared",
    "db_fetch_row", "db_fetch_row_prepared",
    "db_fetch_assoc", "db_fetch_assoc_prepared",
    "db_fetch_insert_id",
    "sqlStatement", "sqlQuery", "sqlFetchArray", "sqlNumRows",
    "getOne", "GetRow", "GetAll", "GetCol", "Execute",
    "get_results", "get_row", "get_var", "get_col",
    "mysqli_query", "mysqli_fetch_assoc", "mysqli_fetch_row",
    "mysqli_fetch_array", "mysqli_num_rows", "mysql_query",
    "mysql_fetch_assoc", "mysql_num_rows",
    "query", "fetch", "fetchAll", "fetchColumn", "fetchObject",
    "file_exists", "is_file", "is_dir", "file_get_contents",
    "is_readable", "filesize",
})

_FALSY_RUNTIME: frozenset = frozenset({
    "", "0", "0.0", "false", "null", "none", "[]", "array", "{}",
})

_DYNAMIC_NODE_TYPES: frozenset = frozenset({
    "AST_VAR", "AST_DIM", "AST_PROP", "AST_STATIC_PROP",
    "AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL",
})

_SUPERGLOBALS: frozenset = frozenset({"_REQUEST", "_POST", "_GET", "_COOKIE"})


def _children(parent2children: dict, nid: int) -> list:
    return parent2children.get(nid, [])


def _string_child(nodes: dict, parent2children: dict, nid: int) -> Optional[str]:
    for c in _children(parent2children, nid):
        n = nodes.get(c)
        if n and n.get("type") == "string":
            return (n.get("code") or "").strip("'\"")
    return None


def _var_name(nodes: dict, parent2children: dict, var_nid: int) -> Optional[str]:
    n = nodes.get(var_nid)
    if not n or n.get("type") != "AST_VAR":
        return None
    return _string_child(nodes, parent2children, var_nid)


def _subtree(parent2children: dict, root: int) -> list:
    seen = {root}
    stack = [root]
    while stack:
        cur = stack.pop()
        for c in _children(parent2children, cur):
            if c not in seen:
                seen.add(c)
                stack.append(c)
    return list(seen)


def _rhs_of_assign(nodes: dict, parent2children: dict, assign_nid: int) -> Optional[int]:
    n = nodes.get(assign_nid)
    if not n or n.get("type") not in ("AST_ASSIGN", "AST_ASSIGN_OP", "AST_ASSIGN_REF"):
        return None
    kids = sorted(_children(parent2children, assign_nid),
                  key=lambda c: _childnum(nodes, c))
    return kids[-1] if kids else None


def _childnum(nodes: dict, nid: int) -> int:
    try:
        return int(nodes.get(nid, {}).get("childnum") or 0)
    except (ValueError, TypeError):
        return 0


def _callee_name(nodes: dict, parent2children: dict, call_nid: int) -> Optional[str]:
    n = nodes.get(call_nid)
    if not n:
        return None
    t = n.get("type")
    if t == "AST_CALL":
        for c in _children(parent2children, call_nid):
            cn = nodes.get(c)
            if cn and cn.get("type") == "AST_NAME":
                return _string_child(nodes, parent2children, c)
        return None
    if t in ("AST_METHOD_CALL", "AST_STATIC_CALL"):
        for c in sorted(_children(parent2children, call_nid),
                        key=lambda c: _childnum(nodes, c)):
            cn = nodes.get(c)
            if cn and cn.get("type") == "string":
                return (cn.get("code") or "").strip("'\"")
    return None


def _arg_list(nodes: dict, parent2children: dict, call_nid: int) -> Optional[int]:
    for c in _children(parent2children, call_nid):
        cn = nodes.get(c)
        if cn and cn.get("type") == "AST_ARG_LIST":
            return c
    return None


def _calls_in_subtree(nodes: dict, parent2children: dict, root: int) -> list:
    out = []
    for nid in _subtree(parent2children, root):
        n = nodes.get(nid)
        if n and n.get("type") in ("AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"):
            out.append(nid)
    return out


def _subtree_is_constant(nodes: dict, parent2children: dict, root: int) -> bool:
    for nid in _subtree(parent2children, root):
        n = nodes.get(nid)
        if n and n.get("type") in _DYNAMIC_NODE_TYPES:
            return False
    return True


def _subtree_has_input_source(nodes: dict, parent2children: dict, root: int,
                              wrapper_funcs: set) -> bool:
    for nid in _subtree(parent2children, root):
        n = nodes.get(nid)
        if not n:
            continue
        t = n.get("type")
        if t == "AST_DIM":
            kids = sorted(_children(parent2children, nid),
                          key=lambda c: _childnum(nodes, c))
            if kids:
                base = nodes.get(kids[0])
                if base and base.get("type") == "AST_VAR":
                    if _var_name(nodes, parent2children, kids[0]) in _SUPERGLOBALS:
                        return True
        elif t in ("AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"):
            if _callee_name(nodes, parent2children, nid) in wrapper_funcs:
                return True
    return False


def classify_terminal_guard(
    working_dir: str,
    guard_basename: str,
    guard_line: int,
    *,
    operand_runtime_value: Optional[str] = None,
    condition_value: Optional[object] = None,
) -> Optional[dict]:
    from module1_static_analysis.dispatch_resolver.superglobal_keys import (
        _load_cpg, _load_wrapper_funcs, superglobal_keys_reaching_line,
    )
    from module1_static_analysis.dispatch_resolver.narrow import _containing_file

    bundle = _load_cpg(working_dir)
    if bundle is None:
        return None
    nodes, reaches_rev, parent2children, fig = bundle

    if condition_value in (True, "true", "True", 1):
        return None

    guard_basename = osp.basename(guard_basename)

    use_nodes: list = []
    operand_names: set = set()
    for nid, n in nodes.items():
        if n.get("type") != "AST_VAR":
            continue
        try:
            if int(n.get("lineno") or 0) != guard_line:
                continue
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        cf = _containing_file(fid, fig, nodes) if fid else ""
        if cf and osp.basename(cf) != guard_basename:
            continue
        nm = _var_name(nodes, parent2children, nid)
        if nm:
            use_nodes.append(nid)
            operand_names.add(nm)
    if not use_nodes:
        return None

    wrapper_funcs = _load_wrapper_funcs()

    state_reads: list = []
    input_defs = False
    for u in use_nodes:
        for d in reaches_rev.get(u, []):
            rhs = _rhs_of_assign(nodes, parent2children, d)
            if rhs is None:
                rhs = d
            for call in _calls_in_subtree(nodes, parent2children, rhs):
                callee = _callee_name(nodes, parent2children, call)
                if callee in DB_IO_READ_FUNCS:
                    rn = nodes.get(call, {})
                    try:
                        read_line = int(rn.get("lineno") or 0)
                    except (ValueError, TypeError):
                        read_line = 0
                    state_reads.append((d, call, callee, read_line))
            if _subtree_has_input_source(nodes, parent2children, rhs, wrapper_funcs):
                input_defs = True

    if input_defs and not state_reads:
        return {
            "classification": "INPUT_CONTROLLABLE",
            "tier": 0,
            "operand": sorted(operand_names),
            "guard_line": guard_line,
            "read": None,
            "selector_input_keys": [],
            "required_state": None,
            "evidence": "guard operand reaching-def derives from a request "
                        "superglobal / input wrapper — mutate params.",
        }

    if not state_reads:
        return None

    runtime_confirmed = None
    if operand_runtime_value is not None:
        rv = str(operand_runtime_value).strip()
        if rv.lower() not in _FALSY_RUNTIME:
            return None
        runtime_confirmed = True

    assign_nid, call_nid, read_func, read_line = state_reads[0]
    arglist = _arg_list(nodes, parent2children, call_nid)
    selector_all_const = (
        arglist is not None
        and _subtree_is_constant(nodes, parent2children, arglist)
    )
    tier = 1 if selector_all_const else 2

    selector_keys: list = []
    if read_line > 0:
        try:
            selector_keys = sorted(
                superglobal_keys_reaching_line(guard_basename, read_line, working_dir)
            )
        except Exception:
            selector_keys = []

    operand_disp = "$" + " / $".join(sorted(operand_names))
    if selector_all_const:
        required = (
            f"DB/IO read `{read_func}` (line {read_line}) has a compile-time "
            f"constant selector — no request input can change which rows it "
            f"returns. Reaching the sink requires the matching row(s) to be "
            f"SEEDED in the backing store before the request."
        )
    else:
        keyhint = (f"request key(s) {selector_keys} reach the read line; a "
                   f"param MAY select an already-seeded row"
                   if selector_keys else
                   f"the selector derives from a DB-loaded value (no direct "
                   f"request key found); reaching the sink likely requires "
                   f"backing-store rows matching the loaded selector")
        required = (
            f"DB/IO read `{read_func}` (line {read_line}) returned empty. "
            f"Its selector is non-constant — {keyhint}. If param exploration "
            f"plateaus on this guard, the data is not present and must be SEEDED."
        )

    evidence_bits = [
        f"operand {operand_disp} reaching-def RHS is `{read_func}(...)` at line {read_line}",
    ]
    if runtime_confirmed:
        evidence_bits.append(
            f"runtime B1 observed operand value={operand_runtime_value!r} (empty/falsy)"
        )
    evidence_bits.append(
        "selector all-constant" if selector_all_const else "selector non-constant"
    )

    return {
        "classification": "STATE_SEED_REQUIRED",
        "tier": tier,
        "operand": sorted(operand_names),
        "guard_line": guard_line,
        "read": {"func": read_func, "line": read_line},
        "selector_input_keys": selector_keys,
        "required_state": required,
        "evidence": "; ".join(evidence_bits),
    }


def _main():
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description="Classify a terminal if-guard's controllability "
                    "(DB-state precondition vs input-controllable).")
    ap.add_argument("--working-dir", required=True,
                    help="dir with nodes.csv / rels.csv / cpg_edges.csv")
    ap.add_argument("--guard-file", required=True,
                    help="source-file basename of the guard, e.g. api_automation.php")
    ap.add_argument("--guard-line", type=int, required=True)
    ap.add_argument("--operand-value", default=None,
                    help="B1 observed operand value (lhs.value); omit for static-only")
    ap.add_argument("--condition-value", default=None,
                    help="B1 condition_value (true/false); omit if unknown")
    args = ap.parse_args()

    cv: Optional[object] = None
    if args.condition_value is not None:
        cv = args.condition_value.lower() in ("true", "1", "yes")

    verdict = classify_terminal_guard(
        args.working_dir, args.guard_file, args.guard_line,
        operand_runtime_value=args.operand_value,
        condition_value=cv,
    )
    print(json.dumps(verdict, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _main()
