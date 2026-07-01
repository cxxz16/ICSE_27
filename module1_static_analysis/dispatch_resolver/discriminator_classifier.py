
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from .narrow import CandidateDispatchSite


class DiscriminatorOrigin(str, Enum):
    LITERAL_SET           = "literal_set"
    LITERAL_CONCAT_INPUT  = "literal_concat_input"
    FULLY_INPUT           = "fully_input"
    MIXED_OR_UNKNOWN      = "mixed_or_unknown"


USER_INPUT_VARS = {
    "_GET", "_POST", "_COOKIE", "_REQUEST", "_SERVER", "_FILES",
    "_ENV", "HTTP_ENV_VARS", "HTTP_POST_VARS", "HTTP_GET_VARS",
}

KNOWN_SANITIZERS = {
    "preg_replace", "str_replace", "strtolower", "strtoupper", "ucfirst",
    "ucwords", "trim", "rtrim", "ltrim", "htmlspecialchars", "addslashes",
    "filter_var", "intval", "floatval", "ctype_alpha", "ctype_alnum",
    "is_numeric", "is_string",
}


@dataclass
class DiscriminatorOriginInfo:
    origin: DiscriminatorOrigin
    discriminator_var: str
    literals: list[str] = field(default_factory=list)
    input_sources: list[str] = field(default_factory=list)
    sanitizers_applied: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "origin": self.origin.value,
            "discriminator_var": self.discriminator_var,
            "literals": self.literals,
            "input_sources": self.input_sources,
            "sanitizers_applied": self.sanitizers_applied,
            "note": self.note,
        }


def classify(
    site: CandidateDispatchSite,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
) -> DiscriminatorOriginInfo:
    site_node = nodes.get(site.site_id)
    if not site_node:
        return _unknown("site node missing", "")

    funcid_init = int(site_node.get("funcid") or 0)
    tainted_vars = _compute_tainted_vars(funcid_init, nodes, parent2children)

    callable_id = _find_callable_child(site, nodes, parent2children)
    if callable_id is None:
        return _unknown("could not locate callable expression", "")

    cnode = nodes.get(callable_id)
    if cnode and cnode["type"] == "string":
        return DiscriminatorOriginInfo(
            origin=DiscriminatorOrigin.LITERAL_SET,
            discriminator_var="<literal>",
            literals=[cnode.get("code", "")],
            note="callable is a string literal at the dispatch site itself",
        )

    var_name = _ast_var_name(callable_id, nodes, parent2children)
    if var_name is None:
        return _unknown(
            "callable expression is neither a simple variable nor a literal",
            "<complex>",
        )

    funcid = int(site_node.get("funcid") or 0)
    assignments = _assignments_to_var(var_name, funcid, site.site_id, nodes, parent2children)

    if not assignments:
        return DiscriminatorOriginInfo(
            origin=DiscriminatorOrigin.MIXED_OR_UNKNOWN,
            discriminator_var=var_name,
            note="no in-function assignment found; var likely comes from "
                 "function parameter or outer scope (needs caller-side analysis)",
        )

    info = DiscriminatorOriginInfo(
        origin=DiscriminatorOrigin.MIXED_OR_UNKNOWN,
        discriminator_var=var_name,
    )
    has_pure_literal = False
    has_concat_with_input = False
    has_pure_input = False

    for asgn_id in assignments:
        rhs_id = _rhs_of_assign(asgn_id, parent2children)
        if rhs_id is None:
            continue
        outcome = _classify_expr(rhs_id, nodes, parent2children, info, tainted_vars)
        if outcome == "literal":
            has_pure_literal = True
        elif outcome == "concat_with_input":
            has_concat_with_input = True
        elif outcome == "input":
            has_pure_input = True

    if has_concat_with_input:
        info.origin = DiscriminatorOrigin.LITERAL_CONCAT_INPUT
        info.note = "literal piece concatenated with user-controlled input"
    elif has_pure_input and not has_pure_literal:
        info.origin = DiscriminatorOrigin.FULLY_INPUT
        info.note = "discriminator entirely derives from user input — potential RCE"
    elif has_pure_literal and not has_pure_input:
        info.origin = DiscriminatorOrigin.LITERAL_SET
        info.note = f"{len(info.literals)} literal value(s) bound, no input mixed in"
    elif has_pure_literal and has_pure_input:
        info.origin = DiscriminatorOrigin.LITERAL_CONCAT_INPUT
        info.note = "multiple defs across literal and input branches"
    else:
        info.origin = DiscriminatorOrigin.MIXED_OR_UNKNOWN
        info.note = "no clear literal/input pattern in any def"
    return info


def _find_callable_child(
    site: CandidateDispatchSite,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
) -> Optional[int]:
    children = parent2children.get(site.site_id, [])
    if not children:
        return None

    cat = site.category

    if cat == "DYN_NEW_CLASS":
        return children[0]

    if cat == "DYN_CALL_FN":
        return children[0]

    if cat == "DYN_CALL_METHOD":
        return children[1] if len(children) > 1 else None

    if cat == "DYN_CALL_STATIC_METHOD":
        return children[1] if len(children) > 1 else None

    if cat == "DYN_CALL_STATIC_CLASS":
        return children[0]

    if cat == "DYN_CALL_STATIC_BOTH":
        return children[1] if len(children) > 1 else children[0]

    if cat == "DYN_CUF":
        if len(children) < 2:
            return None
        arg_list_id = children[1]
        arg_children = parent2children.get(arg_list_id, [])
        if not arg_children:
            return None
        return arg_children[0]

    if cat == "DYN_CALLBACK_BUILTIN":
        if len(children) < 2:
            return None
        arg_list_id = children[1]
        arg_children = parent2children.get(arg_list_id, [])
        if not arg_children:
            return None
        try:
            pos = int((site.callable_arg_positions or "0").split(";")[0])
        except ValueError:
            pos = 0
        if pos >= len(arg_children):
            return None
        return arg_children[pos]

    if cat == "DYN_REFLECTION_INVOKE":
        return children[0]

    return None


def _ast_var_name(
    node_id: int,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
) -> Optional[str]:
    n = nodes.get(node_id)
    if not n or n.get("type") != "AST_VAR":
        return None
    children = parent2children.get(node_id, [])
    if not children:
        return None
    name_node = nodes.get(children[0])
    if not name_node or name_node.get("type") != "string":
        return None
    return name_node.get("code", "") or None


def _rhs_of_assign(asgn_id: int, parent2children: dict[int, list[int]]) -> Optional[int]:
    children = parent2children.get(asgn_id, [])
    return children[1] if len(children) > 1 else None


def _assignments_to_var(
    var_name: str,
    funcid: int,
    before_node_id: int,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
) -> list[int]:
    results: list[int] = []
    for nid, n in nodes.items():
        if n.get("type") != "AST_ASSIGN":
            continue
        try:
            if int(n.get("funcid") or 0) != funcid:
                continue
        except (ValueError, TypeError):
            continue
        children = parent2children.get(nid, [])
        if not children:
            continue
        lhs_id = children[0]
        lhs_var = _ast_var_name(lhs_id, nodes, parent2children)
        if lhs_var == var_name:
            results.append(nid)
    return results


def _classify_expr(
    expr_id: int,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
    info: DiscriminatorOriginInfo,
    tainted_vars: set[str],
) -> str:
    has_lit, has_inp = _walk_for_signals(
        expr_id, nodes, parent2children, info, tainted_vars, depth=0
    )
    if has_lit and has_inp:
        return "concat_with_input"
    if has_inp:
        return "input"
    if has_lit:
        return "literal"
    return "unknown"


def _compute_tainted_vars(
    funcid: int,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
) -> set[str]:
    tainted: set[str] = set()

    for nid, n in nodes.items():
        if n.get("type") != "AST_PARAM":
            continue
        try:
            if int(n.get("funcid") or 0) != funcid:
                continue
        except (ValueError, TypeError):
            continue
        for c in parent2children.get(nid, []):
            cn = nodes.get(c)
            if cn and cn.get("type") == "string":
                pname = cn.get("code", "")
                if pname:
                    tainted.add(pname)
                break
    func_assigns: list[tuple[str, int]] = []
    for nid, n in nodes.items():
        if n.get("type") != "AST_ASSIGN":
            continue
        try:
            if int(n.get("funcid") or 0) != funcid:
                continue
        except (ValueError, TypeError):
            continue
        children = parent2children.get(nid, [])
        if len(children) < 2:
            continue
        lhs_var = _ast_var_name(children[0], nodes, parent2children)
        if lhs_var is None:
            continue
        func_assigns.append((lhs_var, children[1]))

    for _ in range(10):
        added = False
        for lhs, rhs in func_assigns:
            if lhs in tainted:
                continue
            if _expr_touches_input(rhs, nodes, parent2children, tainted, depth=0):
                tainted.add(lhs)
                added = True
        if not added:
            break
    return tainted


def _expr_touches_input(
    nid: int,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
    tainted_vars: set[str],
    depth: int,
) -> bool:
    if depth > 12:
        return False
    n = nodes.get(nid)
    if not n:
        return False
    typ = n.get("type", "")

    if typ == "AST_VAR":
        children = parent2children.get(nid, [])
        if children:
            nname = nodes.get(children[0])
            if nname and nname.get("type") == "string":
                vname = nname.get("code", "")
                if vname in USER_INPUT_VARS:
                    return True
                if vname in tainted_vars:
                    return True
        return False

    for c in parent2children.get(nid, []):
        if _expr_touches_input(c, nodes, parent2children, tainted_vars, depth + 1):
            return True
    return False


def _walk_for_signals(
    nid: int,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
    info: DiscriminatorOriginInfo,
    tainted_vars: set[str],
    depth: int,
) -> tuple[bool, bool]:
    if depth > 12:
        return (False, False)
    n = nodes.get(nid)
    if not n:
        return (False, False)
    typ = n.get("type", "")
    code = n.get("code", "") or ""

    has_lit = False
    has_inp = False

    if typ == "string":
        if code:
            info.literals.append(code)
            has_lit = True
        return (has_lit, has_inp)

    if typ == "AST_VAR":
        children = parent2children.get(nid, [])
        if children:
            nname = nodes.get(children[0])
            if nname and nname.get("type") == "string":
                vname = nname.get("code", "")
                if vname in USER_INPUT_VARS:
                    if vname not in info.input_sources:
                        info.input_sources.append(vname)
                    has_inp = True
                elif vname in tainted_vars:
                    if "<transitive>" not in info.input_sources:
                        info.input_sources.append("<transitive>")
                    has_inp = True
        return (has_lit, has_inp)

    if typ == "AST_DIM":
        for c in parent2children.get(nid, []):
            l, i = _walk_for_signals(c, nodes, parent2children, info, tainted_vars, depth + 1)
            has_lit = has_lit or l
            has_inp = has_inp or i
        return (has_lit, has_inp)

    if typ in ("AST_BINARY_OP",) and n.get("flags") == "BINARY_CONCAT":
        for c in parent2children.get(nid, []):
            l, i = _walk_for_signals(c, nodes, parent2children, info, tainted_vars, depth + 1)
            has_lit = has_lit or l
            has_inp = has_inp or i
        return (has_lit, has_inp)

    if typ == "AST_CALL":
        children = parent2children.get(nid, [])
        if children:
            name_node = nodes.get(children[0])
            fname = ""
            if name_node and name_node.get("type") in ("AST_NAME",):
                ncs = parent2children.get(name_node["id"], []) if "id" in name_node else []
                if not ncs:
                    ncs = parent2children.get(int(name_node.get("id") or 0), [])
                if ncs:
                    snode = nodes.get(ncs[0])
                    if snode:
                        fname = snode.get("code", "") or ""
            elif name_node and name_node.get("type") == "string":
                fname = name_node.get("code", "") or ""
            if fname and fname in KNOWN_SANITIZERS and fname not in info.sanitizers_applied:
                info.sanitizers_applied.append(fname)
            if len(children) >= 2:
                for ac in parent2children.get(children[1], []):
                    l, i = _walk_for_signals(ac, nodes, parent2children, info, tainted_vars, depth + 1)
                    has_lit = has_lit or l
                    has_inp = has_inp or i
        return (has_lit, has_inp)

    if typ == "AST_METHOD_CALL":
        children = parent2children.get(nid, [])
        for c in children:
            l, i = _walk_for_signals(c, nodes, parent2children, info, tainted_vars, depth + 1)
            has_lit = has_lit or l
            has_inp = has_inp or i
        return (has_lit, has_inp)

    if typ in ("AST_CONDITIONAL",):
        for c in parent2children.get(nid, []):
            l, i = _walk_for_signals(c, nodes, parent2children, info, tainted_vars, depth + 1)
            has_lit = has_lit or l
            has_inp = has_inp or i
        return (has_lit, has_inp)

    for c in parent2children.get(nid, []):
        l, i = _walk_for_signals(c, nodes, parent2children, info, tainted_vars, depth + 1)
        has_lit = has_lit or l
        has_inp = has_inp or i
    return (has_lit, has_inp)


def _unknown(reason: str, var_name: str) -> DiscriminatorOriginInfo:
    return DiscriminatorOriginInfo(
        origin=DiscriminatorOrigin.MIXED_OR_UNKNOWN,
        discriminator_var=var_name,
        note=reason,
    )
