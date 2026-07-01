
from __future__ import annotations

import argparse
import csv
import json
import os
import os.path as osp
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

csv.field_size_limit(sys.maxsize)

_VIPER_ROOT = osp.dirname(osp.abspath(__file__))
if _VIPER_ROOT not in sys.path:
    sys.path.insert(0, _VIPER_ROOT)

from module1_static_analysis.dispatch_resolver import discover_entry, EntryDiscovery
from module1_static_analysis.dispatch_resolver.edge_injector import inject as inject_dispatch_edges
from module1_static_analysis.dispatch_resolver.fig_builder import _read_nodes, _read_rels
from module1_static_analysis.dispatch_resolver.context_extractor import _read_child_to_parent
from module1_static_analysis import param_extractor

PREDATOR_SCRIPTS = osp.join(osp.dirname(_VIPER_ROOT), "scripts")


def _reverse_reachable_files(sink_file: str, sink_line: int,
                              working_dir: str, *, cap: int = 6000,
                              extra_caller_edges: list = None) -> list:
    from collections import deque
    try:
        from module1_static_analysis.dispatch_resolver.entry_finder import CallGraph, _enclosing_function_of
        from module1_static_analysis.dispatch_resolver.fig_builder import build_fig, _read_nodes as _rn
        from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    except Exception:
        return []
    wd = Path(working_dir)
    try:
        fig = build_fig(wd)
        nodes = _rn(wd / "nodes.csv")
        cg = CallGraph.load(wd / "call_graph.csv")
    except Exception:
        return []
    sink_fn = _enclosing_function_of(sink_file, sink_line, nodes, fig)
    if not sink_fn:
        return []
    _extra_callers: dict = {}
    for _e in (extra_caller_edges or []):
        try:
            _caller, _callee = int(_e[0]), int(_e[1])
        except (TypeError, ValueError, IndexError):
            continue
        _extra_callers.setdefault(_callee, []).append(_caller)
    seen = {sink_fn}
    q = deque([sink_fn])
    files: set = set()
    while q and len(seen) <= cap:
        cur = q.popleft()
        f = _containing_file(cur, fig, nodes)
        if f:
            files.add(f)
        for caller in list(cg.callers_of.get(cur, [])) + _extra_callers.get(cur, []):
            if caller not in seen:
                seen.add(caller)
                q.append(caller)
    return sorted(files)


def _entry_candidates_in_cone(sink_file: str, sink_line: int,
                               working_dir: str, *, cap: int = 6000) -> list:
    from collections import deque
    try:
        from module1_static_analysis.dispatch_resolver.entry_finder import (
            CallGraph, _enclosing_function_of, _is_toplevel_file,
            _is_include_target)
        from module1_static_analysis.dispatch_resolver.fig_builder import build_fig, _read_nodes, _read_rels
    except Exception:
        return []
    wd = Path(working_dir)
    try:
        fig = build_fig(wd)
        nodes = _read_nodes(wd / "nodes.csv")
        p2c = _read_rels(wd / "rels.csv")
        cg = CallGraph.load(wd / "call_graph.csv")
    except Exception:
        return []
    sink_fn = _enclosing_function_of(sink_file, sink_line, nodes, fig)
    if not sink_fn:
        return []
    seen = {sink_fn}
    q = deque([sink_fn])
    out: list = []
    while q and len(seen) <= cap:
        cur = q.popleft()
        if _is_toplevel_file(cur, fig):
            f = fig.file_by_funcid(cur)
            if f and not _is_include_target(fig, f.path, nodes, p2c) \
                    and f.path not in out:
                out.append(f.path)
        for caller in cg.callers_of.get(cur, []):
            if caller not in seen:
                seen.add(caller)
                q.append(caller)
    return out


def _instr_info_min_dist_by_file(instr_info_path: str) -> dict:
    import csv as _csv
    out: dict = {}
    cur = None
    try:
        with open(instr_info_path, encoding="latin-1") as f:
            r = _csv.reader(f, delimiter="\t")
            next(r, None)
            for row in r:
                if len(row) < 4:
                    continue
                if row[1] == "f":
                    cur = row[3]
                elif row[1] == "d" and cur:
                    try:
                        d = float(row[3])
                    except ValueError:
                        continue
                    if cur not in out or d < out[cur]:
                        out[cur] = d
    except OSError:
        pass
    return out


def _constraints_for_candidate(entry_file, entry_url, *, sink_abs, sink_line,
                               working_dir, method, project_root,
                               sink_dominator_lines, instr_info, framework,
                               cpg=None):
    import os
    _real = os.path.realpath(entry_file)
    try:
        disc = discover_entry(
            sink_abs, sink_line, working_dir,
            webroot_predicate=lambda p: os.path.realpath(p) == _real,
            cpg=cpg)
    except Exception:
        return entry_url, None
    if not getattr(disc, "found", False):
        return entry_url, None
    eu = entry_url
    if getattr(disc, "entry_query", "") and disc.entry_query not in eu:
        eu += ("&" if "?" in eu else "?") + disc.entry_query
    scope = switch_dom = None
    if getattr(disc, "hops", None):
        try:
            scope, switch_dom = _in_scope_lines_from_discovery(
                disc, working_dir, sink_line=sink_line)
        except Exception:
            pass
    try:
        c = param_extractor.extract(
            instr_info_csv=instr_info, php_source_file=sink_abs,
            entry_url=eu, method=method, sink_line=sink_line,
            project_root=project_root, sink_dominator_lines=sink_dominator_lines,
            working_dir=working_dir, entry_file=disc.entry_file,
            framework=framework,
            extra_scan_files=_caller_files_from_discovery(disc, project_root),
            extra_scan_line_scope=scope, extra_scan_switch_case_dom=switch_dom)
        return eu, c
    except Exception:
        return eu, None


def _caller_files_from_discovery(discovery, project_root: str = "") -> list:
    if not discovery or not getattr(discovery, "found", False):
        return []
    out: list = []
    ef = getattr(discovery, "entry_file", None)
    if ef:
        out.append(ef)
    if project_root:
        import re as _re
        proot = Path(_abs(project_root))
        _bn_cache: dict = {}
        for h in getattr(discovery, "hops", []) or []:
            for lbl in (getattr(h, "from_label", ""), getattr(h, "to_label", "")):
                for fn in _re.findall(r"([A-Za-z0-9_./-]+\.php)\b", lbl or ""):
                    bn = os.path.basename(fn)
                    if bn not in _bn_cache:
                        try:
                            _bn_cache[bn] = [str(p) for p in proot.rglob(bn)]
                        except Exception:
                            _bn_cache[bn] = []
                    out.extend(_bn_cache[bn])
    seen: set = set()
    uniq: list = []
    for f in out:
        if f and f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


def _find_enclosing_switch_case(target_line: int, scope_funcid: int,
                                  target_file: str, nodes: dict,
                                  parent2children: dict,
                                  child_to_parent: dict) -> tuple:
    target_bn = osp.basename(target_file)
    target_node = 0
    for nid, n in nodes.items():
        try:
            if int(n.get("lineno") or 0) != target_line:
                continue
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if scope_funcid and fid != scope_funcid:
            continue
        fn = nodes.get(fid) or {}
        if fn.get("type") == "AST_TOPLEVEL":
            if osp.basename(fn.get("name", "").strip('"')) != target_bn:
                continue
        target_node = nid
        break
    if not target_node:
        return (0, None)

    cur = target_node
    for _ in range(80):
        parent = child_to_parent.get(cur)
        if parent is None:
            break
        pn = nodes.get(parent)
        if pn and pn.get("type") == "AST_SWITCH_CASE":
            case_value = None
            kids = sorted(parent2children.get(parent, []),
                          key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
            for c in kids:
                cn = nodes.get(c)
                if cn and cn.get("type") == "string":
                    case_value = (cn.get("code") or "").strip().strip('"').strip("'")
                    break
                if cn and cn.get("type") in ("integer", "double"):
                    case_value = (cn.get("code") or "").strip()
                    break
            switch_line = 0
            list_parent = child_to_parent.get(parent)
            if list_parent is not None:
                switch_parent = child_to_parent.get(list_parent)
                if switch_parent is not None:
                    sn = nodes.get(switch_parent)
                    if sn and sn.get("type") == "AST_SWITCH":
                        try:
                            switch_line = int(sn.get("lineno") or 0)
                        except (ValueError, TypeError):
                            pass
            return (switch_line, case_value)
        cur = parent
    return (0, None)


def _find_callsite_line(caller_funcid: int, callee_funcid: int,
                          nodes: dict, parent2children: dict) -> int:
    callee_node = nodes.get(callee_funcid)
    if not callee_node:
        return 0
    callee_name = (callee_node.get("name") or "").strip().strip('"').strip("'")
    if not callee_name:
        return 0
    callee_bn = callee_name.split("\\")[-1]
    callee_class = (callee_node.get("classname") or "").strip().strip('"').strip("'")
    callee_class_bn = callee_class.split("\\")[-1] if callee_class else ""

    def _static_call_class(call_nid: int) -> str:
        kids = sorted(parent2children.get(call_nid, []),
                      key=lambda x: int(nodes.get(x, {}).get("childnum") or 0))
        if not kids:
            return ""
        cls_node = nodes.get(kids[0])
        if not cls_node or cls_node.get("type") != "AST_NAME":
            return ""
        for c in parent2children.get(kids[0], []):
            cn = nodes.get(c)
            if cn and cn.get("type") == "string":
                return (cn.get("code") or "").strip().strip('"').strip("'").split("\\")[-1]
        return ""

    def _has_name_descendant(root: int, target: str, max_depth: int = 5) -> bool:
        stack: list = [(root, 0)]
        seen: set = set()
        while stack:
            x, depth = stack.pop()
            if x in seen or depth > max_depth:
                continue
            seen.add(x)
            n = nodes.get(x)
            if not n:
                continue
            if n.get("type") == "string":
                s = (n.get("code") or "").strip().strip('"').strip("'")
                if s == target or s == callee_bn:
                    return True
            for c in parent2children.get(x, []):
                stack.append((c, depth + 1))
        return False

    for nid, n in nodes.items():
        if n.get("type") not in ("AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"):
            continue
        try:
            if int(n.get("funcid") or 0) != caller_funcid:
                continue
        except (ValueError, TypeError):
            continue
        if not _has_name_descendant(nid, callee_name):
            continue
        if callee_class_bn and n.get("type") == "AST_STATIC_CALL":
            if _static_call_class(nid) != callee_class_bn:
                continue
        try:
            return int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
    return 0


def _compute_dominator_lines_of(
    working_dir: str, target_file: str, target_line: int,
    scope_funcid: int = 0,
) -> set:
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists() or target_line <= 0:
        return set()
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")
    child_to_parent = _read_child_to_parent(wd / "rels.csv")

    target_basename = osp.basename(target_file)
    target_node = 0
    for nid, n in nodes.items():
        if n.get("type") not in ("AST_CALL", "AST_NEW", "AST_METHOD_CALL",
                                  "AST_STATIC_CALL", "AST_ASSIGN"):
            continue
        try:
            if int(n.get("lineno") or 0) != target_line:
                continue
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if scope_funcid and fid != scope_funcid:
            continue
        cur = fid
        for _ in range(8):
            fn = nodes.get(cur)
            if not fn:
                break
            if fn.get("type") == "AST_TOPLEVEL" and fn.get("flags") == "TOPLEVEL_FILE":
                if osp.basename(fn.get("name", "").strip('"')) == target_basename:
                    target_node = nid
                break
            try:
                cur = int(fn.get("funcid") or 0)
            except (ValueError, TypeError):
                break
            if not cur or cur == fid:
                break
        if target_node:
            break
    if not target_node:
        return {target_line}

    out: set = {target_line}

    cur = target_node
    for _ in range(80):
        parent = child_to_parent.get(cur)
        if parent is None:
            break
        pn = nodes.get(parent)
        if pn and pn.get("type") in ("AST_IF", "AST_IF_ELEM"):
            try:
                ln = int(pn.get("lineno") or 0)
                if ln > 0:
                    out.add(ln)
            except (ValueError, TypeError):
                pass
        if pn and pn.get("type") == "AST_SWITCH":
            try:
                ln = int(pn.get("lineno") or 0)
                if ln > 0:
                    out.add(ln)
            except (ValueError, TypeError):
                pass
        cur = parent

    ABORT_TYPES = ("AST_EXIT", "AST_THROW")

    def _subtree_aborts(root: int, max_depth: int = 30) -> bool:
        stack: list = [(root, 0)]
        seen: set = set()
        while stack:
            x, depth = stack.pop()
            if x in seen or depth > max_depth:
                continue
            seen.add(x)
            n = nodes.get(x)
            if n and n.get("type") in ABORT_TYPES:
                return True
            for c in parent2children.get(x, []):
                stack.append((c, depth + 1))
        return False

    for nid, n in nodes.items():
        if n.get("type") != "AST_IF":
            continue
        try:
            ln = int(n.get("lineno") or 0)
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if ln <= 0 or ln >= target_line:
            continue
        if scope_funcid and fid != scope_funcid:
            continue
        for elem in parent2children.get(nid, []):
            en = nodes.get(elem)
            if not en or en.get("type") != "AST_IF_ELEM":
                continue
            for c in parent2children.get(elem, []):
                cn = nodes.get(c)
                if cn and cn.get("type") == "AST_STMT_LIST":
                    if _subtree_aborts(c):
                        out.add(ln)
                    break
            if ln in out:
                break
    return out


def _in_scope_lines_from_discovery(discovery, working_dir: str,
                                    sink_line: int = 0) -> dict:
    if not discovery or not getattr(discovery, "found", False):
        return {}, {}
    if not discovery.hops:
        return {}, {}
    try:
        from module1_static_analysis.dispatch_resolver.fig_builder import build_fig, _read_nodes as _rn
        from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    except Exception:
        return {}, {}
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists():
        return {}, {}
    nodes = _rn(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")
    child_to_parent = _read_child_to_parent(wd / "rels.csv")
    try:
        fig = build_fig(wd)
    except Exception:
        return {}, {}

    result: dict = {}
    switch_case_dom: dict = {}

    def _add(file: str, lines: set):
        if not file:
            return
        result.setdefault(file, set()).update(lines)

    for hop in discovery.hops:
        caller_funcid = hop.to_funcid
        callee_funcid = hop.from_funcid
        caller_file = _containing_file(caller_funcid, fig, nodes)
        if not caller_file:
            continue
        if getattr(hop, "kind", "") == "include_dispatch" and getattr(hop, "site_line", 0):
            callsite_line = hop.site_line
        else:
            callsite_line = _find_callsite_line(
                caller_funcid, callee_funcid, nodes, parent2children)
        if not callsite_line:
            continue
        caller_node = nodes.get(caller_funcid) or {}
        is_toplevel = caller_node.get("type") == "AST_TOPLEVEL"
        scope_fid = 0 if is_toplevel else caller_funcid
        dom_lines = _compute_dominator_lines_of(
            working_dir, caller_file, callsite_line, scope_funcid=scope_fid)
        _add(caller_file, dom_lines)
        sw_line, case_val = _find_enclosing_switch_case(
            callsite_line, caller_funcid, caller_file,
            nodes, parent2children, child_to_parent)
        if sw_line and case_val is not None:
            switch_case_dom[(caller_file, sw_line)] = case_val

    if sink_line and discovery.hops:
        sink_callee_fid = discovery.hops[0].from_funcid
        sink_file = _containing_file(sink_callee_fid, fig, nodes)
        if sink_file:
            sink_doms = _compute_dominator_lines_of(
                working_dir, sink_file, sink_line, scope_funcid=sink_callee_fid)
            _add(sink_file, sink_doms)
            _sw_l, _sw_v = _find_enclosing_switch_case(
                sink_line, sink_callee_fid, sink_file,
                nodes, parent2children, child_to_parent)
            if _sw_l and _sw_v is not None:
                switch_case_dom[(sink_file, _sw_l)] = _sw_v
    return result, switch_case_dom


def _dispatch_query_from_switch_case(switch_case_dom: dict, sink_file: str) -> list:
    import re
    sink_dir = osp.dirname(_abs(sink_file))
    SW_REQ = re.compile(
        r"switch\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"](\w+)['\"]")
    out: list = []
    seen_keys: set = set()
    for (sw_file, sw_line), case_val in sorted(switch_case_dom.items()):
        if osp.dirname(_abs(sw_file)) != sink_dir:
            continue
        try:
            with open(sw_file, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            line_text = lines[sw_line - 1] if 0 < sw_line <= len(lines) else ""
        except Exception:
            continue
        m = SW_REQ.search(line_text)
        if not m:
            continue
        key = m.group(2)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        out.append((key, case_val))
    return out


def _fold_dispatch_action_into_url(url: str, switch_case_dom: dict, sink_file: str,
                                   working_dir: str, vlog=None) -> str:
    for _k, _v in _dispatch_query_from_switch_case(switch_case_dom or {}, sink_file):
        if f"{_k}=" in url:
            continue
        url += ("&" if "?" in url else "?") + f"{_k}={_v}"
        if vlog:
            vlog(f"  dispatch action '{_k}={_v}': → {url}")
    try:
        from module1_static_analysis.dispatch_resolver.interproc_include import recover_package_dispatch_for_sink
        _pkg = recover_package_dispatch_for_sink(working_dir, sink_file)
    except Exception:
        _pkg = None
    if _pkg and f"{_pkg.param}=" not in url:
        url += ("&" if "?" in url else "?") + f"{_pkg.param}={_pkg.value}"
        if vlog:
            vlog(f"  package dispatch '{_pkg.param}={_pkg.value}': → {url}")
    return url


def _abs(p: str) -> str:
    return str(Path(p).resolve())


def _ensure_targets_csv(working_dir: str, sink_abs: str, sink_line: int) -> None:
    p = osp.join(working_dir, "targets.csv")
    with open(p, "w") as f:
        f.write(f"{sink_abs}:{sink_line}\n")


def _run_predator_pipeline(working_dir: str, output_dir: str, *,
                            dense: bool = True,
                            file_filter_path: str = "") -> None:
    os.makedirs(output_dir, exist_ok=True)
    env = os.environ.copy()
    if dense:
        env["VIPER_DENSE_DIST"] = "1"
        env["VIPER_USE_AUGMENTED"] = "1"
    if file_filter_path:
        env["VIPER_FILE_FILTER"] = file_filter_path
    proc = subprocess.run(
        ["conda", "run", "-n", "autocyper", "python", "__main__.py",
         "-w", _abs(working_dir), "-o", _abs(output_dir)],
        cwd=PREDATOR_SCRIPTS,
        env=env,
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"[pipeline] predator stderr (last 800 chars):\n"
                         f"{proc.stderr[-800:]}\n")
        raise RuntimeError(f"predator pipeline failed (exit {proc.returncode})")


def _write_file_filter(sink_file: str, project_root: str, output_dir: str,
                        *, extra_seeds: Optional[list] = None) -> str:
    sink_path = Path(_abs(sink_file))
    seeds = [sink_path]
    if extra_seeds:
        for s in extra_seeds:
            try:
                p = Path(_abs(str(s)))
                if p not in seeds:
                    seeds.append(p)
            except (TypeError, OSError):
                pass
    included = param_extractor._collect_included_files(
        sink_path, Path(_abs(project_root)),
        extra_seeds=[p for p in seeds if p != sink_path] or None,
    )
    files = seeds + [p for p in included if p not in seeds]
    out = Path(output_dir) / "_viper_file_filter.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(str(p) for p in files) + "\n")
    return str(out)


def _compute_sink_dominator_lines(
    working_dir: str, sink_file: str, sink_line: int
) -> list[int]:
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists():
        return []
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")
    child_to_parent = _read_child_to_parent(wd / "rels.csv")

    sink_basename = osp.basename(sink_file)
    sink_node = 0
    sink_funcid = 0
    for nid, n in nodes.items():
        if n.get("type") not in ("AST_CALL", "AST_NEW", "AST_METHOD_CALL",
                                  "AST_STATIC_CALL", "AST_ASSIGN"):
            continue
        try:
            if int(n.get("lineno") or 0) != sink_line:
                continue
        except (ValueError, TypeError):
            continue
        cur = nid
        for _ in range(80):
            nn = nodes.get(cur)
            if not nn:
                break
            if nn.get("type") == "AST_TOPLEVEL" and nn.get("flags") == "TOPLEVEL_FILE":
                if osp.basename(nn.get("name", "").strip('"')) == sink_basename:
                    sink_node = nid
                    try:
                        sink_funcid = int(n.get("funcid") or 0)
                    except (ValueError, TypeError):
                        sink_funcid = 0
                break
            try:
                fid = int(nn.get("funcid") or 0)
            except (ValueError, TypeError):
                break
            cp = child_to_parent.get(cur)
            cur = cp if cp is not None else (fid if fid != cur else 0)
        if sink_node:
            break
    if not sink_node:
        return []

    out: set[int] = set()

    cur = sink_node
    for _ in range(80):
        parent = child_to_parent.get(cur)
        if parent is None:
            break
        pn = nodes.get(parent)
        if pn and pn.get("type") in ("AST_IF", "AST_IF_ELEM", "AST_SWITCH"):
            try:
                ln = int(pn.get("lineno") or 0)
                if ln > 0:
                    out.add(ln)
            except (ValueError, TypeError):
                pass
        cur = parent

    def _node_in_sink_file(node_id: int) -> bool:
        n = nodes.get(node_id)
        if not n:
            return False
        try:
            funcid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            return False
        if not funcid:
            return False
        fn = nodes.get(funcid)
        if not fn:
            return False
        if fn.get("type") == "AST_TOPLEVEL" and fn.get("flags") == "TOPLEVEL_FILE":
            return osp.basename(fn.get("name", "").strip('"')) == sink_basename
        try:
            outer = int(fn.get("funcid") or 0)
        except (ValueError, TypeError):
            return False
        outer_n = nodes.get(outer) if outer else None
        if outer_n and outer_n.get("type") == "AST_TOPLEVEL" \
                and outer_n.get("flags") == "TOPLEVEL_FILE":
            return osp.basename(outer_n.get("name", "").strip('"')) == sink_basename
        return False

    ABORT_TYPES = ("AST_EXIT", "AST_THROW")
    def _subtree_aborts(root: int, max_depth: int = 30) -> bool:
        stack: list[tuple[int, int]] = [(root, 0)]
        seen: set[int] = set()
        while stack:
            x, depth = stack.pop()
            if x in seen or depth > max_depth:
                continue
            seen.add(x)
            n = nodes.get(x)
            if n and n.get("type") in ABORT_TYPES:
                return True
            for c in parent2children.get(x, []):
                stack.append((c, depth + 1))
        return False

    for nid, n in nodes.items():
        if n.get("type") != "AST_IF":
            continue
        try:
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if ln <= 0 or ln >= sink_line:
            continue
        if not _node_in_sink_file(nid):
            continue
        for elem in parent2children.get(nid, []):
            en = nodes.get(elem)
            if not en or en.get("type") != "AST_IF_ELEM":
                continue
            for c in parent2children.get(elem, []):
                cn = nodes.get(c)
                if cn and cn.get("type") == "AST_STMT_LIST":
                    if _subtree_aborts(c):
                        out.add(ln)
                    break
            if ln in out:
                break

    return sorted(out)

    def _node_in_sink_file(node_id: int) -> bool:
        n = nodes.get(node_id)
        if not n:
            return False
        try:
            funcid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            return False
        if not funcid:
            return False
        fn = nodes.get(funcid)
        if not fn:
            return False
        if fn.get("type") == "AST_TOPLEVEL" and fn.get("flags") == "TOPLEVEL_FILE":
            return osp.basename(fn.get("name", "").strip('"')) == sink_basename
        try:
            outer = int(fn.get("funcid") or 0)
        except (ValueError, TypeError):
            return False
        outer_n = nodes.get(outer) if outer else None
        if outer_n and outer_n.get("type") == "AST_TOPLEVEL" \
                and outer_n.get("flags") == "TOPLEVEL_FILE":
            return osp.basename(outer_n.get("name", "").strip('"')) == sink_basename
        return False


def _find_node_at_sink_line(nodes, child_to_parent, sink_basename, sink_line):
    def _scan(type_filter):
        for nid, n in nodes.items():
            if type_filter is not None and n.get("type") not in type_filter:
                continue
            try:
                if int(n.get("lineno") or 0) != sink_line:
                    continue
            except (ValueError, TypeError):
                continue
            cur = nid
            for _ in range(80):
                nn = nodes.get(cur)
                if not nn:
                    break
                if nn.get("type") == "AST_TOPLEVEL" and nn.get("flags") == "TOPLEVEL_FILE":
                    if osp.basename(nn.get("name", "").strip('"')) == sink_basename:
                        return nid
                    break
                try:
                    fid = int(nn.get("funcid") or 0)
                except (ValueError, TypeError):
                    break
                cp = child_to_parent.get(cur)
                cur = cp if cp is not None else (fid if fid != cur else 0)
        return 0
    return (_scan(("AST_CALL", "AST_NEW", "AST_METHOD_CALL",
                   "AST_STATIC_CALL", "AST_ASSIGN"))
            or _scan(None))


def _compute_sink_enclosing_if_lines(
    working_dir: str, sink_file: str, sink_line: int
) -> list[int]:
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists() or not (wd / "rels.csv").exists():
        return []
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")
    child_to_parent = _read_child_to_parent(wd / "rels.csv")

    sink_basename = osp.basename(sink_file)
    sink_node = _find_node_at_sink_line(
        nodes, child_to_parent, sink_basename, sink_line)

    if not sink_node:
        return []

    out: set[int] = set()
    cur = sink_node
    for _ in range(50):
        parent = child_to_parent.get(cur)
        if parent is None:
            break
        p_node = nodes.get(parent)
        if p_node and p_node.get("type") == "AST_IF_ELEM":
            try:
                ln = int(p_node.get("lineno") or 0)
                if ln > 0:
                    out.add(ln)
            except (ValueError, TypeError):
                pass
        cur = parent
    return sorted(out)


def _compute_sink_inside_if(
    working_dir: str, sink_file: str, sink_line: int,
    enclosing_if_lines: list, body_ranges: list,
) -> str:
    if enclosing_if_lines or body_ranges:
        return "yes"
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists() or not (wd / "rels.csv").exists():
        return "unknown"
    try:
        nodes = _read_nodes(wd / "nodes.csv")
        child_to_parent = _read_child_to_parent(wd / "rels.csv")
    except Exception:
        return "unknown"
    sink_node = _find_node_at_sink_line(
        nodes, child_to_parent, osp.basename(sink_file), sink_line)
    return "no" if sink_node else "unknown"


def _compute_sink_enclosing_if_body_ranges(
    working_dir: str, sink_file: str, sink_line: int
) -> list[dict]:
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists() or not (wd / "rels.csv").exists():
        return []
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")
    child_to_parent = _read_child_to_parent(wd / "rels.csv")

    sink_basename = osp.basename(sink_file)
    sink_node = _find_node_at_sink_line(
        nodes, child_to_parent, sink_basename, sink_line)

    if not sink_node:
        return []

    def _subtree_lineno_range(root: int) -> tuple:
        min_ln = None
        max_ln = None
        stack = [root]
        seen = {root}
        while stack:
            cur_ = stack.pop()
            n = nodes.get(cur_)
            if n:
                try:
                    ln = int(n.get("lineno") or 0)
                    if ln > 0:
                        if min_ln is None or ln < min_ln:
                            min_ln = ln
                        if max_ln is None or ln > max_ln:
                            max_ln = ln
                except (ValueError, TypeError):
                    pass
            for c in parent2children.get(cur_, []):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return (min_ln or 0, max_ln or 0)

    out: list[dict] = []
    seen_lines: set = set()
    cur = sink_node
    for _ in range(50):
        parent = child_to_parent.get(cur)
        if parent is None:
            break
        p_node = nodes.get(parent)
        if p_node and p_node.get("type") == "AST_IF_ELEM":
            try:
                if_line = int(p_node.get("lineno") or 0)
            except (ValueError, TypeError):
                if_line = 0
            if if_line and if_line not in seen_lines:
                seen_lines.add(if_line)
                body_start = body_end = 0
                for c in parent2children.get(parent, []):
                    if nodes.get(c, {}).get("type") == "AST_STMT_LIST":
                        body_start, body_end = _subtree_lineno_range(c)
                        break
                out.append({
                    "if_line":    if_line,
                    "body_start": body_start,
                    "body_end":   body_end,
                })
        cur = parent
    return out


def _extract_sink_gate_constraints(
    working_dir: str, sink_file: str, sink_line: int,
    framework: Optional[str] = None,
) -> list[dict]:
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists() or not (wd / "rels.csv").exists():
        return []
    nodes = _read_nodes(wd / "nodes.csv")
    p2c = _read_rels(wd / "rels.csv")
    c2p = _read_child_to_parent(wd / "rels.csv")
    sink_basename = osp.basename(sink_file)
    sink_node = _find_node_at_sink_line(nodes, c2p, sink_basename, sink_line)
    if not sink_node:
        return []

    fw_methods = []
    if framework:
        try:
            from module1_static_analysis import param_extractor as _pe
            _pe._load_input_sources(framework)
            fw_methods = list(_pe._INPUT_WRAPPER_METHODS)
        except Exception:
            fw_methods = []

    def _str_child(nid, want_childnum=None):
        for c in p2c.get(nid, []):
            cn = nodes.get(c, {})
            if cn.get("type") == "string":
                if want_childnum is None or str(cn.get("childnum")) == str(want_childnum):
                    return (cn.get("code") or "").strip().strip('"')
        return None

    def _var_name(nid):
        return _str_child(nid)

    def _const_name(const_nid):
        for c in p2c.get(const_nid, []):
            if nodes.get(c, {}).get("type") == "AST_NAME":
                return _str_child(c)
        return None

    def _child_at(nid, childnum):
        for c in p2c.get(nid, []):
            if str(nodes.get(c, {}).get("childnum")) == str(childnum):
                return c
        return None

    def _accessor_in_subtree(root):
        st = [root]; seen = {root}
        while st:
            cur = st.pop(); n = nodes.get(cur) or {}
            t = n.get("type")
            if t == "AST_METHOD_CALL" and fw_methods:
                mname = _str_child(cur, "1")
                obj = _child_at(cur, "0")
                for (objp, method, channel) in fw_methods:
                    if mname != method:
                        continue
                    if objp:
                        if obj is None or nodes.get(obj, {}).get("type") not in (
                                "AST_PROP", "AST_METHOD_CALL", "AST_STATIC_PROP"):
                            continue
                        if _str_child(obj) != objp:
                            continue
                    arglist = _child_at(cur, "2")
                    k = _str_child(arglist) if arglist is not None else None
                    if k:
                        return (channel, k)
            if t == "AST_DIM":
                cs = p2c.get(cur, [])
                if cs and nodes.get(cs[0], {}).get("type") == "AST_VAR":
                    bn = _var_name(cs[0])
                    if bn in ("_GET", "_POST", "_REQUEST", "_COOKIE"):
                        for c in cs[1:]:
                            if nodes.get(c, {}).get("type") == "string":
                                return (bn.lstrip("_"),
                                        (nodes[c].get("code") or "").strip().strip('"'))
            for c in p2c.get(cur, []):
                if c not in seen:
                    seen.add(c); st.append(c)
        return None

    def _local_assign_rhs(varname, funcid):
        for nid, n in nodes.items():
            if n.get("type") not in ("AST_ASSIGN", "AST_ASSIGN_OP"):
                continue
            if str(n.get("funcid")) != str(funcid):
                continue
            cs = p2c.get(nid, [])
            if len(cs) < 2:
                continue
            if nodes.get(cs[0], {}).get("type") == "AST_VAR" and _var_name(cs[0]) == varname:
                return cs[1]
        return None

    def _formal_index(funcid, varname):
        try:
            fdecl = int(funcid)
        except (ValueError, TypeError):
            return None
        for c in p2c.get(fdecl, []):
            if nodes.get(c, {}).get("type") == "AST_PARAM_LIST":
                for pc in p2c.get(c, []):
                    if nodes.get(pc, {}).get("type") == "AST_PARAM" \
                       and _str_child(pc, "1") == varname:
                        try:
                            return int(nodes.get(pc, {}).get("childnum"))
                        except (ValueError, TypeError):
                            return None
        return None

    def _callsite_args_at(func_name, pos):
        out = []
        for nid, n in nodes.items():
            t = n.get("type")
            if t not in ("AST_METHOD_CALL", "AST_STATIC_CALL", "AST_CALL"):
                continue
            if t == "AST_CALL":
                nm = None
                for c in p2c.get(nid, []):
                    if nodes.get(c, {}).get("type") == "AST_NAME":
                        nm = _str_child(c); break
            else:
                nm = _str_child(nid, "1")
            if nm != func_name:
                continue
            arglist = _child_at(nid, "2")
            if arglist is None:
                for c in p2c.get(nid, []):
                    if nodes.get(c, {}).get("type") == "AST_ARG_LIST":
                        arglist = c; break
            if arglist is None:
                continue
            args = p2c.get(arglist, [])
            if pos < len(args):
                out.append((args[pos], n.get("funcid")))
        return out

    def _resolve_var_to_http(varname, funcid, depth=0):
        if depth > 4:
            return None
        rhs = _local_assign_rhs(varname, funcid)
        if rhs is not None:
            acc = _accessor_in_subtree(rhs)
            if acc:
                return acc
            if nodes.get(rhs, {}).get("type") == "AST_VAR":
                rv = _var_name(rhs)
                if rv and rv != varname:
                    r = _resolve_var_to_http(rv, funcid, depth + 1)
                    if r:
                        return r
        fname = nodes.get(int(funcid), {}).get("name") if funcid else None
        idx = _formal_index(funcid, varname) if funcid else None
        if fname and idx is not None:
            for (arg_id, caller_fid) in _callsite_args_at(fname, idx):
                acc = _accessor_in_subtree(arg_id)
                if acc:
                    return acc
                if nodes.get(arg_id, {}).get("type") == "AST_VAR":
                    av = _var_name(arg_id)
                    if av:
                        r = _resolve_var_to_http(av, caller_fid, depth + 1)
                        if r:
                            return r
        return None

    def _gate_polarity(cond):
        n = nodes.get(cond, {}); t = n.get("type")
        flags = n.get("flags") or ""
        pairs = []
        if t == "AST_VAR":
            nm = _var_name(cond)
            if nm:
                pairs.append((nm, "truthy"))
        elif t == "AST_UNARY_OP" and "BOOL_NOT" in flags:
            inner = p2c.get(cond, [])
            inner = inner[0] if inner else None
            it = nodes.get(inner, {}).get("type") if inner is not None else None
            if it == "AST_VAR":
                nm = _var_name(inner)
                if nm:
                    pairs.append((nm, "falsy"))
            elif it == "AST_EMPTY":
                for c in p2c.get(inner, []):
                    if nodes.get(c, {}).get("type") == "AST_VAR":
                        nm = _var_name(c)
                        if nm:
                            pairs.append((nm, "truthy"))
        elif t in ("AST_EMPTY", "AST_ISSET"):
            for c in p2c.get(cond, []):
                if nodes.get(c, {}).get("type") == "AST_VAR":
                    nm = _var_name(c)
                    if nm:
                        pairs.append((nm, "falsy" if t == "AST_EMPTY" else "truthy"))
        elif t == "AST_BINARY_OP":
            cs = p2c.get(cond, [])
            var = const = lit = None
            for c in cs:
                cc = nodes.get(c, {}); ct = cc.get("type")
                if ct == "AST_VAR" and var is None:
                    var = _var_name(c)
                elif ct == "AST_CONST":
                    const = _const_name(c)
                elif ct in ("string", "integer"):
                    lit = (cc.get("code") or "").strip().strip('"')
            is_eq = "IS_EQUAL" in flags or "IS_IDENTICAL" in flags
            is_neq = "IS_NOT_EQUAL" in flags or "IS_NOT_IDENTICAL" in flags
            if var and const is not None:
                cv = const.lower()
                falsy_c = cv in ("false", "null")
                truthy_c = cv == "true"
                if is_eq:
                    pairs.append((var, "falsy" if falsy_c else "truthy"))
                elif is_neq:
                    pairs.append((var, "truthy" if falsy_c else "falsy"))
            elif var and lit is not None and is_eq:
                pairs.append((var, "falsy" if lit in ("0", "") else {"eq": lit}))
        else:
            st = [cond]; seen = {cond}
            while st:
                cur = st.pop()
                if nodes.get(cur, {}).get("type") == "AST_VAR":
                    nm = _var_name(cur)
                    if nm:
                        pairs.append((nm, "truthy"))
                for c in p2c.get(cur, []):
                    if c not in seen:
                        seen.add(c); st.append(c)
        return pairs

    results = []
    seen_lines = set()
    cur = sink_node
    for _ in range(50):
        par = c2p.get(cur)
        if par is None:
            break
        pn = nodes.get(par, {})
        if pn.get("type") == "AST_IF_ELEM":
            try:
                if_line = int(pn.get("lineno") or 0)
            except (ValueError, TypeError):
                if_line = 0
            if if_line and if_line not in seen_lines:
                seen_lines.add(if_line)
                cond = None
                for c in p2c.get(par, []):
                    ct = nodes.get(c, {}).get("type")
                    if ct not in ("AST_STMT_LIST", "NULL"):
                        cond = c; break
                if cond is not None:
                    funcid = nodes.get(cond, {}).get("funcid")
                    _direct = _accessor_in_subtree(cond)
                    for (varname, required) in _gate_polarity(cond):
                        acc = _resolve_var_to_http(varname, funcid)
                        if acc:
                            results.append({"param": acc[1], "channel": acc[0],
                                            "required": required, "line": if_line})
                        elif _direct:
                            results.append({"param": _direct[1], "channel": _direct[0],
                                            "required": required, "line": if_line})
        cur = par
    _seen = set(); _out = []
    for r in results:
        k = (r["param"], r["line"])
        if k in _seen:
            continue
        _seen.add(k); _out.append(r)
    return _out


def _compute_predicate_lookahead(working_dir: str, sink_file: str,
                                   output_dir: str) -> list[dict]:
    wd = Path(working_dir)
    instr_csv = osp.join(output_dir, "instr-info.csv")
    nodes_csv = wd / "nodes.csv"
    rels_csv = wd / "rels.csv"
    if not (osp.exists(instr_csv) and nodes_csv.exists() and rels_csv.exists()):
        return []

    sink_basename = osp.basename(sink_file)
    sink_real = osp.realpath(sink_file)
    line_dist_exact: dict[int, int] = {}
    line_dist_bn: dict[int, int] = {}
    cur_is_bn = False
    cur_is_exact = False
    try:
        with open(instr_csv) as f:
            next(f, None)
            for raw in f:
                parts = raw.rstrip("\n").split("\t")
                if len(parts) < 4:
                    continue
                if parts[1] == "f":
                    fp = parts[3].strip()
                    cur_is_bn = (osp.basename(fp) == sink_basename)
                    cur_is_exact = cur_is_bn and (osp.realpath(fp) == sink_real)
                elif parts[1] == "d" and cur_is_bn:
                    try:
                        ln = int(parts[2])
                        d = int(float(parts[3]))
                    except ValueError:
                        continue
                    if ln not in line_dist_bn or d < line_dist_bn[ln]:
                        line_dist_bn[ln] = d
                    if cur_is_exact and (ln not in line_dist_exact
                                         or d < line_dist_exact[ln]):
                        line_dist_exact[ln] = d
    except OSError:
        return []
    line_dist = line_dist_exact if line_dist_exact else line_dist_bn
    if not line_dist:
        return []

    nodes = _read_nodes(nodes_csv)
    from module1_static_analysis.dispatch_resolver import build_fig
    from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    fig = build_fig(wd)

    p2c: dict[int, list[int]] = {}
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
                p2c.setdefault(p, []).append(c)
    except OSError:
        return []

    try:
        src_lines = Path(sink_file).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except OSError:
        src_lines = []

    def _full_condition(start_ln: int, max_lines: int = 12) -> str:
        if not (0 < start_ln <= len(src_lines)):
            return ""
        buf: list[str] = []
        depth = 0
        started = False
        in_q: str | None = None
        for i in range(start_ln - 1, min(len(src_lines), start_ln - 1 + max_lines)):
            raw_ln = src_lines[i]
            buf.append(raw_ln.strip())
            j = 0
            while j < len(raw_ln):
                ch = raw_ln[j]
                if in_q is not None:
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == in_q:
                        in_q = None
                elif ch in ("'", '"'):
                    in_q = ch
                elif ch == "(":
                    depth += 1
                    started = True
                elif ch == ")":
                    depth -= 1
                j += 1
            if started and depth <= 0:
                break
        return " ".join(x for x in buf if x)[:400]

    def _body_range(elem_id: int) -> tuple[int, int] | None:
        kids = sorted(p2c.get(elem_id, []),
                      key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
        body = None
        for c in kids:
            if nodes.get(c, {}).get("type") == "AST_STMT_LIST":
                body = c
        if not body:
            return None
        seen = {body}
        q = [body]
        lns = set()
        while q:
            cur = q.pop()
            try:
                ln = int(nodes.get(cur, {}).get("lineno") or 0)
                if ln > 0:
                    lns.add(ln)
            except (ValueError, TypeError):
                pass
            for c in p2c.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    q.append(c)
        return (min(lns), max(lns)) if lns else None

    _TERMINATORS = {"AST_RETURN", "AST_EXIT", "AST_THROW",
                    "AST_BREAK", "AST_CONTINUE"}

    def _body_stmt_list(elem_id: int) -> int | None:
        for c in sorted(p2c.get(elem_id, []),
                        key=lambda c: int(nodes.get(c, {}).get("childnum") or 0)):
            if nodes.get(c, {}).get("type") == "AST_STMT_LIST":
                return c
        return None

    def _elem_is_else(elem_id: int) -> bool:
        kids = sorted(p2c.get(elem_id, []),
                      key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
        return bool(kids) and nodes.get(kids[0], {}).get("type") == "NULL"

    def _stmt_terminates(node_id: int) -> bool:
        t = nodes.get(node_id, {}).get("type")
        if t in _TERMINATORS:
            return True
        if t == "AST_IF":
            elems = sorted(
                [c for c in p2c.get(node_id, [])
                 if nodes.get(c, {}).get("type") == "AST_IF_ELEM"],
                key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
            if not elems or not _elem_is_else(elems[-1]):
                return False
            return all(_body_terminates(e) for e in elems)
        return False

    def _body_terminates(elem_id: int) -> bool:
        sl = _body_stmt_list(elem_id)
        if sl is None:
            return False
        kids = sorted(p2c.get(sl, []),
                      key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
        if not kids:
            return False
        return _stmt_terminates(kids[-1])

    def _then_terminates(elem_id: int) -> bool:
        return _body_terminates(elem_id)

    def _subtree_max_line(root: int) -> int:
        seen = {root}
        q = [root]
        mx = 0
        while q:
            cur = q.pop()
            try:
                ln = int(nodes.get(cur, {}).get("lineno") or 0)
            except (ValueError, TypeError):
                ln = 0
            if ln > mx:
                mx = ln
            for c in p2c.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    q.append(c)
        return mx

    out: list[dict] = []
    for nid, n in nodes.items():
        if n.get("type") != "AST_IF":
            continue
        try:
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if not fid:
            continue
        cf = _containing_file(fid, fig, nodes)
        if not cf or osp.basename(cf) != sink_basename:
            continue
        elems = sorted(
            [c for c in p2c.get(nid, [])
             if nodes.get(c, {}).get("type") == "AST_IF_ELEM"],
            key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
        if not elems:
            continue
        if_end = _subtree_max_line(nid)
        after_if = [d for l, d in line_dist.items() if l > if_end]
        branges = [_body_range(e) for e in elems]
        for k, e in enumerate(elems):
            try:
                ln = int(nodes.get(e, {}).get("lineno") or 0)
            except (ValueError, TypeError):
                continue
            if ln <= 0:
                continue
            rng = branges[k]
            if not rng:
                continue
            bmin, bmax = rng
            then_vals = [d for l, d in line_dist.items() if bmin <= l <= bmax]
            false_vals: list[int] = []
            for j in range(k + 1, len(elems)):
                fr = branges[j]
                if fr:
                    fmin, fmax = fr
                    false_vals += [d for l, d in line_dist.items()
                                   if fmin <= l <= fmax]
            if _then_terminates(e):
                false_vals += after_if
            else:
                then_vals += after_if
                false_vals += after_if
            raw = _full_condition(ln) if 0 < ln <= len(src_lines) else ""
            out.append({
                "file": sink_file,
                "line": ln,
                "then_dist": min(then_vals) if then_vals else None,
                "false_dist": min(false_vals) if false_vals else None,
                "raw_line": raw,
            })
    out.sort(key=lambda d: d["line"])
    return out


def _compute_in_scope_dynamic_sites(working_dir: str,
                                      in_scope_basenames: list[str]) -> list[dict]:
    wd = Path(working_dir)
    sinks_csv = wd / "dispatch_sinks.csv"
    nodes_csv = wd / "nodes.csv"
    if not (sinks_csv.exists() and nodes_csv.exists() and in_scope_basenames):
        return []
    in_scope_set = set(in_scope_basenames)

    import csv
    site_cats: dict[int, str] = {}
    with open(sinks_csv) as f:
        for row in csv.DictReader(f):
            try:
                site_cats[int(row["site_id"])] = row["category"]
            except (ValueError, KeyError):
                continue
    if not site_cats:
        return []

    nodes = _read_nodes(nodes_csv)
    from module1_static_analysis.dispatch_resolver import build_fig
    from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    fig = build_fig(wd)

    out: list[dict] = []
    for sid, cat in site_cats.items():
        n = nodes.get(sid)
        if not n:
            continue
        try:
            lineno = int(n.get("lineno") or 0)
            funcid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if lineno <= 0 or funcid <= 0:
            continue
        file_path = _containing_file(funcid, fig, nodes)
        if not file_path:
            continue
        if osp.basename(file_path) not in in_scope_set:
            continue
        out.append({
            "file": file_path, "line": lineno,
            "category": cat, "site_id": sid,
        })
    out.sort(key=lambda d: (d["file"], d["line"], d["site_id"]))
    return out


def _compute_post_sink_lines(working_dir: str, sink_file: str, sink_line: int) -> list[int]:
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists() or not (wd / "rels.csv").exists():
        return []
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")
    child_to_parent = _read_child_to_parent(wd / "rels.csv")

    sink_basename = osp.basename(sink_file)
    sink_call_types = ("AST_CALL", "AST_NEW", "AST_METHOD_CALL",
                       "AST_STATIC_CALL", "AST_ASSIGN")
    sink_candidates = []
    for nid, n in nodes.items():
        if n.get("type") not in sink_call_types:
            continue
        try:
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if ln != sink_line:
            continue
        sink_candidates.append(nid)

    def _file_of(nid: int) -> str:
        cur = nid
        for _ in range(50):
            n = nodes.get(cur)
            if not n:
                return ""
            if n.get("type") == "AST_TOPLEVEL" and n.get("flags") == "TOPLEVEL_FILE":
                return n.get("name", "").strip('"')
            cur_parent = child_to_parent.get(cur)
            if cur_parent is None:
                try:
                    fid = int(n.get("funcid") or 0)
                except (ValueError, TypeError):
                    return ""
                if fid == cur:
                    return ""
                cur = fid
            else:
                cur = cur_parent
        return ""

    sink_node = 0
    for cand in sink_candidates:
        if osp.basename(_file_of(cand)) == sink_basename:
            sink_node = cand
            break
    if sink_node == 0:
        return []

    cur = sink_node
    stmt_list_id = 0
    sink_stmt_in_list = 0
    for _ in range(50):
        parent = child_to_parent.get(cur)
        if parent is None:
            break
        p_node = nodes.get(parent)
        if p_node and p_node.get("type") == "AST_STMT_LIST":
            stmt_list_id = parent
            sink_stmt_in_list = cur
            break
        cur = parent
    if not stmt_list_id:
        return []

    siblings = parent2children.get(stmt_list_id, [])
    try:
        sink_idx = siblings.index(sink_stmt_in_list)
    except ValueError:
        return []

    out: set[int] = set()
    def _collect(nid: int) -> None:
        n = nodes.get(nid)
        if not n:
            return
        try:
            ln = int(n.get("lineno") or 0)
            if ln > 0:
                out.add(ln)
        except (ValueError, TypeError):
            pass
        for c in parent2children.get(nid, []):
            _collect(c)

    for s in siblings[sink_idx:]:
        _collect(s)
    return sorted(out)


def _compute_pre_sink_lines(working_dir: str, sink_file: str, sink_line: int) -> list[int]:
    wd = Path(working_dir)
    if not (wd / "nodes.csv").exists() or not (wd / "rels.csv").exists():
        return []
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")
    child_to_parent = _read_child_to_parent(wd / "rels.csv")

    sink_basename = osp.basename(sink_file)
    sink_call_types = ("AST_CALL", "AST_NEW", "AST_METHOD_CALL",
                       "AST_STATIC_CALL", "AST_ASSIGN")
    sink_candidates = []
    for nid, n in nodes.items():
        if n.get("type") not in sink_call_types:
            continue
        try:
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if ln != sink_line:
            continue
        sink_candidates.append(nid)

    def _file_of(nid: int) -> str:
        cur = nid
        for _ in range(50):
            n = nodes.get(cur)
            if not n:
                return ""
            if n.get("type") == "AST_TOPLEVEL" and n.get("flags") == "TOPLEVEL_FILE":
                return n.get("name", "").strip('"')
            cur_parent = child_to_parent.get(cur)
            if cur_parent is None:
                try:
                    fid = int(n.get("funcid") or 0)
                except (ValueError, TypeError):
                    return ""
                if fid == cur:
                    return ""
                cur = fid
            else:
                cur = cur_parent
        return ""

    sink_node = 0
    for cand in sink_candidates:
        if osp.basename(_file_of(cand)) == sink_basename:
            sink_node = cand
            break
    if sink_node == 0:
        return []

    out: set[int] = set()
    def _collect(nid: int) -> None:
        n = nodes.get(nid)
        if not n:
            return
        try:
            ln = int(n.get("lineno") or 0)
            if ln > 0:
                out.add(ln)
        except (ValueError, TypeError):
            pass
        for c in parent2children.get(nid, []):
            _collect(c)

    cur = sink_node
    for _ in range(80):
        parent = child_to_parent.get(cur)
        if parent is None:
            break
        p_node = nodes.get(parent)
        if p_node and p_node.get("type") == "AST_STMT_LIST":
            siblings = parent2children.get(parent, [])
            try:
                idx = siblings.index(cur)
            except ValueError:
                idx = -1
            if idx > 0:
                for s in siblings[:idx]:
                    _collect(s)
            sl_parent = child_to_parent.get(parent)
            sl_pn = nodes.get(sl_parent) if sl_parent is not None else None
            if sl_pn and sl_pn.get("type") in (
                "AST_FUNC_DECL", "AST_METHOD", "AST_CLOSURE"
            ):
                break
            cur = parent
        else:
            cur = parent
    return sorted(out)


def _derive_entry_url(entry_file: str, project_root: str, webroot_url: str) -> str:
    entry_abs = _abs(entry_file)
    root_abs  = _abs(project_root)
    if not entry_abs.startswith(root_abs + os.sep) and entry_abs != root_abs:
        raise ValueError(
            f"entry_file ({entry_abs}) not under project_root ({root_abs}); "
            f"cannot derive URL"
        )
    rel = osp.relpath(entry_abs, root_abs).replace(os.sep, "/")
    return webroot_url.rstrip("/") + "/" + rel


def _request_key_of(node_id: int, nodes: dict, p2c: dict) -> str:
    n = nodes.get(node_id)
    if not n:
        return ""
    t = n.get("type")

    def _str_child(nid):
        for c in p2c.get(nid, []):
            cn = nodes.get(c)
            if cn and cn.get("type") == "string":
                return (cn.get("code") or "").strip().strip('"').strip("'")
        return ""

    if t == "AST_CALL":
        kids = sorted(p2c.get(node_id, []),
                      key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
        for k in kids:
            if (nodes.get(k) or {}).get("type") == "AST_ARG_LIST":
                ak = sorted(p2c.get(k, []),
                            key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
                if ak:
                    return _str_child(ak[0]) or (
                        (nodes.get(ak[0]) or {}).get("code") or ""
                    ).strip().strip('"').strip("'")
        return ""
    if t == "AST_DIM":
        kids = sorted(p2c.get(node_id, []),
                      key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
        if len(kids) >= 2:
            k1 = nodes.get(kids[1])
            if k1 and k1.get("type") == "string":
                return (k1.get("code") or "").strip().strip('"').strip("'")
    return ""


def _default_case_dispatch_constraints(
        working_dir: str, sink_file: str, sink_enclosing_funcid: int) -> list[dict]:
    if not sink_enclosing_funcid:
        return []
    try:
        from module1_static_analysis.dispatch_resolver.superglobal_keys import _load_cpg
        from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    except ImportError:
        return []
    bundle = _load_cpg(working_dir)
    if not bundle:
        return []
    nodes, _rev, p2c, fig, c2p, _rrv = bundle
    fn = nodes.get(sink_enclosing_funcid)
    if not fn:
        return []
    fname = (fn.get("name") or "").strip().strip('"').strip("'")
    if not fname:
        return []
    sink_bn = osp.basename(sink_file)
    out: list[dict] = []
    seen: set = set()
    for nid, n in nodes.items():
        if n.get("type") != "AST_CALL":
            continue
        kids = sorted(p2c.get(nid, []),
                      key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
        if not kids or (nodes.get(kids[0]) or {}).get("type") != "AST_NAME":
            continue
        callee = ""
        for c in p2c.get(kids[0], []):
            cn = nodes.get(c)
            if cn and cn.get("type") == "string":
                callee = (cn.get("code") or "").strip().strip('"').strip("'")
                break
        if callee != fname:
            continue
        try:
            cfid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            cfid = 0
        cf = _containing_file(cfid, fig, nodes) if cfid else None
        if not cf or osp.basename(str(cf)) != sink_bn:
            continue
        cur, sc = nid, None
        for _ in range(20):
            par = c2p.get(cur)
            if par is None:
                break
            if (nodes.get(par) or {}).get("type") == "AST_SWITCH_CASE":
                sc = par
                break
            cur = par
        if sc is None:
            continue
        sc_kids = sorted(p2c.get(sc, []),
                         key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
        if not sc_kids or (nodes.get(sc_kids[0]) or {}).get("type") != "NULL":
            continue
        sl = c2p.get(sc)
        sw = c2p.get(sl) if sl is not None else None
        if sw is None or (nodes.get(sw) or {}).get("type") != "AST_SWITCH":
            continue
        sw_kids = sorted(p2c.get(sw, []),
                         key=lambda x: int((nodes.get(x) or {}).get("childnum") or 0))
        if not sw_kids:
            continue
        key = _request_key_of(sw_kids[0], nodes, p2c)
        if key and key not in seen:
            seen.add(key)
            out.append({
                "param": key,
                "must_equal": "",
                "site_line": n.get("lineno"),
                "discriminator_origin": "switch_default",
                "condition_natural": (
                    f"{fname}() is the default: arm of switch on '{key}'; "
                    f"set '{key}' empty/non-case to route to it"),
            })
    return out


def _dispatch_constraints_from(discovery: EntryDiscovery) -> list[dict]:
    out: list[dict] = []
    for d in discovery.dispatch_decisions:
        for r in d.resolved_callees:
            if not r.reaches_sink:
                continue
            sc = r.structured_condition or {}
            out.append({
                "site_id":               d.site_id,
                "site_file":             d.file,
                "site_line":             d.lineno,
                "method":                d.method,
                "discriminator_origin":  d.discriminator_origin,
                "callee":                r.callee,
                "callee_file":           r.file,
                "callee_line":           r.line,
                "condition_natural":     r.condition,
                "param":                 sc.get("param", ""),
                "must_equal":            sc.get("equals", ""),
            })
    return out


def run_pipeline(
    *,
    sink_file: str,
    sink_line: int,
    working_dir: str,
    output_dir: str,
    project_root: str,
    webroot_url: str,
    entry_url_override: str = "",
    method: str = "GET",
    entry_suffix: str = "",
    llm_backend: str = "none",
    llm_model: str = "claude-opus-4-7",
    skip_predator: bool = False,
    do_seed_gen: bool = False,
    verbose: bool = False,
) -> dict:

    sink_abs = _abs(sink_file)
    working_dir = _abs(working_dir)
    output_dir = _abs(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    def vlog(msg: str):
        if verbose:
            print(f"[pipeline] {msg}", file=sys.stderr)

    vlog("stage 1: discover_entry")
    backend = None
    if llm_backend == "anthropic":
        from module1_static_analysis.dispatch_resolver import make_anthropic_backend
        backend = make_anthropic_backend(model=llm_model)

    predicate = (lambda _p: True) if not entry_suffix \
        else (lambda p, sfx=entry_suffix: p.endswith(sfx) or p.endswith("/" + sfx))

    discoveries = discover_entry(
        sink_file=sink_abs,
        sink_line=sink_line,
        working_dir=working_dir,
        llm_call=backend,
        webroot_predicate=predicate,
        verbose=verbose,
        collect_all=True,
    )
    _notfound_disc = None
    if not isinstance(discoveries, list):
        if getattr(discoveries, "found", False):
            discoveries = [discoveries]
        else:
            _notfound_disc = discoveries
            discoveries = []

    fw_result = None
    fw_candidates: list = []
    if not entry_url_override:
        try:
            from module1_static_analysis.framework_routing.pipeline_bridge import (
                resolve_entry_url as _fw_resolve,
                resolve_entry_candidates as _fw_candidates_fn,
            )
            fw_result = _fw_resolve(
                sink_file_abs=sink_abs, sink_line=sink_line,
                project_root=project_root, webroot_url=webroot_url,
                working_dir=working_dir,
            )
            fw_candidates = _fw_candidates_fn(
                sink_file_abs=sink_abs, sink_line=sink_line,
                project_root=project_root, webroot_url=webroot_url,
                working_dir=working_dir,
            )
        except Exception as e:
            vlog(f"stage 1b: framework_routing raised {type(e).__name__}: {e}")
            fw_result = None
            fw_candidates = []

    _real_fw = fw_result is not None and fw_result.framework != "flat_php"
    if _real_fw and fw_candidates:
        _sink_fid = (discoveries[0].sink_enclosing_funcid if discoveries
                     else (_notfound_disc.sink_enclosing_funcid if _notfound_disc else 0))
        _sink_lbl = (discoveries[0].sink_enclosing_label if discoveries
                     else (_notfound_disc.sink_enclosing_label if _notfound_disc else ""))
        _fw_discs = []
        _seen = set()
        for _c in fw_candidates:
            _key = (_c.entry_url, _c.handler_file)
            if _key in _seen:
                continue
            _seen.add(_key)
            _fw_discs.append(EntryDiscovery(
                sink_file=sink_abs, sink_line=sink_line,
                sink_enclosing_funcid=_sink_fid, sink_enclosing_label=_sink_lbl,
                found=True, entry_file=_c.handler_file or sink_abs,
                framework_entry_url=_c.entry_url,
            ))
        _fw_files = {d.entry_file for d in _fw_discs}
        discoveries = _fw_discs + [d for d in discoveries if d.entry_file not in _fw_files]
        vlog(f"stage 1b: framework={fw_result.framework} → merged "
             f"{len(_fw_discs)} route candidate(s) "
             f"(+{len(discoveries) - len(_fw_discs)} BFS fallback)")

    _pin = os.environ.get("VIPER_PIN_ENTRY_URL", "").strip()
    if _pin:
        _pinned = [d for d in discoveries
                   if _pin in (getattr(d, "framework_entry_url", "") or "")
                   or _pin in (d.entry_file or "")]
        if _pinned:
            discoveries = _pinned
            print(f"[stage-1b] VIPER_PIN_ENTRY_URL={_pin!r} → pinned to "
                  f"{len(discoveries)} discovery(ies): "
                  + ", ".join(getattr(d, 'framework_entry_url', '') or osp.basename(d.entry_file)
                              for d in discoveries))
        else:
            vlog(f"stage 1b: VIPER_PIN_ENTRY_URL={_pin!r} matched 0 — keeping all")

    if not discoveries:
        return {
            "stage_failed": "discover_entry",
            "reason": "no web entry found for sink",
        }
    discovery = discoveries[0]
    entry_file = discovery.entry_file
    vlog(f"entry: {entry_file}  (+{len(discoveries) - 1} more candidate(s))")

    print(f"[stage-1] discover_entry collect_all → {len(discoveries)} entry(ies): "
          + ", ".join(osp.basename(d.entry_file) for d in discoveries))

    vlog("stage 1.5: inject synthetic dispatch edges")
    aug_path, syn_edges = inject_dispatch_edges(discovery, working_dir)
    vlog(f"injected {len(syn_edges)} synthetic edge(s) → {aug_path.name}")
    for e in syn_edges:
        vlog(f"  {e}")

    _bridge_edges: list = []

    if fw_result is not None and fw_result.framework in ("codeigniter3", "codeigniter4"):
        try:
            from module1_static_analysis.framework_routing.pipeline_bridge import ci_loader_calls_edges
            _loader_edges = ci_loader_calls_edges(
                working_dir, project_root, fw_result.framework)
            if _loader_edges:
                _bridge_edges.extend(_loader_edges)
                with open(aug_path, "a", encoding="utf-8") as _fa:
                    for _caller, _callee in _loader_edges:
                        _fa.write(f"{_caller}\t{_callee}\tCALLS\t\n")
                vlog(f"stage 1.5b: injected {len(_loader_edges)} CI loader "
                     f"bridge edge(s) → {aug_path.name}")
        except Exception as _e:
            vlog(f"stage 1.5b: CI loader edge injection skipped ({_e})")

    if fw_result is not None and fw_result.framework in ("laravel", "laravel5"):
        try:
            from module1_static_analysis.framework_routing.pipeline_bridge import datagrid_calls_edges
            _dg_edges = datagrid_calls_edges(
                working_dir, project_root, fw_result.framework)
            if _dg_edges:
                _bridge_edges.extend(_dg_edges)
                with open(aug_path, "a", encoding="utf-8") as _fa:
                    for _caller, _callee in _dg_edges:
                        _fa.write(f"{_caller}\t{_callee}\tCALLS\t\n")
                vlog(f"stage 1.5c: injected {len(_dg_edges)} DataGrid "
                     f"bridge edge(s) → {aug_path.name}")
        except Exception as _e:
            vlog(f"stage 1.5c: DataGrid edge injection skipped ({_e})")

    try:
        from module1_static_analysis.dispatch_resolver.cg_refine import refine_dynamic_dispatch_edges
        _aug = osp.join(working_dir, "cpg_edges_augmented.csv")
        _base = "cpg_edges_augmented.csv" if osp.exists(_aug) else "cpg_edges.csv"
        _ref = refine_dynamic_dispatch_edges(
            working_dir, src_edges=_base,
            dst_edges="cpg_edges_augmented.csv", write_call_graph=False)
        if _ref.get("total_pruned"):
            vlog(f"stage 1.6: cg_refine pruned {_ref['total_pruned']} over-approx "
                 f"call_user_func edge(s) across {len(_ref['refined_sites'])} site(s)")
        else:
            vlog("stage 1.6: cg_refine — no over-approx edges to prune")
    except Exception as _e:
        vlog(f"stage 1.6: cg_refine skipped ({_e})")

    _existing_instr = osp.join(output_dir, "instr-info.csv")
    _skip_dist = os.environ.get("VIPER_SKIP_DIST", "0") == "1"
    if not skip_predator and _skip_dist and osp.exists(_existing_instr) \
            and osp.getsize(_existing_instr) > 0:
        vlog(f"stage 2: SKIP (VIPER_SKIP_DIST=1, reusing {_existing_instr} "
             f"— {osp.getsize(_existing_instr)} bytes)")
    elif not skip_predator:
        vlog("stage 2: run predator pipeline (sink as target, dense distance)")
        _ensure_targets_csv(working_dir, sink_abs, sink_line)
        _caller_files = _reverse_reachable_files(
            sink_abs, sink_line, working_dir, extra_caller_edges=_bridge_edges)
        for _disc in discoveries:
            for _ef in _caller_files_from_discovery(_disc, project_root):
                if _ef not in _caller_files:
                    _caller_files.append(_ef)
        filter_path = _write_file_filter(
            sink_abs, project_root, output_dir,
            extra_seeds=_caller_files,
        )
        vlog(f"  file filter: {filter_path} "
             f"({sum(1 for _ in open(filter_path))} file(s), "
             f"caller seeds: {len(_caller_files)})")
        _run_predator_pipeline(working_dir, output_dir, dense=True,
                                file_filter_path=filter_path)

    instr_info = osp.join(output_dir, "instr-info.csv")
    if not osp.exists(instr_info):
        return {
            "stage_failed": "predator_pipeline",
            "reason": f"instr-info.csv not produced at {instr_info}",
            "discovery": discovery.to_dict(),
        }

    _md = _instr_info_min_dist_by_file(instr_info)
    print("[stage-2] distance per entry: "
          + ", ".join(f"{osp.basename(d.entry_file)}={_md.get(d.entry_file, '∞')}"
                      for d in discoveries))

    framework_entry_meta: Optional[dict] = None
    use_bfs_dom_scope = False
    if entry_url_override:
        entry_url = entry_url_override
        vlog(f"stage 3: entry_url override = {entry_url}")
        use_bfs_dom_scope = bool(discovery and discovery.found
                                  and len(discovery.hops) > 0)
    else:
        if fw_result is not None:
            _bfs_hops = len(discovery.hops) if discovery else 0
            use_bfs_over_fw = (
                fw_result.framework == "flat_php"
                and discovery and discovery.found
                and _bfs_hops > 0
                and entry_file != sink_abs
            )
            if use_bfs_over_fw:
                entry_url = _derive_entry_url(entry_file, project_root, webroot_url)
                use_bfs_dom_scope = True
                vlog(f"stage 3a: framework_routing returned flat_php "
                     f"{fw_result.entry_url}, but stage 1 BFS walked "
                     f"{_bfs_hops} hop(s) to {entry_file} — using BFS result")
            else:
                entry_url = fw_result.entry_url
                framework_entry_meta = fw_result.to_dict()
                for _disc in discoveries:
                    if not getattr(_disc, "framework_entry_url", ""):
                        _disc.framework_entry_url = fw_result.entry_url
                vlog(f"stage 3a: framework_routing matched {fw_result.framework} "
                     f"({fw_result.hit_kind}, {fw_result.candidate_count} cand): "
                     f"{entry_url}")
                if fw_result.indirect_path:
                    vlog(f"  indirect via: {' → '.join(fw_result.indirect_path)}")
        else:
            vlog("stage 3: derive entry URL from project_root + webroot_url")
            entry_url = _derive_entry_url(entry_file, project_root, webroot_url)
            use_bfs_dom_scope = bool(discovery and discovery.found
                                      and len(discovery.hops) > 0)
            vlog(f"  base entry_url: {entry_url}")

    _bfs_scope_lines: Optional[dict] = None
    _bfs_switch_case_dom: Optional[dict] = None
    if use_bfs_dom_scope:
        _bfs_scope_lines, _bfs_switch_case_dom = _in_scope_lines_from_discovery(
            discovery, working_dir, sink_line=sink_line)
        vlog(f"stage 3b BFS scope: "
             f"{sum(len(v) for v in _bfs_scope_lines.values())} allowed line(s) across "
             f"{len(_bfs_scope_lines)} file(s); switch_case_dom={_bfs_switch_case_dom}")
    if not entry_url_override:
        if getattr(discovery, "entry_query", "") and discovery.entry_query not in entry_url:
            sep = "&" if "?" in entry_url else "?"
            new_url = entry_url + sep + discovery.entry_query
            vlog(f"stage 3b: dynamic-include dispatch query "
                 f"'{discovery.entry_query}': {entry_url} → {new_url}")
            entry_url = new_url
        entry_url = _fold_dispatch_action_into_url(
            entry_url, _bfs_switch_case_dom or {}, sink_abs, working_dir, vlog)

    sink_dominator_lines = _compute_sink_dominator_lines(
        working_dir, sink_abs, sink_line)
    vlog(f"stage 3.5: sink_dominator_lines = {sink_dominator_lines}")

    import time as _time
    fw_name = (framework_entry_meta or {}).get("framework") if framework_entry_meta else None
    entry_candidates = []
    for _d in discoveries:
        _eu = (getattr(_d, "framework_entry_url", "")
               or _derive_entry_url(_d.entry_file, project_root, webroot_url))
        if _d.entry_query and _d.entry_query not in _eu:
            _eu += ("&" if "?" in _eu else "?") + _d.entry_query
        _t = _time.time()
        try:
            _scope, _swdom = _in_scope_lines_from_discovery(
                _d, working_dir, sink_line=sink_line)
        except Exception:
            _scope = _swdom = None
        _eu = _fold_dispatch_action_into_url(
            _eu, _swdom or {}, sink_abs, working_dir, vlog)
        try:
            _c = param_extractor.extract(
                instr_info_csv=instr_info, php_source_file=sink_abs, entry_url=_eu,
                method=method, sink_line=sink_line, project_root=project_root,
                sink_dominator_lines=sink_dominator_lines, working_dir=working_dir,
                entry_file=_d.entry_file, framework=fw_name,
                extra_scan_files=_caller_files_from_discovery(_d, project_root),
                extra_scan_line_scope=_scope, extra_scan_switch_case_dom=_swdom)
        except Exception as _e:
            _c = None
            vlog(f"  per-discovery extract failed for {_d.entry_file}: {_e}")
        entry_candidates.append({
            "entry_url": _eu, "entry_file": _d.entry_file, "method": method,
            "speculative_distance": _md.get(_d.entry_file, float("inf")),
            "constraints": _c, "_extract_sec": round(_time.time() - _t, 1)})
    entry_candidates.sort(key=lambda c: c["speculative_distance"])

    print(f"[stage-3/4] {len(entry_candidates)} per-entry candidate(s); "
          + ", ".join(f"{osp.basename(c['entry_file'])}={c['speculative_distance']:.0f}"
                      for c in entry_candidates))
    _primary = entry_candidates[0]
    entry_url = _primary["entry_url"]
    entry_file = _primary["entry_file"]
    constraints = _primary["constraints"] or {}
    discovery = next((d for d in discoveries if d.entry_file == entry_file),
                     discoveries[0])
    if not constraints:
        return {"stage_failed": "param_extractor",
                "reason": "primary candidate produced no constraints",
                "entry_url": entry_url}


    _EXIT_KEY_TOKENS = ("logout", "logoff", "signout", "sign_out",
                        "loggout", "disconnect", "exit")
    def _is_exit_key(_k: str) -> bool:
        return any(_t in (_k or "").lower() for _t in _EXIT_KEY_TOKENS)
    _ps0 = constraints.get("param_sources")
    if isinstance(_ps0, dict):
        for _k in [k for k in _ps0 if _is_exit_key(k)]:
            _ps0.pop(_k, None)
    for _ifc in constraints.get("if_constraints", []) or []:
        if isinstance(_ifc.get("params"), list):
            _ifc["params"] = [p for p in _ifc["params"] if not _is_exit_key(p)]
        if isinstance(_ifc.get("param_sources"), dict):
            for _k in [k for k in _ifc["param_sources"] if _is_exit_key(k)]:
                _ifc["param_sources"].pop(_k, None)

    if discovery and getattr(discovery, "dispatch_param_sources", None):
        _ps = constraints.setdefault("param_sources", {})
        for _k, _ch in discovery.dispatch_param_sources.items():
            _ps.setdefault(_k, _ch)

    skip_autoappend = (
        framework_entry_meta is not None and "?" in entry_url
    )
    if not entry_url_override and not skip_autoappend:
        from urllib.parse import parse_qs, urlparse
        _existing_qs = parse_qs(urlparse(entry_url).query)
        _dispatch_keys = set(
            (getattr(discovery, "dispatch_param_sources", None) or {}).keys()
        )
        _EXIT_KEY_TOKENS = ("logout", "logoff", "signout", "sign_out",
                            "loggout", "disconnect", "exit")
        get_keys: list[str] = []
        for k, src in constraints.get("param_sources", {}).items():
            if src != "GET" or k in get_keys or k in _existing_qs:
                continue
            if k not in _dispatch_keys:
                vlog(f"stage 4b: GET gate '{k}' is not a dispatch param — "
                     f"keeping it MUTABLE (not frozen into entry_url)")
                continue
            if any(tok in k.lower() for tok in _EXIT_KEY_TOKENS):
                vlog(f"stage 4b: skip exit/logout-like GET gate '{k}' "
                     f"(presence diverts from sink)")
                continue
            get_keys.append(k)
        if get_keys:
            from urllib.parse import urlencode
            qs = urlencode([(k, "1") for k in get_keys])
            sep = "&" if "?" in entry_url else "?"
            new_entry_url = entry_url + sep + qs
            vlog(f"stage 4b: auto-appended dispatch GET gate(s) "
                 f"{get_keys}: {entry_url} → {new_entry_url}")
            entry_url = new_entry_url
            constraints["entry_url"] = entry_url

    _dc = _dispatch_constraints_from(discovery)
    _dc += _default_case_dispatch_constraints(
        working_dir, sink_abs, discovery.sink_enclosing_funcid)
    constraints["dispatch_constraints"] = _dc
    constraints["discovery_hops"] = [h.to_dict() for h in discovery.hops]
    constraints["synthetic_edges"] = [
        {"site_id": e.site_id, "callee_node_id": e.callee_node_id,
         "callee": e.callee_label, "site_category": e.site_category}
        for e in syn_edges
    ]
    constraints["post_sink_lines"] = _compute_post_sink_lines(
        working_dir, sink_abs, sink_line)
    constraints["pre_sink_lines"] = _compute_pre_sink_lines(
        working_dir, sink_abs, sink_line)
    constraints["sink_enclosing_if_lines"] = _compute_sink_enclosing_if_lines(
        working_dir, sink_abs, sink_line)
    constraints["sink_enclosing_if_body_ranges"] = _compute_sink_enclosing_if_body_ranges(
        working_dir, sink_abs, sink_line)
    constraints["sink_inside_if"] = _compute_sink_inside_if(
        working_dir, sink_abs, sink_line,
        constraints["sink_enclosing_if_lines"],
        constraints["sink_enclosing_if_body_ranges"])
    vlog(f"sink_inside_if: {constraints['sink_inside_if']}")
    if os.environ.get("VIPER_EXTRACT_MINIMAL_SCOPE") == "1":
        constraints["sink_gate_constraints"] = []
    else:
        constraints["sink_gate_constraints"] = _extract_sink_gate_constraints(
            working_dir, sink_abs, sink_line, framework=fw_name)
    vlog(f"sink_gate_constraints: {constraints['sink_gate_constraints']}")
    constraints["sink_dominator_lines"] = sink_dominator_lines
    constraints["in_scope_dynamic_sites"] = _compute_in_scope_dynamic_sites(
        working_dir, constraints.get("in_scope_files", []))
    constraints["predicate_lookahead"] = _compute_predicate_lookahead(
        working_dir, sink_abs, output_dir)
    vlog(f"post_sink_lines: {len(constraints['post_sink_lines'])} line(s); "
         f"sink_enclosing_if_lines: {constraints['sink_enclosing_if_lines']}; "
         f"in_scope_dynamic_sites: {len(constraints['in_scope_dynamic_sites'])}; "
         f"predicate_lookahead: {len(constraints['predicate_lookahead'])}")

    seed = None
    if do_seed_gen:
        vlog("stage 6: seed_generator.generate_seed")
        try:
            from module1_static_analysis import seed_generator
            seed = seed_generator.generate_seed(constraints, verbose=verbose)
        except Exception as e:
            seed = {"error": str(e)}

    if framework_entry_meta is not None:
        constraints["framework_entry"] = framework_entry_meta
        constraints["framework_prefilled_params"] = \
            framework_entry_meta.get("prefilled_params", {})
        constraints["framework_required_params"] = \
            framework_entry_meta.get("required_params", [])

    if os.environ.get("VIPER_LLM_INJECTION_SCHEMA", "0") == "1":
        try:
            from module1_static_analysis.dispatch_resolver.injection_schema import build_injection_schema
            from common.llm import chat as _llm_chat
            def _llm_call(_p):
                _r = _llm_chat(_p, stage="injection_schema")
                return _r.get("content", "") if isinstance(_r, dict) else str(_r)
            _stmt = (constraints.get("sink") or {}).get("statement", "")
            _schema = build_injection_schema(sink_abs, sink_line, _stmt, discovery, _llm_call,
                                             working_dir=working_dir)
            if _schema:
                from module1_static_analysis.dispatch_resolver.injection_schema import reconcile_schema_with_static
                reconcile_schema_with_static(_schema, constraints.get("param_sources") or {})
                constraints["injection_param_schema"] = _schema
                vlog(f"injection_param_schema: {_schema.get('params')} "
                     f"(inject={_schema.get('inject_param')})")
        except Exception as _e:
            vlog(f"injection_param_schema skipped: {_e}")
    else:
        vlog("injection_param_schema: LLM feature off by default (export VIPER_LLM_INJECTION_SCHEMA=1 to enable);"
             " inject_param decided by m3 static fallback (param_sources unconstrained)")

    _SINK_SHARED = ("sink", "exit_guards", "post_sink_lines", "pre_sink_lines",
                    "sink_dominator_lines", "predicate_lookahead",
                    "sink_enclosing_if_lines", "sink_enclosing_if_body_ranges",
                    "in_scope_dynamic_sites", "dispatch_constraints",
                    "injection_param_schema")
    for _cand in entry_candidates:
        if _cand["entry_file"] == entry_file:
            _cand["constraints"] = constraints
            continue
        _cc = _cand.get("constraints")
        if not isinstance(_cc, dict):
            continue
        for _k in _SINK_SHARED:
            if _k in constraints and _k not in _cc:
                _cc[_k] = constraints[_k]
        _cand.pop("_extract_sec", None)
    constraints.pop("_extract_sec", None)

    result = {
        "sink": {"file": sink_abs, "line": sink_line},
        "entry_url": entry_url,
        "entry_file": entry_file,
        "method": method,
        "entry_candidates": entry_candidates,
        "discovery": discovery.to_dict(),
        "constraints": constraints,
        "seed": seed,
        "framework_entry": framework_entry_meta,
    }
    out_json = osp.join(output_dir, "pipeline_result.json")
    with open(out_json, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    vlog(f"wrote {out_json}")
    return result


def _main():
    ap = argparse.ArgumentParser(
        description="VIPER module ① pipeline: sink → entry URL → params → seed.")
    ap.add_argument("--working-dir", required=True,
                    help="TChecker output dir (nodes.csv, ...).")
    ap.add_argument("--sink-file", required=True,
                    help="Absolute or relative path to sink PHP file.")
    ap.add_argument("--sink-line", required=True, type=int)
    ap.add_argument("--output-dir", required=True,
                    help="Where instr-info.csv + request_data.json + result are written.")
    ap.add_argument("--project-root", required=True,
                    help="Filesystem path that maps to webroot_url.")
    ap.add_argument("--webroot-url", required=True,
                    help="HTTP base URL that maps to project_root (e.g. "
                         "http://localhost:8770/openemr). Used to derive "
                         "entry_url from entry_file's relative path. "
                         "**Ignored when --entry-url is given.**")
    ap.add_argument("--entry-url", default="",
                    help="If set, skip _derive_entry_url and use this string "
                         "verbatim as the entry URL. Use when the caller (e.g. "
                         "the eval harness) already knows the precise URL "
                         "including framework-required query strings "
                         "(?site=default for OpenEMR, etc).")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--entry-suffix", default="",
                    help="Restrict entry candidate to files matching suffix (e.g. index.php).")
    ap.add_argument("--llm-backend", choices=["none", "anthropic"], default="none")
    ap.add_argument("--llm-model", default="claude-opus-4-7")
    ap.add_argument("--skip-predator", action="store_true",
                    help="Don't re-run predator pipeline (reuse existing instr-info.csv).")
    ap.add_argument("--seed", action="store_true",
                    help="Also run seed_generator (LLM required).")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    result = run_pipeline(
        sink_file=args.sink_file,
        sink_line=args.sink_line,
        working_dir=args.working_dir,
        output_dir=args.output_dir,
        project_root=args.project_root,
        webroot_url=args.webroot_url,
        entry_url_override=args.entry_url,
        method=args.method,
        entry_suffix=args.entry_suffix,
        llm_backend=args.llm_backend,
        llm_model=args.llm_model,
        skip_predator=args.skip_predator,
        do_seed_gen=args.seed,
        verbose=args.verbose,
    )

    if "stage_failed" in result:
        print(f"\n✗ pipeline failed at stage: {result['stage_failed']}")
        if "reason" in result:
            print(f"  reason: {result['reason']}")
        sys.exit(2)

    print("\n✓ pipeline complete")
    print(f"  entry_url:           {result['entry_url']}")
    print(f"  entry_file:          {result['entry_file']}")
    print(f"  discovery hops:      {len(result['discovery']['hops'])}")
    print(f"  dispatch constraints: {len(result['constraints']['dispatch_constraints'])}")
    print(f"  if-constraints:      {len(result['constraints']['if_constraints'])}")
    print(f"  param assignments:   {len(result['constraints']['param_assignments'])}")
    print(f"  injection chain:     {len(result['constraints']['injection_chain'])}")
    if result.get("seed"):
        s = result["seed"]
        if "error" in s:
            print(f"  seed:                ERROR — {s['error']}")
        else:
            print(f"  seed POST data:      {s.get('post_data', '')}")
            print(f"  seed URL:            {s.get('url_with_params', '')}")
    print(f"\n  full result:         {osp.join(_abs(args.output_dir), 'pipeline_result.json')}")


if __name__ == "__main__":
    _main()
