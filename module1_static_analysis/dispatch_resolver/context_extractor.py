
from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from .fig_builder import FIG, _read_nodes, _read_rels
from .narrow import CandidateDispatchSite, _containing_file
from .discriminator_classifier import (
    classify as classify_discriminator,
    DiscriminatorOrigin,
    DiscriminatorOriginInfo,
)


class Reachability(str, Enum):
    REACHABLE   = "reachable"
    UNREACHABLE = "unreachable"
    POTENTIAL   = "potential"

MAX_REACH_RECURSION_DEPTH = 2


CONTEXT_LINES_BEFORE = 25
CONTEXT_LINES_AFTER  = 5


@dataclass
class CandidateCallee:
    name: str
    kind: str
    file: str
    line: int
    reachability: Reachability = Reachability.UNREACHABLE
    snippet: str = ""

    @property
    def reaches_sink(self) -> bool:
        return self.reachability != Reachability.UNREACHABLE


@dataclass
class DispatchContext:
    site: CandidateDispatchSite

    enclosing_function_signature: str
    enclosing_function_body: str
    enclosing_function_lines: tuple[int, int]

    discriminator_expression: str
    discriminator_kind: str
    discriminator_origin: DiscriminatorOriginInfo

    callers: list[dict]

    candidate_callees: list[CandidateCallee]

    feasibility: str
    feasibility_reason: str

    sink_file: str

    standalone_vulnerability_signal: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["site"] = asdict(self.site)
        d["discriminator_origin"] = self.discriminator_origin.to_dict()
        return d


def build_context(
    site: CandidateDispatchSite,
    fig: FIG,
    working_dir: str | Path,
    sink_file: str,
    sink_line: int = 0,
) -> DispatchContext:
    wd = Path(working_dir)
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")

    sink_node = fig.file_by_path(sink_file)
    sink_abs = sink_node.path if sink_node else sink_file

    site_node = nodes.get(site.site_id)
    enclosing_func_id = int(site_node.get("funcid") or 0) if site_node else 0

    discr_origin = classify_discriminator(site, nodes, parent2children)

    enc_signature, enc_body, enc_lines = _read_enclosing_function_slice(
        site.file, site.lineno, nodes, enclosing_func_id,
        discriminator_var=discr_origin.discriminator_var,
        cpg_edges_csv=wd / "cpg_edges.csv",
    )

    discr_expr, discr_kind = _identify_discriminator(site, enc_body)

    callers = _find_callers(enclosing_func_id, fig, wd)

    callees = _enumerate_callees_strategy(
        site, fig, sink_abs, discr_origin
    )

    _compute_reachability(
        callees,
        sink_file=sink_abs, sink_line=sink_line,
        nodes=nodes, fig=fig, working_dir=wd,
    )

    feasibility, reason, vuln_flag = _classify_feasibility(
        site, callees, callers, discr_origin
    )

    return DispatchContext(
        site=site,
        enclosing_function_signature=enc_signature,
        enclosing_function_body=enc_body,
        enclosing_function_lines=enc_lines,
        discriminator_expression=discr_expr,
        discriminator_kind=discr_kind,
        discriminator_origin=discr_origin,
        callers=callers,
        candidate_callees=callees,
        feasibility=feasibility,
        feasibility_reason=reason,
        sink_file=sink_abs,
        standalone_vulnerability_signal=vuln_flag,
    )


_FN_DECL_RE = re.compile(
    r"^\s*(?:public|protected|private|static|\s)*\s*function\s+(\w+)\s*\([^)]*\)[^{]*",
    re.MULTILINE,
)


def _read_enclosing_function(
    file: str, site_lineno: int, nodes: dict[int, dict], enc_func_id: int
) -> tuple[str, str, tuple[int, int]]:
    text = Path(file).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    func_node = nodes.get(enc_func_id) if enc_func_id else None
    if func_node and func_node.get("type") in ("AST_FUNC_DECL", "AST_METHOD"):
        start = int(func_node.get("lineno") or 1)
        end   = int(func_node.get("endlineno") or 0) or start
        body = "\n".join(lines[start - 1: end])
        sig = lines[start - 1] if start - 1 < len(lines) else ""
        return sig.strip(), body, (start, end)

    s = max(0, site_lineno - CONTEXT_LINES_BEFORE - 1)
    e = min(len(lines), site_lineno + CONTEXT_LINES_AFTER)
    return "<top-level scope>", "\n".join(lines[s:e]), (s + 1, e)


SLICE_MODE_LINE_THRESHOLD = 80
SLICE_DISPATCH_CONTEXT_LINES = 2


def _read_enclosing_function_slice(
    file: str, site_lineno: int, nodes: dict[int, dict], enc_func_id: int,
    *,
    discriminator_var: str = "",
    cpg_edges_csv: Path | None = None,
) -> tuple[str, str, tuple[int, int]]:
    text = Path(file).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    func_node = nodes.get(enc_func_id) if enc_func_id else None
    if not (func_node and func_node.get("type") in ("AST_FUNC_DECL", "AST_METHOD")):
        return _read_enclosing_function(file, site_lineno, nodes, enc_func_id)

    start = int(func_node.get("lineno") or 1)
    end   = int(func_node.get("endlineno") or 0) or start
    func_lines = end - start + 1

    if (func_lines <= SLICE_MODE_LINE_THRESHOLD
            or not discriminator_var
            or cpg_edges_csv is None
            or not Path(cpg_edges_csv).exists()):
        return _read_enclosing_function(file, site_lineno, nodes, enc_func_id)

    reaches_edges = _read_reaches_edges(cpg_edges_csv)
    relevant_vars = _expand_var_set(reaches_edges, {discriminator_var})

    relevant_node_ids: set[int] = set()
    for s_id, e_id, var in reaches_edges:
        if var in relevant_vars:
            relevant_node_ids.add(s_id)
            relevant_node_ids.add(e_id)

    keep_lines: set[int] = set()
    for nid in relevant_node_ids:
        n = nodes.get(nid)
        if not n: continue
        try:
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if start <= ln <= end:
            keep_lines.add(ln)

    GATE_TYPES = ("AST_IF", "AST_IF_ELEM", "AST_RETURN",
                  "AST_THROW", "AST_EXIT", "AST_BREAK", "AST_CONTINUE")
    for nid, n in nodes.items():
        try:
            funcid = int(n.get("funcid") or 0)
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if funcid != enc_func_id:
            continue
        if n.get("type") in GATE_TYPES and start <= ln <= end:
            keep_lines.add(ln)

    keep_lines.add(start)
    for ln in range(max(start, site_lineno - SLICE_DISPATCH_CONTEXT_LINES),
                    min(end, site_lineno + SLICE_DISPATCH_CONTEXT_LINES) + 1):
        keep_lines.add(ln)
    keep_lines.add(end)

    sorted_ls = sorted(keep_lines)
    out_pieces: list[str] = []
    prev = None
    for ln in sorted_ls:
        if prev is not None and ln > prev + 1:
            gap = ln - prev - 1
            out_pieces.append(f"        // ... ({gap} line{'s' if gap > 1 else ''} elided) ...")
        if 1 <= ln <= len(lines):
            out_pieces.append(lines[ln - 1])
        prev = ln

    body = "\n".join(out_pieces)
    sig = lines[start - 1] if start - 1 < len(lines) else ""

    body = (f"// [VIPER slice mode: discriminator={discriminator_var!r} reach-relevant + "
            f"gates from a {func_lines}-line function]\n{body}")

    return sig.strip(), body, (start, end)


def _read_reaches_edges(cpg_edges_csv: Path) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    try:
        with open(cpg_edges_csv, "r", encoding="utf-8") as f:
            first = next(f, None)
            for raw in f:
                parts = raw.rstrip("\n").split("\t")
                if len(parts) < 4 or parts[2] != "REACHES":
                    continue
                try:
                    out.append((int(parts[0]), int(parts[1]), parts[3]))
                except ValueError:
                    continue
    except (FileNotFoundError, OSError):
        return []
    return out


def _expand_var_set(reaches_edges: list[tuple[int, int, str]],
                     seed_vars: set[str]) -> set[str]:
    if not seed_vars or not reaches_edges:
        return set(seed_vars)
    uses_at: dict[int, set[str]] = {}
    defs_at: dict[int, set[str]] = {}
    for s, e, var in reaches_edges:
        defs_at.setdefault(s, set()).add(var)
        uses_at.setdefault(e, set()).add(var)

    result = set(seed_vars)
    while True:
        relevant_use_nodes = {n for n, vs in uses_at.items() if vs & result}
        new_vars = set()
        for n in relevant_use_nodes:
            new_vars |= defs_at.get(n, set())
        if new_vars <= result:
            return result
        result |= new_vars


def _identify_discriminator(site: CandidateDispatchSite, fn_body: str) -> tuple[str, str]:
    line_text = ""
    for line in fn_body.splitlines():
        if site.category == "DYN_NEW_CLASS" and "new $" in line:
            line_text = line.strip(); break
        if site.category == "DYN_CALL_METHOD" and "->$" in line:
            line_text = line.strip(); break
        if site.category == "DYN_CUF" and "call_user_func" in line:
            line_text = line.strip(); break
        if site.category in ("DYN_CALL_FN",) and re.search(r"\$\w+\s*\(", line):
            line_text = line.strip(); break

    kind_map = {
        "DYN_NEW_CLASS":         "class_var",
        "DYN_CALL_METHOD":       "method_name_var",
        "DYN_CALL_FN":           "function_name_var",
        "DYN_CUF":               "cuf_arg",
        "DYN_CALL_STATIC_BOTH":  "mixed",
        "DYN_CALL_STATIC_CLASS": "class_var",
        "DYN_CALL_STATIC_METHOD":"method_name_var",
        "DYN_CALLBACK_BUILTIN":  "cuf_arg",
        "DYN_REFLECTION_INVOKE": "function_name_var",
        "DYN_NEW_CLASS":         "class_var",
    }
    return line_text or "<not found>", kind_map.get(site.category, "mixed")


def _find_callers(enc_func_id: int, fig: FIG, wd: Path) -> list[dict]:
    out: list[dict] = []
    cg_path = wd / "call_graph.csv"
    if not cg_path.exists() or enc_func_id == 0:
        return out

    nodes = _read_nodes(wd / "nodes.csv")

    callers_funcids: set[int] = set()
    with cg_path.open("r", encoding="utf-8") as f:
        for raw in f:
            cells = raw.rstrip("\n").split("\t")
            if len(cells) < 3:
                continue
            try:
                start, end = int(cells[0]), int(cells[1])
            except ValueError:
                continue
            if end == enc_func_id:
                callers_funcids.add(start)

    enc_func_node = nodes.get(enc_func_id) or {}
    enc_func_name = enc_func_node.get("name", "")

    for cf in callers_funcids:
        cf_file = _containing_file(cf, fig, nodes)
        if not cf_file or not Path(cf_file).exists():
            continue
        text = Path(cf_file).read_text(encoding="utf-8", errors="replace")
        snippet = ""
        line_no = 0
        if enc_func_name:
            pat = re.compile(r"\b" + re.escape(enc_func_name) + r"\s*\(")
            for i, line in enumerate(text.splitlines(), start=1):
                stripped = line.lstrip()
                if stripped.startswith(("//", "#", "*", "/*")):
                    continue
                if pat.search(line):
                    line_no = i
                    snippet = line.strip()
                    break
        out.append({"file": cf_file, "line": line_no, "snippet": snippet})
    return out


_CLASS_RE = re.compile(
    r"^\s*(?:final\s+|abstract\s+|readonly\s+)*class\s+(\w+)", re.MULTILINE
)
_FN_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|abstract|final)\s+)*"
    r"function\s+(\w+)\s*\(",
    re.MULTILINE,
)


def _enumerate_callees_strategy(
    site: CandidateDispatchSite,
    fig: FIG,
    sink_abs: str,
    discr: DiscriminatorOriginInfo,
) -> list[CandidateCallee]:
    if discr.origin == DiscriminatorOrigin.FULLY_INPUT:
        return []

    if discr.origin == DiscriminatorOrigin.LITERAL_SET:
        out: list[CandidateCallee] = []
        if site.category in ("DYN_CALL_METHOD", "DYN_REFLECTION_INVOKE"):
            return _enumerate_callees(site, fig, sink_abs)
        for lit in discr.literals:
            for f in fig.files:
                ftext = Path(f.path).read_text(encoding="utf-8", errors="replace")
                ftext_lines = ftext.splitlines()
                pat = re.compile(rf"^\s*(?:(?:public|protected|private|static|abstract|final)\s+)*"
                                 rf"(?:class|function)\s+{re.escape(lit)}\b")
                for i, ln in enumerate(ftext_lines, start=1):
                    if pat.match(ln):
                        out.append(CandidateCallee(
                            name=lit,
                            kind="class" if "class" in ln else "function",
                            file=f.path, line=i,
                            snippet=ln,
                        ))
        return out

    return _enumerate_callees(site, fig, sink_abs)


def _enumerate_callees(
    site: CandidateDispatchSite, fig: FIG, sink_abs: str
) -> list[CandidateCallee]:
    out: list[CandidateCallee] = []
    src_text = Path(site.file).read_text(encoding="utf-8", errors="replace")

    name_hint = _extract_name_hint(site, src_text)

    if site.category in ("DYN_NEW_CLASS",):
        for f in fig.files:
            ftext = Path(f.path).read_text(encoding="utf-8", errors="replace")
            ftext_lines = ftext.splitlines()
            for m in _CLASS_RE.finditer(ftext):
                cls = m.group(1)
                if name_hint and not cls.startswith(name_hint):
                    continue
                ln = ftext.count("\n", 0, m.start(1)) + 1
                out.append(CandidateCallee(
                    name=cls, kind="class", file=f.path, line=ln,
                    snippet=ftext_lines[ln - 1] if ln - 1 < len(ftext_lines) else "",
                ))

    elif site.category in ("DYN_CALL_METHOD",):
        method_hint = _extract_method_name_literal(site, src_text)
        for f in fig.files:
            ftext = Path(f.path).read_text(encoding="utf-8", errors="replace")
            ftext_lines = ftext.splitlines()
            for m in _FN_RE.finditer(ftext):
                fn = m.group(1)
                if method_hint and fn != method_hint:
                    continue
                ln = ftext.count("\n", 0, m.start(1)) + 1
                cls = _enclosing_class(ftext, m.start())
                fq = f"{cls}::{fn}" if cls else fn
                out.append(CandidateCallee(
                    name=fq, kind="method" if cls else "function",
                    file=f.path, line=ln,
                    snippet=ftext_lines[ln - 1] if ln - 1 < len(ftext_lines) else "",
                ))

    elif site.category in ("DYN_CUF", "DYN_CALL_FN", "DYN_CALLBACK_BUILTIN"):
        allow = _extract_allowlist(src_text, site.lineno)
        if allow:
            for f in fig.files:
                ftext = Path(f.path).read_text(encoding="utf-8", errors="replace")
                ftext_lines = ftext.splitlines()
                for m in _FN_RE.finditer(ftext):
                    fn = m.group(1)
                    if fn not in allow:
                        continue
                    ln = ftext.count("\n", 0, m.start(1)) + 1
                    out.append(CandidateCallee(
                        name=fn, kind="function", file=f.path, line=ln,
                        snippet=ftext_lines[ln - 1] if ln - 1 < len(ftext_lines) else "",
                    ))
        else:
            for f in fig.files:
                ftext = Path(f.path).read_text(encoding="utf-8", errors="replace")
                ftext_lines = ftext.splitlines()
                for m in _FN_RE.finditer(ftext):
                    fn = m.group(1)
                    ln = ftext.count("\n", 0, m.start(1)) + 1
                    out.append(CandidateCallee(
                        name=fn, kind="function", file=f.path, line=ln,
                        snippet=ftext_lines[ln - 1] if ln - 1 < len(ftext_lines) else "",
                    ))

    return out


def _extract_name_hint(site: CandidateDispatchSite, src_text: str) -> str:
    lines = src_text.splitlines()
    for i in range(max(0, site.lineno - 30), site.lineno):
        m = re.search(r"\$\w+\s*=\s*['\"]([A-Z]\w*)['\"]\s*\.", lines[i])
        if m:
            return m.group(1)
    return ""


def _extract_method_name_literal(site: CandidateDispatchSite, src_text: str) -> str:
    lines = src_text.splitlines()
    for i in range(max(0, site.lineno - 30), site.lineno):
        m = re.search(r"\$\w*[Mm](?:Name|ethod)\w*\s*=\s*['\"](\w+)['\"]", lines[i])
        if m:
            return m.group(1)
    return ""


def _extract_allowlist(src_text: str, around_line: int) -> list[str]:
    lines = src_text.splitlines()
    snippet = "\n".join(lines[max(0, around_line - 30): around_line + 5])
    m = re.search(r"\[\s*((['\"][^'\"]+['\"]\s*,\s*)+['\"][^'\"]+['\"])\s*\]", snippet)
    if not m:
        return []
    return re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))


def _enclosing_class(ftext: str, offset: int) -> str:
    last = ""
    for m in _CLASS_RE.finditer(ftext, 0, offset):
        last = m.group(1)
    return last


def _compute_reachability(
    candidates: list[CandidateCallee],
    *,
    sink_file: str, sink_line: int,
    nodes: dict[int, dict], fig: FIG, working_dir: Path,
) -> None:
    if not candidates:
        return

    if sink_line == 0:
        for c in candidates:
            c.reachability = (Reachability.REACHABLE
                              if c.file == sink_file else Reachability.UNREACHABLE)
        return

    succ_map = _read_succ_map(working_dir / "cpg_edges.csv")
    raw_site_ids = _read_dispatch_node_ids(working_dir / "dispatch_sinks.csv")
    flows_to_nodes = _read_flows_to_node_set(working_dir / "cpg_edges.csv")
    child_to_parent = _read_child_to_parent(working_dir / "rels.csv")
    stmt_to_sites = _dispatch_stmt_index(
        raw_site_ids, child_to_parent, flows_to_nodes)
    halt_set = set(stmt_to_sites.keys())

    sink_node = _find_sink_node(sink_file, sink_line, nodes, fig)
    parent2children = _read_rels(working_dir / "rels.csv")

    if sink_node == 0:
        for c in candidates:
            c.reachability = (Reachability.REACHABLE
                              if c.file == sink_file else Reachability.UNREACHABLE)
        return

    for c in candidates:
        entry = _candidate_entry_node(c, nodes, fig)
        if entry == 0:
            c.reachability = Reachability.UNREACHABLE
            continue
        c.reachability = _forward_reach(
            entry=entry, sink_node=sink_node,
            succ_map=succ_map,
            halt_set=halt_set, stmt_to_sites=stmt_to_sites,
            nodes=nodes, fig=fig, working_dir=working_dir,
            parent2children=parent2children,
            depth=0,
        )


def _read_succ_map(cpg_edges_csv: Path) -> dict[int, list[int]]:
    out: dict[int, list[int]] = defaultdict(list)
    if not cpg_edges_csv.exists():
        return out
    with cpg_edges_csv.open("r", encoding="utf-8") as f:
        next(f, None)
        for raw in f:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[2] not in ("FLOWS_TO", "CALLS"):
                continue
            try:
                out[int(parts[0])].append(int(parts[1]))
            except ValueError:
                continue
    return out


def _read_flows_to_node_set(cpg_edges_csv: Path) -> set[int]:
    out: set[int] = set()
    if not cpg_edges_csv.exists():
        return out
    with cpg_edges_csv.open("r", encoding="utf-8") as f:
        next(f, None)
        for raw in f:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[2] != "FLOWS_TO":
                continue
            try:
                out.add(int(parts[0]))
                out.add(int(parts[1]))
            except ValueError:
                continue
    return out


def _read_child_to_parent(rels_csv: Path) -> dict[int, int]:
    out: dict[int, int] = {}
    if not rels_csv.exists():
        return out
    with rels_csv.open("r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            if not row or len(row) < 2:
                continue
            try:
                p, c = int(row[0]), int(row[1])
            except ValueError:
                continue
            out.setdefault(c, p)
    return out


def _read_dispatch_node_ids(dispatch_sinks_csv: Path) -> set[int]:
    out: set[int] = set()
    if not dispatch_sinks_csv.exists():
        return out
    with dispatch_sinks_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                out.add(int(row["site_id"]))
            except (ValueError, KeyError):
                continue
    return out


def _dispatch_stmt_index(
    site_ids: set[int],
    child_to_parent: dict[int, int],
    flows_to_nodes: set[int],
    max_walk: int = 20,
) -> dict[int, list[int]]:
    out: dict[int, list[int]] = defaultdict(list)
    for site in site_ids:
        cur = site
        for _ in range(max_walk):
            if cur in flows_to_nodes:
                out[cur].append(site)
                break
            parent = child_to_parent.get(cur)
            if parent is None or parent == cur:
                break
            cur = parent
    return out


def _find_sink_node(sink_file: str, sink_line: int,
                     nodes: dict[int, dict], fig: FIG) -> int:
    target_path = fig.file_by_path(sink_file)
    target = target_path.path if target_path else sink_file
    for nid, n in nodes.items():
        try:
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if ln != sink_line:
            continue
        try:
            funcid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if funcid and _containing_file(funcid, fig, nodes) == target:
            return nid
    return 0


def _candidate_entry_node(cand: CandidateCallee,
                           nodes: dict[int, dict], fig: FIG) -> int:
    target_path = fig.file_by_path(cand.file)
    target = target_path.path if target_path else cand.file
    target_types = (
        "AST_METHOD", "AST_FUNC_DECL", "AST_TOPLEVEL", "AST_CLOSURE"
    )
    for nid, n in nodes.items():
        if n.get("type") not in target_types:
            continue
        try:
            ln = int(n.get("lineno") or 0)
        except (ValueError, TypeError):
            continue
        if ln != cand.line:
            continue
        try:
            funcid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        cf = _containing_file(funcid, fig, nodes) if funcid else \
             (n.get("name", "") if n.get("flags") == "TOPLEVEL_FILE" else "")
        if cf == target:
            return nid
    return 0


def _expand_callee_entry(entry: int, nodes: dict[int, dict],
                          parent2children: dict[int, list[int]]) -> list[int]:
    n = nodes.get(entry)
    if not n:
        return [entry]
    typ = n.get("type", "")
    flags = n.get("flags", "")

    if typ == "AST_TOPLEVEL" and flags == "TOPLEVEL_CLASS":
        method_starts: list[int] = []
        for nid, nn in nodes.items():
            try:
                if (int(nn.get("funcid") or 0) == entry
                        and nn.get("type") == "AST_METHOD"):
                    method_starts.extend(_expand_callee_entry(
                        nid, nodes, parent2children))
            except (ValueError, TypeError):
                continue
        return method_starts or [entry]

    if typ in ("AST_METHOD", "AST_FUNC_DECL", "AST_CLOSURE"):
        for child in parent2children.get(entry, []):
            cn = nodes.get(child)
            if cn and cn.get("type") == "CFG_FUNC_ENTRY":
                return [child]
        for child in parent2children.get(entry, []):
            cn = nodes.get(child)
            if cn and cn.get("type") == "AST_STMT_LIST":
                stmts = parent2children.get(child, [])
                if stmts:
                    return [stmts[0]]
        for off in range(1, 6):
            cn = nodes.get(entry + off)
            if cn and cn.get("type") == "AST_STMT_LIST":
                stmts = parent2children.get(entry + off, [])
                if stmts:
                    return [stmts[0]]
        return [entry]
    return [entry]


def _forward_reach(
    *,
    entry: int, sink_node: int,
    succ_map: dict[int, list[int]],
    halt_set: set[int],
    stmt_to_sites: dict[int, list[int]],
    nodes: dict[int, dict], fig: FIG, working_dir: Path,
    parent2children: dict[int, list[int]],
    depth: int,
) -> Reachability:
    visited: set[int] = set()
    body_starts = _expand_callee_entry(entry, nodes, parent2children)
    queue: list[int] = list(body_starts)
    encountered_stmts: set[int] = set()
    while queue:
        n = queue.pop(0)
        if n in visited:
            continue
        visited.add(n)
        if n == sink_node:
            return Reachability.REACHABLE
        if n in halt_set:
            encountered_stmts.add(n)
            continue
        queue.extend(succ_map.get(n, []))

    if not encountered_stmts:
        return Reachability.UNREACHABLE
    if depth >= MAX_REACH_RECURSION_DEPTH - 1:
        return Reachability.POTENTIAL

    for stmt in encountered_stmts:
        for d_site_id in stmt_to_sites.get(stmt, []):
            sub_site = _site_from_node(d_site_id, nodes, working_dir)
            if not sub_site:
                continue
            d_origin = classify_discriminator(sub_site, nodes, parent2children)
            sub_cands = _enumerate_callees_strategy(sub_site, fig, "", d_origin)
            for sc in sub_cands:
                sub_entry = _candidate_entry_node(sc, nodes, fig)
                if sub_entry == 0:
                    continue
                sv = _forward_reach(
                    entry=sub_entry, sink_node=sink_node,
                    succ_map=succ_map,
                    halt_set=halt_set, stmt_to_sites=stmt_to_sites,
                    nodes=nodes, fig=fig, working_dir=working_dir,
                    parent2children=parent2children,
                    depth=depth + 1,
                )
                if sv == Reachability.REACHABLE:
                    return Reachability.REACHABLE
    return Reachability.POTENTIAL


def _site_from_node(node_id: int, nodes: dict[int, dict],
                     working_dir: Path) -> Optional[CandidateDispatchSite]:
    n = nodes.get(node_id)
    if not n:
        return None
    ds_csv = working_dir / "dispatch_sinks.csv"
    if not ds_csv.exists():
        return None
    with ds_csv.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                if int(row["site_id"]) != node_id:
                    continue
            except (ValueError, KeyError):
                continue
            from .narrow import CandidateDispatchSite as CDS
            from .fig_builder import build_fig as _bfig
            return CDS(
                site_id=node_id,
                category=row.get("category", ""),
                callable_arg_positions=row.get("callable_arg_positions", ""),
                data_arg_positions_hint=row.get("data_arg_positions_hint", ""),
                file=str(_containing_file(int(n.get("funcid") or 0),
                                           _bfig(working_dir), nodes)),
                lineno=int(n.get("lineno") or 0),
            )
    return None


def _classify_feasibility(
    site: CandidateDispatchSite,
    callees: list[CandidateCallee],
    callers: list[dict],
    discr: DiscriminatorOriginInfo,
) -> tuple[str, str, Optional[str]]:
    if discr.origin == DiscriminatorOrigin.FULLY_INPUT:
        vuln = (f"Discriminator '{discr.discriminator_var}' is fully controlled "
                f"by user input ({', '.join(discr.input_sources)}); the "
                f"dispatch can be coerced to ANY callable in the project, "
                f"including PHP built-ins like system/exec/eval. "
                f"This is a standalone RCE candidate independent of the "
                f"downstream SQLi sink.")
        return ("RUNTIME_REQUIRED",
                "discriminator fully user-controlled — candidate space unbounded",
                vuln)

    n = len(callees)
    if n == 0:
        return ("RUNTIME_REQUIRED",
                "no static candidates discoverable from name hint or allow-list",
                None)
    if n > 50:
        return ("STATIC_AMBIGUOUS",
                f"{n} candidates exceeds the easy-LLM threshold (50)",
                None)
    if not callers:
        return ("STATIC_AMBIGUOUS",
                "no callers found in static call graph (probably indirect)",
                None)
    return ("STATIC_RESOLVABLE",
            f"{n} candidate(s), {len(callers)} caller(s) — both bounded",
            None)


def _main():
    import argparse, json

    from .fig_builder import build_fig
    from .narrow import narrow

    ap = argparse.ArgumentParser(description="Extract per-site context for LLM dispatch resolution.")
    ap.add_argument("-w", "--working-dir", required=True)
    ap.add_argument("-s", "--sink-file", required=True)
    ap.add_argument("-l", "--sink-line", type=int, default=0,
                    help="Sink line number; needed for accurate Reachability (0 = file-equality fallback).")
    ap.add_argument("--summary-only", action="store_true",
                    help="Print compact summary instead of full JSON.")
    args = ap.parse_args()

    wd = Path(args.working_dir)
    fig = build_fig(wd)
    sites = narrow(args.sink_file, fig, wd / "dispatch_sinks.csv", wd / "nodes.csv")

    contexts = [build_context(s, fig, wd, args.sink_file, sink_line=args.sink_line)
                for s in sites]

    if args.summary_only:
        for c in contexts:
            print(f"\n── site {c.site.site_id} ({c.site.category}) @ {c.site.file}:{c.site.lineno}")
            print(f"   feasibility:  {c.feasibility}  ({c.feasibility_reason})")
            d = c.discriminator_origin
            print(f"   discriminator: ${d.discriminator_var}  origin={d.origin.value}")
            if d.literals:
                print(f"     literals:       {d.literals[:5]}")
            if d.input_sources:
                print(f"     input_sources:  {d.input_sources}")
            if d.sanitizers_applied:
                print(f"     sanitizers:     {d.sanitizers_applied}")
            if d.note:
                print(f"     note:           {d.note}")
            if c.standalone_vulnerability_signal:
                print(f"   ⚠ standalone vulnerability:")
                print(f"     {c.standalone_vulnerability_signal}")
            print(f"   callers:      {len(c.callers)}")
            for cl in c.callers:
                print(f"     - {cl['file']}:{cl['line']}  {cl['snippet']!r}")
            print(f"   candidates:   {len(c.candidate_callees)}")
            for cc in c.candidate_callees:
                tag = {"reachable": "★ REACHES SINK",
                       "potential":  "≈ MAY REACH (2nd dispatch)",
                       "unreachable": ""}.get(cc.reachability.value, "")
                print(f"     - {cc.name:<30} {cc.kind}  @ {Path(cc.file).name}:{cc.line}  {tag}")
    else:
        print(json.dumps([c.to_dict() for c in contexts], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _main()
