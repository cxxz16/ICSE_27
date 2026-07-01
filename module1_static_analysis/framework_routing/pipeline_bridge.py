from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .reverse_lookup import lookup as _ir_lookup
from .route_ir import EntryURLCandidate, Route
from .schema import FrameworkSchema, detect_framework, load_schema
from .extractor import extract_routes


KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


@dataclass
class EntryResolveResult:
    entry_url: str
    http_method: str
    framework: str
    prefilled_params: dict[str, list[str]] = field(default_factory=dict)
    required_params: list[str] = field(default_factory=list)
    auth_constraints: list[dict] = field(default_factory=list)
    hit_kind: str = "direct"
    indirect_path: list[str] = field(default_factory=list)
    matched_route_pattern: str = ""
    candidate_count: int = 0
    handler_file: str = ""
    debug: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_url": self.entry_url,
            "http_method": self.http_method,
            "framework": self.framework,
            "prefilled_params": self.prefilled_params,
            "required_params": self.required_params,
            "auth_constraints": self.auth_constraints,
            "hit_kind": self.hit_kind,
            "indirect_path": self.indirect_path,
            "matched_route_pattern": self.matched_route_pattern,
            "candidate_count": self.candidate_count,
            "handler_file": self.handler_file,
            "debug": self.debug,
        }


def resolve_entry_url(
    sink_file_abs: str | Path,
    sink_line: int,
    project_root: str | Path,
    webroot_url: str,
    working_dir: Optional[str | Path] = None,
    *,
    framework_override: Optional[str] = None,
) -> Optional[EntryResolveResult]:
    project_root = Path(project_root).resolve()
    sink_path = Path(sink_file_abs).resolve()

    framework = framework_override or detect_framework(project_root)
    if not framework:
        return None

    schema_path = KNOWLEDGE_DIR / f"{framework}.yaml"
    if not schema_path.exists():
        return None
    schema = load_schema(schema_path)

    routes = extract_routes(project_root, schema)
    if not routes:
        return None

    try:
        rel_sink = sink_path.relative_to(project_root).as_posix()
    except ValueError:
        return None

    cg_resolver = None
    if working_dir is not None:
        try:
            cg_resolver = _build_cpg_caller_resolver(
                Path(working_dir), project_root, framework=framework)
        except Exception as e:
            cg_resolver = None
            _last_resolver_err = str(e)
        else:
            _last_resolver_err = ""
    else:
        _last_resolver_err = "no working_dir provided"

    cands = _ir_lookup(
        rel_sink, sink_line, routes,
        base_url=webroot_url,
        call_graph_resolver=cg_resolver,
    )
    if not cands:
        return None

    cands_sorted = sorted(
        cands,
        key=lambda c: (
            0 if c.hit_kind == "direct" else 1,
            -sum(len(v) for v in c.prefilled_params.values()),
        ),
    )
    best = cands_sorted[0]
    return _materialize_result(
        best, framework, schema, webroot_url, project_root,
        len(routes), len(cands), _last_resolver_err)


def resolve_entry_candidates(
    sink_file_abs: str | Path,
    sink_line: int,
    project_root: str | Path,
    webroot_url: str,
    working_dir: Optional[str | Path] = None,
    *,
    framework_override: Optional[str] = None,
) -> list[EntryResolveResult]:
    project_root = Path(project_root).resolve()
    sink_path = Path(sink_file_abs).resolve()
    framework = framework_override or detect_framework(project_root)
    if not framework:
        return []
    schema_path = KNOWLEDGE_DIR / f"{framework}.yaml"
    if not schema_path.exists():
        return []
    schema = load_schema(schema_path)
    routes = extract_routes(project_root, schema)
    if not routes:
        return []
    try:
        rel_sink = sink_path.relative_to(project_root).as_posix()
    except ValueError:
        return []

    cg_resolver = None
    _resolver_err = "no working_dir provided"
    if working_dir is not None:
        try:
            cg_resolver = _build_cpg_caller_resolver(
                Path(working_dir), project_root, framework=framework)
            _resolver_err = ""
        except Exception as e:
            cg_resolver = None
            _resolver_err = str(e)

    cands = _ir_lookup(
        rel_sink, sink_line, routes,
        base_url=webroot_url, call_graph_resolver=cg_resolver)
    if not cands:
        return []
    cands_sorted = sorted(
        cands,
        key=lambda c: (
            0 if c.hit_kind == "direct" else 1,
            -sum(len(v) for v in c.prefilled_params.values()),
        ),
    )
    return [
        _materialize_result(c, framework, schema, webroot_url, project_root,
                            len(routes), len(cands), _resolver_err)
        for c in cands_sorted
    ]


def _materialize_result(
    best, framework, schema, webroot_url, project_root,
    n_routes, n_cands, resolver_err,
) -> EntryResolveResult:
    entry_url = best.materialized_url
    front_controller = (schema.extras or {}).get("front_controller", "")
    if front_controller:
        _prefix = webroot_url.rstrip("/")
        if entry_url.startswith(_prefix):
            _rest = entry_url[len(_prefix):]
            if not _rest.lstrip("/").startswith(front_controller):
                entry_url = f"{_prefix}/{front_controller}{_rest}"

    handler_file_abs = ""
    if best.source_route is not None and best.source_route.handler_locator.file:
        handler_file_abs = str(project_root / best.source_route.handler_locator.file)

    return EntryResolveResult(
        entry_url=entry_url,
        http_method=best.http_method,
        framework=framework,
        prefilled_params=dict(best.prefilled_params),
        required_params=list(best.required_params),
        auth_constraints=[_auth_to_dict(a) for a in best.auth_constraints],
        hit_kind=best.hit_kind,
        indirect_path=list(best.indirect_path),
        matched_route_pattern=best.url_pattern,
        candidate_count=n_cands,
        handler_file=handler_file_abs,
        debug={
            "n_routes_extracted": n_routes,
            "n_candidates": n_cands,
            "cg_resolver_err": resolver_err,
        },
    )


def _auth_to_dict(a) -> dict:
    return {"kind": a.kind, "name": a.name, "parameters": dict(a.parameters)}


_FUNC_LIKE_TYPES = {"AST_METHOD", "AST_FUNC_DECL", "AST_CLOSURE"}


@dataclass
class _FuncMeta:
    nid: int
    file: str
    name: str
    lineno: int
    endlineno: int


def _build_cpg_caller_resolver(
    working_dir: Path,
    project_root: Path,
    framework: Optional[str] = None,
) -> Callable[[str, int], Iterable[tuple[str, int, list[str]]]]:
    nodes_csv = working_dir / "nodes.csv"
    cg_csv    = working_dir / "call_graph.csv"
    if not nodes_csv.exists():
        raise FileNotFoundError(f"nodes.csv missing under {working_dir}")
    if not cg_csv.exists():
        raise FileNotFoundError(f"call_graph.csv missing under {working_dir}")

    funcid_to_file, func_decl = _index_nodes(nodes_csv, project_root)

    callers: dict[int, list[int]] = {}
    with cg_csv.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh, delimiter="\t")
        next(reader, None)
        for row in reader:
            if len(row) < 3:
                continue
            try:
                s = int(row[0]); e = int(row[1])
            except ValueError:
                continue
            if row[2] != "CALLS":
                continue
            callers.setdefault(e, []).append(s)

    file_funcs: dict[str, list[tuple[int, int, int]]] = {}
    for nid, meta in func_decl.items():
        file_funcs.setdefault(meta.file, []).append(
            (meta.lineno, meta.endlineno or 10**9, nid))
    for v in file_funcs.values():
        v.sort()

    def _containing_func(file_rel: str, line: int) -> Optional[int]:
        best: Optional[tuple[int, int, int]] = None
        for s, e, nid in file_funcs.get(file_rel, []):
            if s <= line <= e:
                if best is None or (e - s) < (best[1] - best[0]):
                    best = (s, e, nid)
        return best[2] if best else None

    if framework in ("codeigniter3", "codeigniter4"):
        for callee, caller in _ci_loader_edges(
            project_root, func_decl, _containing_func):
            callers.setdefault(callee, []).append(caller)

    if framework in ("laravel", "laravel5"):
        for callee, caller in _datagrid_edges(
            project_root, func_decl, _containing_func):
            callers.setdefault(callee, []).append(caller)

    MAX_DEPTH = 5
    MAX_YIELDS = 200

    def resolver(sink_file_rel: str, sink_line: int):
        sink_func = _containing_func(sink_file_rel, sink_line)
        if sink_func is None:
            return

        visited: set[int] = {sink_func}
        frontier: list[tuple[int, list[str], int]] = []
        sink_meta = func_decl[sink_func]
        for caller in callers.get(sink_func, []):
            if caller not in func_decl:
                continue
            frontier.append((caller, [sink_meta.name], 1))

        yielded = 0
        while frontier:
            nid, chain_from_sink, depth = frontier.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            meta = func_decl[nid]
            yield meta.file, meta.lineno, list(reversed(chain_from_sink + [meta.name]))
            yielded += 1
            if yielded >= MAX_YIELDS:
                return
            if depth >= MAX_DEPTH:
                continue
            for parent in callers.get(nid, []):
                if parent not in func_decl or parent in visited:
                    continue
                frontier.append((parent, chain_from_sink + [meta.name], depth + 1))

    return resolver


_CI_LOAD_RE = re.compile(
    r"\$this\s*->\s*load\s*->\s*(?:model|library|driver)\s*\(\s*"
    r"(?P<arg>\[[^\]]*\]|['\"][\w/]+['\"])"
    r"(?:\s*,\s*(?:true|false|null|\$\w+|['\"](?P<alias>\w+)['\"]))?",
    re.IGNORECASE,
)
_CI_STR_RE = re.compile(r"['\"]([\w/]+)['\"]")
_CI_PROP_CALL_RE = re.compile(r"\$this\s*->\s*(\w+)\s*->\s*(\w+)\s*\(")


def _ci_loader_edges(
    project_root: Path,
    func_decl: dict[int, "_FuncMeta"],
    containing_func: Callable[[str, int], Optional[int]],
) -> list[tuple[int, int]]:
    by_file_method: dict[str, dict[str, int]] = {}
    for nid, m in func_decl.items():
        if m.file:
            by_file_method.setdefault(m.file, {})[m.name.lower()] = nid
    loadable_files: dict[str, str] = {}
    for f in by_file_method:
        fl = f.lower()
        base = f.rsplit("/", 1)[-1]
        bl = base[:-4].lower() if base.lower().endswith(".php") else base.lower()
        if any(d in fl for d in ("/models/", "/model/", "/libraries/",
                                 "/library/", "/third_party/")) \
           or bl.endswith("_model") or bl.startswith("mdl_"):
            loadable_files[bl] = f

    prop2class: dict[str, str] = {}
    file_text: dict[str, str] = {}
    for f in by_file_method:
        try:
            file_text[f] = (project_root / f).read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _CI_LOAD_RE.finditer(file_text[f]):
            names = _CI_STR_RE.findall(m.group("arg"))
            for nm in names:
                base = nm.rsplit("/", 1)[-1].lower()
                prop = (m.group("alias") or base).lower() if len(names) == 1 else base
                prop2class[prop] = base

    edges: list[tuple[int, int]] = []
    for f, text in file_text.items():
        for m in _CI_PROP_CALL_RE.finditer(text):
            base = prop2class.get(m.group(1).lower())
            if not base:
                continue
            cf = loadable_files.get(base)
            if not cf:
                continue
            callee = by_file_method.get(cf, {}).get(m.group(2).lower())
            if callee is None:
                continue
            line = text.count("\n", 0, m.start()) + 1
            caller = containing_func(f, line)
            if caller is None or caller == callee:
                continue
            edges.append((callee, caller))
    return edges


_DATAGRID_REF_RE = re.compile(r"(?P<cls>[A-Za-z_]\w*DataGrid)\s*::\s*class")


def _datagrid_edges(
    project_root: Path,
    func_decl: dict[int, "_FuncMeta"],
    containing_func: Callable[[str, int], Optional[int]],
) -> list[tuple[int, int]]:
    by_file_method: dict[str, dict[str, int]] = {}
    for nid, m in func_decl.items():
        if m.file:
            by_file_method.setdefault(m.file, {})[m.name.lower()] = nid
    datagrid_files: dict[str, str] = {}
    for f in by_file_method:
        base = f.rsplit("/", 1)[-1]
        bl = base[:-4].lower() if base.lower().endswith(".php") else base.lower()
        if bl.endswith("datagrid"):
            datagrid_files[bl] = f

    edges: list[tuple[int, int]] = []
    for f in by_file_method:
        try:
            text = (project_root / f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _DATAGRID_REF_RE.finditer(text):
            cls = m.group("cls").lower()
            gf = datagrid_files.get(cls)
            if not gf or gf == f:
                continue
            line = text.count("\n", 0, m.start()) + 1
            caller = containing_func(f, line)
            if caller is None:
                continue
            for callee in by_file_method.get(gf, {}).values():
                if callee == caller:
                    continue
                edges.append((callee, caller))
    return edges


def datagrid_calls_edges(
    working_dir: str | Path,
    project_root: str | Path,
    framework: Optional[str] = None,
) -> list[tuple[int, int]]:
    if framework not in ("laravel", "laravel5"):
        return []
    working_dir = Path(working_dir)
    project_root = Path(project_root).resolve()
    nodes_csv = working_dir / "nodes.csv"
    if not nodes_csv.exists():
        return []
    _, func_decl = _index_nodes(nodes_csv, project_root)

    file_funcs: dict[str, list[tuple[int, int, int]]] = {}
    for nid, meta in func_decl.items():
        file_funcs.setdefault(meta.file, []).append(
            (meta.lineno, meta.endlineno or 10**9, nid))
    for v in file_funcs.values():
        v.sort()

    def _containing_func(file_rel: str, line: int) -> Optional[int]:
        best: Optional[tuple[int, int, int]] = None
        for s, e, nid in file_funcs.get(file_rel, []):
            if s <= line <= e:
                if best is None or (e - s) < (best[1] - best[0]):
                    best = (s, e, nid)
        return best[2] if best else None

    return [(caller, callee) for (callee, caller)
            in _datagrid_edges(project_root, func_decl, _containing_func)]


def ci_loader_calls_edges(
    working_dir: str | Path,
    project_root: str | Path,
    framework: Optional[str] = None,
) -> list[tuple[int, int]]:
    if framework not in ("codeigniter3", "codeigniter4"):
        return []
    working_dir = Path(working_dir)
    project_root = Path(project_root).resolve()
    nodes_csv = working_dir / "nodes.csv"
    if not nodes_csv.exists():
        return []
    _, func_decl = _index_nodes(nodes_csv, project_root)

    file_funcs: dict[str, list[tuple[int, int, int]]] = {}
    for nid, meta in func_decl.items():
        file_funcs.setdefault(meta.file, []).append(
            (meta.lineno, meta.endlineno or 10**9, nid))
    for v in file_funcs.values():
        v.sort()

    def _containing_func(file_rel: str, line: int) -> Optional[int]:
        best: Optional[tuple[int, int, int]] = None
        for s, e, nid in file_funcs.get(file_rel, []):
            if s <= line <= e:
                if best is None or (e - s) < (best[1] - best[0]):
                    best = (s, e, nid)
        return best[2] if best else None

    return [(caller, callee) for (callee, caller)
            in _ci_loader_edges(project_root, func_decl, _containing_func)]


def _index_nodes(
    nodes_csv: Path,
    project_root: Path,
) -> tuple[dict[int, str], dict[int, _FuncMeta]]:
    project_root = Path(project_root).resolve()
    topl: dict[int, str] = {}
    func_parent: dict[int, int] = {}
    raw_func_decls: dict[int, dict] = {}

    project_root_str = str(project_root)

    with nodes_csv.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh, delimiter="\t")
        header = next(reader, None) or []
        cols = {name: i for i, name in enumerate(header)}
        i_id      = cols.get("id:int", 0)
        i_type    = cols.get("type", 2)
        i_flags   = cols.get("flags:string_array", 3)
        i_lineno  = cols.get("lineno:int", 4)
        i_funcid  = cols.get("funcid:int", 7)
        i_classnm = cols.get("classname", 8)
        i_endln   = cols.get("endlineno:int", 10)
        i_name    = cols.get("name", 11)

        for row in reader:
            if len(row) <= i_name:
                continue
            t = row[i_type]
            if t == "AST_TOPLEVEL":
                flag = row[i_flags] if len(row) > i_flags else ""
                try:
                    nid = int(row[i_id])
                except ValueError:
                    continue
                if flag == "TOPLEVEL_FILE":
                    path = row[i_name].strip().strip('"')
                    if path:
                        topl[nid] = path
                else:
                    try:
                        fid = int(row[i_funcid] or 0)
                        if fid:
                            func_parent[nid] = fid
                    except ValueError:
                        pass
            elif t in _FUNC_LIKE_TYPES:
                try:
                    nid = int(row[i_id])
                    fid = int(row[i_funcid] or 0)
                    lineno = int(row[i_lineno] or 0)
                    endln  = int(row[i_endln] or 0) if i_endln < len(row) else 0
                except ValueError:
                    continue
                if fid:
                    func_parent[nid] = fid
                raw_func_decls[nid] = {
                    "name": row[i_name].strip().strip('"') if i_name < len(row) else "",
                    "classname": row[i_classnm].strip().strip('"') if i_classnm < len(row) else "",
                    "lineno": lineno,
                    "endlineno": endln,
                    "funcid": fid,
                }

    funcid_to_file_abs: dict[int, str] = dict(topl)
    for fid in list(func_parent):
        cur = fid
        seen = set()
        while cur in func_parent and cur not in seen:
            seen.add(cur)
            cur = func_parent[cur]
        if cur in topl:
            funcid_to_file_abs[fid] = topl[cur]

    def _rel(p: str) -> Optional[str]:
        try:
            return Path(p).resolve().relative_to(project_root).as_posix()
        except ValueError:
            return None

    funcid_to_file_rel: dict[int, str] = {}
    for fid, abs_path in funcid_to_file_abs.items():
        rel = _rel(abs_path)
        if rel:
            funcid_to_file_rel[fid] = rel

    func_decl: dict[int, _FuncMeta] = {}
    for nid, info in raw_func_decls.items():
        file_rel = funcid_to_file_rel.get(nid)
        if not file_rel:
            file_abs = funcid_to_file_abs.get(nid)
            if file_abs:
                file_rel = _rel(file_abs)
        if not file_rel:
            continue
        func_decl[nid] = _FuncMeta(
            nid=nid,
            file=file_rel,
            name=info["name"],
            lineno=info["lineno"],
            endlineno=info["endlineno"],
        )

    return funcid_to_file_rel, func_decl
