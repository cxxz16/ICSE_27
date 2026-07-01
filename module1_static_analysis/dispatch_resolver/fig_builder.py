
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

csv.field_size_limit(sys.maxsize)


@dataclass
class FileNode:
    funcid: int
    path: str


@dataclass
class IncludeEdge:
    from_file: str
    to_file: Optional[str]
    site_node_id: int
    site_lineno: int
    kind: str
    resolution: str
    raw_repr: str
    dyn_glob_base: Optional[str] = None
    dyn_suffix: Optional[str] = None
    dyn_hole_node: Optional[int] = None


@dataclass
class FIG:
    files: list[FileNode]
    edges: list[IncludeEdge]

    def file_by_path(self, path: str) -> Optional[FileNode]:
        norm = _normpath(path)
        for f in self.files:
            if f.path == norm:
                return f
        candidates = [f for f in self.files
                      if f.path.endswith(norm) or f.path.endswith("/" + norm)]
        if len(candidates) == 1:
            return candidates[0]
        return None

    def file_by_funcid(self, funcid: int) -> Optional[FileNode]:
        for f in self.files:
            if f.funcid == funcid:
                return f
        return None

    def edges_into(self, target_path: str) -> list[IncludeEdge]:
        norm = _normpath(target_path)
        return [e for e in self.edges if e.to_file == norm]

    def transitive_includers(self, target_path: str) -> set[str]:
        f = self.file_by_path(target_path)
        norm = f.path if f else _normpath(target_path)
        visited: set[str] = set()
        frontier = [norm]
        while frontier:
            cur = frontier.pop()
            for e in self.edges_into(cur):
                if e.from_file and e.from_file not in visited:
                    visited.add(e.from_file)
                    frontier.append(e.from_file)
        return visited

    def dynamic_includers(self, target_path: str) -> list[tuple]:
        f = self.file_by_path(target_path)
        norm = f.path if f else _normpath(target_path)
        out: list[tuple] = []
        for e in self.edges:
            if e.resolution != "dynamic_glob" or not e.dyn_glob_base:
                continue
            base = e.dyn_glob_base
            suffix = e.dyn_suffix or ""
            if not norm.startswith(base):
                continue
            if suffix and not norm.endswith(suffix):
                continue
            middle = norm[len(base):len(norm) - len(suffix)] if suffix else norm[len(base):]
            if not middle or "/" in middle:
                continue
            out.append((e.from_file, e, middle))
        return out

    def to_dict(self) -> dict:
        return {
            "files": [asdict(f) for f in self.files],
            "edges": [asdict(e) for e in self.edges],
        }


_KIND_BY_FLAG = {
    "EXEC_INCLUDE":      "include",
    "EXEC_INCLUDE_ONCE": "include_once",
    "EXEC_REQUIRE":      "require",
    "EXEC_REQUIRE_ONCE": "require_once",
    "EXEC_EVAL":         "eval",
}


def build_fig(working_dir: str | Path) -> FIG:
    wd = Path(working_dir)
    nodes = _read_nodes(wd / "nodes.csv")
    parent2children = _read_rels(wd / "rels.csv")

    files: list[FileNode] = []
    funcid2path: dict[int, str] = {}
    for n in nodes.values():
        if n["type"] == "AST_TOPLEVEL" and n["flags"] == "TOPLEVEL_FILE":
            path = _normpath(n["name"])
            files.append(FileNode(funcid=int(n["id"]), path=path))
            funcid2path[int(n["id"])] = path

    _file_memo: dict[int, str] = dict(funcid2path)

    def _file_of(fid: int) -> str:
        chain: list[int] = []
        cur: Optional[int] = fid
        seen: set[int] = set()
        path = ""
        while cur is not None and cur not in seen:
            if cur in _file_memo:
                path = _file_memo[cur]
                break
            seen.add(cur)
            n = nodes.get(cur)
            if n is None:
                break
            if n.get("type") == "AST_TOPLEVEL" and n.get("flags") == "TOPLEVEL_FILE":
                path = _normpath(n.get("name", ""))
                _file_memo[cur] = path
                break
            chain.append(cur)
            try:
                cur = int(n.get("funcid"))
            except (TypeError, ValueError):
                break
        for c in chain:
            _file_memo[c] = path
        return path

    define_map = _build_define_map(nodes, parent2children, funcid2path)

    file_paths = frozenset(f.path for f in files)
    try:
        import os as _os
        project_root = _os.path.commonpath(list(file_paths)) if file_paths else ""
    except Exception:
        project_root = ""

    edges: list[IncludeEdge] = []
    for n in nodes.values():
        if n["type"] != "AST_INCLUDE_OR_EVAL":
            continue
        kind = _KIND_BY_FLAG.get(n["flags"], "include")
        from_path = _file_of(int(n["funcid"]))
        site_node_id = int(n["id"])
        site_lineno = int(n["lineno"]) if n["lineno"] else 0

        if kind == "eval":
            edges.append(IncludeEdge(
                from_file=from_path, to_file=None,
                site_node_id=site_node_id, site_lineno=site_lineno,
                kind=kind, resolution="eval", raw_repr="<eval>",
            ))
            continue

        children = parent2children.get(site_node_id, [])
        if not children:
            edges.append(IncludeEdge(
                from_file=from_path, to_file=None,
                site_node_id=site_node_id, site_lineno=site_lineno,
                kind=kind, resolution="dynamic_other", raw_repr="<no path expr>",
            ))
            continue
        path_expr_id = children[0]
        edges.append(_resolve_include(
            path_expr_id, from_path, site_node_id, site_lineno, kind,
            define_map, nodes, parent2children, file_paths, project_root,
        ))

    fig = FIG(files=files, edges=edges)
    _upgrade_opaque_dynamic_edges(fig, nodes, parent2children, define_map)
    return fig


def _upgrade_opaque_dynamic_edges(
    fig: FIG, nodes: dict, parent2children: dict, define_map: dict,
) -> None:
    try:
        from .interproc_include import build_func_index, recover_include_shape
    except Exception:
        return
    fidx = build_func_index(nodes, parent2children)
    for e in fig.edges:
        kids = parent2children.get(e.site_node_id, [])
        if not kids:
            continue
        operand = kids[0]
        on = nodes.get(operand)
        if not on or on.get("type") != "AST_VAR":
            continue
        site_node = nodes.get(e.site_node_id)
        try:
            includer_fid = int(site_node.get("funcid") or 0) if site_node else 0
        except (ValueError, TypeError):
            includer_fid = 0
        try:
            shape = recover_include_shape(
                operand, includer_fid, e.from_file,
                nodes, parent2children, fidx, define_map)
        except Exception:
            shape = None
        if shape is None:
            continue
        includer_dir = str(Path(e.from_file).parent).rstrip("/") if e.from_file else ""
        if not shape.suffix and shape.glob_base.rstrip("/") == includer_dir:
            continue
        e.resolution = "dynamic_glob"
        e.dyn_glob_base = shape.glob_base
        e.dyn_suffix = shape.suffix
        e.dyn_hole_node = shape.hole_node
        e.raw_repr = (e.raw_repr or "") + " [interproc]"


def _resolve_include(
    path_expr_id: int, from_path: str, site_node_id: int, site_lineno: int,
    kind: str, define_map: dict, nodes: dict, parent2children: dict,
    file_paths=frozenset(), project_root: str = "",
) -> IncludeEdge:
    segs = _flatten_concat(path_expr_id, from_path, define_map, nodes, parent2children)
    repr_str = _expr_repr(path_expr_id, nodes, parent2children)
    holes = [s for s in segs if s[0] == "hole"]

    if not holes and segs and all(s[0] == "str" for s in segs):
        folded = "".join(s[1] for s in segs)
        abs_path = folded if folded.startswith("/") else (
            _normpath(str(Path(from_path).parent / folded)) if from_path else _normpath(folded))
        return IncludeEdge(
            from_file=from_path, to_file=_normpath(abs_path),
            site_node_id=site_node_id, site_lineno=site_lineno,
            kind=kind, resolution="static", raw_repr=folded,
        )

    if len(holes) == 1:
        prefix = ""
        i = 0
        while i < len(segs) and segs[i][0] == "str":
            prefix += segs[i][1]; i += 1
        suffix = ""
        j = len(segs) - 1
        while j >= 0 and segs[j][0] == "str":
            suffix = segs[j][1] + suffix; j -= 1
        if i == j and segs[i][0] == "hole":
            glob_base = _pick_glob_base(from_path, prefix, file_paths, project_root)
            return IncludeEdge(
                from_file=from_path, to_file=None,
                site_node_id=site_node_id, site_lineno=site_lineno,
                kind=kind, resolution="dynamic_glob", raw_repr=repr_str,
                dyn_glob_base=glob_base, dyn_suffix=suffix,
                dyn_hole_node=segs[i][1],
            )

    label = "dynamic_var" if any(
        nodes.get(s[1], {}).get("type") in ("AST_VAR", "AST_DIM")
        for s in holes) else "dynamic_other"
    return IncludeEdge(
        from_file=from_path, to_file=None,
        site_node_id=site_node_id, site_lineno=site_lineno,
        kind=kind, resolution=label, raw_repr=repr_str,
    )


def _resolve_path_expr(
    node_id: int,
    includer_path: str,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
) -> tuple[Optional[str], str, str]:
    folded, repr_str = _fold(node_id, includer_path, nodes, parent2children)
    if folded is None:
        return None, repr_str, _expr_repr(node_id, nodes, parent2children)

    abs_path = folded if folded.startswith("/") else _normpath(
        str(Path(includer_path).parent / folded) if includer_path else folded
    )
    return _normpath(abs_path), "static", folded


def _fold(
    node_id: int,
    includer_path: str,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
) -> tuple[Optional[str], str]:
    n = nodes.get(node_id)
    if not n:
        return None, "dynamic_other"

    typ = n["type"]
    flags = n["flags"]
    code = n["code"]

    if typ == "string":
        return code, "static"

    if typ == "AST_MAGIC_CONST":
        if flags == "MAGIC_DIR":
            return str(Path(includer_path).parent) if includer_path else "", "static"
        if flags == "MAGIC_FILE":
            return includer_path or "", "static"
        return None, "dynamic_other"

    if typ == "AST_BINARY_OP" and flags == "BINARY_CONCAT":
        kids = parent2children.get(node_id, [])
        if len(kids) != 2:
            return None, "dynamic_other"
        lv, llabel = _fold(kids[0], includer_path, nodes, parent2children)
        rv, rlabel = _fold(kids[1], includer_path, nodes, parent2children)
        if lv is None or rv is None:
            return None, llabel if lv is None else rlabel
        return lv + rv, "static"

    if typ == "AST_VAR":
        return None, "dynamic_var"

    if typ in ("AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"):
        return None, "dynamic_call"

    return None, "dynamic_other"


def _expr_repr(
    node_id: int,
    nodes: dict[int, dict],
    parent2children: dict[int, list[int]],
    depth: int = 0,
) -> str:
    if depth > 5:
        return "..."
    n = nodes.get(node_id)
    if not n:
        return "?"
    typ = n["type"]
    if typ == "string":
        return f"'{n['code']}'"
    if typ == "AST_MAGIC_CONST":
        return n["flags"]
    if typ == "AST_VAR":
        kids = parent2children.get(node_id, [])
        if kids:
            cn = nodes.get(kids[0])
            if cn and cn["type"] == "string":
                return f"${cn['code']}"
        return "$?"
    if typ == "AST_BINARY_OP" and n["flags"] == "BINARY_CONCAT":
        kids = parent2children.get(node_id, [])
        if len(kids) == 2:
            return _expr_repr(kids[0], nodes, parent2children, depth+1) + " . " \
                 + _expr_repr(kids[1], nodes, parent2children, depth+1)
    if typ in ("AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"):
        return f"<{typ}>(...)"
    return f"<{typ}>"


def _build_define_map(
    nodes: dict, parent2children: dict, funcid2path: dict
) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for nid, n in nodes.items():
        if n["type"] != "AST_CALL":
            continue
        kids = parent2children.get(nid, [])
        name = None
        arglist = None
        for c in kids:
            cn = nodes.get(c)
            if not cn:
                continue
            if cn["type"] == "AST_NAME":
                for cc in parent2children.get(c, []):
                    ccn = nodes.get(cc)
                    if ccn and ccn["type"] == "string":
                        name = ccn["code"]
            elif cn["type"] == "AST_ARG_LIST":
                arglist = c
        if (name or "").lower() != "define" or arglist is None:
            continue
        args = sorted(parent2children.get(arglist, []),
                      key=lambda x: int(nodes.get(x, {}).get("childnum") or 0))
        if len(args) < 2:
            continue
        a0, a1 = nodes.get(args[0]), nodes.get(args[1])
        if not (a0 and a1 and a0["type"] == "string" and a1["type"] == "string"):
            continue
        const_name = a0["code"]
        const_val = a1["code"]
        deffile = funcid2path.get(int(n["funcid"] or 0), "")
        out.setdefault(const_name, {})[deffile] = const_val
    return out


def _const_value(
    const_node_id: int, includer_path: str, define_map: dict,
    nodes: dict, parent2children: dict,
) -> Optional[str]:
    n = nodes.get(const_node_id)
    if not n or n["type"] != "AST_CONST":
        return None
    cname = None
    for c in parent2children.get(const_node_id, []):
        cn = nodes.get(c)
        if cn and cn["type"] == "AST_NAME":
            for cc in parent2children.get(c, []):
                ccn = nodes.get(cc)
                if ccn and ccn["type"] == "string":
                    cname = ccn["code"]
    if cname is None:
        return None
    d = define_map.get(cname, {})
    if includer_path in d:
        return d[includer_path]
    vals = set(d.values())
    if len(vals) == 1:
        return next(iter(vals))
    return None


def _flatten_concat(
    node_id: int, includer_path: str, define_map: dict,
    nodes: dict, parent2children: dict,
) -> list[tuple]:
    n = nodes.get(node_id)
    if not n:
        return [("hole", node_id)]
    typ = n["type"]
    if typ == "AST_BINARY_OP" and n["flags"] == "BINARY_CONCAT":
        kids = parent2children.get(node_id, [])
        kids = sorted(kids, key=lambda x: int(nodes.get(x, {}).get("childnum") or 0))
        out: list[tuple] = []
        for k in kids:
            out.extend(_flatten_concat(k, includer_path, define_map, nodes, parent2children))
        return out
    if typ == "AST_ENCAPS_LIST":
        kids = parent2children.get(node_id, [])
        kids = sorted(kids, key=lambda x: int(nodes.get(x, {}).get("childnum") or 0))
        out: list[tuple] = []
        for k in kids:
            out.extend(_flatten_concat(k, includer_path, define_map, nodes, parent2children))
        return out
    if typ == "string":
        return [("str", n["code"])]
    if typ == "AST_MAGIC_CONST":
        if n["flags"] == "MAGIC_DIR":
            return [("str", str(Path(includer_path).parent) if includer_path else "")]
        if n["flags"] == "MAGIC_FILE":
            return [("str", includer_path or "")]
        return [("hole", node_id)]
    if typ == "AST_CONST":
        v = _const_value(node_id, includer_path, define_map, nodes, parent2children)
        return [("str", v)] if v is not None else [("hole", node_id)]
    return [("hole", node_id)]


def _resolve_prefix_against(base_dir: str, prefix: str) -> str:
    if prefix.startswith("/"):
        raw = prefix
    elif base_dir:
        raw = base_dir.rstrip("/") + "/" + prefix
    else:
        raw = prefix
    if "/" in raw:
        dpart, tail = raw.rsplit("/", 1)
        import os as _os
        return _os.path.normpath(dpart) + "/" + tail
    return raw


def _resolve_rel_prefix(includer_path: str, prefix: str) -> str:
    base = str(Path(includer_path).parent) if includer_path else ""
    return _resolve_prefix_against(base, prefix)


def _pick_glob_base(from_path: str, prefix: str,
                    file_paths, project_root: str) -> str:
    base1 = _resolve_rel_prefix(from_path, prefix)
    if prefix.startswith("/"):
        return base1
    if any(p.startswith(base1) for p in file_paths):
        return base1
    if project_root:
        base2 = _resolve_prefix_against(project_root.rstrip("/"), prefix)
        if any(p.startswith(base2) for p in file_paths):
            return base2
    return base1


def _split_tsv_quote_aware(line: str) -> list[str]:
    fields: list[str] = []
    buf: list[str] = []
    in_q = False
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if in_q:
            if c == "\\" and i + 1 < n:
                buf.append(c)
                buf.append(line[i + 1])
                i += 2
                continue
            buf.append(c)
            if c == '"':
                in_q = False
            i += 1
            continue
        if c == "\t":
            fields.append("".join(buf))
            buf = []
            i += 1
            continue
        if c == '"' and not buf:
            in_q = True
        buf.append(c)
        i += 1
    fields.append("".join(buf))
    return fields


def _read_nodes(path: Path) -> dict[int, dict]:
    rename = {
        "id:int": "id",
        "labels:label": "labels",
        "type": "type",
        "flags:string_array": "flags",
        "lineno:int": "lineno",
        "code": "code",
        "childnum:int": "childnum",
        "funcid:int": "funcid",
        "classname": "classname",
        "namespace": "namespace",
        "endlineno:int": "endlineno",
        "name": "name",
        "doccomment": "doccomment",
    }

    def _unq(s: str) -> str:
        return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s

    out: dict[int, dict] = {}
    with path.open("r", encoding="utf-8", errors="replace") as f:
        header = f.readline().rstrip("\r\n")
        if not header:
            return out
        cols = [rename.get(h, h) for h in header.split("\t")]
        ncols = len(cols)
        try:
            code_idx = cols.index("code")
        except ValueError:
            code_idx = -1
        n_after = (ncols - code_idx - 1) if code_idx >= 0 else 0
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            parts = _split_tsv_quote_aware(line)
            if len(parts) != ncols:
                parts = line.split("\t")
                if len(parts) < ncols:
                    continue
                if len(parts) > ncols and code_idx >= 0:
                    code = "\t".join(parts[code_idx:len(parts) - n_after])
                    parts = (parts[:code_idx] + [code]
                             + (parts[len(parts) - n_after:] if n_after else []))
            row = {c: _unq(v) for c, v in zip(cols, parts)}
            try:
                nid = int(row["id"])
            except (ValueError, KeyError):
                continue
            out[nid] = row
    return out


def _read_rels(path: Path) -> dict[int, list[int]]:
    out: dict[int, list[int]] = defaultdict(list)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f, delimiter="\t")
        first = next(reader, None)
        if first and first[0].isdigit():
            try:
                out[int(first[0])].append(int(first[1]))
            except (ValueError, IndexError):
                pass
        for row in reader:
            if not row or len(row) < 2:
                continue
            try:
                p, c = int(row[0]), int(row[1])
            except ValueError:
                continue
            out[p].append(c)
    return out


def _normpath(p: str) -> str:
    if not p:
        return ""
    p = p.strip().strip('"').strip("'")
    return str(Path(p).resolve()) if p.startswith("/") else str(Path(p))


def _main():
    import argparse
    ap = argparse.ArgumentParser(description="Build a File Include Graph from TChecker output.")
    ap.add_argument("-w", "--working-dir", required=True,
                    help="Directory with nodes.csv + rels.csv")
    ap.add_argument("-o", "--out", default="-",
                    help="Output JSON file path (default '-' = stdout)")
    args = ap.parse_args()

    fig = build_fig(args.working_dir)
    payload = fig.to_dict()
    text = json.dumps(payload, indent=2, ensure_ascii=False)

    n_files = len(fig.files)
    n_static = sum(1 for e in fig.edges if e.resolution == "static")
    n_dyn = len(fig.edges) - n_static
    summary = (
        f"# FIG: {n_files} files, {len(fig.edges)} edges "
        f"({n_static} static, {n_dyn} dynamic)\n"
    )

    if args.out == "-":
        print(summary + text)
    else:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(summary + f"# wrote {args.out}")


if __name__ == "__main__":
    _main()
