
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


_EXIT_LIKE_TYPES = {"AST_EXIT", "AST_THROW"}

_FUNC_LIKE_TYPES = {"AST_FUNC_DECL", "AST_CLOSURE", "AST_METHOD"}


@dataclass
class BodyRangeInfo:
    body_start: Optional[int] = None
    body_end:   Optional[int] = None
    body_has_exit: bool = False


@dataclass
class BodyRangeResolver:
    working_dir: Path
    in_scope_files: set[str]

    _funcid_to_file: dict[int, str] = field(default_factory=dict)
    _in_scope_funcids: set[int] = field(default_factory=set)
    _ifelem_index: dict[tuple[str, int], BodyRangeInfo] = field(default_factory=dict)
    _dispatch_lines_by_file: dict[str, set[int]] = field(default_factory=dict)
    _built: bool = False

    def lookup(self, file_path: str, ifelem_lineno: int) -> Optional[BodyRangeInfo]:
        if not self._built:
            self._build()
        return self._ifelem_index.get((file_path, ifelem_lineno))

    def body_contains_dispatch(self, file_path: str, body_start: int,
                                body_end: int) -> bool:
        if not self._built:
            self._build()
        lines = self._dispatch_lines_by_file.get(file_path, set())
        if not lines:
            return False
        return any(body_start <= ln <= body_end for ln in lines)


    def _build(self) -> None:
        self._built = True

        wd = Path(self.working_dir)
        nodes_csv = wd / "nodes.csv"
        rels_csv  = wd / "rels.csv"
        if not nodes_csv.is_file() or not rels_csv.is_file():
            return

        topl: dict[int, str]  = {}
        func_parent: dict[int, int] = {}

        with nodes_csv.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh, delimiter="\t")
            header = next(reader, None)
            cols = {name: i for i, name in enumerate(header or [])}
            i_id     = cols.get("id:int",    0)
            i_flags  = cols.get("flags:string_array", 3)
            i_type   = cols.get("type",      2)
            i_lineno = cols.get("lineno:int", 4)
            i_funcid = cols.get("funcid:int", 7)
            i_name   = cols.get("name",     11)
            for row in reader:
                if len(row) <= i_name:
                    continue
                nt = row[i_type]
                if nt == "AST_TOPLEVEL":
                    try:
                        nid = int(row[i_id])
                    except ValueError:
                        continue
                    flag = row[i_flags] if len(row) > i_flags else ""
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
                elif nt in _FUNC_LIKE_TYPES:
                    try:
                        nid = int(row[i_id])
                        fid = int(row[i_funcid] or 0)
                    except ValueError:
                        continue
                    if fid:
                        func_parent[nid] = fid

        for fid in list(topl):
            self._funcid_to_file[fid] = topl[fid]
        for fid in list(func_parent):
            cur = fid
            seen = set()
            while cur in func_parent and cur not in seen:
                seen.add(cur)
                cur = func_parent[cur]
            if cur in topl:
                self._funcid_to_file[fid] = topl[cur]

        self._in_scope_funcids = {
            fid for fid, f in self._funcid_to_file.items()
            if f in self.in_scope_files
        }

        ifelem_meta: dict[int, tuple[str, int]] = {}
        node_lineno: dict[int, int] = {}
        node_type:   dict[int, str] = {}
        node_file:   dict[int, str] = {}

        with nodes_csv.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh, delimiter="\t")
            next(reader, None)
            for row in reader:
                if len(row) <= max(i_id, i_type, i_lineno, i_funcid):
                    continue
                try:
                    fid = int(row[i_funcid] or 0)
                    nid = int(row[i_id])
                except ValueError:
                    continue
                in_scope = fid in self._in_scope_funcids or nid in self._in_scope_funcids
                if not in_scope:
                    continue
                try:
                    ln = int(row[i_lineno] or 0)
                except ValueError:
                    ln = 0
                nt = row[i_type]
                node_lineno[nid] = ln
                node_type[nid]   = nt
                fp = self._funcid_to_file.get(fid) or self._funcid_to_file.get(nid, "")
                if fp:
                    node_file[nid] = fp
                if nt == "AST_IF_ELEM" and fp:
                    ifelem_meta[nid] = (fp, ln)

        children_of: dict[int, list[int]] = {}
        with rels_csv.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh, delimiter="\t")
            next(reader, None)
            for row in reader:
                if len(row) < 3 or row[2] != "PARENT_OF":
                    continue
                try:
                    s = int(row[0]); e = int(row[1])
                except ValueError:
                    continue
                if s in node_lineno and e in node_lineno:
                    children_of.setdefault(s, []).append(e)

        for ifelem_id, (fp, ln) in ifelem_meta.items():
            stmt_list = None
            for c in children_of.get(ifelem_id, []):
                if node_type.get(c) == "AST_STMT_LIST":
                    stmt_list = c
                    break
            if stmt_list is None:
                self._ifelem_index[(fp, ln)] = BodyRangeInfo()
                continue

            stack = [stmt_list]
            seen = {stmt_list}
            min_ln, max_ln = None, None
            has_exit = False
            while stack:
                cur = stack.pop()
                cur_ln = node_lineno.get(cur, 0)
                cur_ty = node_type.get(cur, "")
                if cur_ln:
                    if min_ln is None or cur_ln < min_ln:
                        min_ln = cur_ln
                    if max_ln is None or cur_ln > max_ln:
                        max_ln = cur_ln
                if cur_ty in _EXIT_LIKE_TYPES:
                    has_exit = True
                for child in children_of.get(cur, []):
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)

            self._ifelem_index[(fp, ln)] = BodyRangeInfo(
                body_start=min_ln,
                body_end=max_ln,
                body_has_exit=has_exit,
            )

        ds_csv = wd / "dispatch_sinks.csv"
        if ds_csv.is_file():
            with ds_csv.open(newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    try:
                        sid = int(row["site_id"])
                    except (KeyError, ValueError, TypeError):
                        continue
                    ln = node_lineno.get(sid)
                    fp = node_file.get(sid)
                    if not ln or not fp:
                        continue
                    self._dispatch_lines_by_file.setdefault(fp, set()).add(ln)


def build_resolver_for_sink(
    working_dir: Path,
    sink_file: str,
    fig,
) -> BodyRangeResolver:
    in_scope = {sink_file}
    try:
        in_scope |= set(fig.transitive_includers(sink_file))
    except Exception:
        pass
    return BodyRangeResolver(working_dir=Path(working_dir),
                              in_scope_files=in_scope)
