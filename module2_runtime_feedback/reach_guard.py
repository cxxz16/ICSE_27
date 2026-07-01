from __future__ import annotations

import csv
import os


class CpgIndex:

    def __init__(self, nodes_csv, rels_csv):
        self.node: dict = {}
        self.kids: dict = {}
        self._toplevel_file: dict = {}
        self._file_cache: dict = {}
        self._load(nodes_csv, rels_csv)

    def _load(self, nodes_csv, rels_csv):
        with open(nodes_csv, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f, delimiter="\t"):
                try:
                    nid = int(row["id:int"])
                except (ValueError, KeyError, TypeError):
                    continue

                def _int(col):
                    v = row.get(col, "")
                    try:
                        return int(v)
                    except (ValueError, TypeError):
                        return -1
                self.node[nid] = {
                    "type": row.get("type", ""),
                    "lineno": _int("lineno:int"),
                    "childnum": _int("childnum:int"),
                    "endlineno": _int("endlineno:int"),
                    "code": (row.get("code") or ""),
                    "funcid": _int("funcid:int"),
                    "name": (row.get("name") or "").strip('"'),
                }
                if self.node[nid]["type"] == "AST_TOPLEVEL":
                    self._toplevel_file[nid] = os.path.basename(self.node[nid]["name"])
        with open(rels_csv, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f, delimiter="\t"):
                if row.get("type") != "PARENT_OF":
                    continue
                try:
                    self.kids.setdefault(int(row["start"]), []).append(int(row["end"]))
                except (ValueError, KeyError, TypeError):
                    continue

    def _file_of(self, nid):
        if nid in self._file_cache:
            return self._file_cache[nid]
        fid = nid
        seen = set()
        out = None
        while fid in self.node and fid not in seen:
            seen.add(fid)
            if fid in self._toplevel_file:
                out = self._toplevel_file[fid]
                break
            fid = self.node[fid]["funcid"]
        self._file_cache[nid] = out
        return out

    def _stmt_list_first_line(self, stmt_list_id):
        kids = self.kids.get(stmt_list_id, [])
        if not kids:
            return self.node[stmt_list_id]["lineno"] or None
        first = min(kids, key=lambda k: self.node[k]["childnum"])
        return self.node[first]["lineno"] or None

    def _elem_body_line(self, elem_id):
        for k in self.kids.get(elem_id, []):
            if self.node[k]["type"] == "AST_STMT_LIST":
                return self._stmt_list_first_line(k)
        return None

    def guard_then_else_lines(self, guard_line, guard_basename=None):
        cand = [nid for nid, n in self.node.items()
                if n["type"] == "AST_IF" and n["lineno"] == guard_line
                and (guard_basename is None or self._file_of(nid) == guard_basename)]
        if not cand:
            return None
        if_id = cand[0]
        elems = sorted([k for k in self.kids.get(if_id, [])
                        if self.node[k]["type"] == "AST_IF_ELEM"],
                       key=lambda k: self.node[k]["childnum"])
        if not elems:
            return None
        then_line = self._elem_body_line(elems[0])
        if len(elems) > 1:
            else_line = self._elem_body_line(elems[1])
        else:
            end = self.node[if_id]["endlineno"]
            else_line = (end + 1) if end and end > 0 else None
        guard_code = (self.node[if_id]["code"]
                      or (self.node[elems[0]]["code"] if elems else "")).strip()
        return {"then_line": then_line, "else_line": else_line,
                "guard_code": guard_code, "if_node": if_id}


def guard_branch_target(guard_file, guard_line, cpg_index, distance_table,
                        file_key=None):
    bn = os.path.basename(guard_file or "")
    dk = file_key(guard_file or "") if file_key else bn
    info = cpg_index.guard_then_else_lines(guard_line, bn)
    if not info:
        return None
    tl, el = info["then_line"], info["else_line"]
    then_dist = distance_table.get((dk, tl)) if tl else None
    else_dist = distance_table.get((dk, el)) if el else None
    if then_dist is None and else_dist is None:
        return None
    want_true = (else_dist is None) or (then_dist is not None and then_dist <= else_dist)
    return {"want_true": want_true, "then_dist": then_dist, "else_dist": else_dist,
            "then_line": tl, "else_line": el, "guard_code": info["guard_code"]}


def target_from_lookahead(guard_file, guard_line, predicate_lookahead):
    bn = os.path.basename(guard_file or "")
    for pl in (predicate_lookahead or []):
        try:
            if int(pl.get("line", -1)) != int(guard_line):
                continue
        except (ValueError, TypeError):
            continue
        if os.path.basename(pl.get("file", "")) != bn:
            continue
        td, fd = pl.get("then_dist"), pl.get("false_dist")
        if td is None and fd is None:
            return None
        want_true = (fd is None) or (td is not None and td <= fd)
        return {"want_true": want_true, "then_dist": td, "else_dist": fd,
                "then_line": None, "else_line": None,
                "guard_code": (pl.get("raw_line") or "").strip()}
    return None


def resolve_guard_target(guard_file, guard_line, predicate_lookahead,
                         cpg_index, distance_table, file_key=None):
    hit = target_from_lookahead(guard_file, guard_line, predicate_lookahead)
    if hit is not None:
        hit["source"] = "lookahead"
        return hit
    if cpg_index and distance_table:
        hit = guard_branch_target(guard_file, guard_line, cpg_index,
                                  distance_table, file_key=file_key)
        if hit is not None:
            hit["source"] = "cpg"
            return hit
    return None


if __name__ == "__main__":
    import sys
    nodes = sys.argv[1] if len(sys.argv) > 1 else "/home/user/research/Predator/nodes.csv"
    rels = sys.argv[2] if len(sys.argv) > 2 else "/home/user/research/Predator/rels.csv"
    idx = CpgIndex(nodes, rels)
    n_if = sum(1 for n in idx.node.values() if n["type"] == "AST_IF")
    print(f"loaded {len(idx.node)} nodes, {n_if} AST_IF, TOPLEVEL->file: {idx._toplevel_file}")
    shown = 0
    for nid, n in sorted(idx.node.items()):
        if n["type"] != "AST_IF":
            continue
        info = idx.guard_then_else_lines(n["lineno"], idx._file_of(nid))
        if info:
            print(f"  AST_IF#{nid} @line {n['lineno']} (file={idx._file_of(nid)}) "
                  f"→ then_line={info['then_line']} else_line={info['else_line']} "
                  f"code={info['guard_code'][:50]!r}")
            shown += 1
        if shown >= 8:
            break
    assert n_if > 0, "expected at least one AST_IF"
    print("✓ CPG AST traversal: can locate AST_IF and extract then/else first lines")
