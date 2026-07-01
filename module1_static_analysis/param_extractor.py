
import re
import os
import csv
import json
import argparse
from collections import deque
from pathlib import Path
from typing import Optional


_INCLUDE_MAX_DEPTH = 2
_INCLUDE_MAX_FILES = 15


def _read_dist_lines(instr_info_csv: str) -> list[dict]:
    nodes = []
    with open(instr_info_csv) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            if row['type'] in ('d', 'e'):
                nodes.append({
                    'lineno': int(row['lineno']),
                    'dist':   float(row['value']),
                })
    return sorted(nodes, key=lambda x: -x['dist'])


def _read_source(php_file: str) -> list[str]:
    with open(php_file, encoding='utf-8', errors='replace') as f:
        return f.readlines()


def _get_line(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ''


IF_PAT = re.compile(
    r'^\s*(?:if|else\s*if|elseif)\s*\((.+)\)',
    re.IGNORECASE
)

SWITCH_PAT = re.compile(
    r'^\s*switch\s*\((.+)\)\s*\{?\s*$',
    re.IGNORECASE
)
CASE_LITERAL_PAT = re.compile(
    r"""^\s*case\s+(?P<q>['"])(?P<val>[^'"]+)(?P=q)\s*:""",
    re.IGNORECASE
)

_REQUEST_VAR_PAT = re.compile(
    r'\$_(REQUEST|GET|POST|COOKIE)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]')

_FILTER_INPUT_PAT = re.compile(
    r"filter_input\s*\(\s*INPUT_(GET|POST|COOKIE)\s*,\s*[\'\"]([^\'\"]+)[\'\"]")


_ALIAS_FROM_INPUT = re.compile(
    r"\$(\w+)\s*=\s*"
    r"(?:\([^)]+\)\s*)?"
    r"(?:\(\s*)?"
    r"\$(?:_(?:REQUEST|POST|GET|COOKIE)|params)"
    r"\s*\[\s*['\"]([\w.-]+)['\"]\s*\]"
)
_ALIAS_FROM_FILTER_INPUT = re.compile(
    r"\$(\w+)\s*=\s*"
    r"(?:\([^)]*\)\s*)?"
    r"(?:\w+\s*\(\s*)*"
    r"filter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE)\s*,\s*['\"]([\w.-]+)['\"]"
)
_LOCAL_VAR_REF = re.compile(r"\$(?!\_(?:REQUEST|POST|GET|COOKIE)\b)(\w+)")


_INPUT_WRAPPER_VAR_PATS: list[tuple] = []
_INPUT_WRAPPER_ALIAS_PATS: list[tuple] = []
_INPUT_WRAPPER_METHODS: list[tuple] = []


def _load_input_sources(framework: Optional[str]) -> None:
    global _INPUT_WRAPPER_VAR_PATS, _INPUT_WRAPPER_ALIAS_PATS, _INPUT_WRAPPER_METHODS
    _INPUT_WRAPPER_VAR_PATS = []
    _INPUT_WRAPPER_ALIAS_PATS = []
    _INPUT_WRAPPER_METHODS = []
    if not framework:
        return
    knowledge_dir = Path(__file__).parent / "framework_routing" / "knowledge"
    yaml_path = knowledge_dir / f"{framework}.yaml"
    if not yaml_path.exists():
        return
    try:
        import yaml
        with yaml_path.open("r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception:
        return
    for entry in (doc.get("input_sources") or []):
        matcher = entry.get("matcher") or ""
        sup = (entry.get("superglobal") or "REQUEST").upper()
        if sup not in ("GET", "POST", "REQUEST", "COOKIE"):
            sup = "REQUEST"
        try:
            var_pat = re.compile(matcher)
        except re.error:
            continue
        if "key" not in var_pat.groupindex:
            continue
        _INPUT_WRAPPER_VAR_PATS.append((var_pat, sup))
        _flat = matcher.replace(r"\s*", "").replace("\\", "")
        _accs = re.findall(r"->(\w+)", _flat)
        if _accs:
            _method = _accs[-1]
            _objp = _accs[-2] if len(_accs) >= 2 and _accs[-2] != "this" else None
            _INPUT_WRAPPER_METHODS.append((_objp, _method, sup))
        alias_src = (
            r"\$(\w+)\s*=\s*"
            r"(?:\([^)]+\)\s*)?"
            r"(?:\(\s*)?"
            + matcher
        )
        try:
            _INPUT_WRAPPER_ALIAS_PATS.append((re.compile(alias_src), sup))
        except re.error:
            continue


def _scan_inputs(text: str) -> list[tuple]:
    pairs: list[tuple] = list(_REQUEST_VAR_PAT.findall(text))
    pairs.extend(_FILTER_INPUT_PAT.findall(text))
    for pat, sup in _INPUT_WRAPPER_VAR_PATS:
        for m in pat.finditer(text):
            key = m.group("key")
            if key:
                pairs.append((sup, key))
    return pairs


def _build_alias_map(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        for m in _ALIAS_FROM_INPUT.finditer(line):
            local, key = m.group(1), m.group(2)
            out.setdefault(local, key)
        for m in _ALIAS_FROM_FILTER_INPUT.finditer(line):
            local, key = m.group(1), m.group(2)
            out.setdefault(local, key)
        for pat, _sup in _INPUT_WRAPPER_ALIAS_PATS:
            for m in pat.finditer(line):
                local = m.group(1)
                key = m.group("key") if "key" in pat.groupindex else None
                if local and key:
                    out.setdefault(local, key)
    return out


_EQ_SUPER_LIT = re.compile(
    r"""\$_(?:REQUEST|POST|GET|COOKIE)\s*\[\s*['"]([^'"]+)['"]\s*\]"""
    r"""\s*(?<![!<>=])==(=)?\s*['"]([^'"]+)['"]""")
_EQ_LIT_SUPER = re.compile(
    r"""['"]([^'"]+)['"]\s*(?<![!<>=])==(=)?\s*"""
    r"""\$_(?:REQUEST|POST|GET|COOKIE)\s*\[\s*['"]([^'"]+)['"]\s*\]""")
_EQ_VAR_LIT = re.compile(
    r"""\$([A-Za-z_]\w*)\s*(?<![!<>=])==(=)?\s*['"]([^'"]+)['"]""")
_EQ_LIT_VAR = re.compile(
    r"""['"]([^'"]+)['"]\s*(?<![!<>=])==(=)?\s*\$([A-Za-z_]\w*)""")


_IMPLODE_SEP = r"""(?:'[^']*'|"[^"]*"|[^,()]*)"""
_IMPLODE_VARARG = re.compile(
    rf"""implode\s*\(\s*{_IMPLODE_SEP}\s*,\s*\$([A-Za-z_]\w*)\s*\)""")
_IMPLODE_SUPER = re.compile(
    rf"""implode\s*\(\s*{_IMPLODE_SEP}\s*,\s*"""
    r"""\$_(?:POST|GET|REQUEST|COOKIE)\s*\[\s*['"]([^'"]+)['"]\s*\]\s*\)""")


def _detect_array_params(lines: list, alias_map: dict) -> set:
    out: set = set()
    for line in lines:
        for m in _IMPLODE_SUPER.finditer(line):
            out.add(m.group(1))
        for m in _IMPLODE_VARARG.finditer(line):
            key = alias_map.get(m.group(1))
            if key:
                out.add(key)
    return out


def _extract_eq_values(condition: str, alias_map: dict) -> dict:
    out: dict = {}
    if not condition:
        return out
    for m in _EQ_SUPER_LIT.finditer(condition):
        out.setdefault(m.group(1), m.group(3))
    for m in _EQ_LIT_SUPER.finditer(condition):
        out.setdefault(m.group(3), m.group(1))
    for m in _EQ_VAR_LIT.finditer(condition):
        key = alias_map.get(m.group(1))
        if key:
            out.setdefault(key, m.group(3))
    for m in _EQ_LIT_VAR.finditer(condition):
        key = alias_map.get(m.group(3))
        if key:
            out.setdefault(key, m.group(1))
    return out


def _extract_if_constraints(lines: list[str], dist_nodes: list[dict],
                              body_resolver=None, source_file: str = "",
                              working_dir: Optional[str] = None) -> list[dict]:
    constraints = []
    alias_map = _build_alias_map(lines)
    for node in dist_nodes:
        line_text = _get_line(lines, node['lineno'])
        stripped = re.sub(r'^\}\s*', '', line_text)
        m = IF_PAT.match(stripped)
        if not m:
            continue
        condition = m.group(1).strip()
        pairs = _scan_inputs(line_text)
        param_set: list[str] = [name for _sup, name in pairs]
        param_src: dict[str, str] = {name: sup for sup, name in pairs}
        for local in _LOCAL_VAR_REF.findall(condition):
            key = alias_map.get(local)
            if key and key not in param_set:
                param_set.append(key)
                param_src.setdefault(key, 'REQUEST')
        if working_dir and source_file:
            try:
                from module1_static_analysis.dispatch_resolver import superglobal_keys_reaching_line
                for k in superglobal_keys_reaching_line(
                        source_file, node['lineno'], working_dir):
                    if k not in param_set:
                        param_set.append(k)
                        param_src.setdefault(k, 'REQUEST')
            except Exception:
                pass
        c = {
            'lineno':    node['lineno'],
            'dist':      node['dist'],
            'condition': condition,
            'params':    param_set,
            'param_sources': param_src,
            'eq_values': _extract_eq_values(condition, alias_map),
            'raw_line':  line_text,
        }
        if source_file:
            c['source_file'] = source_file
        if body_resolver is not None and source_file:
            info = body_resolver.lookup(source_file, node['lineno'])
            if info is not None:
                c['body_start']    = info.body_start
                c['body_end']      = info.body_end
                c['body_has_exit'] = info.body_has_exit
                if info.body_start and info.body_end:
                    c['body_contains_dispatch'] = body_resolver.body_contains_dispatch(
                        source_file, info.body_start, info.body_end)
                else:
                    c['body_contains_dispatch'] = False
        if not param_set:
            continue
        constraints.append(c)
    seen: dict[tuple, dict] = {}
    for c in constraints:
        key = (c['lineno'], c['condition'])
        if key not in seen or c['dist'] < seen[key]['dist']:
            seen[key] = c
    return sorted(seen.values(), key=lambda c: c['dist'])


_INCLUDE_RE = re.compile(
    r"^\s*(?:include|include_once|require|require_once)\s*"
    r"\(?\s*['\"]([^'\"]+)['\"]\s*\)?\s*;",
    re.IGNORECASE | re.MULTILINE,
)

_DIE_LIKE_RE = re.compile(r"\b(die|exit|throw)\b")


def _resolve_include_path(include_arg: str, current_file: Path,
                           project_root: Path) -> Optional[Path]:
    if not include_arg:
        return None
    candidate = (current_file.parent / include_arg).resolve()
    try:
        candidate.relative_to(project_root.resolve())
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def _collect_included_files(sink_file: Path, project_root: Path,
                             *, max_depth: int = _INCLUDE_MAX_DEPTH,
                             max_files: int = _INCLUDE_MAX_FILES,
                             extra_seeds: Optional[list] = None,
                             ) -> list[Path]:
    seeds = [sink_file.resolve()]
    for s in (extra_seeds or []):
        try:
            seeds.append(Path(s).resolve())
        except (TypeError, OSError):
            pass
    visited: set[Path] = set(seeds)
    out: list[Path] = []
    queue: deque[tuple[Path, int]] = deque((s, 0) for s in seeds)
    while queue and len(out) < max_files:
        cur, depth = queue.popleft()
        if depth >= max_depth:
            continue
        try:
            text = cur.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _INCLUDE_RE.finditer(text):
            inc_path = _resolve_include_path(m.group(1), cur, project_root)
            if inc_path is None or inc_path in visited:
                continue
            visited.add(inc_path)
            out.append(inc_path)
            queue.append((inc_path, depth + 1))
            if len(out) >= max_files:
                break
    return out


def _extract_if_constraints_in_file(
    file: Path, body_resolver=None,
    working_dir: Optional[str] = None,
    require_die: bool = True,
    allowed_lines: Optional[set] = None,
    switch_case_dom: Optional[dict] = None,
) -> list[dict]:
    try:
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    file_str = str(file)
    alias_map = _build_alias_map(lines)

    def _cpg_keys(lineno: int) -> set[str]:
        if not working_dir:
            return set()
        try:
            from module1_static_analysis.dispatch_resolver import superglobal_keys_reaching_line
            return superglobal_keys_reaching_line(file_str, lineno, working_dir)
        except Exception:
            return set()

    def _emit_entry(lineno: int, line_text: str, condition: str,
                    extra_params: Optional[list] = None,
                    extra_param_sources: Optional[dict] = None) -> Optional[dict]:
        if allowed_lines is not None and lineno not in allowed_lines:
            return None
        pairs = _scan_inputs(line_text)
        alias_keys: list[str] = []
        for local in _LOCAL_VAR_REF.findall(condition):
            key = alias_map.get(local)
            if key:
                alias_keys.append(key)
        cpg_keys = _cpg_keys(lineno)
        existing = {n for _sup, n in pairs} | set(alias_keys)
        merged = [n for _sup, n in pairs] + \
                 [k for k in alias_keys if k not in {n for _sup, n in pairs}] + \
                 [k for k in cpg_keys if k not in existing] + \
                 [k for k in (extra_params or []) if k not in existing and k not in cpg_keys]
        if not merged:
            return None
        ps = {name: sup for sup, name in pairs}
        for k in alias_keys:
            ps.setdefault(k, 'REQUEST')
        for k in cpg_keys:
            ps.setdefault(k, 'REQUEST')
        for k, v in (extra_param_sources or {}).items():
            ps.setdefault(k, v)
        return {
            'lineno':       lineno,
            'dist':         -1.0,
            'condition':    condition,
            'params':       merged,
            'param_sources': ps,
            'eq_values':    _extract_eq_values(condition, alias_map),
            'raw_line':     line_text.strip(),
            'source_file':  file_str,
        }

    out: list[dict] = []
    i = 0
    while i < len(lines):
        i += 1
        line = lines[i - 1]
        stripped = re.sub(r'^\}\s*', '', line)
        sm = SWITCH_PAT.match(stripped)
        if sm:
            discriminant = sm.group(1).strip()
            depth = 0
            end_idx = len(lines)
            for j in range(i - 1, len(lines)):
                depth += lines[j].count('{') - lines[j].count('}')
                if j > i - 1 and depth <= 0:
                    end_idx = j + 1
                    break
            cases: list[str] = []
            for cj in range(i, end_idx):
                cm = CASE_LITERAL_PAT.match(lines[cj])
                if cm:
                    cases.append(cm.group('val'))
            wrapper_key_pat = re.compile(r"\w+\s*\(\s*['\"](\w+)['\"]")
            heuristic_keys = wrapper_key_pat.findall(discriminant)
            _dom_case = None
            if switch_case_dom is not None:
                _dom_case = switch_case_dom.get(i)
                if _dom_case is not None:
                    cases = [c for c in cases if c == _dom_case]
            for case_val in cases:
                synth = f"{discriminant} == '{case_val}'"
                entry = _emit_entry(
                    i, line, synth,
                    extra_params=heuristic_keys,
                    extra_param_sources={k: 'REQUEST' for k in heuristic_keys},
                )
                if entry is None:
                    continue
                entry['switch_case_value'] = case_val
                entry['switch_discriminant'] = discriminant
                if body_resolver is not None:
                    info = body_resolver.lookup(file_str, i)
                    if info is not None:
                        entry['body_start']    = info.body_start
                        entry['body_end']      = info.body_end
                        entry['body_has_exit'] = info.body_has_exit
                        entry['body_contains_dispatch'] = False
                out.append(entry)
            continue
        m = IF_PAT.match(stripped)
        if not m:
            continue
        condition = m.group(1).strip()
        if require_die:
            lookahead = "\n".join(lines[i: min(len(lines), i + 10)])
            if not _DIE_LIKE_RE.search(lookahead):
                continue
        entry = _emit_entry(i, line, condition)
        if entry is None:
            continue
        if body_resolver is not None:
            info = body_resolver.lookup(file_str, i)
            if info is not None:
                entry['body_start']    = info.body_start
                entry['body_end']      = info.body_end
                entry['body_has_exit'] = info.body_has_exit
                if info.body_start and info.body_end:
                    entry['body_contains_dispatch'] = body_resolver.body_contains_dispatch(
                        file_str, info.body_start, info.body_end)
                else:
                    entry['body_contains_dispatch'] = False
        out.append(entry)
    return out


ASSIGN_PAT = re.compile(
    r'^\s*\$(\w+)\s*=\s*(.+?)\s*;?\s*$'
)
REQUEST_RHS_PAT = re.compile(
    r'\$_(?:REQUEST|GET|POST|COOKIE)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]'
)

def _extract_assignments(lines: list[str]) -> dict:
    result = {}
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if '\$' in line or '$_REQUEST' not in line and '$_GET' not in line and '$_POST' not in line:
            pass
        rhs_keys = REQUEST_RHS_PAT.findall(line)
        if not rhs_keys:
            continue
        m = ASSIGN_PAT.match(line)
        if not m:
            continue
        lhs_var = m.group(1)
        rhs_expr = m.group(2).rstrip(';').strip()

        DIRECT_RHS = re.compile(
            r'^(?:\w+\()?'
            r'\$_(?:REQUEST|GET|POST|COOKIE)\['
        )
        if not DIRECT_RHS.match(rhs_expr):
            continue

        for k in rhs_keys:
            if k not in result:
                result[k] = {
                    'lhs_var':  lhs_var,
                    'rhs_expr': rhs_expr,
                    'lineno':   i,
                }
    return result


def _extract_exit_guards(lines: list[str], scan_lines: int = 120) -> list[dict]:
    guards = []
    i = 0
    while i < min(scan_lines, len(lines)):
        line = lines[i].strip()
        m = IF_PAT.match(line)
        if m:
            condition = m.group(1).strip()
            window = ' '.join(l.strip() for l in lines[i:i+4])
            if re.search(r'\b(exit|die)\s*[;(]', window):
                guards.append({
                    'lineno':    i + 1,
                    'condition': condition,
                    'raw_line':  line,
                    'note':      'must NOT satisfy this condition (leads to exit)',
                })
        i += 1
    return guards


_VIPER_INPUT_SUPERGLOBALS = {"_GET", "_POST", "_REQUEST", "_COOKIE"}

_VIPER_RELAY_SUPERGLOBALS = {"_SESSION", "GLOBALS"}

_VIPER_TAINT_MAX_RELAY_DEPTH = 4


def _viper_keyaware_backward_taint(
    working_dir: str,
    sink_file: str,
    sink_lineno: int,
    in_scope_files: Optional[set] = None,
) -> list[dict]:
    wd = Path(working_dir)
    nodes_csv = wd / "nodes.csv"
    rels_csv  = wd / "rels.csv"
    if not nodes_csv.is_file() or not rels_csv.is_file():
        return []

    nodes: dict[int, dict] = {}
    children: dict[int, list[int]] = {}
    funcid_to_file: dict[int, str] = {}
    file_to_toplevel: dict[str, int] = {}

    with nodes_csv.open(newline="", encoding="utf-8", errors="replace") as fh:
        header_line = fh.readline().rstrip("\r\n")
        header = header_line.split("\t") if header_line else []
        cols = {name: i for i, name in enumerate(header)}
        i_id     = cols.get("id:int", 0)
        i_type   = cols.get("type", 2)
        i_flags  = cols.get("flags:string_array", 3)
        i_lineno = cols.get("lineno:int", 4)
        i_code   = cols.get("code", 5)
        i_childnum = cols.get("childnum:int", 6)
        i_funcid = cols.get("funcid:int", 7)
        i_name   = cols.get("name", 11)
        ncols = len(header)
        n_after = (ncols - i_code - 1) if i_code >= 0 else 0

        def _unq(s):
            return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s

        rows_cache: list[list[str]] = []
        for line in fh:
            line = line.rstrip("\r\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < ncols:
                continue
            if len(parts) > ncols and i_code >= 0:
                code = "\t".join(parts[i_code:len(parts) - n_after])
                parts = (parts[:i_code] + [code]
                         + (parts[len(parts) - n_after:] if n_after else []))
            rows_cache.append([_unq(p) for p in parts])

    func_parent: dict[int, int] = {}
    funcid_to_name: dict[int, str] = {}
    for row in rows_cache:
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
                    file_to_toplevel[path] = nid
                    funcid_to_file[nid] = path
            else:
                try:
                    fid = int(row[i_funcid] or 0)
                    if fid:
                        func_parent[nid] = fid
                except ValueError:
                    pass
        elif nt in ("AST_FUNC_DECL", "AST_CLOSURE", "AST_METHOD"):
            try:
                nid = int(row[i_id])
                fid = int(row[i_funcid] or 0)
                if fid:
                    func_parent[nid] = fid
            except ValueError:
                pass
            if len(row) > i_name:
                _fname = row[i_name].strip().strip('"')
                if _fname:
                    try:
                        funcid_to_name[int(row[i_id])] = _fname
                    except ValueError:
                        pass

    for fid in list(func_parent):
        cur = fid
        seen = set()
        while cur in func_parent and cur not in seen:
            seen.add(cur)
            cur = func_parent[cur]
        if cur in funcid_to_file:
            funcid_to_file[fid] = funcid_to_file[cur]

    if in_scope_files is None:
        in_scope_funcids = set(funcid_to_file.keys())
    else:
        in_scope_funcids = {
            fid for fid, f in funcid_to_file.items() if f in in_scope_files
        }

    for row in rows_cache:
        if len(row) <= i_name:
            continue
        try:
            nid = int(row[i_id])
            fid = int(row[i_funcid] or 0)
        except ValueError:
            continue
        if fid not in in_scope_funcids and nid not in in_scope_funcids:
            continue
        try:
            ln = int(row[i_lineno] or 0)
        except ValueError:
            ln = 0
        nodes[nid] = {
            "type":     row[i_type],
            "lineno":   ln,
            "code":     row[i_code] if len(row) > i_code else "",
            "funcid":   fid,
            "childnum": int(row[i_childnum] or 0) if (len(row) > i_childnum and row[i_childnum].lstrip("-").isdigit()) else 0,
        }

    child_to_parent: dict[int, int] = {}
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
            if s in nodes and e in nodes:
                children.setdefault(s, []).append(e)
                child_to_parent[e] = s
    for s, cs in children.items():
        cs.sort(key=lambda c: nodes[c].get("childnum", 0))

    def _is_superglobal_dim(nid: int) -> Optional[tuple]:
        n = nodes.get(nid)
        if not n or n["type"] != "AST_DIM":
            return None
        cs = children.get(nid, [])
        if len(cs) < 2:
            return None
        var_node = nodes.get(cs[0])
        key_node = nodes.get(cs[1])
        if (var_node is None or key_node is None
            or var_node["type"] != "AST_VAR" or key_node["type"] != "string"):
            return None
        vcs = children.get(cs[0], [])
        if not vcs:
            return None
        vname_node = nodes.get(vcs[0])
        if not vname_node or vname_node["type"] != "string":
            return None
        super_name = vname_node["code"].strip().strip('"')
        key = key_node["code"].strip().strip('"')
        return (super_name, key)

    def _collect_superglobal_uses_in_subtree(root: int) -> list[tuple]:
        out: list[tuple] = []
        stack = [root]
        seen = {root}
        while stack:
            cur = stack.pop()
            sg = _is_superglobal_dim(cur)
            if sg:
                out.append(sg)
            for c in children.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return out

    def _collect_local_var_names_in_subtree(root: int) -> list[str]:
        out: set[str] = set()
        stack = [root]
        seen = {root}
        while stack:
            cur = stack.pop()
            n = nodes.get(cur)
            if n and n["type"] == "AST_VAR":
                vcs = children.get(cur, [])
                if vcs:
                    vname_node = nodes.get(vcs[0])
                    if vname_node and vname_node["type"] == "string":
                        name = vname_node["code"].strip().strip('"')
                        if name and name not in _VIPER_INPUT_SUPERGLOBALS \
                           and name not in _VIPER_RELAY_SUPERGLOBALS:
                            out.add(name)
            for c in children.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return list(out)

    try:
        from module1_static_analysis.dispatch_resolver.superglobal_keys import _load_wrapper_funcs as _lwf
        _wrapper_funcs = _lwf()
    except Exception:
        _wrapper_funcs = set()

    def _collect_wrapper_uses_in_subtree(root: int) -> list[tuple]:
        if not _wrapper_funcs:
            return []
        out: list[tuple] = []
        stack = [root]
        seen = {root}
        while stack:
            cur = stack.pop()
            n = nodes.get(cur)
            if n and n["type"] == "AST_CALL":
                cs = children.get(cur, [])
                if cs:
                    head = nodes.get(cs[0])
                    if head and head["type"] == "AST_NAME":
                        fn = None
                        for hc in children.get(cs[0], []):
                            hn = nodes.get(hc)
                            if hn and hn["type"] == "string":
                                fn = hn["code"].strip().strip('"')
                                break
                        if fn in _wrapper_funcs:
                            for ac in cs:
                                an = nodes.get(ac)
                                if an and an["type"] == "AST_ARG_LIST":
                                    for arg in children.get(ac, []):
                                        argn = nodes.get(arg)
                                        if argn and argn["type"] == "string":
                                            key = argn["code"].strip().strip('"')
                                            if key:
                                                out.append(("_REQUEST", key))
                                            break
                                    break
            for c in children.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return out

    def _obj_prop_is(obj_id, prop: str) -> bool:
        if obj_id is None:
            return False
        on = nodes.get(obj_id)
        if not on or on["type"] not in (
                "AST_PROP", "AST_METHOD_CALL", "AST_STATIC_PROP"):
            return False
        for c in children.get(obj_id, []):
            cn = nodes.get(c)
            if cn and cn["type"] == "string" \
               and cn["code"].strip().strip('"') == prop:
                return True
        return False

    def _first_string_arg_of_call(call_id: int) -> Optional[str]:
        for c in children.get(call_id, []):
            cn = nodes.get(c)
            if cn and cn["type"] == "AST_ARG_LIST":
                for arg in children.get(c, []):
                    an = nodes.get(arg)
                    if an and an["type"] == "string":
                        return an["code"].strip().strip('"')
                return None
        return None

    def _collect_framework_input_uses_in_subtree(root: int) -> list[tuple]:
        if not _INPUT_WRAPPER_METHODS:
            return []
        out: list[tuple] = []
        stack = [root]
        seen = {root}
        while stack:
            cur = stack.pop()
            n = nodes.get(cur)
            if n and n["type"] == "AST_METHOD_CALL":
                cs = children.get(cur, [])
                mname = None
                obj_id = None
                for c in cs:
                    cn = nodes.get(c)
                    if not cn:
                        continue
                    if cn.get("childnum") == 0:
                        obj_id = c
                    elif cn.get("childnum") == 1 and cn["type"] == "string":
                        mname = cn["code"].strip().strip('"')
                if mname:
                    for (obj_prop, method, channel) in _INPUT_WRAPPER_METHODS:
                        if mname != method:
                            continue
                        if obj_prop and not _obj_prop_is(obj_id, obj_prop):
                            continue
                        key = _first_string_arg_of_call(cur)
                        if key:
                            tok = "_" + channel if not channel.startswith("_") else channel
                            out.append((tok, key))
                        break
            for c in children.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return out

    _alias_cache: dict = {}

    def _input_alias_map(funcid) -> dict:
        key = str(funcid)
        if key in _alias_cache:
            return _alias_cache[key]
        amap: dict = {}
        for nid, n in nodes.items():
            if n.get("type") != "AST_ASSIGN" or str(n.get("funcid")) != key:
                continue
            cs = children.get(nid, [])
            if len(cs) < 2:
                continue
            if nodes.get(cs[0], {}).get("type") != "AST_VAR":
                continue
            lcs = children.get(cs[0], [])
            if not lcs or nodes.get(lcs[0], {}).get("type") != "string":
                continue
            vname = (nodes[lcs[0]].get("code") or "").strip().strip('"')
            rhs = cs[1]; rt = nodes.get(rhs, {}).get("type")
            ch = None
            if rt == "AST_VAR":
                rcs = children.get(rhs, [])
                if rcs and nodes.get(rcs[0], {}).get("type") == "string":
                    bn = (nodes[rcs[0]].get("code") or "").strip().strip('"')
                    if bn in _VIPER_INPUT_SUPERGLOBALS:
                        ch = bn
            elif rt == "AST_METHOD_CALL" and _INPUT_WRAPPER_METHODS:
                mname = None; obj = None; arglist = None
                for c in children.get(rhs, []):
                    cn = nodes.get(c, {}); cnum = str(cn.get("childnum"))
                    if cnum == "0":
                        obj = c
                    elif cnum == "1" and cn.get("type") == "string":
                        mname = (cn.get("code") or "").strip().strip('"')
                    elif cn.get("type") == "AST_ARG_LIST":
                        arglist = c
                if not (children.get(arglist, []) if arglist is not None else []):
                    for (objp, method, channel) in _INPUT_WRAPPER_METHODS:
                        if mname != method:
                            continue
                        if objp:
                            if obj is None:
                                continue
                            _ok = any(
                                nodes.get(oc, {}).get("type") == "string"
                                and (nodes[oc].get("code") or "").strip().strip('"') == objp
                                for oc in children.get(obj, []))
                            if not _ok:
                                continue
                        ch = "_" + channel
                        break
            if ch:
                amap[vname] = ch
        _alias_cache[key] = amap
        return amap

    def _collect_input_alias_uses_in_subtree(root: int, funcid) -> list[tuple]:
        amap = _input_alias_map(funcid)
        if not amap:
            return []
        out: list[tuple] = []
        stack = [root]; seen = {root}
        while stack:
            cur = stack.pop()
            n = nodes.get(cur) or {}
            if n.get("type") == "AST_DIM":
                cs = children.get(cur, [])
                if cs and nodes.get(cs[0], {}).get("type") == "AST_VAR":
                    bcs = children.get(cs[0], [])
                    bname = ((nodes[bcs[0]].get("code") or "").strip().strip('"')
                             if bcs and nodes.get(bcs[0], {}).get("type") == "string"
                             else None)
                    if bname in amap:
                        for c in cs[1:]:
                            if nodes.get(c, {}).get("type") == "string":
                                k = (nodes[c].get("code") or "").strip().strip('"')
                                if k:
                                    out.append((amap[bname], k))
                                break
            for c in children.get(cur, []):
                if c not in seen:
                    seen.add(c); stack.append(c)
        return out

    def _find_local_var_writes(varname: str, funcid_scope: int) -> list[int]:
        out = []
        for nid, meta in nodes.items():
            if meta["type"] not in ("AST_ASSIGN", "AST_ASSIGN_OP"):
                continue
            if meta["funcid"] != funcid_scope:
                continue
            cs = children.get(nid, [])
            if len(cs) < 2:
                continue
            lhs = nodes.get(cs[0])
            if not lhs or lhs["type"] != "AST_VAR":
                continue
            vcs = children.get(cs[0], [])
            if not vcs:
                continue
            vname_node = nodes.get(vcs[0])
            if vname_node and vname_node["type"] == "string" \
               and vname_node["code"].strip().strip('"') == varname:
                out.append(nid)
        return out

    def _find_relay_writes(relay: str, key: str) -> list[int]:
        out = []
        for nid, meta in nodes.items():
            if meta["type"] != "AST_ASSIGN":
                continue
            cs = children.get(nid, [])
            if len(cs) < 2:
                continue
            lhs_id = cs[0]
            sg = _is_superglobal_dim(lhs_id)
            if sg and sg == (relay, key):
                out.append(nid)
        return out

    _fparam_cache: dict = {}

    def _formal_params(funcid: int) -> dict:
        if funcid in _fparam_cache:
            return _fparam_cache[funcid]
        out: dict = {}
        for nid, meta in nodes.items():
            if meta["type"] != "AST_PARAM" or meta["funcid"] != funcid:
                continue
            name = None
            for c in children.get(nid, []):
                cn = nodes.get(c)
                if cn and cn["type"] == "string":
                    name = cn["code"].strip().strip('"')
                    break
            if name:
                out[name] = meta.get("childnum", 0)
        _fparam_cache[funcid] = out
        return out

    _callsite_cache: dict = {}

    def _callsite_args(func_name: str, pos: int) -> list[tuple]:
        key = (func_name, pos)
        if key in _callsite_cache:
            return _callsite_cache[key]
        out: list[tuple] = []
        for nid, meta in nodes.items():
            t = meta["type"]
            if t not in ("AST_CALL", "AST_STATIC_CALL", "AST_METHOD_CALL"):
                continue
            cs = children.get(nid, [])
            if not cs:
                continue
            matched = False
            if t == "AST_CALL":
                head = nodes.get(cs[0])
                if head and head["type"] == "AST_NAME":
                    for c in children.get(cs[0], []):
                        sn = nodes.get(c)
                        if sn and sn["type"] == "string" \
                           and sn["code"].strip().strip('"') == func_name:
                            matched = True
                            break
            else:
                for c in cs:
                    cn = nodes.get(c)
                    if cn and cn.get("childnum") == 1 and cn["type"] == "string" \
                       and cn["code"].strip().strip('"') == func_name:
                        matched = True
                        break
            if not matched:
                continue
            arg_list = None
            for c in cs:
                cn = nodes.get(c)
                if cn and cn["type"] == "AST_ARG_LIST":
                    arg_list = c
                    break
            if arg_list is None:
                continue
            arg_children = children.get(arg_list, [])
            if pos < len(arg_children):
                out.append((arg_children[pos], nodes[arg_list]["funcid"]))
        _callsite_cache[key] = out
        return out

    sink_file_abs = str(Path(sink_file).resolve())
    sink_toplevel = file_to_toplevel.get(sink_file_abs)
    if sink_toplevel is None:
        sink_basename = os.path.basename(sink_file_abs)
        for path, tid in file_to_toplevel.items():
            if os.path.basename(path) == sink_basename:
                sink_toplevel = tid
                break
    sink_call_types = ("AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL",
                        "AST_NEW", "AST_ASSIGN", "AST_ASSIGN_OP")

    def _in_sink_file(nid: int) -> bool:
        fid = nodes[nid]["funcid"]
        return fid in funcid_to_file and funcid_to_file[fid] == sink_file_abs

    sink_node: Optional[int] = None
    for nid, meta in nodes.items():
        if meta["type"] not in sink_call_types:
            continue
        if meta["lineno"] != sink_lineno:
            continue
        if _in_sink_file(nid):
            sink_node = nid
            break
    if sink_node is None:
        for nid, meta in nodes.items():
            if meta["lineno"] != sink_lineno or not _in_sink_file(nid):
                continue
            cur = nid
            seen = set()
            while cur is not None and cur not in seen:
                seen.add(cur)
                if nodes[cur]["type"] in sink_call_types:
                    sink_node = cur
                    break
                cur = child_to_parent.get(cur)
            if sink_node is not None:
                break
    if sink_node is None:
        return []

    _LOCAL_BFS_MAX_DEPTH = 6
    sink_funcid = nodes[sink_node]["funcid"]
    direct_sink_refs = _collect_superglobal_uses_in_subtree(sink_node)
    direct_sink_refs += _collect_wrapper_uses_in_subtree(sink_node)
    direct_sink_refs += _collect_framework_input_uses_in_subtree(sink_node)
    direct_sink_refs += _collect_input_alias_uses_in_subtree(
        sink_node, nodes.get(sink_node, {}).get("funcid"))
    sink_refs = list(direct_sink_refs)

    visited_assigns: set = set()
    visited_local_names: set = set()
    queue: list = [(v, sink_funcid)
                   for v in _collect_local_var_names_in_subtree(sink_node)]
    depth = 0
    while queue and depth < _LOCAL_BFS_MAX_DEPTH:
        depth += 1
        next_queue: list = []
        for (vname, fid) in queue:
            if (vname, fid) in visited_local_names:
                continue
            visited_local_names.add((vname, fid))
            writes = _find_local_var_writes(vname, fid)
            for assign_id in writes:
                if assign_id in visited_assigns:
                    continue
                visited_assigns.add(assign_id)
                cs = children.get(assign_id, [])
                if len(cs) < 2:
                    continue
                rhs_id = cs[1]
                sink_refs.extend(_collect_superglobal_uses_in_subtree(rhs_id))
                sink_refs.extend(_collect_wrapper_uses_in_subtree(rhs_id))
                sink_refs.extend(_collect_framework_input_uses_in_subtree(rhs_id))
                sink_refs.extend(_collect_input_alias_uses_in_subtree(rhs_id, fid))
                next_queue.extend((v, fid)
                                  for v in _collect_local_var_names_in_subtree(rhs_id))
            fparams = _formal_params(fid)
            if vname in fparams:
                fname = funcid_to_name.get(fid)
                if fname:
                    for (arg_id, call_fid) in _callsite_args(
                            fname, fparams[vname]):
                        sink_refs.extend(
                            _collect_superglobal_uses_in_subtree(arg_id))
                        sink_refs.extend(
                            _collect_wrapper_uses_in_subtree(arg_id))
                        sink_refs.extend(
                            _collect_framework_input_uses_in_subtree(arg_id))
                        sink_refs.extend(
                            _collect_input_alias_uses_in_subtree(arg_id, call_fid))
                        next_queue.extend(
                            (v, call_fid)
                            for v in _collect_local_var_names_in_subtree(arg_id))
        queue = next_queue

    if not sink_refs:
        return []

    results: list[dict] = []
    seen_results: set = set()

    def _record(kind: str, key: str, via: list):
        sig = (kind, key)
        if sig in seen_results:
            return
        seen_results.add(sig)
        results.append({"kind": kind, "key": key, "via": list(via)})

    def _backward(super_name: str, key: str, via: list, depth: int):
        if super_name in _VIPER_INPUT_SUPERGLOBALS:
            _record(super_name, key, via)
            return
        if super_name not in _VIPER_RELAY_SUPERGLOBALS:
            return
        if depth >= _VIPER_TAINT_MAX_RELAY_DEPTH:
            return
        new_via = via + [(super_name, key)]
        for assign_id in _find_relay_writes(super_name, key):
            cs = children.get(assign_id, [])
            if len(cs) < 2:
                continue
            rhs_id = cs[1]
            for (rhs_super, rhs_key) in _collect_superglobal_uses_in_subtree(rhs_id):
                _backward(rhs_super, rhs_key, new_via, depth + 1)

    for (super_name, key) in dict.fromkeys(sink_refs):
        _backward(super_name, key, [], 0)

    return results


def _extract_injection_chain(instr_info_csv: str, lines: list[str],
                              sink_lineno: int = 0,
                              working_dir: Optional[str] = None,
                              sink_file: Optional[str] = None,
                              in_scope_files: Optional[set] = None) -> list[dict]:
    chain = []
    seen = set()
    with open(instr_info_csv) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            if row['type'] != 't':
                continue
            lineno  = int(row['lineno'])
            varname = row['value'].strip()
            key = (lineno, varname)
            if key in seen:
                continue
            seen.add(key)
            chain.append({
                'lineno':   lineno,
                'varname':  varname,
                'source':   _get_line(lines, lineno),
            })

    if sink_lineno > 0:
        sink_text = _get_line(lines, sink_lineno)
        for sup, name in _scan_inputs(sink_text):
            key = (sink_lineno, name)
            if key in seen:
                continue
            seen.add(key)
            chain.append({
                'lineno':   sink_lineno,
                'varname':  name,
                'source':   sink_text,
            })

        alias_map = _build_alias_map(lines)
        if alias_map:
            ctx_start = max(1, sink_lineno - 5)
            ctx_end = min(len(lines), sink_lineno + 5)
            for ln in range(ctx_start, ctx_end + 1):
                ctx_text = _get_line(lines, ln)
                for local in _LOCAL_VAR_REF.findall(ctx_text):
                    http_key = alias_map.get(local)
                    if not http_key:
                        continue
                    k = (sink_lineno, http_key)
                    if k in seen:
                        continue
                    seen.add(k)
                    chain.append({
                        'lineno':  sink_lineno,
                        'varname': http_key,
                        'source':  sink_text,
                    })

    if working_dir and sink_file and sink_lineno > 0:
        try:
            viper_sources = _viper_keyaware_backward_taint(
                working_dir, sink_file, sink_lineno, in_scope_files=in_scope_files)
        except Exception as _e:
            viper_sources = []
        for s in viper_sources:
            key = (sink_lineno, s["key"])
            if key in seen:
                continue
            seen.add(key)
            via_descr = "" if not s["via"] else (
                " via " + " → ".join(f"${r}['{k}']" for (r, k) in s["via"])
            )
            chain.append({
                'lineno':   sink_lineno,
                'varname':  s["key"],
                'source':   f"<VIPER backward: ${s['kind']}['{s['key']}']{via_descr}>",
                'origin':   'viper_backward',
            })

    return sorted(chain, key=lambda x: x['lineno'])


def _extract_sink_context(lines: list[str], sink_lineno: int, context: int = 5) -> dict:
    start = max(1, sink_lineno - context)
    end   = min(len(lines), sink_lineno + context)
    ctx_lines = {}
    for ln in range(start, end + 1):
        ctx_lines[ln] = lines[ln - 1].rstrip()
    return {
        'lineno':     sink_lineno,
        'statement':  _get_line(lines, sink_lineno),
        'context':    ctx_lines,
    }


def extract(
    instr_info_csv: str,
    php_source_file: str,
    entry_url: str,
    method: str,
    sink_line: int = 0,
    project_root: Optional[str] = None,
    sink_dominator_lines: Optional[list[int]] = None,
    working_dir: Optional[str] = None,
    entry_file: Optional[str] = None,
    framework: Optional[str] = None,
    extra_scan_files: Optional[list] = None,
    extra_scan_line_scope: Optional[dict] = None,
    extra_scan_switch_case_dom: Optional[dict] = None,
) -> dict:
    _load_input_sources(framework)
    dist_nodes = _read_dist_lines(instr_info_csv)
    lines      = _read_source(php_source_file)
    sink_lineno = sink_line if sink_line > 0 else \
                  min(n['lineno'] for n in dist_nodes if n['dist'] == 1.0)

    included: list[Path] = []
    body_resolver = None
    _minimal_scope = os.environ.get("VIPER_EXTRACT_MINIMAL_SCOPE") == "1"
    if project_root and not _minimal_scope:
        sink_path = Path(php_source_file).resolve()
        extra_seeds = [entry_file] if entry_file else None
        included = _collect_included_files(
            sink_path, Path(project_root), extra_seeds=extra_seeds)
    if working_dir:
        try:
            from module1_static_analysis.dispatch_resolver.body_range_resolver import BodyRangeResolver
            in_scope = {str(Path(php_source_file).resolve())}
            in_scope.update(str(p) for p in included)
            body_resolver = BodyRangeResolver(
                working_dir=working_dir, in_scope_files=in_scope)
        except Exception:
            body_resolver = None

    if_constraints   = _extract_if_constraints(
        lines, dist_nodes,
        body_resolver=body_resolver,
        source_file=str(Path(php_source_file).resolve()),
        working_dir=working_dir)
    if sink_dominator_lines:
        dom_set = set(sink_dominator_lines)
        if_constraints = [c for c in if_constraints if c['lineno'] in dom_set]
    if sink_dominator_lines:
        try:
            _sink_switch = [
                c for c in _extract_if_constraints_in_file(
                    Path(php_source_file).resolve(),
                    body_resolver=body_resolver, working_dir=working_dir,
                    allowed_lines=set(sink_dominator_lines))
                if c.get('switch_case_value')
            ]
            if_constraints.extend(_sink_switch)
        except Exception:
            pass
    for inc in included:
        if_constraints.extend(_extract_if_constraints_in_file(
            inc, body_resolver=body_resolver, working_dir=working_dir))
    for extra in (extra_scan_files or []):
        try:
            p = Path(extra).resolve()
        except Exception:
            continue
        if not p.is_file():
            continue
        _allowed = None
        if extra_scan_line_scope:
            _allowed = extra_scan_line_scope.get(str(p)) \
                or extra_scan_line_scope.get(str(Path(extra)))
        _sw_dom = None
        if extra_scan_switch_case_dom:
            _sw_dom = {sw_ln: case_val
                       for (f, sw_ln), case_val in extra_scan_switch_case_dom.items()
                       if f == str(p) or f == str(Path(extra))}
        if_constraints.extend(_extract_if_constraints_in_file(
            p, body_resolver=body_resolver, working_dir=working_dir,
            require_die=False, allowed_lines=_allowed,
            switch_case_dom=_sw_dom))
    assignments      = _extract_assignments(lines)
    exit_guards      = _extract_exit_guards(lines)
    sink             = _extract_sink_context(lines, sink_lineno)
    _in_scope = {str(Path(php_source_file).resolve())}
    _in_scope.update(str(p) for p in included)
    if entry_file:
        try:
            _in_scope.add(str(Path(entry_file).resolve()))
        except Exception:
            pass
    for _ex in (extra_scan_files or []):
        try:
            _in_scope.add(str(Path(_ex).resolve()))
        except Exception:
            pass
    injection_chain  = _extract_injection_chain(
        instr_info_csv, lines,
        sink_lineno=sink_lineno,
        working_dir=working_dir,
        sink_file=php_source_file,
        in_scope_files=_in_scope,
    )

    param_sources: dict[str, str] = {}
    for ifc in if_constraints:
        for name, sup in ifc.get('param_sources', {}).items():
            cur = param_sources.get(name)
            if cur in (None, 'REQUEST'):
                param_sources[name] = sup
    sg_in_source = re.compile(
        r'\$_(REQUEST|GET|POST|COOKIE)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]')
    try:
        from module1_static_analysis.dispatch_resolver.superglobal_keys import _load_wrapper_funcs
        _wrapper_funcs = _load_wrapper_funcs()
    except Exception:
        _wrapper_funcs = set()
    wrapper_call_pat = None
    if _wrapper_funcs:
        wrapper_call_pat = re.compile(
            r'\b(?:' + '|'.join(map(re.escape, sorted(_wrapper_funcs)))
            + r')\s*\(\s*[\'"]([^\'"]+)[\'"]'
        )
    for ic in injection_chain:
        src = ic.get('source', '')
        for sup, name in sg_in_source.findall(src):
            cur = param_sources.get(name)
            if cur in (None, 'REQUEST'):
                param_sources[name] = sup
        if wrapper_call_pat:
            for name in wrapper_call_pat.findall(src):
                if name not in param_sources:
                    param_sources[name] = 'REQUEST'

    array_params = sorted(_detect_array_params(lines, _build_alias_map(lines)))
    return {
        'entry_url':         entry_url,
        'method':            method,
        'sink':              sink,
        'if_constraints':    if_constraints,
        'exit_guards':       exit_guards,
        'param_assignments': assignments,
        'injection_chain':   injection_chain,
        'param_sources':     param_sources,
        'array_params':      array_params,
        'in_scope_files':    [os.path.basename(php_source_file)] +
                              [inc.name for inc in included],
    }


def main():
    parser = argparse.ArgumentParser(description='VIPER param constraint extractor')
    parser.add_argument('--instr-info', required=True, help='path to instr-info.csv')
    parser.add_argument('--source',     required=True, help='path to PHP source file')
    parser.add_argument('--entry-url',  required=True, help='entry URL (e.g. http://localhost/...)')
    parser.add_argument('--method',     default='POST')
    args = parser.parse_args()

    result = extract(args.instr_info, args.source, args.entry_url, args.method)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
