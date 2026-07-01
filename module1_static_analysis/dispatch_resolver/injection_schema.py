from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Optional


_FUNC_LABEL_RE = re.compile(r"@\s*([^\s:]+):(\d+)")


def _read_lines(path: str) -> list[str]:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return []


def _func_source(lines: list[str], start_lineno: int, focus_line: Optional[int] = None,
                 max_full: int = 55, head: int = 14, win: int = 14) -> str:
    end = min(len(lines), start_lineno - 1 + 400)
    depth = 0
    started = False
    for i in range(start_lineno - 1, end):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and depth <= 0:
            end = i + 1
            break
    full = lines[start_lineno - 1:end]
    if (focus_line is None or len(full) <= max_full
            or not (start_lineno <= focus_line <= end)):
        return "".join(full)
    fi = focus_line - start_lineno
    parts = list(full[:head])
    w0, w1 = max(head, fi - win), min(len(full), fi + win)
    if w0 > head:
        parts.append("        // … (unrelated branches omitted) …\n")
    parts += full[w0:w1]
    if w1 < len(full):
        parts.append("        // … (unrelated branches omitted) …\n")
    return "".join(parts)


def _functions_on_path(discovery) -> list[tuple]:
    out: list[tuple] = []
    seen = set()

    def _add(label: str):
        if not label:
            return
        m = _FUNC_LABEL_RE.search(label)
        if not m:
            return
        key = (m.group(1), int(m.group(2)))
        if key in seen:
            return
        seen.add(key)
        out.append((m.group(1), int(m.group(2)), label))

    _add(getattr(discovery, "sink_enclosing_label", "") or "")
    for h in (getattr(discovery, "hops", None) or []):
        _add(getattr(h, "from_label", "") or "")
        _add(getattr(h, "to_label", "") or "")
    return out


_DYNAMIC_KEY_RE = re.compile(r"\$\w+\s*\[[^\]]*\.\s*\$")


def _field_writer_functions(sink_fn_src: str, sink_file_lines: list[str]) -> list[tuple]:
    fields = set(re.findall(r"\$this->(\w+)\b", sink_fn_src))
    if not fields:
        return []
    out: list[tuple] = []
    seen = set()
    cur_fn_line = 0
    cur_fn_name = ""
    for i, line in enumerate(sink_file_lines, start=1):
        fm = re.search(r"function\s+(\w+)\s*\(", line)
        if fm:
            cur_fn_line = i
            cur_fn_name = fm.group(1)
        for fld in fields:
            if re.search(rf"\$this->{re.escape(fld)}\s*(\[\s*\])?\s*=", line):
                key = (cur_fn_line, cur_fn_name)
                if cur_fn_line and key not in seen:
                    src = _func_source(sink_file_lines, cur_fn_line)
                    if _DYNAMIC_KEY_RE.search(src):
                        seen.add(key)
                        out.append((cur_fn_line, fld, cur_fn_name))
    return out


def _downstream_callee_funcs(sink_file: str, sink_line: int, working_dir: str,
                             *, max_depth: int = 2, cap: int = 60) -> list[tuple]:
    if not working_dir:
        return []
    try:
        from module1_static_analysis.dispatch_resolver.entry_finder import CallGraph, _enclosing_function_of
        from module1_static_analysis.dispatch_resolver.fig_builder import build_fig, _read_nodes
        from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    except Exception:
        return []
    wd = Path(working_dir)
    try:
        fig = build_fig(wd)
        nodes = _read_nodes(wd / "nodes.csv")
        cg = CallGraph.load(wd / "call_graph.csv")
    except Exception:
        return []
    sink_fn = _enclosing_function_of(sink_file, sink_line, nodes, fig)
    if not sink_fn:
        return []
    out: list[tuple] = []
    seen = {sink_fn}
    frontier = [sink_fn]
    for _ in range(max_depth):
        nxt: list[int] = []
        for fn in frontier:
            for callee in cg.callees_of.get(fn, []):
                if callee in seen or len(seen) > cap:
                    continue
                seen.add(callee)
                nxt.append(callee)
                meta = nodes.get(callee) or {}
                fpath = _containing_file(callee, fig, nodes) or ""
                try:
                    ln = int(meta.get("lineno") or 0)
                except (ValueError, TypeError):
                    ln = 0
                nm = (str(meta.get("name") or "")).strip('"') or f"func{callee}"
                if fpath and ln:
                    out.append((fpath, ln, f"{nm} @ {Path(fpath).name}:{ln}"))
        frontier = nxt
        if len(seen) > cap:
            break
    return out


_PARAM_KEY_LINE_RE = re.compile(
    r"\$\w+\s*\[[^\]]*\.\s*\$"
    r"|\$_(REQUEST|GET|POST|COOKIE|SERVER)\b"
    r"|\bpreg_match\b|\bforeach\b|\bexplode\b")


def _slice_to_param_keys(src: str, *, head: int = 5, ctx: int = 2,
                         small: int = 16) -> str:
    lines = src.splitlines()
    if len(lines) <= small:
        return src
    keep = set(range(min(head, len(lines))))
    for i, ln in enumerate(lines):
        if _PARAM_KEY_LINE_RE.search(ln):
            keep.update(range(max(0, i - ctx), min(len(lines), i + ctx + 1)))
    if len(keep) <= head:
        return "\n".join(lines[:head]) + \
            "\n        // … (no request-param key construction here) …"
    out, prev = [], -1
    for i in sorted(keep):
        if prev >= 0 and i > prev + 1:
            out.append("        // …")
        out.append(lines[i])
        prev = i
    return "\n".join(out)


def extract_injection_path_code(sink_file: str, sink_line: int, discovery,
                                working_dir: str = "") -> dict:
    code: dict[str, str] = {}
    sink_lines = _read_lines(sink_file)
    sink_fn_full = (_func_source(sink_lines, _enclosing_decl_line(sink_lines, sink_line))
                    if sink_lines else "")

    for f_file, f_line, label in _functions_on_path(discovery):
        lines = sink_lines if Path(f_file).name == Path(sink_file).name else _read_lines(f_file)
        if not lines:
            continue
        src = _func_source(lines, f_line, focus_line=sink_line)
        if src.strip():
            code[label] = src

    for w_line, fld, fn_name in _field_writer_functions(sink_fn_full, sink_lines):
        label = f"{fn_name} @ {Path(sink_file).name}:{w_line} (parses request → $this->{fld})"
        if label not in code:
            code[label] = _func_source(sink_lines, w_line)

    for f_file, f_line, label in _downstream_callee_funcs(sink_file, sink_line, working_dir):
        if label in code:
            continue
        lines = sink_lines if Path(f_file).name == Path(sink_file).name else _read_lines(f_file)
        if not lines:
            continue
        src = _func_source(lines, f_line, focus_line=sink_line)
        if not src.strip():
            continue
        if _DYNAMIC_KEY_RE.search(src) or re.search(
                r"\$_(REQUEST|GET|POST|COOKIE|SERVER)\b", src):
            code[label] = _slice_to_param_keys(src)
    return code


def _enclosing_decl_line(lines: list[str], target: int) -> int:
    for i in range(min(target, len(lines)) - 1, -1, -1):
        if re.search(r"function\s+\w+\s*\(", lines[i]):
            return i + 1
    return max(1, target)


_SCHEMA_PROMPT = """You are analysing a PHP web app to recover the HTTP request \
parameter KEYS (names only) that an input PARSER reads to build the value \
reaching a SQL sink.

SINK: {sink_file}:{sink_line}
SINK STATEMENT: {sink_stmt}

CODE (request-param parsing on the path to the sink):

{code}

Your ONLY job: list the request parameter KEYS the parser reads. They are often \
DYNAMICALLY NAMED — the parser builds a key by concatenating fixed literal \
fragments with a varying index/counter (a loop over numbered groups, an \
array-style field set, …); the literal fragments are pinned by the code, only the \
index varies. Report each key as the CONCRETE literal string an HTTP request would \
actually send for the first/minimal instance (smallest index), NOT a template with \
a placeholder.

(Illustrative only, UNRELATED app: a parser reading `$in['f_'.$k.'_v']` in a loop \
→ you'd report the literal `f_0_v` / `f_1_v`, never `f_<k>_v`.)

STRICT RULES — follow exactly:
- Output KEYS (names) ONLY. Do NOT assign any value to any key. Values are decided \
later at runtime from dynamic feedback, NEVER by you — do not invent values, \
placeholders, or example field names.
- Output only keys you can justify DIRECTLY from the parser's key construction in \
the code shown. Do NOT include branch/route selectors (type/action/mode/searchtype) \
— those are recovered separately by static analysis.
- Do NOT invent generic keys (limit/offset/page/...) the parser code does not read.
- `payload_param`: IF the code makes clear which single key carries the attacker \
value that flows into the SQL string, name that key. This is a BEST-EFFORT HINT \
only — if the shown code is insufficient to tell, set it to null.

Respond with ONLY a JSON object (KEYS ONLY, no values):
{{"param_keys": ["<key>", ...], "payload_param": "<key-or-null>", "notes": "<one line>"}}"""


def infer_param_schema(code: dict, sink_file: str, sink_line: int, sink_stmt: str,
                       llm_call: Callable[[str], str]) -> Optional[dict]:
    if not code or llm_call is None:
        return None
    code_blob = "\n\n".join(f"// ===== {label} =====\n{src}" for label, src in code.items())
    if len(code_blob) > 16000:
        code_blob = code_blob[:16000] + "\n// …(truncated)…"
    prompt = _SCHEMA_PROMPT.format(sink_file=Path(sink_file).name, sink_line=sink_line,
                                   sink_stmt=sink_stmt, code=code_blob)
    try:
        resp = llm_call(prompt)
    except Exception:
        return None
    m = re.search(r"\{.*\}", resp or "", re.DOTALL)
    if not m:
        return None
    import json
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    keys = obj.get("param_keys")
    if not isinstance(keys, list):
        return None
    keys = [str(k) for k in keys if k]
    if not keys:
        return None
    payload = obj.get("payload_param")
    payload = str(payload) if (payload and str(payload) in keys) else None
    params = {k: ("{INJECT}" if k == payload else "") for k in keys}
    return {"params": params, "inject_param": payload,
            "param_keys": keys, "notes": obj.get("notes", "")}


_DISPATCH_CONCAT_RE = re.compile(
    r"""call_user_func\s*\(\s*array\s*\(\s*\$this\s*,\s*"""
    r"""\$this->(\w+)\s*\.\s*['"](\w+)['"]""")
_NEW_ARG_KEY_RE = re.compile(r"""new\s+\w+\s*\([^)]*\$\w+\[['"](\w+)['"]\]""")


def _dispatch_param_candidates(sink_file: str, sink_line: int,
                               working_dir: str) -> Optional[dict]:
    sink_lines = _read_lines(sink_file)
    if not sink_lines:
        return None
    sink_fn_full = _func_source(sink_lines, _enclosing_decl_line(sink_lines, sink_line))
    blobs: list[tuple] = [(sink_file, sink_fn_full)]
    for f_file, f_line, _label in _downstream_callee_funcs(sink_file, sink_line, working_dir):
        lines = sink_lines if Path(f_file).name == Path(sink_file).name else _read_lines(f_file)
        if lines:
            blobs.append((f_file, _func_source(lines, f_line)))
    field = suffix = None
    for _fpath, src in blobs:
        m = _DISPATCH_CONCAT_RE.search(src)
        if m:
            field, suffix = m.group(1), m.group(2)
            break
    if not field or not suffix:
        return None
    whole = "".join(sink_lines)
    cands = sorted(set(re.findall(rf"function\s+(\w+){re.escape(suffix)}\b", whole)))
    if not cands:
        return None
    pm = _NEW_ARG_KEY_RE.search(sink_fn_full)
    param = pm.group(1) if pm else field
    return {
        "param": param,
        "dispatch_field": field,
        "suffix": suffix,
        "candidates": cands,
        "via": f'call_user_func(array($this, $this->{field} . "{suffix}"))',
    }


def build_injection_schema(sink_file: str, sink_line: int, sink_stmt: str,
                           discovery, llm_call: Callable[[str], str],
                           working_dir: str = "") -> Optional[dict]:
    code = extract_injection_path_code(sink_file, sink_line, discovery, working_dir)
    if not code:
        return None
    schema = infer_param_schema(code, sink_file, sink_line, sink_stmt, llm_call)
    if schema is not None:
        schema["_path_functions"] = list(code.keys())
        dpc = _dispatch_param_candidates(sink_file, sink_line, working_dir)
        if dpc:
            schema["dispatch_param_candidates"] = dpc
    return schema


def reconcile_schema_with_static(schema: Optional[dict],
                                 param_sources: dict) -> Optional[dict]:
    if not schema:
        return schema
    static_keys = set(param_sources or {})
    dpc_param = (schema.get("dispatch_param_candidates") or {}).get("param")
    if dpc_param:
        static_keys.add(dpc_param)
    _num = re.compile(r"^(.*?)(\d+)(.*)$")
    static_idx: dict = {}
    for k in (param_sources or {}):
        m = _num.match(k)
        if m:
            static_idx[m.group(1)] = m.group(2)

    def _align(key: str) -> str:
        m = _num.match(key)
        if m and m.group(1) in static_idx:
            return m.group(1) + static_idx[m.group(1)] + m.group(3)
        return key

    params = schema.get("params") or {}
    payload = schema.get("inject_param")
    new_params: dict = {}
    new_payload = payload
    for k, v in params.items():
        ak = _align(k)
        if k == payload:
            new_payload = ak
        if ak in static_keys:
            continue
        new_params[ak] = v
    schema["params"] = new_params
    schema["inject_param"] = new_payload if new_payload in new_params else None
    schema["param_keys"] = list(new_params)
    return schema
