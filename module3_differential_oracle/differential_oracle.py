
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


RECV_LOG_IN_CONTAINER    = "/tmp/viper_recv.bin"
BLOCKER_LOG_IN_CONTAINER = "/tmp/viper.jsonl"


@dataclass
class Observation:
    label: str
    http_status: int = 0
    response_body: str = ""
    sentinel_seen: bool = False
    recv_capture: bytes = b""
    trace_events: list = field(default_factory=list)
    elapsed_ms: int = 0

    @property
    def recv_size(self) -> int:
        return len(self.recv_capture)

    @property
    def body_len(self) -> int:
        return len(self.response_body)


@dataclass
class DifferentialVerdict:
    verdict: str
    reason: str = ""
    differences: dict = field(default_factory=dict)
    sentinel_seen: dict = field(default_factory=dict)
    recv_sizes: dict = field(default_factory=dict)
    body_lens: dict = field(default_factory=dict)
    http_statuses: dict = field(default_factory=dict)
    elapsed_ms: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _docker_exec(container: str, cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", container, "bash", "-c", cmd],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def _docker_read_bytes(container: str, path: str) -> bytes:
    proc = subprocess.run(
        ["docker", "exec", container, "cat", path],
        capture_output=True,
    )
    return proc.stdout if proc.returncode == 0 else b""


def _docker_read_text(container: str, path: str) -> str:
    proc = subprocess.run(
        ["docker", "exec", container, "cat", path],
        capture_output=True,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", errors="replace")


def observe(
    *,
    label: str,
    container: str,
    entry_url: str,
    body: str,
    extra_headers: Optional[dict] = None,
    sentinel_uuid: str = "",
    http_method: str = "POST",
    get_query: str = "",
    override_keys: Optional[set] = None,
) -> Observation:

    url = entry_url
    if get_query:
        ov = override_keys or set()
        if ov and "?" in url:
            _base, _qs = url.split("?", 1)
            _kept = "&".join(
                kv for kv in _qs.split("&")
                if not ("=" in kv and kv.split("=", 1)[0] in ov)
            )
            url = _base + ("?" + _kept if _kept else "")
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
        if body:
            url += ("&" if "?" in url else "?") + body
        body = None
        http_method = "GET"

    if http_method == "POST" and body:
        try:
            body = maybe_inject_csrf(
                post_body=body, http_method=http_method,
                get_url=entry_url, cookies=None,
                extra_headers=extra_headers,
            )
        except Exception:
            pass

    cmd = ["curl", "-sS", "-m", "30", "--noproxy", "*",
           "-D", "-",
           "-w", "\n__HTTP_STATUS__%{http_code}__\n__TIME_TOTAL__%{time_total}__\n",
           "-X", http_method, url]
    if http_method == "POST":
        cmd += ["-H", "Content-Type: application/x-www-form-urlencoded",
                "--data-binary", body]
    for k, v in (extra_headers or {}).items():
        cmd.extend(["-H", f"{k}: {v}"])
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    raw = (proc.stdout or "") + (proc.stderr or "")

    http_status = 0
    sm = re.search(r"__HTTP_STATUS__(\d+)__", raw)
    if sm:
        http_status = int(sm.group(1))
        raw = re.sub(r"\n?__HTTP_STATUS__\d+__\n?", "", raw)

    elapsed_ms = 0
    tm = re.search(r"__TIME_TOTAL__([\d.]+)__", raw)
    if tm:
        try:
            elapsed_ms = int(float(tm.group(1)) * 1000)
        except ValueError:
            pass
        raw = re.sub(r"\n?__TIME_TOTAL__[\d.]+__\n?", "", raw)

    headers_text = ""
    body_text = raw
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            headers_text, body_text = raw.split(sep, 1)
            break
    if body_text.startswith("curl:"):
        body_text = ""

    recv = _docker_read_bytes(container, RECV_LOG_IN_CONTAINER)
    jsonl = _docker_read_text(container, BLOCKER_LOG_IN_CONTAINER)
    events = []
    for ln in jsonl.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            events.append(json.loads(ln))
        except json.JSONDecodeError:
            continue

    sentinel_ok = bool(sentinel_uuid and (
        sentinel_uuid in body_text or sentinel_uuid in headers_text))

    return Observation(
        label=label, http_status=http_status,
        response_body=body_text, sentinel_seen=sentinel_ok,
        recv_capture=recv, trace_events=events,
        elapsed_ms=elapsed_ms,
    )


_NOISE_PATTERNS = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"), "<TS>"),
    (re.compile(r"\b[0-9a-f]{32,64}\b", re.I), "<HEX>"),
    (re.compile(r"name=\"_token\"\s*value=\"[^\"]+\""), "<CSRF>"),
    (re.compile(r"PHPSESSID=[^;\s]+"), "PHPSESSID=<S>"),
    (re.compile(r"VIPER_SENTINEL_[0-9a-f]+"), "<SENT>"),
]


def _normalize_body(s: str) -> str:
    if not s:
        return ""
    for pat, sub in _NOISE_PATTERNS:
        s = pat.sub(sub, s)
    return s


_DB_ERROR_TOKENS = (
    "SQL syntax", "SQLSTATE", "ORA-", "PG::", "psycopg",
    "PSQLException", "SQLite3::", "Microsoft OLE DB",
    "ODBC Driver", "Warning: mysql", "Warning: pg",
    "You have an error", "supplied argument is not a valid",
    "Unclosed quotation",
)
_ROW_COUNT_PAT = re.compile(r"(\d+)\s+rows?\s+(returned|affected|in set)", re.I)


def _key_region(body: str) -> dict:
    norm = _normalize_body(body)
    tokens = sorted(t for t in _DB_ERROR_TOKENS if t.lower() in norm.lower())
    rows = sorted({int(m.group(1)) for m in _ROW_COUNT_PAT.finditer(norm)})
    return {"db_error_tokens": tokens, "row_counts": rows}


def diff(safe: Observation, mal: Observation) -> DifferentialVerdict:
    base = {
        "sentinel_seen": {"safe": safe.sentinel_seen, "mal": mal.sentinel_seen},
        "recv_sizes":    {"safe": safe.recv_size,     "mal": mal.recv_size},
        "body_lens":     {"safe": safe.body_len,      "mal": mal.body_len},
        "http_statuses": {"safe": safe.http_status,   "mal": mal.http_status},
        "elapsed_ms":    {"safe": safe.elapsed_ms,    "mal": mal.elapsed_ms},
    }

    if not (safe.sentinel_seen and mal.sentinel_seen):
        which = []
        if not safe.sentinel_seen: which.append("safe")
        if not mal.sentinel_seen:  which.append("mal")
        return DifferentialVerdict(
            verdict="INCONCLUSIVE",
            reason=f"sentinel missing in: {','.join(which)} "
                   f"(path diverged before reaching sink — payload affects "
                   f"upstream control flow, can't isolate sink behavior)",
            **base,
        )

    diffs: dict = {}

    if safe.recv_capture != mal.recv_capture:
        recv_delta = abs(safe.recv_size - mal.recv_size)
        recv_noise_floor = max(50, int(0.01 * safe.recv_size))
        import os
        _override = os.environ.get("VIPER_RECV_NOISE_FLOOR")
        if _override:
            try: recv_noise_floor = int(_override)
            except ValueError: pass
        if recv_delta > recv_noise_floor:
            diffs["recv_bytes"] = {
                "safe_bytes": safe.recv_size,
                "mal_bytes":  mal.recv_size,
                "first_diff_offset": _first_diff_offset(safe.recv_capture, mal.recv_capture),
                "delta": recv_delta,
                "noise_floor": recv_noise_floor,
            }

    def _db_err_tokens(raw: bytes) -> set:
        try:
            low = raw.decode("latin-1", "replace").lower()
        except Exception:
            return set()
        return {t for t in _DB_ERROR_TOKENS if t.lower() in low}
    _safe_recv_err = _db_err_tokens(safe.recv_capture)
    _mal_recv_err  = _db_err_tokens(mal.recv_capture)
    if _mal_recv_err - _safe_recv_err:
        diffs["sql_error_in_recv"] = {
            "new_tokens": sorted(_mal_recv_err - _safe_recv_err),
            "safe": sorted(_safe_recv_err), "mal": sorted(_mal_recv_err),
        }

    if safe.http_status != mal.http_status:
        diffs["http_status"] = {"safe": safe.http_status, "mal": mal.http_status}

    safe_n = _normalize_body(safe.response_body)
    mal_n  = _normalize_body(mal.response_body)
    if abs(len(safe_n) - len(mal_n)) > max(20, int(0.05 * len(safe_n))):
        diffs["body_length"] = {
            "safe_len": len(safe_n), "mal_len": len(mal_n),
            "delta": len(mal_n) - len(safe_n),
        }

    safe_kr = _key_region(safe.response_body)
    mal_kr  = _key_region(mal.response_body)
    if safe_kr != mal_kr:
        diffs["key_region"] = {"safe": safe_kr, "mal": mal_kr}

    _WEAK_DIMS = {"recv_bytes"}
    strong = [d for d in diffs if d not in _WEAK_DIMS]
    if strong:
        return DifferentialVerdict(
            verdict="CONFIRMED",
            reason=f"{len(strong)} strong dimension(s) differ: {', '.join(strong)}",
            differences=diffs, **base,
        )
    if diffs:
        return DifferentialVerdict(
            verdict="INCONCLUSIVE",
            reason=f"only weak dimension(s) differ: {', '.join(diffs)} "
                   f"(recv byte-delta without DB error / status / body change "
                   f"— deferring to time-based fallback)",
            differences=diffs, **base,
        )
    return DifferentialVerdict(
        verdict="NEGATIVE",
        reason="all signal dimensions match — payload is benign at this sink",
        **base,
    )


def _first_diff_offset(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n if len(a) != len(b) else -1


def predator_oracle(obs: "Observation") -> tuple[bool, list]:
    try:
        low_recv = obs.recv_capture.decode("latin-1", "replace").lower()
    except Exception:
        low_recv = ""
    low_body = (obs.response_body or "").lower()
    tokens = sorted(
        t for t in _DB_ERROR_TOKENS
        if t.lower() in low_recv or t.lower() in low_body
    )
    return (bool(tokens), tokens)


def build_p_mal(baseline: dict, param: str, payload: str,
                mode: str = "append") -> dict:
    out = dict(baseline)
    base_val = str(out.get(param, ""))
    out[param] = (base_val + payload) if mode == "append" else payload
    return out


def probe(
    *,
    container: str,
    entry_url: str,
    baseline_observation: Observation,
    baseline_params: dict,
    param: str,
    payload: str,
    sentinel_uuid: str,
    extra_headers: Optional[dict] = None,
    mutate_mode: str = "append",
    http_method: str = "POST",
    param_sources: Optional[dict] = None,
) -> tuple[DifferentialVerdict, Observation]:
    from urllib.parse import urlencode
    mal_params = build_p_mal(baseline_params, param, payload, mode=mutate_mode)
    if param_sources:
        get_p = {k: str(v) for k, v in mal_params.items()
                 if (param_sources or {}).get(k) == "GET"}
        post_p = {k: str(v) for k, v in mal_params.items()
                  if (param_sources or {}).get(k) != "GET"}
        mal_body = urlencode(post_p)
        get_query = urlencode(get_p)
        method = "GET" if (get_p and not post_p) else http_method
    else:
        mal_body = urlencode({k: str(v) for k, v in mal_params.items()})
        get_query = ""
        method = http_method
    mal = observe(
        label=f"mal[{param}={payload!r}]",
        container=container, entry_url=entry_url, body=mal_body,
        extra_headers=extra_headers, sentinel_uuid=sentinel_uuid,
        http_method=method, get_query=get_query,
        override_keys={param},
    )
    return diff(baseline_observation, mal), mal


def time_channel_confirmed(
    safe: Observation, mal: Observation, *, threshold_ms: int = 1500
) -> bool:
    if not (safe.sentinel_seen and mal.sentinel_seen):
        return False
    return (mal.elapsed_ms - safe.elapsed_ms) >= threshold_ms


_CSRF_CFG_CACHE: Optional[dict] = None
_CSRF_CFG_LOADED = False


def _load_csrf_cfg() -> Optional[dict]:
    global _CSRF_CFG_CACHE, _CSRF_CFG_LOADED
    if _CSRF_CFG_LOADED:
        return _CSRF_CFG_CACHE
    _CSRF_CFG_LOADED = True
    import os
    path = os.environ.get("VIPER_CSRF_CONFIG", "")
    if not path or not Path(path).is_file():
        return None
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(cfg, dict) or "extract_regex" not in cfg:
            return None
        try:
            pat = re.compile(cfg["extract_regex"])
            if pat.groups < 1:
                return None
        except re.error:
            return None
        cfg.setdefault("field_name", "__csrf_magic")
        cfg.setdefault("applies_to_method", ["POST"])
        _CSRF_CFG_CACHE = cfg
        return cfg
    except Exception:
        return None


def refresh_csrf_token(
    *, get_url: str, cookies: Optional[dict] = None,
    extra_headers: Optional[dict] = None,
) -> Optional[str]:
    cfg = _load_csrf_cfg()
    if not cfg:
        return None
    _strip = cfg.get("token_get_strip_params") or []
    if _strip:
        try:
            from urllib.parse import (urlsplit, urlunsplit,
                                      parse_qsl, urlencode)
            _sp = urlsplit(get_url)
            _q = [(k, v) for k, v in parse_qsl(_sp.query, keep_blank_values=True)
                  if k not in _strip]
            get_url = urlunsplit(
                (_sp.scheme, _sp.netloc, _sp.path, urlencode(_q), _sp.fragment))
        except Exception:
            pass
    cmd = ["curl", "-sS", "-m", "5", "--noproxy", "*", get_url]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        cmd += ["-H", f"Cookie: {cookie_str}"]
    if extra_headers:
        for k, v in extra_headers.items():
            if k.lower() == "cookie" and cookies:
                continue
            cmd += ["-H", f"{k}: {v}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                              encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return None
    body = (proc.stdout or "") + (proc.stderr or "")
    m = re.compile(cfg["extract_regex"]).search(body)
    import os as _os
    if _os.environ.get("VIPER_DUMP_REQUEST") == "1":
        _ck = cookies or next((v for k, v in (extra_headers or {}).items()
                               if k.lower() == "cookie"), "")
        print(f"  [csrf-dbg] GET {get_url[:75]} resp_len={len(body)} "
              f"token={'yes' if m else 'NO'} login_page={'login_username' in body.lower()} "
              f"cookie={str(_ck)[:45]}")
    if not m:
        return None
    return m.group(1)


def maybe_inject_csrf(
    *, post_body: str, http_method: str,
    get_url: str, cookies: Optional[dict] = None,
    extra_headers: Optional[dict] = None,
) -> str:
    cfg = _load_csrf_cfg()
    if not cfg:
        return post_body
    if http_method.upper() not in [m.upper() for m in cfg["applies_to_method"]]:
        return post_body
    token = refresh_csrf_token(
        get_url=get_url, cookies=cookies, extra_headers=extra_headers)
    if not token:
        return post_body
    header_name = cfg.get("header_name")
    if header_name:
        if extra_headers is not None:
            extra_headers[header_name] = token
        return post_body
    import urllib.parse as _up
    field = cfg['field_name']
    new_kv = f"{field}={_up.quote(token, safe='')}"
    if post_body:
        kept = [kv for kv in post_body.split('&')
                if kv and '=' in kv and kv.split('=', 1)[0] != field]
        if kept:
            new_body = new_kv + '&' + '&'.join(kept)
        else:
            new_body = new_kv
    else:
        new_body = new_kv
    return new_body
