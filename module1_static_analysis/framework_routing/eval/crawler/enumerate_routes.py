from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("requests is required: pip install requests", file=sys.stderr)
    sys.exit(1)


_ID_NAMES = {
    "id", "uid", "user_id", "post_id",
    "user", "post", "album", "artist", "song", "playlist", "playlistfolder",
    "genre", "tag", "podcast", "episode", "station", "preset", "comment",
    "queue", "folder", "subfolder", "thumbnail", "_format",
}
_SLUG_NAMES = {"slug", "name", "path", "tag", "category"}


def synth_value(name: str) -> str:
    n = name.lower().lstrip("_").rstrip("?")
    if n in {"locale", "_locale"}:
        return "en"
    if "uuid" in n:
        return "00000000-0000-0000-0000-000000000001"
    if n in _SLUG_NAMES:
        return "demo"
    if n in _ID_NAMES:
        return "1"
    return "1"


def materialize(uri: str) -> str:
    def repl(m: re.Match) -> str:
        token = m.group(1)
        token = token.split(":", 1)[0].split("<", 1)[0]
        return synth_value(token)
    return re.sub(r"\{([^}]+?)\}", repl, uri.lstrip("/"))


def fetch_routes_laravel(container: str) -> list[dict]:
    out = subprocess.check_output(
        ["docker", "exec", container, "php", "artisan", "route:list", "--json"],
        text=True,
    )
    return json.loads(out)


def fetch_routes_symfony(container: str) -> list[dict]:
    out = subprocess.check_output(
        ["docker", "exec", container, "php", "bin/console",
         "debug:router", "--format=json", "--show-controllers"],
        text=True,
    )
    data = json.loads(out)
    rows: list[dict] = []
    for name, body in data.items():
        path = body.get("path") or body.get("pathRegex") or ""
        method = body.get("method") or "ANY"
        rows.append({"name": name, "uri": path, "method": method})
    return rows


def explode_methods(field: str) -> list[str]:
    chunks: list[str] = []
    for piece in (field or "").replace(",", "|").split("|"):
        m = piece.strip().upper()
        if not m or m in {"HEAD", "ANY"}:
            continue
        chunks.append(m)
    if not chunks:
        chunks.append("GET")
    return chunks


SKIP_URI_PREFIXES = (
    "_profiler", "/_profiler",
    "_wdt", "/_wdt",
    "_error", "/_error",
    "_fragment", "/_fragment",
)


def main():
    ap = argparse.ArgumentParser(__doc__)
    ap.add_argument("--target", choices=["laravel", "symfony"], required=True)
    ap.add_argument("--container", required=True, help="docker container name")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--auth-header", default=None,
                    help='e.g. "Authorization: Bearer ..."')
    ap.add_argument("--cookie", default=None, help='raw Cookie header value')
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--skip", action="append", default=[],
                    help="additional URI prefix to skip (repeatable)")
    ap.add_argument("--limit", type=int, default=0,
                    help="dev: only hit first N routes (0=all)")
    args = ap.parse_args()

    if args.target == "laravel":
        routes = fetch_routes_laravel(args.container)
    else:
        routes = fetch_routes_symfony(args.container)
    print(f"[*] {len(routes)} routes returned by {args.target}")

    sess = requests.Session()
    sess.trust_env = False
    headers: dict[str, str] = {}
    if args.auth_header:
        k, _, v = args.auth_header.partition(":")
        headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    skip_prefixes = SKIP_URI_PREFIXES + tuple(args.skip)
    stats = {"ok": 0, "fail": 0, "skipped": 0}
    methods_hit: dict[str, int] = {}
    sample_errs: list[str] = []

    for i, r in enumerate(routes):
        if args.limit and i >= args.limit:
            break
        uri = r.get("uri") or r.get("path") or ""
        if not uri or uri.lstrip("/").startswith(skip_prefixes) \
           or uri.startswith(skip_prefixes):
            stats["skipped"] += 1
            continue
        methods = explode_methods(r.get("method") or r.get("methods", ""))
        concrete = materialize(uri)
        full = args.base_url.rstrip("/") + "/" + concrete
        for method in methods:
            try:
                kwargs = dict(headers=headers, timeout=args.timeout,
                              verify=False, allow_redirects=False)
                if method != "GET":
                    kwargs["data"] = ""
                sess.request(method, full, **kwargs)
                methods_hit[method] = methods_hit.get(method, 0) + 1
                stats["ok"] += 1
            except requests.RequestException as e:
                stats["fail"] += 1
                if len(sample_errs) < 5:
                    sample_errs.append(f"{method} {full}: {type(e).__name__}: {e}")

    print(f"[done] hit={stats['ok']}  fail={stats['fail']}  skipped={stats['skipped']}")
    print(f"       by-method: {dict(sorted(methods_hit.items()))}")
    if sample_errs:
        print("[sample errors]")
        for e in sample_errs:
            print(f"  {e}")


if __name__ == "__main__":
    main()
