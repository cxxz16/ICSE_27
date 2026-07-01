
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit


def _exec(container: str, sh: str) -> str:
    try:
        p = subprocess.run(
            ["docker", "exec", container, "sh", "-c", sh],
            capture_output=True, text=True, timeout=30,
        )
        return p.stdout or ""
    except Exception:
        return ""


def _served_dir(container: str, url_path: str) -> str | None:
    p = "/" + url_path.strip("/")

    aliases: list[tuple[str, str]] = []
    out = _exec(container,
                "grep -RhiE '^[[:space:]]*Alias[[:space:]]' "
                "/etc/apache2 /etc/httpd 2>/dev/null")
    for line in out.splitlines():
        toks = line.split()
        if len(toks) >= 3 and toks[0].lower() == "alias":
            aliases.append((toks[1].strip('"').rstrip("/"), toks[2].strip('"')))

    container_path: str | None = None
    for fake, real in sorted(aliases, key=lambda x: -len(x[0])):
        if p == fake or p.startswith(fake + "/"):
            container_path = real.rstrip("/") + p[len(fake):]
            break

    if container_path is None:
        docroot = ""
        s = _exec(container, "apache2ctl -S 2>/dev/null; apachectl -S 2>/dev/null")
        for line in s.splitlines():
            if "DocumentRoot:" in line:
                docroot = line.split('"')[1] if '"' in line else line.split(":", 1)[1].strip()
                break
        if not docroot:
            return None
        container_path = docroot.rstrip("/") + "/" + p.lstrip("/")

    rp = _exec(container, f"realpath {shlex.quote(container_path)} 2>/dev/null").strip()
    return rp or container_path


def _trailing_overlap(a: str, b: str) -> int:
    sa, sb = a.strip("/").split("/"), b.strip("/").split("/")
    n = 0
    for x, y in zip(reversed(sa), reversed(sb)):
        if x != y:
            break
        n += 1
    return n


def _container_path_of(container: str, served_dir: str, host_file: str) -> str | None:
    try:
        host_hash = hashlib.md5(open(host_file, "rb").read()).hexdigest()
    except OSError:
        return None
    base = os.path.basename(host_file)
    out = _exec(
        container,
        f"find {shlex.quote(served_dir)} -type f -name {shlex.quote(base)} "
        f"-exec md5sum {{}} + 2>/dev/null",
    )
    cands: list[str] = []
    for line in out.splitlines():
        h, _, path = line.partition("  ")
        if h.strip() == host_hash and path.strip():
            cands.append(path.strip())
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    return max(cands, key=lambda c: _trailing_overlap(c, host_file))


def calibrate(container: str, pipeline_result: str, webroot_url: str) -> dict:
    try:
        d = json.load(open(pipeline_result, encoding="utf-8"))
    except Exception as e:
        return {"status": "skip", "reason": f"cannot read pipeline_result: {e}"}

    _fw_meta = d.get("framework_entry") or (
        d.get("constraints", {}) if isinstance(d.get("constraints"), dict) else {}
    ).get("framework_entry")
    if _fw_meta:
        return {"status": "skip", "old_url": d.get("entry_url"),
                "reason": f"framework entry ({_fw_meta.get('framework')}) — "
                          f"route URL already served-correct"}

    entry_file = d.get("entry_file") or (d.get("sink") or {}).get("file")
    old_url = d.get("entry_url")
    if not entry_file or not old_url:
        return {"status": "skip", "reason": "no entry_file / entry_url"}

    wparts = urlsplit(webroot_url)
    url_prefix = wparts.path

    served = _served_dir(container, url_prefix)
    if not served:
        return {"status": "skip", "old_url": old_url,
                "reason": "could not resolve served dir from Apache config"}

    cpath = _container_path_of(container, served, entry_file)
    if not cpath:
        return {"status": "skip", "old_url": old_url,
                "reason": f"entry file not found under served dir {served} "
                          f"(hash mismatch / not served)"}

    rel = os.path.relpath(cpath, served).replace(os.sep, "/")
    new_path = url_prefix.rstrip("/") + "/" + rel
    op = urlsplit(old_url)
    new_url = urlunsplit((op.scheme or wparts.scheme,
                          op.netloc or wparts.netloc,
                          new_path, op.query, ""))

    if new_url == old_url:
        return {"status": "noop", "old_url": old_url, "new_url": new_url,
                "reason": "already correct"}

    d["entry_url_pre_calib"] = old_url
    d["entry_url"] = new_url
    if isinstance(d.get("constraints"), dict):
        d["constraints"]["entry_url"] = new_url
    try:
        json.dump(d, open(pipeline_result, "w", encoding="utf-8"),
                  indent=2, ensure_ascii=False)
    except Exception as e:
        return {"status": "skip", "old_url": old_url,
                "reason": f"patch write failed: {e}"}
    return {"status": "patched", "old_url": old_url, "new_url": new_url,
            "served_dir": served, "container_file": cpath}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--container", required=True)
    ap.add_argument("--pipeline-result", required=True)
    ap.add_argument("--webroot-url", required=True)
    a = ap.parse_args()
    r = calibrate(a.container, a.pipeline_result, a.webroot_url)
    print(f"[webroot-calib] {r.get('status')}: {r.get('reason', '')}")
    if r.get("status") in ("patched", "noop"):
        print(f"  old: {r.get('old_url')}")
        print(f"  new: {r.get('new_url')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
