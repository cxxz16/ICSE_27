
import json
import re
import subprocess
import urllib.request
import argparse
from urllib.parse import urlencode, urljoin


def login(container_name: str, login_config: dict) -> str:
    url      = login_config['url']
    get_data = login_config.get('getData', '')
    if get_data:
        url += f"?{get_data}"
    post_data = login_config.get('postData', '')

    cmd = [
        "docker", "exec", container_name,
        "curl", "-s", "-i", "-X", "POST",
        "-d", post_data,
        url,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    output = result.stdout

    cookies_dict = {}
    for line in output.splitlines():
        if line.lower().startswith("set-cookie:"):
            cookie_val = line.split(":", 1)[1].strip()
            for part in cookie_val.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies_dict[k.strip()] = v.strip()

    if not cookies_dict:
        raise RuntimeError(
            f"Login failed — no Set-Cookie in response.\n"
            f"stdout={output[:300]}\nstderr={result.stderr[:200]}"
        )

    login_cookie = "; ".join(f"{k}={v}" for k, v in cookies_dict.items())

    session_id = cookies_dict.get(login_config.get('loginSessionCookie', 'OpenEMR'), '')
    if session_id:
        subprocess.run(
            ["docker", "exec", container_name,
             "chmod", "666", f"/tmp/sess_{session_id}"],
            capture_output=True,
        )

    print(f"[tester] login ok  LOGIN_COOKIE={login_cookie[:40]}...")
    return login_cookie


def make_stdin(get_params: str, post_params: str) -> bytes:
    return f"\x00{get_params}\x00{post_params}\x00".encode()


def run_variant(
    container_name:  str,
    script_filename: str,
    login_cookie:    str,
    post_params:     str,
    get_params:      str = "",
) -> dict:
    stdin_bytes = make_stdin(get_params, post_params)

    cmd = [
        "docker", "exec", "-i", "-u", "www-data", container_name,
        "env",
        "STRICT=1",
        "LD_PRELOAD=/wclibs/lib_db_fault_escalator.so",
        "LD_LIBRARY_PATH=/wclibs",
        f"LOGIN_COOKIE={login_cookie}",
        "REQUEST_METHOD=POST",
        "CONTENT_TYPE=application/x-www-form-urlencoded",
        f"CONTENT_LENGTH={len(post_params.encode())}",
        f"SCRIPT_FILENAME={script_filename}",
        f"SCRIPT_NAME={script_filename}",
        "DOCUMENT_ROOT=/var/www/html",
        "SERVER_NAME=localhost",
        "/usr/local/bin/php-cgi",
    ]

    try:
        result = subprocess.run(cmd, input=stdin_bytes, capture_output=True, timeout=15)
        rc = result.returncode
        triggered = (rc == 139) or (rc < 0 and abs(rc) == 11)
        return {
            'triggered':  triggered,
            'returncode': rc,
            'stdout':     result.stdout.decode('utf-8', errors='replace')[:300],
            'stderr':     result.stderr.decode('utf-8', errors='replace')[:200],
        }
    except subprocess.TimeoutExpired:
        return {'triggered': False, 'returncode': None, 'error': 'timeout'}
    except Exception as e:
        return {'triggered': False, 'returncode': None, 'error': str(e)}


def test_variants(
    variants:       list[dict],
    constraints:    dict,
    witcher_config: dict,
    container_name: str,
    base_url:       str,
    webroot:        str = "/var/www/html",
) -> list[dict]:
    entry_url    = constraints['entry_url']
    login_config = witcher_config.get('direct', {})

    path_part   = entry_url.split('localhost', 1)[-1]
    script_path = webroot.rstrip('/') + path_part

    login_cookie = login(container_name, login_config)

    results = []
    for i, params in enumerate(variants):
        post_str = urlencode(params)
        res = run_variant(
            container_name  = container_name,
            script_filename = script_path,
            login_cookie    = login_cookie,
            post_params     = post_str,
        )
        triggered = res.get('triggered', False)
        flag = "✅ SIGSEGV — SQLi TRIGGERED" if triggered else "   "
        print(
            f"  [{i:02d}] {flag}  rc={res.get('returncode')}  "
            f"payload={post_str[:80]}"
        )
        results.append({'index': i, 'params': params, 'post_data': post_str, **res})

    triggered_list = [r for r in results if r.get('triggered')]
    print(f"\n[tester] {len(triggered_list)}/{len(variants)} triggered oracle")
    return results


def main():
    parser = argparse.ArgumentParser(description='VIPER tester (Predator oracle)')
    parser.add_argument('--variants',        required=True)
    parser.add_argument('--constraints',     required=True)
    parser.add_argument('--witcher-config',  required=True)
    parser.add_argument('--container',       default='openemr-vul1')
    parser.add_argument('--base-url',        default='http://localhost:18091')
    parser.add_argument('--output', '-o',    default=None)
    args = parser.parse_args()

    variants       = json.load(open(args.variants))
    constraints    = json.load(open(args.constraints))
    witcher_config = json.load(open(args.witcher_config))

    print(f"[tester] container={args.container}  variants={len(variants)}")
    results = test_variants(
        variants, constraints, witcher_config,
        container_name = args.container,
        base_url       = args.base_url,
    )
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[tester] saved to {args.output}")


if __name__ == '__main__':
    main()
