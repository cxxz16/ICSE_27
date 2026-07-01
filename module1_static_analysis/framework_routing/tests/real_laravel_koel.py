
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup
from VIPER.framework_routing.schema import detect_framework


PROJECT = Path("/home/user/research/Predator/working/real-world-apps/koel")
SCHEMA_PATH = _HERE.parents[1] / "knowledge" / "laravel.yaml"


def main() -> int:
    print(f"project: {PROJECT}")
    print(f"detect_framework -> {detect_framework(PROJECT)!r}")

    schema = load_schema(SCHEMA_PATH)
    routes = extract_routes(PROJECT, schema)
    print(f"extracted {len(routes)} routes\n")

    by_handler_kind = Counter(r.handler_locator.kind for r in routes)
    print(f"handler kinds: {dict(by_handler_kind)}")
    unresolved = sum(1 for r in routes if not r.handler_locator.file)
    print(f"unresolved handlers: {unresolved}/{len(routes)}")

    api_routes = [r for r in routes if r.url_pattern.startswith("/api")]
    print(f"api-prefixed routes: {len(api_routes)}")
    print(f"non-api routes:      {len(routes) - len(api_routes)}")

    auth_routes = [r for r in routes if r.auth_constraints]
    print(f"auth-bearing routes: {len(auth_routes)}")

    print("\nFirst 15 routes (raw):")
    for r in routes[:15]:
        h = r.handler_locator
        print(
            f"  {r.http_method:6s} {r.url_pattern[:60]:60s} -> "
            f"{(h.file or '(unresolved)')}:{h.line_start}  "
            f"auth={[a.name for a in r.auth_constraints]}"
        )

    print("\nLast 10 routes (raw):")
    for r in routes[-10:]:
        h = r.handler_locator
        print(
            f"  {r.http_method:6s} {r.url_pattern[:60]:60s} -> "
            f"{(h.file or '(unresolved)')}:{h.line_start}  "
            f"auth={[a.name for a in r.auth_constraints]}"
        )

    target = "app/Http/Controllers/API/PlaylistController.php"
    if (PROJECT / target).exists():
        with (PROJECT / target).open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if "public function index" in line:
                    sink_line = lineno
                    break
            else:
                sink_line = 0
        if sink_line:
            cands = lookup(target, sink_line, routes)
            print(f"\nLookup {target}:{sink_line}: {len(cands)} candidate(s)")
            for c in cands[:5]:
                print(
                    f"  {c.http_method:6s} {c.materialized_url}  "
                    f"auth={[a.name for a in c.auth_constraints]}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
