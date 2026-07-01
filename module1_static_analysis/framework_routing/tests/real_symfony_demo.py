
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup
from VIPER.framework_routing.schema import detect_framework


PROJECT = Path("/home/user/research/Predator/working/real-world-apps/symfony-demo")
SCHEMA_PATH = _HERE.parents[1] / "knowledge" / "symfony.yaml"


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

    print("\nFirst 25 routes:")
    for r in routes[:25]:
        h = r.handler_locator
        print(
            f"  {r.http_method:6s} {r.url_pattern:50s} -> "
            f"{(h.file or '(unresolved)') + ':' + str(h.line_start)}  "
            f"auth={[a.name for a in r.auth_constraints]}"
        )

    blog = "src/Controller/BlogController.php"
    print(f"\nRoutes hitting {blog}:")
    for r in routes:
        if r.handler_locator.file == blog:
            print(f"  {r.http_method:6s} {r.url_pattern:40s} -> :{r.handler_locator.line_start}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
