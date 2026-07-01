
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup


PROJECT = Path("/home/user/research/Predator/working/real-world-apps/ci4-bonfire")
SCHEMA_PATH = _HERE.parents[1] / "knowledge" / "codeigniter4.yaml"


def main() -> int:
    print(f"project: {PROJECT}")
    schema = load_schema(SCHEMA_PATH)
    routes = extract_routes(PROJECT, schema)
    print(f"extracted {len(routes)} routes")

    by_method = Counter(r.http_method for r in routes)
    print(f"by method: {dict(by_method)}")

    unresolved = [r for r in routes if not r.handler_locator.file]
    print(f"unresolved handlers: {len(unresolved)}/{len(routes)}")

    inferred = [
        r for r in routes
        if r.origin and "resource" in (r.origin.declaration_kind or "")
    ]
    print(f"resource-expanded routes: {len(inferred)}")

    auth_routes = [r for r in routes if r.auth_constraints]
    print(f"auth-bearing routes: {len(auth_routes)}")

    by_file = Counter(
        r.origin.declared_at[0] if r.origin else "?" for r in routes
    )
    print("\nroutes per file (top 8):")
    for f, n in by_file.most_common(8):
        print(f"  {n:3d}  {f}")

    print("\nfirst 15 routes:")
    for r in routes[:15]:
        h = r.handler_locator
        print(
            f"  {r.http_method:6s} {r.url_pattern[:55]:55s} -> "
            f"{(h.file or '(unresolved)')}:{h.line_start}  "
            f"auth={[a.name for a in r.auth_constraints]}"
        )

    print("\nspot-check: routes from src/Users/Config/Routes.php:")
    users_routes = [
        r for r in routes
        if r.origin and "Users" in r.origin.declared_at[0]
    ]
    for r in users_routes:
        h = r.handler_locator
        print(
            f"  {r.http_method:6s} {r.url_pattern[:55]:55s} -> "
            f"{(h.file or '(unresolved)')}:{h.line_start}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
