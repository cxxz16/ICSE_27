
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup
from VIPER.framework_routing.schema import detect_framework


FIXTURE = _HERE.parent / "fixtures" / "symfony_demo"
SCHEMA_PATH = _HERE.parents[1] / "knowledge" / "symfony.yaml"


def find_line(path: Path, needle: str) -> int:
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if needle in line:
                return lineno
    raise RuntimeError(f"needle {needle!r} not found in {path}")


def main() -> int:
    print(f"detect_framework -> {detect_framework(FIXTURE)!r}")

    schema = load_schema(SCHEMA_PATH)
    routes = extract_routes(FIXTURE, schema)
    print(f"extracted {len(routes)} routes")
    for r in routes:
        h = r.handler_locator
        print(
            f"  {r.http_method:6s} {r.url_pattern:32s}  "
            f"-> {h.file or '(closure)'}:{h.line_start}  "
            f"auth={[a.name for a in r.auth_constraints]}"
        )

    sink_file = "src/Controller/UserController.php"
    sink_line = find_line(FIXTURE / sink_file, "echo $name;")
    print(f"\nsink = {sink_file}:{sink_line}")
    cands = lookup(sink_file, sink_line, routes, base_url="http://localhost")
    print(f"lookup -> {len(cands)} candidate(s)")
    for c in cands:
        print(json.dumps(
            {
                "method": c.http_method,
                "url": c.materialized_url,
                "auth": [a.name for a in c.auth_constraints],
                "prefilled": c.prefilled_params,
            },
            indent=2, ensure_ascii=False,
        ))

    sink2 = "src/Controller/Admin/ProductController.php"
    sink2_line = find_line(FIXTURE / sink2, "$value = $request->request->get")
    print(f"\nsink = {sink2}:{sink2_line}")
    cands2 = lookup(sink2, sink2_line, routes, base_url="http://localhost")
    print(f"lookup -> {len(cands2)} candidate(s)")
    for c in cands2:
        print(f"  {c.http_method:6s} {c.materialized_url}  auth={[a.name for a in c.auth_constraints]}")

    sink3 = "src/Controller/HealthController.php"
    sink3_line = find_line(FIXTURE / sink3, "'status' => 'ok'")
    print(f"\nsink = {sink3}:{sink3_line}")
    cands3 = lookup(sink3, sink3_line, routes, base_url="http://localhost")
    print(f"lookup -> {len(cands3)} candidate(s)")
    for c in cands3:
        print(f"  {c.http_method:6s} {c.materialized_url}  auth={[a.name for a in c.auth_constraints]}")

    return 0 if cands and cands2 and cands3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
