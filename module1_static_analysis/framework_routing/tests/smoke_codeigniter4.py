
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup
from VIPER.framework_routing.schema import detect_framework


FIXTURE = _HERE.parent / "fixtures" / "ci4_demo"
SCHEMA_PATH = _HERE.parents[1] / "knowledge" / "codeigniter4.yaml"


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
            f"  {r.http_method:6s} {r.url_pattern:36s}  "
            f"-> {h.file or '(closure)'}:{h.line_start}  "
            f"auth={[a.name for a in r.auth_constraints]}"
        )

    sink_file = "app/Controllers/UserController.php"
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

    photos_file = "app/Controllers/Photos.php"
    photos_line = find_line(FIXTURE / photos_file, "$value = $this->request->getPost")
    print(f"\nsink = {photos_file}:{photos_line}")
    cands2 = lookup(photos_file, photos_line, routes, base_url="http://localhost")
    print(f"lookup -> {len(cands2)} candidate(s)")
    for c in cands2:
        print(f"  {c.http_method:6s} {c.materialized_url}  auth={[a.name for a in c.auth_constraints]}")

    admin_file = "app/Controllers/Admin/Settings.php"
    admin_line = find_line(FIXTURE / admin_file, "$value = $this->request->getPost")
    print(f"\nsink = {admin_file}:{admin_line}")
    cands3 = lookup(admin_file, admin_line, routes, base_url="http://localhost")
    print(f"lookup -> {len(cands3)} candidate(s)")
    for c in cands3:
        print(f"  {c.http_method:6s} {c.materialized_url}  auth={[a.name for a in c.auth_constraints]}")

    return 0 if cands and cands2 and cands3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
