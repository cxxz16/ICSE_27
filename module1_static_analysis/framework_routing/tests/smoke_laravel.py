
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup
from VIPER.framework_routing.schema import detect_framework


FIXTURE = _HERE.parent / "fixtures" / "laravel_demo"
SCHEMA_PATH = _HERE.parents[1] / "knowledge" / "laravel.yaml"


def main() -> int:
    print(f"detect_framework -> {detect_framework(FIXTURE)!r}")
    schema = load_schema(SCHEMA_PATH)
    routes = extract_routes(FIXTURE, schema)
    print(f"extracted {len(routes)} routes")
    for r in routes:
        h = r.handler_locator
        print(
            f"  {r.http_method:6s} {r.url_pattern:40s}  "
            f"-> {h.file or '(closure)'}:{h.line_start}  "
            f"auth={[a.name for a in r.auth_constraints]}"
        )

    sink_file = "app/Http/Controllers/UserController.php"
    target_text = "echo $name;"
    sink_path = FIXTURE / sink_file
    with sink_path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if target_text in line:
                sink_line = lineno
                break
        else:
            print("FAIL: sink line not found in fixture")
            return 1
    print(f"\nsink = {sink_file}:{sink_line}")

    cands = lookup(sink_file, sink_line, routes, base_url="http://localhost")
    print(f"lookup found {len(cands)} candidate(s)")
    for c in cands:
        print(json.dumps(
            {
                "method": c.http_method,
                "url": c.materialized_url,
                "auth": [a.name for a in c.auth_constraints],
                "prefilled": c.prefilled_params,
                "required": c.required_params,
            },
            indent=2,
            ensure_ascii=False,
        ))

    settings_file = "app/Http/Controllers/Admin/SettingsController.php"
    with (FIXTURE / settings_file).open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if "$value = $request->input" in line:
                settings_line = lineno
                break
    cands2 = lookup(settings_file, settings_line, routes, base_url="http://localhost")
    print(f"\nsettings sink = {settings_file}:{settings_line}")
    print(f"  {len(cands2)} candidate(s)")
    for c in cands2:
        print(f"  {c.http_method:6s} {c.materialized_url}  auth={[a.name for a in c.auth_constraints]}")

    return 0 if cands and cands2 else 1


if __name__ == "__main__":
    raise SystemExit(main())
