from __future__ import annotations
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup

PROJECT = Path("/home/user/research/Predator/working/real-world-apps/koel")
SCHEMA = _HERE.parents[1] / "knowledge" / "laravel.yaml"
SINK_FILE = "app/Http/Controllers/API/FavoriteController.php"
SINK_LINE = 45

schema = load_schema(SCHEMA)
routes = extract_routes(PROJECT, schema)
print(f"extracted {len(routes)} routes from Koel\n")

cands = lookup(SINK_FILE, SINK_LINE, routes, base_url="http://localhost")
print(f"Lookup {SINK_FILE}:{SINK_LINE} -> {len(cands)} candidate(s)")
for c in cands:
    print(f"\n  {c.http_method} {c.materialized_url}")
    print(f"    auth         = {[a.name for a in c.auth_constraints]}")
    print(f"    path params  = {c.path_params}")
    print(f"    prefilled    = {c.prefilled_params}")
    print(f"    required     = {c.required_params}")
    print(f"    handler line = {c.source_route.handler_locator.line_start}-{c.source_route.handler_locator.line_end}")
