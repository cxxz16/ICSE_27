from __future__ import annotations
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup

PROJECT = Path("/home/user/research/Predator/working/real-world-apps/koel")
SCHEMA = _HERE.parents[1] / "knowledge" / "laravel.yaml"
SINK_FILE = "app/Http/Controllers/API/MovePlaylistSongsController.php"
SINK_LINE = 15

schema = load_schema(SCHEMA)
routes = extract_routes(PROJECT, schema)
print(f"INPUT:   sink = {SINK_FILE}:{SINK_LINE}")
print(f"INDEX:   {len(routes)} routes extracted from project\n")

cands = lookup(SINK_FILE, SINK_LINE, routes, base_url="http://localhost:8088")
print(f"OUTPUT:  {len(cands)} entry URL candidate(s)\n")
for i, c in enumerate(cands, 1):
    print(f"  [{i}] {c.http_method} {c.materialized_url}")
    print(f"      auth         = {[a.name for a in c.auth_constraints]}")
    print(f"      path_params  = {c.path_params}")
    print(f"      handler line = {c.source_route.handler_locator.line_start}–{c.source_route.handler_locator.line_end}")
    print(f"      declared at  = {c.source_route.origin.declared_at}")
