
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import (
    extract_routes,
    load_schema,
    lookup,
)
from VIPER.framework_routing.schema import detect_framework


PROJECT_ROOT = Path("/home/user/research/Predator/working/openemr-source/openemr")
SINK_FILE = "interface/main/messages/messages.php"
SINK_LINE = 743

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "flat_php.yaml"


def main() -> int:
    fingerprint = detect_framework(PROJECT_ROOT)
    print(f"detect_framework -> {fingerprint!r}")

    schema = load_schema(SCHEMA_PATH)
    print(f"loaded schema: {schema.framework} (version_range={schema.version_range})")

    schema.extras["web_root"] = "."

    routes = extract_routes(PROJECT_ROOT, schema)
    print(f"extracted {len(routes)} routes")

    routes_for_sink = [r for r in routes if r.handler_locator.file == SINK_FILE]
    print(f"routes whose handler_locator.file == sink_file: {len(routes_for_sink)}")
    if routes_for_sink:
        r = routes_for_sink[0]
        print(f"  url_pattern = {r.url_pattern}")
        print(
            f"  param_sources sample = "
            f"{[(p.channel, p.name) for p in r.param_sources[:8]]}"
        )

    cands = lookup(SINK_FILE, SINK_LINE, routes, base_url="http://localhost")
    print(f"lookup found {len(cands)} entry URL candidate(s)")
    for c in cands[:3]:
        print(json.dumps(c.to_dict(), indent=2, ensure_ascii=False, default=str)[:1500])
    return 0 if cands else 1


if __name__ == "__main__":
    raise SystemExit(main())
