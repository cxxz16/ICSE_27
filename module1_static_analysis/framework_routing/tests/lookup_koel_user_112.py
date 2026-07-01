
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[3]))

from VIPER.framework_routing import extract_routes, load_schema, lookup

PROJECT = Path("/home/user/research/Predator/working/real-world-apps/koel")
SCHEMA = _HERE.parents[1] / "knowledge" / "laravel.yaml"

if len(sys.argv) >= 3:
    SINK_FILE = sys.argv[1]
    SINK_LINE = int(sys.argv[2])
else:
    SINK_FILE = "app/Models/Song.php"
    SINK_LINE = 132

MAX_HOPS = 4


def enclosing_method(path: Path, line: int) -> tuple[str, int, int] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    offset = sum(len(l) for l in lines[: line - 1])
    fn_re = re.compile(r"(?:public|protected|private)\s+(?:static\s+)?function\s+(\w+)\s*\(")
    matches = list(fn_re.finditer(text, 0, offset))
    if not matches:
        return None
    m = matches[-1]
    name = m.group(1)
    brace_open = text.find("{", m.end())
    depth = 1
    i = brace_open + 1
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    start_line = text.count("\n", 0, m.start()) + 1
    end_line = text.count("\n", 0, i) + 1
    return name, start_line, end_line


def grep_callers(method_name: str) -> list[tuple[str, int]]:
    try:
        out = subprocess.check_output(
            [
                "grep", "-rn",
                "-E", rf"(->|::){re.escape(method_name)}\(",
                str(PROJECT / "app"),
            ],
            text=True,
        )
    except subprocess.CalledProcessError:
        return []
    callers = []
    for hit in out.strip().splitlines():
        parts = hit.split(":", 2)
        if len(parts) < 3:
            continue
        file_abs, lineno_s, _ = parts
        try:
            lineno = int(lineno_s)
        except ValueError:
            continue
        rel = Path(file_abs).relative_to(PROJECT).as_posix()
        if rel == SINK_FILE:
            continue
        callers.append((rel, lineno))
    return callers


def call_graph_resolver(file_path: str, line: int) -> Iterable[tuple[str, int, list[str]]]:
    seen: set[tuple[str, str]] = set()
    frontier: list[tuple[str, int, list[str]]] = [(file_path, line, [])]
    hop = 0
    while frontier and hop < MAX_HOPS:
        hop += 1
        next_frontier: list[tuple[str, int, list[str]]] = []
        for cur_file, cur_line, chain in frontier:
            info = enclosing_method(PROJECT / cur_file, cur_line)
            if not info:
                continue
            method_name, _, _ = info
            key = (cur_file, method_name)
            if key in seen:
                continue
            seen.add(key)
            callers = grep_callers(method_name)
            print(f"  [hop {hop}] `{method_name}()` at {cur_file}:{cur_line} ← {len(callers)} caller(s)")
            for caller_file, caller_line in callers:
                new_chain = chain + [f"{cur_file}:{cur_line} ← {caller_file}:{caller_line} ({method_name})"]
                yield caller_file, caller_line, new_chain
                next_frontier.append((caller_file, caller_line, new_chain))
        frontier = next_frontier


schema = load_schema(SCHEMA)
routes = extract_routes(PROJECT, schema)
print(f"extracted {len(routes)} routes from Koel\n")

direct = lookup(SINK_FILE, SINK_LINE, routes, base_url="http://localhost")
print(f"=== Direct lookup of {SINK_FILE}:{SINK_LINE} ===")
print(f"  {len(direct)} candidate(s) — Models are never handler files, expected 0")

print(f"\n=== Indirect lookup via call-graph resolver ===")
indirect = lookup(
    SINK_FILE, SINK_LINE, routes,
    base_url="http://localhost",
    call_graph_resolver=call_graph_resolver,
)
print(f"\n  {len(indirect)} entry URL(s) reach this sink:")
for c in indirect:
    print(
        f"    {c.http_method} {c.materialized_url}  "
        f"auth={[a.name for a in c.auth_constraints]}  "
        f"chain={c.indirect_path}"
    )
if not indirect:
    print("    (none — sink is not reachable from any HTTP route)")
