
from __future__ import annotations

from typing import Callable, Iterable, Optional
from urllib.parse import urlencode

from .route_ir import EntryURLCandidate, Route


def lookup(
    sink_file: str,
    sink_line: int,
    routes: list[Route],
    *,
    base_url: str = "",
    call_graph_resolver: Optional[Callable[[str, int], Iterable[tuple[str, int, list[str]]]]] = None,
) -> list[EntryURLCandidate]:
    direct = list(_direct_hits(sink_file, sink_line, routes, base_url))
    indirect: list[EntryURLCandidate] = []
    if call_graph_resolver is not None:
        for handler_file, handler_line, chain in call_graph_resolver(sink_file, sink_line):
            for cand in _direct_hits(handler_file, handler_line, routes, base_url):
                cand.hit_kind = "indirect"
                cand.indirect_path = list(chain)
                indirect.append(cand)
    return _dedupe(direct + indirect)


def _direct_hits(
    sink_file: str,
    sink_line: int,
    routes: list[Route],
    base_url: str,
) -> Iterable[EntryURLCandidate]:
    for r in routes:
        h = r.handler_locator
        if not h.file:
            continue
        if h.file != sink_file:
            continue
        if not h.contains_line(sink_line):
            continue
        yield _materialize(r, base_url)


def _materialize(route: Route, base_url: str) -> EntryURLCandidate:
    path_params = {
        p.name: f"__{p.name.upper()}__"
        for p in route.param_sources
        if p.channel == "path"
    }
    url_path = route.url_pattern
    for name, placeholder in path_params.items():
        url_path = url_path.replace("{" + name + "}", placeholder)
        url_path = url_path.replace("{" + name + "?}", placeholder)

    materialized = (base_url.rstrip("/") if base_url else "") + url_path

    prefilled: dict[str, list[str]] = {}
    required: list[str] = []
    for p in route.param_sources:
        if p.channel == "path":
            continue
        prefilled.setdefault(p.name, [])
        if p.examples:
            for ex in p.examples:
                if ex not in prefilled[p.name]:
                    prefilled[p.name].append(ex)
        if p.required and p.name not in required:
            required.append(p.name)

    if route.http_method in ("GET", "ANY"):
        sample = {
            name: vals[0]
            for name, vals in prefilled.items()
            if vals
        }
        if sample:
            sep = "&" if "?" in materialized else "?"
            materialized = materialized + sep + urlencode(sample)

    method = route.http_method
    if method == "ANY":
        method = "GET"

    return EntryURLCandidate(
        http_method=method,
        url_pattern=route.url_pattern,
        materialized_url=materialized,
        path_params=path_params,
        prefilled_params=prefilled,
        required_params=required,
        auth_constraints=list(route.auth_constraints),
        hit_kind="direct",
        source_route=route,
    )


def _dedupe(cands: list[EntryURLCandidate]) -> list[EntryURLCandidate]:
    seen: set[tuple[str, str]] = set()
    out: list[EntryURLCandidate] = []
    for c in cands:
        key = (c.http_method, c.url_pattern)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out
