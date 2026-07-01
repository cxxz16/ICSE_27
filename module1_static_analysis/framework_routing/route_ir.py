
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Literal, Optional


HttpMethod = Literal[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"
]

HandlerKind = Literal["function", "method", "closure", "invokable", "file"]

ParamChannel = Literal[
    "path", "query", "body_form", "body_json", "header", "cookie"
]

AuthKind = Literal[
    "middleware", "guard", "decorator", "manual_check", "none"
]


@dataclass
class RouteOrigin:
    declared_at: tuple[str, int]
    declaration_kind: str
    inherited_from: list["RouteOrigin"] = field(default_factory=list)


@dataclass
class HandlerRef:
    kind: HandlerKind
    file: str
    symbol: Optional[str] = None
    class_fqcn: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    def contains_line(self, line: int) -> bool:
        if self.kind == "file":
            return True
        if self.line_start is None or self.line_end is None:
            return False
        return self.line_start <= line <= self.line_end


@dataclass
class ParamSource:
    channel: ParamChannel
    name: str
    required: bool = False
    type_hint: Optional[str] = None
    examples: list[str] = field(default_factory=list)
    declared_at: Optional[tuple[str, int]] = None


@dataclass
class AuthHint:
    kind: AuthKind
    name: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class Route:
    http_method: HttpMethod
    url_pattern: str
    handler_locator: HandlerRef
    pattern_constraints: dict[str, str] = field(default_factory=dict)
    auth_constraints: list[AuthHint] = field(default_factory=list)
    param_sources: list[ParamSource] = field(default_factory=list)
    origin: Optional[RouteOrigin] = None

    def key(self) -> tuple[str, str]:
        return (self.http_method, self.url_pattern)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntryURLCandidate:
    http_method: HttpMethod
    url_pattern: str
    materialized_url: str
    path_params: dict[str, str] = field(default_factory=dict)
    prefilled_params: dict[str, list[str]] = field(default_factory=dict)
    required_params: list[str] = field(default_factory=list)
    auth_constraints: list[AuthHint] = field(default_factory=list)
    hit_kind: Literal["direct", "indirect"] = "direct"
    source_route: Optional[Route] = None
    indirect_path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.source_route is not None:
            d["source_route"] = self.source_route.to_dict()
        return d


RFC_RESTFUL_7: list[dict[str, Any]] = [
    {"method": "GET",    "url_suffix": "",            "action": "index"},
    {"method": "GET",    "url_suffix": "/create",     "action": "create"},
    {"method": "POST",   "url_suffix": "",            "action": "store"},
    {"method": "GET",    "url_suffix": "/{id}",       "action": "show"},
    {"method": "GET",    "url_suffix": "/{id}/edit",  "action": "edit"},
    {"method": "PUT",    "url_suffix": "/{id}",       "action": "update"},
    {"method": "DELETE", "url_suffix": "/{id}",       "action": "destroy"},
]

RFC_RESTFUL_5_API: list[dict[str, Any]] = [
    e for e in RFC_RESTFUL_7 if e["action"] not in ("create", "edit")
]


def concat_url(*parts: str) -> str:
    cleaned = [p for p in parts if p]
    if not cleaned:
        return "/"
    keep_trailing = cleaned[-1].endswith("/")
    joined = "/".join(p.strip("/") for p in cleaned)
    out = "/" + joined if not joined.startswith("/") else joined
    while "//" in out:
        out = out.replace("//", "/")
    if not out.startswith("/"):
        out = "/" + out
    if keep_trailing and not out.endswith("/"):
        out = out + "/"
    return out
