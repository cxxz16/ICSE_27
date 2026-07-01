
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .route_ir import (
    AuthHint,
    HandlerRef,
    ParamSource,
    Route,
    RouteOrigin,
    concat_url,
)
from .schema import (
    DeclarationPattern,
    FrameworkSchema,
    HandlerResolution,
    ParamSourceRule,
    RouteLocation,
)


_RESOURCE_SINGULAR_TOKEN = "{__resource_singular__}"


def _singularize(word: str) -> str:
    if not word or len(word) <= 1:
        return word
    lower = word.lower()
    irregular = {
        "people": "person", "children": "child", "men": "man", "women": "woman",
        "teeth": "tooth", "feet": "foot", "geese": "goose", "mice": "mouse",
    }
    if lower in irregular:
        return irregular[lower]
    if lower.endswith("ies") and len(lower) > 3:
        return word[:-3] + "y"
    if lower.endswith("ses") and len(lower) > 3:
        return word[:-2]
    if lower.endswith("s") and not lower.endswith("ss"):
        return word[:-1]
    return word


def _placeholder_name(segment: str, schema: Optional[FrameworkSchema] = None) -> str:
    sing = _singularize(segment)
    if schema is not None:
        sep = schema.extras.get("resource_placeholder_separator")
        if isinstance(sep, str) and sep:
            sing = sing.replace("-", sep)
    return sing


def _decompose_resource_path(
    raw_url: str, schema: Optional[FrameworkSchema] = None
) -> tuple[str, str]:
    segments = [s for s in raw_url.strip("/").split(".") if s]
    if not segments:
        return ("/", "")
    parts: list[str] = []
    for i, seg in enumerate(segments):
        parts.append(seg)
        if i < len(segments) - 1:
            parts.append("{" + _placeholder_name(seg, schema) + "}")
    return ("/" + "/".join(parts), _placeholder_name(segments[-1], schema))


def extract_routes(
    project_root: str | Path,
    schema: FrameworkSchema,
) -> list[Route]:
    root = Path(project_root).resolve()
    strategy = schema.handler_resolution.strategy if schema.handler_resolution else ""
    if strategy == "url_to_path_direct":
        return _extract_flat(root, schema)
    if strategy == "psr4":
        return _extract_psr4(root, schema)
    raise NotImplementedError(
        f"handler_resolution.strategy='{strategy}' is not implemented yet"
    )


def _extract_flat(root: Path, schema: FrameworkSchema) -> list[Route]:
    web_root_key = (
        schema.handler_resolution.options.get("web_root_key", "web_root")
        if schema.handler_resolution
        else "web_root"
    )
    web_root_rel = schema.extras.get(web_root_key, ".")
    web_root = (root / web_root_rel).resolve()

    routes: list[Route] = []
    for loc in schema.route_locations:
        if loc.kind != "file_path_mirror":
            continue
        scan_bases = [(root / p).resolve() for p in (loc.paths or ["."])]
        glob = loc.extra.get("file_glob", "**/*.php")
        excludes = list(loc.extra.get("exclude_globs", []))
        for base in scan_bases:
            if not base.exists():
                continue
            for path in base.glob(glob):
                if not path.is_file():
                    continue
                rel_to_root = path.relative_to(root).as_posix()
                if _matches_any(rel_to_root, excludes):
                    continue
                try:
                    rel_to_web = path.relative_to(web_root).as_posix()
                except ValueError:
                    continue
                url_pattern = "/" + rel_to_web

                handler = HandlerRef(
                    kind="file",
                    file=rel_to_root,
                    symbol=None,
                    line_start=None,
                    line_end=None,
                )
                origin = RouteOrigin(
                    declared_at=(rel_to_root, 0),
                    declaration_kind="implicit_file_route",
                )
                file_text = _safe_read(path)
                params = _harvest_params_from_text(
                    file_text, rel_to_root, schema.param_sources
                )
                params.extend(_path_params_from_pattern(url_pattern))
                auth = _detect_manual_auth(file_text, schema)
                routes.append(
                    Route(
                        http_method="ANY",
                        url_pattern=url_pattern,
                        handler_locator=handler,
                        param_sources=params,
                        auth_constraints=auth,
                        origin=origin,
                    )
                )
    return routes


@dataclass
class _RawDecl:
    pattern_id: str
    declared_at: tuple[str, int]
    fields: dict[str, str]
    expand_by: Optional[str]
    declared_line_end: Optional[int] = None
    inherited_prefix: str = ""
    inherited_auth_markers: list[str] = None
    inherited_namespace: str = ""
    inherited_class: Optional[str] = None
    methods_override: Optional[list[str]] = None
    class_inference_strategy: Optional[str] = None
    handler_class_relative: bool = False

    def __post_init__(self):
        if self.inherited_auth_markers is None:
            self.inherited_auth_markers = []


_PROVIDER_GLOBS = (
    "packages/**/*ServiceProvider.php",
    "app/**/*ServiceProvider.php",
    "Modules/**/*ServiceProvider.php",
)
_PREFIX_GROUP_RE = re.compile(
    r"Route::[^;]*?->\s*prefix\s*\(\s*(?P<p>config\s*\([^()]*\)|['\"][^'\"]*['\"])\s*\)"
    r"[^;]*?->\s*group\s*\(\s*(?P<g>[^;]+?)\)\s*;",
    re.DOTALL,
)
_REQUIRE_RE = re.compile(
    r"\b(?:require|require_once|include|include_once)\b\s*\(?\s*"
    r"(?:__DIR__\s*\.\s*)?['\"](?P<path>[^'\"]+)['\"]",
)
_CONFIG_CALL_RE = re.compile(
    r"config\s*\(\s*['\"](?P<key>[^'\"]+)['\"]\s*(?:,\s*(?P<def>['\"][^'\"]*['\"]|[^)]+))?\)"
)
_DIR_STR_RE = re.compile(r"__DIR__\s*\.\s*['\"](?P<p>[^'\"]+)['\"]")


def _resolve_config_value(root: Path, expr: str) -> Optional[str]:
    expr = expr.strip()
    if expr[:1] in "'\"":
        return expr.strip("'\"")
    m = _CONFIG_CALL_RE.search(expr)
    if not m:
        return None
    key = m.group("key")
    inline_def = (m.group("def") or "").strip().strip("'\"") or None
    parts = key.split(".", 1)
    if len(parts) == 2:
        cfile, ckey = parts
        cf = root / "config" / f"{cfile}.php"
        if cf.exists():
            try:
                txt = cf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                txt = ""
            km = re.search(
                rf"['\"]{re.escape(ckey)}['\"]\s*=>\s*"
                rf"(?:env\s*\([^,]+,\s*['\"](?P<envdef>[^'\"]*)['\"]\s*\)"
                rf"|['\"](?P<lit>[^'\"]*)['\"])",
                txt)
            if km:
                return km.group("envdef") or km.group("lit")
    return inline_def


def _expand_require_chain(start: Path, _depth: int = 0) -> list[Path]:
    files: list[Path] = []
    if _depth > 6 or not start.is_file():
        return files
    files.append(start)
    try:
        txt = start.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return files
    for m in _REQUIRE_RE.finditer(txt):
        p = m.group("path")
        if not p.endswith(".php"):
            continue
        child = (start.parent / p.lstrip("/")).resolve()
        for f in _expand_require_chain(child, _depth + 1):
            if f not in files:
                files.append(f)
    return files


def _resolve_provider_prefixes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    seen: set[Path] = set()
    for g in _PROVIDER_GLOBS:
        for prov in root.glob(g):
            if not prov.is_file() or prov in seen:
                continue
            seen.add(prov)
            try:
                txt = prov.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in _PREFIX_GROUP_RE.finditer(txt):
                prefix = _resolve_config_value(root, m.group("p"))
                if not prefix:
                    continue
                gm = _DIR_STR_RE.search(m.group("g"))
                if not gm:
                    continue
                tgt = (prov.parent / gm.group("p").lstrip("/")).resolve()
                for rf in _expand_require_chain(tgt):
                    try:
                        rel = rf.relative_to(root).as_posix()
                    except ValueError:
                        continue
                    out.setdefault(rel, prefix)
    return out


def _extract_psr4(root: Path, schema: FrameworkSchema) -> list[Route]:
    psr4_map = _load_psr4_map(root, schema.handler_resolution) if schema.handler_resolution else {}
    default_ns = (
        schema.handler_resolution.options.get("default_controller_namespace", "")
        if schema.handler_resolution
        else ""
    )

    yaml_decls: list[_RawDecl] = []
    propagated_prefixes: dict[str, list[str]] = {}
    for loc in schema.route_locations:
        if loc.kind != "yaml_routes":
            continue
        propagate_to = list(
            loc.extra.get("propagate_import_prefix_to")
            or loc.extra.get("options", {}).get("propagate_import_prefix_to", [])
            or []
        )
        expanded: list[Path] = []
        for rel in loc.paths:
            if any(c in rel for c in "*?["):
                expanded.extend(p for p in root.glob(rel) if p.is_file())
            else:
                p = root / rel
                if p.exists():
                    expanded.append(p)
        for path in expanded:
            rel_str = path.relative_to(root).as_posix()
            decls, imports = _parse_yaml_routes(rel_str, path)
            yaml_decls.extend(decls)
            if not propagate_to:
                continue
            for imp in imports:
                pref = imp.get("prefix") or ""
                if not pref:
                    continue
                resource = str(imp.get("resource") or "")
                if resource.startswith("@"):
                    continue
                for kind in propagate_to:
                    propagated_prefixes.setdefault(kind, []).append(pref)

    def _apply_propagated(loc_kind: str, decls: list[_RawDecl]) -> None:
        extras = propagated_prefixes.get(loc_kind)
        if not extras:
            return
        combined = ""
        for p in extras:
            combined = concat_url(combined, p)
        for d in decls:
            d.inherited_prefix = concat_url(combined, d.inherited_prefix or "")

    provider_prefixes: dict[str, str] = _resolve_provider_prefixes(root)

    raw_decls: list[_RawDecl] = list(yaml_decls)
    for loc in schema.route_locations:
        if loc.kind == "yaml_routes":
            continue
        if loc.kind == "php_files":
            prefix_overrides: dict[str, str] = dict(loc.extra.get("api_url_prefix", {}) or {})
            for rel in loc.paths:
                path = root / rel
                if not path.exists():
                    continue
                decls = _parse_php_route_file(
                    rel, path, schema.declaration_patterns, schema.grouping,
                    default_namespace=default_ns,
                )
                base_prefix = prefix_overrides.get(rel, "") or provider_prefixes.get(rel, "")
                if base_prefix:
                    for d in decls:
                        d.inherited_prefix = concat_url(base_prefix, d.inherited_prefix or "")
                _apply_propagated(loc.kind, decls)
                raw_decls.extend(decls)
        elif loc.kind == "php_files_glob":
            base = (root / loc.extra.get("base", ".")).resolve()
            glob = loc.extra.get("file_glob", "**/*.php")
            excludes = list(loc.extra.get("exclude_globs", []))
            prefix_overrides: dict[str, str] = dict(
                loc.extra.get("api_url_prefix", {}) or {}
            )
            for path in base.glob(glob):
                if not path.is_file():
                    continue
                rel = path.relative_to(root).as_posix()
                if _matches_any(rel, excludes):
                    continue
                decls = _parse_php_route_file(
                    rel, path, schema.declaration_patterns, schema.grouping,
                    default_namespace=default_ns,
                )
                base_prefix = prefix_overrides.get(rel, "")
                if not base_prefix:
                    for pat, pref in prefix_overrides.items():
                        if fnmatch.fnmatch(rel, pat):
                            base_prefix = pref
                            break
                if not base_prefix:
                    base_prefix = provider_prefixes.get(rel, "")
                if base_prefix:
                    for d in decls:
                        d.inherited_prefix = concat_url(base_prefix, d.inherited_prefix or "")
                _apply_propagated(loc.kind, decls)
                raw_decls.extend(decls)

    class_def_index = _build_class_def_index(root, schema)

    routes: list[Route] = []
    for d in raw_decls:
        for r in _materialize_raw_decl(d, schema, root, psr4_map, class_def_index):
            routes.append(r)
    return routes


def _parse_php_route_file(
    file_rel: str,
    path: Path,
    patterns: list[DeclarationPattern],
    grouping,
    default_namespace: str = "",
) -> list[_RawDecl]:
    text = _safe_read(path)
    if not text:
        return []
    return _parse_declarations_php(
        file_rel, text, patterns, grouping, default_namespace=default_namespace
    )


_USE_RE = re.compile(
    r'^\s*use\s+(?P<fqcn>[A-Za-z_\\][A-Za-z0-9_\\]*)(?:\s+as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?\s*;',
    re.MULTILINE,
)
_NAMESPACE_RE = re.compile(
    r'^\s*namespace\s+(?P<ns>[A-Za-z_\\][A-Za-z0-9_\\]*)\s*;',
    re.MULTILINE,
)


def _collect_use_aliases(text: str) -> dict[str, str]:
    first_class = re.search(r'^\s*(?:final\s+|abstract\s+|readonly\s+)*class\s+\w', text, re.MULTILINE)
    region = text[:first_class.start()] if first_class else text
    aliases: dict[str, str] = {}
    for m in _USE_RE.finditer(region):
        fqcn = m.group("fqcn").lstrip("\\")
        alias = m.group("alias") or fqcn.rsplit("\\", 1)[-1]
        aliases[alias] = fqcn
    return aliases


def _collect_file_namespace(text: str) -> str:
    m = _NAMESPACE_RE.search(text)
    return m.group("ns").lstrip("\\") if m else ""


def _qualify(
    class_name: str,
    use_aliases: dict[str, str],
    file_namespace: str,
    *,
    from_scope: bool,
) -> str:
    if not class_name:
        return class_name
    cn = class_name.lstrip("\\")
    if "\\" in cn:
        return cn
    if cn in use_aliases:
        return use_aliases[cn]
    if from_scope and file_namespace:
        return f"{file_namespace}\\{cn}"
    return cn


def _parse_declarations_php(
    file_rel: str,
    text: str,
    patterns: list[DeclarationPattern],
    grouping,
    default_namespace: str = "",
) -> list[_RawDecl]:
    results: list[_RawDecl] = []
    use_aliases = _collect_use_aliases(text)
    file_namespace = _collect_file_namespace(text)

    _DECL_FLAGS = re.VERBOSE | re.DOTALL
    decl_compiled = []
    for dp in patterns:
        if isinstance(dp.matcher, str):
            decl_compiled.append((dp, re.compile(dp.matcher, _DECL_FLAGS)))
        else:
            decl_compiled.append((dp, None))

    group_compiled = []
    for g in grouping.scope_kinds:
        try:
            group_compiled.append((g, re.compile(g.matcher, _DECL_FLAGS)))
        except re.error:
            continue

    group_spans = []
    for g, rx in group_compiled:
        if rx is None:
            continue
        for m in rx.finditer(text):
            open_pos = m.end()
            brace_open = text.find("{", open_pos)
            if brace_open == -1:
                continue
            depth = 1
            i = brace_open + 1
            while i < len(text) and depth > 0:
                ch = text[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            end = i
            attrs = _extract_group_attrs(
                text[m.start():brace_open + 1], scope=g
            )
            group_spans.append((brace_open + 1, end, attrs))
    group_spans.sort(key=lambda s: (s[0], s[1]))

    def line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    def enclosing_groups(pos: int) -> list[dict[str, Any]]:
        return [attrs for (s, e, attrs) in group_spans if s <= pos < e]

    field_extractor_compiled: dict[str, list[tuple[str, "re.Pattern[str]"]]] = {}
    action_anchor_compiled: dict[str, dict[str, Any]] = {}
    for dp in patterns:
        compiled: list[tuple[str, "re.Pattern[str]"]] = []
        for name, src in dp.field_extractors.items():
            try:
                compiled.append((name, re.compile(src, _DECL_FLAGS)))
            except re.error:
                continue
        field_extractor_compiled[dp.id] = compiled
        if dp.action_anchor:
            try:
                action_anchor_compiled[dp.id] = {
                    "anchor": re.compile(
                        dp.action_anchor["pattern"], _DECL_FLAGS
                    ),
                    "max_distance": int(dp.action_anchor.get("max_distance", 2048)),
                }
            except re.error:
                pass

    for dp, rx in decl_compiled:
        if rx is None:
            continue
        for m in rx.finditer(text):
            fields = dict(m.groupdict())
            fields = {k: v for k, v in fields.items() if v is not None}
            if not fields:
                fields = {f"_{i}": g for i, g in enumerate(m.groups()) if g}

            matched_text = m.group(0)

            ac = action_anchor_compiled.get(dp.id)
            sibling_window = ""
            anchor_m = None
            if ac:
                window = text[m.end():m.end() + ac["max_distance"]]
                fn_kw = re.search(r"\bfunction\s+\w", window)
                if fn_kw:
                    sibling_window = window[: fn_kw.start()]
                anchor_m = ac["anchor"].match(window)
                if not anchor_m:
                    continue

            search_scope = matched_text + sibling_window

            for name, sub_rx in field_extractor_compiled.get(dp.id, []):
                if name in fields:
                    continue
                sm = sub_rx.search(search_scope)
                if sm:
                    v = sm.groupdict().get("v") or (sm.group(1) if sm.groups() else None)
                    if v:
                        fields[name] = v

            if anchor_m:
                for k, v in anchor_m.groupdict().items():
                    if v is not None and k not in fields:
                        fields[k] = v

            if dp.yields:
                groupdict = m.groupdict()
                for key, template in dp.yields.items():
                    if key in fields and fields[key] is not None:
                        continue
                    if not isinstance(template, str):
                        if template is not None:
                            fields[key] = template
                        continue
                    if template.startswith("$") and "${" not in template:
                        var_name = template[1:]
                        ref_val = groupdict.get(var_name)
                        if ref_val is not None:
                            fields[key] = ref_val
                        continue
                    out = template
                    for gname, gval in groupdict.items():
                        if gval is None:
                            continue
                        out = out.replace("${" + gname + "}", gval)
                    fields[key] = out

            outer = enclosing_groups(m.start())
            inherited_prefix = ""
            inherited_auth_markers: list[str] = []
            inherited_namespace = ""
            inherited_class: Optional[str] = None
            for attrs in outer:
                if attrs.get("prefix"):
                    inherited_prefix = concat_url(inherited_prefix, attrs["prefix"])
                if attrs.get("namespace"):
                    inherited_namespace = (
                        inherited_namespace + "\\" + attrs["namespace"]
                    ).strip("\\")
                if attrs.get("auth_markers"):
                    inherited_auth_markers.extend(attrs["auth_markers"])
                if attrs.get("handler_class"):
                    inherited_class = attrs["handler_class"]

            for class_key in ("class", "handler_class"):
                if class_key in fields:
                    fields[class_key] = _qualify(
                        fields[class_key], use_aliases, file_namespace, from_scope=False
                    )
            if inherited_class:
                inherited_class = _qualify(
                    inherited_class, use_aliases, file_namespace, from_scope=True
                )

            methods_override = None
            if "methods" in fields:
                methods_override = []
                for chunk in fields["methods"].split(","):
                    chunk = chunk.strip().strip("'\"")
                    for sub in chunk.split("|"):
                        sub = sub.strip()
                        if sub:
                            methods_override.append(sub.upper())

            results.append(
                _RawDecl(
                    pattern_id=dp.id,
                    declared_at=(file_rel, line_of(m.start())),
                    declared_line_end=line_of(m.end()),
                    fields=fields,
                    expand_by=dp.expand_by,
                    inherited_prefix=inherited_prefix,
                    inherited_auth_markers=inherited_auth_markers,
                    inherited_namespace=inherited_namespace,
                    inherited_class=inherited_class,
                    methods_override=methods_override,
                    class_inference_strategy=dp.class_inference,
                    handler_class_relative=dp.handler_class_relative,
                )
            )
    return results


def _infer_class_from_url(url_pattern: str, strategy: str) -> Optional[str]:
    if strategy == "pascal_case_of_last_segment":
        for seg in url_pattern.strip("/").split("/"):
            if not seg or seg.startswith("{") or seg.startswith("("):
                continue
            return seg[:1].upper() + seg[1:]
    return None


_GROUP_ATTR_RE = {
    "prefix": re.compile(r'\bprefix\s*\(\s*(["\'])(?P<v>[^"\']+)\1'),
    "namespace": re.compile(r'\bnamespace\s*\(\s*(["\'])(?P<v>[^"\']+)\1'),
    "domain": re.compile(r'\bdomain\s*\(\s*(["\'])(?P<v>[^"\']+)\1'),
    "handler_class": re.compile(r'\bcontroller\s*\(\s*(?P<v>[A-Za-z_\\][A-Za-z0-9_\\]*)::class\s*\)'),
}
_GROUP_AUTH_RE = {
    "single": re.compile(r'\bmiddleware\s*\(\s*(["\'])(?P<v>[^"\']+)\1\s*\)'),
    "array": re.compile(r'\bmiddleware\s*\(\s*\[(?P<v>[^\]]+)\]\s*\)'),
}


def _extract_group_attrs(chunk: str, scope=None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    custom = getattr(scope, "attr_patterns", None) or {}

    for attr in ("prefix", "namespace", "domain", "handler_class"):
        if attr in custom:
            try:
                rx = re.compile(custom[attr])
            except re.error:
                continue
            if m := rx.search(chunk):
                out[attr] = m.groupdict().get("v") or (m.group(1) if m.groups() else None)
        elif rx := _GROUP_ATTR_RE.get(attr):
            if m := rx.search(chunk):
                out[attr] = m.group("v")

    auth_markers: list[str] = []
    if "auth_marker" in custom:
        try:
            rx = re.compile(custom["auth_marker"])
            for m in rx.finditer(chunk):
                v = m.groupdict().get("v") or (m.group(1) if m.groups() else None)
                if v:
                    auth_markers.append(v)
        except re.error:
            pass
    else:
        if m := _GROUP_AUTH_RE["single"].search(chunk):
            auth_markers.append(m.group("v"))
        if m := _GROUP_AUTH_RE["array"].search(chunk):
            for piece in m.group("v").split(","):
                piece = piece.strip().strip("'\"")
                if piece:
                    auth_markers.append(piece)
    if auth_markers:
        out["auth_markers"] = auth_markers
    return out


_CAMEL_TO_SNAKE_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_CLASS_DEF_RE = re.compile(
    r"^\s*(?:abstract\s+|final\s+|readonly\s+)*class\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)


def _build_class_def_index(
    root: Path,
    schema: FrameworkSchema,
) -> dict[str, tuple[str, int, Optional[int]]]:
    index: dict[str, tuple[str, int, Optional[int]]] = {}
    for loc in schema.route_locations:
        if loc.kind == "php_files":
            iter_paths = [
                (rel, root / rel) for rel in loc.paths if (root / rel).exists()
            ]
        elif loc.kind == "php_files_glob":
            base = (root / loc.extra.get("base", ".")).resolve()
            if not base.exists():
                continue
            glob = loc.extra.get("file_glob", "**/*.php")
            excludes = list(loc.extra.get("exclude_globs", []))
            iter_paths = []
            for p in base.glob(glob):
                if not p.is_file():
                    continue
                rel = p.relative_to(root).as_posix()
                if _matches_any(rel, excludes):
                    continue
                iter_paths.append((rel, p))
        else:
            continue
        for rel, path in iter_paths:
            text = _safe_read(path)
            if not text:
                continue
            for m in _CLASS_DEF_RE.finditer(text):
                name = m.group("name")
                if name in index:
                    continue
                line_start = text.count("\n", 0, m.start()) + 1
                brace_open = text.find("{", m.end())
                line_end: Optional[int] = None
                if brace_open != -1:
                    depth = 1
                    i = brace_open + 1
                    while i < len(text) and depth > 0:
                        ch = text[i]
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                        i += 1
                    line_end = text.count("\n", 0, i) + 1
                index[name] = (rel, line_start, line_end)
    return index


def _resolve_deferred_yields(d: _RawDecl) -> None:
    hc_raw = (
        d.fields.get("class")
        or d.fields.get("handler_class")
        or d.inherited_class
        or ""
    )
    short = hc_raw.lstrip("\\").rsplit("\\", 1)[-1] if hc_raw else ""
    _ns_parts = hc_raw.lstrip("\\").split("\\")[:-1] if hc_raw else []
    method = d.fields.get("action") or d.fields.get("handler_method") or ""
    snake_class  = _CAMEL_TO_SNAKE_RE.sub("_", short).lower() if short else ""
    kebab_class  = _CAMEL_TO_SNAKE_RE.sub("-", short).lower() if short else ""
    snake_method = _CAMEL_TO_SNAKE_RE.sub("_", method).lower() if method else ""
    kebab_method = _CAMEL_TO_SNAKE_RE.sub("-", method).lower() if method else ""
    short_url = short[:-len("Controller")] if short.endswith("Controller") and len(short) > len("Controller") else short
    method_url = method[len("action"):] if method.startswith("action") and len(method) > len("action") else method
    _class_name = short
    for _suf in ("Controller", "Action"):
        if _class_name.endswith(_suf) and len(_class_name) > len(_suf):
            _class_name = _class_name[: -len(_suf)]
            break
    derived = {
        "handler_class_short":               short,
        "handler_class_short_lower":         short.lower(),
        "handler_class_short_snake":         snake_class,
        "handler_class_short_kebab":         kebab_class,
        "handler_class_url_segment":         _CAMEL_TO_SNAKE_RE.sub("-", short_url).lower() if short_url else "",
        "handler_class_url_segment_lower":   short_url.lower() if short_url else "",
        "handler_method":                    method,
        "handler_method_lower":              method.lower(),
        "handler_method_snake":              snake_method,
        "handler_method_kebab":              kebab_method,
        "handler_method_url_segment":        _CAMEL_TO_SNAKE_RE.sub("-", method_url).lower() if method_url else "",
        "handler_class_name":                _class_name,
        **{f"handler_ns_{_i + 1}": (_ns_parts[_i] if _i < len(_ns_parts) else "")
           for _i in range(6)},
    }
    for key, val in list(d.fields.items()):
        if not isinstance(val, str) or "${" not in val:
            continue
        new = val
        for vname, vval in derived.items():
            new = new.replace("${" + vname + "}", vval)
        d.fields[key] = new


def _materialize_raw_decl(
    d: _RawDecl,
    schema: FrameworkSchema,
    root: Path,
    psr4_map: dict[str, list[str]],
    class_def_index: Optional[dict[str, tuple[str, int, Optional[int]]]] = None,
) -> Iterable[Route]:
    _resolve_deferred_yields(d)
    raw_url = d.fields.get("url", d.fields.get("url_pattern", "")) or ""
    expansion_now = schema.expansions.get(d.expand_by) if d.expand_by else None
    if expansion_now is not None:
        decomposed_url, _resource_singular = _decompose_resource_path(raw_url, schema)
        base_url = concat_url(d.inherited_prefix or "", decomposed_url)
    else:
        _resource_singular = ""
        base_url = concat_url(d.inherited_prefix or "", raw_url)

    auth = [_marker_to_auth(mw, schema) for mw in d.inherited_auth_markers]
    if d.fields.get("auth_marker"):
        auth.append(_marker_to_auth(d.fields["auth_marker"], schema))

    handler_class_raw = d.fields.get("class") or d.fields.get("handler_class") or d.inherited_class
    if not handler_class_raw and d.class_inference_strategy:
        raw_url = d.fields.get("url") or d.fields.get("url_pattern") or base_url
        handler_class_raw = _infer_class_from_url(raw_url, d.class_inference_strategy)
    if handler_class_raw:
        default_ns = (
            schema.handler_resolution.options.get("default_controller_namespace", "")
            if schema.handler_resolution
            else ""
        )
        if handler_class_raw.startswith("\\"):
            handler_class_raw = handler_class_raw.lstrip("\\")
        elif d.handler_class_relative:
            parts: list[str] = []
            if default_ns:
                parts.append(default_ns.strip("\\"))
            if d.inherited_namespace:
                parts.append(d.inherited_namespace.strip("\\"))
            parts.append(handler_class_raw.strip("\\"))
            handler_class_raw = "\\".join(p for p in parts if p)
        elif "\\" not in handler_class_raw:
            if d.inherited_namespace:
                handler_class_raw = d.inherited_namespace + "\\" + handler_class_raw
            elif default_ns:
                handler_class_raw = default_ns + "\\" + handler_class_raw

    expansion = expansion_now

    if expansion:
        for entry in expansion:
            method = entry["http_method"]
            url_suffix = entry.get("url_suffix", "")
            if _RESOURCE_SINGULAR_TOKEN in url_suffix:
                url_suffix = url_suffix.replace(
                    _RESOURCE_SINGULAR_TOKEN,
                    "{" + (_resource_singular or "id") + "}",
                )
            url = concat_url(base_url, url_suffix)
            action = entry["action"]
            handler = _resolve_handler(handler_class_raw, action, root, psr4_map, schema, class_def_index)
            origin = RouteOrigin(
                declared_at=d.declared_at,
                declaration_kind=f"{d.pattern_id}::{action}",
            )
            yield _finalize_route(
                method=method,
                url_pattern=url,
                handler=handler,
                handler_class=handler_class_raw,
                auth=list(auth),
                origin=origin,
                schema=schema,
                root=root,
            )
    else:
        action = d.fields.get("action") or d.fields.get("handler_method")
        closure_mode = (
            schema.handler_resolution.options.get("closure_handling")
            if schema.handler_resolution else None
        )
        if handler_class_raw is None and closure_mode == "inline_inspection" and d.declared_at[0]:
            handler = HandlerRef(
                kind="closure",
                file=d.declared_at[0],
                symbol=None,
                class_fqcn=None,
                line_start=d.declared_at[1],
                line_end=d.declared_line_end or d.declared_at[1],
            )
        else:
            handler = _resolve_handler(handler_class_raw, action, root, psr4_map, schema, class_def_index)

        methods: list[str]
        if d.methods_override:
            methods = [m.upper() for m in d.methods_override]
        else:
            single = (d.fields.get("method") or d.fields.get("http_method") or "ANY").upper()
            methods = [single]

        for method in methods:
            origin = RouteOrigin(
                declared_at=d.declared_at,
                declaration_kind=d.pattern_id,
            )
            yield _finalize_route(
                method=method,
                url_pattern=base_url,
                handler=handler,
                handler_class=handler_class_raw,
                auth=list(auth),
                origin=origin,
                schema=schema,
                root=root,
            )


def _finalize_route(
    method: str,
    url_pattern: str,
    handler: HandlerRef,
    handler_class: Optional[str],
    auth: list[AuthHint],
    origin: RouteOrigin,
    schema: FrameworkSchema,
    root: Path,
) -> Route:
    url_pattern = _normalize_url_placeholders(url_pattern, schema)
    params = list(_path_params_from_pattern(url_pattern))
    if handler.file:
        body_text = _read_method_body(root, handler)
        if body_text:
            params.extend(
                _harvest_params_from_text(body_text, handler.file, schema.param_sources)
            )
    return Route(
        http_method=method,
        url_pattern=url_pattern,
        handler_locator=handler,
        param_sources=params,
        auth_constraints=auth,
        origin=origin,
    )


def _parse_yaml_routes(
    file_rel: str, path: Path
) -> tuple[list[_RawDecl], list[dict[str, Any]]]:
    try:
        import yaml
    except ImportError:
        return [], []
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception:
        return [], []
    if not isinstance(data, dict):
        return [], []
    decls: list[_RawDecl] = []
    imports: list[dict[str, Any]] = []
    for name, body in data.items():
        if not isinstance(body, dict):
            continue
        if "resource" in body:
            prefix = body.get("prefix") or ""
            if isinstance(prefix, str):
                imports.append({
                    "name": str(name),
                    "resource": body.get("resource"),
                    "prefix": prefix,
                    "declared_in": file_rel,
                })
            continue
        url_pat = body.get("path") or body.get("pattern")
        controller = body.get("controller") or body.get("defaults", {}).get("_controller")
        if not url_pat or not controller:
            continue
        if "::" in controller:
            cls, _, action = controller.rpartition("::")
        elif "@" in controller:
            cls, _, action = controller.rpartition("@")
        else:
            cls, action = controller, "__invoke"
        methods_field = body.get("methods")
        if isinstance(methods_field, str):
            methods_override = [methods_field.upper()]
        elif isinstance(methods_field, list):
            methods_override = [str(m).upper() for m in methods_field]
        else:
            methods_override = None
        decls.append(
            _RawDecl(
                pattern_id=f"yaml_route::{name}",
                declared_at=(file_rel, 0),
                fields={
                    "url": url_pat,
                    "class": cls.lstrip("\\"),
                    "action": action,
                },
                expand_by=None,
                methods_override=methods_override,
            )
        )
    return decls, imports


def _load_psr4_map(root: Path, hr: HandlerResolution) -> dict[str, list[str]]:
    manifest = hr.options.get("composer_manifest", "composer.json")
    keys = hr.options.get("autoload_keys", ["autoload.psr-4"])
    composer = root / manifest
    if not composer.exists():
        return {}
    try:
        with composer.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    for k in keys:
        cur: Any = data
        for part in k.split("."):
            if not isinstance(cur, dict) or part not in cur:
                cur = None
                break
            cur = cur[part]
        if isinstance(cur, dict):
            for ns, dirs in cur.items():
                ns_norm = ns.rstrip("\\")
                if isinstance(dirs, str):
                    dirs_list = [dirs.rstrip("/")]
                elif isinstance(dirs, list):
                    dirs_list = [d.rstrip("/") for d in dirs if isinstance(d, str)]
                else:
                    continue
                if dirs_list:
                    out.setdefault(ns_norm, []).extend(dirs_list)
    return out


def _resolve_handler(
    class_fqcn: Optional[str],
    method: Optional[str],
    root: Path,
    psr4_map: dict[str, list[str]],
    schema: Optional[FrameworkSchema] = None,
    class_def_index: Optional[dict[str, tuple[str, int, Optional[int]]]] = None,
) -> HandlerRef:
    if not class_fqcn:
        return HandlerRef(kind="closure", file="", symbol=None)
    fqcn = class_fqcn.lstrip("\\")
    file_path: Optional[Path] = None
    for ns_prefix in sorted(psr4_map.keys(), key=len, reverse=True):
        ns_norm = ns_prefix.rstrip("\\")
        if fqcn == ns_norm or fqcn.startswith(ns_norm + "\\"):
            rel = fqcn[len(ns_norm):].lstrip("\\").replace("\\", "/")
            for base_dir in psr4_map[ns_prefix]:
                candidate = root / base_dir / f"{rel}.php"
                if candidate.exists():
                    file_path = candidate
                    break
            if file_path is not None:
                break
    if file_path is None and class_def_index:
        fallback_kind = ""
        if schema and schema.handler_resolution:
            fallback_kind = schema.handler_resolution.options.get("fallback", "") or ""
        if fallback_kind == "scan_for_class_definition":
            short = fqcn.rsplit("\\", 1)[-1]
            hit = class_def_index.get(short)
            if hit:
                rel, _ls, _le = hit
                candidate = root / rel
                if candidate.exists():
                    file_path = candidate
    file_rel = file_path.relative_to(root).as_posix() if file_path else ""
    line_start, line_end = (None, None)
    kind = "method"
    if file_path and method:
        line_start, line_end = _find_method_span(file_path, method)
    return HandlerRef(
        kind=kind,
        file=file_rel,
        symbol=method,
        class_fqcn=fqcn,
        line_start=line_start,
        line_end=line_end,
    )


_METHOD_DEF_RE_TPL = (
    r'(public|protected|private)?\s*(?:static\s+)?function\s+{name}\s*\('
)


def _find_method_span(file_path: Path, method_name: str) -> tuple[Optional[int], Optional[int]]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return (None, None)
    rx = re.compile(_METHOD_DEF_RE_TPL.format(name=re.escape(method_name)))
    m = rx.search(text)
    if not m:
        return (None, None)
    start = text.count("\n", 0, m.start()) + 1
    brace_open = text.find("{", m.end())
    if brace_open == -1:
        return (start, None)
    depth = 1
    i = brace_open + 1
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    end = text.count("\n", 0, i) + 1
    return (start, end)


def _read_method_body(root: Path, handler: HandlerRef) -> str:
    if not handler.file or handler.line_start is None or handler.line_end is None:
        return ""
    p = root / handler.file
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    return "".join(lines[handler.line_start - 1: handler.line_end])


_PATH_PARAM_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\??\}")


def _normalize_url_placeholders(url_pattern: str, schema: FrameworkSchema) -> str:
    pat = schema.extras.get("url_placeholder_pattern")
    if pat:
        try:
            rx = re.compile(pat)
            counter = {"n": 0}

            def repl(m: "re.Match[str]") -> str:
                gd = m.groupdict()
                type_name = gd.get("type") or "p"
                counter["n"] += 1
                return f"{{{type_name}_{counter['n']}}}"

            url_pattern = rx.sub(repl, url_pattern)
        except re.error:
            pass

    sep = schema.extras.get("placeholder_qualifier_separator")
    if sep and isinstance(sep, str):
        sep_quoted = re.escape(sep)
        inner_re = re.compile(
            r"\{(?P<name>[^{}" + sep_quoted + r"?]+)(?P<opt>\?)?" + sep_quoted + r"[^{}]*\}"
        )
        url_pattern = inner_re.sub(
            lambda m: "{" + m.group("name") + (m.group("opt") or "") + "}",
            url_pattern,
        )

    return url_pattern


def _path_params_from_pattern(url_pattern: str) -> list[ParamSource]:
    out: list[ParamSource] = []
    for m in _PATH_PARAM_RE.finditer(url_pattern):
        out.append(
            ParamSource(
                channel="path",
                name=m.group(1),
                required="?" not in m.group(0),
            )
        )
    return out


def _harvest_params_from_text(
    text: str, file_rel: str, rules: list[ParamSourceRule]
) -> list[ParamSource]:
    seen: set[tuple[str, str]] = set()
    out: list[ParamSource] = []
    for rule in rules:
        for pattern in rule.extract_from_code:
            try:
                rx = re.compile(pattern)
            except re.error:
                continue
            for m in rx.finditer(text):
                name = m.groupdict().get("name") if m.groupdict() else None
                if name is None:
                    groups = [g for g in m.groups() if g]
                    if not groups:
                        continue
                    name = groups[-1]
                key = (rule.channel, name)
                if key in seen:
                    continue
                seen.add(key)
                line = text.count("\n", 0, m.start()) + 1
                out.append(
                    ParamSource(
                        channel=rule.channel,
                        name=name,
                        declared_at=(file_rel, line),
                    )
                )
    return out


def _detect_manual_auth(text: str, schema: FrameworkSchema) -> list[AuthHint]:
    out: list[AuthHint] = []
    for pat in schema.auth_model.manual_check_patterns:
        try:
            rx = re.compile(pat)
        except re.error:
            continue
        if rx.search(text):
            out.append(AuthHint(kind="manual_check", name=pat))
    return out


def _marker_to_auth(marker: str, schema: FrameworkSchema) -> AuthHint:
    aliases = schema.auth_model.auth_marker_aliases
    if marker in aliases:
        spec = aliases[marker]
        return AuthHint(kind=spec.get("kind", "middleware"), name=marker, parameters=dict(spec))
    if ":" in marker:
        head = marker.split(":", 1)[0]
        if head in aliases:
            spec = aliases[head]
            return AuthHint(kind=spec.get("kind", "middleware"), name=marker, parameters=dict(spec))
    return AuthHint(kind="middleware", name=marker)


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _matches_any(rel_path: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat):
            return True
    return False
