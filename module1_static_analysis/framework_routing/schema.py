
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError as exc:
    raise ImportError(
        "PyYAML is required for framework_routing.schema. "
        "Install with: pip install pyyaml"
    ) from exc


@dataclass
class RouteLocation:
    kind: str
    paths: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeclarationPattern:
    id: str
    matcher: Any
    yields: dict[str, str] = field(default_factory=dict)
    expand_by: Optional[str] = None
    field_extractors: dict[str, str] = field(default_factory=dict)
    action_anchor: Optional[dict[str, Any]] = None
    class_inference: Optional[str] = None
    handler_class_relative: bool = False


@dataclass
class HandlerResolution:
    strategy: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class GroupingScope:
    id: str
    matcher: str
    inherits: list[str] = field(default_factory=list)
    attr_patterns: dict[str, str] = field(default_factory=dict)


@dataclass
class Grouping:
    scope_kinds: list[GroupingScope] = field(default_factory=list)
    prefix_concat: str = "path_concat"


@dataclass
class ParamSourceRule:
    channel: str
    extract_from: Optional[str] = None
    extract_from_code: list[str] = field(default_factory=list)
    extract_from_class: Optional[dict[str, Any]] = None


@dataclass
class AuthModel:
    auth_marker_aliases: dict[str, dict[str, Any]] = field(default_factory=dict)
    inheritance: str = "from_group_and_controller"
    manual_check_patterns: list[str] = field(default_factory=list)


@dataclass
class FrameworkSchema:
    framework: str
    version_range: str = "*"
    route_locations: list[RouteLocation] = field(default_factory=list)
    declaration_patterns: list[DeclarationPattern] = field(default_factory=list)
    handler_resolution: Optional[HandlerResolution] = None
    grouping: Grouping = field(default_factory=Grouping)
    expansions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    param_sources: list[ParamSourceRule] = field(default_factory=list)
    auth_model: AuthModel = field(default_factory=AuthModel)
    extras: dict[str, Any] = field(default_factory=dict)


REQUIRED_KEYS = {"framework", "route_locations", "handler_resolution"}


def load_schema(path: str | Path) -> FrameworkSchema:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"{p}: top-level YAML must be a mapping")
    missing = REQUIRED_KEYS - raw.keys()
    if missing:
        raise ValueError(f"{p}: missing required keys: {sorted(missing)}")

    schema = FrameworkSchema(
        framework=raw["framework"],
        version_range=raw.get("version_range", "*"),
        route_locations=[
            RouteLocation(
                kind=rl["kind"],
                paths=list(rl.get("paths", [])),
                extra={k: v for k, v in rl.items() if k not in ("kind", "paths")},
            )
            for rl in raw.get("route_locations", [])
        ],
        declaration_patterns=[
            DeclarationPattern(
                id=dp["id"],
                matcher=dp["matcher"],
                yields=dict(dp.get("yields", {})),
                expand_by=dp.get("expand_by"),
                field_extractors=dict(dp.get("field_extractors", {})),
                action_anchor=dp.get("action_anchor"),
                class_inference=dp.get("class_inference"),
                handler_class_relative=bool(dp.get("handler_class_relative", False)),
            )
            for dp in raw.get("declaration_patterns", [])
        ],
        handler_resolution=_parse_handler_resolution(raw["handler_resolution"]),
        grouping=Grouping(
            scope_kinds=[
                GroupingScope(
                    id=g["id"],
                    matcher=g["matcher"],
                    inherits=list(g.get("inherits", [])),
                    attr_patterns=dict(g.get("attr_patterns", {})),
                )
                for g in raw.get("grouping", {}).get("scope_kinds", [])
            ],
            prefix_concat=raw.get("grouping", {}).get("prefix_concat", "path_concat"),
        ),
        expansions={k: list(v) for k, v in raw.get("expansions", {}).items()},
        param_sources=[
            ParamSourceRule(
                channel=ps["channel"],
                extract_from=ps.get("extract_from"),
                extract_from_code=list(ps.get("extract_from_code", [])),
                extract_from_class=ps.get("extract_from_class"),
            )
            for ps in raw.get("param_sources", [])
        ],
        auth_model=AuthModel(
            auth_marker_aliases=dict(
                raw.get("auth_model", {}).get(
                    "auth_marker_aliases",
                    raw.get("auth_model", {}).get("middleware_aliases", {}),
                )
            ),
            inheritance=raw.get("auth_model", {}).get("inheritance", "from_group_and_controller"),
            manual_check_patterns=list(raw.get("auth_model", {}).get("manual_check_patterns", [])),
        ),
        extras=dict(raw.get("extras", {})),
    )
    _validate(schema, source=str(p))
    return schema


def _parse_handler_resolution(raw: dict[str, Any]) -> HandlerResolution:
    strategy = raw["strategy"]
    options: dict[str, Any] = {}
    for k, v in raw.items():
        if k == "strategy":
            continue
        if k == "options" and isinstance(v, dict):
            options.update(v)
        else:
            options[k] = v
    return HandlerResolution(strategy=strategy, options=options)


def _validate(schema: FrameworkSchema, source: str) -> None:
    for dp in schema.declaration_patterns:
        if dp.expand_by and dp.expand_by not in schema.expansions:
            raise ValueError(
                f"{source}: declaration_pattern '{dp.id}' references "
                f"unknown expansion '{dp.expand_by}'"
            )


def detect_framework(project_root: str | Path) -> Optional[str]:
    root = Path(project_root)
    composer = root / "composer.json"
    if composer.exists():
        try:
            import json
            with composer.open("r", encoding="utf-8") as f:
                manifest = json.load(f)
            deps = {**manifest.get("require", {}), **manifest.get("require-dev", {})}
            if "laravel/framework" in deps:
                ver = _installed_laravel_version(root) or deps["laravel/framework"]
                if _is_laravel_5(ver):
                    return "laravel5"
                return "laravel"
            if "symfony/symfony" in deps or "symfony/framework-bundle" in deps:
                return "symfony"
            name = manifest.get("name", "") or ""
            if name.endswith("-bundle") or "/bundles/" in name:
                if any(k.startswith("symfony/") for k in deps):
                    ctrl_dir = root / "src" / "Controller"
                    if ctrl_dir.exists():
                        for p in ctrl_dir.rglob("*.php"):
                            try:
                                if "#[Route" in p.read_text(
                                    encoding="utf-8", errors="replace"
                                ):
                                    return "symfony"
                            except OSError:
                                continue
                            break
                        return "symfony"
            if "codeigniter4/framework" in deps:
                return "codeigniter4"
            if "codeigniter/framework" in deps:
                if (root / "application" / "config" / "routes.php").exists():
                    return "codeigniter3"
            if "yiisoft/yii2" in deps or any(
                k.startswith("yiisoft/yii2-") for k in deps
            ):
                return "yii2"
            if "yiisoft/yii" in deps:
                return "yii"
            if "topthink/framework" in deps or "topthink/think" in deps:
                return "thinkphp"
        except Exception:
            pass
    if (root / "system" / "core" / "CodeIgniter.php").exists() \
       and (root / "application" / "config" / "routes.php").exists():
        return "codeigniter3"
    if (root / "vendor" / "topthink" / "framework").exists() \
       and (root / "app").is_dir():
        return "thinkphp"
    for _tp3 in ("ThinkPHP/ThinkPHP.php", "Core/ThinkPHP/ThinkPHP.php",
                 "System/ThinkPHP/ThinkPHP.php", "Lib/ThinkPHP/ThinkPHP.php"):
        if (root / _tp3).exists():
            return "thinkphp3"
    if (root / "wp-config.php").exists() or (root / "wp-load.php").exists():
        return "wordpress"
    if (root / "index.php").exists():
        for sub in root.iterdir():
            if sub.is_dir() and any(sub.rglob("*.php")):
                return "flat_php"
                break
    return None


def _installed_laravel_version(root: Path) -> Optional[str]:
    lock = root / "composer.lock"
    if not lock.exists():
        return None
    try:
        import json
        with lock.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    for pkg in data.get("packages", []) or []:
        if pkg.get("name") == "laravel/framework":
            return pkg.get("version")
    return None


def _is_laravel_5(version_spec: str) -> bool:
    import re
    if not version_spec:
        return False
    s = str(version_spec).strip().lstrip("v")
    if re.match(r"^5\.\d", s):
        return True
    if re.match(r"^[~^]5\.\d", s):
        return True
    if re.search(r"\b5\.\d", s) and re.search(r"<\s*6\b", s):
        return True
    return False
