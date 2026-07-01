
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


_DIE_RE     = re.compile(r"\b(die|exit|__halt_compiler)\s*\(")
_THROW_RE   = re.compile(r"\bthrow\s+new\s+([A-Za-z_][A-Za-z0-9_\\]*)")
_REDIR_RE   = re.compile(r"\bheader\s*\(\s*['\"]\s*Location\s*:", re.I)
_DYN_CALL_RE = re.compile(
    r"\bcall_user_func(?:_array)?\s*\(|"
    r"\bnew\s+\$[A-Za-z_]\w*|"
    r"->\$[A-Za-z_]\w*\s*\(|"
    r"\bReflectionMethod\b|\bReflectionClass\b"
)

_FN_DECL_RE = re.compile(
    r"^\s*(?:public|protected|private|static|abstract|final|\s)*\s*"
    r"function\s+(\w+)\s*\("
)

_HEURISTICS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\b(fopen|fread|fwrite|fsockopen|curl_exec|"
                r"socket_connect|file_get_contents|stream_socket_client)\b"),
     "B6", "io_failure"),
    (re.compile(r"\bnew\s+PDO\b|\bnew\s+(mysqli|Memcache(?:d)?|Redis)\b"),
     "B6", "io_failure"),
    (re.compile(r"\bthrow\s+new\s+(PDO|IO|Connection|Network|"
                r"File|Filesystem|Socket)Exception\b"),
     "B6", "io_failure"),

    (re.compile(r"\b(fetch|fetchAll|fetchColumn|fetchObject|rowCount)\s*\(\s*\)"
                r"\s*(?:[=!]==?\s*(?:false|null|0|''|\"\"|\[\])|"
                r"\s*\)\s*===?\s*0)?"),
     "B5", "iteration_empty"),
    (re.compile(r"\bif\s*\(\s*!\s*\$\w+\s*(?:->fetch|->rowCount)\b"),
     "B5", "iteration_empty"),
    (re.compile(r"\bcount\s*\(\s*\$\w+\s*\)\s*===?\s*0\b"),
     "B5", "iteration_empty"),

    (re.compile(r"\bpreg_match\s*\("),                          "B3", "validation_reject"),
    (re.compile(r"\bin_array\s*\("),                            "B3", "validation_reject"),
    (re.compile(r"\bctype_(?:digit|alpha|alnum|space)\s*\("),   "B3", "validation_reject"),
    (re.compile(r"\bfilter_(?:var|input)\s*\("),                "B3", "validation_reject"),
    (re.compile(r"\b(?:is_(?:int|string|array|numeric))\s*\("), "B3", "validation_reject"),
    (re.compile(r"['\"](?:must (?:be|match|equal)|invalid|"
                r"required|format|expected)['\"]", re.I),       "B3", "validation_reject"),

    (re.compile(r"\b(auth|login|logout|session|csrf|token|"
                r"permission|access|role|grant)\b", re.I),      "B2", "auth_gate"),
    (re.compile(r"\$_SESSION\s*\[", re.I),                       "B2", "auth_gate"),
    (re.compile(r"\bhash_equals\s*\("),                          "B2", "auth_gate"),
    (re.compile(r"\bpassword_verify\s*\("),                      "B2", "auth_gate"),
]


_IF_GUARD_RE = re.compile(r"\bif\s*\(")


_FRAMEWORK_GATES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bthrow\s+new\s+(?:AccessDenied|Authentication|HttpException|"
                r"NotFoundHttpException|UnauthorizedHttpException)"),
     "symfony: throw HTTP*Exception (kernel converts to 401/403/404 Response)"),
    (re.compile(r"\bnew\s+RedirectResponse\s*\("),
     "symfony: explicit RedirectResponse (often gate→login)"),
    (re.compile(r"\bnew\s+JsonResponse\s*\([^,)]*,\s*(?:401|403|404|422)"),
     "symfony: JsonResponse with reject status"),
    (re.compile(r"\$this->denyAccessUnlessGranted\s*\("),
     "symfony: AbstractController::denyAccessUnlessGranted (Voter gate)"),
    (re.compile(r"\$this->createNotFoundException\s*\("),
     "symfony: AbstractController::createNotFoundException"),
    (re.compile(r"\babort\s*\(\s*(?:401|403|404|419|422|500)\b"),
     "laravel: abort(reject_status)"),
    (re.compile(r"\babort_if\s*\(|\babort_unless\s*\("),
     "laravel: abort_if/abort_unless (conditional reject)"),
    (re.compile(r"\bredirect\s*\(\s*['\"][^'\"]+['\"]\s*\)\s*->withErrors"),
     "laravel: redirect+withErrors (form validation reject)"),
    (re.compile(r"\$this->authorize\s*\("),
     "laravel: Policy authorize() (gate-style)"),
    (re.compile(r"->respond\s*\([^,)]+,\s*(?:401|403|404|422)\b"),
     "ci4: respond with reject status"),
    (re.compile(r"throw\s+new\s+(?:ForbiddenException|UnauthorizedException|"
                r"PageNotFoundException)"),
     "ci4: throw framework-mapped HTTP exception"),
]


@dataclass
class FrameworkGate:
    file: str
    line: int
    pattern_label: str
    enclosing_function: str
    snippet: str


_CATCH_OPEN_RE  = re.compile(r"\bcatch\s*\([^)]+\)\s*\{")


@dataclass
class BlockingSite:
    file: str
    line: int
    kind: str
    snippet: str
    enclosing_function: str = ""
    back_context: str = ""
    classified_as: str = ""
    classified_label: str = ""
    classification_evidence: str = ""


@dataclass
class AuditReport:
    target_root: str
    php_files_scanned: int = 0
    sites: list[BlockingSite] = field(default_factory=list)
    by_class: dict = field(default_factory=dict)
    uncovered_count: int = 0
    framework_gates: list[FrameworkGate] = field(default_factory=list)


def _is_in_catch(back_text: str) -> bool:
    opens = len(_CATCH_OPEN_RE.findall(back_text))
    closes = back_text.count("}")
    return opens > closes


def _enclosing_function(lines: list[str], idx: int) -> str:
    for j in range(idx, max(0, idx - 200), -1):
        m = _FN_DECL_RE.match(lines[j])
        if m:
            return m.group(1)
    return "<top-level>"


def _back_window(lines: list[str], idx: int, n: int = 30) -> str:
    s = max(0, idx - n)
    return "\n".join(lines[s:idx + 1])


def _classify(site: BlockingSite) -> tuple[str, str, str]:
    back = site.back_context
    for pat, cls, label in _HEURISTICS:
        m = pat.search(back)
        if m:
            return (cls, label,
                    f"matched /{pat.pattern[:60]}.../: {m.group(0)[:80]!r}")

    if _IF_GUARD_RE.search(back):
        return ("B1", "predicate_guard",
                "generic if-guard in back-window, no class keyword matched")

    if site.kind in ("die", "exit", "throw"):
        return ("B7", "early_exit",
                "die/exit/throw with no enclosing guard — naked terminator")
    if site.kind == "redirect":
        return ("B7", "early_exit",
                "header(Location:) — control-flow change to other URL")

    return ("UNCOVERED", "?",
            "fits no B1-B6 pattern AND not a naked exit — likely new blocker class")


def _scan_file(path: Path) -> tuple[list[BlockingSite], list[FrameworkGate]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], []
    lines = text.splitlines()
    sites: list[BlockingSite] = []
    gates: list[FrameworkGate] = []
    pending_redirect: Optional[int] = None
    for i, line in enumerate(lines):
        m_die = _DIE_RE.search(line)
        m_thr = _THROW_RE.search(line)
        m_red = _REDIR_RE.search(line)
        m_dyn = _DYN_CALL_RE.search(line)

        if m_red:
            pending_redirect = i

        if m_die or m_thr:
            back = _back_window(lines, i, 30)
            kind = "die" if (m_die and m_die.group(1) in ("die", "exit")) else \
                   ("__halt_compiler" if m_die else "throw")
            if pending_redirect is not None and i - pending_redirect <= 2 and m_die:
                kind = "redirect"
                pending_redirect = None
            if m_thr and _is_in_catch(back):
                continue
            site = BlockingSite(
                file=str(path), line=i + 1, kind=kind,
                snippet=line.strip()[:200],
                enclosing_function=_enclosing_function(lines, i),
                back_context=back,
            )
            cls, label, ev = _classify(site)
            site.classified_as = cls
            site.classified_label = label
            site.classification_evidence = ev
            sites.append(site)

        if m_dyn:
            site = BlockingSite(
                file=str(path), line=i + 1, kind="dynamic_dispatch",
                snippet=line.strip()[:200],
                enclosing_function=_enclosing_function(lines, i),
                back_context=_back_window(lines, i, 5),
                classified_as="B4", classified_label="dispatch_miss",
                classification_evidence=f"matched dispatch pattern: {m_dyn.group(0)[:60]!r}",
            )
            sites.append(site)

        for pat, label in _FRAMEWORK_GATES:
            m_fg = pat.search(line)
            if m_fg:
                gates.append(FrameworkGate(
                    file=str(path), line=i + 1, pattern_label=label,
                    enclosing_function=_enclosing_function(lines, i),
                    snippet=line.strip()[:200],
                ))
                break
    return sites, gates


def _walk_php(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ("vendor", "node_modules", ".git",
                                     "test", "tests", "Tests", "spec")]
        for fn in filenames:
            if fn.endswith(".php") or fn.endswith(".inc.php"):
                out.append(Path(dirpath) / fn)
    return out


_CLASS_ORDER = ["B1", "B2", "B3", "B4", "B5", "B6", "B7", "UNCOVERED"]
_CLASS_DESC = {
    "B1": "predicate_guard",   "B2": "auth_gate",
    "B3": "validation_reject", "B4": "dispatch_miss",
    "B5": "iteration_empty",   "B6": "io_failure",
    "B7": "early_exit",        "UNCOVERED": "—",
}


def _summarize(report: AuditReport) -> AuditReport:
    counts: dict[str, int] = {c: 0 for c in _CLASS_ORDER}
    for s in report.sites:
        counts[s.classified_as] = counts.get(s.classified_as, 0) + 1
    report.by_class = counts
    report.uncovered_count = counts.get("UNCOVERED", 0)
    return report


def _emit_markdown(report: AuditReport, *, max_per_class: int = 12) -> str:
    lines: list[str] = []
    lines.append(f"# Blocker coverage audit · `{report.target_root}`")
    lines.append("")
    lines.append(f"PHP files scanned: **{report.php_files_scanned}**  ")
    lines.append(f"die/exit/throw + dyn-dispatch sites: **{len(report.sites)}**  ")
    if report.uncovered_count:
        lines.append(f"⚠ UNCOVERED (within die-based scan): **{report.uncovered_count}**")
    else:
        lines.append("✓ All die-based sites classifiable into B1–B7.")
    lines.append(f"Framework-level gates (NOT covered by B1–B7): "
                 f"**{len(report.framework_gates)}**")
    if report.framework_gates:
        lines.append("⚠ Framework gates surfaced — these terminate requests via "
                     "Response/Voter/middleware, NOT via die/exit/throw. The "
                     "current 7-blocker schema does NOT model them: runtime "
                     "hooks won't emit a BlockerEvent at these sites even "
                     "though the PoC fails to reach the sink.")
    lines.append("")
    lines.append("## Per-class counts")
    lines.append("")
    lines.append("| Class | Label | Count |")
    lines.append("|-------|-------|-------|")
    for c in _CLASS_ORDER:
        n = report.by_class.get(c, 0)
        lines.append(f"| {c} | {_CLASS_DESC[c]} | {n} |")
    lines.append("")
    lines.append("## Sites (per class, sampled)")
    for c in _CLASS_ORDER:
        bucket = [s for s in report.sites if s.classified_as == c]
        if not bucket:
            continue
        lines.append("")
        lines.append(f"### {c} · {_CLASS_DESC[c]} ({len(bucket)} sites)")
        lines.append("")
        for s in bucket[:max_per_class]:
            rel = s.file
            try:
                rel = os.path.relpath(s.file, report.target_root)
            except ValueError:
                pass
            lines.append(f"- `{rel}:{s.line}`  (`{s.kind}` in `{s.enclosing_function}`)")
            lines.append(f"  - `{s.snippet}`")
            lines.append(f"  - evidence: {s.classification_evidence}")
        if len(bucket) > max_per_class:
            lines.append(f"  *(+ {len(bucket) - max_per_class} more)*")
    if report.framework_gates:
        lines.append("")
        lines.append("## ⚠ Framework-level gates (GAP relative to 7-blocker schema)")
        lines.append("")
        by_label: dict[str, list[FrameworkGate]] = {}
        for g in report.framework_gates:
            by_label.setdefault(g.pattern_label, []).append(g)
        for label, group in sorted(by_label.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"### `{label}` — {len(group)} site(s)")
            lines.append("")
            for g in group[:max_per_class]:
                rel = g.file
                try:
                    rel = os.path.relpath(g.file, report.target_root)
                except ValueError:
                    pass
                lines.append(f"- `{rel}:{g.line}` in `{g.enclosing_function}`")
                lines.append(f"  - `{g.snippet}`")
            if len(group) > max_per_class:
                lines.append(f"  *(+ {len(group) - max_per_class} more)*")
            lines.append("")
    return "\n".join(lines) + "\n"


def _main():
    ap = argparse.ArgumentParser(
        description="Static audit of blocker-class coverage on a PHP tree.")
    ap.add_argument("--target", required=True,
                    help="PHP source root to scan recursively.")
    ap.add_argument("--report", default="-",
                    help="Markdown report path (default '-' = stdout).")
    ap.add_argument("--json", default="",
                    help="Optional JSON output path (raw sites + summary).")
    ap.add_argument("--max-per-class", type=int, default=12,
                    help="Cap displayed sites per class in markdown (default 12).")
    args = ap.parse_args()

    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"error: --target {root} is not a directory", file=sys.stderr)
        return 1

    files = _walk_php(root)
    report = AuditReport(target_root=str(root), php_files_scanned=len(files))
    for f in files:
        s, g = _scan_file(f)
        report.sites.extend(s)
        report.framework_gates.extend(g)
    _summarize(report)

    md = _emit_markdown(report, max_per_class=args.max_per_class)
    if args.report == "-":
        print(md)
    else:
        Path(args.report).write_text(md, encoding="utf-8")
        print(f"wrote {args.report}", file=sys.stderr)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({
                "target_root": report.target_root,
                "php_files_scanned": report.php_files_scanned,
                "by_class": report.by_class,
                "uncovered_count": report.uncovered_count,
                "framework_gates_count": len(report.framework_gates),
                "sites": [asdict(s) for s in report.sites],
                "framework_gates": [asdict(g) for g in report.framework_gates],
            }, f, indent=2, ensure_ascii=False)
        print(f"wrote {args.json}", file=sys.stderr)

    return 2 if (report.uncovered_count or report.framework_gates) else 0


if __name__ == "__main__":
    sys.exit(_main())
