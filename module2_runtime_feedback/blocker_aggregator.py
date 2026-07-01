
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class BlockerEvent:
    kind: str
    location: dict
    distance_at_blocker: int = -1
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "BlockerEvent":
        return cls(
            kind=d.get("kind", "unknown"),
            location=d.get("location", {}),
            distance_at_blocker=int(d.get("distance_at_blocker", -1)),
            raw=d,
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PocRecord:
    method: str = ""
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""


@dataclass
class OutcomeRecord:
    http_status: int = 0
    response_excerpt: str = ""
    reached_sink: bool = False


@dataclass
class IterationTrace:
    iteration_index: int
    poc: PocRecord = field(default_factory=PocRecord)
    outcome: OutcomeRecord = field(default_factory=OutcomeRecord)
    blocker_events: list[BlockerEvent] = field(default_factory=list)
    cleared_blockers: list[dict] = field(default_factory=list)
    terminal_blocker: Optional[BlockerEvent] = None
    min_distance: int = -1
    total_blockers_emitted: int = 0
    parse_warnings: list[str] = field(default_factory=list)
    bailout_end: bool = False
    bailout_predicate: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "iteration_index": self.iteration_index,
            "poc": asdict(self.poc),
            "outcome": asdict(self.outcome),
            "blocker_events": [b.to_dict() for b in self.blocker_events],
            "cleared_blockers": self.cleared_blockers,
            "terminal_blocker": (self.terminal_blocker.to_dict()
                                 if self.terminal_blocker else None),
            "min_distance": self.min_distance,
            "total_blockers_emitted": self.total_blockers_emitted,
            "parse_warnings": self.parse_warnings,
            "bailout_end": self.bailout_end,
            "bailout_predicate": self.bailout_predicate,
        }


@dataclass
class RunHistory:
    iterations: list[IterationTrace] = field(default_factory=list)

    @property
    def distance_progress(self) -> list[int]:
        return [it.min_distance for it in self.iterations]

    @property
    def plateau_iterations(self) -> int:
        prog = self.distance_progress
        if len(prog) < 2:
            return 0
        last = prog[-1]
        n = 0
        for d in reversed(prog[:-1]):
            if d == last:
                n += 1
            else:
                break
        return n

    @property
    def unique_blocker_locations(self) -> list[dict]:
        seen: set[tuple] = set()
        out: list[dict] = []
        for it in self.iterations:
            for b in it.blocker_events:
                key = (b.location.get("file"), b.location.get("line"),
                       b.kind)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "file": b.location.get("file"),
                    "line": b.location.get("line"),
                    "kind": b.kind,
                })
        return out

    def add_iteration(self, it: IterationTrace) -> None:
        self.iterations.append(it)

    def to_dict(self) -> dict:
        return {
            "iterations":           [it.to_dict() for it in self.iterations],
            "distance_progress":    self.distance_progress,
            "plateau_iterations":   self.plateau_iterations,
            "unique_blocker_locs":  self.unique_blocker_locations,
        }


def parse_jsonl(path: str | Path) -> tuple[list[BlockerEvent], list[str]]:
    events: list[BlockerEvent] = []
    warnings: list[str] = []
    p = Path(path)
    if not p.exists():
        warnings.append(f"jsonl path does not exist: {p}")
        return events, warnings
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for ln_no, ln in enumerate(f, 1):
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
            except json.JSONDecodeError as e:
                warnings.append(f"line {ln_no}: bad JSON ({e}); skipped")
                continue
            if not isinstance(d, dict):
                warnings.append(f"line {ln_no}: not a JSON object; skipped")
                continue
            events.append(BlockerEvent.from_dict(d))
    return events, warnings


def split_log_by_envelopes(events: list[BlockerEvent]) -> list[list[BlockerEvent]]:
    chunks: list[list[BlockerEvent]] = []
    cur: list[BlockerEvent] = []
    saw_start = False
    for e in events:
        if e.kind == "request_start":
            if cur:
                chunks.append(cur)
            cur = [e]
            saw_start = True
        elif e.kind == "request_end":
            cur.append(e)
            chunks.append(cur)
            cur = []
        else:
            cur.append(e)
    if cur:
        chunks.append(cur)
    if not saw_start:
        return [events] if events else []
    return chunks


def _path_suffix(path: str, k: int) -> str:
    parts = [seg for seg in str(path).replace("\\", "/").split("/") if seg]
    if not parts:
        return str(path)
    if k <= 1:
        return parts[-1]
    return "/".join(parts[-k:])


class _PathKeyer:

    def __init__(self, paths):
        bn_paths: dict[str, set] = {}
        for p in paths:
            norm = str(p).replace("\\", "/")
            bn_paths.setdefault(_path_suffix(norm, 1), set()).add(norm)
        self._depth: dict[str, int] = {}
        for bn, ps in bn_paths.items():
            self._depth[bn] = 1 if len(ps) <= 1 else self._disambig_depth(ps)

    @staticmethod
    def _disambig_depth(paths, cap: int = 8) -> int:
        for k in range(2, cap + 1):
            if len({_path_suffix(p, k) for p in paths}) == len(paths):
                return k
        return cap

    def file_key(self, path: str) -> str:
        norm = str(path).replace("\\", "/")
        bn = _path_suffix(norm, 1)
        return _path_suffix(norm, self._depth.get(bn, 1))


def _basename_keyer() -> "_PathKeyer":
    return _PathKeyer([])


def _load_distance_table(
    instr_info_path: str | Path,
) -> tuple[dict[tuple[str, int], int], "_PathKeyer"]:
    p = Path(instr_info_path)
    if not p.exists():
        return {}, _basename_keyer()
    rows: list[tuple[str, int, int]] = []
    file_paths: set = set()
    current_path = ""
    try:
        for ln_no, line in enumerate(
                p.read_text(encoding="utf-8", errors="replace").splitlines()):
            if ln_no == 0:
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            row_type = parts[1]
            try:
                lineno = int(parts[2])
            except ValueError:
                continue
            if row_type == "f":
                current_path = parts[3].strip()
                file_paths.add(current_path)
            elif row_type == "d" and current_path:
                try:
                    dist = int(float(parts[3]))
                except ValueError:
                    continue
                rows.append((current_path, lineno, dist))
    except OSError:
        return {}, _basename_keyer()
    keyer = _PathKeyer(file_paths)
    table: dict[tuple[str, int], int] = {}
    for fpath, lineno, dist in rows:
        key = (keyer.file_key(fpath), lineno)
        if key not in table or dist < table[key]:
            table[key] = dist
    return table, keyer


def _patch_distances_from_table(
    events: list[BlockerEvent],
    distance_table: dict[tuple[str, int], int],
    keyer: "Optional[_PathKeyer]" = None,
) -> None:
    if not distance_table:
        return
    if keyer is None:
        keyer = _basename_keyer()
    for e in events:
        if e.distance_at_blocker >= 0:
            continue
        fk = keyer.file_key(e.location.get("file", ""))
        try:
            ln = int(e.location.get("line", 0) or 0)
        except (ValueError, TypeError):
            continue
        d = distance_table.get((fk, ln))
        if d is not None:
            e.distance_at_blocker = d
            if isinstance(e.raw, dict):
                e.raw["distance_at_blocker"] = d


def patch_distances_into_raw(raw_events, instr_info_path) -> list:
    table, keyer = _load_distance_table(instr_info_path)
    if not table:
        return raw_events
    for e in raw_events:
        try:
            if float(e.get("distance_at_blocker", -1)) >= 0:
                continue
        except (ValueError, TypeError):
            pass
        loc = e.get("location") or {}
        fk = keyer.file_key(str(loc.get("file", "") or ""))
        try:
            ln = int(loc.get("line", 0) or 0)
        except (ValueError, TypeError):
            continue
        d = table.get((fk, ln))
        if d is not None:
            e["distance_at_blocker"] = d
    return raw_events


def _recompute_trigger_conditions(events: list[BlockerEvent]) -> None:
    entered_then: list[BlockerEvent] = []
    for e in events:
        if e.kind == 'predicate_guard':
            pred = e.raw.get('predicate', {})
            if pred.get('condition_value') is True and pred.get('jumped') is False:
                entered_then.append(e)
            continue
        if e.kind != 'early_exit':
            continue
        exit_file = e.location.get('file', '')
        try:
            exit_line = int(e.location.get('line', 0) or 0)
        except (ValueError, TypeError):
            exit_line = 0
        chosen: Optional[BlockerEvent] = None
        for prev in reversed(entered_then):
            pf = prev.location.get('file', '')
            try:
                pl = int(prev.location.get('line', 0) or 0)
            except (ValueError, TypeError):
                pl = 0
            if pf == exit_file and 0 < pl < exit_line:
                chosen = prev
                break
        if chosen is None:
            continue
        pred = chosen.raw.get('predicate', {})
        lhs = pred.get('operands', {}).get('lhs', {})
        ex = e.raw.setdefault('exit', {})
        ex['trigger_condition'] = {
            'file': chosen.location.get('file'),
            'line': chosen.location.get('line'),
            'opcode': chosen.location.get('opcode'),
            'op1': {
                'value': lhs.get('value'),
                'type': lhs.get('type'),
            },
            'condition_value': True,
            'jumped': False,
            '_dominating': True,
        }


def aggregate_iteration(
    *,
    iteration_index: int,
    blocker_log_path: str | Path,
    poc: Optional[PocRecord] = None,
    outcome: Optional[OutcomeRecord] = None,
    file_whitelist: Optional[set[str]] = None,
    instr_info_path: Optional[str | Path] = None,
) -> IterationTrace:
    events, warnings = parse_jsonl(blocker_log_path)

    chunks = split_log_by_envelopes(events)
    if chunks:
        chosen = None
        for chunk in reversed(chunks):
            if any(b.kind == "request_start" for b in chunk):
                chosen = chunk
                break
        events = chosen if chosen is not None else chunks[-1]

    envelopes = [b for b in events if b.kind in ("request_start", "request_end")]
    real_events = [b for b in events if b.kind not in ("request_start", "request_end")]
    real_events = [b for b in real_events
                   if os.path.basename(b.location.get("file", "")) != "viper_prepend.php"]
    if file_whitelist:
        _ALWAYS_PASS = {"early_exit", "php_fatal"}
        real_events = [b for b in real_events
                       if b.kind in _ALWAYS_PASS
                       or os.path.basename(b.location.get("file", "")) in file_whitelist]

    finite_distances = [b.distance_at_blocker for b in real_events
                        if b.distance_at_blocker >= 0]
    min_dist = min(finite_distances) if finite_distances else -1

    req_start = next((e for e in envelopes if e.kind == "request_start"), None)
    req_end   = next((e for e in envelopes if e.kind == "request_end"), None)
    if poc is None and req_start:
        poc = PocRecord(
            method=req_start.raw.get("method", ""),
            url=req_start.raw.get("uri", ""),
            body=req_start.raw.get("query", ""),
        )
    if outcome is None and req_end:
        outcome = OutcomeRecord(http_status=int(req_end.raw.get("http_status", 0)))

    events = real_events

    if instr_info_path:
        _dt, _dk = _load_distance_table(instr_info_path)
        _patch_distances_from_table(events, _dt, _dk)

    finite_distances = [b.distance_at_blocker for b in events
                        if b.distance_at_blocker >= 0]
    min_dist = min(finite_distances) if finite_distances else -1

    _recompute_trigger_conditions(events)

    early_exits = [b for b in events if b.kind == "early_exit"]
    if early_exits:
        terminal: Optional[BlockerEvent] = early_exits[-1]
    else:
        finite = [b for b in events if b.distance_at_blocker > 0]
        if finite:
            terminal = min(finite, key=lambda b: b.distance_at_blocker)
        else:
            terminal = events[-1] if events else None

    cleared: list[dict] = []
    if events and outcome and outcome.reached_sink:
        for b in events:
            cleared.append({
                "file": b.location.get("file"),
                "line": b.location.get("line"),
                "kind": b.kind,
            })

    return IterationTrace(
        iteration_index=iteration_index,
        poc=poc or PocRecord(),
        outcome=outcome or OutcomeRecord(),
        blocker_events=events,
        cleared_blockers=cleared,
        terminal_blocker=terminal,
        min_distance=min_dist,
        total_blockers_emitted=len(events),
        parse_warnings=warnings,
    )


def _summarize(it: IterationTrace) -> str:
    lines = [
        f"iteration #{it.iteration_index}",
        f"  blockers emitted: {it.total_blockers_emitted}",
        f"  min_distance:     {it.min_distance}",
        f"  reached_sink:     {it.outcome.reached_sink}",
        f"  http_status:      {it.outcome.http_status}",
    ]
    if it.terminal_blocker:
        tb = it.terminal_blocker
        loc = tb.location
        lines.append(
            f"  terminal blocker: {tb.kind} @ "
            f"{loc.get('file', '?')}:{loc.get('line', '?')} "
            f"({loc.get('opcode', '')})"
        )
        if tb.kind == "predicate_guard":
            pred = tb.raw.get("predicate", {})
            ops  = pred.get("operands", {})
            lhs  = ops.get("lhs", {})
            lines.append(
                f"    op1.value={lhs.get('value', '?')!r:<25} "
                f"op1.type={lhs.get('type', '?'):<8} "
                f"truthy={pred.get('condition_value')} "
                f"jumped={pred.get('jumped')}"
            )
        elif tb.kind == "early_exit":
            ex = tb.raw.get("exit", {})
            mech = ex.get("mechanism", "?")
            cls  = tb.raw.get("exit", {}).get("exception_class") or ""
            msg  = (ex.get("message", {}).get("value", "") or "")[:120]
            extra = f" exception_class={cls!r}" if cls else ""
            lines.append(f"    mechanism={mech}{extra}  message={msg!r}")
    if it.parse_warnings:
        lines.append(f"  parse warnings ({len(it.parse_warnings)}):")
        for w in it.parse_warnings[:5]:
            lines.append(f"    - {w}")
    return "\n".join(lines)


def _main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Parse VIPER blocker JSONL → IterationTrace.")
    ap.add_argument("--log", required=True, help="Path to *.jsonl produced by PHP hook.")
    ap.add_argument("--iter-index", type=int, default=0)
    ap.add_argument("--reached-sink", action="store_true",
                    help="Mark this iteration as having reached the sink.")
    ap.add_argument("--http-status", type=int, default=0)
    ap.add_argument("--json", action="store_true",
                    help="Output full IterationTrace JSON instead of summary.")
    ap.add_argument("--max-events", type=int, default=20,
                    help="When --json absent: print first N events as well.")
    args = ap.parse_args()

    outcome = OutcomeRecord(http_status=args.http_status,
                            reached_sink=args.reached_sink)
    it = aggregate_iteration(
        iteration_index=args.iter_index,
        blocker_log_path=args.log,
        outcome=outcome,
    )

    if args.json:
        print(json.dumps(it.to_dict(), indent=2, ensure_ascii=False))
        return

    print(_summarize(it))
    if it.blocker_events:
        print(f"\n  first {min(args.max_events, len(it.blocker_events))} events:")
        for b in it.blocker_events[:args.max_events]:
            loc = b.location
            tail = ""
            if b.kind == "predicate_guard":
                pred = b.raw.get("predicate", {})
                tail = (f"  [{loc.get('opcode', '')}, "
                        f"truthy={pred.get('condition_value')}, "
                        f"jumped={pred.get('jumped')}, "
                        f"d={b.distance_at_blocker}]")
            print(f"    {loc.get('file', '?')}:{loc.get('line', '?')}  "
                  f"{b.kind}{tail}")


if __name__ == "__main__":
    _main()
