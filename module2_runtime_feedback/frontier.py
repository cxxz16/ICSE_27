
from __future__ import annotations

import math
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl

from module2_runtime_feedback.blocker_aggregator import IterationTrace, BlockerEvent


_INF_DIST = math.inf


_DEFAULT_BLOCKER_BUDGET = 3

_DEFAULT_TOP_K = 3

_DEFAULT_WINDOW = 8

_DEFAULT_SPEC_MAX_TRY = 3


@dataclass
class FrontierState:

    iteration_index: int
    poc_params: dict
    trace: IterationTrace

    score: tuple
    min_distance: float
    deepest_location: tuple
    call_chain_signature: tuple
    dispatch_callees_observed: list[str]
    target_path_events: int
    wrong_dispatch_count: int
    over_budget_penalty: int
    terminal_blocker_loc: tuple
    terminal_blocker_kind: str
    terminal_blocker_hits: int = 0

    def short(self) -> str:
        f, l = self.terminal_blocker_loc
        return (f"iter#{self.iteration_index} score={self.score} "
                f"d={self.min_distance} term={self.terminal_blocker_kind}@{f}:{l} "
                f"target_evt={self.target_path_events} "
                f"wrong_dispatch={self.wrong_dispatch_count}")


def score_tuple(
    *,
    reached_sink: bool,
    min_distance: float,
    target_path_events: int,
    wrong_dispatch_count: int,
    over_budget_penalty: int,
) -> tuple:
    return (
        0 if reached_sink else 1,
        min_distance,
        -target_path_events,
        wrong_dispatch_count,
        over_budget_penalty,
    )


def is_better(a: FrontierState, b: Optional[FrontierState]) -> bool:
    if b is None:
        return True
    a_bailout = bool(getattr(a.trace, "bailout_end", False))
    b_bailout = bool(getattr(b.trace, "bailout_end", False))
    if a_bailout and not b_bailout:
        return False
    if b_bailout and not a_bailout:
        return True
    return a.score < b.score


def _basename(p: str) -> str:
    if not p:
        return ""
    return p.rsplit("/", 1)[-1]


def _decode_body(body: str) -> dict:
    try:
        return dict(parse_qsl(body, keep_blank_values=True))
    except Exception:
        return {}


def _expected_callees(pipeline_result: dict) -> set[str]:
    out: set[str] = set()
    for dc in pipeline_result.get("constraints", {}).get("dispatch_constraints", []):
        c = dc.get("callee", "")
        if c:
            out.add(c)
            if "::" in c:
                out.add(c.rsplit("::", 1)[1])
    return out


def _known_dispatch_sites(pipeline_result: dict) -> set[tuple[str, int]]:
    out: set[tuple[str, int]] = set()
    for dc in pipeline_result.get("constraints", {}).get("dispatch_constraints", []):
        f = dc.get("site_file", "")
        try:
            ln = int(dc.get("site_line", 0))
        except (ValueError, TypeError):
            continue
        out.add((_basename(f), ln))
    return out


def _trace_min_distance(trace: IterationTrace) -> float:
    if trace.min_distance is None or trace.min_distance < 0:
        return _INF_DIST
    return float(trace.min_distance)


def _deepest_location(trace: IterationTrace) -> tuple:
    best_basename = ""
    best_line = -1
    for b in trace.blocker_events:
        try:
            ln = int(b.location.get("line", 0))
        except (ValueError, TypeError):
            continue
        if ln > best_line:
            best_line = ln
            best_basename = _basename(b.location.get("file", ""))
    return (best_basename, max(0, best_line))


def _call_chain_signature(
    trace: IterationTrace, entry_uri: str = ""
) -> tuple:
    callees: list[str] = []
    for b in trace.blocker_events:
        if b.kind == "dispatch_observed":
            d = b.raw.get("dispatch", {})
            c = d.get("callee_actual", "")
            if c:
                callees.append(c)
    term = trace.terminal_blocker
    term_loc = (
        (_basename(term.location.get("file", "")),
         int(term.location.get("line", 0)) if str(term.location.get("line", 0)).isdigit() else 0)
        if term else ("", 0)
    )
    return (entry_uri, tuple(callees), term_loc)


def _count_target_and_wrong_dispatch(
    trace: IterationTrace, expected: set[str]
) -> tuple[int, int]:
    if not expected:
        return (0, 0)
    target = 0
    wrong = 0
    for b in trace.blocker_events:
        if b.kind != "dispatch_observed":
            continue
        d = b.raw.get("dispatch", {})
        c = d.get("callee_actual", "")
        if not c:
            continue
        is_target = (c in expected)
        if not is_target and "::" in c:
            is_target = c.rsplit("::", 1)[1] in expected
        if is_target:
            target += 1
        else:
            wrong += 1
    return target, wrong


@dataclass
class FrontierTracker:

    expected_callees: set[str] = field(default_factory=set)
    known_dispatch_sites: set = field(default_factory=set)
    budget: int = _DEFAULT_BLOCKER_BUDGET
    plateau_patience: int = _DEFAULT_WINDOW
    top_k: int = _DEFAULT_TOP_K
    speculative_max_try: int = _DEFAULT_SPEC_MAX_TRY

    if_constraints: list = field(default_factory=list)

    _bests: list[FrontierState] = field(default_factory=list)
    history: list[FrontierState] = field(default_factory=list)
    blocker_visit_count: dict = field(default_factory=dict)
    runtime_discoveries: dict = field(default_factory=dict)

    _window: deque = field(default_factory=lambda: deque(maxlen=_DEFAULT_WINDOW))
    _backtrack_consumed: set = field(default_factory=set)
    _speculative_streak: int = 0
    _plateau_kind: str = "ok"

    def __post_init__(self):
        if self._window.maxlen != self.plateau_patience:
            self._window = deque(self._window, maxlen=self.plateau_patience)

    @classmethod
    def from_pipeline(cls, pipeline_result: dict,
                      budget: int = _DEFAULT_BLOCKER_BUDGET,
                      plateau_patience: int = _DEFAULT_WINDOW,
                      top_k: int = _DEFAULT_TOP_K,
                      speculative_max_try: int = _DEFAULT_SPEC_MAX_TRY):
        return cls(
            expected_callees=_expected_callees(pipeline_result),
            known_dispatch_sites=_known_dispatch_sites(pipeline_result),
            budget=budget,
            plateau_patience=plateau_patience,
            top_k=top_k,
            speculative_max_try=speculative_max_try,
            if_constraints=pipeline_result.get("constraints", {})
                                          .get("if_constraints", []) or [],
        )

    @property
    def best(self) -> Optional[FrontierState]:
        return self._bests[0] if self._bests else None

    @property
    def bests(self) -> list[FrontierState]:
        return list(self._bests)

    @property
    def plateau_kind(self) -> str:
        return self._plateau_kind

    @property
    def in_plateau(self) -> bool:
        return self._plateau_kind != "ok"

    def build_state(self, iteration_index: int, trace: IterationTrace,
                    entry_uri: str = "") -> FrontierState:
        term = trace.terminal_blocker
        if term:
            key = (term.location.get("file", ""),
                   int(term.location.get("line", 0))
                   if str(term.location.get("line", 0)).isdigit() else 0,
                   term.kind)
            self.blocker_visit_count[key] = self.blocker_visit_count.get(key, 0) + 1
            terminal_hits = self.blocker_visit_count[key]
            over_budget = max(0, terminal_hits - self.budget)
        else:
            terminal_hits = 0
            over_budget = 0

        target_evt, wrong_dispatch = _count_target_and_wrong_dispatch(
            trace, self.expected_callees)
        min_dist = _trace_min_distance(trace)
        reached = bool(trace.outcome.reached_sink)
        score = score_tuple(
            reached_sink=reached,
            min_distance=min_dist,
            target_path_events=target_evt,
            wrong_dispatch_count=wrong_dispatch,
            over_budget_penalty=over_budget,
        )
        term = trace.terminal_blocker
        term_loc = (
            (_basename(term.location.get("file", "")),
             int(term.location.get("line", 0)) if str(term.location.get("line", 0)).isdigit() else 0)
            if term else ("", 0)
        )
        term_kind = term.kind if term else ""
        return FrontierState(
            iteration_index=iteration_index,
            poc_params=_decode_body(trace.poc.body),
            trace=trace,
            score=score,
            min_distance=min_dist,
            deepest_location=_deepest_location(trace),
            call_chain_signature=_call_chain_signature(trace, entry_uri),
            dispatch_callees_observed=[
                b.raw.get("dispatch", {}).get("callee_actual", "")
                for b in trace.blocker_events if b.kind == "dispatch_observed"
            ],
            target_path_events=target_evt,
            wrong_dispatch_count=wrong_dispatch,
            over_budget_penalty=over_budget,
            terminal_blocker_loc=term_loc,
            terminal_blocker_kind=term_kind,
            terminal_blocker_hits=terminal_hits,
        )

    def observe(self, state: FrontierState) -> bool:
        self.history.append(state)

        for b in state.trace.blocker_events:
            if b.kind != "dispatch_observed":
                continue
            loc_basename = _basename(b.location.get("file", ""))
            try:
                ln = int(b.location.get("line", 0))
            except (ValueError, TypeError):
                continue
            site = (loc_basename, ln)
            if site in self.known_dispatch_sites:
                continue
            callee = b.raw.get("dispatch", {}).get("callee_actual", "")
            if not callee:
                continue
            entry = self.runtime_discoveries.setdefault(
                site, {"callees": set(), "first_iter": state.iteration_index,
                        "last_iter": state.iteration_index})
            entry["callees"].add(callee)
            entry["last_iter"] = state.iteration_index

        entered_top_k = self._maybe_admit_to_top_k(state)
        self._window.append(state)
        prev_kind = self._plateau_kind
        self._plateau_kind = self._classify_plateau()

        if self._plateau_kind == "regress_speculative" and prev_kind == "regress_speculative":
            self._speculative_streak += 1
        elif self._plateau_kind == "regress_speculative":
            self._speculative_streak = 1
        else:
            self._speculative_streak = 0

        return entered_top_k

    def _maybe_admit_to_top_k(self, state: FrontierState) -> bool:
        sig = state.call_chain_signature
        existing_idx = next(
            (i for i, b in enumerate(self._bests)
             if b.call_chain_signature == sig),
            None,
        )
        if existing_idx is not None:
            if is_better(state, self._bests[existing_idx]):
                self._bests[existing_idx] = state
                self._bests.sort(key=lambda s: s.score)
                return True
            return False

        if len(self._bests) < self.top_k:
            self._bests.append(state)
            self._bests.sort(key=lambda s: s.score)
            return True

        worst = self._bests[-1]
        if is_better(state, worst):
            self._bests[-1] = state
            self._bests.sort(key=lambda s: s.score)
            return True
        return False

    def _classify_plateau(self) -> str:
        if len(self._window) < self._window.maxlen:
            return "ok"

        window = list(self._window)
        dists  = [s.min_distance for s in window]

        if self._bests and self._bests[0].iteration_index == window[-1].iteration_index:
            return "ok"

        if window[-1].terminal_blocker_hits >= self.budget:
            return "stuck"

        if all(d == dists[0] for d in dists):
            return "stuck"

        if all(math.isfinite(d) for d in dists):
            if all(dists[i] < dists[i + 1] for i in range(len(dists) - 1)):
                if self._path_has_speculative_branch_in_window():
                    return "regress_speculative"
                return "regress_dead"

        return "ok"

    def _path_has_speculative_branch_in_window(self) -> bool:
        if not self.if_constraints:
            return False
        cons_by_loc: dict = {}
        for c in self.if_constraints:
            src = c.get("source_file") or ""
            bn = _basename(src) if src else ""
            cons_by_loc[(bn, c.get("lineno", -1))] = c

        for state in self._window:
            for b in state.trace.blocker_events:
                if b.kind != "predicate_guard":
                    continue
                pred = b.raw.get("predicate", {})
                if not pred.get("condition_value", False):
                    continue
                bn = _basename(b.location.get("file", ""))
                try:
                    ln = int(b.location.get("line", 0))
                except (ValueError, TypeError):
                    continue
                c = cons_by_loc.get((bn, ln)) or cons_by_loc.get(("", ln))
                if c and c.get("body_contains_dispatch", False):
                    return True
        return False

    def next_backtrack_target(self) -> Optional[FrontierState]:
        for b in self._bests:
            if b.iteration_index in self._backtrack_consumed:
                continue
            self._backtrack_consumed.add(b.iteration_index)
            return b
        return None

    def next_base_params(self, *, fallback: dict) -> dict:
        if self._plateau_kind == "ok":
            return fallback
        if self._plateau_kind == "regress_speculative" \
           and self._speculative_streak < self.speculative_max_try:
            return fallback
        target = self.next_backtrack_target()
        if target is not None:
            return target.poc_params
        return fallback

    def over_budget_blockers(self) -> list[tuple]:
        return [
            k for k, count in self.blocker_visit_count.items()
            if count >= self.budget
        ]

    def diverged_from_best(self, state: FrontierState) -> bool:
        if self.best is None or state is self.best:
            return False
        if state.call_chain_signature == self.best.call_chain_signature:
            return False
        if is_better(state, self.best):
            return False
        return True

    def summary(self) -> dict:
        latest = self.history[-1] if self.history else None
        best = self.best
        return {
            "best_iter":      best.iteration_index if best else None,
            "best_score":     list(best.score) if best else None,
            "best_signature": (
                [best.call_chain_signature[0]]
                + list(best.call_chain_signature[1])
                + [list(best.call_chain_signature[2])]
                if best else None
            ),
            "best_poc":       best.poc_params if best else None,
            "top_k_bests": [
                {"iter": b.iteration_index,
                 "score": list(b.score),
                 "min_distance": (b.min_distance if math.isfinite(b.min_distance) else None),
                 "poc": b.poc_params}
                for b in self._bests
            ],
            "over_budget":    [
                {"file": _basename(f), "line": ln, "kind": k,
                 "count": self.blocker_visit_count[(f, ln, k)]}
                for (f, ln, k) in self.over_budget_blockers()
            ],
            "current_latest_iter": latest.iteration_index if latest else 0,
            "latest_score":   list(latest.score) if latest else None,
            "regressed_vs_best": (
                bool(latest and best and latest.score > best.score)
            ),
            "diverged_from_best": (
                bool(latest and self.diverged_from_best(latest))
            ),
            "plateau_kind":          self._plateau_kind,
            "in_plateau":            self.in_plateau,
            "plateau_window":        self.plateau_patience,
            "speculative_streak":    self._speculative_streak,
            "speculative_max_try":   self.speculative_max_try,
            "backtrack_consumed":    sorted(self._backtrack_consumed),
            "plateau_streak":        (self.plateau_patience
                                       if self._plateau_kind != "ok" else 0),
            "plateau_patience":      self.plateau_patience,
            "runtime_discoveries": [
                {"file": f, "line": ln,
                 "callees": sorted(d["callees"]),
                 "first_iter": d["first_iter"], "last_iter": d["last_iter"]}
                for (f, ln), d in self.runtime_discoveries.items()
            ],
        }
