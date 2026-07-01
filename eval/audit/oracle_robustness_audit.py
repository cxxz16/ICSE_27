
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, parse_qsl

_VIPER_DIR = Path(__file__).resolve().parent.parent
if str(_VIPER_DIR) not in sys.path:
    sys.path.insert(0, str(_VIPER_DIR))

from module3_differential_oracle.differential_oracle import observe, diff, Observation, DifferentialVerdict
from module3_differential_oracle.sentinel_injector import SentinelInjector


@dataclass
class AxisStats:
    n: int = 0
    mean: float = 0.0
    stdev: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    distinct: int = 0

    @classmethod
    def from_numbers(cls, xs: list[float]) -> "AxisStats":
        if not xs:
            return cls()
        return cls(
            n=len(xs),
            mean=statistics.fmean(xs),
            stdev=(statistics.pstdev(xs) if len(xs) > 1 else 0.0),
            min_val=min(xs), max_val=max(xs),
            distinct=len(set(xs)),
        )


@dataclass
class PayloadResult:
    param: str
    payload: str
    mal_obs: list[dict] = field(default_factory=list)
    single_shot_verdict: str = ""
    single_shot_reason: str = ""
    robust_verdict: str = ""
    robust_reason: str = ""
    axes: dict = field(default_factory=dict)


@dataclass
class AuditResult:
    label: str
    n_baseline: int = 0
    n_mal_per_payload: int = 0
    baseline_axes: dict = field(default_factory=dict)
    baseline_sentinel_seen_rate: float = 0.0
    baseline_status_modes: list = field(default_factory=list)
    payload_results: list[PayloadResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _today_admin_token() -> str:
    import datetime
    return hashlib.md5(
        ("VIPER-AUDIT-" + datetime.datetime.utcnow().strftime("%Y-%m-%d")).encode()
    ).hexdigest()


def _docker_cp_in(container: str, src: str, dst: str) -> bool:
    proc = subprocess.run(
        ["docker", "cp", src, f"{container}:{dst}"],
        capture_output=True, text=True,
    )
    return proc.returncode == 0


def _body_normalize(s: str) -> str:
    import re
    s = re.sub(r"VIPER_SENTINEL_[0-9a-f]+", "<SENT>", s or "")
    s = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?", "<TS>", s)
    return s


def _body_hash(s: str) -> str:
    return hashlib.md5(_body_normalize(s).encode("utf-8", "replace")).hexdigest()[:12]


def _obs_summary(o: Observation) -> dict:
    return {
        "status": o.http_status,
        "body_len": o.body_len,
        "body_hash": _body_hash(o.response_body),
        "recv_size": o.recv_size,
        "sentinel_seen": o.sentinel_seen,
    }


def _run_baseline_pool(
    *, n: int, container: str, entry_url: str, body: str,
    sentinel_uuid: str, headers: dict, sleep_ms: int = 100,
) -> list[Observation]:
    pool: list[Observation] = []
    for i in range(n):
        o = observe(
            label=f"safe[{i}]", container=container, entry_url=entry_url,
            body=body, extra_headers=headers, sentinel_uuid=sentinel_uuid,
        )
        pool.append(o)
        time.sleep(sleep_ms / 1000.0)
    return pool


def _run_payload_pool(
    *, n: int, container: str, entry_url: str, baseline_params: dict,
    param: str, payload: str, sentinel_uuid: str, headers: dict,
    sleep_ms: int = 100,
) -> list[Observation]:
    mal_params = dict(baseline_params)
    base_val = str(mal_params.get(param, ""))
    mal_params[param] = base_val + payload
    mal_body = urlencode({k: str(v) for k, v in mal_params.items()})
    pool: list[Observation] = []
    for i in range(n):
        o = observe(
            label=f"mal[{i}|{param}={payload!r}]",
            container=container, entry_url=entry_url, body=mal_body,
            extra_headers=headers, sentinel_uuid=sentinel_uuid,
        )
        pool.append(o)
        time.sleep(sleep_ms / 1000.0)
    return pool


def _axis_summary(pool: list[Observation]) -> dict:
    statuses = [o.http_status for o in pool]
    body_lens = [o.body_len for o in pool]
    recv_sizes = [o.recv_size for o in pool]
    hashes = [_body_hash(o.response_body) for o in pool]
    return {
        "status":    AxisStats.from_numbers([float(x) for x in statuses]),
        "body_len":  AxisStats.from_numbers([float(x) for x in body_lens]),
        "recv_size": AxisStats.from_numbers([float(x) for x in recv_sizes]),
        "body_distinct_hashes": len(set(hashes)),
    }


def _robust_judgment(
    baseline_axes: dict, mal_pool: list[Observation],
    *, k_sigma: float = 2.0, min_delta_pct: float = 0.05,
) -> tuple[str, str, dict]:
    if any(not o.sentinel_seen for o in mal_pool):
        return ("INDETERMINATE",
                "at least one mal run did not see sentinel (reach failed under payload)",
                {})
    mal_axes = _axis_summary(mal_pool)
    out: dict[str, dict] = {}
    deviations: list[tuple[str, float, str]] = []
    for axis in ("status", "body_len", "recv_size"):
        b: AxisStats = baseline_axes[axis]
        m: AxisStats = mal_axes[axis]
        abs_delta = abs(m.mean - b.mean)
        if b.stdev > 0:
            z = abs_delta / b.stdev
            outside = z > k_sigma
            reason_axis = f"z={z:.2f}σ (base.μ={b.mean:.1f}, base.σ={b.stdev:.2f}, mal.μ={m.mean:.1f})"
        else:
            denom = max(b.mean, 1.0)
            pct = abs_delta / denom
            outside = pct >= min_delta_pct
            reason_axis = f"Δ={abs_delta:.1f} ({pct*100:.1f}% of base.μ={b.mean:.1f}, mal.μ={m.mean:.1f})"
        out[axis] = {
            "base_mean": b.mean, "base_stdev": b.stdev,
            "mal_mean": m.mean, "mal_stdev": m.stdev,
            "abs_delta": abs_delta, "outside_envelope": outside,
            "reason": reason_axis,
        }
        if outside:
            deviations.append((axis, abs_delta, reason_axis))
    base_hashes = set()
    if deviations:
        ax, _, ev = max(deviations, key=lambda t: t[1])
        return ("CONFIRMED",
                f"axis {ax} outside baseline envelope: {ev}",
                out)
    return ("NEGATIVE",
            "all axes within baseline envelope; payload did not perturb backend",
            out)


def _single_shot_verdict(
    safe: Observation, mal: Observation
) -> DifferentialVerdict:
    return diff(safe, mal)


def run_audit(
    *,
    label: str,
    container: str, entry_url: str,
    sink_file: str, sink_line: int,
    sink_in_container: str,
    baseline_body: str,
    mutable_params: list[str],
    payloads: list[str],
    n_baseline: int, n_mal: int,
    extra_headers: dict,
) -> AuditResult:
    res = AuditResult(label=label, n_baseline=n_baseline, n_mal_per_payload=n_mal)
    with SentinelInjector(sink_file, sink_line) as sent:
        if not _docker_cp_in(container, sink_file, sink_in_container):
            res.notes.append(
                f"WARN docker cp sink_file → container failed (path={sink_in_container})")
        baseline_pool = _run_baseline_pool(
            n=n_baseline, container=container, entry_url=entry_url,
            body=baseline_body, sentinel_uuid=sent.uuid, headers=extra_headers,
        )
        seen_rate = sum(1 for o in baseline_pool if o.sentinel_seen) / max(1, n_baseline)
        res.baseline_sentinel_seen_rate = seen_rate
        res.baseline_status_modes = sorted({o.http_status for o in baseline_pool})
        baseline_axes = _axis_summary(baseline_pool)
        res.baseline_axes = {k: (asdict(v) if isinstance(v, AxisStats) else v)
                              for k, v in baseline_axes.items()}
        if seen_rate < 1.0:
            res.notes.append(
                f"baseline sentinel seen rate = {seen_rate*100:.0f}% — reach is "
                f"flaky; oracle on this baseline is inherently noisy")

        baseline_params = dict(parse_qsl(baseline_body, keep_blank_values=True))
        for param in mutable_params:
            if param not in baseline_params:
                res.notes.append(f"param {param!r} not in baseline body — skipped")
                continue
            for payload in payloads:
                mal_pool = _run_payload_pool(
                    n=n_mal, container=container, entry_url=entry_url,
                    baseline_params=baseline_params, param=param, payload=payload,
                    sentinel_uuid=sent.uuid, headers=extra_headers,
                )
                ss = _single_shot_verdict(baseline_pool[0], mal_pool[0])
                r_verdict, r_reason, r_axes = _robust_judgment(baseline_axes, mal_pool)
                pr = PayloadResult(
                    param=param, payload=payload,
                    mal_obs=[_obs_summary(o) for o in mal_pool],
                    single_shot_verdict=ss.verdict,
                    single_shot_reason=ss.reason,
                    robust_verdict=r_verdict,
                    robust_reason=r_reason,
                    axes=r_axes,
                )
                res.payload_results.append(pr)
    return res


def _cross_scenario_summary(results: list[AuditResult]) -> str:
    if len(results) < 2:
        return ""
    lines: list[str] = []
    lines.append("## Cross-scenario flips (baseline noise masking)")
    lines.append("")
    by_key: dict[tuple[str, str], dict[str, str]] = {}
    for res in results:
        for pr in res.payload_results:
            by_key.setdefault((pr.param, pr.payload), {})[res.label] = pr.robust_verdict
    flips = []
    for (p, pl), verdicts in by_key.items():
        if len(set(verdicts.values())) > 1:
            flips.append((p, pl, verdicts))
    if not flips:
        lines.append("No cross-scenario flips: every (param, payload) gets the same "
                     "robust verdict in every scenario. Either the oracle is "
                     "fully robust to the constructed baseline noise, OR the "
                     "scenarios don't actually differ enough — inspect the "
                     "noise envelope rows above to tell which.")
        return "\n".join(lines) + "\n"
    lines.append(f"⚠ **{len(flips)} (param, payload) pairs flip robust verdict across "
                 f"scenarios.** Each flip is evidence that *baseline state* — not "
                 f"the payload — determines the oracle's output. In any scenario "
                 f"where this payload comes out NEGATIVE while another shows it "
                 f"CONFIRMED, the baseline has masked a real signal.")
    lines.append("")
    lines.append("| param | payload | " +
                 " | ".join(res.label for res in results) + " |")
    lines.append("|" + "---|" * (len(results) + 2))
    for p, pl, verdicts in flips:
        row = f"| `{p}` | `{pl}` |"
        for res in results:
            row += f" {verdicts.get(res.label, '—')} |"
        lines.append(row)
    return "\n".join(lines) + "\n"


def _emit_markdown(results: list[AuditResult], *, k_sigma: float, min_delta_pct: float) -> str:
    lines: list[str] = []
    lines.append("# Differential-oracle robustness audit")
    lines.append("")
    lines.append(f"Settings: `k_sigma={k_sigma}`, `min_delta_pct={min_delta_pct*100:.1f}%`")
    lines.append("")
    for res in results:
        lines.append(f"## Scenario · `{res.label}`")
        lines.append("")
        lines.append(f"- baseline runs: **{res.n_baseline}**")
        lines.append(f"- mal runs per payload: **{res.n_mal_per_payload}**")
        lines.append(f"- baseline sentinel seen rate: **{res.baseline_sentinel_seen_rate*100:.0f}%**")
        lines.append(f"- baseline HTTP status modes: `{res.baseline_status_modes}`")
        if res.notes:
            for n in res.notes:
                lines.append(f"- ⚠ {n}")
        lines.append("")
        lines.append("### Baseline noise envelope")
        lines.append("")
        lines.append("| axis | mean | stdev | range |")
        lines.append("|------|------|-------|-------|")
        for axis in ("status", "body_len", "recv_size"):
            a = res.baseline_axes.get(axis, {})
            lines.append(f"| {axis} | {a.get('mean',0):.1f} | "
                         f"{a.get('stdev',0):.2f} | "
                         f"[{a.get('min_val',0):.0f}, {a.get('max_val',0):.0f}] |")
        dh = res.baseline_axes.get('body_distinct_hashes', 0)
        lines.append(f"")
        lines.append(f"distinct normalized body hashes across baseline pool: **{dh}** "
                     f"({'flicker-free' if dh == 1 else 'baseline content varies — noise present'})")
        lines.append("")
        lines.append("### Per-payload verdicts: single-shot vs robust")
        lines.append("")
        lines.append("| param | payload | single-shot | robust | agree? | strongest axis |")
        lines.append("|-------|---------|-------------|--------|--------|----------------|")
        flip_count = 0
        for pr in res.payload_results:
            agree = pr.single_shot_verdict == pr.robust_verdict
            if not agree:
                flip_count += 1
            outside = [(ax, d["abs_delta"]) for ax, d in pr.axes.items()
                       if d.get("outside_envelope")]
            if outside:
                strongest = max(outside, key=lambda t: t[1])[0]
            else:
                strongest = "—"
            lines.append(f"| `{pr.param}` | `{pr.payload}` | "
                         f"{pr.single_shot_verdict} | {pr.robust_verdict} | "
                         f"{'✓' if agree else '✗ FLIP'} | {strongest} |")
        lines.append("")
        lines.append(f"single-shot vs robust **disagreements**: **{flip_count}/{len(res.payload_results)}**")
        flipped = [pr for pr in res.payload_results
                   if pr.single_shot_verdict != pr.robust_verdict]
        if flipped:
            lines.append("")
            lines.append("### Disagreement details")
            for pr in flipped:
                lines.append("")
                lines.append(f"**`{pr.param}` ← `{pr.payload}`**")
                lines.append(f"- single-shot: {pr.single_shot_verdict} — {pr.single_shot_reason[:140]}")
                lines.append(f"- robust:      {pr.robust_verdict} — {pr.robust_reason[:140]}")
                for ax, d in pr.axes.items():
                    flag = "★" if d.get("outside_envelope") else " "
                    lines.append(f"  - {flag} {ax}: {d.get('reason','')}")
        lines.append("")
    return "\n".join(lines) + "\n"


_DEFAULT_PAYLOADS = [
    "'", '"', "\\",
    "';",
    "' OR '1'='1",
    "' OR 1=1--",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
]


def _main():
    ap = argparse.ArgumentParser(
        description="Audit differential-oracle robustness under noisy baseline.")
    ap.add_argument("--container", default="viper-sqli-demo")
    ap.add_argument("--entry-url", required=True,
                    help="Full POST URL (e.g. http://localhost:8765/sqli_chain_demo/index.php)")
    ap.add_argument("--sink-file", required=True,
                    help="Host path of file containing the sink line "
                         "(passed to SentinelInjector — restored on exit)")
    ap.add_argument("--sink-line", type=int, required=True)
    ap.add_argument("--sink-in-container", required=True,
                    help="Container-side path of the same sink_file (for docker cp)")
    ap.add_argument("--baseline-poc", required=True,
                    help="URL-encoded POST body that reaches the sink benignly.")
    ap.add_argument("--noisy-baseline-poc", default="",
                    help="Optional second baseline whose response itself "
                         "contains backend errors. Surfaces noisy-baseline "
                         "robustness.")
    ap.add_argument("--mutable-params", required=True,
                    help="Comma-separated param names to inject payloads into.")
    ap.add_argument("--n-baseline", type=int, default=5)
    ap.add_argument("--n-mal", type=int, default=3)
    ap.add_argument("--k-sigma", type=float, default=2.0)
    ap.add_argument("--min-delta-pct", type=float, default=0.05)
    ap.add_argument("--admin-token", default="",
                    help="Override admin token; default = md5('VIPER-AUDIT-' + UTC date)")
    ap.add_argument("--report", default="-")
    ap.add_argument("--json", default="")
    ap.add_argument("--payloads", default="",
                    help="Comma-separated payloads; default = built-in SQLi set.")
    args = ap.parse_args()

    headers = {"X-Admin-Token": args.admin_token or _today_admin_token()}
    mutable = [p.strip() for p in args.mutable_params.split(",") if p.strip()]
    payloads = ([p for p in args.payloads.split(",") if p]
                if args.payloads else _DEFAULT_PAYLOADS)

    scenarios: list[AuditResult] = []
    print(f"[audit] scenario 1: plain baseline …", file=sys.stderr)
    r1 = run_audit(
        label="plain", container=args.container, entry_url=args.entry_url,
        sink_file=args.sink_file, sink_line=args.sink_line,
        sink_in_container=args.sink_in_container,
        baseline_body=args.baseline_poc,
        mutable_params=mutable, payloads=payloads,
        n_baseline=args.n_baseline, n_mal=args.n_mal,
        extra_headers=headers,
    )
    scenarios.append(r1)

    if args.noisy_baseline_poc:
        print(f"[audit] scenario 2: noisy baseline …", file=sys.stderr)
        r2 = run_audit(
            label="noisy_baseline",
            container=args.container, entry_url=args.entry_url,
            sink_file=args.sink_file, sink_line=args.sink_line,
            sink_in_container=args.sink_in_container,
            baseline_body=args.noisy_baseline_poc,
            mutable_params=mutable, payloads=payloads,
            n_baseline=args.n_baseline, n_mal=args.n_mal,
            extra_headers=headers,
        )
        scenarios.append(r2)

    md = _emit_markdown(scenarios, k_sigma=args.k_sigma,
                         min_delta_pct=args.min_delta_pct)
    md += "\n" + _cross_scenario_summary(scenarios)
    if args.report == "-":
        print(md)
    else:
        Path(args.report).write_text(md, encoding="utf-8")
        print(f"wrote {args.report}", file=sys.stderr)

    if args.json:
        payload = {
            "k_sigma": args.k_sigma,
            "min_delta_pct": args.min_delta_pct,
            "scenarios": [asdict(s) for s in scenarios],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        print(f"wrote {args.json}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(_main())
