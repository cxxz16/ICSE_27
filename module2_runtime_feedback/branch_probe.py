from __future__ import annotations

import json
import random
import subprocess

BRANCH_KINDS = ("branch_compare", "switch_observed")


def gen_nonce(rng: random.Random) -> str:
    return str(rng.randint(10 ** 9, 10 ** 10 - 1))


def build_nonce_assignment(params, *, seed=None):
    rng = random.Random(seed)
    assignment, nonce_map = {}, {}
    for p in params:
        while True:
            n = gen_nonce(rng)
            if n in nonce_map:
                continue
            if any(n in m or m in n for m in nonce_map):
                continue
            break
        assignment[p] = n
        nonce_map[n] = p
    return assignment, nonce_map


def read_branch_events(container, blocker_log="/tmp/viper.jsonl"):
    raw = subprocess.run(
        ["docker", "exec", container, "cat", blocker_log],
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    out = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            ev = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if ev.get("kind") in BRANCH_KINDS:
            out.append(ev)
    return out


def read_all_events(container, blocker_log="/tmp/viper.jsonl"):
    raw = subprocess.run(
        ["docker", "exec", container, "cat", blocker_log],
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    out = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def probe(container, send_fn, *, blocker_log="/tmp/viper.jsonl"):
    subprocess.run(["docker", "exec", container, "truncate", "-s", "0", blocker_log],
                   capture_output=True)
    send_fn()
    return read_all_events(container, blocker_log)


if __name__ == "__main__":
    asg, nm = build_nonce_assignment(["rule_1", "operator", "type"], seed=42)
    print("assignment(injection):", asg)
    print("nonce_map(reverse) :", nm)
    assert set(asg) == {"rule_1", "operator", "type"}
    assert all(nm[n] == p for p, n in asg.items()), "nonce_map must map back to the parameters"
    assert len(nm) == 3, "three parameters, three distinct nonces"
    for a in nm:
        for b in nm:
            if a != b:
                assert a not in b, f"a nonce being a substring of another causes partial mismatch: {a} in {b}"
    assert all(n.isdigit() and len(n) == 10 for n in nm), "pure digits, 10 chars"

    sample = (
        '{"kind":"request_start"}\n'
        '{"kind":"branch_compare","operands":{"lhs":{"value":"' + asg["rule_1"] + '"}}}\n'
        'GARBAGE LINE\n'
        '{"kind":"switch_observed","cases":["a","b"]}\n'
    )
    parsed = [json.loads(l) for l in sample.splitlines()
              if l.strip() and l.strip().startswith("{")]
    kept = [e for e in parsed if e.get("kind") in BRANCH_KINDS]
    assert len(kept) == 2, "keep only branch_compare/switch_observed"

    print("\n✓ self-test passed: random nonce + mapping record + mutual non-substring + branch event filtering")
