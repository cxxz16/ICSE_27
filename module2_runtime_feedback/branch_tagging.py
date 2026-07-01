from __future__ import annotations

_CMP_KINDS = ("branch_compare", "switch_observed")


def _operand_value(ev, side):
    return ((ev.get("operands") or {}).get(side) or {}).get("value")


def _match_nonce(lhs_val, nonce_to_param):
    if lhs_val is None:
        return None
    s = str(lhs_val)
    for nonce, param in nonce_to_param.items():
        if s == str(nonce):
            return (param, str(nonce), "exact")
    for nonce, param in nonce_to_param.items():
        if str(nonce) in s:
            return (param, str(nonce), "partial")
    return None


def _candidates(ev):
    if ev.get("kind") == "switch_observed":
        return [c for c in (ev.get("cases") or []) if c is not None]
    rhs = _operand_value(ev, "rhs")
    return [rhs] if rhs is not None else []


def tag_controlled_branches(events, nonce_to_param):
    nodes: dict = {}
    for ev in events:
        if not isinstance(ev, dict) or ev.get("kind") not in _CMP_KINDS:
            continue
        m = _match_nonce(_operand_value(ev, "lhs"), nonce_to_param)
        if not m:
            continue
        param, nonce, match_kind = m
        loc = ev.get("location") or {}
        key = (loc.get("file"), loc.get("line"), loc.get("opcode"))
        node = nodes.get(key)
        if node is None:
            node = {
                "location": loc, "controlled_by": param, "nonce": nonce,
                "match": match_kind, "kind": ev.get("kind"), "candidates": [],
            }
            nodes[key] = node
        if match_kind == "exact":
            node["match"] = "exact"
        for c in _candidates(ev):
            if c not in node["candidates"]:
                node["candidates"].append(c)
    return list(nodes.values())


if __name__ == "__main__":
    NONCE = "23456432"
    nonce_to_param = {NONCE: "rule_1"}

    events = [
        {"kind": "switch_observed",
         "location": {"file": "search.class.php", "line": 1104, "opcode": "SWITCH_STRING"},
         "operands": {"lhs": {"value": NONCE, "type": "string"}},
         "cases": ["anywhere", "title", "favorite", "last_play", "year"]},
        {"kind": "branch_compare",
         "location": {"file": "search.class.php", "line": 1200, "opcode": "IS_EQUAL"},
         "operands": {"lhs": {"value": NONCE + "_x", "type": "string"},
                      "rhs": {"value": "song", "type": "string"}}},
        {"kind": "branch_compare",
         "location": {"file": "auth.class.php", "line": 80, "opcode": "IS_IDENTICAL"},
         "operands": {"lhs": {"value": "admin", "type": "string"},
                      "rhs": {"value": "guest", "type": "string"}}},
    ]

    out = tag_controlled_branches(events, nonce_to_param)
    import json
    print(json.dumps(out, ensure_ascii=False, indent=2))

    assert len(out) == 2, f"expected 2 controlled nodes tagged, got {len(out)}"
    sw = next(n for n in out if n["location"]["line"] == 1104)
    assert sw["controlled_by"] == "rule_1" and sw["match"] == "exact"
    assert "last_play" in sw["candidates"] and len(sw["candidates"]) == 5
    deriv = next(n for n in out if n["location"]["line"] == 1200)
    assert deriv["match"] == "partial" and deriv["candidates"] == ["song"]
    assert all(n["location"]["line"] != 80 for n in out), "unrelated branches must not be tagged"
    print("\n✓ self-test passed: nonce tagging + candidate enumeration + partial derivation + unrelated-branch exclusion")
