from __future__ import annotations

from module2_runtime_feedback.branch_tagging import tag_controlled_branches


class ParamDecisionNode:

    __slots__ = ("param", "candidates", "distance", "distance_estimated",
                 "controlled_branches", "source")

    def __init__(self, param, candidates, distance, *,
                 distance_estimated=False, controlled_branches=None,
                 source="runtime"):
        self.param = param
        self.candidates = list(candidates)
        self.distance = distance
        self.distance_estimated = distance_estimated
        self.controlled_branches = controlled_branches or []
        self.source = source

    def __repr__(self):
        d = f"{self.distance}{'~' if self.distance_estimated else ''}"
        return (f"<ParamDecisionNode {self.param} d={d} "
                f"cand={len(self.candidates)} branches={len(self.controlled_branches)}>")


def _order_key(n):
    d = n.distance
    if d is None or d < 0:
        d = float("inf")
    neg = float("-inf") if d == float("inf") else -d
    return (neg, bool(n.distance_estimated))


class ControllableBranchTree:

    def __init__(self, nonce_map=None):
        self.nonce_map = dict(nonce_map or {})
        self.params: dict = {}
        self._steps = 0

    def ingest_probe(self, events):
        tagged = tag_controlled_branches(events, self.nonce_map)
        for nd in tagged:
            param = nd["controlled_by"]
            loc = nd.get("location") or {}
            dist, est = self._loc_distance(loc, events)
            node = self.params.get(param)
            if node is None:
                node = ParamDecisionNode(
                    param, [], dist, controlled_branches=[], source="runtime")
                self.params[param] = node
            for c in nd.get("candidates", []):
                if c not in node.candidates:
                    node.candidates.append(c)
            if loc not in node.controlled_branches:
                node.controlled_branches.append(loc)
            if dist is not None and (node.distance is None or
                                     (node.distance < 0 <= dist) or
                                     (0 <= dist < node.distance)):
                node.distance = dist
                node.distance_estimated = est
        return self.params

    def _loc_distance(self, loc, events):
        key = (loc.get("file"), loc.get("line"), loc.get("opcode"))
        first_idx = None
        for i, ev in enumerate(events):
            l = ev.get("location") or {}
            if (l.get("file"), l.get("line"), l.get("opcode")) == key:
                d = ev.get("distance_at_blocker")
                if d is not None and float(d) >= 0:
                    return (float(d), False)
                if first_idx is None:
                    first_idx = i
        if first_idx is not None:
            for ev in events[first_idx + 1:]:
                d = ev.get("distance_at_blocker")
                if d is not None and float(d) >= 0:
                    return (float(d), True)
        return (-1.0, False)

    def add_ranged_node(self, param, candidates, distance, *, source="static"):
        node = self.params.get(param)
        if node is None:
            self.params[param] = ParamDecisionNode(
                param, list(candidates), distance, source=source)
        else:
            for c in candidates:
                if c not in node.candidates:
                    node.candidates.append(c)
            node.source = "both"
        return self.params[param]

    def search(self, reach_trigger_fn, *, max_steps=10_000):
        order = sorted(self.params.values(), key=_order_key)
        self._steps = 0
        return self._dfs(order, 0, {}, reach_trigger_fn, max_steps)

    def _dfs(self, order, i, decision, fn, max_steps):
        if self._steps >= max_steps or i == len(order):
            return None
        node = order[i]
        for v in node.candidates:
            nxt = dict(decision)
            nxt[node.param] = v
            self._steps += 1
            reached, triggered, _ = fn(nxt)
            if triggered:
                return nxt
            if not reached:
                continue
            r = self._dfs(order, i + 1, nxt, fn, max_steps)
            if r:
                return r
        return None


class SearchCursor:

    def __init__(self, tree):
        self.tree = tree
        self.order = sorted(tree.params.values(), key=_order_key)
        self.stack = []
        self.done = False
        self._empty_tried = False

    def _push(self):
        depth = len(self.stack)
        if depth >= len(self.order):
            return False
        it = iter(list(self.order[depth].candidates))
        try:
            v = next(it)
        except StopIteration:
            return False
        self.stack.append([self.order[depth].param, it, v])
        return True

    def _advance(self):
        while self.stack:
            try:
                self.stack[-1][2] = next(self.stack[-1][1])
                return True
            except StopIteration:
                self.stack.pop()
        return False

    def next_decision(self):
        if self.done:
            return None
        if not self.order:
            return None if self._empty_tried else {}
        if not self.stack and not self._push():
            return None
        return {p: v for (p, _it, v) in self.stack}

    def report(self, reached, triggered, events=None):
        if events:
            self.tree.ingest_probe(events)
        if not self.order:
            self._empty_tried = True
            if triggered:
                self.done = True
            return
        if triggered:
            self.done = True
        elif reached:
            if not self._push():
                if not self._advance():
                    self.done = True
        else:
            if not self._advance():
                self.done = True


if __name__ == "__main__":
    tree = ControllableBranchTree()
    tree.add_ranged_node("type", ["album", "song"], distance=30)
    NONCE = "23456432"
    tree.nonce_map[NONCE] = "rule_1"
    tree.ingest_probe([
        {"kind": "switch_observed",
         "location": {"file": "search.class.php", "line": 1104, "opcode": "SWITCH_STRING"},
         "distance_at_blocker": 2,
         "operands": {"lhs": {"value": NONCE, "type": "string"}},
         "cases": ["missing_artist", "title", "last_play"]},
    ])

    print("tagged parameter nodes:")
    for n in tree.params.values():
        print(" ", n, "candidates=", n.candidates)

    calls = []

    def fake_reach_trigger(decision):
        calls.append(dict(decision))
        typ = decision.get("type")
        rule1 = decision.get("rule_1")
        reached = (typ in ("album", "song"))
        triggered = reached and (rule1 == "last_play")
        return (reached, triggered, [])

    winner = tree.search(fake_reach_trigger)
    print(f"\nDFS steps={tree._steps}  winning decision={winner}")
    for c in calls[:8]:
        print("  ", c)

    assert winner == {"type": "album", "rule_1": "last_play"}, winner
    _r1_tries = [c.get("rule_1") for c in calls if "rule_1" in c]
    assert _r1_tries == ["missing_artist", "title", "last_play"], _r1_tries
    assert all(c.get("type") == "album" for c in calls if "rule_1" in c), \
        "when rule_1 is exhausted, type must stay fixed to the first candidate album (outer level only fixes, does not preempt exhaustion)"
    print("\n✓ self-test passed: descending order (rule_1 nearest the sink is exhausted innermost first) -> type=album/rule_1=last_play")

    calls_search = list(calls)
    calls.clear()
    cur = SearchCursor(tree)
    winner2 = None
    while True:
        dec = cur.next_decision()
        if dec is None:
            break
        reached, triggered, _ = fake_reach_trigger(dec)
        cur.report(reached, triggered)
        if triggered:
            winner2 = dec
            break
    print(f"SearchCursor winner={winner2}  steps={len(calls)}")
    assert winner2 == {"type": "album", "rule_1": "last_play"}, winner2
    assert calls == calls_search, \
        f"cursor must follow the same sequence as recursive DFS:\n cursor={calls}\n search={calls_search}"
    print("✓ SearchCursor behaves identically to recursive DFS")
