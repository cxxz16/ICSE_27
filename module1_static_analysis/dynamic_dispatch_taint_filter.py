
import argparse
import csv
import os
import sys
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from module1_static_analysis.dynamic_dispatch_analyzer import CPG


SUPERGLOBALS = {'_GET', '_POST', '_REQUEST', '_COOKIE',
                '_SESSION', '_SERVER', '_FILES', '_ENV'}

MAX_DEPTH = 30


class TaintFilter:
    def __init__(self, cpg):
        self.cpg = cpg
        self.reaches_in = defaultdict(list)
        self._subtree_globals_cache = {}
        self.superglobal_nodes = set()

    def load_pdg(self, cpg_edges_csv, quiet=False):
        if not quiet:
            print(f'[*] loading PDG REACHES edges ...', file=sys.stderr)
        n = 0
        with open(cpg_edges_csv, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                if row.get('type') != 'REACHES':
                    continue
                try:
                    s = int(row['start']); e = int(row['end'])
                except (ValueError, KeyError):
                    continue
                var = (row.get('var') or '').strip()
                self.reaches_in[e].append((s, var))
                n += 1
        if not quiet:
            print(f'[+] {n} REACHES edges loaded', file=sys.stderr)

    def find_superglobals(self, quiet=False):
        if not quiet:
            print('[*] indexing superglobal source nodes ...', file=sys.stderr)
        for nid, n in self.cpg.nodes.items():
            if n['type'] == 'string' and n['code'] in SUPERGLOBALS:
                self.superglobal_nodes.add(nid)
        if not quiet:
            print(f'[+] {len(self.superglobal_nodes)} superglobal source nodes',
                  file=sys.stderr)

    def subtree_has_superglobal(self, root_id):
        if root_id in self._subtree_globals_cache:
            return self._subtree_globals_cache[root_id]

        found = set()
        stack = [root_id]
        visited = set()
        depth_limit = 100
        steps = 0
        while stack and steps < 10000:
            steps += 1
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            n = self.cpg.get(nid)
            if not n:
                continue
            if nid in self.superglobal_nodes:
                found.add(n['code'])
            children = self.cpg.children.get(nid, {})
            for cid in children.values():
                if cid not in visited:
                    stack.append(cid)
        self._subtree_globals_cache[root_id] = found
        return found

    def backward_reach(self, start_node, max_depth=MAX_DEPTH):
        if not start_node:
            return False, -1, set()

        direct = self.subtree_has_superglobal(start_node)
        if direct:
            return True, 0, direct

        seeds = [start_node]
        cur = start_node
        for _ in range(5):
            parent = self.cpg.parent.get(cur)
            if parent is None:
                break
            seeds.append(parent)
            cur = parent

        visited = set(seeds)
        queue = deque([(s, 0) for s in seeds])
        all_sources = set()
        min_depth = None
        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for (def_node, var) in self.reaches_in.get(node, []):
                if def_node in visited:
                    continue
                visited.add(def_node)
                sg = self.subtree_has_superglobal(def_node)
                if sg:
                    all_sources |= sg
                    if min_depth is None or depth + 1 < min_depth:
                        min_depth = depth + 1
                queue.append((def_node, depth + 1))
        if all_sources:
            return True, min_depth, all_sources
        return False, -1, set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--classified', required=True,
                    help='Phase 2 dispatch_classified.csv')
    ap.add_argument('--nodes', required=True)
    ap.add_argument('--rels', required=True)
    ap.add_argument('--cpg-edges', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--phase1', required=True,
                    help='Phase 1 report (need callable_subexpr_id)')
    ap.add_argument('--include-static', action='store_true',
                    help='also include STATIC_* sites (default: only DYNAMIC)')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    print('[*] loading Phase 1 report ...', file=sys.stderr)
    callable_id_map = {}
    with open(args.phase1, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                cid = int(row['callable_subexpr_id']) if row['callable_subexpr_id'] else None
                callable_id_map[row['site_id']] = cid
            except ValueError:
                callable_id_map[row['site_id']] = None

    print('[*] loading Phase 2 classification ...', file=sys.stderr)
    classified = []
    with open(args.classified, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            classified.append(row)
    print(f'[+] {len(classified)} sites total', file=sys.stderr)

    cpg = CPG(args.nodes, args.rels, quiet=args.quiet)
    tf = TaintFilter(cpg)
    tf.find_superglobals(quiet=args.quiet)
    tf.load_pdg(args.cpg_edges, quiet=args.quiet)

    print('[*] running taint reachability ...', file=sys.stderr)
    out_rows = []
    stats_by_cat = defaultdict(lambda: defaultdict(int))
    overall = defaultdict(int)
    for i, site in enumerate(classified):
        if not args.quiet and i % 500 == 0:
            print(f'  {i}/{len(classified)}', file=sys.stderr)
        if not args.include_static and site['kind'] != 'DYNAMIC':
            stats_by_cat[site['category']]['skipped_static'] += 1
            overall['skipped_static'] += 1
            continue
        cid = callable_id_map.get(site['site_id'])
        if cid is None:
            tag = 'NO_CALLABLE'
            depth = -1
            sources = set()
        else:
            reachable, depth, sources = tf.backward_reach(cid)
            tag = 'Y' if reachable else 'N'
        stats_by_cat[site['category']][tag] += 1
        overall[tag] += 1
        out_rows.append({
            'site_id': site['site_id'],
            'category': site['category'],
            'file': site['file'],
            'line': site['line'],
            'kind': site['kind'],
            'candidate_count': site['candidate_count'],
            'taint_reachable': tag,
            'taint_path_depth': depth if depth >= 0 else '',
            'source_kind': ','.join(sorted(sources)) if sources else '',
        })

    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['site_id', 'category', 'file', 'line',
                                          'kind', 'candidate_count',
                                          'taint_reachable', 'taint_path_depth',
                                          'source_kind'])
        w.writeheader()
        for r in out_rows:
            w.writerow(r)
    print(f'[+] wrote {args.out}', file=sys.stderr)

    print()
    print('=' * 72)
    print('Phase 3 · Taint Reachability — Overall')
    print('=' * 72)
    total_eval = sum(overall[k] for k in ('Y', 'N', 'NO_CALLABLE'))
    print(f'  TAINT_REACHABLE (Y):  {overall["Y"]:6d}  '
          f'({100*overall["Y"]/total_eval:.1f}% of evaluated)' if total_eval else '')
    print(f'  NOT_REACHABLE (N):    {overall["N"]:6d}')
    print(f'  NO_CALLABLE_NODE:     {overall["NO_CALLABLE"]:6d}')
    print(f'  Skipped (STATIC):     {overall["skipped_static"]:6d}')
    print()
    print('Per-category:')
    print(f'  {"category":30s} {"Y":>6s} {"N":>6s} {"NoCal":>6s} {"static-skip":>12s}')
    for cat in sorted(stats_by_cat.keys()):
        d = stats_by_cat[cat]
        print(f'  {cat:30s} {d["Y"]:6d} {d["N"]:6d} {d["NO_CALLABLE"]:6d} {d["skipped_static"]:12d}')
    print('=' * 72)


if __name__ == '__main__':
    main()
