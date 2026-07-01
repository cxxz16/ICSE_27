
import argparse
import csv
import os
import sys
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from module1_static_analysis.dynamic_dispatch_analyzer import CPG, CALLBACK_BUILTINS, USER_FUNC_CALLS
from module1_static_analysis.dynamic_dispatch_classifier import Classifier as Phase2Classifier
from module1_static_analysis.dynamic_dispatch_taint_filter import TaintFilter, SUPERGLOBALS

DISPATCH_CALL_CATEGORIES = {
    'DYN_CALL_FN', 'DYN_CUF', 'DYN_CALLBACK_BUILTIN',
    'DYN_CALL_METHOD', 'DYN_CALL_STATIC_METHOD',
    'DYN_CALL_STATIC_CLASS', 'DYN_CALL_STATIC_BOTH',
    'DYN_NEW_CLASS', 'DYN_REFLECTION_INVOKE',
}

CUF_CALLABLES = {'call_user_func', 'call_user_func_array',
                 'forward_static_call', 'forward_static_call_array'}


def get_ast_call_node_for_site(cpg, site_id, category, callable_id):
    return site_id


def get_arg_list_node(cpg, dispatch_node_id, category):
    if category in ('DYN_CALL_FN', 'DYN_CUF', 'DYN_CALLBACK_BUILTIN'):
        return cpg.child(dispatch_node_id, 1)
    if category in ('DYN_CALL_METHOD',):
        return cpg.child(dispatch_node_id, 2)
    if category in ('DYN_CALL_STATIC_METHOD', 'DYN_CALL_STATIC_CLASS', 'DYN_CALL_STATIC_BOTH'):
        return cpg.child(dispatch_node_id, 2)
    if category == 'DYN_NEW_CLASS':
        return cpg.child(dispatch_node_id, 1)
    if category == 'DYN_REFLECTION_INVOKE':
        return cpg.child(dispatch_node_id, 2)
    return None


def _get_call_function_name(cpg, ast_call_node):
    callee = cpg.child(ast_call_node, 0)
    if callee is None or cpg.type_of(callee) != 'AST_NAME':
        return None
    name_node = cpg.child(callee, 0)
    if name_node is None:
        return None
    return cpg.code_of(name_node)


def get_args(cpg, dispatch_node_id, category, callee_name=None):
    arg_list = get_arg_list_node(cpg, dispatch_node_id, category)
    if arg_list is None:
        return []
    children = cpg.children.get(arg_list, {})
    sorted_keys = sorted(children.keys())
    arg_node_ids = [children[k] for k in sorted_keys]

    if category == 'DYN_CUF':
        return arg_node_ids[1:]

    if category == 'DYN_CALLBACK_BUILTIN':
        fn_name = _get_call_function_name(cpg, dispatch_node_id)
        if fn_name and fn_name.lower() in CALLBACK_BUILTINS:
            callable_positions = set(CALLBACK_BUILTINS[fn_name.lower()])
            return [aid for pos, aid in enumerate(arg_node_ids)
                    if pos not in callable_positions]
        return arg_node_ids

    return arg_node_ids


def is_concrete_literal(s):
    if s is None:
        return False
    if isinstance(s, str) and s.startswith('<CONST:'):
        return False
    if isinstance(s, str) and s.startswith('<OBJ:'):
        return False
    return True


def classify_callee_dynamism(phase2: Phase2Classifier, callable_id, cpg):
    if callable_id is None:
        return 'DYNAMIC_UNBOUNDED', set()
    n = cpg.get(callable_id)
    if not n:
        return 'DYNAMIC_UNBOUNDED', set()
    func_id = n.get('funcid')
    candidates = phase2.resolve(callable_id, func_id)
    if candidates is None:
        return 'DYNAMIC_UNBOUNDED', set()
    if not candidates:
        return 'DYNAMIC_UNBOUNDED', set()

    n_total = len(candidates)
    n_concrete = sum(1 for c in candidates if is_concrete_literal(c))

    if n_total == 1 and n_concrete == 1:
        return 'STATIC_SINGLE', candidates
    return 'DYNAMIC_BOUNDED', candidates


def analyze_site(site, ph1_row, cpg, phase2, taint_filter):
    sid = int(site['site_id'])
    category = site['category']
    try:
        callable_id = int(ph1_row['callable_subexpr_id']) if ph1_row.get('callable_subexpr_id') else None
    except ValueError:
        callable_id = None

    callee_dynamism, callee_candidates = classify_callee_dynamism(
        phase2, callable_id, cpg)
    sample = '|'.join(sorted(str(c) for c in callee_candidates)[:5])
    candidate_count = len(callee_candidates) if callee_candidates else 0

    args = get_args(cpg, sid, category)
    arg_count = len(args)

    tainted_indices = []
    all_sources = set()
    for i, arg_id in enumerate(args):
        reachable, depth, sources = taint_filter.backward_reach(arg_id)
        if reachable:
            tainted_indices.append(i)
            all_sources |= sources

    if callee_dynamism == 'STATIC_SINGLE':
        fuzz_priority = 'SKIP'
    elif callee_dynamism == 'DYNAMIC_BOUNDED':
        fuzz_priority = 'HIGH_BOUNDED' if tainted_indices else 'LOW_BOUNDED'
    else:
        fuzz_priority = 'HIGH_UNBOUNDED' if tainted_indices else 'LOW_UNBOUNDED'

    return {
        'site_id': sid, 'category': category,
        'file': site['file'], 'line': site['line'],
        'callee_dynamism': callee_dynamism,
        'callee_candidate_count': candidate_count,
        'callee_candidates_sample': sample[:200],
        'arg_count': arg_count,
        'tainted_arg_count': len(tainted_indices),
        'tainted_arg_indices': ','.join(str(i) for i in tainted_indices),
        'taint_sources': ','.join(sorted(all_sources)),
        'fuzz_priority': fuzz_priority,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--phase1', required=True,
                    help='Phase 1 dynamic_dispatch_report.csv')
    ap.add_argument('--nodes', required=True)
    ap.add_argument('--rels', required=True)
    ap.add_argument('--cpg-edges', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    print('[*] loading Phase 1 sites ...', file=sys.stderr)
    sites = []
    with open(args.phase1, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['category'] in DISPATCH_CALL_CATEGORIES:
                sites.append(row)
    print(f'[+] {len(sites)} dispatch-call sites (others excluded)', file=sys.stderr)

    cpg = CPG(args.nodes, args.rels, quiet=args.quiet)
    phase2 = Phase2Classifier(cpg)
    phase2.load_pdg_edges(args.cpg_edges, quiet=args.quiet)
    tf = TaintFilter(cpg)
    tf.find_superglobals(quiet=args.quiet)
    tf.load_pdg(args.cpg_edges, quiet=args.quiet)

    print('[*] analyzing ...', file=sys.stderr)
    rows = []
    stats_priority = defaultdict(int)
    stats_by_cat = defaultdict(lambda: defaultdict(int))
    for i, site in enumerate(sites):
        if not args.quiet and i % 200 == 0:
            print(f'  {i}/{len(sites)}', file=sys.stderr)
        result = analyze_site(site, site, cpg, phase2, tf)
        stats_priority[result['fuzz_priority']] += 1
        stats_by_cat[site['category']][result['fuzz_priority']] += 1
        rows.append(result)

    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['site_id', 'category', 'file', 'line',
                                          'callee_dynamism',
                                          'callee_candidate_count',
                                          'callee_candidates_sample',
                                          'arg_count', 'tainted_arg_count',
                                          'tainted_arg_indices',
                                          'taint_sources', 'fuzz_priority'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f'[+] wrote {args.out}', file=sys.stderr)

    print()
    print('=' * 88)
    print('Phase A + B + C · Dispatch-Call Sites with 3-tier callee + arg taint')
    print('=' * 88)
    total = len(rows)
    KEYS = ('HIGH_BOUNDED', 'HIGH_UNBOUNDED', 'LOW_BOUNDED', 'LOW_UNBOUNDED', 'SKIP')
    for k in KEYS:
        c = stats_priority[k]
        if total:
            print(f'  {k:18s}  {c:6d}  ({100*c/total:.1f}%)')
    print()
    print('Per-category:')
    hdr = ['category'] + list(KEYS) + ['total']
    print(('  ' + '{:30s}' + ' {:>14s}' * (len(hdr)-2) + ' {:>6s}').format(*hdr))
    for cat in sorted(stats_by_cat.keys()):
        d = stats_by_cat[cat]
        t = sum(d.values())
        cells = [d[k] for k in KEYS] + [t]
        print(('  ' + '{:30s}' + ' {:>14d}' * (len(KEYS)) + ' {:>6d}').format(cat, *cells))
    print('=' * 88)


if __name__ == '__main__':
    main()
