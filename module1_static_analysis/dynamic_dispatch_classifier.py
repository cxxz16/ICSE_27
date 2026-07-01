
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from module1_static_analysis.dynamic_dispatch_analyzer import CPG, LITERAL_TYPES


EFFECTIVELY_CONST_VARS = {
    'srcdir', 'webroot', 'rootdir', 'fileroot', 'oeroot',
    'OE_SITE_DIR', 'OE_SITE_WEBROOT',
}

def _symbolic_const(name):
    return f'<CONST:{name}>'


TIGHT = 10
BOUNDED = 100
RECURSION_LIMIT = 25


class Classifier:
    def __init__(self, cpg):
        self.cpg = cpg
        self.reaches = defaultdict(list)
        self.parent2child_by_num = cpg.children
        self._resolve_cache = {}

    def load_pdg_edges(self, cpg_edges_csv, quiet=False):
        if not quiet:
            print(f'[*] loading PDG REACHES edges from {cpg_edges_csv} ...', file=sys.stderr)
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
                self.reaches[e].append((s, var))
                n += 1
        if not quiet:
            print(f'[+] {n} REACHES edges loaded', file=sys.stderr)

    def _funcid_of(self, node_id):
        n = self.cpg.get(node_id)
        return n['funcid'] if n else None

    def _name_of_var(self, var_node_id):
        child = self.cpg.child(var_node_id, 0)
        if child is None:
            return None
        n = self.cpg.get(child)
        if n and n['type'] == 'string':
            return n['code']
        return None

    def _name_of_ast_name(self, name_node_id):
        child = self.cpg.child(name_node_id, 0)
        if child is None:
            return None
        n = self.cpg.get(child)
        if n and n['type'] == 'string':
            return n['code']
        return None

    def _find_assign_for_def(self, def_node_id):
        n = self.cpg.get(def_node_id)
        if not n:
            return None, 'unknown'
        t = n['type']
        if t in ('AST_ASSIGN', 'AST_ASSIGN_REF'):
            rhs = self.cpg.child(def_node_id, 1)
            return rhs, 'assign'
        if t == 'AST_ASSIGN_OP':
            return None, 'assign_op'
        if t == 'AST_FOREACH':
            return None, 'foreach'
        if t == 'AST_PARAM':
            return None, 'param'
        if t == 'AST_STATIC':
            rhs = self.cpg.child(def_node_id, 1)
            return rhs, 'static_init'
        if t == 'AST_GLOBAL':
            return None, 'global'
        return self.cpg.child(def_node_id, 1), 'other'

    def resolve(self, node_id, scope_func_id, depth=0, visited=None):
        if visited is None:
            visited = set()
        if node_id is None:
            return None
        if depth > RECURSION_LIMIT:
            return None
        if node_id in visited:
            return None
        visited = visited | {node_id}

        n = self.cpg.get(node_id)
        if not n:
            return None
        t = n['type']

        if t == 'string':
            return {n['code']}

        if t == 'integer':
            return {n['code'] or '0'}

        if t == 'AST_NAME':
            inner = self._name_of_ast_name(node_id)
            return {inner} if inner else None

        if t == 'AST_CONST':
            const_name = self._name_of_ast_name(self.cpg.child(node_id, 0))
            return {_symbolic_const(const_name or '?')}

        if t == 'AST_MAGIC_CONST':
            return {_symbolic_const(n.get('flags') or 'MAGIC')}

        if t == 'AST_BINARY_OP':
            flags = n.get('flags') or ''
            if 'CONCAT' in flags:
                left = self.cpg.child(node_id, 0)
                right = self.cpg.child(node_id, 1)
                l = self.resolve(left, scope_func_id, depth + 1, visited)
                r = self.resolve(right, scope_func_id, depth + 1, visited)
                if l is None or r is None:
                    return None
                out = set()
                for a in l:
                    for b in r:
                        out.add(a + b)
                        if len(out) > BOUNDED * 10:
                            return None
                return out
            return None

        if t == 'AST_ENCAPS_LIST':
            children = self.cpg.children.get(node_id, {})
            parts = []
            for cn in sorted(children.keys()):
                child_id = children[cn]
                child_t = self.cpg.type_of(child_id)
                if child_t == 'string':
                    parts.append({self.cpg.code_of(child_id) or ''})
                else:
                    sub = self.resolve(child_id, scope_func_id, depth + 1, visited)
                    if sub is None:
                        return None
                    parts.append(sub)
            out = ['']
            for p in parts:
                new_out = []
                for prefix in out:
                    for suf in p:
                        new_out.append(prefix + suf)
                        if len(new_out) > BOUNDED * 10:
                            return None
                out = new_out
            return set(out)

        if t == 'AST_VAR':
            var_name = self._name_of_var(node_id)
            if var_name in EFFECTIVELY_CONST_VARS:
                return {_symbolic_const('$' + var_name)}
            defs = self.reaches.get(node_id, [])
            if not defs:
                return None
            same_scope = []
            for def_id, var in defs:
                df = self._funcid_of(def_id)
                if df is None or df == scope_func_id:
                    same_scope.append(def_id)
            if not same_scope:
                return None
            result = set()
            for def_id in same_scope:
                rhs, kind = self._find_assign_for_def(def_id)
                if kind in ('param', 'foreach', 'assign_op', 'global', 'unknown'):
                    return None
                sub = self.resolve(rhs, scope_func_id, depth + 1, visited)
                if sub is None:
                    return None
                result.update(sub)
                if len(result) > BOUNDED * 10:
                    return None
            return result if result else None

        if t == 'AST_ARRAY':
            children = self.cpg.children.get(node_id, {})
            if len(children) != 2:
                return None
            elem0 = children.get(0)
            elem1 = children.get(1)
            if elem0 is None or elem1 is None:
                return None
            val0 = self.cpg.child(elem0, 0)
            val1 = self.cpg.child(elem1, 0)
            obj_repr = self._name_of_var(val0) if self.cpg.type_of(val0) == 'AST_VAR' else '?'
            method_names = self.resolve(val1, scope_func_id, depth + 1, visited)
            if method_names is None:
                return None
            return {f'<OBJ:${obj_repr}>::{m}' for m in method_names}

        if t == 'AST_DIM':
            return None

        if t == 'AST_PROP':
            return None

        if t == 'AST_STATIC_PROP':
            return None

        if t == 'AST_CALL':
            return None

        if t in ('AST_METHOD_CALL', 'AST_STATIC_CALL'):
            return None

        if t == 'AST_CONDITIONAL':
            then_branch = self.cpg.child(node_id, 1)
            else_branch = self.cpg.child(node_id, 2)
            t_set = self.resolve(then_branch, scope_func_id, depth + 1, visited)
            e_set = self.resolve(else_branch, scope_func_id, depth + 1, visited)
            if t_set is None or e_set is None:
                return None
            return t_set | e_set

        if t == 'AST_COALESCE':
            a = self.resolve(self.cpg.child(node_id, 0), scope_func_id, depth + 1, visited)
            b = self.resolve(self.cpg.child(node_id, 1), scope_func_id, depth + 1, visited)
            if a is None and b is None:
                return None
            return (a or set()) | (b or set())

        return None

    def classify_site(self, callable_subexpr_id):
        if not callable_subexpr_id:
            return ('DYNAMIC', None, 'no_callable_subexpr')
        func_id = self._funcid_of(callable_subexpr_id)
        if func_id is None:
            return ('DYNAMIC', None, 'no_func_scope')
        candidates = self.resolve(callable_subexpr_id, func_id)
        if candidates is None:
            return ('DYNAMIC', None, 'unresolvable')
        if not candidates:
            return ('DYNAMIC', None, 'empty')
        n = len(candidates)
        if n <= TIGHT:
            kind = 'STATIC_TIGHT'
        elif n <= BOUNDED:
            kind = 'STATIC_BOUNDED'
        else:
            kind = 'STATIC_LARGE'
        return (kind, candidates, f'{n}_candidates')


def load_phase1_report(path):
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--report', required=True,
                    help='Phase 1 dynamic_dispatch_report.csv')
    ap.add_argument('--nodes', required=True)
    ap.add_argument('--rels', required=True)
    ap.add_argument('--cpg-edges', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    print('[*] loading Phase 1 sites ...', file=sys.stderr)
    sites = load_phase1_report(args.report)
    print(f'[+] {len(sites)} sites', file=sys.stderr)

    cpg = CPG(args.nodes, args.rels, quiet=args.quiet)
    cls = Classifier(cpg)
    cls.load_pdg_edges(args.cpg_edges, quiet=args.quiet)

    print('[*] classifying ...', file=sys.stderr)
    rows = []
    by_kind = defaultdict(int)
    by_kind_cat = defaultdict(lambda: defaultdict(int))
    for i, site in enumerate(sites):
        if not args.quiet and i % 500 == 0:
            print(f'  {i}/{len(sites)}', file=sys.stderr)
        try:
            cid = int(site['callable_subexpr_id']) if site['callable_subexpr_id'] else None
        except (TypeError, ValueError):
            cid = None
        kind, candidates, reason = cls.classify_site(cid)
        by_kind[kind] += 1
        by_kind_cat[site['category']][kind] += 1
        cand_count = len(candidates) if candidates else 0
        sample = '|'.join(sorted(candidates)[:5]) if candidates else ''
        rows.append({
            'site_id': site['site_id'],
            'category': site['category'],
            'file': site['file'],
            'line': site['line'],
            'kind': kind,
            'candidate_count': cand_count,
            'candidate_sample': sample[:200],
            'reason': reason,
        })

    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['site_id', 'category', 'file', 'line',
                                          'kind', 'candidate_count',
                                          'candidate_sample', 'reason'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f'[+] wrote {args.out}', file=sys.stderr)

    print()
    print('=' * 72)
    print('Classification — Overall')
    print('=' * 72)
    total = len(rows)
    for k in ('STATIC_TIGHT', 'STATIC_BOUNDED', 'STATIC_LARGE', 'DYNAMIC'):
        c = by_kind[k]
        print(f'  {k:18s}  {c:6d}  ({100*c/total:5.1f}%)')
    print()
    print('Per-category breakdown:')
    print(f'  {"category":30s} {"TIGHT":>7s} {"BOUNDED":>9s} {"LARGE":>7s} {"DYNAMIC":>9s} {"total":>7s}')
    for cat in sorted(by_kind_cat.keys()):
        d = by_kind_cat[cat]
        total_cat = sum(d.values())
        print(f'  {cat:30s} {d["STATIC_TIGHT"]:7d} {d["STATIC_BOUNDED"]:9d} '
              f'{d["STATIC_LARGE"]:7d} {d["DYNAMIC"]:9d} {total_cat:7d}')
    print('=' * 72)


if __name__ == '__main__':
    main()
