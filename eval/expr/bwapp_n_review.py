
import csv
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from module1_static_analysis.dynamic_dispatch_analyzer import CPG


def find_stmt_ancestor(cpg, node_id, max_hops=8):
    STMT_TYPES = {'AST_ASSIGN', 'AST_ASSIGN_OP', 'AST_ASSIGN_REF',
                  'AST_RETURN', 'AST_ECHO', 'AST_THROW', 'AST_PRINT',
                  'AST_IF_ELEM', 'AST_WHILE', 'AST_DO_WHILE', 'AST_FOR',
                  'AST_FOREACH', 'AST_SWITCH', 'AST_BREAK', 'AST_CONTINUE',
                  'AST_CALL', 'AST_METHOD_CALL', 'AST_STATIC_CALL', 'AST_NEW',
                  'AST_INCLUDE_OR_EVAL', 'AST_EXIT', 'AST_UNSET', 'AST_GLOBAL',
                  'AST_USE_TRAIT', 'AST_TRY', 'AST_CATCH'}
    cur = node_id
    for _ in range(max_hops):
        n = cpg.get(cur)
        if n and n['type'] in STMT_TYPES:
            return cur
        parent = cpg.parent.get(cur)
        if parent is None:
            return cur
        cur = parent
    return cur


def collect_subtree_codes(cpg, root):
    result = []
    stack = [root]
    visited = set()
    while stack:
        nid = stack.pop()
        if nid in visited:
            continue
        visited.add(nid)
        n = cpg.get(nid)
        if not n:
            continue
        if n['code']:
            result.append((n['lineno'], n['type'], n['code']))
        for c in cpg.children.get(nid, {}).values():
            if c not in visited:
                stack.append(c)
    return sorted(result, key=lambda x: (x[0], x[1]))


def reconstruct_lines(cpg, target_line, callable_id, file_path):
    func_id = (cpg.get(callable_id) or {}).get('funcid')
    out = []
    for nid, n in cpg.nodes.items():
        if n.get('funcid') != func_id:
            continue
        ln = n.get('lineno', 0)
        if not (target_line - 8 <= ln <= target_line + 2):
            continue
        if n['code']:
            out.append((ln, n['type'], n['code'], nid))
    return sorted(out, key=lambda x: (x[0], x[3]))


def main():
    cpg = CPG('/home/user/research/Predator/working/tchecker-results/bWAPP/nodes.csv',
              '/home/user/research/Predator/working/tchecker-results/bWAPP/rels.csv',
              quiet=True)

    callable_map = {}
    with open('/home/user/research/Predator/VIPER/expr/bwapp_dynamic_dispatch.csv') as f:
        for row in csv.DictReader(f):
            callable_map[row['site_id']] = (
                int(row['callable_subexpr_id']) if row['callable_subexpr_id'] else None,
                row['details'],
            )

    n_sites = []
    with open('/home/user/research/Predator/VIPER/expr/bwapp_dispatch_taint_filtered.csv') as f:
        for row in csv.DictReader(f):
            if row['taint_reachable'] == 'N':
                n_sites.append(row)

    print(f'# bWAPP — {len(n_sites)} N (taint-unreachable) sites · code review\n')
    for i, site in enumerate(n_sites, 1):
        sid = site['site_id']
        cid, details = callable_map.get(sid, (None, ''))
        site_node = cpg.get(int(sid))
        funcid = site_node['funcid'] if site_node else None
        print(f'## #{i} site_id={sid} · {site["category"]} · {site["file"]}:{site["line"]}')
        print(f'   callable_subexpr_id={cid}  details={details}  funcid={funcid}\n')
        if cid:
            stmt_root = find_stmt_ancestor(cpg, int(sid))
            subtree = collect_subtree_codes(cpg, stmt_root)
            print('   --- AST subtree of enclosing statement (key string nodes) ---')
            for ln, t, code in subtree:
                if t == 'string' or 'string' in t.lower():
                    code_short = code[:120].replace('\n', '\\n')
                    print(f'     L{ln} {t}  {code_short}')
        nearby = reconstruct_lines(cpg, int(site['line']), cid or int(sid), site['file'])
        print('   --- nearby nodes in same function (line range ±) ---')
        last_line = -1
        for ln, t, code, nid in nearby:
            if t in ('AST_TOPLEVEL',):
                continue
            code_short = code[:80].replace('\n', '\\n')
            marker = '  ' if ln != int(site['line']) else '*>'
            print(f'   {marker} L{ln:5d} [{t:25s}] {code_short}')
        print()


if __name__ == '__main__':
    main()
