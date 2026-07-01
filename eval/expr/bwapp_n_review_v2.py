
import csv
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from module1_static_analysis.dynamic_dispatch_analyzer import CPG


def reconstruct_line(cpg, file_id, line_no):
    parts = []
    for nid, n in cpg.nodes.items():
        if n.get('lineno') != line_no:
            continue
        if n['code']:
            parts.append((nid, n['type'], n['code']))
    return sorted(parts, key=lambda x: x[0])


def main():
    cpg = CPG('/home/user/research/Predator/working/tchecker-results/bWAPP/nodes.csv',
              '/home/user/research/Predator/working/tchecker-results/bWAPP/rels.csv',
              quiet=True)

    n_sites = []
    with open('/home/user/research/Predator/VIPER/expr/bwapp_dispatch_taint_filtered.csv') as f:
        for row in csv.DictReader(f):
            if row['taint_reachable'] == 'N':
                n_sites.append(row)

    callable_map = {}
    with open('/home/user/research/Predator/VIPER/expr/bwapp_dynamic_dispatch.csv') as f:
        for row in csv.DictReader(f):
            callable_map[row['site_id']] = row

    print('# bWAPP 16 N-Site Code Review\n')
    print('All 16 are in the **nusoap SOAP library**. ')
    print('My Phase 3 marked them N because the callable comes from SOAP request body / parsed XML,')
    print('not from `$_GET/$_POST/...` superglobals. But these *are* real dynamic dispatch — just from')
    print('a source the current taint definition does not track.\n')
    print('Below: for each site, dump nodes on lines [target-6, target+1] with type+code,')
    print('grouped by line, sorted by node id.\n')
    print('---\n')

    cur_file = None
    by_file = {}
    for s in n_sites:
        by_file.setdefault(s['file'], []).append(s)

    for fpath, sites in by_file.items():
        print(f'## File: `{fpath}`  ({len(sites)} N sites)\n')
        for site in sites:
            sid = int(site['site_id'])
            line = int(site['line'])
            cat = site['category']
            ph1 = callable_map.get(str(sid), {})
            cid = ph1.get('callable_subexpr_id', '?')
            details = ph1.get('details', '')

            print(f'### site_id={sid} · {cat} · line {line}')
            print(f'   callable_subexpr_id={cid}, {details}\n')
            print('```php')
            site_node = cpg.get(sid)
            funcid = site_node['funcid'] if site_node else None
            by_line = {}
            for nid, n in cpg.nodes.items():
                if n.get('funcid') != funcid:
                    continue
                ln = n.get('lineno', 0)
                if line - 6 <= ln <= line + 1:
                    if n['code']:
                        by_line.setdefault(ln, []).append((nid, n['type'], n['code']))
            for ln in sorted(by_line.keys()):
                nodes = sorted(by_line[ln], key=lambda x: x[0])
                marker = '*' if ln == line else ' '
                snippet_parts = []
                for nid, t, c in nodes:
                    cc = c[:100].replace('\n', '\\n')
                    if t == 'string':
                        snippet_parts.append(f'"{cc}"' if not cc.startswith('"') else cc)
                    elif t == 'integer':
                        snippet_parts.append(cc)
                    elif t == 'AST_NAME':
                        pass
                    else:
                        snippet_parts.append(f'<{t}:{cc}>')
                line_str = ' / '.join(snippet_parts)[:200]
                print(f'{marker} L{ln:5d}  {line_str}')
            print('```\n')

    print()


if __name__ == '__main__':
    main()
