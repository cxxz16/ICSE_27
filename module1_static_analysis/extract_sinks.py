
import re
import sys
import argparse
sys.path.insert(0, '/home/user/research/Predator/VIPER')
from module1_static_analysis.dynamic_dispatch_analyzer import CPG


def parse_summary(stdout_log):
    with open(stdout_log, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()
    m = re.search(r'^Summary:\s*\{(.+)\}\s*$', text, re.MULTILINE)
    if not m:
        sys.exit('[!] no Summary line found')
    body = m.group(1)
    sinks = []
    for entry in re.finditer(r'(\d+)=\[([^\]]*)\]', body):
        sid = int(entry.group(1))
        path_str = entry.group(2).strip()
        path = [int(x.strip()) for x in path_str.split(',')] if path_str else []
        sinks.append((sid, path))
    return sinks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--stdout-log', default='/home/user/research/Predator/logs/openemr-tck4-stdout.log')
    ap.add_argument('--nodes', default='/home/user/research/Predator/working/openemr-source/nodes.csv')
    ap.add_argument('--rels', default='/home/user/research/Predator/working/openemr-source/rels.csv')
    ap.add_argument('--out', default='/home/user/research/Predator/VIPER/expr/openemr_sinks.csv')
    args = ap.parse_args()

    print('[*] parsing Summary...', file=sys.stderr)
    sinks = parse_summary(args.stdout_log)
    print(f'[+] {len(sinks)} sinks in Summary', file=sys.stderr)

    print('[*] loading CPG...', file=sys.stderr)
    cpg = CPG(args.nodes, args.rels)

    rows = []
    for (sid, path) in sinks:
        n = cpg.get(sid)
        if not n:
            rows.append((sid, '', 0, '', len(path), 'NODE_NOT_FOUND'))
            continue
        f = cpg.file_of(sid)
        ln = n.get('lineno', 0)
        t = n.get('type', '')
        rows.append((sid, f, ln, t, len(path), ','.join(str(x) for x in path)))

    with open(args.out, 'w', encoding='utf-8') as f:
        f.write('sink_id,file,line,ast_type,callstack_depth,callstack\n')
        for r in rows:
            f.write(f'{r[0]},{r[1]},{r[2]},{r[3]},{r[4]},"{r[5]}"\n')
    print(f'[+] wrote {args.out}', file=sys.stderr)

    total = len(rows)
    no_file = sum(1 for r in rows if not r[1])
    with_path = sum(1 for r in rows if r[4] > 0)
    by_file = {}
    for r in rows:
        if r[1]:
            by_file[r[1]] = by_file.get(r[1], 0) + 1
    print(f'\nTotal sinks:        {total}')
    print(f'Resolved file:line: {total - no_file}')
    print(f'No file (orphan):   {no_file}')
    print(f'With callstack:     {with_path}')
    print(f'Distinct files:     {len(by_file)}')
    print(f'\nTop 10 files:')
    for f, c in sorted(by_file.items(), key=lambda x: -x[1])[:10]:
        print(f'  {c:5d}  {f}')


if __name__ == '__main__':
    main()
