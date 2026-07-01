
import csv
import os
import random
import sys
from collections import defaultdict

SRC_ROOT = '/home/user/research/Predator/working/openemr-source'
PH3_CSV = '/home/user/research/Predator/VIPER/expr/openemr_dispatch_taint_filtered.csv'
PH1_CSV = '/home/user/research/Predator/VIPER/expr/openemr_dynamic_dispatch.csv'
SEED = 42
PER_GROUP = 3
CONTEXT = 5


def load_phase3():
    rows = []
    with open(PH3_CSV) as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def load_phase1_details():
    m = {}
    with open(PH1_CSV) as f:
        for r in csv.DictReader(f):
            m[r['site_id']] = r
    return m


def load_php_snippet(rel_path, target_line):
    full = os.path.join(SRC_ROOT, rel_path)
    if not os.path.exists(full):
        return None, f'[file not found: {full}]'
    try:
        with open(full, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        return None, f'[read err: {e}]'
    if target_line < 1 or target_line > len(lines):
        return None, f'[line {target_line} out of range; file has {len(lines)} lines]'
    start = max(1, target_line - CONTEXT)
    end = min(len(lines), target_line + CONTEXT)
    snippet = []
    for ln in range(start, end + 1):
        snippet.append((ln, lines[ln - 1].rstrip('\n'), ln == target_line))
    return snippet, None


def render(rows, ph1, header):
    print(f'## {header}\n')
    if not rows:
        print('(no sites in this group)\n')
        return
    for i, site in enumerate(rows, 1):
        sid = site['site_id']
        ph1_row = ph1.get(sid, {})
        print(f'### #{i}/{len(rows)} site_id={sid} · {site["category"]}')
        print(f'   file: `{site["file"]}` line: {site["line"]}')
        print(f'   kind={site["kind"]}, candidate_count={site["candidate_count"]}, '
              f'taint_reachable={site["taint_reachable"]}, '
              f'depth={site.get("taint_path_depth", "")}, '
              f'source_kind={site.get("source_kind", "")}')
        print(f'   phase1_details: {ph1_row.get("details", "")}')
        line = int(site['line']) if site['line'] and site['line'].isdigit() else 0
        snippet, err = load_php_snippet(site['file'], line)
        if snippet is None:
            print(f'\n```\n{err}\n```\n')
        else:
            print('\n```php')
            for ln, text, is_target in snippet:
                marker = '>' if is_target else ' '
                print(f'{marker} {ln:5d}  {text}')
            print('```\n')
        print()


def main():
    rng = random.Random(SEED)
    ph3 = load_phase3()
    ph1 = load_phase1_details()

    groups = defaultdict(list)
    for r in ph3:
        groups[(r['taint_reachable'], r['category'])].append(r)

    print('# OpenEMR Phase 3 — Review Samples\n')
    print(f'Source: {PH3_CSV}')
    print(f'PHP root: {SRC_ROOT}')
    print(f'Sampling: {PER_GROUP} per (taint_reachable, category), seed={SEED}\n')

    print('## Group sizes\n')
    print('| taint_reachable | category | total | sampled |')
    print('|---|---|---|---|')
    for (tr, cat) in sorted(groups.keys()):
        print(f'| {tr} | {cat} | {len(groups[(tr, cat)])} | {min(PER_GROUP, len(groups[(tr, cat)]))} |')
    print()
    print('---\n')

    for tr_label, tr_value in [('TAINT-REACHABLE (Y) — kept for fuzz', 'Y'),
                                ('FILTERED OUT (N) — taint not reachable', 'N')]:
        print(f'# {tr_label}\n')
        for (tr, cat) in sorted(groups.keys()):
            if tr != tr_value:
                continue
            shuffled = list(groups[(tr, cat)])
            rng.shuffle(shuffled)
            picked = shuffled[:PER_GROUP]
            render(picked, ph1, f'Category: {cat}  ({len(groups[(tr, cat)])} total)')


if __name__ == '__main__':
    main()
