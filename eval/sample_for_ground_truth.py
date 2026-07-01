
import argparse
import csv
import os
import random
import sys
from collections import defaultdict


def load_report(path):
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def stratified_sample(rows, per_cat, prefer_app, seed):
    rng = random.Random(seed)
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r['category']].append(r)
    samples = []
    for cat in sorted(by_cat.keys()):
        cat_rows = by_cat[cat]
        if prefer_app:
            app = [r for r in cat_rows if '/vendor/' not in r['file']]
            ven = [r for r in cat_rows if '/vendor/' in r['file']]
            rng.shuffle(app); rng.shuffle(ven)
            picked = app[:per_cat]
            if len(picked) < per_cat:
                picked.extend(ven[:per_cat - len(picked)])
        else:
            shuffled = list(cat_rows)
            rng.shuffle(shuffled)
            picked = shuffled[:per_cat]
        samples.extend(picked)
    return samples


def load_php_snippet(src_root, rel_path, target_line, context):
    full = os.path.join(src_root, rel_path)
    if not os.path.exists(full):
        return None, f'(source not found at {full})'
    try:
        with open(full, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        return None, f'(read error: {e})'
    if target_line < 1 or target_line > len(lines):
        return None, f'(line {target_line} out of range; file has {len(lines)} lines)'
    start = max(1, target_line - context)
    end = min(len(lines), target_line + context)
    snippet = []
    for ln in range(start, end + 1):
        snippet.append((ln, lines[ln - 1].rstrip('\n'), ln == target_line))
    return snippet, None


def render_snippet(snippet, err):
    if snippet is None:
        return f'```\n{err}\n```\n'
    out = ['```php']
    for (ln, text, is_target) in snippet:
        marker = '> ' if is_target else '  '
        out.append(f'{marker}{ln:6d}  {text}')
    out.append('```')
    return '\n'.join(out)


def render_sample(idx, total, sample, snippet, err):
    return f"""## Sample {idx}/{total} · `{sample['category']}`

- **site_id**: {sample['site_id']}
- **file**: `{sample['file']}`
- **line**: {sample['line']}
- **ast_type**: {sample['ast_type']}
- **callable_subexpr_id**: {sample['callable_subexpr_id']}
- **details**: {sample['details']}

{render_snippet(snippet, err)}

**Review** (replace `?` with Y/N/?):
- real_dynamic:    `?`   <!-- is my "dynamic" label correct? N = I misjudged (actually static) -->
- taint_reachable: `?`   <!-- can the callable expression receive external input (GET/POST/COOKIE/SESSION/DB read)? -->
- vuln_related:    `?`   <!-- does it match an exploitable pattern (command/SQL/RCE/LFI/...)? -->
- notes:

---
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--report', required=True, help='dynamic_dispatch_report.csv')
    ap.add_argument('--src-root', required=True, help='PHP source root directory')
    ap.add_argument('--out', required=True, help='output markdown file')
    ap.add_argument('--per-cat', type=int, default=5, help='samples per category (default 5)')
    ap.add_argument('--context', type=int, default=5, help='lines of PHP context (default 5)')
    ap.add_argument('--seed', type=int, default=42, help='RNG seed')
    ap.add_argument('--prefer-app', action='store_true', help='prefer app over vendor in each stratum')
    args = ap.parse_args()

    rows = load_report(args.report)
    print(f'[*] loaded {len(rows)} sites from {args.report}', file=sys.stderr)

    samples = stratified_sample(rows, args.per_cat, args.prefer_app, args.seed)
    print(f'[*] sampled {len(samples)} sites (target {args.per_cat}/category)', file=sys.stderr)

    by_cat_count = defaultdict(int)
    for s in samples: by_cat_count[s['category']] += 1
    header = ['# Dynamic Dispatch Ground-Truth Samples', '',
              f'- source: {args.report}',
              f'- src_root: {args.src_root}',
              f'- per-category target: {args.per_cat}',
              f'- prefer_app: {args.prefer_app}',
              f'- seed: {args.seed}',
              f'- total samples: {len(samples)}',
              '',
              '## Sampling distribution', '']
    for cat in sorted(by_cat_count.keys()):
        header.append(f'- {cat}: {by_cat_count[cat]}')
    header.extend(['', '## Labeling guide', '',
                   '- **real_dynamic**: my classification is correct that this is genuinely dynamic. `N` if it is *effectively* static (e.g., `__DIR__ . "/foo.php"` resolves to a fixed path).',
                   '- **taint_reachable**: an external input source (GET/POST/COOKIE/SESSION/file/DB) can flow into the callable subexpression. `?` if cannot quickly determine.',
                   '- **vuln_related**: this site corresponds to a real exploit pattern (RCE via dynamic call, LFI via include, etc.). `?` if uncertain.',
                   '', '---', ''])
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))
        for i, s in enumerate(samples, 1):
            line = int(s['line']) if s['line'] else 0
            snippet, err = load_php_snippet(args.src_root, s['file'], line, args.context)
            f.write(render_sample(i, len(samples), s, snippet, err))
    print(f'[+] wrote {args.out}', file=sys.stderr)


if __name__ == '__main__':
    main()
