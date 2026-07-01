
import argparse
import json
import os.path
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse, parse_qsl


def resolve_url_against_file(url_path, from_file):
    if not url_path:
        return ('', 'absolute')
    if url_path.startswith(('http://', 'https://')):
        return (url_path, 'absolute')
    if '__PHP__' in url_path:
        return (url_path, 'unresolvable_php')
    if url_path.startswith('/'):
        return (url_path.lstrip('/'), 'web_absolute')
    from_dir = os.path.dirname(from_file)
    combined = os.path.normpath(os.path.join(from_dir, url_path))
    if combined.startswith('..'):
        return (url_path, 'unresolvable_escape')
    return (combined, 'relative_resolved')


class NavGraphBuilder:

    HTML_PATTERNS = [
        (re.compile(r'''<a\b[^>]*?\bhref\s*=\s*(["'])((?:(?!\1).)*?)\1''',
                    re.IGNORECASE),
         'html_a_href', 'GET'),
        (re.compile(r'''<form\b[^>]*?\baction\s*=\s*(["'])((?:(?!\1).)*?)\1''',
                    re.IGNORECASE),
         'html_form_action', 'POST'),
        (re.compile(r'''<i?frame\b[^>]*?\bsrc\s*=\s*(["'])((?:(?!\1).)*?)\1''',
                    re.IGNORECASE),
         'html_frame_src', 'GET'),
    ]

    JS_PATTERNS = [
        (re.compile(r'''(?:window\.)?location(?:\.href)?\s*=\s*(["'])((?:(?!\1).)*?)\1'''),
         'js_location_href', 'GET'),
        (re.compile(r'''\bwindow\.open\s*\(\s*(["'])((?:(?!\1).)*?)\1'''),
         'js_window_open', 'GET'),
        (re.compile(r'''\$\.(?:ajax|get|post)\s*\(\s*[{(]?\s*(?:url\s*:\s*)?(["'])((?:(?!\1).)*?)\1'''),
         'js_jquery_ajax', 'GET'),
        (re.compile(r'''\bfetch\s*\(\s*(["'])((?:(?!\1).)*?)\1'''),
         'js_fetch', 'GET'),
    ]

    PHP_PATTERNS = [
        (re.compile(r'''\b(?:include|require)(?:_once)?\s*\(?\s*["']([^"']+\.(?:php|inc))["']''',
                    re.IGNORECASE),
         'php_include', 'GET'),
        (re.compile(r'''\bheader\s*\(\s*["']\s*Location\s*:\s*([^"'\\]+?)["']''',
                    re.IGNORECASE),
         'php_header_location', 'GET'),
    ]

    ALL_PATTERNS = HTML_PATTERNS + JS_PATTERNS + PHP_PATTERNS

    FORM_METHOD_RE = re.compile(
        r'''<form\b[^>]*?\bmethod\s*=\s*["']?(get|post)["']?''',
        re.IGNORECASE)

    def __init__(self, project_root, file_globs=('*.php', '*.inc')):
        self.project_root = Path(project_root).resolve()
        self.file_globs = file_globs
        self.refs_to = defaultdict(list)
        self._files_scanned = 0
        self._refs_total = 0

    def scan(self, exclude_substrs=('/vendor/', '/node_modules/', '/test/', '/tests/')):
        for glob in self.file_globs:
            for php in self.project_root.rglob(glob):
                rel = str(php.relative_to(self.project_root))
                if any(sub in '/' + rel for sub in exclude_substrs):
                    continue
                self._scan_file(php)
        return self

    PHP_TAG_RE = re.compile(r'<\?(?:php\b|=)?.*?\?>', re.DOTALL)

    def _scan_file(self, php_path):
        try:
            text = php_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            return
        rel = str(php_path.relative_to(self.project_root))
        self._files_scanned += 1
        lines = text.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, ref_type, default_method in self.ALL_PATTERNS:
                for m in pattern.finditer(line):
                    url = m.groups()[-1]
                    url = self.PHP_TAG_RE.sub('__PHP__', url)
                    method = default_method
                    if ref_type == 'html_form_action':
                        ctx = '\n'.join(
                            lines[max(0, i - 3): min(len(lines), i + 2)])
                        mm = self.FORM_METHOD_RE.search(ctx)
                        if mm:
                            method = mm.group(1).upper()
                    self._record_ref(rel, i, ref_type, method, url, line.strip())

    def _record_ref(self, from_file, from_line, ref_type, method, url, raw_line):
        parsed = self._parse_ref_url(url)
        if not parsed['basename']:
            return
        if not (parsed['basename'].endswith('.php')
                or parsed['basename'].endswith('.inc')):
            return
        resolved_path, resolve_status = resolve_url_against_file(
            parsed['path'], from_file)
        ref = {
            'from_file': from_file,
            'from_line': from_line,
            'ref_type': ref_type,
            'method': method,
            'url_template': parsed['path'],
            'resolved_path': resolved_path,
            'resolve_status': resolve_status,
            'prefilled_params': parsed['params'],
            'raw_line': raw_line[:200],
        }
        self.refs_to[parsed['basename']].append(ref)
        self._refs_total += 1

    @staticmethod
    def _parse_ref_url(url):
        try:
            p = urlparse(url)
            path = p.path or url.split('?', 1)[0]
            basename = Path(path).name if path else ''
            params = dict(parse_qsl(p.query, keep_blank_values=True))
            return {'basename': basename, 'path': path, 'params': params}
        except Exception:
            return {'basename': '', 'path': url, 'params': {}}

    def get_refs_to(self, target_basename):
        return self.refs_to.get(target_basename, [])

    def stats(self):
        return {
            'files_scanned': self._files_scanned,
            'distinct_targets': len(self.refs_to),
            'refs_total': self._refs_total,
        }


class FrameworkRouterPlaceholder:

    SUPPORTED = []

    def __init__(self, project_root):
        self.project_root = Path(project_root)

    def detect_framework(self):
        return None

    def routes_to(self, target_relpath):
        return []


def aggregate_seed_params(refs):
    bag = defaultdict(set)
    for ref in refs:
        for k, v in ref.get('prefilled_params', {}).items():
            bag[k].add(v)
    return {k: sorted(v) for k, v in bag.items()}


def build_enriched_entry_urls(
        sink_file_relpath,
        nav_graph,
        framework_router,
        predator_request_data=None,
        host='http://localhost',
        web_root=''):
    sink_basename = Path(sink_file_relpath).name
    entries = []

    def _make_url(path):
        if path.startswith(('http://', 'https://')):
            return path
        prefix = f'/{web_root}' if web_root else ''
        return f'{host}{prefix}/{path.lstrip("/")}'

    entries.append({
        'url': _make_url(sink_file_relpath),
        'resolved_path': sink_file_relpath,
        'method': 'POST',
        'method_source': 'sink_file_self',
        'prefilled_params': {},
        'ref_origins': [{'kind': 'self', 'from': sink_file_relpath}],
        'from_predator': False,
    })

    nav_refs = nav_graph.get_refs_to(sink_basename)
    by_key = {}
    for ref in nav_refs:
        key = (ref['resolved_path'], ref['method'])
        if key not in by_key:
            by_key[key] = {
                'url': _make_url(ref['resolved_path']),
                'resolved_path': ref['resolved_path'],
                'method': ref['method'],
                'method_source': ref['ref_type'],
                'prefilled_params': dict(ref['prefilled_params']),
                'ref_origins': [],
                'from_predator': False,
                'resolve_statuses': set(),
            }
        else:
            for k, v in ref['prefilled_params'].items():
                if k not in by_key[key]['prefilled_params'] or v:
                    by_key[key]['prefilled_params'][k] = v
        by_key[key]['ref_origins'].append({
            'kind': ref['ref_type'],
            'from': ref['from_file'],
            'line': ref['from_line'],
            'url_template': ref['url_template'],
            'resolve_status': ref['resolve_status'],
            'snippet': ref['raw_line'][:120],
        })
        by_key[key]['resolve_statuses'].add(ref['resolve_status'])
    for v in by_key.values():
        v['resolve_statuses'] = sorted(v['resolve_statuses'])
    entries.extend(by_key.values())

    for route in framework_router.routes_to(sink_file_relpath):
        pass

    if predator_request_data:
        predator_urls = predator_request_data.get('requestsFound', {})
        for key, info in predator_urls.items():
            url = info.get('_url', '')
            method = info.get('_method', 'GET')
            mkey = (url, method)
            existing = next((e for e in entries
                             if e['url'] == url and e['method'] == method), None)
            if existing is None:
                entries.append({
                    'url': url,
                    'method': method,
                    'method_source': 'predator_corpus_builder',
                    'prefilled_params': {
                        kv.split('=', 1)[0]: kv.split('=', 1)[1] if '=' in kv else ''
                        for kv in info.get('_pivotal_input_set', []) or []
                    },
                    'ref_origins': [{'kind': 'predator_request_data',
                                     'pivotal_set': info.get('_pivotal_input_set', [])}],
                    'from_predator': True,
                })
            else:
                existing['from_predator'] = True
                existing.setdefault('predator_pivotal_set',
                                    info.get('_pivotal_input_set', []))

    all_refs = nav_refs[:]
    seed_params = aggregate_seed_params(all_refs)

    return {
        'sink_file': sink_file_relpath,
        'sink_basename': sink_basename,
        'entry_urls': entries,
        'seed_params': seed_params,
        'nav_graph_stats': nav_graph.stats(),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-root', required=True)
    ap.add_argument('--sink-file', required=True,
                    help='Sink file relative to project-root, e.g. openemr/library/pnotes.inc')
    ap.add_argument('--predator-request-data', default=None,
                    help='Optional: Predator-generated request_data.json to merge')
    ap.add_argument('--web-root', default='',
                    help='URL prefix prepended to project-relative paths, '
                         'e.g. "openemr" for OpenEMR served at /openemr/. '
                         'Default empty (paths used as-is).')
    ap.add_argument('--host', default='http://localhost',
                    help='Host part of generated URLs (default http://localhost)')
    ap.add_argument('--out', default=None,
                    help='Output JSON path (default: stdout)')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    nav = NavGraphBuilder(args.project_root)
    if not args.quiet:
        print(f'[*] scanning {args.project_root} ...', file=sys.stderr)
    nav.scan()
    s = nav.stats()
    if not args.quiet:
        print(f'[+] {s["files_scanned"]} files, {s["distinct_targets"]} target basenames, '
              f'{s["refs_total"]} refs total', file=sys.stderr)

    fw = FrameworkRouterPlaceholder(args.project_root)

    pred_rd = None
    if args.predator_request_data:
        pred_rd = json.loads(Path(args.predator_request_data).read_text())

    result = build_enriched_entry_urls(
        sink_file_relpath=args.sink_file,
        nav_graph=nav,
        framework_router=fw,
        predator_request_data=pred_rd,
        host=args.host,
        web_root=args.web_root,
    )

    out = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(out, encoding='utf-8')
        if not args.quiet:
            print(f'[+] wrote {args.out}', file=sys.stderr)
    else:
        print(out)


if __name__ == '__main__':
    main()
