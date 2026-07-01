
import argparse
import csv
import os
import sys
from collections import defaultdict


LITERAL_TYPES = {"string", "AST_NAME", "AST_CONST"}

USER_FUNC_CALLS = {
    "call_user_func", "call_user_func_array",
    "forward_static_call", "forward_static_call_array",
}

CALLBACK_BUILTINS = {
    "array_map": [0],
    "array_filter": [1],
    "array_reduce": [1],
    "array_walk": [1],
    "array_walk_recursive": [1],
    "usort": [1],
    "uasort": [1],
    "uksort": [1],
    "preg_replace_callback": [1],
    "preg_replace_callback_array": [0],
    "register_shutdown_function": [0],
    "spl_autoload_register": [0],
    "set_error_handler": [0],
    "set_exception_handler": [0],
    "register_tick_function": [0],
    "iterator_apply": [1],
    "header_register_callback": [0],
    "ob_start": [0],
    "session_set_save_handler": [0, 1, 2, 3, 4, 5],
    "mb_ereg_replace_callback": [2],
    "xml_set_character_data_handler": [1],
    "xml_set_default_handler": [1],
    "xml_set_element_handler": [1, 2],
    "xml_set_end_namespace_decl_handler": [1],
    "xml_set_external_entity_ref_handler": [1],
    "xml_set_notation_decl_handler": [1],
    "xml_set_processing_instruction_handler": [1],
    "xml_set_start_namespace_decl_handler": [1],
    "xml_set_unparsed_entity_decl_handler": [1],
}

REFLECTION_INVOKE_METHODS = {"invoke", "invokeArgs", "newInstance", "newInstanceArgs"}


class CPG:

    def __init__(self, nodes_csv, rels_csv, quiet=False):
        self.nodes = {}
        self.children = defaultdict(dict)
        self.parent = {}
        self.toplevel_file = {}
        self.defined_functions = set()
        self._load_nodes(nodes_csv, quiet=quiet)
        self._load_rels(rels_csv, quiet=quiet)

    @staticmethod
    def _int(s, default=0):
        try:
            return int(s)
        except (TypeError, ValueError):
            return default

    def _load_nodes(self, path, quiet=False):
        if not quiet:
            print(f"[*] loading nodes from {path} ...", file=sys.stderr)
        n_total = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                nid = self._int(row.get('id:int'), -1)
                if nid < 0:
                    continue
                flags = row.get('flags:string_array', '') or ''
                self.nodes[nid] = {
                    'type':    row.get('type', ''),
                    'flags':   flags,
                    'lineno':  self._int(row.get('lineno:int')),
                    'code':    (row.get('code') or '').strip('"'),
                    'childnum': self._int(row.get('childnum:int'), -1),
                    'funcid':  self._int(row.get('funcid:int')),
                    'name':    (row.get('name') or '').strip('"'),
                }
                if 'TOPLEVEL_FILE' in flags:
                    self.toplevel_file[nid] = self.nodes[nid]['name']
                ntype = self.nodes[nid]['type']
                if ntype in ('AST_FUNC_DECL', 'AST_METHOD', 'AST_CLOSURE'):
                    fname = self.nodes[nid]['name']
                    if fname:
                        self.defined_functions.add(fname)
                n_total += 1
        if not quiet:
            print(f"[+] {n_total} nodes loaded, {len(self.toplevel_file)} toplevel files, "
                  f"{len(self.defined_functions)} defined funcs/methods", file=sys.stderr)

    def _load_rels(self, path, quiet=False):
        if not quiet:
            print(f"[*] loading rels from {path} ...", file=sys.stderr)
        n_parent_of = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                if row.get('type') != 'PARENT_OF':
                    continue
                p = self._int(row.get('start'), -1)
                c = self._int(row.get('end'), -1)
                if p < 0 or c < 0:
                    continue
                cn = self.nodes.get(c, {}).get('childnum', -1)
                self.children[p][cn] = c
                self.parent[c] = p
                n_parent_of += 1
        if not quiet:
            print(f"[+] {n_parent_of} PARENT_OF edges loaded", file=sys.stderr)

    def child(self, parent_id, childnum):
        return self.children.get(parent_id, {}).get(childnum)

    def get(self, nid):
        return self.nodes.get(nid)

    def type_of(self, nid):
        n = self.nodes.get(nid)
        return n['type'] if n else None

    def code_of(self, nid):
        n = self.nodes.get(nid)
        return n['code'] if n else None

    def file_of(self, nid):
        cur = nid
        depth = 0
        while cur is not None and depth < 10000:
            if cur in self.toplevel_file:
                return self.toplevel_file[cur]
            cur = self.parent.get(cur)
            depth += 1
        return ''


class Site:
    __slots__ = ('id', 'category', 'ast_type', 'file', 'line',
                 'callable_subexpr_id', 'details')

    def __init__(self, id, category, ast_type, file, line,
                 callable_subexpr_id=None, details=''):
        self.id = id
        self.category = category
        self.ast_type = ast_type
        self.file = file
        self.line = line
        self.callable_subexpr_id = callable_subexpr_id
        self.details = details


def is_literal(cpg, nid):
    if nid is None:
        return False
    return cpg.type_of(nid) in LITERAL_TYPES


def get_call_callee_name(cpg, call_id):
    callee = cpg.child(call_id, 0)
    if callee is None:
        return None
    if cpg.type_of(callee) != 'AST_NAME':
        return None
    name_node = cpg.child(callee, 0)
    if name_node is None:
        return None
    return cpg.code_of(name_node) or cpg.get(name_node).get('name', '') or None


def _site(cpg, nid, category, ast_type, callable_id=None, details=''):
    n = cpg.get(nid) or {}
    return Site(
        id=nid,
        category=category,
        ast_type=ast_type,
        file=cpg.file_of(nid),
        line=n.get('lineno', 0),
        callable_subexpr_id=callable_id,
        details=details,
    )


def detect_call(cpg, nid):
    callee = cpg.child(nid, 0)
    if callee is None:
        return []
    if not is_literal(cpg, callee):
        return [_site(cpg, nid, 'DYN_CALL_FN', 'AST_CALL',
                      callable_id=callee,
                      details=f'callee_type={cpg.type_of(callee)}')]

    name = get_call_callee_name(cpg, nid)
    if not name:
        return []
    nl = name.lower()
    sites = []
    args_list = cpg.child(nid, 1)

    if nl in USER_FUNC_CALLS:
        arg0 = cpg.child(args_list, 0) if args_list else None
        if arg0 is not None and not is_literal(cpg, arg0):
            sites.append(_site(cpg, nid, 'DYN_CUF', 'AST_CALL',
                                callable_id=arg0,
                                details=f'fn={name},arg0_type={cpg.type_of(arg0)}'))
    elif nl in CALLBACK_BUILTINS:
        for pos in CALLBACK_BUILTINS[nl]:
            arg = cpg.child(args_list, pos) if args_list else None
            if arg is not None and not is_literal(cpg, arg):
                sites.append(_site(cpg, nid, 'DYN_CALLBACK_BUILTIN', 'AST_CALL',
                                    callable_id=arg,
                                    details=f'fn={name},pos={pos},arg_type={cpg.type_of(arg)}'))
                break
    elif nl == 'create_function':
        sites.append(_site(cpg, nid, 'DYN_CREATE_FUNCTION', 'AST_CALL',
                            details=f'fn={name}'))
    elif nl == 'assert':
        arg0 = cpg.child(args_list, 0) if args_list else None
        if arg0 is not None and cpg.type_of(arg0) == 'string':
            sites.append(_site(cpg, nid, 'DYN_ASSERT_STR', 'AST_CALL',
                                callable_id=arg0, details=f'fn={name}'))
    return sites


def detect_method_call(cpg, nid):
    method_id = cpg.child(nid, 1)
    if method_id is None:
        return []
    t = cpg.type_of(method_id)
    if t != 'string':
        return [_site(cpg, nid, 'DYN_CALL_METHOD', 'AST_METHOD_CALL',
                      callable_id=method_id, details=f'method_type={t}')]
    name = cpg.code_of(method_id) or ''
    if name in REFLECTION_INVOKE_METHODS:
        return [_site(cpg, nid, 'DYN_REFLECTION_INVOKE', 'AST_METHOD_CALL',
                      details=f'method={name}')]
    return []


def detect_static_call(cpg, nid):
    class_id = cpg.child(nid, 0)
    method_id = cpg.child(nid, 1)
    class_dyn = class_id is not None and not is_literal(cpg, class_id)
    method_dyn = (method_id is not None and
                  cpg.type_of(method_id) not in ('string', 'AST_NAME'))
    if class_dyn and method_dyn:
        return [_site(cpg, nid, 'DYN_CALL_STATIC_BOTH', 'AST_STATIC_CALL',
                      callable_id=method_id)]
    if class_dyn:
        return [_site(cpg, nid, 'DYN_CALL_STATIC_CLASS', 'AST_STATIC_CALL',
                      callable_id=class_id, details=f'class_type={cpg.type_of(class_id)}')]
    if method_dyn:
        return [_site(cpg, nid, 'DYN_CALL_STATIC_METHOD', 'AST_STATIC_CALL',
                      callable_id=method_id, details=f'method_type={cpg.type_of(method_id)}')]
    return []


def detect_new(cpg, nid):
    class_id = cpg.child(nid, 0)
    if class_id is not None and not is_literal(cpg, class_id):
        return [_site(cpg, nid, 'DYN_NEW_CLASS', 'AST_NEW',
                      callable_id=class_id,
                      details=f'class_type={cpg.type_of(class_id)}')]
    return []


def detect_include_or_eval(cpg, nid):
    flags = (cpg.get(nid) or {}).get('flags', '')
    expr = cpg.child(nid, 0)
    if flags == 'EXEC_EVAL':
        return [_site(cpg, nid, 'DYN_EVAL', 'AST_INCLUDE_OR_EVAL',
                      callable_id=expr, details=f'flags={flags}')]
    if expr is not None and cpg.type_of(expr) != 'string':
        return [_site(cpg, nid, 'DYN_INCLUDE', 'AST_INCLUDE_OR_EVAL',
                      callable_id=expr,
                      details=f'flags={flags},expr_type={cpg.type_of(expr)}')]
    return []


def detect_var(cpg, nid):
    name_id = cpg.child(nid, 0)
    if name_id is not None and cpg.type_of(name_id) != 'string':
        return [_site(cpg, nid, 'DYN_VARVAR', 'AST_VAR',
                      callable_id=name_id, details=f'name_type={cpg.type_of(name_id)}')]
    return []


def detect_prop(cpg, nid):
    prop_id = cpg.child(nid, 1)
    if prop_id is not None and cpg.type_of(prop_id) != 'string':
        return [_site(cpg, nid, 'DYN_VAR_PROP', 'AST_PROP',
                      callable_id=prop_id, details=f'prop_type={cpg.type_of(prop_id)}')]
    return []


def detect_static_prop(cpg, nid):
    prop_id = cpg.child(nid, 1)
    if prop_id is not None and cpg.type_of(prop_id) != 'string':
        return [_site(cpg, nid, 'DYN_VAR_STATIC_PROP', 'AST_STATIC_PROP',
                      callable_id=prop_id, details=f'prop_type={cpg.type_of(prop_id)}')]
    return []


DISPATCH = {
    'AST_CALL':              detect_call,
    'AST_METHOD_CALL':       detect_method_call,
    'AST_STATIC_CALL':       detect_static_call,
    'AST_NEW':               detect_new,
    'AST_INCLUDE_OR_EVAL':   detect_include_or_eval,
    'AST_VAR':               detect_var,
    'AST_PROP':              detect_prop,
    'AST_STATIC_PROP':       detect_static_prop,
}


def detect_sites(cpg):
    sites = []
    for nid, n in cpg.nodes.items():
        fn = DISPATCH.get(n['type'])
        if fn is None:
            continue
        sites.extend(fn(cpg, nid))
    return sites


def write_report(sites, output_path):
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['site_id', 'category', 'ast_type', 'file', 'line',
                    'callable_subexpr_id', 'details'])
        for s in sorted(sites, key=lambda x: (x.file, x.line, x.id)):
            w.writerow([s.id, s.category, s.ast_type, s.file, s.line,
                        s.callable_subexpr_id if s.callable_subexpr_id is not None else '',
                        s.details])


def print_summary(sites, cpg):
    by_cat = defaultdict(int)
    by_file = defaultdict(int)
    for s in sites:
        by_cat[s.category] += 1
        by_file[s.file] += 1
    print()
    print('=' * 72)
    print(f'Dynamic Dispatch Sites — Summary')
    print('=' * 72)
    print(f'Total sites:           {len(sites)}')
    print(f'Total nodes scanned:   {len(cpg.nodes)}')
    print(f'Files touched:         {len(by_file)}')
    print(f'Defined funcs/methods: {len(cpg.defined_functions)}')
    print()
    print('By category:')
    for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f'  {cat:30s} {cnt:6d}')
    print()
    print('Top 10 files by site count:')
    for fpath, cnt in sorted(by_file.items(), key=lambda x: -x[1])[:10]:
        print(f'  {cnt:5d}   {fpath}')
    print('=' * 72)


def main():
    ap = argparse.ArgumentParser(
        description='Identify PHP 7 dynamic-dispatch fake-proxy-sink sites in a phpjoern CPG.')
    ap.add_argument('--nodes', required=True, help='path to nodes.csv')
    ap.add_argument('--rels', required=True, help='path to rels.csv')
    ap.add_argument('--out', default='dynamic_dispatch_report.csv',
                    help='output CSV path (default: dynamic_dispatch_report.csv)')
    ap.add_argument('--quiet', action='store_true', help='suppress progress messages')
    args = ap.parse_args()

    if not os.path.exists(args.nodes):
        print(f'[!] nodes.csv not found: {args.nodes}', file=sys.stderr); sys.exit(1)
    if not os.path.exists(args.rels):
        print(f'[!] rels.csv not found: {args.rels}', file=sys.stderr); sys.exit(1)

    cpg = CPG(args.nodes, args.rels, quiet=args.quiet)
    sites = detect_sites(cpg)
    write_report(sites, args.out)
    print(f'[+] wrote {len(sites)} sites to {args.out}', file=sys.stderr)
    if not args.quiet:
        print_summary(sites, cpg)


if __name__ == '__main__':
    main()
