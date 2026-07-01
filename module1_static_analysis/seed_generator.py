
import json
import re
import argparse
from typing import Optional

from common.llm import chat


SYSTEM = (
    "You are an expert in web application security and PHP source code analysis. "
    "Your task is to construct an HTTP request that reaches a vulnerable SQL sink "
    "and triggers a SQL injection error."
)


def _build_prompt(constraints: dict) -> str:
    entry_url = constraints['entry_url']
    method    = constraints['method']
    sink      = constraints['sink']

    ctx_str = '\n'.join(
        f"  line {ln}: {code}"
        for ln, code in sorted(constraints['sink']['context'].items())
    )

    if_lines = []
    for c in constraints['if_constraints']:
        if_lines.append(f"  - line {c['lineno']} (dist={c['dist']}): {c['raw_line']}")
        if_lines.append(f"    → params involved: {c['params']}")
    if_block = '\n'.join(if_lines) if if_lines else '  (none)'

    eg_lines = []
    for g in constraints['exit_guards']:
        eg_lines.append(f"  - line {g['lineno']}: {g['raw_line']}")
        eg_lines.append(f"    → {g['note']}")
    eg_block = '\n'.join(eg_lines) if eg_lines else '  (none)'

    pa_lines = []
    for key, info in constraints['param_assignments'].items():
        pa_lines.append(
            f"  - '{key}': assigned from `{info['rhs_expr']}` at line {info['lineno']}"
        )
    pa_block = '\n'.join(pa_lines) if pa_lines else '  (none)'

    ic_lines = []
    for node in constraints.get('injection_chain', []):
        ic_lines.append(f"  line {node['lineno']:4d}  [{node['varname']}]  {node['source']}")
    ic_block = '\n'.join(ic_lines) if ic_lines else '  (none)'

    prompt = f"""
You are analyzing a PHP web application for SQL injection.

## Target
Entry URL : {entry_url}
Method    : {method}
Sink line : {sink['lineno']} — `{sink['statement']}`

## Sink context (surrounding {len(sink['context'])} lines)
{ctx_str}

## Taint / injection chain (HTTP input → variable → SQL sink)
{ic_block}

## Path conditions to reach the sink (if/elseif on the execution path)
{if_block}

## Exit guards (conditions that abort execution — must NOT be triggered)
{eg_block}

## Parameter assignments (HTTP params and their direct variable bindings)
{pa_block}

## Task
Using the injection chain above:

1. Identify which HTTP parameters are **hard-constrained** (must equal a specific value
   to satisfy an if/elseif condition on the path to sink — do NOT mutate these).
2. Identify which HTTP parameters are **freely mutable** (appear in assignments but
   NOT in hard if==conditions — these are candidate injection points).
3. Generate the minimal set of HTTP POST parameters that:
   - Satisfy all if/elseif hard constraints
   - Do NOT trigger any exit guard
   - Inject a single-quote `'` through the identified taint/injection parameter

Return a JSON object with TWO fields:
{{
  "seed": {{"mode": "update", "action": "store_PDF", "encounter": "1'", ...}},
  "mutable_params": ["encounter", "pid"]
}}

- "seed": the full key=value set for the first test
- "mutable_params": list of parameter names that are NOT hard-constrained
  and could carry injection payloads (i.e. their values flow toward the sink)

No explanation, no markdown fences — just the raw JSON object.
""".strip()

    return prompt


def _parse_response(content: str) -> Optional[dict]:
    try:
        obj = json.loads(content.strip())
        if isinstance(obj, dict) and 'seed' in obj:
            return obj
        if isinstance(obj, dict):
            return {'seed': obj, 'mutable_params': []}
    except json.JSONDecodeError:
        pass
    m = re.search(r'\{.*\}', content, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group())
            if 'seed' in obj:
                return obj
            return {'seed': obj, 'mutable_params': []}
        except json.JSONDecodeError:
            pass
    return None


def generate_seed(constraints: dict, stage: str = "seed_gen", verbose: bool = False) -> dict:
    prompt   = _build_prompt(constraints)

    if verbose:
        print("=" * 60)
        print("EXTRACTED CONSTRAINTS")
        print("=" * 60)
        print(json.dumps(constraints, indent=2, ensure_ascii=False))
        print()
        print("=" * 60)
        print("PROMPT SENT TO LLM")
        print("=" * 60)
        print(prompt)
        print()

    response = chat(prompt, stage=stage)

    usage   = response['usage']
    content = response['content']

    if verbose:
        print("=" * 60)
        print("LLM RESPONSE")
        print("=" * 60)
        print(content)
        print(f"\nUsage: {usage}")
        print()

    parsed = _parse_response(content)
    if parsed is None:
        print(f"[seed_generator] WARNING: could not parse LLM response:\n{content}")
        parsed = {}

    params         = parsed.get('seed', parsed)
    mutable_params = parsed.get('mutable_params', [])

    entry_url = constraints['entry_url']
    method    = constraints['method'].upper()
    post_data = '&'.join(f"{k}={v}" for k, v in params.items())

    if method == 'POST':
        url_with_params = entry_url
    else:
        url_with_params = f"{entry_url}?{post_data}" if post_data else entry_url

    return {
        'params':           params,
        'mutable_params':   mutable_params,
        'post_data':        post_data,
        'url_with_params':  url_with_params,
        'method':           method,
        'usage':            usage,
        'raw_llm_response': content,
    }


def main():
    parser = argparse.ArgumentParser(description='VIPER seed generator')
    parser.add_argument('--constraints', required=True,
                        help='JSON file from param_extractor (or stdin with -)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print extracted constraints + full prompt + LLM response')
    parser.add_argument('--output', '-o', default=None,
                        help='Save full result JSON to this file')
    args = parser.parse_args()

    if args.constraints == '-':
        import sys
        constraints = json.load(sys.stdin)
    else:
        with open(args.constraints) as f:
            constraints = json.load(f)

    result = generate_seed(constraints, verbose=args.verbose)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[seed_generator] saved to {args.output}")

    print("\n=== Generated seed ===")
    print(f"POST data : {result['post_data']}")
    print(f"URL       : {result['url_with_params']}")
    print(f"Tokens    : {result['usage']}")
    print(f"\nFull params:")
    print(json.dumps(result['params'], indent=2))


if __name__ == '__main__':
    main()
