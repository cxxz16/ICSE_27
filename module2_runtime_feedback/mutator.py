
import json
import re
import argparse
from common.llm import chat


SYSTEM = (
    "You are an expert in web application security specializing in SQL injection. "
    "Your task is to generate mutation variants of an HTTP request payload "
    "to trigger a SQL syntax error at a specific sink."
)


def _build_mutation_prompt(
    seed_params:    dict,
    mutable_params: list,
    injection_chain: list,
    if_constraints:  list,
    sqli_dict:      list[str],
    n:              int,
) -> str:
    seed_str   = json.dumps(seed_params, indent=2, ensure_ascii=False)
    dict_str   = '\n'.join(f'  {d!r}' for d in sqli_dict[:20])

    chain_str = '\n'.join(
        f"  line {node['lineno']:4d} [{node['varname']}]  {node['source']}"
        for node in injection_chain
    )

    constrained = [c['params'] for c in if_constraints]
    constrained_flat = sorted(set(p for ps in constrained for p in ps))
    constrained_str = ', '.join(f'`{p}`' for p in constrained_flat) or 'none'

    mutable_str = ', '.join(f'`{p}`' for p in mutable_params) or 'none identified'

    examples = []
    for payload in ["'", "%27"]:
        variant = dict(seed_params)
        if mutable_params:
            variant[mutable_params[0]] = f"EXAMPLE_VALUE{payload}"
        examples.append(variant)
    example_str = json.dumps(examples, indent=2, ensure_ascii=False)

    return f"""
You are generating SQL injection mutation variants for a PHP web application.

## Current seed (HTTP POST parameters)
{seed_str}

## Taint / injection chain (source → sink)
{chain_str}

## Path constraints (if/elseif conditions — MUST keep these values fixed)
These parameters are hard-constrained by if==conditions on the path to sink:
  {constrained_str}

## Mutable parameters (NOT hard-constrained — candidates for injection)
  {mutable_str}

## SQLi payload dictionary
{dict_str}

## Your task
1. Reason from the injection chain: which of the mutable parameters
   actually flows (directly or through variables) into the SQL string at the sink?
2. Generate {n} mutation variants by substituting different SQLi payloads
   into the parameter(s) that affect the SQL sink.
3. Keep hard-constrained parameters exactly as in the seed.
4. Use payloads from the dictionary above; also try variations
   (URL-encoded, backslash-escaped, GBK bypass, comment truncation, etc.).

Each variant must be a complete copy of the seed with only the
injection-relevant parameter(s) varied. Example format:
{example_str}

Return ONLY a JSON array of {n} objects.
No explanation, no markdown fences — just the raw JSON array.
""".strip()


def mutate(
    seed:              dict,
    constraints:       dict,
    request_data_path: str,
    n:                 int = 8,
    stage:             str = "mutate",
) -> list[dict]:
    seed_params     = seed.get('params', {})
    mutable_params  = seed.get('mutable_params', [])
    injection_chain = constraints.get('injection_chain', [])
    if_constraints  = constraints.get('if_constraints', [])

    with open(request_data_path) as f:
        request_data = json.load(f)
    sqli_dict = [
        x.lstrip('&') for x in request_data.get('inputSet', [])
        if "'" in x or '%27' in x or '%5C' in x or '--' in x or '/*' in x
    ]
    sqli_dict = [x for x in sqli_dict if x]
    print(f"[mutator] mutable_params={mutable_params}  dict_size={len(sqli_dict)}")

    prompt   = _build_mutation_prompt(
        seed_params, mutable_params, injection_chain,
        if_constraints, sqli_dict, n
    )
    response = chat(prompt, stage=stage)
    content  = response['content']
    usage    = response['usage']

    variants = []
    try:
        variants = json.loads(content.strip())
        if not isinstance(variants, list):
            variants = [variants]
    except json.JSONDecodeError:
        m = re.search(r'\[.*\]', content, re.DOTALL)
        if m:
            try:
                variants = json.loads(m.group())
            except Exception:
                pass

    print(f"[mutator] generated {len(variants)} variants  tokens={usage}")
    return variants


def main():
    parser = argparse.ArgumentParser(description='VIPER LLM mutator')
    parser.add_argument('--seed',         required=True)
    parser.add_argument('--constraints',  required=True)
    parser.add_argument('--request-data', required=True)
    parser.add_argument('--n',            type=int, default=8)
    parser.add_argument('--output', '-o', default=None)
    args = parser.parse_args()

    seed        = json.load(open(args.seed))
    constraints = json.load(open(args.constraints))
    variants    = mutate(seed, constraints, args.request_data, n=args.n)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(variants, f, indent=2)
        print(f"[mutator] saved to {args.output}")

    print("\n=== Mutation variants ===")
    for i, v in enumerate(variants):
        post = '&'.join(f"{k}={val}" for k, val in v.items())
        print(f"  [{i}] {post}")


if __name__ == '__main__':
    main()
