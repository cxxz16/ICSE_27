
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Callable, Optional

from .context_extractor import DispatchContext, CandidateCallee


@dataclass
class ResolvedCallee:
    callee: str
    file: str
    line: int
    reaches_sink: bool
    condition: str
    structured_condition: dict


@dataclass
class ResolutionResult:
    site_id: int
    file: str
    lineno: int
    method: str
    confidence: float
    discriminator_origin: str = ""
    resolved_callees: list[ResolvedCallee] = field(default_factory=list)
    runtime_handoff_reason: Optional[str] = None
    standalone_vulnerability_signal: Optional[str] = None
    raw_llm_response: Optional[str] = None
    prompt: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


PROMPT_TEMPLATE = """\
You are analysing a PHP dynamic-dispatch site to enumerate which concrete
callee(s) it can resolve to and what input condition selects each.

# Goal
A backward analysis from a SQL-injection sink in the file
    `{sink_file}`
hit this dispatch site (the static call graph cannot resolve it). Tell us
which CANDIDATE CALLEES the dispatch can route to, and for each, what
the user-controlled input must look like to select it.

# Dispatch site
- file: {site_file}
- line: {site_line}
- category: {site_category} ({site_category_description})
- discriminator expression (one source line):
    `{discriminator_expression}`

# Enclosing function (lines {enc_start}–{enc_end} of {site_file})
```php
{enc_body}
```

# Caller(s) of the enclosing function
{callers_section}

# Candidate callees in the project
The following functions/classes were found by name-pattern grep. For each,
the reachability tag tells you whether selecting it keeps the chain to the
sink open:
  - **reaches sink**       ICFG forward-BFS from the callee body proves a
                           static path to the sink line.
  - **may reach via 2nd dispatch**
                           Static path is interrupted by another dynamic
                           dispatch (e.g. nested call_user_func) we couldn't
                           recurse past. Runtime confirmation needed.
  - (no static path)       No control-flow path to sink from this callee at
                           all — dead branch, ignore.

{candidates_section}

# Required output (JSON only, no prose)
Return a JSON array. Each element is one (callee, condition) pair the
dispatch can route to:

```json
[
  {{
    "callee": "<class-or-function-name, fully qualified if a method>",
    "reaches_sink": <true|false>,
    "condition_natural": "<one English sentence: what does the user have to send so the dispatch picks this callee>",
    "condition_structured": {{
      "param": "<name of the user-controllable HTTP parameter that drives selection>",
      "equals": "<exact string value that param must take>"
    }}
  }},
  ...
]
```

Only output the JSON. Do not include explanations or markdown fences.
"""

CATEGORY_DESC = {
    "DYN_NEW_CLASS":          "instantiation `new $cls(...)` where the class name is variable",
    "DYN_CALL_METHOD":        "method call `$obj->$method(...)` where the method name is variable",
    "DYN_CALL_FN":            "function call `$f(...)` where the function name is variable",
    "DYN_CUF":                "`call_user_func($cb, ...)` where the callback comes from variable",
    "DYN_CALLBACK_BUILTIN":   "callback-accepting built-in (e.g. array_map, usort) with variable callback",
    "DYN_CALL_STATIC_BOTH":   "static call `$cls::$m(...)` where both class and method are variable",
    "DYN_CALL_STATIC_CLASS":  "static call `$cls::method(...)` where the class is variable",
    "DYN_CALL_STATIC_METHOD": "static call `Class::$m(...)` where the method name is variable",
    "DYN_REFLECTION_INVOKE":  "Reflection invoke (`$r->invoke(...)`)",
}


def build_prompt(ctx: DispatchContext) -> str:
    callers_section = "_(none found)_"
    if ctx.callers:
        rows = []
        for c in ctx.callers:
            rows.append(f"- `{c['file']}:{c['line']}`\n    ```php\n    {c['snippet']}\n    ```")
        callers_section = "\n".join(rows)

    cand_section = "_(no candidates discovered statically)_"
    if ctx.candidate_callees:
        rows = []
        for cc in ctx.candidate_callees:
            r = getattr(cc, "reachability", None)
            r_val = r.value if hasattr(r, "value") else None
            if r_val == "reachable":
                tag = "**reaches sink**"
            elif r_val == "potential":
                tag = "**may reach via 2nd dispatch**"
            elif r_val == "unreachable":
                tag = "(no static path)"
            else:
                tag = "**reaches sink**" if cc.reaches_sink else "(no static path)"
            rows.append(
                f"- `{cc.name}` — {cc.kind} @ `{Path(cc.file).name}:{cc.line}` — {tag}\n"
                f"  ```php\n  {cc.snippet}\n  ```"
            )
        cand_section = "\n".join(rows)

    return PROMPT_TEMPLATE.format(
        sink_file=ctx.sink_file,
        site_file=ctx.site.file,
        site_line=ctx.site.lineno,
        site_category=ctx.site.category,
        site_category_description=CATEGORY_DESC.get(ctx.site.category, ""),
        discriminator_expression=ctx.discriminator_expression,
        enc_start=ctx.enclosing_function_lines[0],
        enc_end=ctx.enclosing_function_lines[1],
        enc_body=ctx.enclosing_function_body,
        callers_section=callers_section,
        candidates_section=cand_section,
    )


def _parse_response(text: str) -> list[dict]:
    s = text.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s).strip()
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        m = re.search(r"\[[\s\S]*\]", s)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    if not isinstance(data, list):
        return []
    return data


def resolve(
    ctx: DispatchContext,
    llm_call: Optional[Callable[[str], str]] = None,
) -> ResolutionResult:
    base = ResolutionResult(
        site_id=ctx.site.site_id,
        file=ctx.site.file,
        lineno=ctx.site.lineno,
        method="static_full",
        confidence=0.0,
        discriminator_origin=ctx.discriminator_origin.origin.value,
        standalone_vulnerability_signal=ctx.standalone_vulnerability_signal,
    )

    if ctx.feasibility == "RUNTIME_REQUIRED":
        base.method = "runtime_required"
        base.confidence = 0.0
        base.runtime_handoff_reason = ctx.feasibility_reason
        return base

    prompt = build_prompt(ctx)
    base.prompt = prompt

    if llm_call is None:
        base.method = "static_partial"
        base.confidence = 0.5
        base.raw_llm_response = "<no LLM backend; stubbed>"
        for cc in ctx.candidate_callees:
            base.resolved_callees.append(ResolvedCallee(
                callee=cc.name, file=cc.file, line=cc.line,
                reaches_sink=cc.reaches_sink,
                condition="(stub) requires LLM backend to derive condition",
                structured_condition={},
            ))
        return base

    response = llm_call(prompt)
    base.raw_llm_response = response
    parsed = _parse_response(response)
    if not parsed:
        base.method = "static_partial"
        base.confidence = 0.3
        return base

    base.confidence = 0.9 if ctx.feasibility == "STATIC_RESOLVABLE" else 0.6
    cand_index = {cc.name: cc for cc in ctx.candidate_callees}

    for entry in parsed:
        callee_name = entry.get("callee", "")
        cc_meta = cand_index.get(callee_name)
        base.resolved_callees.append(ResolvedCallee(
            callee=callee_name,
            file=cc_meta.file if cc_meta else "",
            line=cc_meta.line if cc_meta else 0,
            reaches_sink=bool(entry.get("reaches_sink", cc_meta.reaches_sink if cc_meta else False)),
            condition=entry.get("condition_natural", ""),
            structured_condition=entry.get("condition_structured", {}),
        ))
    return base


def make_anthropic_backend(model: str = "claude-opus-4-7") -> Callable[[str], str]:
    try:
        import anthropic
    except ImportError as e:
        raise ImportError("pip install anthropic") from e
    client = anthropic.Anthropic()

    def call(prompt: str) -> str:
        msg = client.messages.create(
            model=model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in msg.content if hasattr(b, "text"))
    return call


def _main():
    import argparse

    from .fig_builder import build_fig
    from .narrow import narrow
    from .context_extractor import build_context

    ap = argparse.ArgumentParser(description="Resolve dispatch sites via LLM.")
    ap.add_argument("-w", "--working-dir", required=True)
    ap.add_argument("-s", "--sink-file", required=True)
    ap.add_argument("-l", "--sink-line", type=int, default=0,
                    help="Sink line number; needed for accurate Reachability (0 = file-equality fallback).")
    ap.add_argument("--backend", choices=["none", "anthropic"], default="none",
                    help="LLM backend; 'none' prints prompts only.")
    ap.add_argument("--model", default="claude-opus-4-7")
    ap.add_argument("--print-prompt", action="store_true",
                    help="Print full prompt for each site (with --backend none).")
    args = ap.parse_args()

    wd = Path(args.working_dir)
    fig = build_fig(wd)
    sites = narrow(args.sink_file, fig, wd / "dispatch_sinks.csv", wd / "nodes.csv")
    contexts = [build_context(s, fig, wd, args.sink_file,
                               sink_line=getattr(args, "sink_line", 0))
                for s in sites]

    backend: Optional[Callable[[str], str]] = None
    if args.backend == "anthropic":
        backend = make_anthropic_backend(model=args.model)

    for ctx in contexts:
        print(f"\n══════ site {ctx.site.site_id} ({ctx.site.category}) "
              f"@ {Path(ctx.site.file).name}:{ctx.site.lineno} ══════")
        result = resolve(ctx, llm_call=backend)
        print(f"  method:     {result.method}")
        print(f"  confidence: {result.confidence}")
        if result.runtime_handoff_reason:
            print(f"  → handoff to module ②: {result.runtime_handoff_reason}")
        for r in result.resolved_callees:
            tag = "★ SINK" if r.reaches_sink else "  ----"
            print(f"  {tag}  {r.callee:<35} | {r.condition}")
            if r.structured_condition:
                print(f"          structured: {r.structured_condition}")
        if args.print_prompt and result.prompt:
            print("\n--- PROMPT ---")
            print(result.prompt)


if __name__ == "__main__":
    _main()
