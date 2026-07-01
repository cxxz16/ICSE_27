from __future__ import annotations

import glob
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("/home/user/research/Predator")
LOG_DIR = ROOT / "logs/predator-fuzz"
RESULTS = ROOT / "VIPER/expr/predator_run/fuzz_results.tsv"

MAGIC = "alert(290363)"


RULES = [
    ("script_tag_body",         "TP",
     r"<script\b[^>]*>[^<]*" + re.escape(MAGIC)),
    ("svg_onload",              "TP",
     r"<svg\b[^>]*\bonload\s*=\s*['\"][^'\"]*" + re.escape(MAGIC)),
    ("event_handler_attr",      "TP",
     r"\bon[a-z]+\s*=\s*['\"][^'\"]*" + re.escape(MAGIC)),
    ("href_javascript_url",     "TP",
     r"\bhref\s*=\s*['\"]\s*javascript:[^'\"]*" + re.escape(MAGIC)),
    ("src_javascript_url",      "TP",
     r"\bsrc\s*=\s*['\"]\s*javascript:[^'\"]*" + re.escape(MAGIC)),
    ("action_javascript_url",   "TP",
     r"\baction\s*=\s*['\"]\s*javascript:[^'\"]*" + re.escape(MAGIC)),
    ("unescaped_lt_script",     "TP",
     r"&lt;[Ss][Cc][Rr][Ii][Pp][Tt]"),

    ("window_open_query",       "FP",
     r"window\.open\s*\(\s*['\"][^'\"]*\?[^'\"]*" + re.escape(MAGIC)),
    ("input_value_attr",        "FP",
     r"<input\b[^>]*\bvalue\s*=\s*['\"][^'\"]*" + re.escape(MAGIC)),
    ("non_event_quoted_attr",   "FP",
     r"\b(?:value|title|alt|placeholder|name|id|class)\s*=\s*['\"][^'\"]*"
     + re.escape(MAGIC)),
    ("url_query_param",         "FP",
     r"\b(?:href|src|action)\s*=\s*['\"](?!javascript:)[^'\"]*\?[^'\"]*"
     + re.escape(MAGIC)),

    ("plain_text_or_other",     "MAYBE", r".*"),
]
COMPILED = [(name, verdict, re.compile(pat, re.IGNORECASE)) for name, verdict, pat in RULES]


def classify(line: str) -> tuple[str, str]:
    for name, verdict, rx in COMPILED:
        if rx.search(line):
            return name, verdict
    return ("unmatched", "MAYBE")


def main() -> None:
    crashes = []
    for row in RESULTS.read_text().splitlines()[1:]:
        f = row.split("\t")
        if len(f) >= 6 and f[2] == "CRASH":
            crashes.append((f[0], f[1]))

    overall_v = Counter()
    overall_r = Counter()

    print(f"{'sink':<12} {'TP':>4} {'FP':>4} {'?':>4} {'total':>6}   top rule hits")
    print("-" * 100)
    for sub, sink in crashes:
        per_v = Counter()
        per_r = Counter()
        for xss_file in glob.glob(str(LOG_DIR / f"{sub}-crashes/*/fuzzer-master.xss")):
            with open(xss_file, "r", errors="ignore") as f:
                for line in f:
                    if MAGIC.lower() not in line.lower():
                        continue
                    name, verdict = classify(line)
                    per_v[verdict] += 1
                    per_r[name] += 1
        top3 = ", ".join(f"{n}:{c}" for n, c in per_r.most_common(3))
        tp, fp, maybe = per_v.get("TP", 0), per_v.get("FP", 0), per_v.get("MAYBE", 0)
        total = tp + fp + maybe
        print(f"{sub:<12} {tp:>4} {fp:>4} {maybe:>4} {total:>6}   {top3}")
        overall_v.update(per_v)
        overall_r.update(per_r)

    print("-" * 100)
    tp, fp, maybe = overall_v.get("TP", 0), overall_v.get("FP", 0), overall_v.get("MAYBE", 0)
    print(f"{'TOTAL':<12} {tp:>4} {fp:>4} {maybe:>4} {tp+fp+maybe:>6}")
    print("\nAll rule hits across corpus (descending):")
    for name, c in overall_r.most_common():
        print(f"  {name:<30} {c}")


if __name__ == "__main__":
    main()
