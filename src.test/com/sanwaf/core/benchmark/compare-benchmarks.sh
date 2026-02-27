#!/bin/bash
set -e

if [ $# -lt 2 ]; then
  echo "Usage: bash compare-benchmarks.sh <baseline.json> <current.json>"
  exit 1
fi

BASELINE="$1"
CURRENT="$2"

if [ ! -f "$BASELINE" ]; then echo "File not found: $BASELINE"; exit 1; fi
if [ ! -f "$CURRENT" ]; then echo "File not found: $CURRENT"; exit 1; fi

python3 - "$BASELINE" "$CURRENT" <<'PYEOF'
import json, sys

THRESHOLD = 5.0  # percent — highlight regressions/improvements beyond this

RED   = "\033[31m"
GREEN = "\033[32m"
RESET = "\033[0m"

def load(path):
    with open(path) as f:
        return json.load(f)

def short_name(bench):
    # "com.sanwaf.core.benchmark.SanwafJmhBenchmark.stringClean" -> "stringClean"
    return bench.rsplit(".", 1)[-1]

def build_index(data):
    """Index by (short_name, mode) and also collect secondary metrics."""
    idx = {}
    for entry in data:
        name = short_name(entry["benchmark"])
        mode = entry["mode"]
        score = entry["primaryMetric"]["score"]
        unit = entry["primaryMetric"]["scoreUnit"]
        idx[(name, mode)] = (score, unit)
        # secondary metrics (gc profiler, etc.)
        for sname, smetric in entry.get("secondaryMetrics", {}).items():
            key = (f"{name}:{sname}", mode)
            idx[key] = (smetric["score"], smetric["scoreUnit"])
    return idx

def fmt_num(n):
    if abs(n) >= 1000:
        return f"{n:,.1f}"
    if abs(n) >= 1:
        return f"{n:.2f}"
    if n == 0:
        return "0.000"
    return f"{n:.3f}"

def main():
    base_data = load(sys.argv[1])
    curr_data = load(sys.argv[2])
    base_idx = build_index(base_data)
    curr_idx = build_index(curr_data)

    all_keys = sorted(set(base_idx) | set(curr_idx))
    if not all_keys:
        print("No benchmarks found.")
        return

    # Column widths
    W_NAME = max(len(k[0]) for k in all_keys)
    W_MODE = max(len(k[1]) for k in all_keys)
    W_NUM  = 14

    header = (f"{'Benchmark':<{W_NAME}}  {'Mode':<{W_MODE}}  "
              f"{'Baseline':>{W_NUM}}  {'Current':>{W_NUM}}  "
              f"{'Delta':>{W_NUM}}  {'Delta%':>8}")
    print(header)
    print("-" * len(header))

    for key in all_keys:
        name, mode = key
        b_score, _ = base_idx.get(key, (None, None))
        c_score, _ = curr_idx.get(key, (None, None))

        if b_score is None or c_score is None:
            b_str = fmt_num(b_score) if b_score is not None else "N/A"
            c_str = fmt_num(c_score) if c_score is not None else "N/A"
            print(f"{name:<{W_NAME}}  {mode:<{W_MODE}}  "
                  f"{b_str:>{W_NUM}}  {c_str:>{W_NUM}}  "
                  f"{'N/A':>{W_NUM}}  {'N/A':>8}")
            continue

        delta = c_score - b_score
        if b_score != 0:
            pct = (delta / abs(b_score)) * 100
        else:
            pct = 0.0 if c_score == 0 else float('inf')

        delta_str = f"{'+' if delta >= 0 else ''}{fmt_num(delta)}"
        pct_str   = f"{'+' if pct >= 0 else ''}{pct:.1f}%"

        # For throughput (thrpt), higher is better; for avg/sample, lower is better
        higher_is_better = mode in ("thrpt",)
        improved = (delta > 0) if higher_is_better else (delta < 0)

        color = ""
        if abs(pct) > THRESHOLD:
            color = GREEN if improved else RED

        line = (f"{name:<{W_NAME}}  {mode:<{W_MODE}}  "
                f"{fmt_num(b_score):>{W_NUM}}  {fmt_num(c_score):>{W_NUM}}  "
                f"{delta_str:>{W_NUM}}  {pct_str:>8}")

        if color:
            print(f"{color}{line}{RESET}")
        else:
            print(line)

main()
PYEOF
