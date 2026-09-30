#!/bin/bash
# Paper 3, ت-309 (2026-09-30): full reproduction.  Build the three tools, run the parameter-window sweeps
# (run_windows.sh, ~12 min on 8 cores), the decorrelation-time runs (run_decorr.sh, ~10 min), the mixing
# diagnostic (run_mixing.sh, ~2 min), then the analysis (analyze_family.py -> window/, decorr/, paper3_fig6.png).
set -e; cd "$(dirname "$0")"
echo "=== BUILD $(date -u +%FT%TZ) engine md5=$(md5 -q ../mcl_core.hpp) ==="; c++ --version | head -1
for t in family_decorr family_window family_mixing; do c++ -O3 -std=c++17 -DMCL_UNSAFE_ALLOW_INVALID -o $t $t.cpp; done
./run_windows.sh
./run_decorr.sh
./run_mixing.sh
python3 analyze_family.py | tee analysis_run.txt
