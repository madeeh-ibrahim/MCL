#!/bin/bash
# ت-309(b): parameter-window sweeps of the three coupled families, 8 parallel slices per sweep.
set -e; cd "$(dirname "$0")"; mkdir -p window
LOG=window/run_windows_$(date +%Y%m%d_%H%M%S).log; exec > >(tee -a "$LOG") 2>&1
echo "=== START $(date -u +%FT%TZ) host=$(hostname) engine md5=$(md5 -q ../mcl_core.hpp) ==="
run_sweep() { # name family p q K cmin cmax step delta
  local name=$1 fam=$2 p=$3 q=$4 K=$5 cmin=$6 cmax=$7 st=$8 dl=$9
  echo "### $name: $fam ($p,$q) K=$K param in [$cmin,$cmax] step $st, delta=$dl, n=2048 T=10000 W=200 N=100000  $(date -u +%T)"
  for k in 0 1 2 3 4 5 6 7; do ./family_window $fam $p $q $K $cmin $cmax $st $dl 2048 10000 200 100000 window/${name}_slice$k.csv $k 8 2> window/${name}_slice$k.err & done; wait
  head -1 window/${name}_slice0.csv > window/${name}.csv; for k in 0 1 2 3 4 5 6 7; do tail -n +2 window/${name}_slice$k.csv; done | sort -t, -k5,5g >> window/${name}.csv
  echo "    rows: $(($(wc -l < window/${name}.csv)-1))   $(date -u +%T)"; grep -h "ok\]" window/${name}_slice0.err | head -1
}
run_sweep henon_a_K0.01     henon    3 5 -     1.000 1.399 0.001 0.0005
run_sweep logistic_r_K0.05  logistic 3 5 -     3.500 3.999 0.001 0.0005
run_sweep logistic_r_K0.005 logistic 3 5 0.005 3.500 3.999 0.001 0.0005
run_sweep tent_mu_K0.05     tent     3 5 -     1.200 1.999 0.001 0.0005
echo "=== END $(date -u +%FT%TZ) ==="
