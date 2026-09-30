#!/bin/bash
# ت-309(a): decorrelation-time law on the three coupled families (n = 16,384 seeds, T = 400, engine burn-in
# before the split).  Axes: map parameter (a, r, mu), coupling K, adjacent integer weight, zero control.
set -e; cd "$(dirname "$0")"; mkdir -p decorr
LOG=decorr/run_decorr_$(date +%Y%m%d_%H%M%S).log; exec > >(tee -a "$LOG") 2>&1
echo "=== START $(date -u +%FT%TZ) host=$(hostname) engine md5=$(md5 -q ../mcl_core.hpp) ==="; sw_vers | head -2; c++ --version | head -1
DP="1e-12 1e-10 1e-8 1e-6 1e-4 1e-3 1e-2"          # map-parameter axis (applied downward)
DK1="1e-12 1e-10 1e-8 1e-6 1e-4 1e-3 1e-2"         # K axis, 1-D maps (K = 0.05)
DKH="1e-12 1e-10 1e-8 1e-6 1e-4 1e-3"              # K axis, Henon (K = 0.01)
N=16384; T=400
for base in 1.4 1.3 1.28; do
  ./family_decorr henon param 3 5 $base $N $T decorr/res_henon_a${base}_param $DP
  ./family_decorr henon K     3 5 $base $N $T decorr/res_henon_a${base}_K $DKH
done
./family_decorr henon pq   3 5 1.4 $N $T decorr/res_henon_a1.4_pq
./family_decorr henon zero 3 5 1.4 $N $T decorr/res_henon_a1.4_zero
for base in 4.0 3.9 3.7; do
  ./family_decorr logistic param 3 5 $base $N $T decorr/res_logistic_r${base}_param $DP
  ./family_decorr logistic K     3 5 $base $N $T decorr/res_logistic_r${base}_K $DK1
done
./family_decorr logistic pq   3 5 4.0 $N $T decorr/res_logistic_r4.0_pq
./family_decorr logistic zero 3 5 4.0 $N $T decorr/res_logistic_r4.0_zero
for base in 2.0 1.6 1.3; do
  ./family_decorr tent param 3 5 $base $N $T decorr/res_tent_mu${base}_param $DP
  ./family_decorr tent K     3 5 $base $N $T decorr/res_tent_mu${base}_K $DK1
done
./family_decorr tent pq   3 5 2.0 $N $T decorr/res_tent_mu2.0_pq
./family_decorr tent zero 3 5 2.0 $N $T decorr/res_tent_mu2.0_zero
echo "### control: split at the seed state (no burn-in), logistic r=4 param axis"
FAM_BURNIN=0 ./family_decorr logistic param 3 5 4.0 $N $T decorr/res_logistic_r4.0_param_burnin0 $DP
echo "### control: second topology (2,3), logistic r=4 param axis"
./family_decorr logistic param 2 3 4.0 $N $T decorr/res_logistic_r4.0_param_23 $DP
echo "=== END $(date -u +%FT%TZ) ==="
