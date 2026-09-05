#!/bin/bash
# Paper 3 desk-reject measurements (2026-09-05) — full experiment runs.
# Phase order: 5a decorrelation-time law, 5b in-window control, item 10 Jacobi orthogonality,
# 5c pair-distribution (FULL evidence run of the paper's own mcl_orth_verify, 30-60 min, last).
set -e
cd "$(dirname "$0")"
LOG=run_all_$(date +%Y%m%d_%H%M%S).log
exec > >(tee -a "$LOG") 2>&1
echo "=== START $(date -u +%FT%TZ) host=$(hostname) engine md5=$(md5 -q ../mcl_core.hpp) ==="
sw_vers 2>/dev/null | head -2; c++ --version | head -1

echo "### 5a decorrelation time"
cd decorr_time
D="1e-12 1e-10 1e-8 1e-6 1e-4 1e-2 1e-1"
for upd in gs jacobi; do
  for K in 6 12 20; do
    ./decorr_time omega 3 5 $K $upd 16384 80 res_omega_35_K${K}_${upd} $D
    ./decorr_time K     3 5 $K $upd 16384 80 res_K_35_K${K}_${upd} $D
    ./decorr_time pq    3 5 $K $upd 16384 80 res_pq_35_K${K}_${upd}
  done
done
for tp in "2 3" "7 11" "17 23"; do set -- $tp; ./decorr_time omega $1 $2 12 gs 16384 80 res_omega_${1}${2}_K12_gs $D; done
./decorr_time zero 3 5 12 gs 16384 80 res_zero_35_K12_gs
cd ..

echo "### 5b in-window control"
cd window_control
./window_control 2048 10000 100000 0.01 res_window_grid.csv 0.30 1.00 0.02
cd ..

echo "### item 10 Jacobi orthogonality (20 topologies x 20 seeds x 1e7 bytes)"
cd jacobi_orth
./jacobi_orth 20 10000000 jacobi res_jacobi_full
./jacobi_orth 20 10000000 gs     res_gs_full
cd ..

echo "### 5c FULL evidence run of the paper's mcl_orth_verify (3,800 pairs, N=1e7)"
cd pairs_dist
./mcl_orth_verify --full --evidence-file evidence_full_20260905.tsv | tee mcl_orth_verify_full_20260905.txt
python3 pairs_ks.py "../../P3_Fig3_Regeneration_20260903/fig3_matrix_seed12345678901234_20260903.csv" evidence_full_20260905.tsv 10000000
cd ..
echo "=== END $(date -u +%FT%TZ) ==="
