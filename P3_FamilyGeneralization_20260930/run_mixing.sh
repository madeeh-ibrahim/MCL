#!/bin/bash
# ت-309(b'): intrinsic mixing diagnostic (single-trajectory autocorrelation tails) on the four sweep grids and
# on the base points of the decorrelation runs.  N = 1e5 samples per cell after the engine burn-in.
set -e; cd "$(dirname "$0")"; mkdir -p mixing
LOG=mixing/run_mixing_$(date +%Y%m%d_%H%M%S).log; exec > >(tee -a "$LOG") 2>&1
echo "=== START $(date -u +%FT%TZ) host=$(hostname) engine md5=$(md5 -q ../mcl_core.hpp) ==="
./family_mixing henon    3 5 -     1.000 1.399 0.001 100000 mixing/henon_a_K0.01_mixing.csv     2> mixing/henon.err &
./family_mixing logistic 3 5 -     3.500 3.999 0.001 100000 mixing/logistic_r_K0.05_mixing.csv  2> mixing/log05.err &
./family_mixing logistic 3 5 0.005 3.500 3.999 0.001 100000 mixing/logistic_r_K0.005_mixing.csv 2> mixing/log005.err &
./family_mixing tent     3 5 -     1.200 1.999 0.001 100000 mixing/tent_mu_K0.05_mixing.csv     2> mixing/tent.err &
wait
./family_mixing henon    3 5 - 1.28 1.40 0.02 100000 mixing/basepoints_henon.csv
./family_mixing logistic 3 5 - 3.7  4.0  0.1  100000 mixing/basepoints_logistic.csv
./family_mixing logistic 2 3 - 4.0  4.0  1    100000 mixing/basepoints_logistic23.csv
./family_mixing tent     3 5 - 1.3  2.0  0.1  100000 mixing/basepoints_tent.csv
echo "=== END $(date -u +%FT%TZ) ==="
