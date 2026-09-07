#!/usr/bin/env bash
# Canonical re-run with -ffp-contract=off (plain IEEE binary64 semantics; identical to CPython). Suffix _nofma.
cd "$(dirname "$0")"
S8="12345678901234 70466644885213 55129803364771 89623471905588 31415926535897 27182818284590 98765432109876 17320508075688"
S4="12345678901234 70466644885213 55129803364771 89623471905588"
# wave 1: logistic r=4 (8) + cycle detection (16)
for s in $S8; do ( ./mcl_thirdmap_safezone_nofma 0 $s 100000000 > nofma_map0_seed${s}.log 2>&1 ) & done
( for s in $S8; do ./mcl_logistic_cycle_nofma 4.0 $s 4000000000; done; for s in $S8; do ./mcl_logistic_cycle_nofma 3.99 $s 4000000000; done ) > nofma_logistic_cycles.log 2>&1 &
wait
# wave 2: std map + Henon + logistic 3.99 (4 seeds each)
for s in $S4; do
  ( ./mcl_thirdmap_safezone_nofma 1 $s 100000000 > nofma_map1_seed${s}.log 2>&1 ) &
  ( ./mcl_thirdmap_safezone_nofma 2 $s 100000000 > nofma_map2_seed${s}.log 2>&1 ) &
  ( ./mcl_thirdmap_safezone_nofma 3 $s 100000000 > nofma_map3_seed${s}.log 2>&1 ) &
done; wait
# wave 3: XOR control (5 cases x 2 seeds) + cycle-free logistic scans (transient-only: N below mu)
for cs in 0 1 2 3 4; do for s in 12345678901234 70466644885213; do
  ( ./mcl_xor_control_nofma $cs $s 100000000 > nofma_xor${cs}_seed${s}.log 2>&1 ) &
done; done
( ./mcl_thirdmap_safezone_nofma 0 70466644885213 87000000 > nofma_map0_cyclefree_seed70466644885213_N8.7e7.log 2>&1 ) &
( ./mcl_thirdmap_safezone_nofma 0 27182818284590 84000000 > nofma_map0_cyclefree_seed27182818284590_N8.4e7.log 2>&1 ) &
wait
echo NOFMA_DONE > nofma_DONE.flag
