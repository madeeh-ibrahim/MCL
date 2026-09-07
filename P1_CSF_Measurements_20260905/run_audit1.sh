#!/usr/bin/env bash
cd "$(dirname "$0")"
# A. positive control: MCL single streams through the third-map tool (compare per-position with holdout log 07-19)
( ./mcl_thirdmap_safezone 4 12345678901234 100000000 > audit_map4_MCL_seed12345678901234.log 2>&1 ) &
# B. FMA-off reruns of the key third-map and XOR runs
( ./mcl_thirdmap_safezone_nofma 1 12345678901234 100000000 > audit_nofma_map1_seed12345678901234.log 2>&1 ) &
( ./mcl_thirdmap_safezone_nofma 2 12345678901234 100000000 > audit_nofma_map2_seed12345678901234.log 2>&1 ) &
( ./mcl_thirdmap_safezone_nofma 0 12345678901234 100000000 > audit_nofma_map0_seed12345678901234.log 2>&1 ) &
( ./mcl_xor_control_nofma 0 12345678901234 100000000 > audit_nofma_xor0_seed12345678901234.log 2>&1 ) &
( ./mcl_xor_control_nofma 1 12345678901234 100000000 > audit_nofma_xor1_seed12345678901234.log 2>&1 ) &
( ./mcl_xor_control_nofma 4 12345678901234 100000000 > audit_nofma_xor4_seed12345678901234.log 2>&1 ) &
wait
# C. logistic r=4 with simple decimal x0 (the kind of initialisation the original campaign may have used)
for x in 0.1 0.2 0.3 0.4 0.6 0.7 0.8 0.9 0.123456789 0.314159265; do
  ( ./mcl_thirdmap_safezone 0 0 100000000 $x > audit_logistic_x0_${x}.log 2>&1 ) &
done; wait
echo AUDIT1_DONE > audit1_DONE.flag
