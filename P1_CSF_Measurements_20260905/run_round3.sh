#!/usr/bin/env bash
cd "$(dirname "$0")"
for s in 55129803364771 89623471905588 31415926535897 27182818284590 98765432109876 17320508075688; do
  ( ./mcl_thirdmap_safezone 0 $s 100000000 > thirdmap_map0_seed${s}_M1Pro_20260905.log 2>&1 ) &
done; wait
for s in 12345678901234 70466644885213 55129803364771 89623471905588; do
  ( ./mcl_thirdmap_safezone 3 $s 100000000 > thirdmap_map3_seed${s}_M1Pro_20260905.log 2>&1 ) &
done
for s in 55129803364771 89623471905588; do
  ( ./mcl_thirdmap_safezone 1 $s 100000000 > thirdmap_map1_seed${s}_M1Pro_20260905.log 2>&1 ) &
  ( ./mcl_thirdmap_safezone 2 $s 100000000 > thirdmap_map2_seed${s}_M1Pro_20260905.log 2>&1 ) &
done; wait
echo ROUND3_DONE > round3_DONE.flag
