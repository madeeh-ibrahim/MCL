#!/usr/bin/env bash
cd "$(dirname "$0")"
for cs in 0 1 2 3 4; do for s in 12345678901234 70466644885213; do
  ( ./mcl_xor_control $cs $s 100000000 > xorctl_case${cs}_seed${s}_M1Pro_20260905.log 2>&1 ) &
done; done; wait; echo XOR_DONE > xor_DONE.flag
