#!/usr/bin/env bash
# 6 runs, N = 1e8 each, all in parallel. Platform: MacBook Pro 18,3 (Apple M1 Pro), macOS 14.5, Apple clang 16.
cd "$(dirname "$0")"
for m in 0 1 2; do for s in 12345678901234 70466644885213; do
  ( ./mcl_thirdmap_safezone $m $s 100000000 > thirdmap_map${m}_seed${s}_M1Pro_20260905.log 2>&1 ) &
done; done
wait
echo ALL_DONE > thirdmap_ALL_DONE.flag
