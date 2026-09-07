#!/usr/bin/env bash
cd "$(dirname "$0")"
SEEDS="12345678901234 70466644885213 55129803364771 89623471905588 31415926535897 27182818284590 98765432109876 17320508075688"
for s in $SEEDS; do ( ./mcl_logistic_cycle 4.0 $s 4000000000 ) & done; wait
for s in $SEEDS; do ( ./mcl_logistic_cycle 3.99 $s 4000000000 ) & done; wait
