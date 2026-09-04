#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# MCL Reference Implementation. Free security research / evaluation for all
# (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
# a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
# Review measurement: direct phase-locking diagnostics on the Fig. 1 grid (K in [0.30,1.00] step 0.02).
# Linux/glibc/GCC cells of the Q30 determinism matrix: {-O0..-O3} x {none, undefined, address}.
set -u; cd "$(dirname "$0")"; : > q30_matrix_cells_linux.log
for opt in O0 O1 O2 O3; do for san in none undefined address; do
  f="q30l_${opt}_${san}"; sf=""; [ "$san" != none ] && sf="-fsanitize=$san"
  if g++ -std=c++17 -$opt $sf -DNDEBUG -o "$f" p4_q30_matrix.cpp 2>/dev/null; then
    out=$(./"$f" 2>/dev/null) && echo "x86_64-linux-gnu gcc $opt $san $out" >> q30_matrix_cells_linux.log || echo "x86_64-linux-gnu gcc $opt $san RUN-FAILED" >> q30_matrix_cells_linux.log
  else echo "x86_64-linux-gnu gcc $opt $san BUILD-FAILED" >> q30_matrix_cells_linux.log; fi
  rm -f "$f"
done; done
echo "linux cells: $(wc -l < q30_matrix_cells_linux.log)  distinct: $(grep -o 'FINGERPRINT.*' q30_matrix_cells_linux.log | sort -u | wc -l)  failures: $(grep -c FAILED q30_matrix_cells_linux.log)"
