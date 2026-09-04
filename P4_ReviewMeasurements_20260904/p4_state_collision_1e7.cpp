// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Review measurement: direct phase-locking diagnostics on the Fig. 1 grid (K in [0.30,1.00] step 0.02).
// P4 review measurement 2026-09-04: direct state-collision search, 10^7 post-burn-in iterations,
// full 128-bit state (bits of theta1, theta2). Sort-based exact duplicate count.
#include "mcl_core.hpp"
#include <cstdio>
#include <vector>
#include <algorithm>
int main(){
  const int64_t N = 10000000; MCL_T2 g(12345678901234ULL,3,5);
  std::vector<std::pair<uint64_t,uint64_t>> v; v.reserve(N);
  for(int64_t i=0;i<N;i++){ g.iterate(); v.emplace_back(d2b(g.theta1()), d2b(g.theta2())); }
  std::sort(v.begin(), v.end());
  int64_t dup=0; for(int64_t i=1;i<N;i++) dup += (v[i]==v[i-1]);
  int64_t dup1=0; { std::vector<uint64_t> w; w.reserve(N); for(auto& e: v) w.push_back(e.first); std::sort(w.begin(),w.end()); for(int64_t i=1;i<N;i++) dup1 += (w[i]==w[i-1]); }
  std::printf("engine %d.%d.%d  seed=12345678901234 (3,5) K=12  post-burn-in iterations=%lld\n",MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH,(long long)N);
  std::printf("[128-bit state (theta1,theta2) repeats] %lld   [theta1-only 64-bit repeats] %lld\n",(long long)dup,(long long)dup1);
  std::printf("%s\n", dup==0 ? "RESULT: zero state repetitions in 10^7 iterations (cycle-free at this scale)" : "RESULT: REPETITION FOUND");
  return 0;
}
