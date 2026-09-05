// mcl_hd_throughput.cpp — Doc ID MCL-HD-THROUGHPUT-V2-2026-0905-001
// Paper 5 item F6 (E5-6): HD derivation throughput, frozen engine v6.0.0.
// Measures derive_child (bare: burn-in + 32 bytes + index mix + map/gcd)
// and derive_child_safe (adds Step-4 resonance validation, 100,000 bytes).
#include "mcl_core.hpp"
#include "mcl_hd_v2.hpp"
#include <cstdio>
#include <chrono>
using Clock = std::chrono::steady_clock;
int main(){
  const uint64_t S = 12345678901234ULL;
  volatile long long sink = 0;
  // warmup
  for (int i = 0; i < 5; i++) { auto d = derive_child_v2(S,3,5,i); sink += d.p; }
  const int NB = 200;
  auto t0 = Clock::now();
  for (int i = 0; i < NB; i++) { auto d = derive_child_v2(S,3,5,i); sink += d.p + d.q; }
  auto t1 = Clock::now();
  double us_bare = std::chrono::duration<double,std::micro>(t1-t0).count()/NB;
  const int NS = 50;
  auto t2 = Clock::now();
  for (int i = 0; i < NS; i++) { auto d = derive_child_safe_v2(S,3,5,i); sink += d.p + d.q; }
  auto t3 = Clock::now();
  double us_safe = std::chrono::duration<double,std::micro>(t3-t2).count()/NS;
  printf("derive_child (bare)         : %8.1f us/derivation  = %7.1f derivations/sec\n", us_bare, 1e6/us_bare);
  printf("derive_child_safe (+Step-4) : %8.1f us/derivation  = %7.1f derivations/sec\n", us_safe, 1e6/us_safe);
  printf("Step-4 validation overhead  : %8.1f us (%0.1f%% of safe path)\n", us_safe-us_bare, 100*(us_safe-us_bare)/us_safe);
  printf("(sink=%lld)\n",(long long)sink);
  return 0;
}
