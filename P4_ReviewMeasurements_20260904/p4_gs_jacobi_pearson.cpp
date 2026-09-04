// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Review measurement: direct phase-locking diagnostics on the Fig. 1 grid (K in [0.30,1.00] step 0.02).
// P4 review measurement 2026-09-04: GS-vs-Jacobi Pearson r + Hamming over 10^6 extracted bytes.
// Engine: root mcl_core.hpp v8.1.3 (read-only). Extraction replica is self-checked against
// MCL_T2::gen_byte() byte-for-byte before it is applied to the Jacobi map.
#include "mcl_core.hpp"
#include <cstdio>
#include <vector>
#include <cmath>
static uint8_t extract(double t1, double t2){ uint64_t x = d2b(t1) ^ d2b(t2); return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2); }
int main(){
  const int64_t N = 1000000; const uint64_t seed = 12345678901234ULL; const int64_t p=3,q=5; const double K=K_DEFAULT;
  MCL_T2 g(seed,p,q);                       // constructor performs the B=10,000 burn-in
  double a=g.theta1(), b=g.theta2();        // common post-burn-in start for both maps
  double ja=a, jb=b;
  std::vector<uint8_t> gs(N), rep(N), jac(N);
  for(int64_t i=0;i<N;i++){
    gs[i]=g.gen_byte();
    for(int d=0;d<DECIMATION;d++) mcl_iterate_raw(a,b,p,q,K);      rep[i]=extract(a,b);
    for(int d=0;d<DECIMATION;d++) mcl_iterate_jacobi(ja,jb,p,q,K); jac[i]=extract(ja,jb);
  }
  int64_t mism=0; for(int64_t i=0;i<N;i++) mism += (gs[i]!=rep[i]);
  std::printf("engine %d.%d.%d  seed=%llu (p,q)=(%lld,%lld) K=%.1f  N=%lld bytes (post-burn-in, D=%d)\n",
    MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH,(unsigned long long)seed,(long long)p,(long long)q,K,(long long)N,DECIMATION);
  std::printf("[self-check] replica extractor vs MCL_T2::gen_byte: %lld/%lld identical (%s)\n",(long long)(N-mism),(long long)N, mism?"FAIL":"PASS");
  double sx=0,sy=0,sxx=0,syy=0,sxy=0; int64_t ham=0;
  for(int64_t i=0;i<N;i++){ double x=gs[i], y=jac[i]; sx+=x; sy+=y; sxx+=x*x; syy+=y*y; sxy+=x*y; ham+=__builtin_popcount((unsigned)(gs[i]^jac[i])); }
  double mx=sx/N,my=sy/N; double r=(sxy/N-mx*my)/std::sqrt((sxx/N-mx*mx)*(syy/N-my*my));
  std::printf("[GS vs Jacobi, extracted bytes] Pearson r = %+.6f  |r| = %.6f  (noise floor 1/sqrt(N) = %.6f)\n", r, std::fabs(r), 1.0/std::sqrt((double)N));
  std::printf("[GS vs Jacobi, extracted bytes] bit Hamming distance = %.4f%%  (%lld / %lld bits; 50%% = independent)\n", 100.0*ham/(8.0*N),(long long)ham,(long long)(8*N));
  // mean linear separation of theta1 over the first 10^4 iterations from the common start
  MCL_T2 h(seed,p,q); double ga=h.theta1(), gb=h.theta2(), xa=ga, xb=gb; double acc=0; const int M=10000;
  for(int i=0;i<M;i++){ mcl_iterate_raw(ga,gb,p,q,K); mcl_iterate_jacobi(xa,xb,p,q,K); acc += std::fabs(ga-xa); }
  std::printf("[GS vs Jacobi] mean linear |theta1_GS - theta1_J| over %d iterations = %.4f rad  (2*pi/3 = %.4f)\n", M, acc/M, 2*M_PI/3);
  return mism?1:0;
}
