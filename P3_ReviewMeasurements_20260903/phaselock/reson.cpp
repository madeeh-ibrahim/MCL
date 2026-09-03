// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Review measurement: direct phase-locking diagnostics on the Fig. 1 grid (K in [0.30,1.00] step 0.02).
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cassert>
#include <vector>
#include <string>
#include <complex>
#include <algorithm>
#include <functional>
#include <array>

#include "mcl_core.hpp"

static double wrap(double x){ double w=std::fmod(x+M_PI,2*M_PI); if(w<0) w+=2*M_PI; return w-M_PI; }
int main(){
  const uint64_t seed=12345678901234ULL; const long T=100000; const long NB=500000;
  int tops[4][2]={{2,3},{3,5},{5,7},{7,11}};
  printf("p,q,K,lambda1,W_unwrapped,R_alpha,R_theta1,R_theta2,period,chi2_bytes\n");
  for(auto&tp:tops){ int p=tp[0],q=tp[1];
    for(int k=0;k<36;k++){ double K=0.30+0.02*k;
      MCL_T2 e(seed,p,q,K);
      double d1=0,d2=0; std::complex<double> za(0,0),z1(0,0),z2(0,0);
      for(long t=0;t<T;t++){ double a=e.t1_,b=e.t2_; e.iterate(); double n1=e.t1_,n2=e.t2_;
        d1+=wrap(n1-a); d2+=wrap(n2-b);
        za+=std::polar(1.0,p*b-q*a); z1+=std::polar(1.0,a); z2+=std::polar(1.0,b); }
      double W=d2/d1, Ra=std::abs(za)/T, R1=std::abs(z1)/T, R2=std::abs(z2)/T;
      // exact-period detection (<=256) from the current state
      double s1=e.t1_, s2=e.t2_; int period=0;
      for(int m=1;m<=256;m++){ e.iterate(); double dd=std::hypot(wrap(e.t1_-s1),wrap(e.t2_-s2)); if(dd<1e-9){ period=m; break; } }
      LyapResult L=compute_lyapunov(seed,p,q,K,100000);
      MCL_T2 g(seed,p,q,K); std::vector<uint8_t> buf(NB); g.gen_bytes(buf.data(),NB);
      double cnt[256]={0}; for(uint8_t c:buf) cnt[c]++; double ex=NB/256.0, chi=0; for(int i=0;i<256;i++) chi+=(cnt[i]-ex)*(cnt[i]-ex)/ex;
      printf("%d,%d,%.2f,%.4f,%.6f,%.4f,%.4f,%.4f,%d,%.1f\n",p,q,K,L.l1,W,Ra,R1,R2,period,chi);
    }
  }
  return 0;
}
