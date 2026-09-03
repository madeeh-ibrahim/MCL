// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// K-window sweep over [6,20] at step 0.005 — review measurement for Paper 3 §III.A claim
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdlib>
int main(int argc,char**argv){
  int p=atoi(argv[1]), q=atoi(argv[2]); double lo=atof(argv[3]), hi=atof(argv[4]), step=atof(argv[5]); int iters=atoi(argv[6]);
  int n=0, win=0; double minl1=1e9, minK=-1;
  printf("# (%d,%d) K in [%.3f,%.3f] step %.3f, %d QR iters, seed 12345678901234, engine mcl_core.hpp (public v0.2.1)\n",p,q,lo,hi,step,iters);
  for(long i=0;;++i){ double K=lo+i*step; if(K>hi+1e-9) break;
    LyapResult r=compute_lyapunov(12345678901234ULL,p,q,K,iters); ++n;
    if(r.l1<minl1){minl1=r.l1;minK=K;}
    if(r.l1<=0.02){ printf("WINDOW K=%.3f l1=%+.4f l2=%+.4f\n",K,r.l1,r.l2); ++win; }
  }
  printf("# points=%d windows(l1<=0.02)=%d min_l1=%.4f at K=%.3f\n",n,win,minl1,minK);
  return 0;
}
