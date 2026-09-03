// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Paper 3 Fig. 3 regeneration: 20 canonical coprime channels (mcl_orth_verify RATIOS[]),
// one representative seed (mcl_orth_verify SEEDS[0]), N = 1e7 bytes/channel, K = 12.
// Output: CSV of the 20x20 Pearson matrix on byte values (engine gen_bytes, unmodified header).
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>
#include <cstring>
#include <cassert>
#include <algorithm>
#include <functional>
#include <array>
#include "mcl_core.hpp"
int main(){
  const int NR=20; const int64_t N=10000000; const uint64_t seed=12345678901234ULL; const double K=12.0;
  const int R[NR][2]={{2,3},{3,5},{5,7},{7,11},{8,13},{11,17},{13,19},{17,23},{19,29},{23,31},{29,37},{31,41},{37,43},{41,47},{43,53},{47,59},{53,61},{59,67},{61,71},{67,73}};
  std::vector<std::vector<uint8_t>> ch(NR, std::vector<uint8_t>(N));
  std::vector<double> mean(NR), sd(NR);
  for(int i=0;i<NR;i++){ MCL_T2 e(seed,R[i][0],R[i][1],K); e.gen_bytes(ch[i].data(),N);
    double s=0,s2=0; for(int64_t t=0;t<N;t++){ s+=ch[i][t]; s2+=(double)ch[i][t]*ch[i][t]; }
    mean[i]=s/N; sd[i]=std::sqrt(s2/N-mean[i]*mean[i]); }
  printf("# Paper 3 Fig. 3 data — seed %llu, K=%.1f, N=%lld bytes/channel, Pearson r on byte values\n",(unsigned long long)seed,K,(long long)N);
  printf("i,j,(pi,qi),(pj,qj),r\n");
  for(int i=0;i<NR;i++) for(int j=i+1;j<NR;j++){
    double acc=0; for(int64_t t=0;t<N;t++) acc+=((double)ch[i][t]-mean[i])*((double)ch[j][t]-mean[j]);
    double r=acc/(N*sd[i]*sd[j]);
    printf("%d,%d,(%d;%d),(%d;%d),%.9f\n",i,j,R[i][0],R[i][1],R[j][0],R[j][1],r); }
  return 0;
}
