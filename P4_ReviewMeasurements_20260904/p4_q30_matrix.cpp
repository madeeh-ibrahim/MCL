// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Review measurement: direct phase-locking diagnostics on the Fig. 1 grid (K in [0.30,1.00] step 0.02).
// P4 review measurement 2026-09-04: Q30 two-oscillator integer engine determinism fingerprint.
// One binary = one (arch, opt, sanitizer) cell. Prints a single FINGERPRINT line; all cells must agree.
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <vector>
static uint32_t crc32u(uint32_t c,const uint8_t* d,size_t n){for(size_t i=0;i<n;i++){c^=d[i];for(int k=0;k<8;k++)c=(c>>1)^(0xEDB88320u&(0u-(c&1u)));}return c;}
int main(){
  const uint64_t seeds[10]={1ULL,2ULL,12345678901234ULL,31415926535897ULL,0xDEADBEEFULL,(1ULL<<32),(1ULL<<32)+1,(1ULL<<52)+1,(1ULL<<63),~0ULL};
  const double Ks[8]={1,2,4,6,8,10,11,12};
  uint32_t mc=0xFFFFFFFFu; int cells=0;
  for(uint64_t s: seeds) for(double K: Ks){ uint32_t t1,t2; mcl_q30_init_state(s,t1,t2); int64_t kp=mcl_q30_K_phase(K);
    uint32_t a=t1,b=t2; for(int i=0;i<100000;i++) mcl_q30_iterate_raw(a,b,3,5,kp);
    uint32_t w[4]={t1,t2,a,b}; mc=crc32u(mc,(const uint8_t*)w,16); cells++; }
  // 10 consecutive reproducibility runs, default seed/K, 1e5 iterations
  uint32_t r1=0,r2=0; int repro=0; for(int k=0;k<10;k++){ uint32_t t1,t2; mcl_q30_init_state(12345678901234ULL,t1,t2); int64_t kp=mcl_q30_K_phase(12.0); for(int i=0;i<100000;i++) mcl_q30_iterate_raw(t1,t2,3,5,kp); if(k==0){r1=t1;r2=t2;} repro += (t1==r1&&t2==r2); }
  // 1e7 stability run
  uint32_t s1,s2; mcl_q30_init_state(12345678901234ULL,s1,s2); { int64_t kp=mcl_q30_K_phase(12.0); for(int i=0;i<10000000;i++) mcl_q30_iterate_raw(s1,s2,3,5,kp); }
  // 1 MB raw state-word bytes (t1,t2 little-endian, 8 bytes/iteration), default seed/K, after 1e4 warm-up
  std::vector<uint32_t> hist(256,0); { uint32_t t1,t2; mcl_q30_init_state(12345678901234ULL,t1,t2); int64_t kp=mcl_q30_K_phase(12.0); for(int i=0;i<10000;i++) mcl_q30_iterate_raw(t1,t2,3,5,kp);
    for(int i=0;i<125000;i++){ mcl_q30_iterate_raw(t1,t2,3,5,kp); uint32_t w[2]={t1,t2}; const uint8_t* bp=(const uint8_t*)w; for(int j=0;j<8;j++) hist[bp[j]]++; } }
  double H=0,chi=0; const double n=1000000.0, e=n/256; for(int i=0;i<256;i++){ if(hist[i]){ double pr=hist[i]/n; H-=pr*std::log2(pr);} chi+=(hist[i]-e)*(hist[i]-e)/e; }
  const MCL_Q30_Table& tab=mcl_q30_table(); uint32_t lut=~crc32u(0xFFFFFFFFu,(const uint8_t*)tab.lut,65536*sizeof(int32_t));
  std::printf("FINGERPRINT matrix-crc=0x%08X cells=%d repro=%d/10 stab1e7=0x%08x,0x%08x lut=0x%08x rawbytes1MB entropy=%.6f chi2=%.2f\n", ~mc, cells, repro, s1, s2, lut, H, chi);
  return 0;
}
