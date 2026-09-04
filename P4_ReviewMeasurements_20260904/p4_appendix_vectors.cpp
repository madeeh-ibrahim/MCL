// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Review measurement: direct phase-locking diagnostics on the Fig. 1 grid (K in [0.30,1.00] step 0.02).
// P4 review measurement 2026-09-04: Appendix Vectors 1-3 (this platform), with theta bit patterns and CRCs.
#include "mcl_core.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
static uint32_t crc32(const uint8_t* d, size_t n){uint32_t c=0xFFFFFFFFu;for(size_t i=0;i<n;i++){c^=d[i];for(int k=0;k<8;k++)c=(c>>1)^(0xEDB88320u&(0u-(c&1u)));}return ~c;}
static void hexd(const char* lbl,double d){ uint64_t u; std::memcpy(&u,&d,8); std::printf("  %s 0x%016llx (= %.15f)\n",lbl,(unsigned long long)u,d); }
static void hexb(const char* lbl,const uint8_t* b,int n){ std::printf("  %s",lbl); for(int i=0;i<n;i++){ std::printf("%02x",b[i]); if(i%8==7&&i<n-1) std::printf(" "); } std::printf("\n"); }
int main(){
  #if defined(__APPLE__)
  const char* plat = "macOS Apple-Silicon / Apple-libm (std::sin)";
#elif defined(__linux__)
  const char* plat = "Linux / glibc libm (std::sin) -- see gcc/ldd/uname header lines";
#else
  const char* plat = "unknown platform";
#endif
  std::printf("engine %d.%d.%d  platform: %s\n",MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH,plat);
  for (uint64_t seed : {12345678901234ULL, 31415926535897ULL}) {
    MCL_T2 g(seed,3,5); std::printf("Vector seed=%llu (3,5) K=12 B=10000 D=2\n",(unsigned long long)seed);
    hexd("theta1 post-burn-in:", g.theta1()); hexd("theta2 post-burn-in:", g.theta2());
    std::vector<uint8_t> b(10000); g.gen_bytes(b.data(),10000);
    hexb("first 32 bytes: ", b.data(), 32); std::printf("  CRC-32 (10,000-byte stream): 0x%08X\n", crc32(b.data(),10000));
  }
  { MCL_T2 g(12345678901234ULL,3,5); for(int i=0;i<10000;i++) g.iterate();
    std::printf("Vector 3: seed=12345678901234, N=10000 iterate() after burn-in, then gen_bytes(32)\n");
    hexd("theta1_final:", g.theta1()); hexd("theta2_final:", g.theta2());
    uint8_t out[32]; g.gen_bytes(out,32); hexb("32-byte VDF output: ", out, 32);
    VDFResult r = vdf_compute(12345678901234ULL,3,5,10000); hexb("vdf_compute() API:  ", r.output, 32);
    std::printf("  API vs procedure: %s\n", std::memcmp(out,r.output,32)==0?"IDENTICAL":"DIFFER"); }
  return 0;
}
