// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// P4 review measurement 2026-09-04 (external-review item 1/9): a complete x -> y known-answer
// vector for VDF128-T4 with every intermediate, plus per-iteration avalanche on the T4 map.
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include "mcl_vdf128_t4.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
static uint32_t crc32(const uint8_t* d, size_t n){uint32_t c=0xFFFFFFFFu;for(size_t i=0;i<n;i++){c^=d[i];for(int k=0;k<8;k++)c=(c>>1)^(0xEDB88320u&(0u-(c&1u)));}return ~c;}
static void hex(const char* l,const uint8_t* b,int n){std::printf("  %-22s",l);for(int i=0;i<n;i++){std::printf("%02x",b[i]); if(i%8==7&&i<n-1)std::printf(" ");}std::printf("\n");}
static void st(const char* l,const VDF128_State& s){std::printf("  %-22s%08x %08x %08x %08x\n",l,s.t1,s.t2,s.t3,s.t4);}
static int ham(const VDF128_State& a,const VDF128_State& b){return __builtin_popcount(a.t1^b.t1)+__builtin_popcount(a.t2^b.t2)+__builtin_popcount(a.t3^b.t3)+__builtin_popcount(a.t4^b.t4);}
int main(){
  const char* xs="MCL-VDF128-KAT-1"; const uint8_t* x=(const uint8_t*)xs; size_t xl=std::strlen(xs); const uint64_t B=10000, N=1000;
  std::printf("VDF128-T4 KNOWN-ANSWER VECTOR (engine %d.%d.%d; B=%llu, N=%llu, K=%.1f)\n",MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH,(unsigned long long)B,(unsigned long long)N,K_DEFAULT);
  std::printf("  x (ASCII)             \"%s\"  (%zu bytes)\n",xs,xl);
  uint8_t hx[32]; mcl_sha256(x,xl,hx); hex("SHA-256(x)",hx,32);
  uint8_t kpub[32]; const char* ptag="MCL-VDF128-T4-v1 public parameters"; mcl_sha256((const uint8_t*)ptag,std::strlen(ptag),kpub); hex("K_pub = SHA-256(tag)",kpub,32);
  MCL_Q30_Sextet W=mcl_vdf128_public_weights();
  std::printf("  weights (p12 q12 p13 q13 p14 q14 p23 q23 p24 q24 p34 q34)\n    %u %u %u %u %u %u %u %u %u %u %u %u\n",W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34);
  std::printf("  omega (Q.32)          %08x %08x %08x %08x   K_phase 0x%llx\n",mcl_q30_omega1(),mcl_q30_omega2(),mcl_q30_omega3(),mcl_q30_omega4(),(unsigned long long)mcl_q30_K_phase(K_DEFAULT));
  const MCL_Q30_Table& tab=mcl_q30_table(); std::printf("  LUT CRC-32            0x%08x  (65,536 x int32, lut[i] = (int32)(sin(2*pi*i/65536) * 2^30))\n",crc32((const uint8_t*)tab.lut,65536*4));
  VDF128_State s=mcl_vdf128_init(x,xl); st("init state t1..t4",s);
  const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
  for(uint64_t i=0;i<B;i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp); st("after burn-in (C_0)",s);
  for(int seg=1;seg<=4;seg++){ for(uint64_t i=0;i<N/4;i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp); char l[32]; std::snprintf(l,32,"C_%d (t=%llu)",seg,(unsigned long long)(seg*N/4)); st(l,s); }
  uint8_t buf[80]; auto put32=[&](int o,uint32_t v){buf[o]=(uint8_t)v;buf[o+1]=(uint8_t)(v>>8);buf[o+2]=(uint8_t)(v>>16);buf[o+3]=(uint8_t)(v>>24);};
  put32(0,s.t1);put32(4,s.t2);put32(8,s.t3);put32(12,s.t4); std::memcpy(buf+16,hx,32); for(int i=0;i<8;i++) buf[48+i]=(uint8_t)(N>>(i*8)); static const char* otag="MCL-VDF128-T4-v1-out\0\0\0"; std::memcpy(buf+56,otag,24);
  hex("SHA-256 preimage (80 B)",buf,80);
  uint8_t y[32]; mcl_sha256(buf,80,y); hex("y = SHA-256(preimage)",y,32);
  uint8_t y2[32]; mcl_vdf128_eval(x,xl,N,y2,B); std::printf("  API mcl_vdf128_eval:  %s\n", std::memcmp(y,y2,32)==0?"IDENTICAL":"DIFFER");
  // avalanche on the T4 map: 1-bit state flip at C_0, Hamming after k iterations, averaged over all 128 bit positions
  std::printf("\nAVALANCHE (T4 map, 1-bit state flip at C_0, mean Hamming over 128 positions; 64 = full diffusion)\n");
  VDF128_State c0=mcl_vdf128_init(x,xl); for(uint64_t i=0;i<B;i++) mcl_q30t4_iterate_raw(c0.t1,c0.t2,c0.t3,c0.t4,W,kp);
  for(int k=1;k<=4;k++){ double acc=0; for(int b=0;b<128;b++){ VDF128_State a=c0,d=c0; uint32_t* w=(&d.t1)+(b/32); *w ^= (1u<<(b%32)); for(int i=0;i<k;i++){ mcl_q30t4_iterate_raw(a.t1,a.t2,a.t3,a.t4,W,kp); mcl_q30t4_iterate_raw(d.t1,d.t2,d.t3,d.t4,W,kp);} acc+=ham(a,d);} std::printf("  k=%d iterations: mean Hamming = %.2f / 128\n",k,acc/128); }
  // input avalanche through SHA-256 init and through the whole evaluation
  const char* xs2="MCL-VDF128-KAT-0"; VDF128_State i1=mcl_vdf128_init(x,xl), i2=mcl_vdf128_init((const uint8_t*)xs2,xl); std::printf("  input x vs x' (last char 1->0): init-state Hamming %d/128; ", ham(i1,i2)); uint8_t yb[32]; mcl_vdf128_eval((const uint8_t*)xs2,xl,N,yb,B); int hb=0; for(int i=0;i<32;i++) hb+=__builtin_popcount(y[i]^yb[i]); std::printf("output Hamming %d/256\n",hb);
  return 0;
}
