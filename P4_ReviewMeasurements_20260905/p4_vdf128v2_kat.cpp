// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// P4 R4 (2026-09-05): complete x -> y known-answer vector for VDF128-T4 v2 (per-input weights)
// with every intermediate, plus avalanche profile (1..8 iterations) and input-flip statistics.
#include "mcl_vdf128_t4_v2.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
static uint32_t crc32(const uint8_t* d, size_t n){uint32_t c=0xFFFFFFFFu;for(size_t i=0;i<n;i++){c^=d[i];for(int k=0;k<8;k++)c=(c>>1)^(0xEDB88320u&(0u-(c&1u)));}return ~c;}
static void hex(const char* l,const uint8_t* b,int n){std::printf("  %-22s",l);for(int i=0;i<n;i++){std::printf("%02x",b[i]); if(i%8==7&&i<n-1)std::printf(" ");}std::printf("\n");}
static void st(const char* l,const VDF128_State& s){std::printf("  %-22s%08x %08x %08x %08x\n",l,s.t1,s.t2,s.t3,s.t4);}
static int ham(const VDF128_State& a,const VDF128_State& b){return __builtin_popcount(a.t1^b.t1)+__builtin_popcount(a.t2^b.t2)+__builtin_popcount(a.t3^b.t3)+__builtin_popcount(a.t4^b.t4);}
static int ham256(const uint8_t* a,const uint8_t* b){int h=0;for(int i=0;i<32;i++)h+=__builtin_popcount((unsigned)(a[i]^b[i]));return h;}
static uint64_t sm(uint64_t& z){z+=0x9E3779B97F4A7C15ull;uint64_t r=z;r=(r^(r>>30))*0xBF58476D1CE4E5B9ull;r=(r^(r>>27))*0x94D049BB133111EBull;return r^(r>>31);}
int main(){
  const char* xs="MCL-VDF128-KAT-1"; const uint8_t* x=(const uint8_t*)xs; size_t xl=std::strlen(xs); const uint64_t B=10000, N=1000;
  std::printf("VDF128-T4 v2 KNOWN-ANSWER VECTOR (engine %d.%d.%d; per-input weights; B=%llu, N=%llu, K=%.1f)\n",MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH,(unsigned long long)B,(unsigned long long)N,K_DEFAULT);
  std::printf("  x (ASCII)             \"%s\"  (%zu bytes)\n",xs,xl);
  uint8_t hx[32]; mcl_sha256(x,xl,hx); hex("h = SHA-256(x)",hx,32);
  MCL_Q30_Sextet W=mcl_vdf128v2_weights(x,xl);
  std::printf("  weights = params_from_key(h, 0)  (p12 q12 p13 q13 p14 q14 p23 q23 p24 q24 p34 q34)\n    %u %u %u %u %u %u %u %u %u %u %u %u\n",W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34);
  std::printf("  omega (Q.32)          %08x %08x %08x %08x   K_phase 0x%llx\n",mcl_q30_omega1(),mcl_q30_omega2(),mcl_q30_omega3(),mcl_q30_omega4(),(unsigned long long)mcl_q30_K_phase(K_DEFAULT));
  const MCL_Q30_Table& tab=mcl_q30_table(); std::printf("  LUT CRC-32            0x%08x\n",crc32((const uint8_t*)tab.lut,65536*4));
  VDF128_State s=mcl_vdf128_init(x,xl); st("init state t1..t4",s);
  const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
  for(uint64_t i=0;i<B;i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp); st("after burn-in (C_0)",s);
  for(int seg=1;seg<=4;seg++){ for(uint64_t i=0;i<N/4;i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp); char l[32]; std::snprintf(l,32,"C_%d (t=%llu)",seg,(unsigned long long)(seg*N/4)); st(l,s); }
  uint8_t buf[80]; auto put32=[&](int o,uint32_t v){buf[o]=(uint8_t)v;buf[o+1]=(uint8_t)(v>>8);buf[o+2]=(uint8_t)(v>>16);buf[o+3]=(uint8_t)(v>>24);};
  put32(0,s.t1);put32(4,s.t2);put32(8,s.t3);put32(12,s.t4); std::memcpy(buf+16,hx,32); for(int i=0;i<8;i++) buf[48+i]=(uint8_t)(N>>(i*8)); static const char otag[24]="MCL-VDF128-T4-v2-out\0\0\0"; std::memcpy(buf+56,otag,24);
  hex("SHA-256 preimage (80 B)",buf,80);
  uint8_t y[32]; mcl_sha256(buf,80,y); hex("y = SHA-256(preimage)",y,32);
  uint8_t y2[32]; mcl_vdf128v2_eval(x,xl,N,y2,B); std::printf("  API mcl_vdf128v2_eval: %s\n", std::memcmp(y,y2,32)==0?"IDENTICAL":"DIFFER");
  uint8_t y3[32]; mcl_vdf128v2_eval(x,xl,100000,y3,B); hex("y (same x, N=100000)",y3,32);
  // avalanche profile: 1-bit state flip at C_0, mean Hamming over 128 positions and 8 inputs, k = 1..8
  std::printf("\nAVALANCHE PROFILE (one-bit state flip at C_0; mean Hamming over all 128 positions x 8 inputs; 64 = full diffusion)\n");
  const int NI=8; double acc[9]={0}; double mn[9],mx[9]; for(int k=0;k<9;k++){mn[k]=1e9;mx[k]=-1;}
  for(int in=0;in<NI;in++){ char xi[40]; std::snprintf(xi,40,"VDF128v2-avalanche-%d",in); const uint8_t* xp=(const uint8_t*)xi; size_t xpl=std::strlen(xi);
    MCL_Q30_Sextet Wi=mcl_vdf128v2_weights(xp,xpl); VDF128_State c0=mcl_vdf128_init(xp,xpl); for(uint64_t i=0;i<B;i++) mcl_q30t4_iterate_raw(c0.t1,c0.t2,c0.t3,c0.t4,Wi,kp);
    for(int k=1;k<=8;k++){ double a=0; for(int b=0;b<128;b++){ VDF128_State p=c0,d=c0; uint32_t* w=(&d.t1)+(b/32); *w^=(1u<<(b%32)); for(int i=0;i<k;i++){ mcl_q30t4_iterate_raw(p.t1,p.t2,p.t3,p.t4,Wi,kp); mcl_q30t4_iterate_raw(d.t1,d.t2,d.t3,d.t4,Wi,kp);} a+=ham(p,d);} a/=128; acc[k]+=a; if(a<mn[k])mn[k]=a; if(a>mx[k])mx[k]=a; } }
  for(int k=1;k<=8;k++) std::printf("  k=%d: mean %.2f / 128   (per-input range %.2f .. %.2f)\n",k,acc[k]/NI,mn[k],mx[k]);
  // input flip: 64 random single-bit flips of 16-byte random inputs -> init-state Hamming and output Hamming (N=1000)
  std::printf("\nINPUT-FLIP STATISTICS (64 random one-bit flips of 16-byte inputs; expectations 64/128 and 128/256)\n");
  uint64_t z=20260905ull; double si=0,si2=0,so=0,so2=0; int cnt=64;
  for(int t=0;t<cnt;t++){ uint8_t a[16],b[16]; for(int i=0;i<16;i+=8){uint64_t r=sm(z); std::memcpy(a+i,&r,8);} std::memcpy(b,a,16); int bit=(int)(sm(z)%128); b[bit/8]^=(uint8_t)(1u<<(bit%8));
    VDF128_State ia=mcl_vdf128_init(a,16), ib=mcl_vdf128_init(b,16); int hi=ham(ia,ib); uint8_t ya[32],yb[32]; mcl_vdf128v2_eval(a,16,N,ya,B); mcl_vdf128v2_eval(b,16,N,yb,B); int ho=ham256(ya,yb);
    si+=hi; si2+=hi*hi; so+=ho; so2+=ho*ho; }
  double mi=si/cnt, sdi=std::sqrt(si2/cnt-mi*mi), mo=so/cnt, sdo=std::sqrt(so2/cnt-mo*mo);
  std::printf("  init-state Hamming: mean %.2f / 128 (sd %.2f)   output Hamming: mean %.2f / 256 (sd %.2f)\n",mi,sdi,mo,sdo);
  { const char* x2="MCL-VDF128-KAT-0"; VDF128_State i1=mcl_vdf128_init(x,xl), i2=mcl_vdf128_init((const uint8_t*)x2,16); uint8_t ya[32],yb[32]; mcl_vdf128v2_eval(x,xl,N,ya,B); mcl_vdf128v2_eval((const uint8_t*)x2,16,N,yb,B);
    std::printf("  KAT-1 vs KAT-0 (last char 1->0): init-state Hamming %d/128, output Hamming %d/256\n",ham(i1,i2),ham256(ya,yb)); }
  return 0;
}
