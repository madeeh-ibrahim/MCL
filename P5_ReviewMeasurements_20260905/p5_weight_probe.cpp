// Weight-space perturbation probe (referee Y1): are wrong-credential tags flat when the perturbation is applied
// to the twelve MAP-DEFINING WEIGHTS themselves (not to the key before the KDF)?  Doc ID: MCL-P5-WPROBE-2026-0905-001
// For 200 random K_tx: (a) each of the 12 weights +1 and -1 (24 probes), (b) single-bit flips of weight 0 at bits 0..29 (30 probes);
// Hamming distance of the perturbed tag to the true tag; near-miss = HD <= 32.  Double-precision engine via its sextet
// constructor; Q30 via a scratch copy of the sidecar with an explicit-weights constructor (engine of record untouched).
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include <array>
#include <cstdio>
#include <cstring>
using Tag=std::array<uint8_t,32>;
static const uint64_t SEED=12345678901234ULL;
static int ham(const Tag&a,const Tag&b){int h=0;for(int i=0;i<32;i++)h+=__builtin_popcount((unsigned)(a[i]^b[i]));return h;}
static void keyi(uint64_t i,uint8_t k[32]){uint8_t b[40];std::memset(b,0,32);std::memcpy(b,"MCL-P5-WPROBE",13);for(int j=0;j<8;j++)b[32+j]=(uint8_t)(i>>(8*j));mcl_sha256(b,40,k);}
int main(){
  double sD=0,sQ=0; int nD=0,nQ=0,mnD=256,mxD=0,mnQ=256,mxQ=0,nearD=0,nearQ=0, skipD=0, skipQ=0;
  for(uint64_t i=0;i<200;i++){ uint8_t k[32]; keyi(i,k);
    // ---- double ----
    CouplingSextet cs=mcl_t4_params_from_key(k,0); Tag t0{}; { MCL_T4 e(SEED,cs,K_DEFAULT); e.gen_bytes(t0.data(),32); }
    int64_t* wd=reinterpret_cast<int64_t*>(&cs);
    for(int l=0;l<12;l++) for(int d=-1;d<=1;d+=2){ CouplingSextet c2=cs; int64_t* w2=reinterpret_cast<int64_t*>(&c2); w2[l]+=d; if(w2[l]<2) {skipD++; continue;} if(w2[l&~1]==w2[l|1]) {skipD++; continue;}
      Tag t{}; { MCL_T4 e(SEED,c2,K_DEFAULT); e.gen_bytes(t.data(),32); } int h=ham(t0,t); sD+=h; nD++; mnD=std::min(mnD,h); mxD=std::max(mxD,h); if(h<=32) nearD++; }
    for(int b=0;b<30;b++){ CouplingSextet c2=cs; int64_t* w2=reinterpret_cast<int64_t*>(&c2); w2[0]^=(1LL<<b); if(w2[0]<2||w2[0]==w2[1]||w2[0]>=(1LL<<40)) {skipD++; continue;}
      Tag t{}; { MCL_T4 e(SEED,c2,K_DEFAULT); e.gen_bytes(t.data(),32); } int h=ham(t0,t); sD+=h; nD++; mnD=std::min(mnD,h); mxD=std::max(mxD,h); if(h<=32) nearD++; }
    // ---- Q30 ----
    MCL_Q30_Sextet q=mcl_t4_q30_params_from_key(k,0); Tag u0{}; { MCL_T4_Q30 e(q,SEED,K_DEFAULT); e.gen_bytes(u0.data(),32); }
    uint32_t* wq=reinterpret_cast<uint32_t*>(&q);
    for(int l=0;l<12;l++) for(int d=-1;d<=1;d+=2){ MCL_Q30_Sextet q2=q; uint32_t* w2=reinterpret_cast<uint32_t*>(&q2); int64_t nv=(int64_t)w2[l]+d; if(nv<2||nv>=(1<<30)) {skipQ++; continue;} w2[l]=(uint32_t)nv; if(w2[l&~1]==w2[l|1]) {skipQ++; continue;}
      Tag t{}; { MCL_T4_Q30 e(q2,SEED,K_DEFAULT); e.gen_bytes(t.data(),32); } int h=ham(u0,t); sQ+=h; nQ++; mnQ=std::min(mnQ,h); mxQ=std::max(mxQ,h); if(h<=32) nearQ++; }
    for(int b=0;b<30;b++){ MCL_Q30_Sextet q2=q; uint32_t* w2=reinterpret_cast<uint32_t*>(&q2); w2[0]^=(1u<<b); if(w2[0]<2||w2[0]>=(1u<<30)||w2[0]==w2[1]) {skipQ++; continue;}
      Tag t{}; { MCL_T4_Q30 e(q2,SEED,K_DEFAULT); e.gen_bytes(t.data(),32); } int h=ham(u0,t); sQ+=h; nQ++; mnQ=std::min(mnQ,h); mxQ=std::max(mxQ,h); if(h<=32) nearQ++; }
  }
  std::printf("double : %d weight-space probes (skipped %d invalid) | mean HD %.3f/256 | min %d max %d | near-misses(HD<=32) %d\n",nD,skipD,sD/nD,mnD,mxD,nearD);
  std::printf("Q30    : %d weight-space probes (skipped %d invalid) | mean HD %.3f/256 | min %d max %d | near-misses(HD<=32) %d\n",nQ,skipQ,sQ/nQ,mnQ,mxQ,nearQ);
  return 0; }
