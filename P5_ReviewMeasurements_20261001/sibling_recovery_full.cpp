/*
 * sibling_recovery_full.cpp — Paper 5 §III.B: full sibling recovery for the archived derivation
 * (version 1, derive_child of mcl_core.hpp 8.1.3), both components.
 *   child i = (2 + ((R_lo ^ h_i) mod m),  bump(2 + ((R_hi ^ h2_i) mod m)))   m = M - 2,
 *   h_i = fmix64(i), h2_i = h_i * 0x9E3779B97F4A7C15 (both public); bump() = the engine's own
 *   q adjustment (q+1 with wrap while q == p or gcd(p, q) != 1), replicated below and checked
 *   against derive_child on every child printed.
 * From the three observed children 0, 1, 2 (p AND q) of one parent at M = 10^9, with neither the
 * seed nor the parent pair: (1) recover R_lo from the p-values (as sibling_recovery.cpp, 2026-09-05);
 * (2) recover R_hi: for each offset d0 = 0, 1, 2, … of child 0's bump, enumerate the 2^64/m
 * candidates x = (q_0 - 2 - d0) + k*m, R_hi = x ^ h2_0, and keep those that reproduce the observed
 * q_1 and q_2 under bump() — stopping at the first offset with a survivor; (3) predict children
 * 3…40 in full and compare them with derive_child.
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. sibling_recovery_full.cpp -o sibling_recovery_full
 * Doc ID: MCL-P5-PREUPLOAD-2026-1001-003
 */
#include "mcl_core.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
static int64_t g(int64_t a,int64_t b){while(b){int64_t t=b;b=a%b;a=t;}return a;}
static int64_t bump(int64_t pc,int64_t qc,int64_t M){            // replica of derive_child Step 5 + coprimality loop
  if(pc==qc) qc=2+((qc-2+1)%(M-2));
  while(g(pc>qc?pc:qc,pc>qc?qc:pc)!=1){ qc=2+((qc-2+1)%(M-2)); if(qc==pc) qc=2+((qc-2+1)%(M-2)); }
  return qc; }
int main(){
  const uint64_t S=12345678901234ULL; const int64_t M=1000000000; const uint64_t m=(uint64_t)(M-2);
  DerivedKey c[3]; for(int i=0;i<3;i++) c[i]=derive_child(S,3,5,i,M,K_DEFAULT);
  uint64_t h[3],h2[3]; for(int i=0;i<3;i++){h[i]=fmix64((uint64_t)i);h2[i]=h[i]*0x9E3779B97F4A7C15ULL;}
  std::printf("observed children (seed and parent unknown to the attacker): (%lld,%lld) (%lld,%lld) (%lld,%lld)\n",
    (long long)c[0].p,(long long)c[0].q,(long long)c[1].p,(long long)c[1].q,(long long)c[2].p,(long long)c[2].q);
  const uint64_t kmax=(~0ULL)/m;
  // (1) R_lo from p-values
  auto t0=std::chrono::steady_clock::now(); uint64_t Rlo=0,nlo=0;
  { uint64_t a0=(uint64_t)(c[0].p-2),a1=(uint64_t)(c[1].p-2),a2=(uint64_t)(c[2].p-2);
    for(uint64_t k=0;k<=kmax;k++){uint64_t x=(a0+k*m)^h[0]; if(((x^h[1])%m)==a1 && ((x^h[2])%m)==a2){Rlo=x;nlo++;}} }
  double s1=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
  std::printf("R_lo: %llu survivor(s), 0x%016llx, %.1f s\n",(unsigned long long)nlo,(unsigned long long)Rlo,s1);
  // (2) R_hi from q-values through bump()
  auto t1=std::chrono::steady_clock::now(); uint64_t Rhi=0,nhi=0; int dfound=-1; uint64_t prefilter=0;
  const uint64_t DW=64;                        // pre-filter window for children 1, 2 (bump offsets are small)
  for(int d0=0; d0<64 && nhi==0; d0++){
    uint64_t a0=((uint64_t)(c[0].q-2)+m-(uint64_t)d0)%m;
    for(uint64_t k=0;k<=kmax;k++){
      uint64_t x=a0+k*m; if(x<a0) break; uint64_t R=x^h2[0];
      // child 0 itself must bump to its observed q from this raw value
      uint64_t r1=(R^h2[1])%m, d1=((uint64_t)(c[1].q-2)+m-r1)%m; if(d1>DW) continue;
      uint64_t r2=(R^h2[2])%m, d2=((uint64_t)(c[2].q-2)+m-r2)%m; if(d2>DW) continue;
      prefilter++;
      if(bump(c[0].p,2+(int64_t)((R^h2[0])%m),M)!=c[0].q) continue;
      if(bump(c[1].p,2+(int64_t)r1,M)!=c[1].q) continue;
      if(bump(c[2].p,2+(int64_t)r2,M)!=c[2].q) continue;
      Rhi=R; nhi++; }
    if(nhi) dfound=d0; }
  double s2=std::chrono::duration<double>(std::chrono::steady_clock::now()-t1).count();
  std::printf("R_hi: %llu survivor(s) at child-0 bump offset %d, 0x%016llx, %.1f s (%llu candidates reached the full check)\n",
    (unsigned long long)nhi,dfound,(unsigned long long)Rhi,s2,(unsigned long long)prefilter);
  // ground truth (not used by the attack)
  MCL_T2 e(S,3,5,K_DEFAULT); uint8_t r[32]; e.gen_bytes(r,32); uint64_t TLo=0,THi=0; std::memcpy(&TLo,r,8); std::memcpy(&THi,r+8,8);
  std::printf("ground truth: R_lo %s, R_hi %s\n",Rlo==TLo?"MATCH":"no",Rhi==THi?"MATCH":"no");
  // (3) predict unseen children 3..40 in full
  int ok=0,tot=0; for(int i=3;i<=40;i++){ uint64_t hi=fmix64((uint64_t)i),hi2=hi*0x9E3779B97F4A7C15ULL;
    int64_t pp=2+(int64_t)((Rlo^hi)%m), qq=bump(pp,2+(int64_t)((Rhi^hi2)%m),M); DerivedKey t=derive_child(S,3,5,i,M,K_DEFAULT);
    bool hit=(pp==t.p&&qq==t.q); ok+=hit; tot++;
    if(i==7||!hit) std::printf("  child %d: predicted (%lld,%lld), derive_child (%lld,%lld) %s\n",i,(long long)pp,(long long)qq,(long long)t.p,(long long)t.q,hit?"MATCH":"no"); }
  std::printf("unseen children 3..40 predicted in full (p and q): %d/%d\n",ok,tot);
  return 0; }
