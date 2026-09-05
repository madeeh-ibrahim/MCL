// Proof of concept for referee finding PS-1: recover the parent's 64-bit block R_lo from a few
// observed sibling p-values WITHOUT inverting the engine, then predict an unseen sibling.
// derive_child: p_i = 2 + ((R_lo XOR fmix64(i)) mod (M-2)), p never bumped. M = 1e9 (paper's extended range).
#include "mcl_core.hpp"
#include <cstdio>
#include <chrono>
int main(){
  const uint64_t S=12345678901234ULL; const int64_t M=1000000000; const uint64_t m=(uint64_t)(M-2);
  DerivedKey c0=derive_child(S,3,5,0,M,K_DEFAULT), c1=derive_child(S,3,5,1,M,K_DEFAULT), c2=derive_child(S,3,5,2,M,K_DEFAULT), c7=derive_child(S,3,5,7,M,K_DEFAULT);
  uint64_t h0=fmix64(0),h1=fmix64(1),h2=fmix64(2),h7=fmix64(7);
  uint64_t a0=(uint64_t)(c0.p-2), a1=(uint64_t)(c1.p-2), a2=(uint64_t)(c2.p-2);
  auto t0=std::chrono::steady_clock::now(); uint64_t found=0, nfound=0, kmax=(~0ULL)/m;
  for(uint64_t k=0;k<=kmax;k++){ uint64_t x=(a0+k*m)^h0; if(((x^h1)%m)==a1 && ((x^h2)%m)==a2){found=x;nfound++;} }
  double sec=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
  // ground truth: the parent's first 8 raw bytes
  MCL_T2 e(S,3,5,K_DEFAULT); uint8_t r[32]; e.gen_bytes(r,32); uint64_t R=0; memcpy(&R,r,8);
  int64_t pred7 = 2 + (int64_t)((found^h7)%m);
  printf("M=1e9: observed p at i=0,1,2 = %lld,%lld,%lld | candidates surviving 3 siblings: %llu | recovered R_lo=0x%016llx  true=0x%016llx  %s | %.1f s (%llu k)\n",
    (long long)c0.p,(long long)c1.p,(long long)c2.p,(unsigned long long)nfound,(unsigned long long)found,(unsigned long long)R,(found==R?"MATCH":"no"),sec,(unsigned long long)kmax);
  printf("predicted p for unseen index 7 = %lld ; actual derive_child p = %lld  %s\n",(long long)pred7,(long long)c7.p,(pred7==c7.p?"MATCH":"no"));
  return 0; }
