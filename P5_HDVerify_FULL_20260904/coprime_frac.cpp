// Measures the fraction of derivation indices for which the naive map
// (no gcd enforcement) yields a q_child different from derive_child()'s q_child.
// Parent (3,5), seed 12345678901234, M = 1e6, indices 0..N-1.  Engine of record v8.1.3.
#include "mcl_core.hpp"
#include <cstdio>
#include <cstring>
static int64_t gcd64(int64_t a,int64_t b){while(b){int64_t t=b;b=a%b;a=t;}return a;}
int main(int argc,char**argv){
  const uint64_t S=12345678901234ULL; const int64_t M=1000000; const int64_t N=(argc>1)?atoll(argv[1]):200000;
  // Raw bytes: index-independent (same seed, same parent) -- generated once, exactly as derive_child does.
  MCL_T2 eng(S,3,5,K_DEFAULT); uint8_t raw0[32]; eng.gen_bytes(raw0,32);
  int64_t differ=0, noncoprime_raw=0, p_eq_q=0;
  for(int64_t i=0;i<N;i++){
    uint8_t raw[32]; memcpy(raw,raw0,32);
    uint64_t h=fmix64((uint64_t)i), h2=h*0x9E3779B97F4A7C15ULL;
    for(int b=0;b<8;b++){ raw[b]^=(uint8_t)(h>>(8*b)); raw[8+b]^=(uint8_t)(h2>>(8*b)); }
    uint64_t c1=0,c2=0; memcpy(&c1,raw,8); memcpy(&c2,raw+8,8);
    int64_t pc=2+(int64_t)(c1%(uint64_t)(M-2)), qc=2+(int64_t)(c2%(uint64_t)(M-2));
    if(pc==qc){ p_eq_q++; qc=2+((qc-2+1)%(M-2)); }
    int64_t q_naive=qc;
    if(gcd64(pc,qc)!=1) noncoprime_raw++;
    DerivedKey d=derive_child(S,3,5,i,M,K_DEFAULT);
    if(d.p!=pc){ printf("p mismatch at i=%lld\n",(long long)i); return 1; }
    if(d.q!=q_naive) differ++;
  }
  printf("indices=%lld  p_eq_q_bumps=%lld  raw_noncoprime=%lld (%.2f%%)  q_differs_from_naive=%lld (%.2f%%)  engine v%s\n",
    (long long)N,(long long)p_eq_q,(long long)noncoprime_raw,100.0*noncoprime_raw/N,(long long)differ,100.0*differ/N,MCL_VERSION_STRING);
  return 0;
}
