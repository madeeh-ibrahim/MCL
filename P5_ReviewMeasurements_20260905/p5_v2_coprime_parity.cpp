/*
 * p5_v2_coprime_parity.cpp — derive_child_v2 census at the default parent (3,5), M = 10^6, K = 12:
 * (i) fraction of raw (pre-gcd) pairs that are NOT coprime (expected 1 - 6/pi^2 = 39.2 % for independent words),
 * (ii) parity classes of the emitted (p,q) — v1 had parity(p) XOR parity(q) constant per parent (parity lock),
 * (iii) p == q bumps.  Doc ID: MCL-P5-V2CENSUS-2026-0905-001
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. -I../hd_v2 p5_v2_coprime_parity.cpp -o p5_v2_coprime_parity
 */
#include "mcl_core.hpp"
#include "mcl_hd_v2.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
static uint64_t g(uint64_t a, uint64_t b){ while(b){ uint64_t t=b; b=a%b; a=t;} return a; }
int main(int argc,char**argv){
  const int64_t N = argc>1? atoll(argv[1]) : 200000; const int64_t M=1000000; const uint64_t seed=12345678901234ULL;
  // raw block once (index-independent), then replicate Step 2/3 of v2 to classify the RAW pair
  MCL_T2 eng(seed,3,5,K_DEFAULT); uint8_t raw[32]; eng.gen_bytes(raw,32);
  int64_t noncop=0, bumps=0, cls[4]={0,0,0,0}, differs=0;
  for(int64_t i=0;i<N;i++){
    uint8_t msg[49]; std::memcpy(msg,"MCL-HD-v2",9); std::memcpy(msg+9,raw,32); for(int b=0;b<8;b++) msg[41+b]=(uint8_t)(((uint64_t)i)>>(8*b));
    uint8_t d[32]; mcl_sha256(msg,49,d); uint64_t c1=0,c2=0; for(int b=0;b<8;b++){ c1|=((uint64_t)d[b])<<(8*b); c2|=((uint64_t)d[8+b])<<(8*b); }
    int64_t pr=2+(int64_t)(c1%(uint64_t)(M-2)), qr=2+(int64_t)(c2%(uint64_t)(M-2));
    if(pr==qr) bumps++;
    if(g(pr,qr)!=1) noncop++;
    DerivedKey dk = derive_child_v2(seed,3,5,i,M,K_DEFAULT);
    if(dk.q!=qr) differs++;
    cls[(dk.p&1)*2+(dk.q&1)]++;
  }
  std::printf("derive_child_v2 census: parent (3,5), M=%lld, indices=%lld, engine %s, hd_v2 %s\n",(long long)M,(long long)N,MCL_VERSION_STRING,MCL_HD_V2_VERSION);
  std::printf("raw non-coprime %lld (%.2f%%; independent-uniform expectation %.2f%%) | q differs from raw %lld (%.2f%%) | p==q bumps %lld\n",
    (long long)noncop,100.0*noncop/N,100.0*(1-6.0/(M_PI*M_PI)),(long long)differs,100.0*differs/N,(long long)bumps);
  std::printf("parity classes (p,q): even,even %lld | even,odd %lld | odd,even %lld | odd,odd %lld  (v1 lock: two classes empty)\n",
    (long long)cls[0],(long long)cls[1],(long long)cls[2],(long long)cls[3]);
  return 0; }
