/*
 * p5_G_entropy.cpp — the ONE measurement the Paper-5 §V theorem consumes (referee round 3):
 * collision (birthday) estimate of the min-entropy of G(U) = MCL_T4_Q30(seed_pub, params(U)).gen_bytes(32)
 * on uniform 256-bit U, as a function of the burn-in length B (scratch engine copy with MCL_BURNIN_OVERRIDE).
 * n = 2^25 uniform keys U_i = SHA-256("MCL-P5-GENT" || LE64(i)); each tag truncated to its first 42 bits;
 * expected collisions for an ideal random function: C(n,2)/2^42 ≈ 128.  Doc ID: MCL-P5-GENTROPY-2026-0905-001
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -DMCL_BURNIN_OVERRIDE=<B> -I. p5_G_entropy.cpp -o gent_<B> -lpthread
 */
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
static const uint64_t PUBLIC_SEED=12345678901234ULL;
int main(int argc,char**argv){
  const uint64_t N = (argc>1)? (1ULL<<atoi(argv[1])) : (1ULL<<25); const int T=8; const int BITS=42;
  std::vector<uint64_t> v(N);
  auto work=[&](int t){ for(uint64_t i=t;i<N;i+=T){ uint8_t buf[40]; std::memset(buf,0,32); std::memcpy(buf,"MCL-P5-GENT",11); for(int k=0;k<8;k++) buf[32+k]=(uint8_t)(i>>(8*k));
      uint8_t key[32]; mcl_sha256(buf,40,key); uint8_t tag[32]; { MCL_T4_Q30 e(key,0,PUBLIC_SEED,K_DEFAULT); e.gen_bytes(tag,32); }
      uint64_t x=0; std::memcpy(&x,tag,8); v[i]= x >> (64-BITS); } };
  std::vector<std::thread> th; for(int t=0;t<T;t++) th.emplace_back(work,t); for(auto&x:th) x.join();
  std::sort(v.begin(),v.end()); uint64_t coll=0, maxrun=1, run=1;
  for(uint64_t i=1;i<N;i++){ if(v[i]==v[i-1]){ run++; } else { coll += run*(run-1)/2; maxrun=std::max(maxrun,run); run=1; } } coll += run*(run-1)/2; maxrun=std::max(maxrun,run);
  double expected = (double)N*(double)(N-1)/2.0/ (double)(1ULL<<BITS);
  std::printf("B=%5d | n=2^%d keys | %d-bit truncation | collisions %llu | expected (ideal) %.1f | ratio %.3f | largest multiplicity %llu\n",
    BURNIN, (int)__builtin_ctzll(N), BITS, (unsigned long long)coll, expected, coll/expected, (unsigned long long)maxrun);
  return 0; }
