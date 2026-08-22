#include "mcl_keyed_q30.hpp"
#include <cstdio>
#include <vector>
int main(){ int weak_new=0, checked=0, still_related=0; const uint32_t om[4]={mcl_q30_omega1(),mcl_q30_omega2(),mcl_q30_omega3(),mcl_q30_omega4()};
  for(int k=0;k<65536;k++){ uint8_t ctr[8]; for(int i=0;i<8;i++) ctr[i]=(uint8_t)(k>>(8*i)); uint8_t key[32]; mcl_sha256(ctr,8,key); MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(key,0);
    if(mcl_t4_q30_has_reachable_symmetry(W)) weak_new++; }
  std::printf("new from_key: keys with seed-reachable symmetry: %d / 65536\n",weak_new);
  // engine-level: for 40 keys that CHANGED (read ids from stdin), seeds s and s+2^31 must now give unrelated keystreams
  int id; while(std::scanf("%d",&id)==1 && checked<40){ uint8_t ctr[8]; for(int i=0;i<8;i++) ctr[i]=(uint8_t)(id>>(8*i)); uint8_t key[32]; mcl_sha256(ctr,8,key);
    MCL_T4_Q30 e1(key,0,DEFAULT_SEED,K_DEFAULT), e2(key,0,DEFAULT_SEED+(1ULL<<31),K_DEFAULT); std::vector<uint8_t> a(4096),b(4096); e1.gen_bytes(a.data(),4096); e2.gen_bytes(b.data(),4096);
    int hist[256]={0}; for(int i=0;i<4096;i++) hist[a[i]^b[i]]++; int mx=0; for(int x=0;x<256;x++) if(hist[x]>mx) mx=hist[x]; if(mx>200) still_related++; checked++; }
  std::printf("engine check on %d changed keys: seeds s vs s+2^31 still byte-XOR-related: %d (expect 0)\n",checked,still_related); (void)om; return 0; }
