#include "mcl_core.hpp"
#include "keyed_q30_PQ/mcl_keyed_q30.hpp"
#include <cstdio>
#include <cstring>
int main(){
  // three key sources: (A) patterned as in the 65k sampler, (B) patterned as in the 4k sampler, (C) SHA-256(counter) pseudo-random
  for(int src=0;src<3;src++){
    int N=65536; int pe[12]={0}; int pq_even[6]={0}; int cond9=0;
    for(int k=0;k<N;k++){ uint8_t key[32];
      if(src==0) for(int i=0;i<32;i++) key[i]=(uint8_t)(i*13+k*0x31+(k>>8)*0x97);
      else if(src==1) for(int i=0;i<32;i++) key[i]=(uint8_t)(i*7+k*0x11+(k>>8));
      else { uint8_t ctr[8]; for(int i=0;i<8;i++) ctr[i]=(uint8_t)(k>>(8*i)); mcl_sha256(ctr,8,key); }
      MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(key,0);
      uint32_t w[12]={W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34};
      for(int i=0;i<12;i++) pe[i]+=(w[i]&1)==0;
      for(int e=0;e<6;e++) pq_even[e]+=((w[2*e]-w[2*e+1])&1)==0;
      bool c=(((w[0]-w[1])&1)==0)&&(((w[2]-w[3])&1)==0)&&(((w[6]-w[7])&1)==0)&&((w[4]&1)==0)&&((w[5]&1)==0)&&((w[8]&1)==0)&&((w[9]&1)==0)&&((w[10]&1)==0)&&((w[11]&1)==0);
      cond9+=c; }
    std::printf("source %c: P(weight even) per lane:",'A'+src); for(int i=0;i<12;i++) std::printf(" %.3f",pe[i]/(double)N); std::printf("\n   P(p-q even) per pair:"); for(int e=0;e<6;e++) std::printf(" %.3f",pq_even[e]/(double)N); std::printf("   9-condition fraction %.4f%% (theory 0.195%%)\n",100.0*cond9/N);
  }
  return 0; }
