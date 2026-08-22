#include HDR
#include <cstdio>
int main(){ for(int k=0;k<65536;k++){ uint8_t ctr[8]; for(int i=0;i<8;i++) ctr[i]=(uint8_t)(k>>(8*i)); uint8_t key[32]; mcl_sha256(ctr,8,key); MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(key,0);
  std::printf("%d %u %u %u %u %u %u %u %u %u %u %u %u\n",k,W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34);} return 0; }
