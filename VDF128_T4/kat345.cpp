#include "mcl_vdf128_t4.hpp"
#include <cstdio>
#include <chrono>
using Clock=std::chrono::steady_clock;
int main(){
  { uint8_t xa[8], xb[8]; uint64_t s=12345678901234ULL, s2=s+(1ULL<<32);
    for(int i=0;i<8;i++){xa[i]=(uint8_t)(s>>(8*i));xb[i]=(uint8_t)(s2>>(8*i));}
    VDF128_State A=mcl_vdf128_init(xa,8),B=mcl_vdf128_init(xb,8);
    int d=__builtin_popcount(A.t1^B.t1)+__builtin_popcount(A.t2^B.t2)+__builtin_popcount(A.t3^B.t3)+__builtin_popcount(A.t4^B.t4);
    printf("TEST3 s vs s+2^32: %d/128 bits differ (old path: 0)\n",d);
    xb[0]=xa[0]^1; for(int i=1;i<8;i++) xb[i]=xa[i];
    B=mcl_vdf128_init(xb,8);
    d=__builtin_popcount(A.t1^B.t1)+__builtin_popcount(A.t2^B.t2)+__builtin_popcount(A.t3^B.t3)+__builtin_popcount(A.t4^B.t4);
    printf("TEST3 1-bit flip: %d/128 bits differ (expect ~64)\n",d); }
  { static const MCL_Q30_Sextet W=mcl_vdf128_public_weights();
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
    VDF128_State s=mcl_vdf128_init((const uint8_t*)"tp",2);
    const uint64_t M=200000000ULL; auto t0=Clock::now();
    for(uint64_t i=0;i<M;i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
    double sec=std::chrono::duration<double>(Clock::now()-t0).count();
    printf("TEST4 throughput: %.1f M iter/s (%.1f ns/iter) [%08x]\n",M/1e6/sec,sec*1e9/M,s.t1^s.t2^s.t3^s.t4); }
  { const char* x="MCL-VDF128-KAT-1";
    VDF128_State i0=mcl_vdf128_init((const uint8_t*)x,strlen(x));
    printf("TEST5 KAT init      : %08x %08x %08x %08x\n",i0.t1,i0.t2,i0.t3,i0.t4);
    VDF128_State sB=mcl_vdf128_eval_state((const uint8_t*)x,strlen(x),0);
    printf("TEST5 KAT post-burn : %08x %08x %08x %08x\n",sB.t1,sB.t2,sB.t3,sB.t4);
    VDF128_State sF=mcl_vdf128_eval_state((const uint8_t*)x,strlen(x),100000);
    printf("TEST5 KAT final 1e5 : %08x %08x %08x %08x\n",sF.t1,sF.t2,sF.t3,sF.t4);
    uint8_t y[32],y2[32];
    mcl_vdf128_eval((const uint8_t*)x,strlen(x),100000,y);
    mcl_vdf128_eval((const uint8_t*)x,strlen(x),100000,y2);
    printf("TEST5 KAT y = "); for(int i=0;i<32;i++)printf("%02x",y[i]);
    printf("\nTEST5 determinism: %s\n",memcmp(y,y2,32)==0?"IDENTICAL":"MISMATCH"); }
  return 0;
}
