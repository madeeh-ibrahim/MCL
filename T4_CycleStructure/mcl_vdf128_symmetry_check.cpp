#include "mcl_core.hpp"
#include "keyed_q30_PQ/mcl_keyed_q30.hpp"
#include "VDF128_T4/mcl_vdf128_t4.hpp"
#include <cstdio>
int main(){ MCL_Q30_Sextet W=mcl_vdf128_public_weights(); const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
 const uint32_t P[6]={W.p12,W.p13,W.p14,W.p23,W.p24,W.p34}, Q[6]={W.q12,W.q13,W.q14,W.q23,W.q24,W.q34}; const int I[6]={0,0,0,1,1,2}, J[6]={1,2,3,2,3,3};
 std::printf("VDF128 public weights: %u %u %u %u %u %u %u %u %u %u %u %u\n",W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34);
 int found=0; for(uint32_t c=1;c<65536;c++){ uint32_t b[4]={(c&15)<<28,((c>>4)&15)<<28,((c>>8)&15)<<28,((c>>12)&15)<<28}; bool alg=true; for(int e=0;e<6&&alg;e++){ if((uint32_t)(P[e]*b[J[e]])!=(uint32_t)(Q[e]*b[I[e]]) || (uint32_t)(P[e]*b[I[e]])!=(uint32_t)(Q[e]*b[J[e]])) alg=false; } if(alg){ found++; std::printf("  commuting translation b=%08x %08x %08x %08x\n",b[0],b[1],b[2],b[3]); } }
 // also finer: b_i multiples of 2^24 but restricted to b_i in {0, D*omega_i}? not applicable (init is SHA-based). Report group order over 2^28 lattice.
 std::printf("VDF128-T4 public weight set: non-trivial translation symmetries on the 2^28-lattice: %d (group order %d)\n",found,found+1); (void)kp; return 0; }
