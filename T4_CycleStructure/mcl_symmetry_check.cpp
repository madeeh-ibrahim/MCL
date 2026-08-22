// mcl_symmetry_check.cpp — Doc ID MCL-T4-CYCLE-2026-0822-002 (companion diagnostic)
// Why: the full-width 2-osc calibration found 4 seeds on 3 DISTINCT terminal cycles of
// IDENTICAL length lambda = 1,671,196,332.  Distinct cycles of identical length are the
// signature of a symmetry of the map: a translation T(t) = t + b (mod 2^32 per angle)
// with F(T(t)) = T(F(t)) maps every cycle onto a cycle of the same length.
// For the Q30 map every coupling argument is (p*t_j - q*t_i) mod 2^32, so T commutes
// with F iff every argument is invariant:  p*b_j == q*b_i  (and the reverse argument
// p*b_i == q*b_j) mod 2^32 for every coupled pair.  This tool brute-forces the
// translation symmetry group (b_i restricted to multiples of 2^24, i.e. 256 values per
// angle: 2^16 candidates for 2-osc, 2^32 is too many for T4 so T4 uses multiples of 2^28,
// 16 values per angle = 65,536 candidates) and VERIFIES each candidate by iterating the
// real engine map on a state and its translate for 10,000 steps.
// ADDITIVE: engine untouched.  Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_symmetry_check.cpp -o mcl_symmetry_check
#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include <cstdio>
#include <vector>

static bool commutes_2osc(uint32_t b1,uint32_t b2,int64_t p,int64_t q,int64_t kp,int iters){
    uint32_t x1,x2; mcl_q30_init_state(DEFAULT_SEED,x1,x2); uint32_t y1=x1+b1,y2=x2+b2;
    for(int i=0;i<iters;i++){ mcl_q30_iterate_raw(x1,x2,p,q,kp); mcl_q30_iterate_raw(y1,y2,p,q,kp); if((uint32_t)(y1-x1)!=b1||(uint32_t)(y2-x2)!=b2) return false; }
    return true;
}
static bool commutes_t4(const uint32_t b[4],const MCL_Q30_Sextet& W,int64_t kp,int iters){
    uint64_t s=hash_seed(DEFAULT_SEED); uint32_t x[4]={(uint32_t)(s*mcl_q30_omega1()),(uint32_t)(s*mcl_q30_omega2()),(uint32_t)(s*mcl_q30_omega3()),(uint32_t)(s*mcl_q30_omega4())};
    uint32_t y[4]={x[0]+b[0],x[1]+b[1],x[2]+b[2],x[3]+b[3]};
    for(int i=0;i<iters;i++){ mcl_q30t4_iterate_raw(x[0],x[1],x[2],x[3],W,kp); mcl_q30t4_iterate_raw(y[0],y[1],y[2],y[3],W,kp); for(int k=0;k<4;k++) if((uint32_t)(y[k]-x[k])!=b[k]) return false; }
    return true;
}
int main(){
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
    std::printf("MCL-T4-CYCLE-2026-0822-002  translation-symmetry check, engine mcl_core %s UNMODIFIED\n", MCL_VERSION_STRING);
    // ---- 2-osc (3,5): candidates b1,b2 multiples of 2^24 (256 x 256), verified 10,000 steps ----
    {
        int64_t p=3,q=5; int found=0; std::printf("\n[2-osc (3,5)] brute force over b1,b2 in {k*2^24}: commuting translations (b1,b2):\n");
        for(uint32_t i=0;i<256;i++) for(uint32_t j=0;j<256;j++){
            uint32_t b1=i<<24,b2=j<<24; if(b1==0&&b2==0) continue;
            // algebraic pre-check: p*b2==q*b1 and p*b1==q*b2 (mod 2^32)
            if((uint32_t)(p*b2)!=(uint32_t)(q*b1) || (uint32_t)(p*b1)!=(uint32_t)(q*b2)) continue;
            bool ok=commutes_2osc(b1,b2,p,q,kp,10000); std::printf("  b1=%08x b2=%08x  algebraic ✓  engine-verified %s\n",b1,b2,ok?"✓":"✗"); if(ok) found++;
        }
        std::printf("  => non-trivial commuting translations found: %d  (group order incl. identity = %d)\n",found,found+1);
        std::printf("  theory: (p^2-q^2) a == 0 mod 2^32 with p^2-q^2 = -16  =>  a in {k*2^28}: 16 elements\n");
    }
    // ---- keyed T4: 4 KAT-style keys; candidates b_i multiples of 2^28 (16^4), verified 10,000 steps ----
    for(int k=0;k<4;k++){
        uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i+k*0x11); MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(key,0);
        int found=0; std::printf("\n[T4 key%d] brute force over b_i in {k*2^28}^4 (65,536 candidates):\n",k);
        const uint32_t P[6]={W.p12,W.p13,W.p14,W.p23,W.p24,W.p34}, Q[6]={W.q12,W.q13,W.q14,W.q23,W.q24,W.q34}; const int I[6]={0,0,0,1,1,2}, J[6]={1,2,3,2,3,3};
        for(uint32_t c=1;c<65536;c++){
            uint32_t b[4]={(c&15)<<28,((c>>4)&15)<<28,((c>>8)&15)<<28,((c>>12)&15)<<28};
            bool alg=true; for(int e=0;e<6&&alg;e++){ if((uint32_t)(P[e]*b[J[e]])!=(uint32_t)(Q[e]*b[I[e]]) || (uint32_t)(P[e]*b[I[e]])!=(uint32_t)(Q[e]*b[J[e]])) alg=false; }
            if(!alg) continue;
            bool ok=commutes_t4(b,W,kp,10000); std::printf("  b=%08x %08x %08x %08x  algebraic ✓  engine-verified %s\n",b[0],b[1],b[2],b[3],ok?"✓":"✗"); if(ok) found++;
        }
        int even=0; for(int e=0;e<6;e++) if(((P[e]-Q[e])&1u)==0) even++;
        std::printf("  => non-trivial commuting translations: %d (group order %d); pairs with p-q even: %d/6 (b_i=2^31 for all i is a symmetry iff 6/6)\n",found,found+1,even);
    }
    return 0;
}
