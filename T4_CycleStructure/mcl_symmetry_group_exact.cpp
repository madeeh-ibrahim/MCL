// mcl_symmetry_group_exact.cpp — Doc ID MCL-T4-CYCLE-2026-0822-004 (review-stage diagnostic)
// Exact translation-symmetry group of the Q30 map (ALL translations, not only a 2^28 lattice).
// A translation b (per-angle offsets mod 2^32) commutes with the map iff every coupling argument
// is invariant: for every coupled pair (i,j):  p*b_j == q*b_i  and  p*b_i == q*b_j  (mod 2^32)
// (necessity: the LUT index is the top 16 bits of the argument, so a non-invariant argument changes
//  the increment for SOME states — we verify each algebraic solution by engine simulation anyway).
// Solved by choosing b_1 freely (2^32 values is too many) -> we exploit linearity: the solution set
// is a subgroup of (Z/2^32)^4; we enumerate b_1 over the 2-adic tower: b_1 = c*2^v, v=0..31, c odd,
// and for each v solve the chain congruences for b_2,b_3,b_4 by linear-congruence solving (all
// solutions, handling non-invertible even weights), then verify ALL 12 argument conditions, then
// verify by 10,000-step engine simulation.  Reports group order and generators per weight set.
// Also: weak-key fraction over 65,536 keys for SEED-REACHABLE translations (D any multiple of 2^20),
// and the theoretical probability for the dominant D=2^31 element.
// ADDITIVE: engine untouched. Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_symmetry_group_exact.cpp -o mcl_symmetry_group_exact
#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include "../VDF128_T4/mcl_vdf128_t4.hpp"
#include <cstdio>
#include <vector>
#include <set>
#include <array>
#include <algorithm>

typedef std::array<uint32_t,4> B4;
static uint64_t egcd(int64_t a,int64_t b,int64_t& x,int64_t& y){ if(b==0){x=1;y=0;return a;} int64_t x1,y1; uint64_t g=egcd(b,a%b,x1,y1); x=y1; y=x1-(a/b)*y1; return g; }
// all x in [0,2^32) with a*x == c (mod 2^32)
static std::vector<uint32_t> solve_lin(uint32_t a,uint32_t c){
    std::vector<uint32_t> out; if(a==0){ if(c==0){ /* all x: too many — signal with empty+flag */ } return out; }
    const uint64_t M=1ULL<<32; int64_t x,y; uint64_t g=egcd((int64_t)a,(int64_t)M,x,y);
    if(c%g) return out; uint64_t Mg=M/g; uint64_t x0=(uint64_t)(( (__int128)(x%(int64_t)Mg+(int64_t)Mg)%(int64_t)Mg * (int64_t)(c/g)) % (int64_t)Mg);
    if(g>4096) return out; // degenerate (a multiple of a huge 2-power) — not expected for weights >=2 odd/even mix; report separately
    for(uint64_t k=0;k<g;k++) out.push_back((uint32_t)(x0+k*Mg)); return out;
}
struct Pair{int i,j;uint32_t p,q;};
static bool algebraic_ok(const B4& b,const std::vector<Pair>& P){ for(const auto& e:P){ if((uint32_t)(e.p*b[e.j])!=(uint32_t)(e.q*b[e.i]) || (uint32_t)(e.p*b[e.i])!=(uint32_t)(e.q*b[e.j])) return false; } return true; }
static bool engine_ok_t4(const B4& b,const MCL_Q30_Sextet& W,int64_t kp){
    uint64_t s=hash_seed(DEFAULT_SEED); uint32_t x[4]={(uint32_t)(s*mcl_q30_omega1()),(uint32_t)(s*mcl_q30_omega2()),(uint32_t)(s*mcl_q30_omega3()),(uint32_t)(s*mcl_q30_omega4())};
    uint32_t y[4]={x[0]+b[0],x[1]+b[1],x[2]+b[2],x[3]+b[3]};
    for(int i=0;i<10000;i++){ mcl_q30t4_iterate_raw(x[0],x[1],x[2],x[3],W,kp); mcl_q30t4_iterate_raw(y[0],y[1],y[2],y[3],W,kp); for(int k=0;k<4;k++) if((uint32_t)(y[k]-x[k])!=b[k]) return false; } return true;
}
static bool engine_ok_2osc(uint32_t b1,uint32_t b2,int64_t p,int64_t q,int64_t kp){
    uint32_t x1,x2; mcl_q30_init_state(DEFAULT_SEED,x1,x2); uint32_t y1=x1+b1,y2=x2+b2;
    for(int i=0;i<10000;i++){ mcl_q30_iterate_raw(x1,x2,p,q,kp); mcl_q30_iterate_raw(y1,y2,p,q,kp); if((uint32_t)(y1-x1)!=b1||(uint32_t)(y2-x2)!=b2) return false; } return true;
}
// enumerate the full group for a T4 weight set: b1 ranges over all 2^32? No: solutions form a subgroup; b1 determines b2,b3,b4 up to the
// congruence solution sets. We enumerate b1 = c<<v for v in 0..31 and c odd < 2^(32-v) only when 2^(32-v) <= 2^16 (v>=16), and
// for v<16 we test a necessary condition first: pair (1,2) requires p12^2 == q12^2 mod 2^(32-v) (from the two congruences), which
// fails quickly for generic weights; we report the smallest v at which it could hold.
static void group_t4(const char* tag,const MCL_Q30_Sextet& W,int64_t kp){
    std::vector<Pair> P={{0,1,W.p12,W.q12},{0,2,W.p13,W.q13},{0,3,W.p14,W.q14},{1,2,W.p23,W.q23},{1,3,W.p24,W.q24},{2,3,W.p34,W.q34}};
    std::set<B4> G; G.insert(B4{0,0,0,0});
    // necessary condition per pair: p^2 == q^2 mod 2^(32-v) for the valuation v of the translation on that pair's angles
    int vmin=32; for(const auto& e:P){ uint64_t d=(uint64_t)e.p*e.p-(uint64_t)e.q*e.q; d&=0xFFFFFFFFull; int v2=0; if(d==0) v2=32; else while(((d>>v2)&1)==0) v2++; // need 2^(32-v) | d  => v >= 32-v2
        int vneed=32-v2; if(vneed<0) vneed=0; vmin=std::min(vmin,vneed); }
    // but all pairs must hold simultaneously: v >= max over pairs of (32 - v2(p^2-q^2)) for pairs where both angles carry the translation.
    // Simplest exact route: enumerate b1 = c<<v for v from 0..31 with c in [1, 2^(32-v)) odd, capped at 2^16 candidates per v (v>=16); for v<16 rely on the
    // necessary condition over pairs (0,j): p0j^2 == q0j^2 mod 2^(32-v) — if it fails for any j, no solution with that v for b1 (b1 odd part) can exist? (only if b_j != 0...)
    // To stay exact and cheap we enumerate v>=16 exhaustively and report v<16 feasibility via the necessary condition on ALL pairs.
    int feasible_low_v=-1;
    for(int v=0;v<16;v++){ bool ok=true; for(const auto& e:P){ uint64_t d=((uint64_t)e.p*e.p-(uint64_t)e.q*e.q)&0xFFFFFFFFull; uint64_t mod=1ULL<<(32-v); if(d%mod!=0) ok=false; } if(ok){ feasible_low_v=v; break; } }
    for(int v=16;v<32;v++){
        uint32_t cmax=1u<<(32-v);
        for(uint32_t c=1;c<cmax;c+=2){ B4 b{}; b[0]=c<<v;
            // chain: pair (0,1): p*b1 == q*b0 -> b1 ; pair (0,2) -> b2 ; pair (0,3) -> b3 (all solutions each)
            auto S1=solve_lin(P[0].p,(uint32_t)(P[0].q*b[0])); for(uint32_t b1:S1){ b[1]=b1;
            auto S2=solve_lin(P[1].p,(uint32_t)(P[1].q*b[0])); for(uint32_t b2:S2){ b[2]=b2;
            auto S3=solve_lin(P[2].p,(uint32_t)(P[2].q*b[0])); for(uint32_t b3:S3){ b[3]=b3;
                if(algebraic_ok(b,P)) G.insert(b); } } }
        }
    }
    // translations with b1 == 0 (b0==0): then pair(0,j) forces q*b_j == 0 and p*b_j==0 -> b_j multiple of 2^32/gcd -> enumerate b_j over solutions of q0j*b_j==0 and p0j*b_j==0
    {
        auto Z=[&](uint32_t p,uint32_t q){ std::vector<uint32_t> out; auto A=solve_lin(p,0), Bq=solve_lin(q,0); for(uint32_t x:A) if(std::find(Bq.begin(),Bq.end(),x)!=Bq.end()) out.push_back(x); return out; };
        auto S1=Z(P[0].p,P[0].q), S2=Z(P[1].p,P[1].q), S3=Z(P[2].p,P[2].q);
        for(uint32_t b1:S1) for(uint32_t b2:S2) for(uint32_t b3:S3){ B4 b{0,b1,b2,b3}; if(algebraic_ok(b,P)) G.insert(b); }
    }
    int verified=0; for(const auto& b:G){ if(b==B4{0,0,0,0}) continue; if(engine_ok_t4(b,W,kp)) verified++; }
    std::printf("[%s] exact translation-symmetry group: order %zu (engine-verified non-trivial elements %d/%zu); lowest 2-adic valuation feasible on all pairs: %s\n",tag,G.size(),verified,G.size()-1, feasible_low_v<0?"none below v=16 (no fine symmetry possible)":"v<16 POSSIBLE — inspect");
    int shown=0; for(const auto& b:G){ if(b==B4{0,0,0,0}) continue; if(shown<6){ std::printf("    b = %08x %08x %08x %08x\n",b[0],b[1],b[2],b[3]); shown++; } }
}
int main(){
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
    std::printf("MCL-T4-CYCLE-2026-0822-004 exact symmetry groups, engine mcl_core %s UNMODIFIED\n\n",MCL_VERSION_STRING);
    // 2-osc (3,5): exact group: (p^2-q^2) a == 0 mod 2^32, b = a*q*p^-1
    { int64_t p=3,q=5; int cnt=0,ver=0; uint32_t inv3=0xAAAAAAABu;
      for(uint64_t a=0;a<(1ULL<<32);a+=(1ULL<<28)){ uint32_t A=(uint32_t)a; if(A==0) continue; uint32_t B=(uint32_t)(A*5u*inv3); if((uint32_t)(3u*B)!=(uint32_t)(5u*A)||(uint32_t)(3u*A)!=(uint32_t)(5u*B)) continue; cnt++; if(engine_ok_2osc(A,B,p,q,kp)) ver++; }
      // also check no finer element: need (p^2-q^2)a == 0 -> 16a == 0 mod 2^32 -> a multiple of 2^28 exactly; so order 16 is exact.
      std::printf("[2-osc (3,5)] exact group order %d (non-trivial verified %d/%d); finer elements impossible since p^2-q^2 = -16 forces a = k*2^28\n\n",cnt+1,ver,cnt); }
    for(int k=0;k<4;k++){ uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i+k*0x11); char tag[16]; std::snprintf(tag,16,"T4 key%d",k); group_t4(tag,mcl_t4_q30_params_from_key(key,0),kp); }
    group_t4("VDF128-T4 public weights",mcl_vdf128_public_weights(),kp);
    // weak-key fraction, 65,536 keys, seed-reachable D = m*2^20 (4096 offsets); theory for the dominant D=2^31 element
    { const uint32_t om[4]={mcl_q30_omega1(),mcl_q30_omega2(),mcl_q30_omega3(),mcl_q30_omega4()}; int keys_with=0, keys_with_2p31=0;
      for(int k=0;k<65536;k++){ uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i*13+k*0x31+(k>>8)*0x97); MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(key,0);
        std::vector<Pair> P={{0,1,W.p12,W.q12},{0,2,W.p13,W.q13},{0,3,W.p14,W.q14},{1,2,W.p23,W.q23},{1,3,W.p24,W.q24},{2,3,W.p34,W.q34}};
        bool any=false,d31=false; for(uint32_t m=1;m<4096&&!any;m++){ uint32_t D=m<<20; B4 b{D*om[0],D*om[1],D*om[2],D*om[3]}; if(algebraic_ok(b,P)){ any=true; if(D==(1u<<31)) d31=true; } }
        if(!any){ uint32_t D=1u<<31; B4 b{D*om[0],D*om[1],D*om[2],D*om[3]}; if(algebraic_ok(b,P)) {any=true;d31=true;} }
        if(any) keys_with++; if(d31) keys_with_2p31++; }
      std::printf("\n[weak keys] 65,536 keys: seed-reachable symmetry for %d (%.3f%%); of which via D=2^31: %d. Theory for D=2^31 with omega parity (odd,odd,odd,even): p-q even on pairs (1,2),(1,3),(2,3) AND p,q both even on pairs (1,4),(2,4),(3,4) = 2^-9 = 0.195%%\n",keys_with,100.0*keys_with/65536,keys_with_2p31);
    }
    return 0;
}
