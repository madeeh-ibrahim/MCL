// mcl_symmetry_impact.cpp — Doc ID MCL-T4-CYCLE-2026-0822-003 (companion diagnostic)
// Follows mcl_symmetry_check: translation symmetries of the Q30 map exist (2-osc (3,5): order 16;
// keyed T4: order 1/2/4 depending on weight parities).  Question: are they REACHABLE from the
// public seed interface and do they produce OUTPUT relations?
//   hash_seed(s) == s for s <= 2^52, and t_i = s * omega_i mod 2^32 with every omega_i ODD, so
//   seeds s and s + 2^31 give initial states differing by (2^31, 2^31, 2^31, 2^31) — exactly the
//   "all-angles half-turn".  If that translation commutes with the map (iff all six p-q are even),
//   the two seeds have identical XOR-extracted keystreams forever (half-turns cancel in XOR of 4).
// This tool (a) demonstrates it on the real MCL_T4_Q30 for such a key, (b) shows the commit32
// near-collision, (c) measures the weak-key fraction over 4096 random keys (expected 1/64 = 1.56%),
// (d) checks the 2-osc (3,5) group for seed-reachable elements and the raw vdf_compute_q30 relation.
// ADDITIVE: engine untouched. Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_symmetry_impact.cpp -o mcl_symmetry_impact
#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include <cstdio>
#include <vector>
#include <cstring>

static bool all_pq_even(const MCL_Q30_Sextet& W){
    const uint32_t P[6]={W.p12,W.p13,W.p14,W.p23,W.p24,W.p34}, Q[6]={W.q12,W.q13,W.q14,W.q23,W.q24,W.q34};
    for(int e=0;e<6;e++) if(((P[e]-Q[e])&1u)!=0) return false; return true;
}
int main(){
    std::printf("MCL-T4-CYCLE-2026-0822-003  symmetry impact on the SEED interface, engine mcl_core %s UNMODIFIED\n", MCL_VERSION_STRING);
    // omega parities (a seed offset D translates angle i by D*omega_i mod 2^32)
    const uint32_t om[4]={mcl_q30_omega1(),mcl_q30_omega2(),mcl_q30_omega3(),mcl_q30_omega4()};
    std::printf("\nomega_i (32-bit phase increments): %u %u %u %u  parity: %s %s %s %s\n",om[0],om[1],om[2],om[3],om[0]&1?"odd":"EVEN",om[1]&1?"odd":"EVEN",om[2]&1?"odd":"EVEN",om[3]&1?"odd":"EVEN");
    // (c) SEED-REACHABLE symmetries over 4096 keys: D in {k*2^24, k=1..255}; b_i = D*omega_i; all 12 args invariant?
    int keys_with=0, first_key=-1; uint32_t first_D=0; uint8_t firstkey[32]={0}; int hist[9]={0};
    for(int k=0;k<4096;k++){
        uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i*7+k*0x11+(k>>8)); MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(key,0);
        const uint32_t P[6]={W.p12,W.p13,W.p14,W.p23,W.p24,W.p34}, Q[6]={W.q12,W.q13,W.q14,W.q23,W.q24,W.q34}; const int I[6]={0,0,0,1,1,2}, J[6]={1,2,3,2,3,3};
        int cnt=0; uint32_t Dk=0;
        for(uint32_t kk=1;kk<256;kk++){ uint32_t D=kk<<24; uint32_t b[4]; for(int i=0;i<4;i++) b[i]=D*om[i];
            bool alg=true; for(int e=0;e<6&&alg;e++){ if((uint32_t)(P[e]*b[J[e]])!=(uint32_t)(Q[e]*b[I[e]]) || (uint32_t)(P[e]*b[I[e]])!=(uint32_t)(Q[e]*b[J[e]])) alg=false; }
            if(alg){ cnt++; if(!Dk) Dk=D; } }
        if(cnt){ keys_with++; if(first_key<0){ first_key=k; first_D=Dk; std::memcpy(firstkey,key,32);} }
        hist[cnt>8?8:cnt]++;
    }
    std::printf("(c) keys with >=1 seed-reachable translation symmetry (D multiple of 2^24): %d / 4096 = %.3f%%; histogram of #symmetric offsets per key [0,1,2,..,8+]:",keys_with,100.0*keys_with/4096);
    for(int i=0;i<9;i++) std::printf(" %d",hist[i]); std::printf("\n");
    if(first_key>=0){
        const uint64_t s=DEFAULT_SEED, s2=DEFAULT_SEED+first_D;
        MCL_T4_Q30 e1(firstkey,0,s,K_DEFAULT), e2(firstkey,0,s2,K_DEFAULT);
        // state relation after burn-in: difference must be the constant translation
        uint32_t d1=e2.s1()-e1.s1(), d2=e2.s2()-e1.s2(), d3=e2.s3()-e1.s3(), d4=e2.s4()-e1.s4();
        std::printf("(a) key #%d, seed offset D=0x%08x: post-burn-in state difference = (%08x %08x %08x %08x); predicted b_i=D*omega_i = (%08x %08x %08x %08x) => %s\n",
            first_key,first_D,d1,d2,d3,d4,first_D*om[0],first_D*om[1],first_D*om[2],first_D*om[3],(d1==first_D*om[0]&&d2==first_D*om[1]&&d3==first_D*om[2]&&d4==first_D*om[3])?"SYMMETRY CONFIRMED ON THE REAL ENGINE (constant state offset forever)":"not a symmetry");
        std::vector<uint8_t> a(65536),b(65536); e1.gen_bytes(a.data(),65536); e2.gen_bytes(b.data(),65536);
        size_t diff=0; int xorhist[256]={0}; for(size_t i=0;i<a.size();i++){ diff+=(a[i]!=b[i]); xorhist[a[i]^b[i]]++; }
        int maxv=0,maxx=0; for(int x=0;x<256;x++) if(xorhist[x]>maxv){maxv=xorhist[x];maxx=x;}
        std::printf("    gen_bytes: %zu / 65536 bytes differ; most frequent byte-XOR value 0x%02x occurs %d times (uniform would be ~256) => %s\n",diff,maxx,maxv,maxv>2000?"STRUCTURED KEYSTREAM RELATION (related-seed distinguisher)":"no byte-level constant relation (translation is not a half-turn pattern)");
        MCL_T4_Q30 c1(firstkey,0,s,K_DEFAULT), c2(firstkey,0,s2,K_DEFAULT); uint8_t o1[32],o2[32]; c1.commit32(o1); c2.commit32(o2);
        int hd=0; for(int i=0;i<32;i++) hd+=__builtin_popcount(o1[i]^o2[i]);
        std::printf("(b) commit32 raw for the two seeds: Hamming distance %d / 256 (random ~128; small/structured = related-seed relation in the raw interface)\n",hd);
    }
    // (d) 2-osc (3,5): seed-reachable symmetry?  translation must equal (D*omega1, D*omega2) mod 2^32 for some D
    {
        const uint32_t w1=mcl_q30_omega1(), w2=mcl_q30_omega2(); int hits=0; uint32_t Dfound=0;
        for(uint32_t k=1;k<16;k++){ uint32_t a=k<<28; // group elements have a = k*2^28, b = a*q*p^-1 mod 2^32 (p=3,q=5): b = a*5*inv3
            // inv3 mod 2^32
            uint32_t inv3=0xAAAAAAABu; uint32_t b=(uint32_t)(a*5u*inv3);
            // solve D*w1 == a (w1 odd => invertible): D = a * w1^-1
            uint32_t D=0; bool okD=false;
            if(w1&1u){ uint32_t x=w1; for(int i=0;i<5;i++) x*=2u-w1*x; D=a*x; okD=((uint32_t)(D*w1)==a); }
            else { for(uint64_t t=0;t<(1ULL<<32)&&!okD;t+=(1ULL<<24)){ if((uint32_t)((uint32_t)t*w1)==a){ D=(uint32_t)t; okD=true; } } }  // even omega1: search multiples of 2^24
            if(okD && (uint32_t)(D*w2)==b){ hits++; Dfound=D; std::printf("(d) 2-osc: seed offset D=%u (0x%08x) realises group element (a=%08x,b=%08x)\n",D,D,a,b); }
        }
        std::printf("(d) 2-osc (3,5): seed-reachable non-trivial symmetries: %d of 15\n",hits);
        if(hits){
            uint64_t s=DEFAULT_SEED, s2=DEFAULT_SEED+Dfound; VDFResult r1=vdf_compute_q30(s,3,5,100000), r2=vdf_compute_q30(s2,3,5,100000);
            int hd=0; for(int i=0;i<32;i++) hd+=__builtin_popcount(r1.output[i]^r2.output[i]);
            // verify the word-level relation: each t1 word differs by a, each t2 word by b (mod 2^32)
            bool rel=true; for(int blk=0;blk<4;blk++){ uint32_t x1=0,x2=0,y1=0,y2=0; for(int k=0;k<4;k++){ x1|=(uint32_t)r1.output[blk*8+k]<<(8*k); x2|=(uint32_t)r1.output[blk*8+4+k]<<(8*k); y1|=(uint32_t)r2.output[blk*8+k]<<(8*k); y2|=(uint32_t)r2.output[blk*8+4+k]<<(8*k);} if((uint32_t)(y1-x1)!=(uint32_t)(Dfound*w1) || (uint32_t)(y2-x2)!=(uint32_t)(Dfound*w2)) rel=false; }
            std::printf("    vdf_compute_q30(seed) vs vdf_compute_q30(seed+D), N=1e5: Hamming distance %d / 256; word relation t1'=t1+a, t2'=t2+b in all 4 blocks: %s\n",hd,rel?"HOLDS (related-input relation in the raw 2-osc VDF output)":"does not hold");
            // and for the verifier path: vdf_verify_q30 accepts the translated output for the translated seed trivially; relation lets an attacker derive output(seed+D) from output(seed) WITHOUT recomputation
            std::printf("    consequence: output(seed+D) is derivable from output(seed) by adding constants -- the sequential-work assumption fails for the 15 related inputs of every seed on the raw 2-osc path (superseded in P4 by VDF128-T4 + SHA finalisation; vdf_compute_q30 API still exists)\n");
        }
    }
    return 0;
}
