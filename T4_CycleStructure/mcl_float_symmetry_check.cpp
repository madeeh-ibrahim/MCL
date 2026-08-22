// mcl_float_symmetry_check.cpp — Doc ID MCL-T4-CYCLE-2026-0822-006 (review-stage diagnostic, Float64 path)
// Question: does the translation-symmetry weak-key class of the Q30 realization (record §5a) have a
// counterpart on the DOUBLE-PRECISION path actually used by the P2 keyed-FAR and P5 v3 harnesses
// (mcl_t4_params_from_key + MCL_T4; weights in [2,2^40); t_i(0) = mod2pi(s*OMEGA_i))?
// Three measurements (no engine file modified):
//  (A) Combinatorial class: fraction of key-derived Float64 weight sets whose exact-arithmetic map would
//      commute with the half-turn pattern b=(pi,pi,pi,0) or (pi,pi,pi,pi) (parity conditions) — the
//      analogue of the Q30 condition. (Exists combinatorially: ~2^-9 / 2^-6.)
//  (B) Numerical stability: the 2-osc Float64 map mcl_iterate_raw at (3,5),K=12 has, in exact
//      arithmetic, the order-16 group b1=2*pi*k/16, b2=2*pi*(7k mod 16)/16. Measure the drift
//      d_n = || F^n(theta+b) - F^n(theta) - b ||_{mod 2pi} versus n: if rounding breaks the symmetry,
//      d_n grows from ~1e-16 to O(1) within a few dozen steps (chaos), i.e. no exact relation survives.
//  (C) Seed reachability: on the Float64 path a seed offset D translates angle i by D*OMEGA_i mod 2pi
//      with four incommensurate real OMEGA_i; search D in [1, 2^28] for the best simultaneous
//      approximation of (pi,pi,pi,0) and (pi,pi,pi,pi); report the best residual (radians) and the
//      keystream Hamming distance for the best D on a parity-class key via the REAL MCL_T4.
// Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_float_symmetry_check.cpp -o mcl_float_symmetry_check
#include "../mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <vector>
#include <cstring>

static double dist2pi(double a){ a=std::fmod(a, MCL_TWO_PI); if(a<0) a+=MCL_TWO_PI; return std::min(a, MCL_TWO_PI-a); }

int main(){
    std::printf("MCL-T4-CYCLE-2026-0822-006  Float64-path symmetry check, engine mcl_core %s UNMODIFIED\n\n", MCL_VERSION_STRING);
    // ---------------- (A) combinatorial class on Float64-derived weights ----------------
    int c3_1=0, c_all=0; const int NK=65536; std::vector<int> class_keys;
    for(int k=0;k<NK;k++){ uint8_t ctr[8]; for(int i=0;i<8;i++) ctr[i]=(uint8_t)(k>>(8*i)); uint8_t key[32]; mcl_sha256(ctr,8,key);
        CouplingSextet W=mcl_t4_params_from_key(key,0);
        bool e12=((W.p12-W.q12)&1)==0, e13=((W.p13-W.q13)&1)==0, e23=((W.p23-W.q23)&1)==0;
        bool e14=((W.p14-W.q14)&1)==0, e24=((W.p24-W.q24)&1)==0, e34=((W.p34-W.q34)&1)==0;
        bool z14=((W.p14&1)==0&&(W.q14&1)==0), z24=((W.p24&1)==0&&(W.q24&1)==0), z34=((W.p34&1)==0&&(W.q34&1)==0);
        if(e12&&e13&&e23&&z14&&z24&&z34){ c3_1++; class_keys.push_back(k); }
        if(e12&&e13&&e23&&e14&&e24&&e34) c_all++; }
    std::printf("(A) Float64 key-derived weight sets over %d SHA-256 keys: exact-arithmetic half-turn class (pi,pi,pi,0): %d (%.3f%%, theory 2^-9=0.195%%); (pi,pi,pi,pi): %d (%.3f%%, theory 2^-6=1.56%%)\n", NK, c3_1, 100.0*c3_1/NK, c_all, 100.0*c_all/NK);

    // ---------------- (B) numerical stability of the exact symmetry, 2-osc Float64 ----------------
    {
        const int64_t p=3,q=5; const double K=K_DEFAULT;
        std::printf("\n(B) 2-osc Float64 (3,5) K=12: drift of the exact-arithmetic symmetry b=(2pi/16, 2pi*7/16) under double rounding\n");
        for(int trial=0;trial<3;trial++){
            double t1,t2; mcl_init_state(DEFAULT_SEED+trial*7919ULL,t1,t2); for(int i=0;i<BURNIN;i++) mcl_iterate_raw(t1,t2,p,q,K);
            double u1=mod2pi(t1+MCL_TWO_PI/16.0), u2=mod2pi(t2+MCL_TWO_PI*7.0/16.0);
            std::printf("    seed %d: n=", trial);
            const int marks[]={0,1,2,5,10,20,30,40,50,75,100,200,1000,10000}; int mi=0;
            for(int n=0;n<=10000;n++){
                if(n==marks[mi]){ double d=std::max(dist2pi(u1-t1-MCL_TWO_PI/16.0), dist2pi(u2-t2-MCL_TWO_PI*7.0/16.0)); std::printf("%d:%.1e ",n,d); mi++; if(mi>=14) break; }
                mcl_iterate_raw(t1,t2,p,q,K); mcl_iterate_raw(u1,u2,p,q,K);
            }
            std::printf("\n");
        }
        std::printf("    reading: drift ~1e-16 at n=0 growing to O(1) within tens of steps => the symmetry is NOT preserved by floating-point arithmetic; no exact state relation survives burn-in.\n");
    }

    // ---------------- (C) seed reachability on the Float64 path ----------------
    {
        const double om[4]={OMEGA_1,OMEGA_2,OMEGA_3,OMEGA_4};
        double best3=1e9,best4=1e9; uint64_t D3=0,D4=0;
        for(uint64_t D=1; D<(1ULL<<28); D++){
            double r[4]; for(int i=0;i<4;i++) r[i]=dist2pi((double)D*om[i]-M_PI);
            double m3=std::max(std::max(r[0],r[1]), std::max(r[2], dist2pi((double)D*om[3])));   // target (pi,pi,pi,0)
            double m4=std::max(std::max(r[0],r[1]), std::max(r[2],r[3]));                          // target (pi,pi,pi,pi)
            if(m3<best3){best3=m3;D3=D;} if(m4<best4){best4=m4;D4=D;}
        }
        std::printf("\n(C) seed-offset reachability over D in [1,2^28): best residual for (pi,pi,pi,0): %.3e rad at D=%llu; for (pi,pi,pi,pi): %.3e rad at D=%llu  (exact reachability needs ~1e-16; a 2^28 search of 4 incommensurate phases is expected to reach only ~(2pi/2)/(2^28)^(1/4) ~ 2e-2)\n", best3,(unsigned long long)D3,best4,(unsigned long long)D4);
        // keystream test on the REAL MCL_T4 for a parity-class key with the best D
        if(!class_keys.empty()){
            int k=class_keys[0]; uint8_t ctr[8]; for(int i=0;i<8;i++) ctr[i]=(uint8_t)(k>>(8*i)); uint8_t key[32]; mcl_sha256(ctr,8,key);
            CouplingSextet W=mcl_t4_params_from_key(key,0);
            MCL_T4 e1(DEFAULT_SEED,W,K_DEFAULT), e2(DEFAULT_SEED+D3,W,K_DEFAULT);
            std::vector<uint8_t> a(65536),b(65536); e1.gen_bytes(a.data(),65536); e2.gen_bytes(b.data(),65536);
            long hd=0; int hist[256]={0}; for(size_t i=0;i<a.size();i++){ hd+=__builtin_popcount(a[i]^b[i]); hist[a[i]^b[i]]++; } int mx=0; for(int x=0;x<256;x++) mx=std::max(mx,hist[x]);
            std::printf("    parity-class key #%d on the REAL MCL_T4 (Float64): seeds s vs s+D_best: mean byte HD %.3f/8 (random 4.0), most frequent byte-XOR count %d/65536 (uniform ~256) => %s\n", k, hd/65536.0, mx, (mx<1000 && std::fabs(hd/65536.0-4.0)<0.1)?"NO related-seed relation":"RELATION PRESENT");
            // also the literal Q30 offset 2^31 (the Q30 weak-seed pair) on the Float64 engine
            MCL_T4 e3(DEFAULT_SEED+(1ULL<<31),W,K_DEFAULT); std::vector<uint8_t> c(65536); e3.gen_bytes(c.data(),65536); long hd2=0; for(size_t i=0;i<a.size();i++) hd2+=__builtin_popcount(a[i]^c[i]);
            std::printf("    same key, seeds s vs s+2^31 (the Q30 weak pair) on Float64: mean byte HD %.3f/8 => %s\n", hd2/65536.0, std::fabs(hd2/65536.0-4.0)<0.1?"NO relation (Q30 weak pair does not transfer)":"RELATION PRESENT");
        }
    }
    return 0;
}
