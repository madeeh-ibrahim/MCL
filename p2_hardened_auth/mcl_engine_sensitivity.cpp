/*
 * ============================================================================
 * mcl_engine_sensitivity.cpp — Paper-2 §V.B campaign at the ENGINE LEVEL
 * Doc ID: MCL-P2-ENGSENS-2026-0821-001
 * ============================================================================
 * WHY THIS FILE EXISTS (external review, 2026-08-21, item 2)
 *   The previous re-run fed each attacker candidate (p', q') into a key
 *   derivation function and only the KDF OUTPUT reached the engine. SHA-256
 *   destroys every algebraic relation, so "p ± 1", "preserved sum/product/
 *   ratio", "scaled", "swapped" and "adjacent coprime" all became independent
 *   random parameter pairs: the campaign measured KDF diffusion, not chaotic
 *   parameter sensitivity, while claiming comparability with the published
 *   table — which had measured the engine directly. This file restores the
 *   published experiment's actual meaning: the structured candidate pairs are
 *   fed STRAIGHT TO THE ENGINE with a public seed, so what is measured is the
 *   engine's response sensitivity to structured parameter perturbation.
 *
 * WHAT IS MEASURED
 *     truth = MCL_T2(seed_pub, p,  q,  K).gen_bytes(32)
 *     cand  = MCL_T2(seed_pub, p', q', K').gen_bytes(32)     [strategy-defined]
 *   per strategy: exact 32-byte collisions, Hamming distribution against
 *   truth, near-misses, min/max, and the count of candidates that failed their
 *   own definition (printed, never silently absorbed).
 *
 * SCOPE NOTE (stated, not implied): this is the ENGINE claim. It is NOT the
 *   deployed-protocol claim — the deployed protocol is the keyed twelve-weight
 *   route measured by the companion protocol campaign, where the searchable
 *   secret is a 256-bit key rather than a coupling pair.
 *
 * ENGINE CONTRACT: every candidate is generated inside [2, 1e9) with p != q,
 *   so no candidate can trip the engine's parameter assertions. Devices are
 *   drawn from per-strategy ranges that make each construction feasible AND
 *   keep every derived candidate legal (e.g. p >= 3 where p-1 is used).
 *
 * DETERMINISM: device j and its candidates derive from SHA-256 of a labelled
 *   counter; threads take a fixed stride over j, so results are identical
 *   across runs AND across thread counts.
 *
 * Build: clang++ -std=c++17 -O3 -DNDEBUG mcl_engine_sensitivity.cpp -o mcl_engine_sensitivity
 * Usage: ./mcl_engine_sensitivity [trials_per_strategy=2500000] [threads=7]
 * ============================================================================
 */
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

using clk = std::chrono::high_resolution_clock;
static const int64_t LO = 2, HI = 1000000000LL;
static const uint64_t SEED_PUB = 12345678901234ULL;

static void label_hash(const char* lab, uint64_t a, uint64_t b, uint8_t out[32]) {
    uint8_t buf[48]; std::memset(buf,0,48);
    std::strncpy((char*)buf, lab, 31);
    for (int k=0;k<8;k++){ buf[32+k]=(uint8_t)(a>>(k*8)); buf[40+k]=(uint8_t)(b>>(k*8)); }
    CC_SHA256(buf,sizeof(buf),out);
}
static int64_t span_map(uint64_t v, int64_t lo, int64_t hi){ return lo + (int64_t)(v % (uint64_t)(hi-lo)); }
static int64_t gcd64(int64_t a, int64_t b){ while(b){ int64_t t=a%b; a=b; b=t; } return a<0?-a:a; }

struct Cred { int64_t p, q; };
struct Cand { int64_t p, q; double K; };

// device ranges chosen so BOTH the construction and the engine contract hold
static Cred device_for(int s, uint64_t j) {
    uint8_t h[32]; label_hash("MCL-ENGSENS-DEV", (uint64_t)s, j, h);
    uint64_t a=0,b=0; for(int k=0;k<8;k++){a|=(uint64_t)h[k]<<(k*8); b|=(uint64_t)h[8+k]<<(k*8);}
    Cred c;
    switch (s) {
    case 4:  c.p=span_map(a,LO,HI/2); c.q=span_map(b,LO,HI/2); break;      // sum stays < HI
    case 6:  c.p=span_map(a,LO,HI/4); c.q=span_map(b,LO,HI/4); break;      // k up to 4
    case 15: c.p=span_map(a,LO,HI/2); c.q=span_map(b,LO,HI/2); break;      // 2p, 2q < HI
    case 5:  c.p=2*span_map(a,2,HI/2); c.q=span_map(b,LO,HI/2); break;     // p even -> p/2 >= 2
    case 7: case 8: case 16: case 17:
             c.p=span_map(a,3,HI-1); c.q=span_map(b,3,HI-1); break;        // p-1,q-1 >= 2 ; p+1 < HI
    default: c.p=span_map(a,LO,HI);  c.q=span_map(b,LO,HI);  break;
    }
    if (c.p==c.q) c.q = LO + ((c.q-LO+1) % (HI-LO));
    return c;
}
static int cand_count(int s) {
    switch (s) {
    case 7: case 8: case 11: case 16: return 2;
    case 6: return 3;
    case 5: case 9: case 15: return 1;
    case 17: return 4;                       // four single-bit flips of p
    default: return 4;
    }
}
static Cand candidate(int s, const Cred& d, uint64_t j, int m) {
    uint8_t h[32]; label_hash("MCL-ENGSENS-CAND", (uint64_t)(s*97+m), j, h);
    uint64_t r0=0,r1=0; for(int k=0;k<8;k++){r0|=(uint64_t)h[k]<<(k*8); r1|=(uint64_t)h[8+k]<<(k*8);}
    const double K = K_DEFAULT;
    auto rnd = [&]() -> Cand { int64_t p=span_map(r0,LO,HI), q=span_map(r1,LO,HI);
                               if(p==q) q=LO+((q-LO+1)%(HI-LO)); return {p,q,K}; };
    switch (s) {
    case 1: case 10: return rnd();
    case 2: { int64_t q=span_map(r0,LO,HI); if(q==d.q) q=LO+((q-LO+1)%(HI-LO));
              if(q==d.p) q=LO+((q-LO+2)%(HI-LO)); return {d.p,q,K}; }
    case 3: { int64_t p=span_map(r0,LO,HI); if(p==d.p) p=LO+((p-LO+1)%(HI-LO));
              if(p==d.q) p=LO+((p-LO+2)%(HI-LO)); return {p,d.q,K}; }
    case 4: { int64_t S=d.p+d.q, p=span_map(r0,LO,S-LO), q=S-p;
              if(p==d.p&&q==d.q){p++;q--;} if(p==q){p++;q--;} return {p,q,K}; }
    case 5:  return { d.p/2, 2*d.q, K };
    case 6:  { int64_t k=2+m; return { k*d.p, k*d.q, K }; }
    case 7:  return { m? d.p-1 : d.p+1, d.q, K };
    case 8:  return { d.p, m? d.q-1 : d.q+1, K };
    case 9:  return { d.q, d.p, K };
    case 11: return { d.p, d.q, m? K-0.001 : K+0.001 };
    case 15: return { 2*d.p, 2*d.q, K };
    case 16: { // nearest coprime neighbour, guaranteed legal by the device range
               int64_t cp = d.p + (m? -1 : 1);
               int64_t cq = d.q;
               // walk until coprime and distinct; bounded, always terminates in range
               for (int t=0; t<64 && (gcd64(cp,cq)!=1 || cp==cq); t++) cp += (m? -1 : 1);
               return { cp, cq, K }; }
    case 17: { int bit = (int)(r0 % 30);                    // flip one bit of p
               int64_t p = d.p ^ (int64_t{1} << bit);
               if (p < LO) p += (int64_t{1} << bit);         // keep legal
               if (p >= HI) p -= (int64_t{1} << bit);
               if (p == d.q) p ^= 1;
               if (p == d.p) p ^= 2;
               return { p, d.q, K }; }
    default: return rnd();
    }
}
// definition check; returns false for STRUCTURAL strategies where no algebraic
// definition applies (they are reported as "n/a", never as "100% faithful")
static bool has_definition(int s){ return !(s==12 || s==13 || s==14); }
static bool faithful(int s, const Cred& d, const Cand& c) {
    // every candidate must first be engine-legal
    if (c.p < LO || c.q < LO || c.p >= HI || c.q >= HI || c.p == c.q) return false;
    switch (s) {
    case 1: case 10: return true;
    case 2:  return c.p==d.p && c.q!=d.q;
    case 3:  return c.q==d.q && c.p!=d.p;
    case 4:  return c.p+c.q==d.p+d.q;
    case 5:  return (__int128)c.p*c.q==(__int128)d.p*d.q;
    case 6:  return (__int128)c.p*d.q==(__int128)c.q*d.p && c.p!=d.p;
    case 7:  return c.q==d.q && (c.p==d.p+1||c.p==d.p-1);
    case 8:  return c.p==d.p && (c.q==d.q+1||c.q==d.q-1);
    case 9:  return c.p==d.q && c.q==d.p;
    case 11: return c.p==d.p && c.q==d.q && c.K!=K_DEFAULT;
    case 15: return c.p==2*d.p && c.q==2*d.q;
    case 16: return gcd64(c.p,c.q)==1 && c.q==d.q && c.p!=d.p;
    case 17: return c.q==d.q && __builtin_popcountll((unsigned long long)(c.p^d.p))>=1;
    default: return true;
    }
}
static const char* SNAME[18] = {"",
 "1  random (p',q')","2  correct p, random q'","3  random p', correct q",
 "4  preserved sum p'+q'=p+q","5  preserved product p'q'=pq","6  preserved ratio p'/q'=p/q",
 "7  off-by-one p+-1  [weight neighbour]","8  off-by-one q+-1  [weight neighbour]",
 "9  swapped (q,p)","10 correct K, random (p',q')","11 correct (p,q), K'=K+-0.001",
 "12 previous-session replay  [structural]","13 partial response 128/256  [structural]",
 "14 1000 observed (C,R) then guess  [structural]","15 scaled (2p,2q)",
 "16 nearest adjacent coprime","17 single-BIT flip of p  [weight neighbour]"};

struct Acc { std::atomic<uint64_t> tr{0},su{0},near{0},unf{0}; std::atomic<long long> hs{0};
             std::atomic<int> hmin{256},hmax{0}; };
static void bump(Acc& R,int hd){ R.hs+=hd; if(hd==0)R.su++; if(hd<=32)R.near++;
    int c=R.hmin.load(); while(hd<c&&!R.hmin.compare_exchange_weak(c,hd)){}
    c=R.hmax.load(); while(hd>c&&!R.hmax.compare_exchange_weak(c,hd)){} R.tr++; }

static void run(int s, uint64_t TRIALS, unsigned TH, Acc& R) {
    int C = cand_count(s);
    uint64_t devices = (TRIALS + (uint64_t)C - 1) / (uint64_t)C;
    std::vector<std::thread> th;
    for (unsigned t=0;t<TH;t++) th.emplace_back([&,t]{
        uint8_t truth[32], r[32];
        for (uint64_t j=t;j<devices;j+=TH) {
            Cred d = device_for(s,j);
            { MCL_T2 e(SEED_PUB,d.p,d.q,K_DEFAULT); e.gen_bytes(truth,32); }
            for (int m=0;m<C;m++) {
                Cand c = candidate(s,d,j,m);
                if (has_definition(s) && !faithful(s,d,c)) { R.unf++; continue; }
                if (s==12) {                      // response for another public seed (session)
                    uint8_t h2[32]; label_hash("MCL-ENGSENS-SESS",j,0,h2);
                    uint64_t s2=0; std::memcpy(&s2,h2,8); s2|=1;
                    MCL_T2 e(s2,d.p,d.q,K_DEFAULT); e.gen_bytes(r,32);
                } else if (s==13) { std::memcpy(r,truth,16);
                    uint8_t g[32]; label_hash("MCL-ENGSENS-G13",j,(uint64_t)m,g); std::memcpy(r+16,g,16);
                } else if (s==14) { uint8_t g[32]; label_hash("MCL-ENGSENS-G14",j,(uint64_t)m,g);
                    std::memcpy(r,g,32);
                } else { MCL_T2 e(SEED_PUB,c.p,c.q,c.K); e.gen_bytes(r,32); }
                int hd=0; for(int b=0;b<32;b++) hd+=__builtin_popcount((unsigned)(r[b]^truth[b]));
                bump(R,hd);
            }
        }
    });
    for (auto& x:th) x.join();
}

int main(int argc, char** argv) {
    const uint64_t T = (argc>1)?std::strtoull(argv[1],nullptr,10):2500000ull;
    const unsigned TH = (argc>2)?(unsigned)std::atoi(argv[2]):7u;
    std::printf("================================================================\n");
    std::printf("  Paper-2 SS-V.B campaign at the ENGINE LEVEL (parameter sensitivity)\n");
    std::printf("  MCL-P2-ENGSENS-2026-0821-001   engine mcl_core v%s UNMODIFIED\n", MCL_VERSION_STRING);
    std::printf("  ~%llu trials x 17 strategies | threads %u | parameters fed DIRECTLY to the engine\n",
                (unsigned long long)T, TH);
    std::printf("================================================================\n\n");
    std::printf("%-42s %10s %9s %8s %8s %7s\n","strategy","successes","meanHD","near<=32","min/max","unfaith");
    auto t0=clk::now(); uint64_t TT=0,TS=0,TN=0,TU=0;
    for (int s=1;s<=17;s++) {
        Acc R; run(s,T,TH,R);
        uint64_t tr=R.tr.load();
        std::printf("%-42s %10llu %9.3f %8llu %4d/%-4d %7llu\n", SNAME[s],
            (unsigned long long)R.su.load(), (double)R.hs.load()/(double)tr,
            (unsigned long long)R.near.load(), R.hmin.load(), R.hmax.load(),
            (unsigned long long)R.unf.load());
        std::fflush(stdout);
        TT+=tr; TS+=R.su.load(); TN+=R.near.load(); TU+=R.unf.load();
    }
    double wall=std::chrono::duration<double>(clk::now()-t0).count();
    std::printf("\nTOTAL: %llu successes / %llu trials | near-misses %llu | unfaithful (discarded) %llu\n",
        (unsigned long long)TS,(unsigned long long)TT,(unsigned long long)TN,(unsigned long long)TU);
    std::printf("%.0f s (%.0f trials/s) | CP 95%% UB at 0 successes: per-strategy %.3e, aggregate %.3e\n",
        wall,(double)TT/wall, 3.0/(double)T, 3.0/(double)TT);
    return TS==0?0:1;
}
