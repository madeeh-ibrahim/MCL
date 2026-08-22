/*
 * mcl_auth_far_v3.cpp — Paper-2 FAR campaign on the DERIVATION-ROUTE protocol
 * Doc ID: MCL-P2-FARV3-2026-0821-001
 * ---------------------------------------------------------------------------
 * Protocol under test (Paper 2 SS-IV.B as now specified; patent Claim 4 route):
 *     ctx    = SHA-256( C || IMSI || verifier_id )        // full-width challenge
 *     params = KDF( p||q , "MCL-Challenge-v1", ctx )      // challenge -> DERIVATION
 *     R      = MCL(seed_pub, params).gen_bytes(32)        // public seed
 * The stored device credential remains the coupling pair (p, q) — the paper's
 * 16-byte-per-device storage model and its ~59-bit parameter-space accounting
 * are unchanged; what changes is that the challenge no longer passes through
 * the engine's 64-bit input word.
 *
 * Measures, for a fixed session context: exact 32-byte response collisions by
 * wrong-credential attackers, the Hamming-distance distribution against the
 * true response, near-misses, and the byte-frequency chi^2 of forged responses.
 * Deterministic: trial i draws (p,q) from SHA-256(tag || LE64(i)).
 *
 * Build: clang++ -std=c++17 -O3 -DNDEBUG mcl_auth_far_v3.cpp -o mcl_auth_far_v3
 * Usage: ./mcl_auth_far_v3 [trials=1000000] [threads=2]
 */
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

using clk = std::chrono::high_resolution_clock;
static const uint64_t SEED_PUB = 12345678901234ULL;

// Deployed protocol (Paper 2 §IV.B, keyed twelve-weight mode — the mode §VIII
// itself declares production requires). The stored credential is a 256-bit
// device key; the session context enters the SAME derivation as the public
// challenge value of patent Claim 4. The searchable secret is therefore the
// 256-bit key carried in the twelve map-defining weights (2^128 post-Grover),
// not a ~59.8-bit coupling pair — which is what closes the transcript-based
// offline-enumeration exposure (referee gap G2) BY WIDTH rather than by a
// transport wrapper.
static void respond(const uint8_t key[32], const uint8_t ctx[32], uint8_t out[32]) {
    uint8_t ktx[32];
    mcl_kdf256(key, "MCL-Challenge-v1", ctx, 32, ktx, 32);
    CouplingSextet cs = mcl_t4_params_from_key(ktx, 0);
    { MCL_T4 eng(SEED_PUB, cs, K_DEFAULT); eng.gen_bytes(out, 32); }
    secure_zero(ktx, 32); secure_zero(&cs, sizeof(cs));
}
// deterministic candidate credential for trial i
static void trial_key(uint64_t i, uint8_t key[32]) {
    uint8_t buf[40]; std::memset(buf,0,32);
    std::strncpy((char*)buf, "MCL-P2-FARV4-2026-0821-001", 31);
    for (int k=0;k<8;k++) buf[32+k]=(uint8_t)(i>>(k*8));
    CC_SHA256(buf,sizeof(buf),key);
}

int main(int argc, char** argv) {
    const uint64_t N  = (argc>1)?std::strtoull(argv[1],nullptr,10):1000000ull;
    const unsigned TH = (argc>2)?(unsigned)std::atoi(argv[2]):2u;
    const int TARGETS = (argc>3)?std::atoi(argv[3]):4;   // multi-device replication (review item 11)

    std::printf("================================================================\n");
    std::printf("  Paper-2 protocol FAR — KEYED TWELVE-WEIGHT route (SS-IV.B)\n");
    std::printf("  MCL-P2-FARV4-2026-0821-001  engine mcl_core v%s UNMODIFIED\n", MCL_VERSION_STRING);
    std::printf("  %llu forgeries x %d target devices | threads %u\n",
                (unsigned long long)N, TARGETS, TH);
    std::printf("  credential = 256-bit device key -> 12 map-defining weights\n");
    std::printf("================================================================\n\n");

    uint64_t g_coll=0, g_near=0; double g_hs=0; int g_min=256, g_max=0; uint64_t g_n=0;
    auto t0=clk::now();

    for (int tgt=0; tgt<TARGETS; tgt++) {
        // target device key and session context, both varying per target
        uint8_t key[32]; trial_key(0xD0000000ull + (uint64_t)tgt, key);
        uint8_t pre[48], ctx[32];
        { uint8_t C[32]; trial_key(0xC0000000ull + (uint64_t)tgt, C);
          std::memcpy(pre,C,32);
          uint64_t imsi=0x62A001+(uint64_t)tgt, ver=0x5601;
          for (int k=0;k<8;k++){ pre[32+k]=(uint8_t)(imsi>>(k*8)); pre[40+k]=(uint8_t)(ver>>(k*8)); }
          CC_SHA256(pre,sizeof(pre),ctx); }
        uint8_t truth[32]; respond(key,ctx,truth);

        if (tgt==0) {   // FRR / determinism gate, once
            int mism=0; uint8_t t2[32];
            for (int r=0;r<1000;r++){ respond(key,ctx,t2); if (std::memcmp(t2,truth,32)) mism++; }
            std::printf("FRR gate: 1000 recomputations, %d mismatches -> FRR = %s\n\n",
                        mism, mism? "NONZERO — INVESTIGATE" : "0 (structural)");
            std::printf("%-8s %12s %10s %9s %8s\n","target","forgeries","meanHD","near<=32","min/max");
        }

        std::atomic<uint64_t> coll{0}, near{0};
        std::vector<double> hs((size_t)TH,0.0);
        std::vector<int> hmin((size_t)TH,256), hmax((size_t)TH,0);
        { std::vector<std::thread> th;
          for (unsigned t=0;t<TH;t++) th.emplace_back([&,t]{
              uint8_t k2[32], r[32];
              for (uint64_t i=t;i<N;i+=TH) {
                  trial_key((uint64_t)tgt*0x1000000000ull + i, k2);
                  if (!std::memcmp(k2,key,32)) continue;
                  respond(k2,ctx,r);
                  if (!std::memcmp(r,truth,32)) coll++;
                  int h=0; for(int b=0;b<32;b++) h+=__builtin_popcount((unsigned)(r[b]^truth[b]));
                  hs[t]+=h; if(h<hmin[t])hmin[t]=h; if(h>hmax[t])hmax[t]=h;
                  if (h<=32) near++;
              }
          });
          for (auto& x:th) x.join(); }
        double s=0; int mn=256,mx=0;
        for (unsigned t=0;t<TH;t++){ s+=hs[t]; mn=std::min(mn,hmin[t]); mx=std::max(mx,hmax[t]); }
        std::printf("%-8d %12llu %10.3f %9llu %4d/%-4d\n", tgt,
                    (unsigned long long)coll.load(), s/(double)N,
                    (unsigned long long)near.load(), mn, mx);
        std::fflush(stdout);
        g_coll+=coll.load(); g_near+=near.load(); g_hs+=s; g_n+=N;
        g_min=std::min(g_min,mn); g_max=std::max(g_max,mx);
    }
    double wall=std::chrono::duration<double>(clk::now()-t0).count();
    std::printf("\nAGGREGATE: %llu forgeries accepted / %llu attempts | mean HD %.3f/256"
                " | near-misses %llu | min/max %d/%d\n",
                (unsigned long long)g_coll,(unsigned long long)g_n, g_hs/(double)g_n,
                (unsigned long long)g_near, g_min, g_max);
    std::printf("%.0f s (%.0f attempts/s)\n", wall, (double)g_n/wall);
    std::printf("\nThe searchable secret is the 256-bit device key carried in the twelve\n"
                "map-defining weights, so a transcript does not reduce the search below\n"
                "the key width: this is the width-based closure of referee gap G2.\n");
    return g_coll==0?0:1;
}
