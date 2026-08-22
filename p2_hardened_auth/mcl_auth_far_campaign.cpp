/*
 * ============================================================================
 * mcl_auth_far_campaign.cpp — Paper-2 §VI FAR campaign on the HARDENED (v2)
 *                             challenge-response profile
 * Doc ID: MCL-P2-FAR-2026-0821-001
 * ============================================================================
 * WHY
 *   The published §VI FAR figure (10^8 trials, zero collisions) was measured
 *   on the v1 profile: 64-bit folded challenge, raw engine response as the
 *   transcript. The hardened v2 profile (mcl_auth_hardened.cpp) changes BOTH
 *   the challenge derivation (full-width ctx -> SHA-256 -> seed) and the
 *   transcript (HMAC wrap). Its 12/12 protocol-logic battery proves the
 *   lifecycle properties but produces no FAR number. This campaign produces
 *   the number, at two layers:
 *
 *   LAYER A (engine, direct successor to the published campaign):
 *       Attacker holds a WRONG parameter pair (p',q') != (p,q) and computes
 *       the raw 32-byte engine response for the same context. Measure exact
 *       32-byte collisions, plus the Hamming-distance distribution against
 *       the true response and the byte-frequency chi^2 of forged responses.
 *       This is the chaotic-sensitivity claim itself.
 *
 *   LAYER B (protocol, worst case for the defender):
 *       The attacker is additionally GIVEN K_wrap (i.e. transport secrecy is
 *       assumed already lost) and forges the full R = HMAC(K_wrap, ctx||raw').
 *       Measure acceptance against the true R. This isolates the residual
 *       security contributed by the device parameters alone.
 *
 *   Also measured: FRR / determinism (the true response recomputed R times
 *   must be bit-identical — the paper's structural-zero-FRR claim).
 *
 * DETERMINISM
 *   Trial i draws (p_i, q_i) from SHA-256(campaign_tag || LE64(i)), so the
 *   trial set is independent of thread scheduling and the run is exactly
 *   reproducible. Threads partition the trial index space only.
 *
 * STAGING
 *   argv[1] = trials (default 1e6), argv[2] = threads (default hw-1).
 *   The full 10^8 stage is the same binary with a larger argument.
 *
 * Build: clang++ -std=c++17 -O3 -DNDEBUG mcl_auth_far_campaign.cpp \
 *              -o mcl_auth_far_campaign
 * ============================================================================
 */
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Key256 = std::array<uint8_t, 32>;
using clk = std::chrono::high_resolution_clock;

static void sha256(const uint8_t* m, size_t n, uint8_t out[32]) { CC_SHA256(m, (CC_LONG)n, out); }
static void hmac256(const Key256& k, const uint8_t* m, size_t n, uint8_t out[32]) {
    CCHmac(kCCHmacAlgSHA256, k.data(), k.size(), m, n, out);
}
static void put_u64(Bytes& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8 * i)));
}

// Deployment range per Paper 2 §X.B recommended minimum N = 1e9.
static const int64_t RANGE_LO = 2, RANGE_HI = 1000000000LL;

// Deterministic trial parameters: (p_i, q_i) from SHA-256(tag || LE64(i)).
static void trial_params(uint64_t i, int64_t& p, int64_t& q) {
    uint8_t buf[32 + 8];
    static const char* tag = "MCL-P2-FAR-2026-0821-001 trial ";
    std::memcpy(buf, tag, 31); buf[31] = 0;
    for (int k = 0; k < 8; k++) buf[32 + k] = (uint8_t)(i >> (k * 8));
    uint8_t h[32]; sha256(buf, sizeof(buf), h);
    uint64_t a = 0, b = 0;
    for (int k = 0; k < 8; k++) { a |= (uint64_t)h[k] << (k * 8); b |= (uint64_t)h[8 + k] << (k * 8); }
    const uint64_t span = (uint64_t)(RANGE_HI - RANGE_LO);
    p = RANGE_LO + (int64_t)(a % span);
    q = RANGE_LO + (int64_t)(b % span);
    if (p == q) q = RANGE_LO + ((q - RANGE_LO + 1) % (int64_t)span);
}

// Hardened v2 context and response (identical construction to mcl_auth_hardened.cpp).
struct Ctx { Bytes bytes; uint64_t seed; };
static Ctx build_ctx(const std::array<uint64_t, 4>& C, uint64_t imsi, uint64_t verifier) {
    Ctx c; for (uint64_t w : C) put_u64(c.bytes, w);
    put_u64(c.bytes, imsi); put_u64(c.bytes, verifier);
    uint8_t h[32]; sha256(c.bytes.data(), c.bytes.size(), h);
    uint64_t s = 0; std::memcpy(&s, h, 8); c.seed = s | 1;
    return c;
}
static void raw_response(const Ctx& c, int64_t p, int64_t q, uint8_t out[32]) {
    MCL_T2 eng(c.seed, p, q, K_DEFAULT);
    eng.gen_bytes(out, 32);
}
static void wrapped(const Key256& kw, const Ctx& c, const uint8_t raw[32], uint8_t out[32]) {
    Bytes m = c.bytes; m.insert(m.end(), raw, raw + 32);
    hmac256(kw, m.data(), m.size(), out);
}

int main(int argc, char** argv) {
    const uint64_t TRIALS = (argc > 1) ? std::strtoull(argv[1], nullptr, 10) : 1000000ull;
    unsigned hw = std::thread::hardware_concurrency();
    const unsigned THREADS = (argc > 2) ? (unsigned)std::atoi(argv[2]) : (hw > 2 ? hw - 2 : 1);

    // Enrolled device and session context (fixed, published in the record).
    const int64_t P_TRUE = 3, Q_TRUE = 5;
    const uint64_t IMSI = 0x62A001, VERIFIER = 0x5601;
    const std::array<uint64_t, 4> C = {0x0123456789ABCDEFull, 0xFEDCBA9876543210ull,
                                       0x0F1E2D3C4B5A6978ull, 0x8796A5B4C3D2E1F0ull};
    Key256 kwrap; for (int i = 0; i < 32; i++) kwrap[i] = (uint8_t)(0xA0 + i);

    Ctx ctx = build_ctx(C, IMSI, VERIFIER);
    uint8_t raw_true[32], R_true[32];
    raw_response(ctx, P_TRUE, Q_TRUE, raw_true);
    wrapped(kwrap, ctx, raw_true, R_true);

    std::printf("================================================================\n");
    std::printf("  Paper-2 FAR campaign on the HARDENED (v2) profile\n");
    std::printf("  MCL-P2-FAR-2026-0821-001   engine: mcl_core v%s (%s)\n",
                MCL_VERSION_STRING, MCL_VERSION_DATE);
    std::printf("  trials %llu | threads %u | range [2, 1e9) | device (p,q)=(%lld,%lld)\n",
                (unsigned long long)TRIALS, THREADS, (long long)P_TRUE, (long long)Q_TRUE);
    std::printf("  ctx seed 0x%016llx | true raw %02x%02x%02x%02x | true R %02x%02x%02x%02x\n",
                (unsigned long long)ctx.seed, raw_true[0], raw_true[1], raw_true[2], raw_true[3],
                R_true[0], R_true[1], R_true[2], R_true[3]);
    std::printf("================================================================\n\n");

    // ---- FRR / determinism gate: recompute the true response 1000 times ----
    {
        int mismatches = 0;
        for (int r = 0; r < 1000; r++) {
            uint8_t t[32]; raw_response(ctx, P_TRUE, Q_TRUE, t);
            if (std::memcmp(t, raw_true, 32) != 0) mismatches++;
        }
        std::printf("FRR gate: 1000 recomputations, %d mismatches -> FRR = %s\n\n",
                    mismatches, mismatches == 0 ? "0 (structural)" : "NONZERO — INVESTIGATE");
    }

    // ---- Campaign ----------------------------------------------------------
    std::atomic<uint64_t> collisions_A{0}, collisions_B{0}, near_miss{0}, done{0};
    std::vector<std::array<uint64_t, 256>> hists(THREADS);
    std::vector<double> hd_sum(THREADS, 0.0);
    std::vector<int> hd_min(THREADS, 256), hd_max(THREADS, 0);
    for (auto& h : hists) h.fill(0);

    auto t0 = clk::now();
    {
        std::vector<std::thread> th;
        for (unsigned t = 0; t < THREADS; t++) {
            th.emplace_back([&, t]() {
                uint64_t lo = TRIALS * t / THREADS, hi = TRIALS * (t + 1) / THREADS;
                for (uint64_t i = lo; i < hi; i++) {
                    int64_t p, q; trial_params(i, p, q);
                    if (p == P_TRUE && q == Q_TRUE) continue;      // skip the true pair
                    uint8_t raw[32]; raw_response(ctx, p, q, raw);
                    if (std::memcmp(raw, raw_true, 32) == 0) collisions_A++;
                    int hd = 0;
                    for (int b = 0; b < 32; b++)
                        hd += __builtin_popcount((unsigned)(raw[b] ^ raw_true[b]));
                    hd_sum[t] += hd;
                    if (hd < hd_min[t]) hd_min[t] = hd;
                    if (hd > hd_max[t]) hd_max[t] = hd;
                    if (hd <= 32) near_miss++;                     // <=12.5% of 256 bits
                    for (uint8_t b : raw) hists[t][b]++;
                    uint8_t R[32]; wrapped(kwrap, ctx, raw, R);     // attacker knows K_wrap
                    if (std::memcmp(R, R_true, 32) == 0) collisions_B++;
                    if ((++done & 0xFFFF) == 0) {
                        static std::mutex m; std::lock_guard<std::mutex> g(m);
                        std::fprintf(stderr, "\r  progress %.1f%%",
                                     100.0 * (double)done.load() / (double)TRIALS);
                    }
                }
            });
        }
        for (auto& x : th) x.join();
    }
    double wall = std::chrono::duration<double>(clk::now() - t0).count();
    std::fprintf(stderr, "\r                    \r");

    // Aggregate
    double total_hd = 0; int gmin = 256, gmax = 0;
    std::array<uint64_t, 256> hist{}; hist.fill(0);
    for (unsigned t = 0; t < THREADS; t++) {
        total_hd += hd_sum[t];
        gmin = std::min(gmin, hd_min[t]); gmax = std::max(gmax, hd_max[t]);
        for (int b = 0; b < 256; b++) hist[(size_t)b] += hists[t][(size_t)b];
    }
    uint64_t n = TRIALS;
    double mean_hd = total_hd / (double)n;
    double expect = (double)n * 32.0 / 256.0, chi2 = 0;
    for (uint64_t c : hist) { double d = (double)c - expect; chi2 += d * d / expect; }

    std::printf("LAYER A — engine response forgery (wrong (p,q), same context)\n");
    std::printf("  trials                 %llu\n", (unsigned long long)n);
    std::printf("  exact 32-byte collisions  %llu   -> FAR_A = %s\n",
                (unsigned long long)collisions_A.load(),
                collisions_A.load() == 0 ? "0 (< 1/trials)" : "NONZERO");
    std::printf("  Hamming distance to true  mean %.3f/256 (min %d, max %d)\n",
                mean_hd, gmin, gmax);
    std::printf("  near misses (HD <= 32)    %llu\n", (unsigned long long)near_miss.load());
    std::printf("  forged-byte chi2          %.1f (df 255, crit.001 ~330.5)\n", chi2);
    std::printf("\nLAYER B — full protocol forgery, attacker GIVEN K_wrap\n");
    std::printf("  acceptances               %llu   -> FAR_B = %s\n",
                (unsigned long long)collisions_B.load(),
                collisions_B.load() == 0 ? "0 (< 1/trials)" : "NONZERO");
    std::printf("\nwall %.1f s | %.0f trials/s | %.2f us/trial\n",
                wall, (double)n / wall, wall / (double)n * 1e6);
    std::printf("\nInterpretation: FAR_A is the chaotic-parameter sensitivity claim\n"
                "(the direct successor to the published v1 campaign); FAR_B shows the\n"
                "residual protocol security when transport secrecy is already lost.\n"
                "Scale-up: re-run with a larger first argument (10^8 = full stage).\n");
    return (collisions_A.load() == 0 && collisions_B.load() == 0) ? 0 : 1;
}
