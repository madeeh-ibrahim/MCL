/*
 * ============================================================================
 * mcl_auth_avalanche.cpp — Paper-2 §VI challenge-avalanche + response
 *                          distribution at campaign scale (hardened v2)
 * Doc ID: MCL-P2-AVAL-2026-0821-001
 * ============================================================================
 * WHY
 *   Test-list item 3: the published avalanche/distribution figures were taken
 *   on the v1 profile, and the hardened-profile battery (mcl_auth_hardened)
 *   measured only 2,000 samples — enough to prove the protocol logic, not
 *   enough to publish. This binary measures, at campaign scale:
 *     (1) CHALLENGE avalanche: flip one bit of the 256-bit challenge and
 *         measure the Hamming distance of the wrapped response R, and
 *         separately of the RAW engine response (so the engine's own
 *         sensitivity is visible, not just the HMAC's);
 *     (2) per-bit-position bias: for each of the 256 response bit positions,
 *         the fraction of trials in which it flipped (ideal 0.5) — a strictly
 *         stronger check than the mean, and the one a TIFS referee expects;
 *     (3) byte-frequency chi^2 of the responses;
 *     (4) a negative control: identical challenge -> HD must be exactly 0.
 *
 * DETERMINISM: trial i derives its challenge and flip position from
 *   SHA-256(tag || LE64(i)); thread partitioning does not affect the result.
 *
 * Build: clang++ -std=c++17 -O3 -DNDEBUG mcl_auth_avalanche.cpp -o mcl_auth_avalanche
 * Usage: ./mcl_auth_avalanche [trials=1000000] [threads=hw-2]
 * ============================================================================
 */
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Key256 = std::array<uint8_t, 32>;
using clk = std::chrono::high_resolution_clock;

static void sha256(const uint8_t* m, size_t n, uint8_t o[32]) { CC_SHA256(m, (CC_LONG)n, o); }
static void hmac256(const Key256& k, const uint8_t* m, size_t n, uint8_t o[32]) {
    CCHmac(kCCHmacAlgSHA256, k.data(), k.size(), m, n, o);
}
static void put_u64(Bytes& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8 * i)));
}

struct Trial { std::array<uint64_t, 4> C; int flip_bit; };
static Trial trial_of(uint64_t i) {
    uint8_t buf[32 + 8];
    static const char* tag = "MCL-P2-AVAL-2026-0821-001 trial";
    std::memcpy(buf, tag, 31); buf[31] = 0;
    for (int k = 0; k < 8; k++) buf[32 + k] = (uint8_t)(i >> (k * 8));
    uint8_t h[32]; sha256(buf, sizeof(buf), h);
    Trial t{};
    for (int w = 0; w < 4; w++) {
        uint64_t v = 0;
        for (int k = 0; k < 8; k++) v |= (uint64_t)h[w * 8 + k] << (k * 8);
        t.C[(size_t)w] = v;
    }
    t.flip_bit = (int)(h[0] ^ (h[31] << 1)) & 255;      // 0..255
    return t;
}

static void responses(const std::array<uint64_t, 4>& C, uint64_t imsi, uint64_t verifier,
                      int64_t p, int64_t q, const Key256& kw,
                      uint8_t raw_out[32], uint8_t R_out[32]) {
    Bytes ctx; for (uint64_t w : C) put_u64(ctx, w);
    put_u64(ctx, imsi); put_u64(ctx, verifier);
    uint8_t h[32]; sha256(ctx.data(), ctx.size(), h);
    uint64_t seed = 0; std::memcpy(&seed, h, 8); seed |= 1;
    { MCL_T2 eng(seed, p, q, K_DEFAULT); eng.gen_bytes(raw_out, 32); }
    Bytes m = ctx; m.insert(m.end(), raw_out, raw_out + 32);
    hmac256(kw, m.data(), m.size(), R_out);
}

int main(int argc, char** argv) {
    const uint64_t TRIALS = (argc > 1) ? std::strtoull(argv[1], nullptr, 10) : 1000000ull;
    unsigned hw = std::thread::hardware_concurrency();
    const unsigned THREADS = (argc > 2) ? (unsigned)std::atoi(argv[2]) : (hw > 2 ? hw - 2 : 1);
    const int64_t P = 3, Q = 5;
    const uint64_t IMSI = 0x62A001, VERIFIER = 0x5601;
    Key256 kw; for (int i = 0; i < 32; i++) kw[i] = (uint8_t)(0xA0 + i);

    std::printf("================================================================\n");
    std::printf("  Paper-2 challenge-avalanche at campaign scale (hardened v2)\n");
    std::printf("  MCL-P2-AVAL-2026-0821-001   engine: mcl_core v%s\n", MCL_VERSION_STRING);
    std::printf("  trials %llu | threads %u | device (p,q)=(%lld,%lld)\n",
                (unsigned long long)TRIALS, THREADS, (long long)P, (long long)Q);
    std::printf("================================================================\n\n");

    // negative control
    {
        uint8_t r1[32], R1[32], r2[32], R2[32];
        Trial t = trial_of(0);
        responses(t.C, IMSI, VERIFIER, P, Q, kw, r1, R1);
        responses(t.C, IMSI, VERIFIER, P, Q, kw, r2, R2);
        int hd = 0; for (int b = 0; b < 32; b++) hd += __builtin_popcount((unsigned)(R1[b]^R2[b]));
        std::printf("negative control (identical challenge): HD = %d/256 (expect 0)\n\n", hd);
    }

    std::vector<double> sumR(THREADS, 0.0), sumRaw(THREADS, 0.0);
    std::vector<int> minR(THREADS, 256), maxR(THREADS, 0);
    std::vector<int> minRaw(THREADS, 256), maxRaw(THREADS, 0);
    std::vector<std::array<uint64_t, 256>> bitflip(THREADS), hist(THREADS);
    for (auto& a : bitflip) a.fill(0);
    for (auto& a : hist) a.fill(0);

    auto t0 = clk::now();
    {
        std::vector<std::thread> th;
        for (unsigned t = 0; t < THREADS; t++) {
            th.emplace_back([&, t]() {
                uint64_t lo = TRIALS * t / THREADS, hi = TRIALS * (t + 1) / THREADS;
                for (uint64_t i = lo; i < hi; i++) {
                    Trial tr = trial_of(i);
                    uint8_t raw1[32], R1[32], raw2[32], R2[32];
                    responses(tr.C, IMSI, VERIFIER, P, Q, kw, raw1, R1);
                    auto Cf = tr.C;
                    Cf[(size_t)(tr.flip_bit / 64)] ^= (1ull << (tr.flip_bit % 64));
                    responses(Cf, IMSI, VERIFIER, P, Q, kw, raw2, R2);
                    int hR = 0, hRaw = 0;
                    for (int b = 0; b < 32; b++) {
                        uint8_t dR = (uint8_t)(R1[b] ^ R2[b]);
                        hR += __builtin_popcount((unsigned)dR);
                        hRaw += __builtin_popcount((unsigned)(uint8_t)(raw1[b] ^ raw2[b]));
                        for (int k = 0; k < 8; k++)
                            if (dR & (1u << k)) bitflip[t][(size_t)(b * 8 + k)]++;
                        hist[t][R1[b]]++;
                    }
                    sumR[t] += hR; sumRaw[t] += hRaw;
                    if (hR < minR[t]) minR[t] = hR;   if (hR > maxR[t]) maxR[t] = hR;
                    if (hRaw < minRaw[t]) minRaw[t] = hRaw;
                    if (hRaw > maxRaw[t]) maxRaw[t] = hRaw;
                }
            });
        }
        for (auto& x : th) x.join();
    }
    double wall = std::chrono::duration<double>(clk::now() - t0).count();

    double sR = 0, sRaw = 0; int mnR = 256, mxR = 0, mnW = 256, mxW = 0;
    std::array<uint64_t, 256> bf{}, hs{}; bf.fill(0); hs.fill(0);
    for (unsigned t = 0; t < THREADS; t++) {
        sR += sumR[t]; sRaw += sumRaw[t];
        mnR = std::min(mnR, minR[t]); mxR = std::max(mxR, maxR[t]);
        mnW = std::min(mnW, minRaw[t]); mxW = std::max(mxW, maxRaw[t]);
        for (int b = 0; b < 256; b++) { bf[(size_t)b] += bitflip[t][(size_t)b]; hs[(size_t)b] += hist[t][(size_t)b]; }
    }
    double n = (double)TRIALS;
    double meanR = sR / n, meanRaw = sRaw / n;
    // Per-bit flip fractions. The dispersion of each fraction is sigma =
    // sqrt(0.25/n), so an ABSOLUTE band (e.g. +/-0.01) is only meaningful at
    // one n: with 256 positions the expected worst |z| is ~3 regardless of n.
    // We therefore report both the raw fractions and the standardized score,
    // and gate on |z| (and on the aggregate chi^2), not on a fixed width.
    const double sigma_p = std::sqrt(0.25 / n);
    double pmin = 1.0, pmax = 0.0, pchi = 0.0, zmax = 0.0;
    for (uint64_t c : bf) {
        double p = (double)c / n; pmin = std::min(pmin, p); pmax = std::max(pmax, p);
        zmax = std::max(zmax, std::fabs(p - 0.5) / sigma_p);
        double d = (double)c - n * 0.5; pchi += d * d / (n * 0.25);   // chi^2 vs Binomial(n,1/2)
    }
    double expect = n * 32.0 / 256.0, chi2 = 0;
    for (uint64_t c : hs) { double d = (double)c - expect; chi2 += d * d / expect; }

    std::printf("WRAPPED response R (transmitted):\n");
    std::printf("  mean HD  %.4f/256  (min %d, max %d)\n", meanR, mnR, mxR);
    std::printf("  per-bit flip fraction  min %.5f  max %.5f  (ideal 0.5, sigma %.5f)\n",
                pmin, pmax, sigma_p);
    std::printf("  worst per-bit |z|      %.2f  (256 positions; expected worst ~3.0)\n", zmax);
    std::printf("  per-bit chi2 vs Binomial(n,1/2): %.1f (df 256, crit.001 ~331.8)\n", pchi);
    std::printf("  byte-frequency chi2 %.1f (df 255, crit.001 ~330.5)\n", chi2);
    std::printf("\nRAW engine response (device-internal, never transmitted):\n");
    std::printf("  mean HD  %.4f/256  (min %d, max %d)\n", meanRaw, mnW, mxW);
    std::printf("\nwall %.1f s | %.0f trials/s\n", wall, n / wall);

    // Gate: means within 1 bit of 128; worst standardized per-bit deviation
    // below 4.5 (Bonferroni-safe for 256 positions); both chi^2 below their
    // 0.001 critical values. All criteria are n-scaled, none is absolute.
    bool ok = meanR > 127.0 && meanR < 129.0 && meanRaw > 126.0 && meanRaw < 130.0 &&
              zmax < 4.5 && chi2 < 330.5 && pchi < 331.8;
    std::printf("\nVERDICT: %s\n", ok ? "PASS — avalanche and distribution within expectation"
                                      : "REVIEW — a statistic left its expected band");
    return ok ? 0 : 1;
}
