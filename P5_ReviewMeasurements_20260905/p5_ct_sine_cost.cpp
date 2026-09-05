/*
 * p5_ct_sine_cost.cpp — cost of the keyed sidecar's opt-in constant-time sine on the Paper-5 tag (Eq. 3, Q30).
 * The CT evaluator is an oblivious scan of the whole 65,536-entry table per sine (mcl_keyed_q30.hpp,
 * mcl_q30_sin_ct), so a full battery under it is infeasible; this program computes N tags with the SAME
 * derivation as harness v3.2 (trial i: labels MCL-P5-V3-TX/-KEY/-SDV, verifier 1) and prints the per-tag
 * latency and the SHA-256 fingerprint of the concatenated tags. Build twice and compare the fingerprints:
 *   clang++ -std=c++17 -O3 -DNDEBUG -I.. -I../keyed_q30_PQ p5_ct_sine_cost.cpp -o ct_cost_default
 *   clang++ -std=c++17 -O3 -DNDEBUG -DMCL_Q30_CONSTANT_TIME_SIN -I.. -I../keyed_q30_PQ p5_ct_sine_cost.cpp -o ct_cost_ct
 * Doc ID: MCL-P5-CTCOST-2026-0905-001
 */
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>
static const uint64_t PUBLIC_SEED = 12345678901234ULL;
static void trial_bytes(const char* tag, uint64_t i, uint8_t out[32]) {
    uint8_t buf[40]; std::memset(buf, 0, 32); std::strncpy((char*)buf, tag, 31);
    for (int k = 0; k < 8; k++) buf[32 + k] = (uint8_t)(i >> (8 * k));
    mcl_sha256(buf, 40, out);
}
static void put_u64(std::vector<uint8_t>& b, uint64_t v) { for (int k = 0; k < 8; k++) b.push_back((uint8_t)(v >> (8 * k))); }
int main(int argc, char** argv) {
    const int N = argc > 1 ? atoi(argv[1]) : 3;
    std::vector<uint8_t> all;
    double total_ms = 0;
    for (int i = 0; i < N; i++) {
        uint8_t h[32], K[32], S[32];
        trial_bytes("MCL-P5-V3-TX", (uint64_t)i, h);
        std::vector<uint8_t> pre; put_u64(pre, 1); put_u64(pre, (uint64_t)i);
        uint64_t to = 0, val = 0; std::memcpy(&to, h, 8); std::memcpy(&val, h + 8, 8); put_u64(pre, to); put_u64(pre, val);
        put_u64(pre, 16); pre.insert(pre.end(), h + 16, h + 32);
        put_u64(pre, (uint64_t)i); put_u64(pre, 1000 + (uint64_t)0); put_u64(pre, 1);  // nonce, account, verifier
        trial_bytes("MCL-P5-V3-KEY", (uint64_t)0, K); trial_bytes("MCL-P5-V3-SDV", (uint64_t)0, S);
        uint8_t ctx[32]; mcl_sha256(pre.data(), pre.size(), ctx);
        uint8_t keff[32], ktx[32], tag[32];
        auto t0 = std::chrono::steady_clock::now();
        mcl_keff_from_key_device(K, S, keff);
        mcl_kdf256(keff, "MCL-TxChallenge-v1", ctx, 32, ktx, 32);
        { MCL_T4_Q30 eng(ktx, 0, PUBLIC_SEED, K_DEFAULT); eng.gen_bytes(tag, 32); }
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count(); total_ms += ms;
        all.insert(all.end(), tag, tag + 32);
        std::printf("tag %d: %.3f ms\n", i, ms);
    }
    uint8_t fp[32]; mcl_sha256(all.data(), all.size(), fp);
    std::printf("build: %s | tags %d | mean %.3f ms/tag | fingerprint ", 
#if defined(MCL_Q30_CONSTANT_TIME_SIN)
        "CONSTANT-TIME sine (oblivious 65,536-entry scan per sine)",
#else
        "default table lookup",
#endif
        N, total_ms / N);
    for (int k = 0; k < 32; k++) std::printf("%02x", fp[k]); std::printf("\n");
    return 0;
}
