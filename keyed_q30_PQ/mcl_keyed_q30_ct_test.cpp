/*
 * mcl_keyed_q30_ct_test.cpp -- verification for the constant-time sine (N-1 fix)
 *
 * Proves two things about mcl_q30_sin_ct() / -DMCL_Q30_CONSTANT_TIME_SIN:
 *   (1) BYTE-IDENTITY of the sine primitive: mcl_q30_sin_ct(lut,angle) equals
 *       the fast MCL_Q30_Table::sin_q30(angle) for every one of the 65536
 *       distinct indices (and for sub-index angles, since only bits >=16 count).
 *   (2) BYTE-IDENTITY of the keyed keystream: a T4-Q30 keystream fingerprint,
 *       printed here, must match between a default build and a build with
 *       -DMCL_Q30_CONSTANT_TIME_SIN. The harness compiles this file both ways
 *       and diffs the FP= line.
 *
 * Build (run by the harness):
 *   c++ -std=c++17 -O2 -I .. -I . mcl_keyed_q30_ct_test.cpp -o ct_fast
 *   c++ -std=c++17 -O2 -DMCL_Q30_CONSTANT_TIME_SIN -I .. -I . \
 *       mcl_keyed_q30_ct_test.cpp -o ct_slow
 *   ./ct_fast ; ./ct_slow ; diff their FP= lines
 */
#include "mcl_keyed_q30.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>

// 64-bit FNV-1a over a byte buffer -- a compact keystream fingerprint.
static uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

int main() {
    // ---- (1) sine primitive byte-identity over the full index domain --------
    const MCL_Q30_Table& tab = mcl_q30_table();
    long mism = 0;
    for (uint32_t idx = 0; idx < 65536u; idx++) {
        // exercise several angles that share this top-16-bit index; all must
        // yield the same value in both evaluators.
        for (uint32_t lo : {0u, 1u, 0x8000u, 0xFFFFu}) {
            uint32_t angle = (idx << 16) | lo;
            int32_t a = tab.sin_q30(angle);
            int32_t b = mcl_q30_sin_ct(tab.lut, angle);
            if (a != b) {
                if (mism < 5)
                    std::printf("MISMATCH idx=%u lo=%u fast=%d ct=%d\n",
                                idx, lo, a, b);
                mism++;
            }
        }
    }
    std::printf("sine-primitive: %s (%ld mismatches over 65536*4 angles)\n",
                mism == 0 ? "BYTE-IDENTICAL" : "FAILED", mism);

    // ---- (2) keyed T4-Q30 keystream fingerprint -----------------------------
    // Fixed key + challenge + seed so the fingerprint is reproducible and can be
    // compared across the fast and constant-time builds.
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA3 ^ (i * 7 + 11));
    MCL_T4_Q30 eng(key, /*challenge=*/0x0123456789ABCDEFULL,
                   /*seed=*/0xC0FFEEULL, /*K=*/K_DEFAULT);
    uint8_t ks[4096];
    eng.gen_bytes(ks, sizeof(ks));
    uint64_t fp = fnv1a(ks, sizeof(ks));

#if defined(MCL_Q30_CONSTANT_TIME_SIN)
    const char* mode = "CONSTANT_TIME";
#else
    const char* mode = "FAST_LUT     ";
#endif
    std::printf("FP=%016llx  mode=%s  first8=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                (unsigned long long)fp, mode,
                ks[0], ks[1], ks[2], ks[3], ks[4], ks[5], ks[6], ks[7]);

    return (mism == 0) ? 0 : 1;
}
