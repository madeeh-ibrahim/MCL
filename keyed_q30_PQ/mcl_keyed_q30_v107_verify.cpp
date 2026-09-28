/*
 * ============================================================================
 * MCL Keyed Q30 -- sidecar v1.0.7 -- verification harness
 * ============================================================================
 *
 * Document ID:   MCL-KEYED-Q30-V107-2026-0928-001
 * Version:       1.0.0
 * Date:          September 28, 2026
 * Author:        Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:       madeeh.chaotic.lock@gmail.com
 *
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673,
 *                 PCT/IB2026/058860.
 *
 * PURPOSE: Verify the two additions of sidecar v1.0.7 -- the cascade symmetry
 * check and the opt-in seed rule -- and that the default behaviour is that of
 * v1.0.6.
 *
 * Every expectation below was written before the first run. A row that
 * differs from its expectation fails the run (exit code 1).
 *
 *  [0] The known-answer values of the sidecar (mcl_keyed_q30_self_test).
 *  [1] Default seed rule: the engines reproduce a statement-for-statement
 *      replica of the v1.0.6 rule, byte for byte.
 *  [2] Known-answer values of record.
 *  [3] Cascade key class: rate, check, what the check changes; the criterion
 *      compared with the map itself.
 *  [4] Raw-state relation of the class before and after the check.
 *  [5] Seed interface under the Legacy rule, and the Hashed rule.
 *  [6] seed == 0 is fatal under both rules.
 *  [7] Hashed rule: keystream statistics and known-answer values.
 *
 * The comparison with the bytes of v1.0.6 itself is a separate program,
 * mcl_keyed_q30_v107_dump.cpp, built once against each header.
 *
 * BUILD & RUN (from this file's directory):
 *   c++ -std=c++17 -O3 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
 *       -I.. -o v107_verify mcl_keyed_q30_v107_verify.cpp && ./v107_verify
 *
 * OPTIONS
 *   --keys N    keys sampled in [3] (default 200000)
 * ============================================================================
 */

#include "mcl_keyed_q30.hpp"

#include <cinttypes>
#include <cstdlib>
#include <set>
#include <array>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_total = 0, g_failed = 0;

static void check(bool ok, const char* what) {
    g_total++;
    if (!ok) g_failed++;
    std::printf("    [%s] %s\n", ok ? "PASS" : "FAIL", what);
}

static void test_key(uint32_t i, uint8_t key[32]) {
    // key_i = SHA-256("MCL-Q30H-TEST-KEY" || le32(i))
    uint8_t msg[32];
    const char* lab = "MCL-Q30H-TEST-KEY";   // the key family of this harness
    const size_t n = std::strlen(lab);
    std::memcpy(msg, lab, n);
    for (int b = 0; b < 4; b++) msg[n + (size_t)b] = (uint8_t)(i >> (b * 8));
    mcl_sha256(msg, n + 4, key);
}

static int popcount32(uint32_t x) {
    int c = 0;
    while (x) { x &= x - 1; c++; }
    return c;
}

static int hamming(const uint8_t* a, const uint8_t* b, int n) {
    int c = 0;
    for (int i = 0; i < n; i++) c += popcount32((uint32_t)(a[i] ^ b[i]));
    return c;
}

// The cascade of the sidecar with the four raw (t1, t2) pairs of the
// final serialization returned instead of their SHA-256. Map, schedule and
// order of operations are those of mcl_cascade_q30.
static void cascade_raw(const std::vector<std::pair<int64_t,int64_t> >& ep,
                        uint64_t seed, MCL_Q30_SeedInit mode,
                        uint32_t raw[8]) {
    uint32_t t1, t2;
    mcl_q30_seed_state2(seed, mode, t1, t2);
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const int m = (int)ep.size();
    for (int e = 0; e < m; e++) {
        const int iters = (e == 0) ? MCL_CASCADE_FIRST_EPOCH_ITERS
                                   : MCL_CASCADE_LATER_EPOCH_ITERS;
        for (int i = 0; i < iters; i++)
            mcl_q30_iterate_raw(t1, t2, ep[(size_t)e].first,
                                ep[(size_t)e].second, kp);
    }
    for (int b = 0; b < 4; b++) {
        mcl_q30_iterate_raw(t1, t2, ep[(size_t)(m - 1)].first,
                            ep[(size_t)(m - 1)].second, kp);
        raw[2 * b]     = t1;
        raw[2 * b + 1] = t2;
    }
}

// Statement-for-statement replica of the four-oscillator engine of v1.0.6:
// its seed rule, burn-in, keystream and commitments, from the core functions.
struct T4Replica {
    uint32_t t1, t2, t3, t4;
    MCL_Q30_Sextet w;
    int64_t kp;
    T4Replica(const uint8_t key[32], uint64_t challenge, uint64_t seed)
        : w(mcl_t4_q30_params_from_key(key, challenge)),
          kp(mcl_q30_K_phase(K_DEFAULT)) {
        const uint64_t s = hash_seed(seed);
        t1 = (uint32_t)((s * (uint64_t)mcl_q30_omega1()) & 0xFFFFFFFFULL);
        t2 = (uint32_t)((s * (uint64_t)mcl_q30_omega2()) & 0xFFFFFFFFULL);
        t3 = (uint32_t)((s * (uint64_t)mcl_q30_omega3()) & 0xFFFFFFFFULL);
        t4 = (uint32_t)((s * (uint64_t)mcl_q30_omega4()) & 0xFFFFFFFFULL);
        for (int i = 0; i < BURNIN; i++) mcl_q30t4_iterate_raw(t1, t2, t3, t4, w, kp);
    }
    void bytes(uint8_t* out, int n) {
        for (int i = 0; i < n; i++) {
            for (int d = 0; d < DECIMATION; d++) mcl_q30t4_iterate_raw(t1, t2, t3, t4, w, kp);
            const uint32_t x = t1 ^ t2 ^ t3 ^ t4;
            out[i] = (uint8_t)((x >> 16) ^ (x >> 24));
        }
    }
    void commit32(uint8_t out[32]) {
        for (int b = 0; b < 4; b++) {
            mcl_q30t4_iterate_raw(t1, t2, t3, t4, w, kp);
            for (int k = 0; k < 4; k++) out[b * 8 + k]     = (uint8_t)(t1 >> (k * 8));
            for (int k = 0; k < 4; k++) out[b * 8 + 4 + k] = (uint8_t)((t2 ^ t3 ^ t4) >> (k * 8));
        }
    }
};

// The cascade on an explicit epoch list: replica of the run and of the
// SHA-256 finalization.
static void cascade_out(const std::vector<std::pair<int64_t,int64_t> >& ep,
                        uint64_t seed, MCL_Q30_SeedInit mode, uint8_t out[32]) {
    uint32_t raw[8];
    cascade_raw(ep, seed, mode, raw);
    uint8_t ser[32];
    for (int b = 0; b < 4; b++) {
        for (int k = 0; k < 4; k++) ser[b * 8 + k]     = (uint8_t)(raw[2 * b] >> (k * 8));
        for (int k = 0; k < 4; k++) ser[b * 8 + 4 + k] = (uint8_t)(raw[2 * b + 1] >> (k * 8));
    }
    mcl_sha256(ser, 32, out);
}

// Number of advances of q that lead from the unchecked list to the final one.
static int advances(const std::vector<std::pair<int64_t,int64_t> >& raw,
                    const std::vector<std::pair<int64_t,int64_t> >& fin) {
    const int64_t W_RANGE = (int64_t)((1LL << 30) - 2);
    int64_t q = raw[0].second;
    for (int n = 0; n <= 4096; n++) {
        if (q == fin[0].second) return n;
        q = 2 + ((q - 2 + 1) % W_RANGE);
    }
    return -1;
}

// Engine-level test of one epoch list: does the translation produced by the
// seed offset D commute with the map of EVERY epoch, on `states` random states
// per epoch? Uses the map of the engine only -- no parity argument.
static bool commutes_on_engine(const std::vector<std::pair<int64_t,int64_t> >& ep,
                               uint32_t D, int states, uint64_t& rng) {
    const uint32_t b1 = (uint32_t)(D * mcl_q30_omega1());
    const uint32_t b2 = (uint32_t)(D * mcl_q30_omega2());
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    for (size_t e = 0; e < ep.size(); e++) {
        for (int i = 0; i < states; i++) {
            rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
            uint32_t t1 = (uint32_t)(rng >> 32);
            rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
            uint32_t t2 = (uint32_t)(rng >> 32);
            uint32_t u1 = (uint32_t)(t1 + b1), u2 = (uint32_t)(t2 + b2);
            mcl_q30_iterate_raw(t1, t2, ep[e].first, ep[e].second, kp);
            mcl_q30_iterate_raw(u1, u2, ep[e].first, ep[e].second, kp);
            if ((uint32_t)(u1 - t1) != b1 || (uint32_t)(u2 - t2) != b2) return false;
        }
    }
    return true;
}

// Runs fn in a child process; returns true iff the child died on SIGABRT.
template <typename F>
static bool dies_with_abort(F fn) {
    std::fflush(stdout);
    const pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (std::freopen("/dev/null", "w", stderr) == nullptr) _exit(3);
        fn();
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
}

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);
    long n_keys = 200000;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--keys") == 0 && i + 1 < argc) {
            char* end = nullptr;
            n_keys = std::strtol(argv[++i], &end, 10);
            if (end == nullptr || *end != '\0' || n_keys < 1 || n_keys > 50000000) {
                std::fprintf(stderr, "bad --keys value\n");
                return 2;
            }
        } else {
            std::fprintf(stderr, "usage: %s [--keys N]\n", argv[0]);
            return 2;
        }
    }

    std::printf("================================================================\n");
    std::printf("  MCL KEYED Q30 -- sidecar v1.0.7 verification\n");
    std::printf("  engine %s\n", mcl_version());
    std::printf("  keys sampled in [3]: %ld\n", n_keys);
    std::printf("================================================================\n");

    uint8_t kat_key[32];
    for (int i = 0; i < 32; i++) kat_key[i] = (uint8_t)(i * 7 + 1);

    const uint64_t seeds[6] = {
        DEFAULT_SEED, 1ULL, (1ULL << 31) + 5ULL, (1ULL << 52),
        (1ULL << 52) + 12345ULL, 0xFFFFFFFFFFFFFFFFULL
    };

    // ------------------------------------------------------------------
    std::printf("\n[0] Known-answer values of the sidecar\n");
    check(mcl_keyed_q30_self_test(true), "mcl_keyed_q30_self_test(): six of six");

    // ------------------------------------------------------------------
    std::printf("\n[1] Default seed rule: engines vs a replica of the v1.0.6 rule\n");
    {
        int cmp = 0, bad = 0, bad_explicit = 0;
        for (uint32_t k = 0; k < 64; k++) {
            uint8_t key[32];
            test_key(k, key);
            for (int s = 0; s < 6; s++) {
                const uint64_t ch = (uint64_t)k * 1000003ULL + (uint64_t)s;
                uint8_t a[64], b[64], c[64], ca[32], cb[32], cc[32], oa[32], ob[32];
                {
                    MCL_T4_Q30 e(key, ch, seeds[s]);            // default
                    e.gen_bytes(a, 64); e.commit32(ca); e.commit32_oneway(oa);
                }
                {
                    T4Replica r(key, ch, seeds[s]);             // v1.0.6 rule
                    r.bytes(b, 64); r.commit32(cb);
                    uint8_t raw[32]; r.commit32(raw); mcl_sha256(raw, 32, ob);
                }
                {
                    MCL_T4_Q30 e(key, ch, seeds[s], K_DEFAULT,
                                 MCL_Q30_SeedInit::Legacy);      // explicit
                    e.gen_bytes(c, 64); e.commit32(cc);
                }
                cmp++;
                if (std::memcmp(a, b, 64) != 0 || std::memcmp(ca, cb, 32) != 0
                    || std::memcmp(oa, ob, 32) != 0) bad++;
                if (std::memcmp(a, c, 64) != 0 || std::memcmp(ca, cc, 32) != 0)
                    bad_explicit++;
            }
        }
        std::printf("    four-oscillator: %d comparisons (64 keys x 6 seeds; "
                    "keystream 64 B, commit32, commit32_oneway), %d differ from "
                    "the replica, %d from the explicit Legacy call\n",
                    cmp, bad, bad_explicit);
        check(bad == 0, "MCL_T4_Q30 (default) == replica of the v1.0.6 rule, byte for byte");
        check(bad_explicit == 0, "default == MCL_Q30_SeedInit::Legacy");

        int ccmp = 0, cbad = 0, cbad_explicit = 0;
        for (uint32_t k = 0; k < 64; k++) {
            uint8_t key[32];
            test_key(k, key);
            const std::vector<std::pair<int64_t,int64_t> > ep =
                mcl_cascade_q30_params_from_key(key, MCL_CASCADE_DEFAULT_EPOCHS,
                                                (uint64_t)k);
            for (int s = 0; s < 6; s++) {
                uint8_t a[32], b[32], c[32];
                mcl_cascade_q30(key, a, MCL_CASCADE_DEFAULT_EPOCHS, (uint64_t)k,
                                seeds[s]);
                uint32_t t1, t2;
                mcl_q30_init_state(seeds[s], t1, t2);           // v1.0.6 rule
                uint32_t u1, u2;
                mcl_q30_seed_state2(seeds[s], MCL_Q30_SeedInit::Legacy, u1, u2);
                if (t1 != u1 || t2 != u2) cbad++;
                cascade_out(ep, seeds[s], MCL_Q30_SeedInit::Legacy, b);
                mcl_cascade_q30(key, c, MCL_CASCADE_DEFAULT_EPOCHS, (uint64_t)k,
                                seeds[s], K_DEFAULT, MCL_Q30_SeedInit::Legacy);
                ccmp++;
                if (std::memcmp(a, b, 32) != 0) cbad++;
                if (std::memcmp(a, c, 32) != 0) cbad_explicit++;
            }
        }
        std::printf("    cascade: %d comparisons, %d differ from the replica, "
                    "%d from the explicit Legacy call\n", ccmp, cbad, cbad_explicit);
        check(cbad == 0, "mcl_cascade_q30 (default) == replica on the derived epoch list");
        check(cbad_explicit == 0, "default == MCL_Q30_SeedInit::Legacy (cascade)");
    }

    // ------------------------------------------------------------------
    std::printf("\n[2] Known-answer values of record\n");
    {
        uint8_t a[32], c[32];
        { MCL_T4_Q30 e(kat_key); e.commit32(a); }
        mcl_cascade_q30(kat_key, c);
        const uint32_t ka = compute_crc32(a, 32);
        const uint32_t kc = compute_crc32(c, 32);
        std::printf("    four-oscillator commit CRC-32: 0x%08X\n", ka);
        std::printf("    cascade (m=7)       CRC-32: 0x%08X\n", kc);
        check(ka == 0x58C99E3EU, "four-oscillator commit = 0x58C99E3E");
        check(kc == 0xF7C81BC4U, "cascade = 0xF7C81BC4");
        const int r = advances(mcl_cascade_q30_derive_unchecked(kat_key, 7, 0),
                               mcl_cascade_q30_params_from_key(kat_key, 7, 0));
        std::printf("    advances of q for the KAT key: %d\n", r);
        check(r == 0, "the KAT key is outside the class (0 advances)");
    }

    // ------------------------------------------------------------------
    std::printf("\n[3] Cascade key class over %ld keys (m = 7)\n", n_keys);
    std::vector<uint32_t> weak;
    {
        long symmetric_before = 0, symmetric_after = 0;
        long changed_outside = 0, changed_other_field = 0;
        long both_odd_epochs = 0, epochs = 0;
        int max_steps = 0, min_steps_in_class = 1 << 30;
        long steps_outside = 0;
        long not_coprime = 0, out_of_range = 0, p_eq_q = 0;
        for (long i = 0; i < n_keys; i++) {
            uint8_t key[32];
            test_key((uint32_t)i, key);
            const std::vector<std::pair<int64_t,int64_t> > a =
                mcl_cascade_q30_derive_unchecked(key, 7, 0);
            const std::vector<std::pair<int64_t,int64_t> > b =
                mcl_cascade_q30_params_from_key(key, 7, 0);
            const int steps = advances(a, b);
            for (size_t e = 0; e < a.size(); e++) {
                epochs++;
                if ((a[e].first & 1) && (a[e].second & 1)) both_odd_epochs++;
            }
            const bool sa = mcl_cascade_q30_has_reachable_symmetry(a);
            const bool sb = mcl_cascade_q30_has_reachable_symmetry(b);
            if (sa) { symmetric_before++; weak.push_back((uint32_t)i); }
            if (sb) symmetric_after++;
            if (steps > max_steps) max_steps = steps;
            if (sa && steps < min_steps_in_class) min_steps_in_class = steps;
            if (!sa && steps != 0) steps_outside++;
            bool same = true, only_q0 = true;
            for (size_t e = 0; e < a.size(); e++) {
                if (a[e] != b[e]) {
                    same = false;
                    if (e != 0 || a[e].first != b[e].first) only_q0 = false;
                }
                if (gcd_compute(b[e].first, b[e].second) != 1) not_coprime++;
                if (b[e].first < 2 || b[e].second < 2
                    || b[e].first >= (1LL << 30) || b[e].second >= (1LL << 30))
                    out_of_range++;
                if (b[e].first == b[e].second) p_eq_q++;
            }
            if (!sa && !same) changed_outside++;
            if (sa && (same || !only_q0)) changed_other_field++;
        }
        const double rate = (double)symmetric_before / (double)n_keys;
        const double per_epoch = (double)both_odd_epochs / (double)epochs;
        double expect = (double)n_keys;
        for (int e = 0; e < 7; e++) expect *= per_epoch;
        std::printf("    epochs with p and q both odd: %ld of %ld (%.4f)\n",
                    both_odd_epochs, epochs, per_epoch);
        std::printf("    keys in the class before the check: %ld (%.4f%%); "
                    "expected from the per-epoch rate: %.1f\n",
                    symmetric_before, 100.0 * rate, expect);
        std::printf("    keys in the class after the check:  %ld\n", symmetric_after);
        std::printf("    keys outside the class whose weights changed: %ld\n",
                    changed_outside);
        std::printf("    keys in the class where the change is not q of epoch 0 "
                    "alone: %ld\n", changed_other_field);
        std::printf("    advances of q inside the class: smallest %d, largest %d; "
                    "keys outside the class with an advance: %ld\n",
                    symmetric_before ? min_steps_in_class : 0, max_steps,
                    steps_outside);
        std::printf("    final weights: not coprime %ld, out of range %ld, "
                    "p == q %ld\n", not_coprime, out_of_range, p_eq_q);
        check(symmetric_after == 0, "no key admits the symmetry after the check");
        check(changed_outside == 0, "weights unchanged for every key outside the class");
        check(changed_other_field == 0, "inside the class only q of epoch 0 changes");
        check(not_coprime == 0 && out_of_range == 0 && p_eq_q == 0,
              "final weights stay coprime, distinct and inside [2, 2^30)");
        check(steps_outside == 0 && max_steps <= 64
              && (symmetric_before == 0 || min_steps_in_class >= 1),
              "advances: 0 outside the class, between 1 and 64 inside it");
        if (n_keys >= 100000) {
            // Poisson: observed count within 4 sigma of the expectation
            const double dev = (double)symmetric_before - expect;
            check(dev * dev <= 16.0 * expect + 1.0,
                  "class size agrees with the per-epoch rate (4 sigma)");
            check(symmetric_before > 0, "the class is not empty in this sample");
        }
    }

    std::printf("\n[3b] The criterion against the map (64 random states per epoch)\n");
    {
        uint64_t rng = 0x243F6A8885A308D3ULL;
        // every key of the class, and the first 2000 keys of the sample
        long agree = 0, disagree = 0, in_class = 0, outside = 0;
        long any_D_outside = 0, guarded_any_D = 0;
        std::vector<uint32_t> ids(weak);
        for (uint32_t i = 0; i < 2000 && (long)i < n_keys; i++) {
            bool dup = false;
            for (size_t w = 0; w < weak.size(); w++) if (weak[w] == i) dup = true;
            if (!dup) ids.push_back(i);
        }
        for (size_t k = 0; k < ids.size(); k++) {
            uint8_t key[32];
            test_key(ids[k], key);
            const std::vector<std::pair<int64_t,int64_t> > a =
                mcl_cascade_q30_derive_unchecked(key, 7, 0);
            const bool pred = mcl_cascade_q30_has_reachable_symmetry(a);
            const bool eng = commutes_on_engine(a, 0x80000000U, 64, rng);
            if (pred == eng) agree++; else disagree++;
            if (pred) in_class++; else outside++;
            // the offsets D = 2^k generate every subgroup of Z/2^32: if none of
            // them commutes, no non-zero offset does
            bool any = false;
            for (int j = 0; j < 32; j++)
                if (commutes_on_engine(a, (uint32_t)1u << j, 8, rng)) any = true;
            if (!pred && any) any_D_outside++;
            const std::vector<std::pair<int64_t,int64_t> > b =
                mcl_cascade_q30_params_from_key(key, 7, 0);
            any = false;
            for (int j = 0; j < 32; j++)
                if (commutes_on_engine(b, (uint32_t)1u << j, 8, rng)) any = true;
            if (any) guarded_any_D++;
        }
        std::printf("    epoch lists tested: %zu (%ld in the class, %ld outside)\n",
                    ids.size(), in_class, outside);
        std::printf("    criterion and map agree on D = 2^31: %ld; disagree: %ld\n",
                    agree, disagree);
        std::printf("    lists outside the class for which some D = 2^k commutes: %ld\n",
                    any_D_outside);
        std::printf("    final lists for which some D = 2^k commutes: %ld\n",
                    guarded_any_D);
        check(disagree == 0, "the criterion agrees with the map on every list");
        check(any_D_outside == 0, "outside the class no offset 2^k commutes");
        check(guarded_any_D == 0, "after the check no offset 2^k commutes");
    }

    // ------------------------------------------------------------------
    std::printf("\n[4] Raw-state relation for the keys of the class (%zu keys)\n",
                weak.size());
    {
        const uint64_t s0 = DEFAULT_SEED, s1 = DEFAULT_SEED + (1ULL << 31);
        long translated_before = 0, translated_after = 0, translated_hashed = 0;
        long hd_after = 0, hd_hashed = 0, hd_out_before = 0;
        for (size_t w = 0; w < weak.size(); w++) {
            uint8_t key[32];
            test_key(weak[w], key);
            const std::vector<std::pair<int64_t,int64_t> > a =
                mcl_cascade_q30_derive_unchecked(key, 7, 0);
            const std::vector<std::pair<int64_t,int64_t> > b =
                mcl_cascade_q30_params_from_key(key, 7, 0);
            uint32_t r0[8], r1[8];
            // before: unchecked weights, Legacy seed rule
            cascade_raw(a, s0, MCL_Q30_SeedInit::Legacy, r0);
            cascade_raw(a, s1, MCL_Q30_SeedInit::Legacy, r1);
            bool tr = true;
            for (int i = 0; i < 8; i++)
                if ((uint32_t)(r1[i] - r0[i]) != 0x80000000U) tr = false;
            if (tr) translated_before++;
            uint8_t o0[32], o1[32];
            cascade_out(a, s0, MCL_Q30_SeedInit::Legacy, o0);
            cascade_out(a, s1, MCL_Q30_SeedInit::Legacy, o1);
            hd_out_before += hamming(o0, o1, 32);
            // after: final weights, Legacy seed rule
            cascade_raw(b, s0, MCL_Q30_SeedInit::Legacy, r0);
            cascade_raw(b, s1, MCL_Q30_SeedInit::Legacy, r1);
            tr = true;
            for (int i = 0; i < 8; i++) {
                if ((uint32_t)(r1[i] - r0[i]) != 0x80000000U) tr = false;
                hd_after += popcount32(r0[i] ^ r1[i]);
            }
            if (tr) translated_after++;
            // unchecked weights, Hashed seed rule
            cascade_raw(a, s0, MCL_Q30_SeedInit::Hashed, r0);
            cascade_raw(a, s1, MCL_Q30_SeedInit::Hashed, r1);
            tr = true;
            for (int i = 0; i < 8; i++) {
                if ((uint32_t)(r1[i] - r0[i]) != 0x80000000U) tr = false;
                hd_hashed += popcount32(r0[i] ^ r1[i]);
            }
            if (tr) translated_hashed++;
        }
        const double nk = weak.empty() ? 1.0 : (double)weak.size();
        std::printf("    seeds s = %" PRIu64 " and s + 2^31\n", s0);
        std::printf("    unchecked weights, Legacy seed rule: raw states differ by "
                    "(2^31, 2^31) at all four steps for %ld of %zu keys\n",
                    translated_before, weak.size());
        std::printf("      SHA-256 of those raw states for the two seeds: "
                    "mean distance %.1f of 256 bits\n", (double)hd_out_before / nk);
        std::printf("    final weights, Legacy seed rule    : %ld of %zu; mean "
                    "distance of the raw states %.1f of 256 bits\n",
                    translated_after, weak.size(), (double)hd_after / nk);
        std::printf("    unchecked weights, Hashed seed rule: %ld of %zu; mean "
                    "distance of the raw states %.1f of 256 bits\n",
                    translated_hashed, weak.size(), (double)hd_hashed / nk);
        check(translated_before == (long)weak.size(),
              "before: every key of the class shows the translation");
        check(translated_after == 0, "after the check: none does");
        check(translated_hashed == 0, "Hashed seed rule alone: none does");
        if (weak.size() >= 8) {
            const double ma = (double)hd_after / nk, mh = (double)hd_hashed / nk;
            check(ma > 96.0 && ma < 160.0, "after the check: raw states unrelated (96..160 of 256)");
            check(mh > 96.0 && mh < 160.0, "Hashed rule: raw states unrelated (96..160 of 256)");
        }
    }

    // ------------------------------------------------------------------
    std::printf("\n[5] Seed interface\n");
    {
        // (a) seeds that differ by a multiple of 2^32, all <= 2^52
        int pairs = 0, same_legacy_t4 = 0, same_legacy_c = 0;
        int same_hashed_t4 = 0, same_hashed_c = 0;
        for (int i = 0; i < 16; i++) {
            const uint64_t a = 1000003ULL * (uint64_t)(i + 1);
            const uint64_t b = a + ((uint64_t)(i + 1) << 32);
            uint8_t x[32], y[32];
            { MCL_T4_Q30 e(kat_key, 0, a); e.commit32(x); }
            { MCL_T4_Q30 e(kat_key, 0, b); e.commit32(y); }
            if (std::memcmp(x, y, 32) == 0) same_legacy_t4++;
            mcl_cascade_q30(kat_key, x, 7, 0, a);
            mcl_cascade_q30(kat_key, y, 7, 0, b);
            if (std::memcmp(x, y, 32) == 0) same_legacy_c++;
            { MCL_T4_Q30 e(kat_key, 0, a, K_DEFAULT, MCL_Q30_SeedInit::Hashed); e.commit32(x); }
            { MCL_T4_Q30 e(kat_key, 0, b, K_DEFAULT, MCL_Q30_SeedInit::Hashed); e.commit32(y); }
            if (std::memcmp(x, y, 32) == 0) same_hashed_t4++;
            mcl_cascade_q30(kat_key, x, 7, 0, a, K_DEFAULT, MCL_Q30_SeedInit::Hashed);
            mcl_cascade_q30(kat_key, y, 7, 0, b, K_DEFAULT, MCL_Q30_SeedInit::Hashed);
            if (std::memcmp(x, y, 32) == 0) same_hashed_c++;
            pairs++;
        }
        std::printf("    seed pairs (a, a + k*2^32), all <= 2^52: %d\n", pairs);
        std::printf("    Legacy rule: identical output for %d (four-oscillator) "
                    "and %d (cascade) of %d pairs\n",
                    same_legacy_t4, same_legacy_c, pairs);
        std::printf("    Hashed rule: identical output for %d and %d of %d pairs\n",
                    same_hashed_t4, same_hashed_c, pairs);
        check(same_legacy_t4 == pairs && same_legacy_c == pairs,
              "Legacy rule: only seed mod 2^32 enters (every pair coincides)");
        check(same_hashed_t4 == 0 && same_hashed_c == 0,
              "Hashed rule: no pair coincides");

        // (b) additivity of the initial state in the seed
        int add_legacy = 0, add_hashed = 0, trials = 0;
        for (int i = 0; i < 1000; i++) {
            const uint64_t a = 7919ULL * (uint64_t)(i + 1) + 11ULL;
            const uint64_t b = 104729ULL * (uint64_t)(i + 1) + 5ULL;
            uint32_t ta[4], tb[4], tc[4];
            mcl_q30_seed_state4(a, MCL_Q30_SeedInit::Legacy, ta[0], ta[1], ta[2], ta[3]);
            mcl_q30_seed_state4(b, MCL_Q30_SeedInit::Legacy, tb[0], tb[1], tb[2], tb[3]);
            mcl_q30_seed_state4(a + b, MCL_Q30_SeedInit::Legacy, tc[0], tc[1], tc[2], tc[3]);
            bool ok = true;
            for (int j = 0; j < 4; j++) if ((uint32_t)(ta[j] + tb[j]) != tc[j]) ok = false;
            if (ok) add_legacy++;
            mcl_q30_seed_state4(a, MCL_Q30_SeedInit::Hashed, ta[0], ta[1], ta[2], ta[3]);
            mcl_q30_seed_state4(b, MCL_Q30_SeedInit::Hashed, tb[0], tb[1], tb[2], tb[3]);
            mcl_q30_seed_state4(a + b, MCL_Q30_SeedInit::Hashed, tc[0], tc[1], tc[2], tc[3]);
            ok = true;
            for (int j = 0; j < 4; j++) if ((uint32_t)(ta[j] + tb[j]) != tc[j]) ok = false;
            if (ok) add_hashed++;
            trials++;
        }
        std::printf("    initial state additive in the seed, t(a) + t(b) = t(a + b): "
                    "Legacy rule %d of %d, Hashed rule %d of %d\n",
                    add_legacy, trials, add_hashed, trials);
        check(add_legacy == trials, "Legacy rule: the initial state is linear in the seed");
        check(add_hashed == 0, "Hashed rule: it is not");

        // (c) distinct initial states over 2^20 consecutive seeds
        const uint32_t N = 1u << 20;
        std::set<std::array<uint32_t,4> > s4;
        std::set<std::array<uint32_t,2> > s2;
        for (uint32_t i = 1; i <= N; i++) {
            std::array<uint32_t,4> a4;
            std::array<uint32_t,2> a2;
            mcl_q30_seed_state4((uint64_t)i, MCL_Q30_SeedInit::Hashed,
                                 a4[0], a4[1], a4[2], a4[3]);
            mcl_q30_seed_state2((uint64_t)i, MCL_Q30_SeedInit::Hashed, a2[0], a2[1]);
            s4.insert(a4);
            s2.insert(a2);
        }
        std::printf("    Hashed rule, seeds 1..2^20: %zu distinct 128-bit states, "
                    "%zu distinct 64-bit states\n", s4.size(), s2.size());
        check(s4.size() == (size_t)N && s2.size() == (size_t)N,
              "Hashed rule: 2^20 seeds give 2^20 distinct initial states");

        // (d) avalanche of the hashed rule in the seed
        long flips = 0, bits = 0;
        for (int i = 0; i < 1000; i++) {
            const uint64_t a = 0x9E3779B97F4A7C15ULL * (uint64_t)(i + 1) + 1ULL;
            uint32_t ta[4];
            mcl_q30_seed_state4(a, MCL_Q30_SeedInit::Hashed, ta[0], ta[1], ta[2], ta[3]);
            for (int b = 0; b < 64; b++) {
                const uint64_t a2 = a ^ (1ULL << b);
                if (a2 == 0) continue;
                uint32_t tb[4];
                mcl_q30_seed_state4(a2, MCL_Q30_SeedInit::Hashed, tb[0], tb[1], tb[2], tb[3]);
                for (int j = 0; j < 4; j++) flips += popcount32(ta[j] ^ tb[j]);
                bits += 128;
            }
        }
        const double frac = (double)flips / (double)bits;
        std::printf("    Hashed rule, one seed bit flipped (1000 seeds x 64 bits): "
                    "%.4f of the state bits change\n", frac);
        check(frac > 0.49 && frac < 0.51, "Hashed rule: avalanche within 0.49..0.51");
    }

    // ------------------------------------------------------------------
    std::printf("\n[6] seed == 0\n");
    {
        const bool a = dies_with_abort([&]() {
            uint32_t t[4];
            mcl_q30_seed_state4(0, MCL_Q30_SeedInit::Legacy, t[0], t[1], t[2], t[3]);
        });
        const bool b = dies_with_abort([&]() {
            uint32_t t[4];
            mcl_q30_seed_state4(0, MCL_Q30_SeedInit::Hashed, t[0], t[1], t[2], t[3]);
        });
        const bool c = dies_with_abort([&]() {
            uint8_t o[32];
            mcl_cascade_q30(kat_key, o, 7, 0, 0, K_DEFAULT, MCL_Q30_SeedInit::Hashed);
        });
        const bool d = dies_with_abort([&]() {
            uint32_t t[4];
            mcl_q30_seed_state4(1, MCL_Q30_SeedInit::Hashed, t[0], t[1], t[2], t[3]);
        });
        std::printf("    aborts: Legacy rule %s, Hashed rule %s, Hashed cascade %s; "
                    "control (seed 1) %s\n", a ? "yes" : "no", b ? "yes" : "no",
                    c ? "yes" : "no", d ? "yes" : "no");
        check(a && b && c, "seed 0 is fatal under both rules");
        check(!d, "control: seed 1 is accepted");
    }

    // ------------------------------------------------------------------
    std::printf("\n[7] Hashed seed rule: statistics and known-answer values\n");
    {
        const int64_t N = 1 << 20;
        std::vector<uint8_t> buf((size_t)N);
        MCL_T4_Q30 e(kat_key, 0, DEFAULT_SEED, K_DEFAULT, MCL_Q30_SeedInit::Hashed);
        e.gen_bytes(buf.data(), N);
        const double chi = chi_square(buf.data(), N);
        const double H = shannon_entropy(buf.data(), N);
        std::printf("    keystream 1 MiB: chi^2 = %.2f (threshold %.2f), "
                    "entropy = %.6f bits/byte\n", chi, CHI2_THRESHOLD, H);
        check(chi < CHI2_THRESHOLD, "chi^2 below the df = 255 threshold");
        check(H > 7.99, "Shannon entropy above 7.99 bits/byte");

        uint8_t a[32], c[32], l[32];
        { MCL_T4_Q30 h(kat_key, 0, DEFAULT_SEED, K_DEFAULT, MCL_Q30_SeedInit::Hashed); h.commit32(a); }
        { MCL_T4_Q30 p(kat_key); p.commit32(l); }
        mcl_cascade_q30(kat_key, c, 7, 0, DEFAULT_SEED, K_DEFAULT,
                        MCL_Q30_SeedInit::Hashed);
        std::printf("    values under the Hashed rule:\n");
        std::printf("      four-oscillator commit CRC-32 = 0x%08X\n", compute_crc32(a, 32));
        std::printf("      cascade (m=7)       CRC-32 = 0x%08X\n", compute_crc32(c, 32));
        std::printf("    distance to the Legacy four-oscillator commit: %d of 256 bits\n",
                    hamming(a, l, 32));
        check(compute_crc32(a, 32) == 0x399183A1U, "Hashed rule, four-oscillator commit = 0x399183A1");
        check(compute_crc32(c, 32) == 0x229E97B8U, "Hashed rule, cascade = 0x229E97B8");
        check(std::memcmp(a, l, 32) != 0, "Hashed rule output differs from the Legacy output");
    }

    std::printf("\n================================================================\n");
    std::printf("  checks: %d, failed: %d\n", g_total, g_failed);
    std::printf("  %s\n", g_failed == 0 ? "ALL EXPECTATIONS MET"
                                        : "AT LEAST ONE EXPECTATION FAILED");
    std::printf("================================================================\n");
    return g_failed == 0 ? 0 : 1;
}
