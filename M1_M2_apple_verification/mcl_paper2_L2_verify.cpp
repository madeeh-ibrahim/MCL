// ============================================================================
// mcl_paper2_L2_verify.cpp
// ----------------------------------------------------------------------------
// Deterministic re-measurement of the four Paper-2 (TIFS) numbers whose values
// were traced to the Patent-2-era run and did not match the v6.0.0 archived
// logs. This program measures all four DIRECTLY from the engine of record,
// against the SAME canonical configuration the production tools use
// (DEFAULT_SEED, t2_topos(), K=12), so the results are exactly reproducible.
//
//   (1) §VII.B  multiplex chi-square + Shannon entropy  (N=20 channels x 1e7 B)
//   (2) §VII.B  max channel-to-multiplex |r|  (and the channel-to-channel max,
//               to identify what the paper's "0.000559" actually was)
//   (3) §X.C    next-byte (bigram) prediction accuracy  (vs 1/256 baseline)
//   (4) §IV.C   incorrect-parameter authentication Hamming distance (mean, std)
//
// Build (against the archived v6.0.0 engine that Paper 1 ref [1] pins by MD5):
//   clang++ -O3 -std=c++17 -march=native mcl_paper2_L2_verify.cpp -o mcl_paper2_L2_verify
// Run:
//   ./mcl_paper2_L2_verify | tee paper2_L2_verify_apple_$(date +%Y%m%d).log
//
// Engine: mcl_core.hpp v6.0.0 (this folder; MD5 241db79ecf8a42897eb9a8399cf37929).
// v6.1.0 produces a byte-identical stream (the keyed path is additive), so the
// numbers below are unchanged across the bump.
// ============================================================================
#include "mcl_core.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>
#include <string>

using std::vector;

// ---- byte-distribution statistics ------------------------------------------
static double chi_square_256(const uint8_t* d, int64_t n) {
    int64_t h[256] = {};
    for (int64_t i = 0; i < n; i++) h[d[i]]++;
    const double E = (double)n / 256.0;
    double chi2 = 0.0;
    for (int k = 0; k < 256; k++) {
        const double diff = (double)h[k] - E;
        chi2 += diff * diff / E;
    }
    return chi2;                       // df = 255
}

static double shannon_entropy_256(const uint8_t* d, int64_t n) {
    int64_t h[256] = {};
    for (int64_t i = 0; i < n; i++) h[d[i]]++;
    double H = 0.0;
    for (int k = 0; k < 256; k++) {
        if (!h[k]) continue;
        const double p = (double)h[k] / (double)n;
        H -= p * std::log2(p);
    }
    return H;                          // bits / byte
}

// Pearson correlation: reuse the production engine's pearson_r() (mcl_core.hpp),
// the exact routine the orthogonality/reference tools use, for like-for-like.

// ============================================================================
int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== MCL Paper-2 L2 re-verification (engine v%s, seed %llu, K=%.1f) ===\n",
                MCL_VERSION_STRING, (unsigned long long)DEFAULT_SEED, (double)K_DEFAULT);

    const Topology* topos = t2_topos();
    const int    N_CH = N_T2_TOPOS;                 // 20 canonical pairs
    const int64_t N   = 10000000;                   // 1e7 bytes / channel (paper §VII.B)

    // ------------------------------------------------------------------------
    // Generate the 20 canonical channels once (shared by measurements 1 & 2).
    // ------------------------------------------------------------------------
    std::printf("\n[gen] %d channels x %lld bytes (same seed, t2_topos pairs)...\n",
                N_CH, (long long)N);
    vector<vector<uint8_t>> ch(N_CH, vector<uint8_t>((size_t)N));
    for (int i = 0; i < N_CH; i++) {
        MCL_T2 g(DEFAULT_SEED, topos[i].p, topos[i].q, K_DEFAULT);
        g.gen_bytes(ch[i].data(), N);
    }

    // XOR multiplex (empty) and message-carrying multiplex (steganographic case)
    vector<uint8_t> mux_empty((size_t)N, 0);
    for (int c = 0; c < N_CH; c++)
        for (int64_t i = 0; i < N; i++)
            mux_empty[(size_t)i] ^= ch[c][(size_t)i];

    // same structured cover message the production steganalysis tool uses
    const char* pat = "ATTACK AT DAWN. REPEAT: ATTACK AT DAWN. ";
    const int plen = (int)std::strlen(pat);
    vector<uint8_t> mux_msg((size_t)N);
    for (int64_t i = 0; i < N; i++)
        mux_msg[(size_t)i] = (uint8_t)(mux_empty[(size_t)i] ^ (uint8_t)pat[i % plen]);

    // ---- Measurement 1: multiplex chi-square + entropy ---------------------
    const double chi_empty = chi_square_256(mux_empty.data(), N);
    const double ent_empty = shannon_entropy_256(mux_empty.data(), N);
    const double chi_msg   = chi_square_256(mux_msg.data(), N);
    const double ent_msg   = shannon_entropy_256(mux_msg.data(), N);
    std::printf("\n--- (1) Multiplex uniformity (df=255, crit=%.2f) ---\n", CHI2_THRESHOLD);
    std::printf("  mux_empty  : chi2 = %8.2f   entropy = %.6f bits/byte\n", chi_empty, ent_empty);
    std::printf("  mux_msg    : chi2 = %8.2f   entropy = %.6f bits/byte   <- steganographic case (§VII.B)\n",
                chi_msg, ent_msg);
    std::printf("  paper §VII.B prints: chi2 = 241.39, entropy = 7.999983\n");

    // ---- Measurement 2: channel-to-multiplex and channel-to-channel |r| ----
    double max_ch_mux = 0.0; int arg_ch = -1;
    for (int c = 0; c < N_CH; c++) {
        const double r = std::fabs(pearson_r(ch[c].data(), mux_empty.data(), N));
        if (r > max_ch_mux) { max_ch_mux = r; arg_ch = c; }
    }
    double max_ch_ch = 0.0; int ai = -1, aj = -1;
    for (int i = 0; i < N_CH; i++)
        for (int j = i + 1; j < N_CH; j++) {
            const double r = std::fabs(pearson_r(ch[i].data(), ch[j].data(), N));
            if (r > max_ch_ch) { max_ch_ch = r; ai = i; aj = j; }
        }
    std::printf("\n--- (2) Correlation (N=%lld samples) ---\n", (long long)N);
    std::printf("  max |r| channel-to-multiplex = %.6f  (channel %d = (%lld,%lld) vs 20-way mux)\n",
                max_ch_mux, arg_ch, (long long)topos[arg_ch].p, (long long)topos[arg_ch].q);
    std::printf("  max |r| channel-to-channel   = %.6f  (pair (%lld,%lld) x (%lld,%lld), 190 pairs)\n",
                max_ch_ch, (long long)topos[ai].p, (long long)topos[ai].q,
                (long long)topos[aj].p, (long long)topos[aj].q);
    std::printf("  paper §VII.B prints: max channel-to-multiplex |r| = 0.000559\n");

    // free the big channel buffers before the smaller measurements
    ch.clear(); ch.shrink_to_fit();
    { vector<uint8_t>().swap(mux_empty); }
    { vector<uint8_t>().swap(mux_msg); }

    // ---- Measurement 3: next-byte (bigram) prediction, TRAIN/TEST split -----
    // A first-order (bigram) most-likely-next-byte predictor is TRAINED on the
    // first T_train bytes and SCORED on a DISJOINT T_test region of the same
    // stream. The train/test split is essential: scoring on the training bytes
    // overfits the finite-sample argmax and inflates accuracy above baseline
    // (an in-sample scorer reports ~0.61%, a measurement artifact, not signal).
    // Baseline = 1/256 = 0.390625%.
    {
        const int64_t T_train = 2000000;            // 2e6 (matches the archived attack-suite run)
        const int64_t T_test  = 2000000;            // disjoint held-out region
        const int64_t T = T_train + T_test;
        vector<uint8_t> s((size_t)T);
        MCL_T2 g(DEFAULT_SEED, 3, 5, K_DEFAULT);    // default working config (3,5,12)
        g.gen_bytes(s.data(), T);

        static int64_t cnt[256][256];               // context -> next-byte counts (train only)
        std::memset(cnt, 0, sizeof(cnt));
        for (int64_t i = 0; i + 1 < T_train; i++)
            cnt[s[(size_t)i]][s[(size_t)i + 1]]++;

        uint8_t pred[256];                          // argmax next byte per context
        for (int c = 0; c < 256; c++) {
            int64_t best = -1; int bk = 0;
            for (int k = 0; k < 256; k++) if (cnt[c][k] > best) { best = cnt[c][k]; bk = k; }
            pred[c] = (uint8_t)bk;
        }
        int64_t correct = 0, total = 0;             // score on disjoint test region
        for (int64_t i = T_train; i + 1 < T; i++, total++)
            if (pred[s[(size_t)i]] == s[(size_t)i + 1]) correct++;

        const double acc = 100.0 * (double)correct / (double)total;
        std::printf("\n--- (3) Next-byte (bigram) prediction, held-out (train %lld / test %lld) ---\n",
                    (long long)T_train, (long long)T_test);
        std::printf("  prediction accuracy = %.4f%%   (random baseline 1/256 = %.4f%%)\n",
                    acc, 100.0 / 256.0);
        std::printf("  paper Table 6 / §X.C prints: byte prediction 0.406%% (random 0.39%%);\n");
        std::printf("  archived mcl_attack_suite (held-out): 0.388%% (random 0.3906%%)\n");
    }

    // ---- Measurement 4: incorrect-parameter authentication Hamming ---------
    // Correct config responds to a fixed challenge; many wrong (p',q') respond to
    // the same challenge. Hamming(R, R') over 256-bit (32-byte) responses.
    {
        const uint64_t challenge = DEFAULT_SEED;    // public challenge (Kerckhoffs)
        const int64_t p0 = 3, q0 = 5;
        uint8_t R[32];
        { MCL_T2 g(challenge, p0, q0, K_DEFAULT); g.gen_bytes(R, 32); }

        // sweep a grid of wrong coprime-ish pairs (p' != p0 or q' != q0)
        double sum = 0.0, sumsq = 0.0; int64_t n = 0;
        double hmin = 1e9, hmax = -1e9;
        for (int64_t pp = 2; pp <= 60; pp++)
            for (int64_t qq = 2; qq <= 60; qq++) {
                if (pp == qq) continue;
                if (pp == p0 && qq == q0) continue;
                uint8_t Rp[32];
                { MCL_T2 g(challenge, pp, qq, K_DEFAULT); g.gen_bytes(Rp, 32); }
                int bits = 0;
                for (int b = 0; b < 32; b++) bits += popcount8((uint8_t)(R[b] ^ Rp[b]));
                const double h = (double)bits / 256.0;
                sum += h; sumsq += h * h; n++;
                if (h < hmin) hmin = h;
                if (h > hmax) hmax = h;
            }
        const double mean = sum / (double)n;
        const double var  = sumsq / (double)n - mean * mean;
        const double sd   = std::sqrt(var > 0 ? var : 0);
        std::printf("\n--- (4) Incorrect-parameter authentication Hamming (%lld wrong pairs) ---\n",
                    (long long)n);
        std::printf("  mean = %.4f   std = %.4f   min = %.5f   max = %.5f\n", mean, sd, hmin, hmax);
        std::printf("  paper §IV.C prints: mean 0.4998 +/- 0.0031 (min 0.39844, max 0.61328)\n");
    }

    std::printf("\n=== done ===\n");
    return 0;
}
