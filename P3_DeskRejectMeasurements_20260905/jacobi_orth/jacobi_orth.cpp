// Paper 3 item 10 (2026-09-05): is the Gauss-Seidel update NECESSARY for parameter-induced
// decorrelation?  Re-runs the Sec. V.B protocol of Paper 3 (20 coprime topologies x NS seeds,
// N bytes per channel, Pearson + Hamming with Bonferroni at family-wise alpha = 0.001) with the
// JACOBI (simultaneous) update in place of the engine's Gauss-Seidel update.  Everything else is
// engine-identical: seed -> initial phases (hash_seed, mod2pi(s*OMEGA)), 10,000-step burn-in,
// decimation 2, Goldilocks byte extraction (zone1 ^ zone2), pearson_r / hamming_pct /
// pvalue_from_r / noise_floor from mcl_core.hpp, the RATIOS[] and SEEDS[] of mcl_orth_verify.
// In "gs" mode the tool's byte stream is asserted bit-identical to MCL_T2::gen_bytes.
// Also: raw-phase (cos theta1) Pearson per pair over the first NRAW steps, and lambda_J per topology.
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include "../../mcl_core.hpp"

struct PQ { int64_t p, q; };
static const PQ RATIOS[20] = {{2,3},{3,5},{5,7},{7,11},{8,13},{11,17},{13,19},{17,23},{19,29},{23,31},{29,37},{31,41},{37,43},{41,47},{43,53},{47,59},{53,61},{59,67},{61,71},{67,73}};
static const uint64_t SEEDS[20] = {12345678901234ULL, 98765432109876ULL, 55555555555555ULL, 11111111111111ULL, 77777777777777ULL, 22222222222222ULL, 33333333333333ULL, 44444444444444ULL, 66666666666666ULL, 88888888888888ULL, 99999999999999ULL, 12121212121212ULL, 34343434343434ULL, 56565656565656ULL, 78787878787878ULL, 90909090909090ULL, 13579135791357ULL, 24682468246824ULL, 31415926535897ULL, 27182818284590ULL};

static inline void it(double& t1, double& t2, int64_t p, int64_t q, bool jac) { if (jac) mcl_iterate_jacobi(t1, t2, p, q, K_DEFAULT); else mcl_iterate_raw(t1, t2, p, q, K_DEFAULT); }

static void gen_channel(uint64_t seed, int64_t p, int64_t q, bool jac, uint8_t* buf, int64_t N, double* cos1, int64_t NRAW) {
    uint64_t s = hash_seed(seed); double t1 = mod2pi((double)s * OMEGA_1), t2 = mod2pi((double)s * OMEGA_2);
    for (int i = 0; i < BURNIN; i++) it(t1, t2, p, q, jac);
    for (int64_t n = 0; n < N; n++) {
        for (int d = 0; d < DECIMATION; d++) { it(t1, t2, p, q, jac); }
        buf[n] = mcl_extract_zone1(t1, t2) ^ mcl_extract_zone2(t1, t2);
        if (n < NRAW) cos1[n] = std::cos(t1);
    }
}
static double pearson_d(const double* a, const double* b, int64_t n) {
    double ma = 0, mb = 0; for (int64_t i = 0; i < n; i++) { ma += a[i]; mb += b[i]; } ma /= n; mb /= n;
    double c = 0, va = 0, vb = 0; for (int64_t i = 0; i < n; i++) { double x = a[i] - ma, y = b[i] - mb; c += x * y; va += x * x; vb += y * y; }
    return (va > 0 && vb > 0) ? c / std::sqrt(va * vb) : 0.0;
}

int main(int argc, char** argv) {
    if (argc < 5) { std::fprintf(stderr, "usage: %s NS N gs|jacobi out_prefix [NRAW=1000000]\n", argv[0]); return 2; }
    int NS = atoi(argv[1]); int64_t N = atoll(argv[2]); bool jac = std::strcmp(argv[3], "jacobi") == 0; std::string out = argv[4];
    int64_t NRAW = argc > 5 ? atoll(argv[5]) : 1000000; if (NRAW > N) NRAW = N;
    // optional seed offset (2026-09-05 replicate with fresh seeds): SEED_OFFSET env var is added to every seed
    uint64_t seed_off = 0; if (const char* e = getenv("SEED_OFFSET")) seed_off = strtoull(e, nullptr, 10);
    uint64_t SEEDS_USED[20]; for (int i = 0; i < 20; i++) SEEDS_USED[i] = SEEDS[i] + seed_off;
    if (seed_off) std::fprintf(stderr, "[seed offset] +%llu applied to all 20 seeds\n", (unsigned long long)seed_off);
    const int NR = 20; const int64_t pairs_per_seed = NR * (NR - 1) / 2; const int64_t total_pairs = pairs_per_seed * NS;
    const double bonf = 0.001 / (double)total_pairs; const double ham_eps = 5.0 * 0.5 / std::sqrt(8.0 * (double)N);
    const double raw_bonf = 0.001 / (double)total_pairs;

    // faithfulness check (gs mode): tool byte stream == MCL_T2::gen_bytes
    if (!jac) { std::vector<uint8_t> a(100000), b(100000); std::vector<double> c(1); MCL_T2 e(SEEDS[0], 3, 5); e.gen_bytes(a.data(), 100000);
        gen_channel(SEEDS[0], 3, 5, false, b.data(), 100000, c.data(), 1); if (std::memcmp(a.data(), b.data(), 100000) != 0) { std::fprintf(stderr, "FATAL: gs byte stream differs from MCL_T2::gen_bytes\n"); return 3; }
        std::fprintf(stderr, "[ok] gs mode byte stream bit-identical to MCL_T2::gen_bytes (1e5 bytes)\n"); }

    FILE* fl = fopen((out + "_lyapunov.csv").c_str(), "w"); fprintf(fl, "p,q,update,lambda1,lambda2\n");
    for (int i = 0; i < NR; i++) { LyapResult L = jac ? compute_lyapunov_jacobi(SEEDS[0], RATIOS[i].p, RATIOS[i].q, K_DEFAULT, 1000000) : compute_lyapunov(SEEDS[0], RATIOS[i].p, RATIOS[i].q, K_DEFAULT, 1000000);
        fprintf(fl, "%lld,%lld,%s,%.4f,%.4f\n", (long long)RATIOS[i].p, (long long)RATIOS[i].q, jac ? "jacobi" : "gs", L.l1, L.l2); }
    fclose(fl);

    FILE* fp = fopen((out + "_pairs.csv").c_str(), "w");
    fprintf(fp, "seed_idx,i,j,pi,qi,pj,qj,abs_r_bytes,p_bytes,hamming_pct,ham_dev,r_cos1_raw,p_raw\n");
    double max_r = 0, sum_r = 0, min_p = 1, max_raw = 0, min_praw = 1, max_hdev = 0, sum_h = 0; long fails_p = 0, fails_h = 0, fails_raw = 0; long np = 0;
    std::vector<std::vector<uint8_t>> ch(NR); std::vector<std::vector<double>> raw(NR);
    for (int s = 0; s < NS; s++) {
        for (int i = 0; i < NR; i++) { ch[i].assign((size_t)N, 0); raw[i].assign((size_t)NRAW, 0.0); gen_channel(SEEDS_USED[s], RATIOS[i].p, RATIOS[i].q, jac, ch[i].data(), N, raw[i].data(), NRAW); }
        for (int i = 0; i < NR; i++) for (int j = i + 1; j < NR; j++) {
            double r = std::fabs(pearson_r(ch[i].data(), ch[j].data(), N)); double pv = pvalue_from_r(r, N);
            double h = hamming_pct(ch[i].data(), ch[j].data(), N); double dev = std::fabs(h / 100.0 - 0.5);
            double rr = pearson_d(raw[i].data(), raw[j].data(), NRAW); double praw = pvalue_from_r(std::fabs(rr), NRAW);
            fprintf(fp, "%d,%d,%d,%lld,%lld,%lld,%lld,%.9e,%.4e,%.4f,%.3e,%+.9e,%.4e\n", s, i, j, (long long)RATIOS[i].p, (long long)RATIOS[i].q, (long long)RATIOS[j].p, (long long)RATIOS[j].q, r, pv, h, dev, rr, praw);
            max_r = std::max(max_r, r); sum_r += r; min_p = std::min(min_p, pv); if (pv < bonf) fails_p++; if (dev > ham_eps) fails_h++; max_hdev = std::max(max_hdev, dev); sum_h += h;
            max_raw = std::max(max_raw, std::fabs(rr)); min_praw = std::min(min_praw, praw); if (praw < raw_bonf) fails_raw++; np++;
        }
        std::fprintf(stderr, "  seed %2d/%d done: running max|r|=%.6f min p=%.3e max|r_raw|=%.6f\n", s + 1, NS, max_r, min_p, max_raw);
    }
    fclose(fp);
    FILE* fs = fopen((out + "_summary.txt").c_str(), "w");
    auto W = [&](const char* fmt, auto... a) { std::fprintf(fs, fmt, a...); std::fprintf(stdout, fmt, a...); };
    W("Paper 3 item 10 — %s update — NS=%d seeds x 20 topologies, N=%lld bytes/channel, NRAW=%lld raw steps, K=%g, seed offset %llu\n", jac ? "JACOBI" : "GAUSS-SEIDEL", NS, (long long)N, (long long)NRAW, K_DEFAULT, (unsigned long long)seed_off);
    W("pairs=%ld  Bonferroni alpha/pairs=%.3e  Hamming 5-sigma eps=%.3e\n", np, bonf, ham_eps);
    W("BYTES  : max|r|=%.6f  mean|r|=%.6f  EVT scale=%.6f  min p=%.3e  rejections=%ld/%ld\n", max_r, sum_r / np, noise_floor((int)np, N), min_p, fails_p, np);
    W("HAMMING: mean=%.4f%%  max dev=%.3e  fails=%ld/%ld\n", sum_h / np, max_hdev, fails_h, np);
    W("RAW cos(theta1): max|r|=%.6f  EVT scale=%.6f  min p=%.3e  rejections=%ld/%ld\n", max_raw, noise_floor((int)np, NRAW), min_praw, fails_raw, np);
    fclose(fs); return 0;
}
