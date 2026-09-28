// mcl_grover_resource_estimate.cpp -- Doc ID MCL-GROVER-RES-2026-0927-001 rev 3
// ---------------------------------------------------------------------------
// Itemized quantum RESOURCE MODEL for a Grover key search against the keyed
// T4-Q30 path, set beside the published AES-256 figures.
//
// rev 3 (2026-09-28): comments and the revision string only. The sidecar is
//   referred to by function name, and sidecar v1.0.7 is named. No figure
//   changes: the output differs from that of rev 2 in its first line alone.
// rev 2 (2026-09-27): every primitive cost is either CITED (formula checked
//   against the text of the original paper) or DERIVED (derivation written out
//   below); the circuit is a REVERSIBLE one (temporaries uncomputed or kept,
//   global Bennett compute/uncompute); depth and width follow from the SAME
//   circuit as the gate count; the multiply by the public constant K is folded
//   into the table.
//
// WHAT IT IS / IS NOT
//   IS : a transparent model. Three named circuit configurations x two
//        garbage strategies; every constant is overridable. It is NEITHER an
//        upper NOR a lower bound on the attack: better circuits may exist
//        (Karatsuba / windowed arithmetic, pebbling), and the figures count T
//        gates only. The band between the configurations is the honest output.
//   NOT: a compiled circuit, and NOT a security statement. It prices generic
//        key search; whether a STRUCTURAL quantum attack beats generic search
//        is Paper 4 OP2 and is not addressed here.
//
//   HEADLINE the model supports: a k-bit key costs (pi/4) 2^(k/2) oracle calls
//   for ANY cipher, so the keyed 256-bit path and AES-256 share the exponent;
//   the per-oracle cost differs. This is CONSISTENT WITH Paper 5 sec.VIII, which
//   states 2^128 oracle evaluations as the generic key-search bound, valid only
//   in the absence of structural attacks. (Paper 5 does not contain the phrase
//   "constant factor"; this file does not attribute it to the paper.)
//
// ENGINE-LITERAL OPERATION COUNT (traceability to mcl_q30t4_iterate_raw in
// ../keyed_q30_PQ/mcl_keyed_q30.hpp), per iteration:
//   12 coupling arguments  a = p*t_j - q*t_i      -> 24 multiplies, 12 subtracts
//   12 increments          inc = (K_phase*sin(a))>>30 -> 12 table reads,
//                                                     12 multiplies by K_phase
//    4 updates             t += omega + inc+inc+inc   -> 16 additions
//   => 36 multiplies, 28 additions/subtractions, 12 table reads.
//
// ATTACKER-OPTIMIZED REVERSIBLE CIRCUIT (what is priced)
//   (1) K_phase is a PUBLIC constant, so the table can store inc(a) itself:
//       the 12 multiplies by K_phase cost the attacker nothing.
//   (2) omega_i is a public constant: it is folded into one table per oscillator.
//   (3) a = p*t_j - q*t_i is ONE accumulator: the second product is accumulated
//       with subtraction, so the 12 subtractions are absorbed.
//   (4) The update t_i += f(t_i, ...) is NOT invertible in place (the increment
//       depends on the old t_i), so a reversible circuit must keep 32 qubits of
//       garbage per oscillator update, and the whole trajectory is uncomputed
//       once at the end (Bennett): oracle = 2 x forward.
//   Two garbage strategies, per oscillator update:
//     WIDE   keep every temporary            : 6 mult, 3 lookup, 3 add
//            garbage 192 qubits (3 arguments, 2 table values, the sum)
//     NARROW uncompute temporaries in place  : 12 mult, 3 lookup,
//            2 lookup-uncompute, 3 add ; garbage 32 qubits (the sum)
//   Per iteration = 4 oscillator updates, strictly serial (Gauss-Seidel).
//
// PRIMITIVE COSTS.  Unit = one Toffoli (model A) or one temporary AND (model B).
//   CITED formulas were checked against the papers' own text on 2026-09-27.
//   Model A "textbook": 7 T per Toffoli, T-depth 3 (the Toffoli Amy et al. use),
//   no measurement tricks.
//     adder mod 2^w      2w-3 Toffoli, 2w-3 Toffoli layers           [CITED]
//         Cuccaro, Draper, Kutin, Moulton, quant-ph/0410184, sec.4.1.
//     multiplier         sum_{w=1..n} [2w + adder(w)]                [DERIVED]
//         schoolbook accumulate: row w computes w partial-product bits with w
//         Toffolis, adds them with a w-bit adder, uncomputes them with w more.
//         Layers: sum_{w} [2 + adder(w)] (a row's ANDs are parallel).
//     table lookup       2(L-1) Toffoli, 2(L-1) layers               [DERIVED]
//         the unary-iteration circuit of Babbush et al. has L-1 AND
//         computations and L-1 AND uncomputations; without measurement-based
//         uncomputation each is a Toffoli. Uncomputing a lookup = repeating it.
//   Model B "measurement-assisted": 4 T per AND in T-depth 1, 0 T to uncompute
//   an AND (Gidney 2018; the AND gate of Jaques et al., Appendix C, is 4 T +
//   11 Clifford gates, T-depth 1, total depth 8).
//     adder mod 2^w      w-1 AND, w-1 layers                         [CITED]
//         Gidney, Quantum 2, 74 (2018), arXiv:1709.06648: n-bit adder T-count
//         4n-4.
//     multiplier         sum_{w=1..n} [w + (w-1)] = n^2 AND          [DERIVED]
//         same schoolbook accumulate, AND uncompute free. Layers: n(n+1)/2.
//     table lookup, unary iteration   L-1 AND, L-1 layers            [CITED]
//         Babbush et al., PRX 8, 041015 (2018), arXiv:1805.03662: T-count 4L-4
//         independent of the word length, log L ancillae (sequential).
//     table lookup, QROAM             ceil(L/k) + M(k-1), (k-1)M ancillae
//         Berry et al., Quantum 3, 208 (2019), arXiv:1902.02134.     [CITED]
//         Layers ceil(L/k) + (k-1) is a MODELING ASSUMPTION (unary part
//         sequential, swap network bit-parallel).
//     lookup uncompute                ceil(L/k) + k, minimum 2 sqrt(L)
//         Berry et al., Appendix C (measurement-based).               [CITED]
//   SHA-256 (the KDF), both models: 228,992 T and T-depth 70,400 per
//     compression -- Amy, Di Matteo, Gheorghiu, Mosca, Parent, Schanck,
//     SAC 2016 (LNCS 10532), arXiv:1603.09383, Table 1, row "SHA-256 (Opt.)".
//                                                                    [CITED]
//     The 96-byte weight derivation is 3 hashes of a 57-byte preimage
//     (32 key + 13 label + 8 info + 4 counter) = 2 blocks each = 6 compressions.
//   NOT ITEMIZED (each below 2^-10 of the total): the 12 reductions mod
//     (2^30-2), the p != q fix, the symmetry re-draw of sidecar v1.0.6, the
//     keystream comparison, the Grover diffusion operator.
//
// AES-256 REFERENCES (printed only when --key-bits is 256)
//   NIST, Submission Requirements and Evaluation Criteria (Dec 2016), sec.4.A.5:
//     2^298/MAXDEPTH quantum gates or 2^272 classical gates.
//   Jaques, Naehrig, Roetteler, Virdia, EUROCRYPT 2020, arXiv:1910.01700,
//     Table 12: 1.39 x 2^245 / 2^221 / 2^190 at MAXDEPTH 2^40 / 2^64 / 2^96;
//     Table 8 (oracle, in-place MixColumn, r = 2): 151,164 T, T-depth 126,
//     full depth 3,356, width 4,609; 1,228,150 operations in total
//     (808,071 CNOT + 231,124 one-qubit Clifford + 151,164 T + 37,791
//     measurements).
//   Both AES figures count ALL gates and FULL depth; this model counts T gates
//   and T-depth. The comparison therefore UNDERSTATES the keyed path's cost in
//   the NIST metric by the Clifford overhead; --clifford-gate-factor and
//   --clifford-depth-factor let the reader apply one. The largest Clifford
//   term is NOT modeled at all: writing a 2^16-entry, 32-bit table costs about
//   2^16 x 16 = 2^20 CNOTs per lookup, which a T count does not see.
//
// ADDITIVE: no engine file is modified. Engine of record v8.1.3 / sidecar v1.0.7
// (its four-oscillator path is that of v1.0.6).
// Build:
//   clang++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -I.. \
//       mcl_grover_resource_estimate.cpp -o mcl_grover_resource_estimate
// ---------------------------------------------------------------------------
#include "../mcl_core.hpp"                 // BURNIN, DECIMATION, MCL_VERSION_STRING
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cmath>
#include <string>

static const double PI_D = 3.14159265358979323846264338327950288;
// KDF label of mcl_t4_q30_params_from_key (sidecar line 364); it fixes the
// preimage length and therefore the number of SHA-256 compressions.
static const char* const KDF_LABEL = "MCL-T4-Q30-v1";

struct Params {
    int    word_bits      = 32;         // n: engine phase word
    int    lut_addr_bits  = 16;         // table has 2^16 entries
    int    lut_out_bits   = 32;         // M: width of the stored increment
    int    key_bits       = 256;
    int    out_bytes      = 40;         // keystream bytes compared by the oracle
    long   burnin         = BURNIN;
    int    decimation     = DECIMATION;
    double sha256_T       = 228992.0;   // Amy et al., Table 1
    double sha256_Tdepth  = 70400.0;    // Amy et al., Table 1
    double clifford_gate_factor  = 1.0; // 1 = T gates only
    double clifford_depth_factor = 1.0; // 1 = T-depth only
};

// ---- primitive formulas ----------------------------------------------------
static double adderA_units(int w)  { return (w >= 2) ? (double)(2 * w - 3) : 0.0; }
static double adderA_layers(int w) { return adderA_units(w); }
static double adderB_units(int w)  { return (w >= 1) ? (double)(w - 1) : 0.0; }
static double adderB_layers(int w) { return adderB_units(w); }

static double multA_units(int n)  { double s = 0; for (int w = 1; w <= n; w++) s += 2.0 * w + adderA_units(w); return s; }
static double multA_layers(int n) { double s = 0; for (int w = 1; w <= n; w++) s += 2.0 + adderA_layers(w);    return s; }
static double multB_units(int n)  { double s = 0; for (int w = 1; w <= n; w++) s += (double)w + adderB_units(w); return s; }
static double multB_layers(int n) { double s = 0; for (int w = 1; w <= n; w++) s += 1.0 + adderB_layers(w);      return s; }

struct Lookup { double units, layers, ancillae; long k; };
static Lookup unaryA(double L)  { return Lookup{ 2.0 * (L - 1.0), 2.0 * (L - 1.0), std::ceil(std::log2(L)), 1 }; }
static Lookup unaryB(double L)  { return Lookup{ L - 1.0, L - 1.0, std::ceil(std::log2(L)), 1 }; }
// QROAM compute: minimise ceil(L/k) + M(k-1) over k = 2^j; ties -> larger k (shallower).
static Lookup qroamB(double L, int M) {
    Lookup best{ 0, 0, 0, 0 }; bool have = false;
    for (long k = 1; (double)k <= L; k *= 2) {
        double u = std::ceil(L / (double)k) + (double)M * (double)(k - 1);
        if (!have || u <= best.units) {
            best = Lookup{ u, std::ceil(L / (double)k) + (double)(k - 1),
                           (double)(k - 1) * (double)M + std::ceil(std::log2(L / (double)k)), k };
            have = true;
        }
    }
    return best;
}
// measurement-based lookup uncompute: minimise ceil(L/k) + k over k = 2^j.
static Lookup uncomputeB(double L) {
    Lookup best{ 0, 0, 0, 0 }; bool have = false;
    for (long k = 1; (double)k <= L; k *= 2) {
        double u = std::ceil(L / (double)k) + (double)k;
        if (!have || u < best.units) {
            best = Lookup{ u, u, (double)k + std::ceil(std::log2(L / (double)k)), k };
            have = true;
        }
    }
    return best;
}

struct Config {
    const char* name;
    const char* note;
    double t_per_unit;      // T gates per Toffoli / AND
    double tdepth_per_layer;
    double add_u, add_l, mul_u, mul_l;
    Lookup look, unlook;
};

struct Result { double iterT, iterLayers, oracleT, oracleTdepth, garbage_qubits; };

static Result evaluate(const Config& c, const Params& p, bool narrow, double iters,
                       double kdfT, double kdfTdepth) {
    // per oscillator update
    const double mul  = narrow ? 12.0 : 6.0;
    const double unl  = narrow ?  2.0 : 0.0;
    double units  = mul * c.mul_u + 3.0 * c.look.units + unl * c.unlook.units + 3.0 * c.add_u;
    // depth: the three arguments are built in parallel, each = 2 accumulating
    // multiplies in sequence; lookups parallel; sum = 2 adds; update = 1 add.
    double layers = (narrow ? 4.0 : 2.0) * c.mul_l + c.look.layers
                  + (narrow ? c.unlook.layers : 0.0) + 3.0 * c.add_l;
    Result r;
    r.iterT       = 4.0 * units  * c.t_per_unit;
    r.iterLayers  = 4.0 * layers;
    const double iterTdepth = r.iterLayers * c.tdepth_per_layer;
    r.oracleT       = 2.0 * (iters * r.iterT   + kdfT);        // Bennett: forward + backward
    r.oracleTdepth  = 2.0 * (iters * iterTdepth + kdfTdepth);
    r.garbage_qubits = iters * 4.0 * (narrow ? (double)p.word_bits
                                             : 3.0 * p.word_bits + 2.0 * p.lut_out_bits + p.lut_out_bits);
    return r;
}

// ---- strict command line ----------------------------------------------------
static void usage(const char* a0) {
    std::printf(
      "usage: %s [options]\n"
      "  --word-bits N             engine word width (default 32)\n"
      "  --key-bits N              key length searched (default 256)\n"
      "  --out-bytes N             keystream bytes the oracle compares (default 40)\n"
      "  --burnin N                what-if burn-in (default: engine BURNIN)\n"
      "  --sha-T X                 T gates per SHA-256 compression (default 228992)\n"
      "  --sha-Tdepth X            T-depth per SHA-256 compression (default 70400)\n"
      "  --clifford-gate-factor X  all gates per T gate (default 1 = T only)\n"
      "  --clifford-depth-factor X full depth per T layer (default 1 = T-depth)\n"
      "  --help\n", a0);
}
static bool parse_long(const char* s, long lo, long hi, long& out) {
    errno = 0; char* e = nullptr; long v = std::strtol(s, &e, 10);
    if (errno != 0 || e == s || *e != '\0' || v < lo || v > hi) return false;
    out = v; return true;
}
static bool parse_double(const char* s, double lo, double hi, double& out) {
    errno = 0; char* e = nullptr; double v = std::strtod(s, &e);
    if (errno != 0 || e == s || *e != '\0' || !std::isfinite(v) || v < lo || v > hi) return false;
    out = v; return true;
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    Params p;
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--help") { usage(argv[0]); return 0; }
        if (i + 1 >= argc) { std::fprintf(stderr, "error: option %s needs a value\n", a.c_str()); usage(argv[0]); return 2; }
        const char* v = argv[++i];
        long L = 0; bool ok = false;
        if      (a == "--word-bits")  { ok = parse_long(v, 2, 64, L);          if (ok) { p.word_bits = (int)L; p.lut_out_bits = (int)L; } }
        else if (a == "--key-bits")   { ok = parse_long(v, 2, 4096, L);        if (ok) p.key_bits = (int)L; }
        else if (a == "--out-bytes")  { ok = parse_long(v, 1, 1 << 20, L);     if (ok) p.out_bytes = (int)L; }
        else if (a == "--burnin")     { ok = parse_long(v, 0, 1000000000L, L); if (ok) p.burnin = L; }
        else if (a == "--sha-T")                 ok = parse_double(v, 1.0, 1e12, p.sha256_T);
        else if (a == "--sha-Tdepth")            ok = parse_double(v, 1.0, 1e12, p.sha256_Tdepth);
        else if (a == "--clifford-gate-factor")  ok = parse_double(v, 1.0, 1e6,  p.clifford_gate_factor);
        else if (a == "--clifford-depth-factor") ok = parse_double(v, 1.0, 1e6,  p.clifford_depth_factor);
        else { std::fprintf(stderr, "error: unknown option %s\n", a.c_str()); usage(argv[0]); return 2; }
        if (!ok) { std::fprintf(stderr, "error: bad value '%s' for %s\n", v, a.c_str()); return 2; }
    }

    const int    n = p.word_bits;
    const double L = std::ldexp(1.0, p.lut_addr_bits);
    const double iters = (double)p.burnin + (double)p.out_bytes * (double)p.decimation;

    // KDF: compressions from the real preimage length and output length.
    const size_t pre   = 32 + std::strlen(KDF_LABEL) + 8 + 4;
    const size_t blk   = (pre + 1 + 8 + 63) / 64;
    const size_t nhash = (96 + 31) / 32;
    const double kdfT      = (double)(nhash * blk) * p.sha256_T;
    const double kdfTdepth = (double)blk * p.sha256_Tdepth;          // the hashes run in parallel

    std::printf("MCL-GROVER-RES-2026-0927-001 rev 3   Grover resource model, keyed T4-Q30\n");
    std::printf("engine mcl_core %s (UNMODIFIED): BURNIN=%d DECIMATION=%d\n",
                MCL_VERSION_STRING, BURNIN, DECIMATION);
    std::printf("parameters: word-bits=%d table=2^%d x %d bit key-bits=%d out-bytes=%d burnin=%ld\n",
                n, p.lut_addr_bits, p.lut_out_bits, p.key_bits, p.out_bytes, p.burnin);
    std::printf("            sha-T=%.0f sha-Tdepth=%.0f clifford-gate-factor=%.3g clifford-depth-factor=%.3g\n",
                p.sha256_T, p.sha256_Tdepth, p.clifford_gate_factor, p.clifford_depth_factor);
    std::printf("iterations per oracle (one direction): %ld + %d x %d = %.0f\n",
                p.burnin, p.out_bytes, p.decimation, iters);
    std::printf("KDF: preimage %zu bytes -> %zu block(s) per hash, %zu hashes -> %zu compressions\n",
                pre, blk, nhash, nhash * blk);
    std::printf("ALL FIGURES ARE MODEL OUTPUTS -- neither an upper nor a lower bound. log2 unless stated.\n");

    std::printf("\n-- operation counts per iteration --\n");
    std::printf("  engine-literal (mcl_q30t4_iterate_raw): 36 multiplies, 28 add/sub, 12 table reads\n");
    std::printf("  priced, WIDE   (keep temporaries)     : 24 multiplies, 12 adds, 12 lookups\n");
    std::printf("  priced, NARROW (uncompute temporaries): 48 multiplies, 12 adds, 12 lookups, 8 lookup-uncomputes\n");

    const Lookup ua = unaryA(L), ub = unaryB(L), qb = qroamB(L, p.lut_out_bits), xb = uncomputeB(L);
    const Config cfg[3] = {
        { "A-unary", "textbook Toffoli (7 T, T-depth 3), Cuccaro adders, unary lookup",
          7.0, 3.0, adderA_units(n), adderA_layers(n), multA_units(n), multA_layers(n), ua, ua },
        { "B-unary", "temporary AND (4 T, T-depth 1), Gidney adders, unary QROM",
          4.0, 1.0, adderB_units(n), adderB_layers(n), multB_units(n), multB_layers(n), ub, xb },
        { "B-QROAM", "temporary AND (4 T, T-depth 1), Gidney adders, QROAM",
          4.0, 1.0, adderB_units(n), adderB_layers(n), multB_units(n), multB_layers(n), qb, xb },
    };

    std::printf("\n-- primitive costs (units = Toffoli in A, temporary AND in B) --\n");
    std::printf("  %-8s %10s %10s %12s %12s %10s %8s\n", "config", "adder", "multiplier", "lookup", "lookup-unc", "ancillae", "k");
    for (const Config& c : cfg)
        std::printf("  %-8s %10.0f %10.0f %12.0f %12.0f %10.0f %8ld\n", c.name,
                    c.add_u, c.mul_u, c.look.units, c.unlook.units, c.look.ancillae, c.look.k);

    const double calls_l = std::log2(PI_D / 4.0) + (double)p.key_bits / 2.0;
    const double md_l[3] = { 40.0, 64.0, 96.0 };
    double best_md[3] = { 1e300, 1e300, 1e300 }, worst_md[3] = { -1e300, -1e300, -1e300 };
    double best_oracleT = 1e300, worst_oracleT = -1e300;

    for (const Config& c : cfg) {
        for (int narrow = 0; narrow < 2; narrow++) {
            const Result r = evaluate(c, p, narrow != 0, iters, kdfT, kdfTdepth);
            // dominance inside one oscillator update, in units
            const double mul_u = (narrow ? 12.0 : 6.0) * c.mul_u;
            const double lk_u  = 3.0 * c.look.units + (narrow ? 2.0 * c.unlook.units : 0.0);
            const double ad_u  = 3.0 * c.add_u;
            const char* dom = (lk_u >= mul_u && lk_u >= ad_u) ? "table lookups"
                            : (mul_u >= ad_u ? "multipliers" : "adders");
            const double oT_l = std::log2(r.oracleT * p.clifford_gate_factor);
            const double oD_l = std::log2(r.oracleTdepth * p.clifford_depth_factor);
            std::printf("\n== %s / %s ==  %s\n", c.name, narrow ? "NARROW" : "WIDE", c.note);
            std::printf("  per-iteration T gates      : 2^%.2f   (dominant term: %s)\n", std::log2(r.iterT), dom);
            std::printf("     share of units: lookups %.1f%%  multipliers %.1f%%  adders %.1f%%\n",
                        100.0 * lk_u / (lk_u + mul_u + ad_u), 100.0 * mul_u / (lk_u + mul_u + ad_u),
                        100.0 * ad_u / (lk_u + mul_u + ad_u));
            std::printf("  per-iteration T-depth      : 2^%.2f\n", std::log2(r.iterLayers * c.tdepth_per_layer));
            std::printf("  per-oracle gates           : 2^%.2f   (forward + uncompute; KDF share %.2e)\n",
                        oT_l, 2.0 * kdfT / r.oracleT);
            std::printf("  per-oracle depth           : 2^%.2f\n", oD_l);
            std::printf("  garbage qubits (no pebbling): %.3g   (+ lookup ancillae %.0f)\n",
                        r.garbage_qubits, c.look.ancillae);
            std::printf("  Grover calls (%d-bit key)  : 2^%.2f\n", p.key_bits, calls_l);
            std::printf("  serial search: gates 2^%.2f, depth 2^%.2f\n", calls_l + oT_l, calls_l + oD_l);
            for (int m = 0; m < 3; m++) {
                // parallel Grover under MAXDEPTH: S = (D/MAXDEPTH)^2 machines,
                // total gates = G * D / MAXDEPTH when D > MAXDEPTH.
                const double G = calls_l + oT_l, D = calls_l + oD_l;
                if (oD_l > md_l[m]) {
                    std::printf("     MAXDEPTH 2^%.0f : one oracle call is deeper than MAXDEPTH -- search not runnable\n", md_l[m]);
                    continue;
                }
                const double inflate = (D > md_l[m]) ? (D - md_l[m]) : 0.0;
                const double tot = G + inflate;
                std::printf("     MAXDEPTH 2^%.0f : 2^%.1f gates%s\n", md_l[m], tot,
                            inflate > 0 ? "  (depth-limited, parallelized)" : "");
                if (tot < best_md[m])  best_md[m]  = tot;
                if (tot > worst_md[m]) worst_md[m] = tot;
            }
            if (oT_l < best_oracleT)  best_oracleT  = oT_l;
            if (oT_l > worst_oracleT) worst_oracleT = oT_l;
        }
    }

    bool md_ok[3];
    for (int m = 0; m < 3; m++) md_ok[m] = (best_md[m] < 1e299);

    std::printf("\n== band over the six configurations ==\n");
    std::printf("  per-oracle gates : 2^%.2f ... 2^%.2f\n", best_oracleT, worst_oracleT);
    for (int m = 0; m < 3; m++) {
        if (md_ok[m]) std::printf("  MAXDEPTH 2^%.0f    : 2^%.1f ... 2^%.1f gates\n", md_l[m], best_md[m], worst_md[m]);
        else          std::printf("  MAXDEPTH 2^%.0f    : n/a (no configuration fits one oracle call in the depth limit)\n", md_l[m]);
    }

    if (p.key_bits == 256) {
        const double aes_nist[3] = { 298.0 - 40.0, 298.0 - 64.0, 298.0 - 96.0 };
        const double aes_jnrv[3] = { 245.0 + std::log2(1.39), 221.0 + std::log2(1.39), 190.0 + std::log2(1.39) };
        const double aesT = 151164.0, aesGates = 808071.0 + 231124.0 + 151164.0 + 37791.0;
        std::printf("\n== AES-256 reference (ALL gates, FULL depth) ==\n");
        std::printf("  Grover calls (256-bit key): 2^%.2f -- the same count as above\n", calls_l);
        for (int m = 0; m < 3; m++) {
            if (md_ok[m])
                std::printf("  MAXDEPTH 2^%.0f : NIST 2^%.0f   JNRV 2^%.1f   | keyed path 2^%.1f ... 2^%.1f  (ratio to JNRV 2^%.1f ... 2^%.1f)\n",
                            md_l[m], aes_nist[m], aes_jnrv[m], best_md[m], worst_md[m],
                            best_md[m] - aes_jnrv[m], worst_md[m] - aes_jnrv[m]);
            else
                std::printf("  MAXDEPTH 2^%.0f : NIST 2^%.0f   JNRV 2^%.1f   | keyed path n/a\n",
                            md_l[m], aes_nist[m], aes_jnrv[m]);
        }
        std::printf("  AES-256 oracle (JNRV Table 8, r=2, in-place MixColumn): 2^%.2f T, 2^%.2f operations of all kinds, T-depth 126, width 4609\n",
                    std::log2(aesT), std::log2(aesGates));
        std::printf("  keyed-path oracle / AES-256 oracle, T gates: 2^%.1f ... 2^%.1f\n",
                    best_oracleT - std::log2(p.clifford_gate_factor) - std::log2(aesT),
                    worst_oracleT - std::log2(p.clifford_gate_factor) - std::log2(aesT));
    } else {
        std::printf("\n(AES-256 reference omitted: --key-bits is %d, the published figures are for 256.)\n", p.key_bits);
    }

    std::printf("\n-- reading --\n");
    std::printf("  * Grover's call count depends on the key length only: (pi/4) 2^(%d/2) = 2^%.2f.\n",
                p.key_bits, calls_l);
    if (p.key_bits == 256)
        std::printf("    The keyed path and AES-256 share that exponent; what differs is the oracle.\n");
    std::printf("  * The oracle is larger because it runs %.0f serial iterations; under a depth limit\n", iters);
    std::printf("    the gate total scales with gates x depth, i.e. with the SQUARE of the iteration count.\n");
    std::printf("  * Which term dominates one iteration depends on the lookup circuit (see each block).\n");
    std::printf("  * Consistent with Paper 5 sec.VIII (generic key-search bound, conditional on the absence\n");
    std::printf("    of structural attacks). Nothing here addresses a structural shortcut (Paper 4 OP2).\n");
    std::printf("  * T gates and T-depth only, unless a Clifford factor was given: the AES columns count\n");
    std::printf("    all gates and full depth, so the ratios above UNDERSTATE the keyed path's cost\n");
    std::printf("    (writing one 2^16-entry table is about 2^20 CNOTs, invisible to a T count).\n");
    std::printf("  * Not a bound in either direction: better arithmetic or pebbling would lower it,\n");
    std::printf("    error correction and routing would raise it.\n");
    return 0;
}
