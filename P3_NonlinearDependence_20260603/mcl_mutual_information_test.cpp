/* ============================================================================
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ----------------------------------------------------------------------------
 * Cross-Mutual-Information Test  (Paper 3 v3, Experiment 1 / Phase 2)
 *
 * Cross-channel MI from a 256x256 joint byte histogram, with Miller-Madow
 * finite-sample bias correction, and a permutation null (shuffle Y). MI = 0
 * iff independent; detects nonlinear dependence Pearson misses.
 *
 * Acceptance (per spec): mean MI < 0.01 bits, max < 0.05 bits, perm p large.
 * Positive controls:
 *   --control identical : Y = X           -> MI ~ H(X) ~ 8 bits
 *   --control quadratic : Y = ((X-128)^2) -> MI > 0 (nonlinear, detected)
 *
 * Document ID:  MCL-MI-2026-0526-v6-0-0
 * Version:      6.0.0
 * Date:         June 3, 2026
 * Author:       Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:      madeeh.chaotic.lock@gmail.com
 * ORCID:        https://orcid.org/0009-0002-8562-8325
 * Engine:       mcl_core.hpp (frozen, MD5 241db79ecf8a42897eb9a8399cf37929).
 * License:      PolyForm Noncommercial 1.0.0.  Patent Pending.
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * NO WARRANTY:  PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 * ============================================================================
 */
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>
#include <random>
#include "mcl_core.hpp"

namespace {
constexpr const char* DOC_ID  = "MCL-MI-2026-0526-v6-0-0";
constexpr const char* DOC_VER = "6.0.0";
constexpr double LN2 = 0.6931471805599453;

void print_help() {
    std::printf("MCL (Madeeh Chaotic Lock) - Cross-Mutual-Information Test\n");
    std::printf("DOC_ID %s  DOC_VER %s\n", DOC_ID, DOC_VER);
    std::printf("Usage: mcl_mutual_information_test [--p1 P][--q1 Q][--p2 P][--q2 Q]\n");
    std::printf("       [--K K][--N N][--nperm M][--seed S][--control identical|quadratic]\n");
    std::printf("Defaults: p1=2 q1=3 p2=3 q2=5 K=12 N=1000000 nperm=200 seed=12345678901234\n");
}

// Miller-Madow-corrected MI (bits) from a permuted pairing of x with y[perm].
double mi_mm(const std::vector<uint8_t>& x, const std::vector<uint8_t>& y,
             const std::vector<int64_t>& perm, int64_t N) {
    std::vector<int64_t> joint(256u * 256u, 0);
    std::vector<int64_t> hx(256u, 0), hy(256u, 0);
    for (int64_t t = 0; t < N; ++t) {
        const size_t xi = x[static_cast<size_t>(t)];
        const size_t yi = y[static_cast<size_t>(perm[static_cast<size_t>(t)])];
        joint[xi * 256u + yi] += 1;
        hx[xi] += 1; hy[yi] += 1;
    }
    const double Nd = static_cast<double>(N);
    long double mi = 0.0L;
    int64_t mxy = 0, mx = 0, my = 0;
    for (size_t i = 0; i < 256u; ++i) if (hx[i] > 0) ++mx;
    for (size_t j = 0; j < 256u; ++j) if (hy[j] > 0) ++my;
    for (size_t i = 0; i < 256u; ++i) {
        if (hx[i] == 0) continue;
        for (size_t j = 0; j < 256u; ++j) {
            const int64_t c = joint[i * 256u + j];
            if (c == 0) continue;
            ++mxy;
            const double pij = static_cast<double>(c) / Nd;
            // log2( c*N / (hx_i*hy_j) )
            const double arg = (static_cast<double>(c) * Nd) /
                               (static_cast<double>(hx[i]) * static_cast<double>(hy[j]));
            mi += static_cast<long double>(pij) * (std::log(arg) / LN2);
        }
    }
    const double plugin = static_cast<double>(mi);
    const double mm = (static_cast<double>(mx + my - mxy - 1)) / (2.0 * Nd * LN2);
    return plugin + mm;
}
}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);
    int64_t p1=2,q1=3,p2=3,q2=5,N=1000000,nperm=200;
    double K=12.0; uint64_t seed=12345678901234ULL;
    std::string control;

    for (int i=1;i<argc;++i){ std::string a=argv[i];
        if (a=="--help"||a=="-h"){print_help();return 0;}
        else if (a=="--p1"&&i+1<argc){p1=std::atoll(argv[++i]);}
        else if (a=="--q1"&&i+1<argc){q1=std::atoll(argv[++i]);}
        else if (a=="--p2"&&i+1<argc){p2=std::atoll(argv[++i]);}
        else if (a=="--q2"&&i+1<argc){q2=std::atoll(argv[++i]);}
        else if (a=="--K"&&i+1<argc){K=std::atof(argv[++i]);}
        else if (a=="--N"&&i+1<argc){N=std::atoll(argv[++i]);}
        else if (a=="--nperm"&&i+1<argc){nperm=std::atoll(argv[++i]);}
        else if (a=="--seed"&&i+1<argc){seed=static_cast<uint64_t>(std::strtoull(argv[++i],nullptr,10));}
        else if (a=="--control"&&i+1<argc){control=argv[++i];}
        else {std::fprintf(stderr,"unknown arg: %s\n",a.c_str());return 1;}
    }
    if (N<256||nperm<1){std::fprintf(stderr,"FATAL: N>=256, nperm>=1\n");return 1;}

    const size_t NN=static_cast<size_t>(N);
    std::vector<uint8_t> X(NN), Y(NN);
    { MCL_T2 ex(seed,p1,q1,K); ex.gen_bytes(X.data(),N); ex.erase(); }
    if (control=="identical"){ Y=X; }
    else if (control=="quadratic"){ for (size_t i=0;i<NN;++i){ const double d=static_cast<double>(X[i])-128.0;
        long v=std::lround((d*d)/64.0); if(v<0)v=0; if(v>255)v=255; Y[i]=static_cast<uint8_t>(v);} }
    else { MCL_T2 ey(seed,p2,q2,K); ey.gen_bytes(Y.data(),N); ey.erase(); }

    std::vector<int64_t> idn(NN); for (size_t i=0;i<NN;++i) idn[i]=static_cast<int64_t>(i);
    const double mi_obs=mi_mm(X,Y,idn,N);

    std::mt19937_64 rng(seed);
    std::vector<int64_t> perm=idn;
    long double m=0.0L,m2=0.0L; int64_t ge=0;
    for (int64_t k=0;k<nperm;++k){
        for (size_t i=NN;i>1;--i){ std::uniform_int_distribution<size_t> d(0,i-1);
            const size_t j=d(rng); std::swap(perm[i-1],perm[j]); }
        const double v=mi_mm(X,Y,perm,N);
        m+=v; m2+=static_cast<long double>(v)*v; if (v>=mi_obs) ++ge;
    }
    const double mean=static_cast<double>(m/static_cast<long double>(nperm));
    double var=static_cast<double>(m2/static_cast<long double>(nperm))-mean*mean; if(var<0)var=0;
    const double sd=std::sqrt(var);
    const double pval=(static_cast<double>(ge)+1.0)/(static_cast<double>(nperm)+1.0);
    // Bonferroni at alpha/66 (family = C(12,2) of Table II). NOTE: for the p-value gate to be
    // able to fire, nperm must satisfy 1/(nperm+1) < 0.05/66, i.e. nperm >= 1320; at smaller
    // nperm the magnitude gate (MI<0.01) is the operative criterion.
    const bool pass=(mi_obs<0.01)&&(pval>0.05/66.0);

    std::printf("# MCL mutual-information  DOC_ID %s\n",DOC_ID);
    std::printf("ch1=(%lld,%lld) ch2=(%lld,%lld) K=%.4f N=%lld nperm=%lld seed=%llu%s%s\n",
        static_cast<long long>(p1),static_cast<long long>(q1),
        static_cast<long long>(p2),static_cast<long long>(q2),K,
        static_cast<long long>(N),static_cast<long long>(nperm),
        static_cast<unsigned long long>(seed),
        control.empty()?"":" control=",control.c_str());
    std::printf("MI_MM_observed = %.6e bits\n",mi_obs);
    std::printf("null mean/sd   = %.6e / %.6e bits\n",mean,sd);
    std::printf("perm p-value   = %.5f\n",pval);
    std::printf("VERDICT: %s  (MI<0.01 bits & p>alpha/66)\n",pass?"PASS(indep)":"FAIL(dependent)");
    return 0;
}
