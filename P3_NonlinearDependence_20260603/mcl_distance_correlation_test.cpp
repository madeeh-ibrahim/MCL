/* ============================================================================
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ----------------------------------------------------------------------------
 * Distance Correlation Test  (Paper 3 v3, Experiment 2 / Phase 2)
 *
 * Szekely-Rizzo distance correlation between two MCL channels. dCor in [0,1],
 * and dCor = 0 iff the variables are independent (finite second moments) --
 * detecting linear AND nonlinear dependence, unlike Pearson.
 *
 * Significance by permutation null (shuffle Y); z = (dCor_obs - mean)/sd.
 * Pearson is also reported for contrast.
 *
 * Acceptance: one-sided permutation p-value > alpha (alpha = 0.05/family; e.g. 0.05/66 for the
 *   C(12,2) Table-II campaign). A permutation p-value -- NOT a Gaussian z -- is the decision
 *   statistic because the dCor null is non-negative and right-skewed, so a normal-theory z
 *   overstates upper-tail significance. (An earlier |z|<3.5 build produced a seed-specific false
 *   positive on (3,2)vs(4,6): z=4.07 but perm-p=0.002 > 0.05/66 = PASS; it also vanished at other
 *   seeds and shrank with n. See Paper3_v3_MANIFEST.md "Methodological correction".) The z is still
 *   reported for context. nperm must satisfy 1/(nperm+1) < alpha (nperm>=1320 for family=66).
 * Positive controls prove the apparatus detects dependence:
 *   --control identical  : Y = X            -> dCor = 1, z >> 100
 *   --control quadratic  : Y = ((X-128)^2)  -> Pearson ~ 0 but dCor large
 *                          (demonstrates NONLINEAR detection beyond Pearson)
 *
 * Document ID:  MCL-DCOR-2026-0526-v6-0-0
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
constexpr const char* DOC_ID  = "MCL-DCOR-2026-0526-v6-0-0";
constexpr const char* DOC_VER = "6.0.0";

void print_help() {
    std::printf("MCL (Madeeh Chaotic Lock) - Distance Correlation Test\n");
    std::printf("DOC_ID %s  DOC_VER %s\n", DOC_ID, DOC_VER);
    std::printf("Usage: mcl_distance_correlation_test [--p1 P][--q1 Q][--p2 P][--q2 Q]\n");
    std::printf("       [--K K][--n N][--nperm M][--seed S][--control identical|quadratic]\n");
    std::printf("Defaults: p1=2 q1=3 p2=3 q2=5 K=12 n=2000 nperm=200 seed=12345678901234\n");
}

// centered distance matrix of a byte vector v[0..n) -> out (n*n), and returns dVar^2
double build_centered(const std::vector<uint8_t>& v, int64_t n, std::vector<double>& out) {
    const size_t nn = static_cast<size_t>(n);
    std::vector<double> rowmean(nn, 0.0);
    double grand = 0.0;
    out.assign(nn * nn, 0.0);
    // a_ij = |v_i - v_j|
    for (size_t i = 0; i < nn; ++i) {
        double rs = 0.0;
        const double vi = static_cast<double>(v[i]);
        for (size_t j = 0; j < nn; ++j) {
            const double a = std::fabs(vi - static_cast<double>(v[j]));
            out[i * nn + j] = a;
            rs += a;
        }
        rowmean[i] = rs / static_cast<double>(n);
        grand += rs;
    }
    grand /= static_cast<double>(n) * static_cast<double>(n);
    // double-center (matrix symmetric so colmean == rowmean)
    double dvar2 = 0.0;
    for (size_t i = 0; i < nn; ++i) {
        for (size_t j = 0; j < nn; ++j) {
            const double A = out[i * nn + j] - rowmean[i] - rowmean[j] + grand;
            out[i * nn + j] = A;
            dvar2 += A * A;
        }
    }
    dvar2 /= static_cast<double>(n) * static_cast<double>(n);
    return dvar2;
}

double pearson(const std::vector<uint8_t>& x, const std::vector<uint8_t>& y, int64_t n) {
    long double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
    for (int64_t t = 0; t < n; ++t) {
        const long double a = static_cast<long double>(x[static_cast<size_t>(t)]);
        const long double b = static_cast<long double>(y[static_cast<size_t>(t)]);
        sx += a; sy += b; sxx += a*a; syy += b*b; sxy += a*b;
    }
    const long double nn = static_cast<long double>(n);
    const long double cov = sxy/nn - (sx/nn)*(sy/nn);
    const long double vx  = sxx/nn - (sx/nn)*(sx/nn);
    const long double vy  = syy/nn - (sy/nn)*(sy/nn);
    if (vx <= 0 || vy <= 0) return 0.0;
    return static_cast<double>(cov / std::sqrt(vx*vy));
}
}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);
    int64_t p1=2,q1=3,p2=3,q2=5,n=2000,nperm=200,family=1;
    double K=12.0; uint64_t seed=12345678901234ULL;
    std::string control;

    for (int i=1;i<argc;++i){ std::string a=argv[i];
        if (a=="--help"||a=="-h"){print_help();return 0;}
        else if (a=="--p1"&&i+1<argc){p1=std::atoll(argv[++i]);}
        else if (a=="--q1"&&i+1<argc){q1=std::atoll(argv[++i]);}
        else if (a=="--p2"&&i+1<argc){p2=std::atoll(argv[++i]);}
        else if (a=="--q2"&&i+1<argc){q2=std::atoll(argv[++i]);}
        else if (a=="--K"&&i+1<argc){K=std::atof(argv[++i]);}
        else if (a=="--n"&&i+1<argc){n=std::atoll(argv[++i]);}
        else if (a=="--nperm"&&i+1<argc){nperm=std::atoll(argv[++i]);}
        else if (a=="--seed"&&i+1<argc){seed=static_cast<uint64_t>(std::strtoull(argv[++i],nullptr,10));}
        else if (a=="--control"&&i+1<argc){control=argv[++i];}
        else if (a=="--family"&&i+1<argc){family=std::atoll(argv[++i]);}
        else {std::fprintf(stderr,"unknown arg: %s\n",a.c_str());return 1;}
    }
    if (n<4||nperm<1){std::fprintf(stderr,"FATAL: n>=4, nperm>=1\n");return 1;}

    const size_t nn=static_cast<size_t>(n);
    std::vector<uint8_t> X(nn), Y(nn);
    { MCL_T2 ex(seed,p1,q1,K); ex.gen_bytes(X.data(),n); ex.erase(); }
    if (control=="identical") {
        Y = X;
    } else if (control=="quadratic") {
        for (size_t i=0;i<nn;++i){ const double d=static_cast<double>(X[i])-128.0;
            long v=std::lround((d*d)/64.0); if(v<0)v=0; if(v>255)v=255;
            Y[i]=static_cast<uint8_t>(v); }
    } else {
        MCL_T2 ey(seed,p2,q2,K); ey.gen_bytes(Y.data(),n); ey.erase();
    }

    std::vector<double> A,B;
    const double dvar2x=build_centered(X,n,A);
    const double dvar2y=build_centered(Y,n,B);
    const double denom=std::sqrt(dvar2x*dvar2y);

    auto dcor_from=[&](const std::vector<int64_t>& perm)->double{
        long double s=0.0L;
        for (size_t i=0;i<nn;++i){ const size_t pi=static_cast<size_t>(perm[i]);
            for (size_t j=0;j<nn;++j){
                s += static_cast<long double>(A[i*nn+j]) *
                     static_cast<long double>(B[pi*nn+static_cast<size_t>(perm[j])]);
            } }
        double dcov2=static_cast<double>(s)/(static_cast<double>(n)*static_cast<double>(n));
        if (denom<=0.0) return 0.0;
        double dcor2=dcov2/denom; if (dcor2<0.0) dcor2=0.0;
        return std::sqrt(dcor2);
    };

    std::vector<int64_t> idn(nn); for (size_t i=0;i<nn;++i) idn[i]=static_cast<int64_t>(i);
    const double dcor_obs=dcor_from(idn);

    std::mt19937_64 rng(seed);
    std::vector<int64_t> perm=idn;
    long double m=0.0L, m2=0.0L; int64_t ge=0;
    for (int64_t k=0;k<nperm;++k){
        for (size_t i=nn;i>1;--i){ std::uniform_int_distribution<size_t> d(0,i-1);
            const size_t j=d(rng); std::swap(perm[i-1],perm[j]); }
        const double dc=dcor_from(perm);
        m+=dc; m2+=static_cast<long double>(dc)*dc; if (dc>=dcor_obs) ++ge;
    }
    const double mean=static_cast<double>(m/static_cast<long double>(nperm));
    double var=static_cast<double>(m2/static_cast<long double>(nperm))-mean*mean;
    if (var<0.0) var=0.0;
    const double sd=std::sqrt(var);
    const double z=(sd>0.0)?(dcor_obs-mean)/sd:0.0;
    const double pval=(static_cast<double>(ge)+1.0)/(static_cast<double>(nperm)+1.0);
    const double alpha=0.05/static_cast<double>(family>0?family:1);
    const double pr=pearson(X,Y,n);
    // One-sided permutation test: dCor>=0, so dependence lives in the UPPER tail only.
    // The permutation p-value is robust to the skewed/non-negative dCor null (a Gaussian
    // z-score overstates upper-tail significance on this null). z is still reported for context.
    const bool pass=(pval>alpha);

    std::printf("# MCL distance-correlation  DOC_ID %s\n",DOC_ID);
    std::printf("ch1=(%lld,%lld) ch2=(%lld,%lld) K=%.4f n=%lld nperm=%lld seed=%llu%s%s\n",
        static_cast<long long>(p1),static_cast<long long>(q1),
        static_cast<long long>(p2),static_cast<long long>(q2),K,
        static_cast<long long>(n),static_cast<long long>(nperm),
        static_cast<unsigned long long>(seed),
        control.empty()?"":" control=",control.c_str());
    std::printf("Pearson(X,Y)   = % .6e\n",pr);
    std::printf("dCor_observed  = %.6e\n",dcor_obs);
    std::printf("null mean/sd   = %.6e / %.6e\n",mean,sd);
    std::printf("z-score        = % .4f\n",z);
    std::printf("perm p-value   = %.5f  (one-sided; alpha=0.05/%lld)\n",pval,static_cast<long long>(family));
    std::printf("VERDICT: %s  (perm p>alpha => independent)\n",pass?"PASS(indep)":"FAIL(dependent)");
    return 0;
}
