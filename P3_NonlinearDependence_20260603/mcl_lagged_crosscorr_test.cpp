/* ============================================================================
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ----------------------------------------------------------------------------
 * Lagged Cross-Correlation Test  (Paper 3 v3, Experiment 4 / optional)
 *
 * Pearson(X_t, Y_{t+tau}) for tau in [-L, +L] between two MCL channels, to
 * detect DELAYED linear dependence (X_t depends on Y_{t-k}). Reports the
 * maximum |r| over all lags and where it occurs.
 *
 * Acceptance (per spec): max |r| over all lags < (Bonferroni) noise floor.
 * Positive control: --control shift:K sets Y_t = X_{t-K}; the apparatus MUST
 * then show |r|=1 at lag tau=K, proving it detects delayed dependence.
 *
 * Document ID:  MCL-LAGXCORR-2026-0526-v6-0-0
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
#include <cstring>
#include <vector>
#include <string>
#include "mcl_core.hpp"

namespace {
constexpr const char* DOC_ID  = "MCL-LAGXCORR-2026-0526-v6-0-0";
constexpr const char* DOC_VER = "6.0.0";

void print_help() {
    std::printf("MCL (Madeeh Chaotic Lock) - Lagged Cross-Correlation Test\n");
    std::printf("DOC_ID %s  DOC_VER %s\n", DOC_ID, DOC_VER);
    std::printf("Usage: mcl_lagged_crosscorr_test [--p1 P][--q1 Q][--p2 P][--q2 Q]\n");
    std::printf("       [--K K][--N N][--maxlag L][--seed S][--control shift:K]\n");
    std::printf("Defaults: p1=2 q1=3 p2=3 q2=5 K=12 N=1000000 maxlag=100 seed=12345678901234\n");
}

// Acklam inverse normal CDF: returns x with Phi(x)=p, p in (0,1). ~1e-9 accurate.
double inv_norm_cdf(double p) {
    static const double a[]={-3.969683028665376e+01,2.209460984245205e+02,
        -2.759285104469687e+02,1.383577518672690e+02,-3.066479806614716e+01,2.506628277459239e+00};
    static const double b[]={-5.447609879822406e+01,1.615858368580409e+02,
        -1.556989798598866e+02,6.680131188771972e+01,-1.328068155288572e+01};
    static const double c[]={-7.784894002430293e-03,-3.223964580411365e-01,
        -2.400758277161838e+00,-2.549732539343734e+00,4.374664141464968e+00,2.938163982698783e+00};
    static const double d[]={7.784695709041462e-03,3.224671290700398e-01,
        2.445134137142996e+00,3.754408661907416e+00};
    const double plow=0.02425, phigh=1.0-plow;
    if (p<plow){ const double q=std::sqrt(-2.0*std::log(p));
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) /
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1.0); }
    if (p<=phigh){ const double q=p-0.5, r=q*q;
        return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q /
               (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1.0); }
    const double q=std::sqrt(-2.0*std::log(1.0-p));
    return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) /
            ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1.0);
}

// Pearson over the overlap for integer lag tau (Y shifted by tau vs X).
double xcorr_lag(const std::vector<uint8_t>& x, const std::vector<uint8_t>& y,
                 int64_t N, int64_t tau) {
    int64_t xa, ya, len;
    if (tau >= 0) { xa = 0;     ya = tau;     len = N - tau; }
    else          { xa = -tau;  ya = 0;       len = N + tau; }
    if (len < 2) return 0.0;
    long double sx=0,sy=0,sxx=0,syy=0,sxy=0;
    for (int64_t t = 0; t < len; ++t) {
        const long double a = static_cast<long double>(x[static_cast<size_t>(xa + t)]);
        const long double b = static_cast<long double>(y[static_cast<size_t>(ya + t)]);
        sx+=a; sy+=b; sxx+=a*a; syy+=b*b; sxy+=a*b;
    }
    const long double n = static_cast<long double>(len);
    const long double cov = sxy/n - (sx/n)*(sy/n);
    const long double vx = sxx/n - (sx/n)*(sx/n);
    const long double vy = syy/n - (sy/n)*(sy/n);
    if (vx<=0||vy<=0) return 0.0;
    return static_cast<double>(cov/std::sqrt(vx*vy));
}
}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);
    int64_t p1=2,q1=3,p2=3,q2=5,N=1000000,maxlag=100,family=1;
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
        else if (a=="--maxlag"&&i+1<argc){maxlag=std::atoll(argv[++i]);}
        else if (a=="--seed"&&i+1<argc){seed=static_cast<uint64_t>(std::strtoull(argv[++i],nullptr,10));}
        else if (a=="--control"&&i+1<argc){control=argv[++i];}
        else if (a=="--family"&&i+1<argc){family=std::atoll(argv[++i]);}
        else {std::fprintf(stderr,"unknown arg: %s\n",a.c_str());return 1;}
    }
    if (N<4||maxlag<0||maxlag>=N){std::fprintf(stderr,"FATAL: N>=4,0<=maxlag<N\n");return 1;}

    const size_t NN=static_cast<size_t>(N);
    std::vector<uint8_t> X(NN), Y(NN);
    { MCL_T2 ex(seed,p1,q1,K); ex.gen_bytes(X.data(),N); ex.erase(); }
    int64_t shiftK=-1;
    if (control.rfind("shift:",0)==0) { shiftK=std::atoll(control.c_str()+6);
        for (int64_t t=0;t<N;++t){ const int64_t src=t-shiftK;
            Y[static_cast<size_t>(t)]=(src>=0)?X[static_cast<size_t>(src)]:static_cast<uint8_t>(0); } }
    else { MCL_T2 ey(seed,p2,q2,K); ey.gen_bytes(Y.data(),N); ey.erase(); }

    double maxabs=0.0; int64_t argmax=0;
    for (int64_t tau=-maxlag; tau<=maxlag; ++tau){
        const double r=xcorr_lag(X,Y,N,tau);
        if (std::fabs(r)>maxabs){ maxabs=std::fabs(r); argmax=tau; }
    }
    const double noise=1.0/std::sqrt(static_cast<double>(N));
    const double nlags=static_cast<double>(2*maxlag+1);
    // Bonferroni family-wise threshold over (nlags * family), two-sided alpha=0.05.
    // family folds in cross-pair multiplicity (e.g. --family 66 for the C(12,2) campaign);
    // default family=1 corrects over the 201 lags of this single pair only.
    // (Lags overlap, so this is conservative -- the safe side for a no-dependence claim.)
    const double zcrit=inv_norm_cdf(1.0 - 0.025/(nlags*static_cast<double>(family>0?family:1)));
    const double thresh=zcrit*noise;  // sd of Pearson under H0 ~ 1/sqrt(N)
    const bool pass=(maxabs<thresh);

    std::printf("# MCL lagged-crosscorr  DOC_ID %s\n",DOC_ID);
    std::printf("ch1=(%lld,%lld) ch2=(%lld,%lld) K=%.4f N=%lld maxlag=%lld seed=%llu%s%s\n",
        static_cast<long long>(p1),static_cast<long long>(q1),
        static_cast<long long>(p2),static_cast<long long>(q2),K,
        static_cast<long long>(N),static_cast<long long>(maxlag),
        static_cast<unsigned long long>(seed),
        control.empty()?"":" control=",control.c_str());
    std::printf("noise(1/sqrtN) = %.6e   nlags = %.0f\n",noise,nlags);
    std::printf("max|r|         = %.6e  at lag = %lld\n",maxabs,static_cast<long long>(argmax));
    std::printf("threshold = %.6e  (Bonferroni z_crit=%.3f over %.0f lags)\n",thresh,zcrit,nlags);
    std::printf("VERDICT: %s  (max|r| < z_crit/sqrtN)\n",pass?"PASS(no delayed dep)":"FAIL(delayed dep)");
    return 0;
}
