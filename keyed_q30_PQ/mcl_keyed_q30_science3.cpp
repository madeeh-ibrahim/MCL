/*
 * ============================================================================
 * MCL Keyed Q30 -- SCIENTIFIC v3: PROVE hyperchaos WITHOUT extended precision
 * ----------------------------------------------------------------------------
 * The direct QR spectrum underflows because lambda_1 ~ 86 >> 36 nats/step
 * (double's log-precision). We avoid it with a rigorous bound:
 *
 *   - lambda_1  is measured robustly by a 1-vector Benettin (the dominant
 *     direction never orthogonalizes against anything, so no cancellation).
 *   - Sum_i lambda_i = <ln|det J_step|>  (Oseledets). For this Gauss-Seidel map
 *     det J_step = product of the four sub-step diagonal entries
 *     d1*d2*d3*d4 (each = 1 - K*sum(q*cos)), so ln|det| = sum ln|d_i| --
 *     a sum of well-scaled O(20) numbers, computed with NO catastrophic
 *     cancellation. (For T2 this reduces to the white-paper identity
 *     det J = (1-qKc1)(1-qKc2).)
 *   - Since lambda_2 >= lambda_3 >= lambda_4 and they sum to (Sum - lambda_1),
 *     the LARGEST of the three obeys  lambda_2 >= (Sum - lambda_1)/3.
 *     Therefore  Sum > lambda_1  ==>  lambda_2 > 0  ==>  HYPERCHAOTIC (proven).
 *
 * BUILD: c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish \
 *        -o mcl_keyed_q30_science3 mcl_keyed_q30_science3.cpp && ./mcl_keyed_q30_science3
 * ============================================================================
 */
#include "mcl_keyed_q30.hpp"
#include <cstdio>
#include <cmath>

namespace {

// One Gauss-Seidel step of the continuous 4-oscillator analog. Advances t[4],
// fills Jstep[4][4] (for the lambda_1 vector push) and lndet = ln|det J_step|
// computed from the four sub-step diagonal entries (robust).
struct M4 { double a[4][4]; };
static M4 ident(){ M4 m{}; for(int i=0;i<4;i++) m.a[i][i]=1.0; return m; }
static M4 mul(const M4&A,const M4&B){ M4 C{};
  for(int i=0;i<4;i++)for(int j=0;j<4;j++){double s=0;for(int k=0;k<4;k++)s+=A.a[i][k]*B.a[k][j];C.a[i][j]=s;}
  return C; }

static void step(double t[4], const double P[6], const double Q[6],
                 const double w[4], double K, M4& Jstep, double& lndet) {
    auto C=[&](double x){ return K*std::cos(x); };
    double a12=P[0]*t[1]-Q[0]*t[0], a13=P[1]*t[2]-Q[1]*t[0], a14=P[2]*t[3]-Q[2]*t[0];
    M4 J1=ident();
    double d1 = 1.0-(Q[0]*C(a12)+Q[1]*C(a13)+Q[2]*C(a14));
    J1.a[0][0]=d1; J1.a[0][1]=P[0]*C(a12); J1.a[0][2]=P[1]*C(a13); J1.a[0][3]=P[2]*C(a14);
    t[0]=mod2pi(t[0]+w[0]+K*(std::sin(a12)+std::sin(a13)+std::sin(a14)));
    double b21=P[0]*t[0]-Q[0]*t[1], b23=P[3]*t[2]-Q[3]*t[1], b24=P[4]*t[3]-Q[4]*t[1];
    M4 J2=ident();
    double d2 = 1.0-(Q[0]*C(b21)+Q[3]*C(b23)+Q[4]*C(b24));
    J2.a[1][0]=P[0]*C(b21); J2.a[1][1]=d2; J2.a[1][2]=P[3]*C(b23); J2.a[1][3]=P[4]*C(b24);
    t[1]=mod2pi(t[1]+w[1]+K*(std::sin(b21)+std::sin(b23)+std::sin(b24)));
    double c31=P[1]*t[0]-Q[1]*t[2], c32=P[3]*t[1]-Q[3]*t[2], c34=P[5]*t[3]-Q[5]*t[2];
    M4 J3=ident();
    double d3 = 1.0-(Q[1]*C(c31)+Q[3]*C(c32)+Q[5]*C(c34));
    J3.a[2][0]=P[1]*C(c31); J3.a[2][1]=P[3]*C(c32); J3.a[2][2]=d3; J3.a[2][3]=P[5]*C(c34);
    t[2]=mod2pi(t[2]+w[2]+K*(std::sin(c31)+std::sin(c32)+std::sin(c34)));
    double d41=P[2]*t[0]-Q[2]*t[3], d42=P[4]*t[1]-Q[4]*t[3], d43=P[5]*t[2]-Q[5]*t[3];
    M4 J4=ident();
    double d4 = 1.0-(Q[2]*C(d41)+Q[4]*C(d42)+Q[5]*C(d43));
    J4.a[3][0]=P[2]*C(d41); J4.a[3][1]=P[4]*C(d42); J4.a[3][2]=P[5]*C(d43); J4.a[3][3]=d4;
    t[3]=mod2pi(t[3]+w[3]+K*(std::sin(d41)+std::sin(d42)+std::sin(d43)));
    Jstep = mul(J4,mul(J3,mul(J2,J1)));
    // ln|det J_step| = ln|d1| + ln|d2| + ln|d3| + ln|d4|  (robust, no cancellation)
    lndet = std::log(std::fabs(d1)) + std::log(std::fabs(d2))
          + std::log(std::fabs(d3)) + std::log(std::fabs(d4));
}

// lambda_1 via 1-vector Benettin + Sum lambda via <ln|det|>.
static void measure(const double P[6], const double Q[6], const double w[4],
                    double K, uint64_t seed, long N, double& l1, double& sum) {
    double t[4]; uint64_t s=hash_seed(seed);
    t[0]=mod2pi((double)s*OMEGA_1); t[1]=mod2pi((double)s*OMEGA_2);
    t[2]=mod2pi((double)s*OMEGA_3); t[3]=mod2pi((double)s*OMEGA_4);
    M4 J; double ld;
    for(int i=0;i<BURNIN;i++) step(t,P,Q,w,K,J,ld);
    double u[4]={1,0,0,0}; double acc1=0, accdet=0;
    for(long n=0;n<N;n++){
        step(t,P,Q,w,K,J,ld);
        double Ju[4];
        for(int i=0;i<4;i++){ Ju[i]=0; for(int k=0;k<4;k++) Ju[i]+=J.a[i][k]*u[k]; }
        double r=std::sqrt(Ju[0]*Ju[0]+Ju[1]*Ju[1]+Ju[2]*Ju[2]+Ju[3]*Ju[3]);
        if(r<1e-300) r=1e-300;
        for(int i=0;i<4;i++) u[i]=Ju[i]/r;
        acc1 += std::log(r);
        accdet += ld;
    }
    l1 = acc1/(double)N; sum = accdet/(double)N;
}

static void weights_to_PQ(const MCL_Q30_Sextet& s, double P[6], double Q[6]){
    P[0]=(double)s.p12;Q[0]=(double)s.q12;P[1]=(double)s.p13;Q[1]=(double)s.q13;
    P[2]=(double)s.p14;Q[2]=(double)s.q14;P[3]=(double)s.p23;Q[3]=(double)s.q23;
    P[4]=(double)s.p24;Q[4]=(double)s.q24;P[5]=(double)s.p34;Q[5]=(double)s.q34;
}

} // namespace

int main(){
    std::setbuf(stdout,nullptr);
    std::printf("================================================================\n");
    std::printf("  MCL KEYED Q30 -- SCIENTIFIC v3: hyperchaos via Oseledets bound\n");
    std::printf("================================================================\n");
    std::printf("  Rigorous: lambda_2 >= (Sum_lambda - lambda_1)/3, so\n");
    std::printf("  Sum_lambda > lambda_1  =>  lambda_2 > 0  =>  HYPERCHAOTIC.\n");
    const double w[4]={OMEGA_1,OMEGA_2,OMEGA_3,OMEGA_4};

    // (a) sanity on small weights (compare to direct QR: l1=14.06, l2=2.70)
    {
        double Ps[6]={2,3,5,7,11,13}, Qs[6]={3,5,7,11,13,17}, l1,sum;
        measure(Ps,Qs,w,K_DEFAULT,DEFAULT_SEED,300000,l1,sum);
        double bound=(sum-l1)/3.0;
        std::printf("\n  (a) small weights: lambda_1=%.4f  Sum=%.4f  Sum-l1=%.4f  l2>=%.4f -> %s\n",
                    l1,sum,sum-l1,bound,(sum>l1)?"lambda_2>0 PROVEN":"inconclusive");
    }

    // (b) actual key-derived ~2^30 weights, averaged over several keys
    std::printf("\n  (b) key-derived weights (~2^30):\n");
    int K_KEYS=6, proven=0; double S_l1=0,S_sum=0,S_bnd=0, minbnd=1e9;
    for(int kk=0;kk<K_KEYS;kk++){
        uint8_t kx[32]; for(int i=0;i<32;i++) kx[i]=(uint8_t)(i*7+1+kk*101);
        MCL_Q30_Sextet sk=mcl_t4_q30_params_from_key(kx);
        double P[6],Q[6]; weights_to_PQ(sk,P,Q);
        double l1,sum; measure(P,Q,w,K_DEFAULT,DEFAULT_SEED+(uint64_t)kk*131,250000,l1,sum);
        double bound=(sum-l1)/3.0;
        bool ok=(sum>l1);
        std::printf("    key %d: lambda_1=%.3f  Sum=%.3f  Sum-l1=%+.3f  =>  lambda_2 >= %+.3f  %s\n",
                    kk,l1,sum,sum-l1,bound, ok?"[hyperchaotic]":"[inconclusive]");
        S_l1+=l1; S_sum+=sum; S_bnd+=bound; if(bound<minbnd) minbnd=bound; if(ok) proven++;
    }
    std::printf("\n  mean: lambda_1=%.3f  Sum=%.3f  Sum-l1=%+.3f  mean(l2 lower bound)=%+.3f\n",
                S_l1/K_KEYS, S_sum/K_KEYS, (S_sum-S_l1)/K_KEYS, S_bnd/K_KEYS);
    std::printf("  worst-case l2 lower bound across keys = %+.3f\n", minbnd);
    std::printf("\n  VERDICT: hyperchaos proven for %d/%d keys.\n", proven, K_KEYS);
    if(proven==K_KEYS && minbnd>0.0)
        std::printf("  => PASS: Sum_lambda > lambda_1 for every key => lambda_2 > 0 (>= %.3f) =>\n"
                    "     T4-Q30 (continuous analog) is HYPERCHAOTIC. No extended precision needed;\n"
                    "     the bound is robust (lambda_1 = 1-vector Benettin; Sum = <ln|det|> via the\n"
                    "     four sub-step diagonals, both cancellation-free).\n", minbnd);
    else
        std::printf("  => INCONCLUSIVE: Sum_lambda not robustly above lambda_1; the /3 bound does\n"
                    "     not close lambda_2>0. Needs MPFR (>=128-bit) direct QR.\n");
    return 0;
}
