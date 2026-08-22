/*
 * ============================================================================
 * MCL Keyed Q30 -- DEFINITIVE Lyapunov spectrum at 256-bit precision (MPFR)
 * ----------------------------------------------------------------------------
 * Closes the hyperchaos question. Double precision fails because lambda_1 ~ 86
 * nats/step exceeds double's ~36-nat log budget, so the subdominant directions
 * underflow in QR. At 256-bit mantissa (~177 nats) the dynamic range fits, so a
 * standard 4x4 Benettin QR resolves the FULL spectrum lambda_1..lambda_4 for the
 * real key-derived (~2^30) weights. Hyperchaotic <=> lambda_2 > 0.
 *
 * BUILD (GMP + MPFR via Homebrew):
 *   c++ -std=c++17 -O2 -I ../MCL_publish \
 *       -I /opt/homebrew/opt/mpfr/include -I /opt/homebrew/opt/gmp/include \
 *       mcl_keyed_q30_mpfr_lyap.cpp \
 *       -L /opt/homebrew/opt/mpfr/lib -L /opt/homebrew/opt/gmp/lib -lmpfr -lgmp \
 *       -o mcl_keyed_q30_mpfr_lyap && ./mcl_keyed_q30_mpfr_lyap
 * ============================================================================
 */
#include "mcl_keyed_q30.hpp"
#include <mpfr.h>
#include <cstdio>
#include <vector>

static const mpfr_prec_t PREC = 256;
static const mpfr_rnd_t  RND  = MPFR_RNDN;

namespace {

struct Ctx {
    mpfr_t two_pi, K;
    mpfr_t w[4];
    mpfr_t P[6], Q[6];
    // scratch
    mpfr_t a, c, kc, sinsum, t1tmp, acc, prod;
    mpfr_t row[4];                 // temp row for sub-step row-update
    mpfr_t J[4][4], Qm[4][4], M[4][4], col[4];
    Ctx(){
        mpfr_init2(two_pi,PREC); mpfr_init2(K,PREC);
        mpfr_const_pi(two_pi,RND); mpfr_mul_ui(two_pi,two_pi,2,RND);
        mpfr_set_d(K,K_DEFAULT,RND);
        for(int i=0;i<4;i++) mpfr_init2(w[i],PREC);
        for(int i=0;i<6;i++){ mpfr_init2(P[i],PREC); mpfr_init2(Q[i],PREC); }
        mpfr_inits2(PREC,a,c,kc,sinsum,t1tmp,acc,prod,(mpfr_ptr)0);
        for(int i=0;i<4;i++) mpfr_init2(row[i],PREC);
        for(int i=0;i<4;i++){ mpfr_init2(col[i],PREC);
            for(int j=0;j<4;j++){ mpfr_init2(J[i][j],PREC); mpfr_init2(Qm[i][j],PREC); mpfr_init2(M[i][j],PREC); } }
    }
};

static void mod2pi_m(mpfr_t x, Ctx& X){
    mpfr_fmod(x,x,X.two_pi,RND);
    if(mpfr_sgn(x)<0) mpfr_add(x,x,X.two_pi,RND);
}
// arg = P*tj - Q*ti
static void argf(mpfr_t out, mpfr_t Pp, mpfr_t tj, mpfr_t Qq, mpfr_t ti, Ctx& X){
    mpfr_mul(out,Pp,tj,RND); mpfr_mul(X.acc,Qq,ti,RND); mpfr_sub(out,out,X.acc,RND);
}

// One Gauss-Seidel step: advance t[4], build composed Jstep into X.J.
// Sub-step i replaces row i of Jstep by (active-row coeffs) . Jstep.
static void step(mpfr_t t[4], Ctx& X){
    // Jstep := identity
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) mpfr_set_ui(X.J[i][j], i==j?1:0, RND);

    // coupling table per sub-step: (target oscillator j, pair index)
    // sub-step 0 (osc0): (1,0),(2,1),(3,2)
    // sub-step 1 (osc1): (0,0),(2,3),(3,4)
    // sub-step 2 (osc2): (0,1),(1,3),(3,5)
    // sub-step 3 (osc3): (0,2),(1,4),(2,5)
    static const int tgt[4][3]   = {{1,2,3},{0,2,3},{0,1,3},{0,1,2}};
    static const int pidx[4][3]  = {{0,1,2},{0,3,4},{1,3,5},{2,4,5}};

    for(int i=0;i<4;i++){
        // r[] = active row coefficients; sinsum accumulates K*sum(sin)
        for(int k=0;k<4;k++) mpfr_set_ui(X.row[k],0,RND);
        mpfr_set_ui(X.row[i],1,RND);          // diagonal starts at 1
        mpfr_set_ui(X.sinsum,0,RND);
        for(int e=0;e<3;e++){
            int j=tgt[i][e], pi=pidx[i][e];
            argf(X.a, X.P[pi], t[j], X.Q[pi], t[i], X);   // arg = P*tj - Q*ti
            // kc = K*cos(arg)
            mpfr_cos(X.c,X.a,RND); mpfr_mul(X.kc,X.K,X.c,RND);
            // off-diagonal coeff row[j] += P*kc
            mpfr_mul(X.prod,X.P[pi],X.kc,RND); mpfr_add(X.row[j],X.row[j],X.prod,RND);
            // diagonal coeff row[i] -= Q*kc
            mpfr_mul(X.prod,X.Q[pi],X.kc,RND); mpfr_sub(X.row[i],X.row[i],X.prod,RND);
            // sinsum += K*sin(arg)
            mpfr_sin(X.c,X.a,RND); mpfr_mul(X.prod,X.K,X.c,RND); mpfr_add(X.sinsum,X.sinsum,X.prod,RND);
        }
        // Jstep row i := row[] . Jstep   (newrow[col] = sum_k row[k]*Jstep[k][col])
        // careful: only rows 0..i-1 of Jstep differ from identity; but general form is fine.
        for(int col=0; col<4; col++){
            mpfr_set_ui(X.acc,0,RND);
            for(int k=0;k<4;k++){ mpfr_mul(X.prod,X.row[k],X.J[k][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
            mpfr_set(X.col[col],X.acc,RND);
        }
        for(int col=0; col<4; col++) mpfr_set(X.J[i][col],X.col[col],RND);
        // advance state coordinate i (Gauss-Seidel): t[i] = mod2pi(t[i]+w[i]+sinsum)
        mpfr_add(t[i],t[i],X.w[i],RND); mpfr_add(t[i],t[i],X.sinsum,RND); mod2pi_m(t[i],X);
    }
}

// Benettin QR: M = J*Q; modified Gram-Schmidt -> Q, R diag; accumulate ln r_cc.
static void qr_accumulate(Ctx& X, double acc[4]){
    // M = J * Qm
    for(int r=0;r<4;r++) for(int col=0;col<4;col++){
        mpfr_set_ui(X.acc,0,RND);
        for(int k=0;k<4;k++){ mpfr_mul(X.prod,X.J[r][k],X.Qm[k][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
        mpfr_set(X.M[r][col],X.acc,RND);
    }
    // modified GS on columns of M
    for(int col=0; col<4; col++){
        // subtract projections onto previous orthonormal columns (stored back into Qm progressively)
        for(int p=0;p<col;p++){
            // dot = Qm[:,p] . M[:,col]
            mpfr_set_ui(X.acc,0,RND);
            for(int r=0;r<4;r++){ mpfr_mul(X.prod,X.Qm[r][p],X.M[r][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
            for(int r=0;r<4;r++){ mpfr_mul(X.prod,X.acc,X.Qm[r][p],RND); mpfr_sub(X.M[r][col],X.M[r][col],X.prod,RND); }
        }
        // norm
        mpfr_set_ui(X.acc,0,RND);
        for(int r=0;r<4;r++){ mpfr_mul(X.prod,X.M[r][col],X.M[r][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
        mpfr_sqrt(X.acc,X.acc,RND);               // r_cc
        // accumulate ln(r_cc)
        mpfr_log(X.prod,X.acc,RND);
        acc[col] += mpfr_get_d(X.prod,RND);
        // Qm[:,col] = M[:,col]/r_cc
        for(int r=0;r<4;r++){ mpfr_div(X.Qm[r][col],X.M[r][col],X.acc,RND); }
    }
}

static void set_weights(Ctx& X, const MCL_Q30_Sextet& s){
    double P[6]={(double)s.p12,(double)s.p13,(double)s.p14,(double)s.p23,(double)s.p24,(double)s.p34};
    double Q[6]={(double)s.q12,(double)s.q13,(double)s.q14,(double)s.q23,(double)s.q24,(double)s.q34};
    for(int i=0;i<6;i++){ mpfr_set_d(X.P[i],P[i],RND); mpfr_set_d(X.Q[i],Q[i],RND); }
}

static void lyap_full(Ctx& X, uint64_t seed, long N, double lam[4]){
    mpfr_t t[4]; for(int i=0;i<4;i++) mpfr_init2(t[i],PREC);
    uint64_t s=hash_seed(seed);
    const double OM[4]={OMEGA_1,OMEGA_2,OMEGA_3,OMEGA_4};
    for(int i=0;i<4;i++){ mpfr_set_d(t[i],(double)s*OM[i],RND); mod2pi_m(t[i],X); mpfr_set_d(X.w[i],OM[i],RND); }
    for(int i=0;i<BURNIN;i++) step(t,X);
    // Qm := identity
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) mpfr_set_ui(X.Qm[i][j], i==j?1:0, RND);
    double acc[4]={0,0,0,0};
    for(long n=0;n<N;n++){ step(t,X); qr_accumulate(X,acc); }
    for(int i=0;i<4;i++) lam[i]=acc[i]/(double)N;
    for(int i=0;i<4;i++) mpfr_clear(t[i]);
}

} // namespace

int main(){
    std::setbuf(stdout,nullptr);
    std::printf("================================================================\n");
    std::printf("  MCL KEYED Q30 -- DEFINITIVE Lyapunov spectrum @ %ld-bit (MPFR)\n",(long)PREC);
    std::printf("================================================================\n");
    Ctx X;

    // sanity: small weights (must match the double result l1~14.06, l2~2.70)
    {
        MCL_Q30_Sextet sm{2,3,5,7,11,13,3,5,7,11,13,17}; // arbitrary small (note: field order p12,q12,...)
        // build small structural sextet directly: p12,q12,p13,q13,p14,q14,p23,q23,p24,q24,p34,q34
        MCL_Q30_Sextet small{2,3, 5,7, 11,13, 3,5, 7,11, 13,17};
        (void)sm;
        set_weights(X,small);
        double lam[4]; lyap_full(X,DEFAULT_SEED,40000,lam);
        std::printf("\n  (a) small weights: lambda = [%.4f, %.4f, %.4f, %.4f]  positives=%d\n",
            lam[0],lam[1],lam[2],lam[3],(lam[0]>0)+(lam[1]>0)+(lam[2]>0)+(lam[3]>0));
        std::printf("      (double QR gave l1=14.06,l2=2.70 -> sanity %s)\n",
            (lam[0]>10&&lam[1]>1)?"OK":"CHECK");
    }

    // definitive: real key-derived ~2^30 weights, all keys (incl. the prior inconclusive one)
    std::printf("\n  (b) key-derived weights (~2^30) -- FULL spectrum, 256-bit:\n");
    int K_KEYS=6, hyper=0; double worst_l2=1e9;
    for(int kk=0;kk<K_KEYS;kk++){
        uint8_t kx[32]; for(int i=0;i<32;i++) kx[i]=(uint8_t)(i*7+1+kk*101);
        MCL_Q30_Sextet sk=mcl_t4_q30_params_from_key(kx);
        set_weights(X,sk);
        double lam[4]; lyap_full(X,DEFAULT_SEED+(uint64_t)kk*131,40000,lam);
        double sum=lam[0]+lam[1]+lam[2]+lam[3];
        bool hc=(lam[1]>0);
        std::printf("    key %d: lambda=[%.3f, %.4f, %.2f, %.2f]  sum=%.3f  %s\n",
            kk,lam[0],lam[1],lam[2],lam[3],sum, hc?"[HYPERCHAOTIC: l2>0]":"[l2<=0]");
        if(hc) hyper++; if(lam[1]<worst_l2) worst_l2=lam[1];
    }
    std::printf("\n  VERDICT: lambda_2>0 (hyperchaotic) for %d/%d keys; worst lambda_2 = %.4f\n",
        hyper,K_KEYS,worst_l2);
    std::printf("  => %s\n", (hyper==K_KEYS)
        ? "PASS: T4-Q30 (continuous analog) is HYPERCHAOTIC for all sampled keys (256-bit, definitive)."
        : "MIXED: lambda_2 not positive for all keys -- report honestly.");
    return 0;
}
