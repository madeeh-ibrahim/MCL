/*
 * MCL Keyed Q30 -- lambda_2 GRID SWEEP at 256-bit precision (MPFR)
 * ----------------------------------------------------------------------------
 * Supports Patent-4 Claim 27 / [0036]: "enforce q>p => lambda_2>0 for every key."
 * The 6-key MPFR run established lambda_2 in [2.10,6.49]; this generalizes it to
 * (A) a DENSE sweep over random key-derived 12-weight configs (the realistic
 *     derivation distribution), and (B) a BOUNDARY probe compressing every pair
 *     to q = p + delta to map lambda_2 as q/p -> 1 (the worst-case margin).
 * Same continuous-analog Benettin 4x4 QR at 256-bit as mcl_keyed_q30_mpfr_lyap.cpp.
 *
 * BUILD:
 *   c++ -std=c++17 -O2 -I . -I /opt/homebrew/opt/mpfr/include -I /opt/homebrew/opt/gmp/include \
 *       mcl_keyed_q30_lyap_sweep.cpp \
 *       -L /opt/homebrew/opt/mpfr/lib -L /opt/homebrew/opt/gmp/lib -lmpfr -lgmp \
 *       -o lyap_sweep && ./lyap_sweep [KEYS] [N]
 */
#include "mcl_keyed_q30.hpp"
#include <mpfr.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>

static const mpfr_prec_t PREC = 256;
static const mpfr_rnd_t  RND  = MPFR_RNDN;

namespace {
struct Ctx {
    mpfr_t two_pi, K;
    mpfr_t w[4];
    mpfr_t P[6], Q[6];
    mpfr_t a, c, kc, sinsum, t1tmp, acc, prod;
    mpfr_t row[4];
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
static void argf(mpfr_t out, mpfr_t Pp, mpfr_t tj, mpfr_t Qq, mpfr_t ti, Ctx& X){
    mpfr_mul(out,Pp,tj,RND); mpfr_mul(X.acc,Qq,ti,RND); mpfr_sub(out,out,X.acc,RND);
}
static void step(mpfr_t t[4], Ctx& X){
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) mpfr_set_ui(X.J[i][j], i==j?1:0, RND);
    static const int tgt[4][3]   = {{1,2,3},{0,2,3},{0,1,3},{0,1,2}};
    static const int pidx[4][3]  = {{0,1,2},{0,3,4},{1,3,5},{2,4,5}};
    for(int i=0;i<4;i++){
        for(int k=0;k<4;k++) mpfr_set_ui(X.row[k],0,RND);
        mpfr_set_ui(X.row[i],1,RND);
        mpfr_set_ui(X.sinsum,0,RND);
        for(int e=0;e<3;e++){
            int j=tgt[i][e], pi=pidx[i][e];
            argf(X.a, X.P[pi], t[j], X.Q[pi], t[i], X);
            mpfr_cos(X.c,X.a,RND); mpfr_mul(X.kc,X.K,X.c,RND);
            mpfr_mul(X.prod,X.P[pi],X.kc,RND); mpfr_add(X.row[j],X.row[j],X.prod,RND);
            mpfr_mul(X.prod,X.Q[pi],X.kc,RND); mpfr_sub(X.row[i],X.row[i],X.prod,RND);
            mpfr_sin(X.c,X.a,RND); mpfr_mul(X.prod,X.K,X.c,RND); mpfr_add(X.sinsum,X.sinsum,X.prod,RND);
        }
        for(int col=0; col<4; col++){
            mpfr_set_ui(X.acc,0,RND);
            for(int k=0;k<4;k++){ mpfr_mul(X.prod,X.row[k],X.J[k][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
            mpfr_set(X.col[col],X.acc,RND);
        }
        for(int col=0; col<4; col++) mpfr_set(X.J[i][col],X.col[col],RND);
        mpfr_add(t[i],t[i],X.w[i],RND); mpfr_add(t[i],t[i],X.sinsum,RND); mod2pi_m(t[i],X);
    }
}
static void qr_accumulate(Ctx& X, double acc[4]){
    for(int r=0;r<4;r++) for(int col=0;col<4;col++){
        mpfr_set_ui(X.acc,0,RND);
        for(int k=0;k<4;k++){ mpfr_mul(X.prod,X.J[r][k],X.Qm[k][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
        mpfr_set(X.M[r][col],X.acc,RND);
    }
    for(int col=0; col<4; col++){
        for(int p=0;p<col;p++){
            mpfr_set_ui(X.acc,0,RND);
            for(int r=0;r<4;r++){ mpfr_mul(X.prod,X.Qm[r][p],X.M[r][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
            for(int r=0;r<4;r++){ mpfr_mul(X.prod,X.acc,X.Qm[r][p],RND); mpfr_sub(X.M[r][col],X.M[r][col],X.prod,RND); }
        }
        mpfr_set_ui(X.acc,0,RND);
        for(int r=0;r<4;r++){ mpfr_mul(X.prod,X.M[r][col],X.M[r][col],RND); mpfr_add(X.acc,X.acc,X.prod,RND); }
        mpfr_sqrt(X.acc,X.acc,RND);
        mpfr_log(X.prod,X.acc,RND);
        acc[col] += mpfr_get_d(X.prod,RND);
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
    for(int i=0;i<4;i++) for(int j=0;j<4;j++) mpfr_set_ui(X.Qm[i][j], i==j?1:0, RND);
    double acc[4]={0,0,0,0};
    for(long n=0;n<N;n++){ step(t,X); qr_accumulate(X,acc); }
    for(int i=0;i<4;i++) lam[i]=acc[i]/(double)N;
    for(int i=0;i<4;i++) mpfr_clear(t[i]);
}
// splitmix64 to fill a well-spread 32-byte key from an index
static void fill_key(uint8_t kx[32], uint64_t idx){
    uint64_t z = 0x9E3779B97F4A7C15ULL*(idx+1);
    for(int i=0;i<32;i++){ z+=0x9E3779B97F4A7C15ULL; uint64_t x=z;
        x^=x>>30; x*=0xBF58476D1CE4E5B9ULL; x^=x>>27; x*=0x94D049BB133111EBULL; x^=x>>31; kx[i]=(uint8_t)x; }
}
} // namespace

int main(int argc, char** argv){
    std::setbuf(stdout,nullptr);
    int KEYS = (argc>1)? std::atoi(argv[1]) : 100;
    long N   = (argc>2)? std::atol(argv[2]) : 15000;
    Ctx X;
    std::printf("==== MCL T4-Q30 lambda_2 GRID SWEEP @ %ld-bit MPFR (KEYS=%d, N=%ld) ====\n",(long)PREC,KEYS,N);

    // ---- PART A: dense random key-derived sweep (q>p enforced by the derivation) ----
    std::printf("\n[A] Random key-derived 12-weight configs (~2^30), full 4-D spectrum:\n");
    int pos=0; double mn=1e9,mx=-1e9,sum=0; std::vector<double> l2s;
    for(int kk=0;kk<KEYS;kk++){
        uint8_t kx[32]; fill_key(kx,(uint64_t)kk);
        MCL_Q30_Sextet sk=mcl_t4_q30_params_from_key(kx);
        set_weights(X,sk);
        double lam[4]; lyap_full(X,DEFAULT_SEED+(uint64_t)kk*131,N,lam);
        double l2=lam[1]; l2s.push_back(l2); pos+=(l2>0); sum+=l2;
        if(l2<mn)mn=l2; if(l2>mx)mx=l2;
        std::printf("  key %3d: l=[%.2f, %.4f, %.2f, %.2f]  %s\n",kk,lam[0],lam[1],lam[2],lam[3],l2>0?"l2>0":"*** l2<=0 ***");
    }
    std::sort(l2s.begin(),l2s.end());
    std::printf("\n  [A] RESULT: %d/%d keys have lambda_2>0  | min=%.4f  median=%.4f  mean=%.4f  max=%.4f\n",
        pos,KEYS,mn,l2s[l2s.size()/2],sum/KEYS,mx);

    // ---- PART B: boundary probe -- compress every pair to q=p+delta at p0~2^29 ----
    std::printf("\n[B] Boundary probe: all six pairs set to (p0+i, p0+i+delta), p0=2^29; lambda_2 vs margin:\n");
    uint32_t p0 = 1u<<29;
    long Nb = N*2;  // boundary needs more iterations near l2->0
    uint32_t deltas[] = {1u, 16u, 256u, 4096u, 65536u, (1u<<20), (1u<<24), (1u<<28)};
    for(uint32_t d : deltas){
        uint32_t pp[6],qq[6];
        for(int i=0;i<6;i++){ pp[i]=p0+(uint32_t)i; qq[i]=pp[i]+d; }
        MCL_Q30_Sextet s{pp[0],qq[0],pp[1],qq[1],pp[2],qq[2],pp[3],qq[3],pp[4],qq[4],pp[5],qq[5]};
        set_weights(X,s);
        double lam[4]; lyap_full(X,DEFAULT_SEED,Nb,lam);
        double ratio=(double)qq[0]/(double)pp[0];
        std::printf("  delta=%-10u q/p=%.9f  2ln(q/p)=%+.4e  measured lambda_2=%+.4f  %s\n",
            d,ratio,2.0*std::log(ratio),lam[1], lam[1]>0?"l2>0":"l2<=0 (margin below resolution)");
    }

    // ---- PART C: magnitude scan at the tightest margin q=p+1 ----
    std::printf("\n[C] Magnitude scan at tightest margin q=p+1 (worst per-magnitude case):\n");
    uint32_t ps[] = {2u,4u,16u,256u,4096u,65536u,(1u<<20),(1u<<24),(1u<<29)};
    for(uint32_t pb : ps){
        uint32_t pp[6],qq[6];
        for(int i=0;i<6;i++){ pp[i]=pb+(uint32_t)i; qq[i]=pp[i]+1u; }
        MCL_Q30_Sextet s{pp[0],qq[0],pp[1],qq[1],pp[2],qq[2],pp[3],qq[3],pp[4],qq[4],pp[5],qq[5]};
        set_weights(X,s);
        double lam[4]; lyap_full(X,DEFAULT_SEED,Nb,lam);
        std::printf("  p~%-10u q=p+1  q/p=%.7f  lambda_2=%+.4f  %s\n",
            pb,(double)qq[0]/(double)pp[0],lam[1], lam[1]>0?"l2>0":"l2<=0");
    }

    std::printf("\n==== SWEEP COMPLETE ====\n");
    return 0;
}
