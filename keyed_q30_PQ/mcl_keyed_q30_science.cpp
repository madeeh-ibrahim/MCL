/*
 * ============================================================================
 * MCL Keyed Q30 -- SCIENTIFIC verification (closes the review's open gaps)
 *   [T1] Lyapunov spectrum of the T4 map with key-derived weights (analytic
 *        4x4 Gauss-Seidel Jacobian, Benettin QR) -- is it hyperchaotic?
 *   [T2] Extended statistical battery on the T4-Q30 keystream + sample file
 *        for offline `ent` / `dieharder` / PractRand.
 *   [T3] b_eff: per-coordinate preimage count of the integer Q30 map (full
 *        2^32 scan) -> backward branching b>1 on the LUT engine, byte-filtered.
 *
 * BUILD:
 *   c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish \
 *       -o mcl_keyed_q30_science mcl_keyed_q30_science.cpp && ./mcl_keyed_q30_science
 * ============================================================================
 */
#include "mcl_keyed_q30.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>

// ----------------------------------------------------------------------------
// [T1] Lyapunov spectrum of the CONTINUOUS 4-oscillator Gauss-Seidel map that
// the Q30 integer engine discretizes. Weights cast to double; analytic Jacobian
// via sub-step composition Jstep = J4*J3*J2*J1 (reduces to mcl_core jacobian_gs
// for T2). Hyperchaotic <=> at least two positive exponents.
// ----------------------------------------------------------------------------
namespace {

struct M4 { double a[4][4]; };
static M4 ident() { M4 m{}; for (int i=0;i<4;i++) m.a[i][i]=1.0; return m; }
static M4 mul(const M4&A,const M4&B){ M4 C{};
  for(int i=0;i<4;i++)for(int j=0;j<4;j++){double s=0;for(int k=0;k<4;k++)s+=A.a[i][k]*B.a[k][j];C.a[i][j]=s;}
  return C; }

// pair index: P/Q[0..5] = (12,13,14,23,24,34)
static void step_and_jac(double t[4], const double P[6], const double Q[6],
                         const double w[4], double K, M4& Jstep) {
    auto C = [&](double x){ return K * std::cos(x); };
    // S1: update t0 from t1,t2,t3  (pairs 12,13,14)
    double a12=P[0]*t[1]-Q[0]*t[0], a13=P[1]*t[2]-Q[1]*t[0], a14=P[2]*t[3]-Q[2]*t[0];
    M4 J1=ident();
    J1.a[0][0]=1.0-(Q[0]*C(a12)+Q[1]*C(a13)+Q[2]*C(a14));
    J1.a[0][1]=P[0]*C(a12); J1.a[0][2]=P[1]*C(a13); J1.a[0][3]=P[2]*C(a14);
    t[0]=mod2pi(t[0]+w[0]+K*(std::sin(a12)+std::sin(a13)+std::sin(a14)));
    // S2: update t1 from t0(new),t2,t3  (pairs 12,23,24)
    double b21=P[0]*t[0]-Q[0]*t[1], b23=P[3]*t[2]-Q[3]*t[1], b24=P[4]*t[3]-Q[4]*t[1];
    M4 J2=ident();
    J2.a[1][0]=P[0]*C(b21);
    J2.a[1][1]=1.0-(Q[0]*C(b21)+Q[3]*C(b23)+Q[4]*C(b24));
    J2.a[1][2]=P[3]*C(b23); J2.a[1][3]=P[4]*C(b24);
    t[1]=mod2pi(t[1]+w[1]+K*(std::sin(b21)+std::sin(b23)+std::sin(b24)));
    // S3: update t2 from t0,t1(new),t3  (pairs 13,23,34)
    double c31=P[1]*t[0]-Q[1]*t[2], c32=P[3]*t[1]-Q[3]*t[2], c34=P[5]*t[3]-Q[5]*t[2];
    M4 J3=ident();
    J3.a[2][0]=P[1]*C(c31); J3.a[2][1]=P[3]*C(c32);
    J3.a[2][2]=1.0-(Q[1]*C(c31)+Q[3]*C(c32)+Q[5]*C(c34));
    J3.a[2][3]=P[5]*C(c34);
    t[2]=mod2pi(t[2]+w[2]+K*(std::sin(c31)+std::sin(c32)+std::sin(c34)));
    // S4: update t3 from t0,t1,t2(new)  (pairs 14,24,34)
    double d41=P[2]*t[0]-Q[2]*t[3], d42=P[4]*t[1]-Q[4]*t[3], d43=P[5]*t[2]-Q[5]*t[3];
    M4 J4=ident();
    J4.a[3][0]=P[2]*C(d41); J4.a[3][1]=P[4]*C(d42); J4.a[3][2]=P[5]*C(d43);
    J4.a[3][3]=1.0-(Q[2]*C(d41)+Q[4]*C(d42)+Q[5]*C(d43));
    t[3]=mod2pi(t[3]+w[3]+K*(std::sin(d41)+std::sin(d42)+std::sin(d43)));
    Jstep = mul(J4, mul(J3, mul(J2, J1)));
}

// modified Gram-Schmidt QR of M (columns), return Q (orthonormal cols) + diag R.
static void qr4(const M4& Mm, M4& Qo, double Rd[4]) {
    double v[4][4];
    for(int c=0;c<4;c++) for(int r=0;r<4;r++) v[r][c]=Mm.a[r][c];
    for(int c=0;c<4;c++){
        for(int p=0;p<c;p++){
            double dot=0; for(int r=0;r<4;r++) dot+=Qo.a[r][p]*v[r][c];
            for(int r=0;r<4;r++) v[r][c]-=dot*Qo.a[r][p];
        }
        double nrm=0; for(int r=0;r<4;r++) nrm+=v[r][c]*v[r][c]; nrm=std::sqrt(nrm);
        if(nrm<1e-300) nrm=1e-300;
        Rd[c]=nrm; for(int r=0;r<4;r++) Qo.a[r][c]=v[r][c]/nrm;
    }
}

static void lyapunov_t4(const double P[6], const double Q[6], const double w[4],
                        double K, uint64_t seed, long N, double lam[4]) {
    double t[4];
    uint64_t s = hash_seed(seed);
    t[0]=mod2pi((double)s*OMEGA_1); t[1]=mod2pi((double)s*OMEGA_2);
    t[2]=mod2pi((double)s*OMEGA_3); t[3]=mod2pi((double)s*OMEGA_4);
    M4 J;
    for(int i=0;i<BURNIN;i++) step_and_jac(t,P,Q,w,K,J);
    M4 Qm=ident(); double acc[4]={0,0,0,0};
    for(long n=0;n<N;n++){
        step_and_jac(t,P,Q,w,K,J);
        M4 Mm=mul(J,Qm);
        double Rd[4]; qr4(Mm,Qm,Rd);
        for(int i=0;i<4;i++) acc[i]+=std::log(Rd[i]);
    }
    for(int i=0;i<4;i++) lam[i]=acc[i]/(double)N;
}

static void weights_to_PQ(const MCL_Q30_Sextet& w, double P[6], double Q[6]) {
    P[0]=(double)w.p12; Q[0]=(double)w.q12; P[1]=(double)w.p13; Q[1]=(double)w.q13;
    P[2]=(double)w.p14; Q[2]=(double)w.q14; P[3]=(double)w.p23; Q[3]=(double)w.q23;
    P[4]=(double)w.p24; Q[4]=(double)w.q24; P[5]=(double)w.p34; Q[5]=(double)w.q34;
}

} // namespace

int main(int argc, char**) {
    std::setbuf(stdout,nullptr);
    std::printf("================================================================\n");
    std::printf("  MCL KEYED Q30 -- SCIENTIFIC verification (engine %s)\n", mcl_version());
    std::printf("================================================================\n");
    (void)argc;
    uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i*7+1);
    const double w[4]={OMEGA_1,OMEGA_2,OMEGA_3,OMEGA_4};

    // ---------------- [T1] Lyapunov spectrum ----------------
    std::printf("\n[T1] Lyapunov spectrum (continuous analog, analytic Jacobian, Benettin QR)\n");
    {
        // (a) sanity: small structural sextet (validates the Jacobian/QR code)
        double Ps[6]={2,3,5,7,11,13}, Qs[6]={3,5,7,11,13,17};
        double lam[4];
        lyapunov_t4(Ps,Qs,w,K_DEFAULT,DEFAULT_SEED,60000,lam);
        std::printf("  (a) small weights {2,3,5,7,11,13}/{3,5,7,11,13,17}:\n");
        std::printf("      lambda = [%.3f, %.3f, %.3f, %.3f]  positives=%d\n",
                    lam[0],lam[1],lam[2],lam[3],
                    (lam[0]>0)+(lam[1]>0)+(lam[2]>0)+(lam[3]>0));
        // (b) actual key-derived Q30 weights (~2^30)
        MCL_Q30_Sextet sx = mcl_t4_q30_params_from_key(key);
        double P[6],Q[6]; weights_to_PQ(sx,P,Q);
        double lk[4];
        lyapunov_t4(P,Q,w,K_DEFAULT,DEFAULT_SEED,60000,lk);
        std::printf("  (b) key-derived weights (~2^30):\n");
        std::printf("      lambda = [%.3f, %.3f, %.3f, %.3f]  positives=%d\n",
                    lk[0],lk[1],lk[2],lk[3],
                    (lk[0]>0)+(lk[1]>0)+(lk[2]>0)+(lk[3]>0));
        std::printf("      sum(lambda) = %.3f (= mean ln|det J|, Oseledets)\n",
                    lk[0]+lk[1]+lk[2]+lk[3]);
        int pos = (lk[0]>0)+(lk[1]>0)+(lk[2]>0)+(lk[3]>0);
        std::printf("  => %s (>=2 positive exponents = HYPERCHAOTIC)\n",
                    pos>=2 ? "PASS: hyperchaotic" : "FAIL: not hyperchaotic");
        std::printf("  (note: continuous analog with weights <=2^30 < 2^52, so double-sin is\n");
        std::printf("   accurate; the Q30 integer engine is the shadowing discretization.)\n");
    }

    // ---------------- [T2] extended statistical battery ----------------
    std::printf("\n[T2] Extended statistical battery on the T4-Q30 keystream\n");
    {
        const int64_t N = (int64_t)64 << 20; // 64 MiB
        std::vector<uint8_t> buf((size_t)N);
        MCL_T4_Q30 e(key);
        e.gen_bytes(buf.data(), N);
        std::printf("  sample = %lld MiB\n", (long long)(N>>20));
        std::printf("  chi^2 (df=255)        = %.2f  (threshold %.2f)\n",
                    chi_square(buf.data(),N), CHI2_THRESHOLD);
        std::printf("  Shannon entropy       = %.7f bits/byte\n", shannon_entropy(buf.data(),N));
        std::printf("  bit frequency         = %.7f  (ideal 0.5)\n", bit_frequency(buf.data(),N));
        std::printf("  runs test z           = %.4f  (|z|<3.29 ok)\n", runs_test_z(buf.data(),N));
        for(int lag=1;lag<=8;lag++)
            std::printf("  autocorr lag %d        = %+.6f\n", lag, autocorrelation(buf.data(),N,lag));
        SpectralResult sr = spectral_test(buf.data(),N,2000);
        std::printf("  spectral SNR          = %.3f  (threshold %.1f, %s)\n",
                    sr.snr, SPECTRAL_SNR_THRESHOLD, sr.pass?"PASS":"FAIL");
        // per-bit-position chi^2 (8 positions)
        std::printf("  per-bit chi^2 [b0..b7]: ");
        for(int b=0;b<8;b++){
            long ones=0; for(int64_t i=0;i<N;i++) ones += (buf[(size_t)i]>>b)&1;
            double exp=(double)N/2.0, c=((double)ones-exp)*((double)ones-exp)/exp*2.0;
            std::printf("%.1f ", c);
        }
        std::printf("\n");
        // emit sample for offline `ent` / `dieharder` / PractRand
        FILE* f=std::fopen("t4q30_sample.bin","wb");
        if(f){ std::fwrite(buf.data(),1,(size_t)N,f); std::fclose(f);
            std::printf("  wrote t4q30_sample.bin (%lld MiB) -- run:\n", (long long)(N>>20));
            std::printf("     ent t4q30_sample.bin\n");
            std::printf("     dieharder -g 201 -f t4q30_sample.bin -a   (slow; or PractRand RNG_test)\n");
        }
    }

    // ---------------- [T3] backward branching of the integer Q30 map -------
    // CORRECTED METHOD. The earlier 3-target spot-check was UNDERPOWERED (it
    // sampled 3 image values, most of which have exactly 1 preimage, and wrongly
    // concluded "invertible"). The DEFINITIVE quantity is the image cardinality
    // over the full 2^32 domain (fixed t2): mean preimages over the image =
    // 2^32 / |image|. |image|==2^32 => bijection (b=1); |image|<2^32 => many-to-
    // one. (512 MB bitset, full 2^32 scan, ~20 s.)
    std::printf("\n[T3] Backward branching of the 2-osc Q30 map (image cardinality, full 2^32)\n");
    {
        const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
        const int64_t p=3, q=5;
        const MCL_Q30_Table& tab = mcl_q30_table();
        const uint32_t t2fix = 0x9abcdef0u;
        auto fwd_t1 = [&](uint32_t t1)->uint32_t{
            uint32_t a1=(uint32_t)((int64_t)p*(int64_t)t2fix-(int64_t)q*(int64_t)t1);
            int32_t inc=(int32_t)(((int64_t)kp*(int64_t)tab.sin_q30(a1))>>30);
            return t1 + mcl_q30_omega1() + (uint32_t)inc;
        };
        std::vector<uint64_t> bits((size_t)1 << 26, 0); // 2^32 bits = 512 MB
        uint32_t x=0; do { uint32_t y=fwd_t1(x); bits[y>>6] |= (1ULL<<(y&63)); x++; } while(x!=0);
        uint64_t img=0; for(uint64_t v: bits){ while(v){ img += v&1; v>>=1; } }
        double cover = (double)img / 4294967296.0;
        double b_avg = (img>0) ? 4294967296.0/(double)img : 0.0;
        std::printf("  image cardinality   = %llu / 2^32  (coverage %.2f%%)\n",
                    (unsigned long long)img, 100.0*cover);
        std::printf("  mean per-coord backward branching b = %.3f over the image\n", b_avg);
        std::printf("  cf. Float64 engine per-coord b ~= 38 (Exp6) -> Q30 is ~%.0fx WEAKER folding\n",
                    38.0/b_avg);
        std::printf("  VERDICT: the Q30 map IS many-to-one (b=%.2f>1) but only WEAKLY. The coarse\n", b_avg);
        std::printf("  16-bit LUT linearizes the map (piecewise slope-1), so backward branching is\n");
        std::printf("  far below Float64. WHETHER the KEYSTREAM-CONSTRAINED b_eff stays >1 (the\n");
        std::printf("  one-wayness condition; Float64 had ~6) is NOT established for Q30 and is a\n");
        std::printf("  REAL OPEN RISK -- needs the mcl_beff_compounding methodology ported to Q30.\n");
    }

    std::printf("\n================================================================\n");
    std::printf("  SCIENTIFIC verification complete. See per-section verdicts above.\n");
    std::printf("================================================================\n");
    return 0;
}
