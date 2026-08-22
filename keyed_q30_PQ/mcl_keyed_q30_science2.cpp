/*
 * ============================================================================
 * MCL Keyed Q30 -- SCIENTIFIC verification v2 (closes the two open risks)
 *   [T1b] HYPERCHAOS: 2-vector Benettin Lyapunov (lambda_1, lambda_2 only).
 *         The 4-vector version underflowed because lambda_3,4 ~ -690 exceed
 *         double's range within ONE step (condition number ~ e^777). Tracking
 *         only the TOP TWO Lyapunov vectors never orthogonalizes against the
 *         collapsing directions, so lambda_1 and lambda_2 are measured cleanly
 *         -- and lambda_2 > 0 is exactly the hyperchaos condition.
 *   [T3b] KEYSTREAM-CONSTRAINED b_eff for the integer 2-osc Q30 map, measured
 *         EXACTLY (not estimated) via full 2^32 backward enumeration of the
 *         Gauss-Seidel inverse, then filtered by the observed output byte.
 *         This is the integer port of mcl_extraction_security Exp7 (Float64
 *         b_eff~6). b_eff>1 => one-way; b_eff<=1 => keystream collapses the
 *         backward tree (state-recoverable stream).
 *
 * BUILD:
 *   c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish \
 *       -o mcl_keyed_q30_science2 mcl_keyed_q30_science2.cpp && ./mcl_keyed_q30_science2
 * ============================================================================
 */
#include "mcl_keyed_q30.hpp"
#include <cstdio>
#include <cmath>
#include <vector>

namespace {

// ---- 4x4 Gauss-Seidel one-step map + analytic Jacobian (continuous analog) --
struct M4 { double a[4][4]; };
static M4 ident(){ M4 m{}; for(int i=0;i<4;i++) m.a[i][i]=1.0; return m; }
static M4 mul(const M4&A,const M4&B){ M4 C{};
  for(int i=0;i<4;i++)for(int j=0;j<4;j++){double s=0;for(int k=0;k<4;k++)s+=A.a[i][k]*B.a[k][j];C.a[i][j]=s;}
  return C; }

static void step_and_jac(double t[4], const double P[6], const double Q[6],
                         const double w[4], double K, M4& Jstep) {
    auto C=[&](double x){ return K*std::cos(x); };
    double a12=P[0]*t[1]-Q[0]*t[0], a13=P[1]*t[2]-Q[1]*t[0], a14=P[2]*t[3]-Q[2]*t[0];
    M4 J1=ident();
    J1.a[0][0]=1.0-(Q[0]*C(a12)+Q[1]*C(a13)+Q[2]*C(a14));
    J1.a[0][1]=P[0]*C(a12); J1.a[0][2]=P[1]*C(a13); J1.a[0][3]=P[2]*C(a14);
    t[0]=mod2pi(t[0]+w[0]+K*(std::sin(a12)+std::sin(a13)+std::sin(a14)));
    double b21=P[0]*t[0]-Q[0]*t[1], b23=P[3]*t[2]-Q[3]*t[1], b24=P[4]*t[3]-Q[4]*t[1];
    M4 J2=ident();
    J2.a[1][0]=P[0]*C(b21);
    J2.a[1][1]=1.0-(Q[0]*C(b21)+Q[3]*C(b23)+Q[4]*C(b24));
    J2.a[1][2]=P[3]*C(b23); J2.a[1][3]=P[4]*C(b24);
    t[1]=mod2pi(t[1]+w[1]+K*(std::sin(b21)+std::sin(b23)+std::sin(b24)));
    double c31=P[1]*t[0]-Q[1]*t[2], c32=P[3]*t[1]-Q[3]*t[2], c34=P[5]*t[3]-Q[5]*t[2];
    M4 J3=ident();
    J3.a[2][0]=P[1]*C(c31); J3.a[2][1]=P[3]*C(c32);
    J3.a[2][2]=1.0-(Q[1]*C(c31)+Q[3]*C(c32)+Q[5]*C(c34));
    J3.a[2][3]=P[5]*C(c34);
    t[2]=mod2pi(t[2]+w[2]+K*(std::sin(c31)+std::sin(c32)+std::sin(c34)));
    double d41=P[2]*t[0]-Q[2]*t[3], d42=P[4]*t[1]-Q[4]*t[3], d43=P[5]*t[2]-Q[5]*t[3];
    M4 J4=ident();
    J4.a[3][0]=P[2]*C(d41); J4.a[3][1]=P[4]*C(d42); J4.a[3][2]=P[5]*C(d43);
    J4.a[3][3]=1.0-(Q[2]*C(d41)+Q[4]*C(d42)+Q[5]*C(d43));
    t[3]=mod2pi(t[3]+w[3]+K*(std::sin(d41)+std::sin(d42)+std::sin(d43)));
    Jstep=mul(J4,mul(J3,mul(J2,J1)));
}

// 2-vector Benettin: maintain a 4x2 orthonormal frame; return mean ln of the
// two QR diagonals (= lambda_1, lambda_2). No 3rd/4th direction => no underflow.
static void lyap2(const double P[6], const double Q[6], const double w[4],
                  double K, uint64_t seed, long N, double& l1, double& l2) {
    double t[4]; uint64_t s=hash_seed(seed);
    t[0]=mod2pi((double)s*OMEGA_1); t[1]=mod2pi((double)s*OMEGA_2);
    t[2]=mod2pi((double)s*OMEGA_3); t[3]=mod2pi((double)s*OMEGA_4);
    M4 J;
    for(int i=0;i<BURNIN;i++) step_and_jac(t,P,Q,w,K,J);
    // frame columns u,v (4-vectors)
    double u[4]={1,0,0,0}, v[4]={0,1,0,0};
    double acc1=0, acc2=0;
    for(long n=0;n<N;n++){
        step_and_jac(t,P,Q,w,K,J);
        double Ju[4], Jv[4];
        for(int i=0;i<4;i++){ Ju[i]=0; Jv[i]=0;
            for(int k=0;k<4;k++){ Ju[i]+=J.a[i][k]*u[k]; Jv[i]+=J.a[i][k]*v[k]; } }
        // Gram-Schmidt: r11=|Ju|, q1=Ju/r11; r22=|Jv - (q1.Jv)q1|
        double r11=std::sqrt(Ju[0]*Ju[0]+Ju[1]*Ju[1]+Ju[2]*Ju[2]+Ju[3]*Ju[3]);
        if(r11<1e-300) r11=1e-300;
        double q1[4]; for(int i=0;i<4;i++) q1[i]=Ju[i]/r11;
        double dot=q1[0]*Jv[0]+q1[1]*Jv[1]+q1[2]*Jv[2]+q1[3]*Jv[3];
        double pv[4]; for(int i=0;i<4;i++) pv[i]=Jv[i]-dot*q1[i];
        double r22=std::sqrt(pv[0]*pv[0]+pv[1]*pv[1]+pv[2]*pv[2]+pv[3]*pv[3]);
        if(r22<1e-300) r22=1e-300;
        double q2[4]; for(int i=0;i<4;i++) q2[i]=pv[i]/r22;
        acc1+=std::log(r11); acc2+=std::log(r22);
        for(int i=0;i<4;i++){ u[i]=q1[i]; v[i]=q2[i]; }
    }
    l1=acc1/(double)N; l2=acc2/(double)N;
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
    std::printf("  MCL KEYED Q30 -- SCIENTIFIC v2 (hyperchaos + exact b_eff)\n");
    std::printf("================================================================\n");
    uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i*7+1);
    const double w[4]={OMEGA_1,OMEGA_2,OMEGA_3,OMEGA_4};

    // ---------------- [T1b] hyperchaos via 2-vector Benettin ----------------
    std::printf("\n[T1b] Hyperchaos: top-2 Lyapunov exponents (underflow-free 2-vector Benettin)\n");
    {
        double Ps[6]={2,3,5,7,11,13}, Qs[6]={3,5,7,11,13,17}, l1,l2;
        lyap2(Ps,Qs,w,K_DEFAULT,DEFAULT_SEED,200000,l1,l2);
        std::printf("  (a) small weights: lambda_1=%.4f  lambda_2=%.4f  -> %s\n",
                    l1,l2, (l1>0&&l2>0)?"hyperchaotic":"not");
        MCL_Q30_Sextet sx=mcl_t4_q30_params_from_key(key);
        double P[6],Q[6]; weights_to_PQ(sx,P,Q);
        // average over several keys to be representative
        double sum1=0,sum2=0; int K_KEYS=5; int pos2=0;
        for(int kk=0;kk<K_KEYS;kk++){
            uint8_t kx[32]; for(int i=0;i<32;i++) kx[i]=(uint8_t)(i*7+1+kk*101);
            MCL_Q30_Sextet sk=mcl_t4_q30_params_from_key(kx);
            double Pk[6],Qk[6]; weights_to_PQ(sk,Pk,Qk);
            double a,b; lyap2(Pk,Qk,w,K_DEFAULT,DEFAULT_SEED+(uint64_t)kk*131,120000,a,b);
            std::printf("  (b) key %d (~2^30 weights): lambda_1=%.3f  lambda_2=%.4f  %s\n",
                        kk,a,b,(a>0&&b>0)?"[hyperchaotic]":"[NOT]");
            sum1+=a; sum2+=b; if(a>0&&b>0) pos2++;
        }
        std::printf("  mean over %d keys: lambda_1=%.3f  lambda_2=%.4f ; hyperchaotic in %d/%d\n",
                    K_KEYS,sum1/K_KEYS,sum2/K_KEYS,pos2,K_KEYS);
        std::printf("  => %s\n", (pos2==K_KEYS)
                    ? "PASS: lambda_2>0 for all keys -> T4-Q30 (continuous analog) HYPERCHAOTIC"
                    : "MIXED/FAIL: lambda_2 not uniformly positive -- investigate");
    }

    // ---------------- [T3b] EXACT keystream-constrained b_eff (integer) ------
    std::printf("\n[T3b] EXACT keystream-constrained b_eff of the 2-osc Q30 map (full backward enum)\n");
    {
        const int64_t kp=mcl_q30_K_phase(K_DEFAULT); const int64_t p=3,q=5;
        const MCL_Q30_Table& tab=mcl_q30_table();
        auto incf=[&](uint32_t a)->uint32_t{
            return (uint32_t)(int32_t)(((int64_t)kp*(int64_t)tab.sin_q30(a))>>30); };
        // forward GS: returns (t1',t2')
        auto fwd=[&](uint32_t t1,uint32_t t2,uint32_t&o1,uint32_t&o2){
            uint32_t a1=(uint32_t)((int64_t)p*(int64_t)t2-(int64_t)q*(int64_t)t1);
            o1=t1+mcl_q30_omega1()+incf(a1);
            uint32_t a2=(uint32_t)((int64_t)p*(int64_t)o1-(int64_t)q*(int64_t)t2);
            o2=t2+mcl_q30_omega2()+incf(a2);
        };
        // representative integer output byte from a state (top zones of t1^t2)
        auto obyte=[&](uint32_t t1,uint32_t t2)->uint8_t{
            uint32_t x=t1^t2; return (uint8_t)((x>>16)^(x>>24)); };

        long tot_pre2D=0, tot_byte=0; int targets=4;
        for(int tc=0;tc<targets;tc++){
            // real-trajectory target successor (T1,T2) and the true predecessor's byte
            uint32_t pt1,pt2; mcl_q30_init_state(DEFAULT_SEED+(uint64_t)tc*7919u,pt1,pt2);
            for(int i=0;i<3000+tc*50;i++) mcl_q30_iterate_raw(pt1,pt2,p,q,kp);
            uint8_t o_true=obyte(pt1,pt2);            // observed keystream byte of the predecessor
            uint32_t T1,T2; fwd(pt1,pt2,T1,T2);       // the successor the attacker sees

            // EXACT backward enumeration:
            //   t2' = T2 fixes t2 via: T2 == t2 + omega2 + inc(p*T1 - q*t2)
            //   then t1' = T1 fixes t1 via: T1 == t1 + omega1 + inc(p*t2 - q*t1)
            long pre2D=0, prebyte=0;
            // pass 1: collect valid t2 (full 2^32 scan)
            std::vector<uint32_t> goodT2; goodT2.reserve(8);
            uint32_t z=0;
            do {
                uint32_t a2=(uint32_t)((int64_t)p*(int64_t)T1-(int64_t)q*(int64_t)z);
                if((uint32_t)(z+mcl_q30_omega2()+incf(a2))==T2) goodT2.push_back(z);
                z++;
            } while(z!=0);
            // pass 2: for each valid t2, scan t1 (full 2^32) for forward t1'==T1
            for(uint32_t t2c : goodT2){
                uint32_t y=0;
                do {
                    uint32_t a1=(uint32_t)((int64_t)p*(int64_t)t2c-(int64_t)q*(int64_t)y);
                    if((uint32_t)(y+mcl_q30_omega1()+incf(a1))==T1){
                        pre2D++;
                        if(obyte(y,t2c)==o_true) prebyte++;
                    }
                    y++;
                } while(y!=0);
            }
            std::printf("  target %d: valid t2=%zu, full 2-D preimages=%ld, byte-consistent=%ld\n",
                        tc,goodT2.size(),pre2D,prebyte);
            tot_pre2D+=pre2D; tot_byte+=prebyte;
        }
        double b2D=(double)tot_pre2D/targets;
        double beff=(double)tot_byte/targets;
        std::printf("\n  mean 2-D one-step preimages  b_2D  = %.2f  (Float64 ~ b^2 ~ 1444)\n", b2D);
        std::printf("  mean keystream-constrained   b_eff = %.2f  (Float64 Exp7 ~ 6)\n", beff);
        std::printf("  => b_eff=%.2f. CORRECTION (see mcl_keyed_q30_beff_recheck): b_eff~1 at 8-bit\n"
                    "     is GENERIC arithmetic of small b_2D + 8-bit byte (b_eff ~ 1+(b_2D-1)/2^k;\n"
                    "     measured 1.92/1.33/1.00/1.00 at k=1/2/4/8), NOT a weakness. An ~invertible\n"
                    "     state map is normal for a keystream generator; 'state-recoverable from\n"
                    "     keystream' does NOT follow and was never demonstrated. The real finding is\n"
                    "     only that Q30 is far less folding than Float64 (b_2D~3.25 vs ~1444), which\n"
                    "     matters solely for map-based one-wayness -- unused by any MCL construction\n"
                    "     (HD uses Float64; keyed Q30 gets one-wayness from SHA-256).\n", beff);
    }

    std::printf("\n================================================================\n");
    std::printf("  v2 complete.\n");
    std::printf("================================================================\n");
    return 0;
}
