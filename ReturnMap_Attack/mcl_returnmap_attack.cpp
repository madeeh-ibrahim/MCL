// mcl_returnmap_attack.cpp — Doc ID MCL-RMAP-2026-0822-001
// ---------------------------------------------------------------------------
// Chaos-specific attack attempts (Álvarez–Li 2006, Rule 13; Rule 7 partial key
// knowledge) on the outputs MCL actually exposes.  Until now the project had
// RQA / 0-1 test statistics but NO documented attempt at return-map
// reconstruction, delay-embedding (Takens) structure, error-function attack
// (EFA) parameter estimation, or partial-key leakage.  This tool makes those
// attempts and records them.  A negative result is "attempted, not found",
// never a proof.
//
// TARGETS (what an attacker can observe)
//   A  keyed T4-Q30 keystream bytes      MCL_T4_Q30::gen_byte     (public seed, secret 256-bit key)
//   B  commit32 raw words                (t1, t2^t3^t4) per iteration — the raw-state interface
//   C  full raw state (s1..s4)           strongest model, used for EFA + partial-key tests
//   D  2-osc raw t1 (mcl_q30_iterate_raw, (p,q)=(3,5))  CONTROL: known BROKEN by lattice (June 2026)
//
// ANALYSES
//   §1 Return map occupancy: 2-D (x_n,x_{n+1}) on GxG and 3-D conditional entropy
//      H(x_{n+2}|x_n,x_{n+1}) — a low-dimensional return map shows a curve
//      (occupancy << G^2, conditional entropy << log2 G).
//   §2 Average mutual information I(x_n ; x_{n+tau}), tau = 1..8 (Fraser–Swinney).
//   §3 False nearest neighbours (Kennel) m=1..5 and correlation dimension D2
//      (Grassberger–Procaccia) m=2..6 on a subsample — low-dim attractor => FNN->0,
//      D2 saturates; i.i.d.-like output => FNN stays high, D2 ~ m.
//   §4 Error-function attack: trajectory error and ONE-STEP prediction error as a
//      function of a parameter offset delta along one weight (all other weights
//      known): a basin/monotone curve => gradient => descent recovers the weight;
//      flat at 50% except delta=0 => no EFA gradient.
//   §5 Partial-key leakage (Rule 7): attacker knows 10 of 12 weights and observes
//      the FULL raw state for R iterations; count candidates (p,q) in a 2^12 x 2^12
//      window consistent with the observation.  Raw-state exposure is expected
//      to identify the pair (supports the standing policy "raw-state
//      externalization excluded"); the same test against commit32's XOR-folded
//      word is under-determined by construction and reported as N/A.
//
// NOTHING is executed by building this file.  Run commands are in README.md.
// ---------------------------------------------------------------------------
#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>

using Clock = std::chrono::steady_clock;
static double now_s(){ static auto t0=Clock::now(); return std::chrono::duration<double>(Clock::now()-t0).count(); }

// ------------------------------------------------------------------ targets
struct Series { std::string name; std::vector<double> x; /* in [0,1) */ };

static const uint8_t* kat_key(){ static uint8_t k[32]; for(int i=0;i<32;i++) k[i]=(uint8_t)i; return k; }

static Series target_A(size_t n){
    Series s; s.name="A keyed-T4 keystream bytes"; s.x.resize(n);
    MCL_T4_Q30 e(kat_key(),0,DEFAULT_SEED,K_DEFAULT);
    for(size_t i=0;i<n;i++) s.x[i]=(double)e.gen_byte()/256.0;
    return s;
}
static void target_B(size_t n, Series& t1s, Series& xs){
    t1s.name="B commit32 raw t1 words"; xs.name="B commit32 raw (t2^t3^t4) words"; t1s.x.resize(n); xs.x.resize(n);
    MCL_T4_Q30 e(kat_key(),0,DEFAULT_SEED,K_DEFAULT);
    for(size_t i=0;i<n;i++){ e.iterate(); t1s.x[i]=(double)e.s1()/4294967296.0; xs.x[i]=(double)(e.s2()^e.s3()^e.s4())/4294967296.0; }
}
static Series target_D(size_t n){
    Series s; s.name="D 2-osc raw t1 (3,5) CONTROL"; s.x.resize(n);
    uint32_t t1,t2; mcl_q30_init_state(DEFAULT_SEED,t1,t2); const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
    for(int i=0;i<BURNIN;i++) mcl_q30_iterate_raw(t1,t2,3,5,kp);
    for(size_t i=0;i<n;i++){ mcl_q30_iterate_raw(t1,t2,3,5,kp); s.x[i]=(double)t1/4294967296.0; }
    return s;
}

// Exact expectation of the plug-in (maximum-likelihood) entropy, in bits, of a uniform
// multinomial with K cells and n samples, using the Poisson approximation per cell:
//   E[H] = log2(n) - (K/n) * E[k log2 k],  k ~ Poisson(lambda = n/K).
// Computed in log-space so it is valid for any lambda (Miller–Madow is not, at n/K ~ 2).
static double expected_plugin_entropy_bits(double n, double K){
    const double lam=n/K; if(!(lam>0)) return 0.0;
    const int kmax=(int)(lam+20.0*std::sqrt(lam)+50.0);
    double eklogk=0; for(int k=1;k<=kmax;k++){ double logp=-lam+k*std::log(lam)-std::lgamma((double)k+1.0); eklogk+=std::exp(logp)*k*std::log2((double)k); }
    return std::log2(n)-(K/n)*eklogk;
}
// ------------------------------------------------------------------ §1 return map
static void return_map(const Series& s, int G){
    const size_t n=s.x.size();
    std::vector<uint32_t> h2((size_t)G*G,0);
    for(size_t i=0;i+1<n;i++){ int a=(int)(s.x[i]*G), b=(int)(s.x[i+1]*G); h2[(size_t)a*G+b]++; }
    size_t occ=0; double chi2=0, H=0; const double exp_=(double)(n-1)/((double)G*G);
    for(uint32_t c: h2){ if(c){ occ++; double p=c/(double)(n-1); H-=p*std::log2(p);} chi2+=(c-exp_)*(c-exp_)/exp_; }
    const double df=(double)G*G-1.0;
    const double cells=(double)G*G, occ_exp=1.0-std::exp(-(double)(n-1)/cells);          // uniform multinomial
    // exact expectation of the plug-in entropy for a uniform multinomial (Poisson approximation per cell):
    //   E[H] = log2(n') - (K/n') * E[k log2 k],  k ~ Poisson(lambda = n'/K)     (Miller–Madow is invalid at n'/K ~ 2)
    const double lam=(double)(n-1)/cells;
    const double H_exp=expected_plugin_entropy_bits((double)(n-1),cells);
    const double z_chi=(chi2-df)/std::sqrt(df*(2.0+1.0/lam));   // Var of a Pearson term at expected count lambda is 2+1/lambda
    std::printf("  [§1] %s: 2-D return map G=%d: occupied %.4f (uniform exp %.4f), chi2=%.1f (df %.0f, z=%.2f), H=%.3f bits (uniform exp %.3f)\n",
        s.name.c_str(),G,occ/cells,occ_exp,chi2,df,z_chi,H,H_exp);
    // 3-D conditional entropy on g=min(G,32) (g=64 would carry ~1.4 bits of finite-sample bias at n=2^17)
    const int g=std::min(G,32);
    std::vector<uint32_t> h3((size_t)g*g*g,0), h2b((size_t)g*g,0);
    for(size_t i=0;i+2<n;i++){ int a=(int)(s.x[i]*g), b=(int)(s.x[i+1]*g), c=(int)(s.x[i+2]*g); h3[((size_t)a*g+b)*g+c]++; h2b[(size_t)a*g+b]++; }
    double H3=0,H2=0; const double m=(double)(n-2);
    for(uint32_t c: h3) if(c){ double p=c/m; H3-=p*std::log2(p);} for(uint32_t c: h2b) if(c){ double p=c/m; H2-=p*std::log2(p);}
    const double Hc_exp=expected_plugin_entropy_bits(m,(double)g*g*g)-expected_plugin_entropy_bits(m,(double)g*g); // exact (Poisson) E[H3]-E[H2] under uniform i.i.d.
    std::printf("       3-D: H(x_{n+2}|x_n,x_{n+1}) = %.3f bits; uniform-i.i.d. expectation (exact, g=%d) = %.3f  [log2 g = %.3f]\n",
        H3-H2,g,Hc_exp,std::log2((double)g));
}

// ------------------------------------------------------------------ §2 AMI
static double ami(const Series& s, int tau, int G){
    const size_t n=s.x.size(); if(n<=(size_t)tau+1) return 0;
    std::vector<uint32_t> hj((size_t)G*G,0), ha(G,0), hb(G,0);
    for(size_t i=0;i+tau<n;i++){ int a=(int)(s.x[i]*G), b=(int)(s.x[i+tau]*G); hj[(size_t)a*G+b]++; ha[a]++; hb[b]++; }
    const double m=(double)(n-tau); double I=0;
    for(int a=0;a<G;a++) for(int b=0;b<G;b++){ uint32_t c=hj[(size_t)a*G+b]; if(!c) continue; double p=c/m; I+=p*std::log2(p/((ha[a]/m)*(hb[b]/m))); }
    return I;
}
static void ami_scan(const Series& s, int G){
    std::printf("  [§2] %s: AMI bits (G=%d, bias~%.4f): ", s.name.c_str(), G, ((double)G-1)*((double)G-1)/(2.0*s.x.size()*std::log(2.0)));
    for(int tau=1;tau<=8;tau++) std::printf("tau%d=%.4f ",tau,ami(s,tau,G));
    std::printf("\n");
}

// ------------------------------------------------------------------ §3 FNN + D2
static std::vector<double> shuffled_copy(const std::vector<double>& x, size_t n){
    // deterministic Fisher–Yates with xorshift64* — destroys temporal order, keeps the marginal
    std::vector<double> y(x.begin(), x.begin()+n); uint64_t st=0x9E3779B97F4A7C15ULL;
    for(size_t i=n-1;i>0;i--){ st^=st>>12; st^=st<<25; st^=st>>27; uint64_t r=st*0x2545F4914F6CDD1DULL; size_t j=(size_t)(r%(i+1)); std::swap(y[i],y[j]); }
    return y;
}
static double fnn_fraction(const std::vector<double>& x, int m, double RTOL, double ATOL, double RA, double* tie_frac=nullptr){
    // Kennel et al. 1992: neighbour (in m-D, tau=1) is FALSE if  |e|/dm > RTOL  OR  sqrt(dm^2+e^2)/RA > ATOL.
    // Exact ties (dm == 0, frequent in quantised byte data): Kennel's ratio is infinite, so FALSE iff e > 0.
    const size_t n=x.size(); size_t cnt=0,fnn=0,ties=0;
    for(size_t i=0;i+m<n;i++){
        double best=1e300; size_t bj=0;
        for(size_t j=0;j+m<n;j++){ if(j==i) continue; double d=0; for(int k=0;k<m;k++){ double e=x[i+k]-x[j+k]; d+=e*e; } if(d<best){best=d;bj=j;} }
        double dm=std::sqrt(best), e=std::fabs(x[i+m]-x[bj+m]);
        bool f = (dm==0.0 ? (e>0.0) : (e/dm>RTOL)) || (std::sqrt(dm*dm+e*e)/RA > ATOL);
        cnt++; if(f) fnn++; if(dm==0.0) ties++;
    }
    if(tie_frac) *tie_frac=ties/(double)std::max<size_t>(1,cnt);
    return fnn/(double)std::max<size_t>(1,cnt);
}
static double d2_slope(const std::vector<double>& x, int m, double q1, double q2){
    // Grassberger–Procaccia slope of log C(r) vs log r between the q1- and q2-quantiles of the
    // pairwise-distance distribution (C(r_q) = q by construction): slope = ln(q2/q1)/ln(r_q2/r_q1).
    const size_t n=x.size(); std::vector<float> d; d.reserve((n*(n-1))/2);
    for(size_t i=0;i+m<=n;i++) for(size_t j=i+1;j+m<=n;j++){ double s2=0; for(int k=0;k<m;k++){ double e=x[i+k]-x[j+k]; s2+=e*e; } d.push_back((float)std::sqrt(s2)); }
    if(d.size()<100) return NAN;
    size_t i1=(size_t)(q1*d.size()), i2=(size_t)(q2*d.size());
    std::nth_element(d.begin(),d.begin()+i1,d.end()); double r1=d[i1];
    std::nth_element(d.begin(),d.begin()+i2,d.end()); double r2=d[i2];
    if(!(r1>0.0) || !(r2>r1)) return NAN;
    return std::log(q2/q1)/std::log(r2/r1);
}
static void fnn_d2(const Series& s, size_t nsub){
    const size_t n=std::min(nsub,s.x.size()); const int MMAX=6; const double RTOL=10.0, ATOL=2.0;
    std::vector<double> x(s.x.begin(), s.x.begin()+n), xs=shuffled_copy(s.x,n);
    double mean=0; for(double v: x) mean+=v; mean/=n; double var=0; for(double v: x) var+=(v-mean)*(v-mean); const double RA=std::sqrt(var/n);
    std::printf("  [§3] %s (n=%zu, tau=1; each statistic shown as  series | shuffled-surrogate ):\n", s.name.c_str(), n);
    std::printf("       FNN(m) [tie-frac]: ");
    for(int m=1;m<MMAX;m++){ double tf=0; double a=fnn_fraction(x,m,RTOL,ATOL,RA,&tf), b=fnn_fraction(xs,m,RTOL,ATOL,RA); std::printf("m%d %.3f|%.3f [%.2f]  ", m, a, b, tf); }
    std::printf("\n       D2 slope(m): ");
    for(int m=2;m<=MMAX;m++) std::printf("m%d %.2f|%.2f  ", m, d2_slope(x,m,0.001,0.01), d2_slope(xs,m,0.001,0.01));
    std::printf("\n       reading: the ONLY criterion is series vs surrogate (same marginal, order destroyed): series FNN << surrogate, or D2 saturating below the surrogate,\n"
                "       => low-dimensional deterministic structure; series ~ surrogate => none detected at this n. Absolute values (incl. D2 ~ m) are NOT criteria at this n.\n");
}

// ------------------------------------------------------------------ §4 EFA
static int hd32(uint32_t a,uint32_t b){ return __builtin_popcount(a^b); }
static void efa_T4(){
    // observed: full raw state trajectory for L steps after burn-in, true weights W
    const MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(kat_key(),0);
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT); const int L=4096;
    uint32_t t1,t2,t3,t4; { MCL_T4_Q30 e(kat_key(),0,DEFAULT_SEED,K_DEFAULT); t1=e.s1();t2=e.s2();t3=e.s3();t4=e.s4(); }
    std::vector<uint32_t> obs(4*(L+1)); obs[0]=t1;obs[1]=t2;obs[2]=t3;obs[3]=t4;
    { uint32_t a=t1,b=t2,c=t3,d=t4; for(int i=1;i<=L;i++){ mcl_q30t4_iterate_raw(a,b,c,d,W,kp); obs[4*i]=a;obs[4*i+1]=b;obs[4*i+2]=c;obs[4*i+3]=d; } }
    std::printf("  [§4] EFA on T4 FULL raw state, all weights known except p12=%u; L=%d\n", W.p12, L);
    std::printf("       expectation: flat ~64/128 (sd ~ %.2f over L) for small delta; DIPS at delta = 2^k (k large) are STRUCTURAL — delta*t2 mod 2^32 is then\n"
                "       zero with probability 2^-(32-k) (one-step dip ~ 16*2^-(32-k) + 48*2^-2(32-k) bits: ~2.8 at k=29, ~1.2 at k=28, <0.3 for k<=26)\n"
                "       — i.e. raw state leaks high weight bits (the known lattice structure; raw-state export is excluded by policy)\n", std::sqrt(32.0)/std::sqrt((double)L));
    std::printf("       %-12s %-22s %-22s\n","delta","traj HD/128 (mean)","one-step HD/128 (mean)");
    const long long deltas[]={0,1,-1,2,-2,4,-4,16,-16,256,-256,4096,-4096,65536,-65536,1<<20,-(1<<20),1<<24,-(1<<24),1<<26,-(1<<26),1<<28,-(1<<28),1<<29,-(1<<29)};
    for(long long d: deltas){
        long long pp=(long long)W.p12+d; if(pp<2 || pp>=(1LL<<30)) continue;
        MCL_Q30_Sextet Wc=W; Wc.p12=(uint32_t)pp;
        // trajectory error (free-running from the known initial state)
        uint32_t a=obs[0],b=obs[1],c=obs[2],e=obs[3]; double th=0;
        for(int i=1;i<=L;i++){ mcl_q30t4_iterate_raw(a,b,c,e,Wc,kp); th+=hd32(a,obs[4*i])+hd32(b,obs[4*i+1])+hd32(c,obs[4*i+2])+hd32(e,obs[4*i+3]); }
        // one-step prediction error (candidate re-synchronised to the observed state each step)
        double oh=0;
        for(int i=0;i<L;i++){ uint32_t x=obs[4*i],y=obs[4*i+1],z=obs[4*i+2],u=obs[4*i+3]; mcl_q30t4_iterate_raw(x,y,z,u,Wc,kp); oh+=hd32(x,obs[4*i+4])+hd32(y,obs[4*i+5])+hd32(z,obs[4*i+6])+hd32(u,obs[4*i+7]); }
        std::printf("       %-12lld %-22.2f %-22.2f\n", d, th/L, oh/L);
    }
}
static void efa_2osc(){
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT); const int L=4096; const int64_t P=3,Q=5;
    uint32_t t1,t2; mcl_q30_init_state(DEFAULT_SEED,t1,t2); for(int i=0;i<BURNIN;i++) mcl_q30_iterate_raw(t1,t2,P,Q,kp);
    std::vector<uint32_t> obs(2*(L+1)); obs[0]=t1;obs[1]=t2; { uint32_t a=t1,b=t2; for(int i=1;i<=L;i++){ mcl_q30_iterate_raw(a,b,P,Q,kp); obs[2*i]=a;obs[2*i+1]=b; } }
    std::printf("  [§4] EFA on 2-osc CONTROL (p,q)=(3,5), q known, scan p'; L=%d\n", L);
    std::printf("       %-8s %-22s %-22s\n","p'","traj HD/64 (mean)","one-step HD/64 (mean)");
    for(int64_t pp=1;pp<=12;pp++){
        uint32_t a=obs[0],b=obs[1]; double th=0; for(int i=1;i<=L;i++){ mcl_q30_iterate_raw(a,b,pp,Q,kp); th+=hd32(a,obs[2*i])+hd32(b,obs[2*i+1]); }
        double oh=0; for(int i=0;i<L;i++){ uint32_t x=obs[2*i],y=obs[2*i+1]; mcl_q30_iterate_raw(x,y,pp,Q,kp); oh+=hd32(x,obs[2*i+2])+hd32(y,obs[2*i+3]); }
        std::printf("       %-8lld %-22.2f %-22.2f%s\n",(long long)pp,th/L,oh/L, pp==P?"  <== true":"");
    }
}

static void efa_keystream(){
    // Target A model: attacker sees keystream bytes only, knows all weights but p12, tries a candidate engine
    // with p12+delta from the same public seed and compares L bytes (no re-synchronisation is possible).
    const MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(kat_key(),0); const int64_t kp=mcl_q30_K_phase(K_DEFAULT); const int L=4096;
    auto stream=[&](const MCL_Q30_Sextet& Wc, std::vector<uint8_t>& out){
        uint64_t sd=hash_seed(DEFAULT_SEED); uint32_t t1=(uint32_t)((sd*(uint64_t)mcl_q30_omega1())&0xFFFFFFFFULL), t2=(uint32_t)((sd*(uint64_t)mcl_q30_omega2())&0xFFFFFFFFULL),
                 t3=(uint32_t)((sd*(uint64_t)mcl_q30_omega3())&0xFFFFFFFFULL), t4=(uint32_t)((sd*(uint64_t)mcl_q30_omega4())&0xFFFFFFFFULL);
        for(int i=0;i<BURNIN;i++) mcl_q30t4_iterate_raw(t1,t2,t3,t4,Wc,kp);
        out.resize(L); for(int i=0;i<L;i++){ for(int d=0;d<DECIMATION;d++) mcl_q30t4_iterate_raw(t1,t2,t3,t4,Wc,kp); uint32_t x=t1^t2^t3^t4; out[i]=(uint8_t)((x>>16)^(x>>24)); }
    };
    std::vector<uint8_t> obs; stream(W,obs);
    { MCL_T4_Q30 e(kat_key(),0,DEFAULT_SEED,K_DEFAULT); std::vector<uint8_t> chk(L); e.gen_bytes(chk.data(),L);
      std::printf("  [§4] EFA on keystream (target A): local re-implementation vs MCL_T4_Q30::gen_bytes: %s\n", chk==obs?"IDENTICAL (harness faithful)":"MISMATCH (harness error)"); }
    std::printf("       %-12s %-18s\n","delta","byte-stream HD/8 (mean over 4096 B)");
    const long long deltas[]={0,1,-1,2,-2,256,-256,65536,-65536,1<<24,-(1<<24),1<<28,-(1<<28),1<<29,-(1<<29)};
    for(long long d: deltas){ long long pp=(long long)W.p12+d; if(pp<2||pp>=(1LL<<30)) continue; MCL_Q30_Sextet Wc=W; Wc.p12=(uint32_t)pp; std::vector<uint8_t> c; stream(Wc,c);
        double h=0; for(int i=0;i<L;i++) h+=__builtin_popcount(obs[i]^c[i]); std::printf("       %-12lld %-18.3f\n", d, h/L); }
}

// ------------------------------------------------------------------ §5 partial-key leakage
static void partial_key_T4(int R){
    const MCL_Q30_Sextet W=mcl_t4_q30_params_from_key(kat_key(),0);
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
    uint32_t t1,t2,t3,t4; { MCL_T4_Q30 e(kat_key(),0,DEFAULT_SEED,K_DEFAULT); t1=e.s1();t2=e.s2();t3=e.s3();t4=e.s4(); }
    std::vector<uint32_t> obs(4*(R+1)); obs[0]=t1;obs[1]=t2;obs[2]=t3;obs[3]=t4;
    { uint32_t a=t1,b=t2,c=t3,d=t4; for(int i=1;i<=R;i++){ mcl_q30t4_iterate_raw(a,b,c,d,W,kp); obs[4*i]=a;obs[4*i+1]=b;obs[4*i+2]=c;obs[4*i+3]=d; } }
    // unknown pair = (p12,q12) inside a 2^12 x 2^12 window containing the truth
    const uint32_t WIN=1u<<12; const uint32_t p0=(W.p12/WIN)*WIN, q0=(W.q12/WIN)*WIN;
    std::printf("  [§5] Rule-7 partial-key test, T4 FULL raw state, R=%d observed iterations, unknown (p12,q12) in [%u,%u)x[%u,%u)\n", R,p0,p0+WIN,q0,q0+WIN);
    uint64_t consistent=0; bool truth_found=false; double t0=now_s();
    for(uint32_t p=p0;p<p0+WIN;p++){
        for(uint32_t q=q0;q<q0+WIN;q++){
            if(p==q) continue;
            MCL_Q30_Sextet Wc=W; Wc.p12=p; Wc.q12=q;
            bool ok=true;
            for(int i=0;i<R && ok;i++){ uint32_t x=obs[4*i],y=obs[4*i+1],z=obs[4*i+2],u=obs[4*i+3]; mcl_q30t4_iterate_raw(x,y,z,u,Wc,kp); ok=(x==obs[4*i+4]&&y==obs[4*i+5]&&z==obs[4*i+6]&&u==obs[4*i+7]); }
            if(ok){ consistent++; if(p==W.p12&&q==W.q12) truth_found=true; }
        }
    }
    std::printf("       consistent candidates: %llu of 2^24 (truth %s)  [%.1f s]  -> raw state under partial knowledge %s the pair\n",
        (unsigned long long)consistent, truth_found?"included":"MISSING (harness error)", now_s()-t0, consistent==1?"UNIQUELY IDENTIFIES":"does not uniquely identify");
    std::printf("       commit32 interface: observation is (t1, t2^t3^t4) — candidate step cannot be evaluated without t2,t3,t4 individually: N/A (under-determined; cf. 08_attack_t4_commit32.py June 2026)\n");
}

static void usage(){ std::printf("usage: mcl_returnmap_attack [--n N (default 131072)] [--nsub S (default 3000, max 12000)] [--G g (256)] [--sections 12345] [--R r (4)]\n"); }

int main(int argc,char** argv){
    size_t n=131072, nsub=3000; int G=256; std::string secs="12345"; int R=4;
    for(int i=1;i<argc;i++){ std::string a=argv[i]; auto nx=[&](){ if(i+1>=argc){usage();std::exit(2);} return std::string(argv[++i]); };
        if(a=="--n") n=std::strtoull(nx().c_str(),nullptr,10); else if(a=="--nsub") nsub=std::strtoull(nx().c_str(),nullptr,10);
        else if(a=="--G") G=std::atoi(nx().c_str()); else if(a=="--sections") secs=nx(); else if(a=="--R") R=std::atoi(nx().c_str()); else {usage();return 2;} }
    now_s();
    if(n<4096||n>(1u<<24)){ std::fprintf(stderr,"--n must be in [4096, 2^24]\n"); return 2; }
    if(nsub<64||nsub>12000){ std::fprintf(stderr,"--nsub must be in [64, 12000] (D2 stores nsub^2/2 floats: 12000 -> ~290 MB; time O(nsub^2))\n"); return 2; }
    if(G<16||G>1024){ std::fprintf(stderr,"--G must be in [16,1024]\n"); return 2; }
    if(R<1||R>64){ std::fprintf(stderr,"--R must be in [1,64]\n"); return 2; }
    std::printf("================================================================\n");
    std::printf("  MCL chaos-specific attack attempts (return map / Takens / EFA / partial key)\n");
    std::printf("  MCL-RMAP-2026-0822-001   engine mcl_core %s (%s) UNMODIFIED + keyed sidecar\n", MCL_VERSION_STRING, MCL_VERSION_DATE);
    std::printf("  n=%zu nsub=%zu G=%d sections=%s R=%d  key=KAT{0..31} seed=DEFAULT_SEED K=%.1f\n", n,nsub,G,secs.c_str(),R,K_DEFAULT);
    std::printf("================================================================\n");
    auto has=[&](char c){ return secs.find(c)!=std::string::npos; };
    Series A=target_A(n); Series B1,B2; target_B(n,B1,B2); Series D=target_D(n);
    const Series* all[4]={&A,&B1,&B2,&D};
    if(256%G!=0) std::printf("WARNING: --G=%d does not divide 256 — target A (bytes) will show quantisation artefacts in §1, not dynamics\n",G);
    if(has('1')){ std::printf("\n§1 RETURN-MAP OCCUPANCY / CONDITIONAL ENTROPY\n"); for(auto s: all) return_map(*s,G); }
    if(has('2')){ std::printf("\n§2 AVERAGE MUTUAL INFORMATION (delay selection)\n"); for(auto s: all) ami_scan(*s,64); }
    if(has('3')){ std::printf("\n§3 FALSE NEAREST NEIGHBOURS + CORRELATION DIMENSION (subsample)\n"); for(auto s: all) fnn_d2(*s,nsub); }
    if(has('4')){ std::printf("\n§4 ERROR-FUNCTION ATTACK (parameter-offset scan)\n"); efa_T4(); efa_2osc(); efa_keystream(); }
    if(has('5')){ std::printf("\n§5 PARTIAL-KEY LEAKAGE FROM RAW STATE (Rule 7)\n"); partial_key_T4(R); }
    std::printf("\nDONE (%.0f s)\n", now_s());
    return 0;
}
