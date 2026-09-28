/* symenum.c (v2, 2026-09-27 evening: visit order is now a full permutation) — exhaustive translation-symmetry enumeration on a reduced-width replica of Algorithm 1's
 * unclocked map G (ت-218, 2026-09-27). n words of w bits, Gauss-Seidel order, coupling argument
 * a = p*t_j - q*t_i mod 2^w, table indexed by the top w/2 bits (LUT[i] = trunc(sin(2*pi*i/2^(w/2)) * 2^(w-2))),
 * increment = low_w((K_phase * s) >> (w-2)) with K_phase = floor(K*2^w/(2*pi)), K = 12, omega_k = floor(Omega_k/(2*pi)*2^w),
 * weights p,q uniform in [2, 2^(w-2)) with the pair rule (p != q), NO parity rule (rank-deficient sets are wanted).
 * For every non-zero delta in (Z/2^w)^n: (S) F(t+delta) == F(t)+delta for ALL t  [translation symmetry],
 *                                      (P) F(t+delta) == F(t)     for ALL t  [period].
 * Predicted set: delta with p_ij*delta_j - q_ij*delta_i == 0 and p_ij*delta_i - q_ij*delta_j == 0 (mod 2^w) for all pairs.
 * Reports per weight set: parity-matrix rank, |found S|, |predicted|, |found \ predicted|, |predicted \ found|, |found P|.
 * Usage: ./symenum n w sets seed */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <time.h>
static int n, w; static uint32_t MASK; static int tb; static int32_t lut[1<<16]; static uint64_t kphase; static uint32_t omega[8];
static uint32_t P[8][8], Q[8][8];
static uint64_t sm_state; static uint64_t sm(void){ uint64_t z=(sm_state+=0x9E3779B97F4A7C15ull); z=(z^(z>>30))*0xBF58476D1CE4E5B9ull; z=(z^(z>>27))*0x94D049BB133111EBull; return z^(z>>31); }
static inline uint32_t inc_of(uint32_t a){ int32_t s=lut[a>>(w-tb)]; return (uint32_t)(((uint64_t)((int64_t)kphase*(int64_t)s))>>(w-2)) & MASK; }
static inline void F(const uint32_t* t, uint32_t* o){ uint32_t s[8]; memcpy(s,t,sizeof(uint32_t)*n);
  for(int k=0;k<n;k++){ uint32_t acc=omega[k]; for(int j=0;j<n;j++) if(j!=k){ uint32_t a=(P[k][j]*s[j]-Q[k][j]*s[k])&MASK; acc+=inc_of(a);} s[k]=(s[k]+acc)&MASK; }
  memcpy(o,s,sizeof(uint32_t)*n); }
static void unpack(uint64_t v, uint32_t* t){ for(int k=0;k<n;k++){ t[k]=(uint32_t)(v&MASK); v>>=w; } }
static int predicted(const uint32_t* d){ for(int i=0;i<n;i++) for(int j=i+1;j<n;j++){ uint32_t p=P[i][j], q=Q[i][j];
  if(((p*d[j]-q*d[i])&MASK)!=0) return 0; if(((p*d[i]-q*d[j])&MASK)!=0) return 0; } return 1; }
static int parity_rank(void){ /* 2*C(n,2) rows over GF(2), n columns: rows (q&1)e_i+(p&1)e_j and (p&1)e_i+(q&1)e_j */
  int rows=0; uint32_t M[64]; for(int i=0;i<n;i++) for(int j=i+1;j<n;j++){ uint32_t p=P[i][j]&1,q=Q[i][j]&1; M[rows++]=(q<<i)|(p<<j); M[rows++]=(p<<i)|(q<<j);} 
  int rank=0; for(int c=0;c<n;c++){ int piv=-1; for(int r=rank;r<rows;r++) if(M[r]>>c&1){piv=r;break;} if(piv<0) continue; uint32_t tmp=M[piv];M[piv]=M[rank];M[rank]=tmp; for(int r=0;r<rows;r++) if(r!=rank && (M[r]>>c&1)) M[r]^=M[rank]; rank++; } return rank; }
int main(int argc,char**argv){ if(argc<5){fprintf(stderr,"usage: n w sets seed\n");return 2;} n=atoi(argv[1]); w=atoi(argv[2]); long sets=atol(argv[3]); sm_state=strtoull(argv[4],0,10);
  MASK=(w==32)?0xFFFFFFFFu:((1u<<w)-1); tb=w/2; const double TWO_PI=6.283185307179586;
  for(int i=0;i<(1<<tb);i++) lut[i]=(int32_t)trunc(sin(TWO_PI*(double)i/(double)(1<<tb))*(double)(1u<<(w-2)));
  kphase=(uint64_t)floor(12.0*(double)(1ull<<w)/TWO_PI);
  const double Om[4]={0.6180339887498949,1.3247179572447460,0.4142135623730951,0.7182818284590451}; for(int k=0;k<n;k++) omega[k]=(uint32_t)floor(Om[k%4]/TWO_PI*(double)(1ull<<w))&MASK;
  uint64_t NS=1ull<<(n*w); uint32_t wmax=1u<<(w-2);
  printf("symenum n=%d w=%d table=%d entries weights in [2,%u) sets=%ld seed=%s states=2^%d K_phase=%llu\n",n,w,1<<tb,wmax,sets,argv[4],n*w,(unsigned long long)kphase);
  long agg_sets=0, agg_rankdef=0, agg_found=0, agg_pred=0, agg_extra=0, agg_missing=0, agg_period=0; clock_t c0=clock();
  for(long s=0;s<sets;s++){
    for(int i=0;i<n;i++) for(int j=i+1;j<n;j++){ uint32_t p=2+(uint32_t)(sm()%(wmax-2)), q=2+(uint32_t)(sm()%(wmax-2)); if(p==q) q=2+((q-2+1)%(wmax-2)); P[i][j]=P[j][i]=p; Q[i][j]=Q[j][i]=q; }
    /* note: the real map uses (p_kj,q_kj) per ORDERED use: a_kj = p*t_j - q*t_k with (p,q) the pair's weights — same for both orders */
    int rank=parity_rank(); long found=0,pred=0,extra=0,missing=0,period=0;
    uint32_t d[8],t[8],td[8],o1[8],o2[8];
    /* fixed pseudo-random probe order over t, then exhaustive */
    for(uint64_t dv=1; dv<NS; dv++){ unpack(dv,d); int pr=predicted(d); int symS=1, symP=1;
      for(uint64_t tv=0; tv<NS && (symS||symP); tv++){ uint64_t tr=(tv*0x9E3779B1ull)&(NS-1); /* odd multiplier mod 2^(n*w): a permutation of all states (fix after review #23; the first run's order (tv*c)>>(64-nw) visited 89%/86% of the states) */ unpack(tr,t); for(int k=0;k<n;k++) td[k]=(t[k]+d[k])&MASK; F(t,o1); F(td,o2);
        if(symS){ for(int k=0;k<n;k++) if(((o1[k]+d[k])&MASK)!=o2[k]){symS=0;break;} }
        if(symP){ for(int k=0;k<n;k++) if(o1[k]!=o2[k]){symP=0;break;} } }
      if(symS){found++; if(!pr) extra++;} if(pr){pred++; if(!symS) missing++;} if(symP) period++; }
    printf("set %ld: rank=%d found_S=%ld predicted=%ld extra(found\\pred)=%ld missing(pred\\found)=%ld found_P=%ld weights=",s,rank,found,pred,extra,missing,period);
    for(int i=0;i<n;i++) for(int j=i+1;j<n;j++) printf(" (%u,%u)",P[i][j],Q[i][j]); printf("\n"); fflush(stdout);
    agg_sets++; agg_rankdef+=(rank<n); agg_found+=found; agg_pred+=pred; agg_extra+=extra; agg_missing+=missing; agg_period+=period; }
  printf("TOTAL sets=%ld rank-deficient=%ld found_S=%ld predicted=%ld extra=%ld missing=%ld found_P=%ld elapsed=%.1fs\n",agg_sets,agg_rankdef,agg_found,agg_pred,agg_extra,agg_missing,agg_period,(double)(clock()-c0)/CLOCKS_PER_SEC);
  return (agg_extra||agg_missing)?1:0; }
