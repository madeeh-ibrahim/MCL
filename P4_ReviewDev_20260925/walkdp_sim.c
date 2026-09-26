/* Scaled-down check of Proposition 3(a) (memory-bounded walk-collision attack on a per-input map).
 * Random mapping F on s bits (fresh key per trial = fresh per-input map), honest start uniform.
 * Attacker: P walks from uniform starts run for T = (1-eps)N ticks alongside the honest walk; every walk
 * point that passes an F-independent distinguishing test (rate 2^-d) is stored (first writer wins) with
 * (walk, tick). The honest walk looks up each of its own points that passes the same test. A record
 * (k, tk) found at honest tick tau means walk k is ahead by lead = tau - tk; usable iff lead >= eps*N and
 * tau + lead <= N (walk k has not passed s_N). The attacker then finishes at tick N - lead <= (1-eps)N.
 * Every declared success is VERIFIED: walk k is advanced to honest index N and compared with s_N.
 * Output: success rate (Wilson 95% CI), stored words, the paper's Prop 3(a) value for that memory, and the
 * merge-aware expectation E_det = (P/2^s) * sum_{usable (u,t)} (1 - (1-2^-d)^{W(u,t)}),
 * W = min(T - t, N - 2t + u) + 1  (detection window on the common path after a first contact at (u,t)).
 * Build: cc -O3 -o walkdp_sim walkdp_sim.c -lm
 * Usage: walkdp_sim s log2N eps P d trials seed
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
static inline uint64_t mix(uint64_t z){ z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull; z = (z ^ (z >> 27)) * 0x94D049BB133111EBull; return z ^ (z >> 31); }
static uint64_t rs;
static inline uint64_t rnd(void){ rs += 0x9E3779B97F4A7C15ull; return mix(rs); }
static uint64_t MASK, KF, KD, DPMASK;
static inline uint64_t F(uint64_t x){ return mix(x ^ KF) & MASK; }               /* per-trial random mapping */
static inline int isdp(uint64_t x){ return (mix(x * 0xD6E8FEB86659FD93ull ^ KD) & DPMASK) == 0; } /* F-independent test */
/* open-addressing table with generation stamps */
typedef struct { uint64_t key; uint32_t walk, tick, gen; } Slot;
static Slot* tab; static uint64_t tcap, tmask; static uint32_t gen = 0;
static inline Slot* probe(uint64_t key){ uint64_t h = mix(key ^ 0x51ED270B27ull) & tmask; for(;;){ Slot* s = &tab[h]; if (s->gen != gen || s->key == key) return s; h = (h + 1) & tmask; } }
int main(int argc, char** argv){
    if (argc < 8){ fprintf(stderr, "usage: s log2N eps P d trials seed\n"); return 1; }
    int s = atoi(argv[1]); int lN = atoi(argv[2]); double eps = atof(argv[3]); long P = atol(argv[4]); int d = atoi(argv[5]);
    long trials = atol(argv[6]); rs = strtoull(argv[7], 0, 0);
    uint64_t N = 1ull << lN; uint64_t T = (uint64_t)floor((1.0 - eps) * (double)N); uint64_t need = (uint64_t)ceil(eps * (double)N);
    MASK = (s == 64) ? ~0ull : ((1ull << s) - 1); DPMASK = (d == 0) ? 0 : ((1ull << d) - 1);
    double expect_dp = (double)P * (double)T / ldexp(1.0, d);
    tcap = 1; while ((double)tcap < 4.0 * expect_dp + 1024) tcap <<= 1; tmask = tcap - 1;
    tab = calloc(tcap, sizeof(Slot)); uint64_t* w = malloc(sizeof(uint64_t) * P);
    long succ = 0, verified = 0; double stored_sum = 0, lead_sum = 0;
    for (long tr = 0; tr < trials; tr++){
        gen++; KF = rnd(); KD = rnd(); uint64_t stored = 0;
        for (long k = 0; k < P; k++) w[k] = rnd() & MASK;
        uint64_t h0 = rnd() & MASK, h = h0; int found = 0; long fk = -1; uint64_t ftau = 0, flead = 0;
        for (uint64_t tau = 1; tau <= T; tau++){
            for (long k = 0; k < P; k++){ uint64_t x = F(w[k]); w[k] = x; if (isdp(x)){ Slot* sl = probe(x); if (sl->gen != gen){ sl->gen = gen; sl->key = x; sl->walk = (uint32_t)k; sl->tick = (uint32_t)tau; stored++; } } }
            h = F(h);
            if (!found && isdp(h)){ Slot* sl = probe(h); if (sl->gen == gen && sl->tick < tau){ uint64_t lead = tau - sl->tick; if (lead >= need && tau + lead <= N){ found = 1; fk = sl->walk; ftau = tau; flead = lead; } } }
            if (found){ /* walks keep running to T in the attack; for verification we can stop here */
                uint64_t x = w[fk]; /* walk fk at tick ftau sits at honest index ftau + flead */
                uint64_t idx = ftau + flead; while (idx < N){ x = F(x); idx++; }
                uint64_t y = h; uint64_t hi = ftau; while (hi < N){ y = F(y); hi++; }
                succ++; if (x == y) verified++; lead_sum += (double)flead;
                /* finish counting stored words for the full run length (memory is what the whole run stores) */
                for (uint64_t t2 = tau + 1; t2 <= T; t2++) for (long k = 0; k < P; k++){ uint64_t z = F(w[k]); w[k] = z; if (isdp(z)){ Slot* sl = probe(z); if (sl->gen != gen){ sl->gen = gen; sl->key = z; sl->walk = (uint32_t)k; sl->tick = (uint32_t)t2; stored++; } } }
                break;
            }
        }
        stored_sum += (double)stored;
    }
    double p = (double)succ / trials, z = 1.96, den = 1 + z*z/trials;
    double c = (p + z*z/(2*trials)) / den, hw = z * sqrt(p*(1-p)/trials + z*z/(4.0*trials*trials)) / den;
    double Mst = stored_sum / trials;               /* stored words (distinguished records) */
    double Mtot = Mst + (double)P;                  /* plus one state word per walk */
    double twos = ldexp(1.0, s);
    double a = 0.5 - eps; double cN = (1 - 2.0*(double)N*(double)N/twos) * (1 - 3.0/(a*(double)N));
    double prop3_E  = cN * a*a * (double)N * Mtot / twos;          /* paper, Prop 3(a), expected count  */
    double prop3_P  = fmin(0.5, prop3_E / 2);                       /* paper, success probability        */
    double rho = ldexp(1.0, -d); double sumW = 0;                   /* merge-aware expectation            */
    for (uint64_t u = 0; u <= T; u++) for (uint64_t t = u + need; t <= T; t++){
        long long W1 = (long long)(T - t), W2 = (long long)N - 2*(long long)t + (long long)u; long long W = (W1 < W2 ? W1 : W2); if (W < 0) continue;
        sumW += 1.0 - pow(1.0 - rho, (double)(W + 1)); }
    double Edet = (double)P * sumW / twos;
    printf("s=%d N=2^%d eps=%.3f P=%ld d=%d trials=%ld | success %ld (%.5f, 95%% CI %.5f-%.5f), verified %ld/%ld, mean lead %.0f\n",
           s, lN, eps, P, d, trials, succ, p, c - hw, c + hw, verified, succ, succ ? lead_sum/succ : 0.0);
    printf("   memory: %.1f stored records + %ld walk states = %.1f words | Prop 3(a) with that M: E=%.3e, P(success)>=%.3e | merge-aware E_det=%.3e -> 1-exp(-E)=%.3e | ratio measured/Prop3a = %.1f\n",
           Mst, P, Mtot, prop3_E, prop3_P, Edet, 1 - exp(-Edet), prop3_P > 0 ? p / prop3_P : 0.0);
    return 0;
}
