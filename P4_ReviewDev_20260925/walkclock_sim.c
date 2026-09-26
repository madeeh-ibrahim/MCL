/* Walk-collision attack on an UNCLOCKED map s_{i+1} = F(s_i) versus a CLOCKED map s_{i+1} = F(s_i, i)
 * (iteration index injected into every step, fresh random function per (state, index)).
 * Same attacker resources in both modes: P walks for T = (1-eps)N ticks, records at an F-independent
 * distinguishing rate 2^-d, honest walk looks up its own distinguished points.
 * Unclocked: walk k steps with F; a record found for state s_tau gives lead = tau - tick.
 * Clocked:   walk k is assigned an offset l_k (uniform in [ceil(eps N), N/2]) and steps with F(., tick + l_k),
 *            i.e. it simulates the honest chain l_k indices ahead; a record is usable only if its clock
 *            equals the honest index (records are keyed by (state, clock)); lead = l_k.
 * Every declared success is verified by recomputing s_N both ways.
 * Build: cc -O3 -o walkclock_sim walkclock_sim.c -lm
 * Usage: walkclock_sim clocked(0/1) s log2N eps P d trials seed
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
static inline uint64_t mix(uint64_t z){ z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull; z = (z ^ (z >> 27)) * 0x94D049BB133111EBull; return z ^ (z >> 31); }
static uint64_t rs; static inline uint64_t rnd(void){ rs += 0x9E3779B97F4A7C15ull; return mix(rs); }
static uint64_t MASK, KF, KD, DPMASK; static int CLK;
static inline uint64_t F(uint64_t x, uint64_t i){ return mix(x ^ KF ^ (CLK ? mix(i * 0xA24BAED4963EE407ull + 0x9FB21C651E98DF25ull) : 0)) & MASK; }
static inline int isdp(uint64_t x){ return (mix(x * 0xD6E8FEB86659FD93ull ^ KD) & DPMASK) == 0; }
typedef struct { uint64_t key; uint32_t walk, tick, clk, gen; } Slot;
static Slot* tab; static uint64_t tmask; static uint32_t gen = 0;
static inline Slot* probe(uint64_t key, uint32_t clk){ uint64_t h = mix(key ^ ((uint64_t)clk << 40) ^ 0x51ED270B27ull) & tmask; for(;;){ Slot* s = &tab[h]; if (s->gen != gen || (s->key == key && s->clk == clk)) return s; h = (h + 1) & tmask; } }
int main(int argc, char** argv){
    if (argc < 9){ fprintf(stderr, "usage: clocked s log2N eps P d trials seed\n"); return 1; }
    CLK = atoi(argv[1]); int s = atoi(argv[2]); int lN = atoi(argv[3]); double eps = atof(argv[4]); long P = atol(argv[5]); int d = atoi(argv[6]);
    long trials = atol(argv[7]); rs = strtoull(argv[8], 0, 0);
    uint64_t N = 1ull << lN, T = (uint64_t)floor((1.0 - eps) * (double)N), need = (uint64_t)ceil(eps * (double)N);
    MASK = (1ull << s) - 1; DPMASK = d ? ((1ull << d) - 1) : 0;
    uint64_t tcap = 1; while ((double)tcap < 4.0 * (double)P * (double)T / ldexp(1.0, d) + 1024) tcap <<= 1; tmask = tcap - 1;
    tab = calloc(tcap, sizeof(Slot)); uint64_t* w = malloc(8 * P); uint64_t* off = malloc(8 * P);
    long succ = 0, ver = 0; double stored_sum = 0;
    for (long tr = 0; tr < trials; tr++){
        gen++; KF = rnd(); KD = rnd(); uint64_t stored = 0;
        for (long k = 0; k < P; k++){ w[k] = rnd() & MASK; off[k] = CLK ? need + rnd() % (N/2 - need + 1) : 0; }
        uint64_t h = rnd() & MASK; int found = 0;
        for (uint64_t tau = 1; tau <= T && !found; tau++){
            for (long k = 0; k < P; k++){ uint64_t clk = CLK ? (tau - 1 + off[k]) : 0; uint64_t x = F(w[k], clk); w[k] = x;
                if (isdp(x)){ uint32_t c = CLK ? (uint32_t)(clk + 1) : 0; Slot* sl = probe(x, c); if (sl->gen != gen){ sl->gen = gen; sl->key = x; sl->clk = c; sl->walk = (uint32_t)k; sl->tick = (uint32_t)tau; stored++; } } }
            h = F(h, CLK ? tau - 1 : 0);   /* h = s_tau */
            if (isdp(h)){ Slot* sl = probe(h, CLK ? (uint32_t)tau : 0);
                if (sl->gen == gen && sl->tick < tau){ uint64_t lead = CLK ? off[sl->walk] : tau - sl->tick;
                    if (lead >= need && tau + lead <= N){ found = 1; long k = sl->walk;
                        uint64_t x = w[k], idx = tau + lead; while (idx < N){ x = F(x, CLK ? idx : 0); idx++; }
                        uint64_t y = h, hi = tau; while (hi < N){ y = F(y, CLK ? hi : 0); hi++; }
                        succ++; if (x == y) ver++; } } }
        }
        stored_sum += (double)stored;
    }
    double p = (double)succ / trials, z = 1.96, den = 1 + z*z/trials, c = (p + z*z/(2*trials))/den, hw = z*sqrt(p*(1-p)/trials + z*z/(4.0*trials*trials))/den;
    printf("%s s=%d N=2^%d eps=%.2f P=%ld d=%d trials=%ld | success %ld (%.6f, 95%% CI %.6f-%.6f) verified %ld/%ld | P*T/2^s=%.3e P*N^2/2^s=%.3e\n",
           CLK ? "CLOCKED  " : "UNCLOCKED", s, lN, eps, P, d, trials, succ, p, (c-hw) < 0 ? 0 : c-hw, c+hw, ver, succ, (double)P*T/ldexp(1.0,s), (double)P*N*(double)N/ldexp(1.0,s));
    return 0;
}
