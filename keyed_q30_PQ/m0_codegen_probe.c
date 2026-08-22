/* Freestanding Cortex-M0 codegen probe for Claim 13 (native-word multiply,
 * no FPU, no wider-than-native multiply for the COUPLING ARGUMENT).
 * Mirrors the exact arithmetic of mcl_q30t4_iterate_raw's arg() and inc().
 * Compile to assembly for thumbv6m (ARMv6-M = Cortex-M0, no UMULL, no FPU):
 *   clang -target thumbv6m-none-eabi -mcpu=cortex-m0 -ffreestanding -O2 -S
 * Then inspect .s for: __aeabi_* calls, FPU ops (vmul/vldr/vadd.f).
 */
#include <stdint.h>

/* --- coupling argument: (uint32_t)(p*a - q*b), p/q are key weights < 2^30,
 *     a/b are phase words. Only the low 32 bits are kept (Claim 13 / [0030]). */
uint32_t mcl_arg(int64_t p, uint32_t a, int64_t q, uint32_t b) {
    return (uint32_t)((int64_t)p * (int64_t)a - (int64_t)q * (int64_t)b);
}

/* Same, but written with the Claim-13-optimal 32-bit multiply (low 32 bits
 * of p*a equal the low 32 bits of (uint32_t)p * a). This is the form the
 * claim asserts is sufficient; the probe shows whether the int64 form above
 * already lowers to this, or pulls in __aeabi_lmul. */
uint32_t mcl_arg_w32(uint32_t p, uint32_t a, uint32_t q, uint32_t b) {
    return (uint32_t)(p * a - q * b);
}

/* --- increment scaling: (int32_t)((K_phase * sinval) >> 30). This one
 *     genuinely needs the high bits, so a 64-bit product is expected (this
 *     is the [0031] scaling multiply, NOT the Claim-13 coupling argument). */
uint32_t mcl_inc(int64_t K_phase, int32_t sinval) {
    return (uint32_t)(int32_t)(((int64_t)K_phase * (int64_t)sinval) >> 30);
}

/* --- full single-oscillator update mirroring osc-1 of the engine. */
uint32_t mcl_osc1(uint32_t t1, uint32_t t2, uint32_t t3, uint32_t t4,
                  int64_t p12, int64_t q12, int64_t p13, int64_t q13,
                  int64_t p14, int64_t q14, int64_t K, int32_t s12,
                  int32_t s13, int32_t s14, uint32_t omega1) {
    uint32_t a12 = mcl_arg(p12, t2, q12, t1);
    uint32_t a13 = mcl_arg(p13, t3, q13, t1);
    uint32_t a14 = mcl_arg(p14, t4, q14, t1);
    (void)a12; (void)a13; (void)a14;
    /* sin lookups are table reads (no math); model the scaled increments */
    return t1 + omega1 + mcl_inc(K, s12) + mcl_inc(K, s13) + mcl_inc(K, s14);
}
