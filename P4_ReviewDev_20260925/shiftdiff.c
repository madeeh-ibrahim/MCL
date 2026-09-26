/* Core step of the converse "commuting offset => invariant arguments" (odd-weight case):
 * with g(a) = INC[a >> 16], INC[i] = low32(((uint64)(K_phase*LUT[i])) >> 30), a shift c != 0 (mod 2^32)
 * can leave g(a+c) - g(a) constant in a only if, for c1 = c >> 16 != 0, D(i) = INC[i+c1] - INC[i] is constant
 * in i (or, for c1 = 0, INC is constant). Check every c1 in [1, 65535] on the normative table. */
#include <stdio.h>
#include <stdint.h>
int main(int argc, char** argv){
    static int32_t lut[65536]; static uint32_t inc[65536]; FILE* f = fopen(argv[1], "rb");
    unsigned char b[4]; for (int i = 0; i < 65536; i++){ if (fread(b,1,4,f) != 4) return 2; lut[i] = (int32_t)((uint32_t)b[0] | (uint32_t)b[1]<<8 | (uint32_t)b[2]<<16 | (uint32_t)b[3]<<24); }
    const int64_t kp = 0x1e8ec8a4aLL;
    for (int i = 0; i < 65536; i++) inc[i] = (uint32_t)(((uint64_t)(kp * (int64_t)lut[i])) >> 30);
    int constant_shifts = 0, maxprobe = 0; int incconst = 1; for (int i = 1; i < 65536; i++) if (inc[i] != inc[0]) { incconst = 0; break; }
    for (uint32_t c1 = 1; c1 < 65536; c1++){ uint32_t d0 = inc[c1] - inc[0]; int i; for (i = 1; i < 65536; i++) if (inc[(i + c1) & 0xFFFF] - inc[i] != d0) break; if (i == 65536) constant_shifts++; if (i > maxprobe) maxprobe = i; }
    int anti = 1; for (int i = 0; i < 32768; i++) if (lut[i + 32768] != -lut[i]) { anti = 0; break; }
    printf("INC constant: %s; shifts c1 in [1,65535] with constant INC[i+c1]-INC[i]: %d (largest index needed to see non-constancy: %d)\n", incconst ? "yes" : "no", constant_shifts, maxprobe);
    printf("table antisymmetry LUT[i+32768] == -LUT[i] for all i: %s\n", anti ? "yes" : "no");
    return 0;
}
