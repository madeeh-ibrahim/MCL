// Scratch prototype only (engine untouched): same scan with an optimizer value barrier on the mask.
#include <cstdint>
static inline uint32_t eq0_mask(uint32_t x){ uint32_t neg = 0u - x; return (uint32_t)0 - (uint32_t)(~(x | neg) >> 31); }
static inline uint32_t value_barrier_u32(uint32_t a){ __asm__("" : "+r"(a)); return a; }
extern "C" __attribute__((noinline)) int32_t sin_ct_barrier(const int32_t* lut, uint32_t angle){
    const uint32_t idx = angle >> 16; const volatile int32_t* v = lut; uint32_t acc = 0;
    for (uint32_t i = 0; i < 65536u; ++i) acc |= (uint32_t)v[i] & value_barrier_u32(eq0_mask(i ^ idx));
    return (int32_t)acc;
}
int main(){ static int32_t lut[65536]; for (uint32_t i=0;i<65536;i++) lut[i]=(int32_t)(i*2654435761u);
  unsigned bad=0; for (uint32_t a=0;a<65536;a++) bad += (sin_ct_barrier(lut,a<<16)!=lut[a]); return bad?1:0; }
