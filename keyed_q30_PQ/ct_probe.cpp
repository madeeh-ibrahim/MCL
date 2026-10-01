// ct_probe.cpp — emits mcl_q30_sin_ct() as a standalone, non-inlined function so that its
// machine code can be listed and inspected (2026-09-19 record).
#define MCL_Q30_CONSTANT_TIME_SIN
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
extern "C" __attribute__((noinline)) int32_t probe_sin_ct(const int32_t* lut, uint32_t angle) {
    return mcl_q30_sin_ct(lut, angle);
}
extern "C" __attribute__((noinline)) int32_t probe_sin_fast(const MCL_Q30_Table* tab, uint32_t angle) {
    return tab->sin_q30(angle);
}
int main() { return 0; }
