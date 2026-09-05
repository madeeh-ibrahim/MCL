#!/usr/bin/env bash
# P4 round 6: full re-measurement of VDF128-T4 v3 (neutral strings + full-rank parity rule). Idle host required for timing stages.
set -u; cd "$(dirname "$0")"; S=_apple_20260905v3; t0=$(date +%s); echo "START $(date) load $(sysctl -n vm.loadavg)"
./p4_vdf128v3_kat > vdf128v3_kat$S.log 2>&1 && echo "kat done $(( $(date +%s)-t0 ))s"
python3 - <<'PY'
import re, pathlib
log = pathlib.Path("vdf128v3_kat_apple_20260905v3.log").read_text()
y = re.search(r"y = SHA-256\(preimage\)\s+([0-9a-f ]+)", log).group(1).replace(" ","")
fin = re.search(r"C_4 \(t=1000\)\s+([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})", log).groups()
s = pathlib.Path("vdf128_t4v3_standalone.template.cpp").read_text()
s = re.sub(r'want_y = "[0-9a-f]+"', f'want_y = "{y}"', s)
s = re.sub(r's\.t\[0\] == 0x[0-9a-f]+u && s\.t\[1\] == 0x[0-9a-f]+u && s\.t\[2\] == 0x[0-9a-f]+u && s\.t\[3\] == 0x[0-9a-f]+u',
           f's.t[0] == 0x{fin[0]}u && s.t[1] == 0x{fin[1]}u && s.t[2] == 0x{fin[2]}u && s.t[3] == 0x{fin[3]}u', s)
s = s.replace("Vector 5 (v2)", "Vector 5 (v3)")
pathlib.Path("vdf128_t4v3_standalone.cpp").write_text(s); print("standalone patched:", y[:16], fin)
PY
clang++ -O2 -std=c++17 -o sa3 vdf128_t4v3_standalone.cpp && { ./sa3 ../P4_ReviewMeasurements_20260905/q30_lut_int32le.bin; ./sa3; } > vdf128_t4v3_standalone$S.log 2>&1 && echo "standalone done: $(grep -c REPRODUCED vdf128_t4v3_standalone$S.log)/2"
./vdf128v3_battery > vdf128v3_battery$S.log 2>&1; echo "battery done $(( $(date +%s)-t0 ))s: $(grep SUMMARY vdf128v3_battery$S.log)"
: > vdf128v3_xplat$S.log
for arch in arm64 x86_64; do for O in 0 1 2 3; do
  clang++ -std=c++17 -O$O -arch $arch -I.. mcl_vdf128v3_xplat.cpp -o xp_${arch}_$O 2>/dev/null && ./xp_${arch}_$O > cell_${arch}_$O.txt 2>&1 && echo "cell $arch -O$O: $(shasum -a 256 cell_${arch}_$O.txt | cut -c1-16)  # $(head -1 cell_${arch}_$O.txt)" >> vdf128v3_xplat$S.log
done; done; cat cell_arm64_3.txt >> vdf128v3_xplat$S.log; echo "xplat done $(( $(date +%s)-t0 ))s"
./p4_vdf128v3_distinguisher > vdf128v3_distinguisher$S.log 2>&1 & P5=$!
./vdf128v3_cyclecheck > vdf128v3_cycleprobe$S.log 2>&1 & P1=$!
./p4_vdf128v3_weaklane > vdf128v3_weaklane$S.log 2>&1 & P2=$!
./p4_vdf128v3_weakpair --grind 200000000 > vdf128v3_weakpair_grind$S.log 2>&1 & P3=$!
./p4_vdf128v3_weakpair > vdf128v3_weakpair$S.log 2>&1 & P4=$!
wait $P5 $P4; echo "distinguisher+weakpair done $(( $(date +%s)-t0 ))s"
for i in $(seq 1 36); do docker info >/dev/null 2>&1 && break; sleep 5; done
docker run --rm --platform linux/amd64 -v "$PWD/..":/w -w /w/VDF128_T4 gcc:13 bash -c '
  g++ -std=c++17 -O3 -DNDEBUG -I.. p4_vdf128v3_kat.cpp -o /tmp/kat && /tmp/kat > vdf128v3_kat_linux_glibc_20260905v3.log 2>&1;
  g++ -O2 -std=c++17 -o /tmp/sa3 vdf128_t4v3_standalone.cpp && { /tmp/sa3 ../P4_ReviewMeasurements_20260905/q30_lut_int32le.bin; /tmp/sa3; } > vdf128_t4v3_standalone_linux_glibc_20260905v3.log 2>&1;
  g++ -std=c++17 -O3 -I.. mcl_vdf128v3_xplat.cpp -o /tmp/xp && /tmp/xp > vdf128v3_xplat_linux_glibc_20260905v3.log 2>&1' && echo "docker done $(( $(date +%s)-t0 ))s"
wait $P1 $P2 $P3; echo "probes done $(( $(date +%s)-t0 ))s"
for i in $(seq 1 60); do busy=$(ps -Ao pcpu,comm -r | awk 'NR>1 && $1>50 && $2 !~ /run_v3/' | wc -l | tr -d ' '); [ "$busy" = "0" ] && break; sleep 30; done
echo "quiet host (busy=$busy): bench + sha"; ./vdf128v3_bench > vdf128v3_bench$S.log 2>&1; ./p4_sha256_vs_t4v3_bench > sha256_vs_t4v3_bench$S.log 2>&1
echo "ALL DONE $(( $(date +%s)-t0 ))s $(date)"
