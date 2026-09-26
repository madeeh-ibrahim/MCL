#!/usr/bin/env bash
# VDF128-T4 v4 (clocked map) — full re-measurement, 2026-09-25 (ت-134(أ)). Bench runs last on a quiet host.
set -u; cd "$(dirname "$0")"; S=_apple_20260925v4; t0=$(date +%s); echo "START $(date) load $(sysctl -n vm.loadavg)"
python3 - <<'PY'
import re, pathlib
log = pathlib.Path("vdf128v4_kat_apple_20260925.log").read_text()
y = re.search(r"y = SHA-256\(preimage\)\s+([0-9a-f ]+)", log).group(1).replace(" ","")
fin = re.search(r"C_4 \(t=1000\)\s+([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})", log).groups()
s = pathlib.Path("vdf128_t4v4_standalone.template.cpp").read_text()
s = re.sub(r'want_y = "[0-9a-f]+"', f'want_y = "{y}"', s)
s = re.sub(r's\.t\[0\] == 0x[0-9a-f]+u && s\.t\[1\] == 0x[0-9a-f]+u && s\.t\[2\] == 0x[0-9a-f]+u && s\.t\[3\] == 0x[0-9a-f]+u',
           f's.t[0] == 0x{fin[0]}u && s.t[1] == 0x{fin[1]}u && s.t[2] == 0x{fin[2]}u && s.t[3] == 0x{fin[3]}u', s)
pathlib.Path("vdf128_t4v4_standalone.cpp").write_text(s); print("standalone patched:", y[:16], fin)
PY
clang++ -O2 -std=c++17 -o sa4 vdf128_t4v4_standalone.cpp && { ./sa4 q30_lut_int32le.bin; ./sa4; } > vdf128_t4v4_standalone$S.log 2>&1 && echo "standalone done: $(grep -c REPRODUCED vdf128_t4v4_standalone$S.log)/2"
: > vdf128v4_xplat$S.log
for arch in arm64 x86_64; do for O in 0 1 2 3; do
  clang++ -std=c++17 -O$O -arch $arch -I.. mcl_vdf128v4_xplat.cpp -o xp_${arch}_$O 2>/dev/null && ./xp_${arch}_$O > cell_${arch}_$O.txt 2>&1 && echo "cell $arch -O$O: $(shasum -a 256 cell_${arch}_$O.txt | cut -c1-16)  # $(head -1 cell_${arch}_$O.txt)" >> vdf128v4_xplat$S.log
done; done; cat cell_arm64_3.txt >> vdf128v4_xplat$S.log; echo "xplat done $(( $(date +%s)-t0 ))s"
./p4_vdf128v4_distinguisher > vdf128v4_distinguisher$S.log 2>&1 & P5=$!
./p4_vdf128v4_weaklane > vdf128v4_weaklane$S.log 2>&1 & P2=$!
./p4_vdf128v4_weakpair > vdf128v4_weakpair$S.log 2>&1 & P4=$!
./p4_vdf128v4_weakpair --input weak-lane-v3-174170077 > vdf128v4_weakpair_genuine$S.log 2>&1 & P3=$!
wait $P5 $P2 $P4 $P3; echo "distinguisher+weak probes done $(( $(date +%s)-t0 ))s"
./mcl_vdf128v4_battery > vdf128v4_battery$S.log 2>&1; echo "battery done $(( $(date +%s)-t0 ))s: $(grep SUMMARY vdf128v4_battery$S.log)"
for i in $(seq 1 40); do busy=$(ps -Ao pcpu,comm -r | awk 'NR>1 && $1>50 && $2 !~ /run_v4/' | wc -l | tr -d ' '); [ "$busy" = "0" ] && break; sleep 15; done
echo "quiet host (busy=$busy): bench"; ./mcl_vdf128v4_bench > vdf128v4_bench$S.log 2>&1
echo "ALL DONE $(( $(date +%s)-t0 ))s $(date)"
