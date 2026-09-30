#!/usr/bin/env bash
# VDF128-T4 v4 -- the x86_64 Linux/glibc cell (Part 4 of this record).
# Builds and runs, inside an offline gcc:13 container, the three version-4 programs of
# ../P4_ReviewMeasurements_20260925/ : the known-answer harness, the engine-free
# re-implementation (table file, then a table regenerated with sin()), and the
# fingerprint program at -O0 ... -O3. The source tree is mounted read-only.
# Usage: ./run_linux_v4.sh [engine-root]      (default: the parent of this folder)
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "${1:-$here/..}" && pwd)"; S=20260928
docker run --rm --network none --platform linux/amd64 -v "$root":/src:ro -v "$here":/out \
  -w /src/P4_ReviewMeasurements_20260925 gcc:13 bash -c '
set -u; S='"$S"'
{ echo "# host: $(uname -srm)"; echo "# os: $(grep PRETTY /etc/os-release | cut -d= -f2)"
  echo "# gcc: $(g++ --version | head -1)"; echo "# glibc: $(ldd --version | head -1)"
  echo "# container: gcc:13 (linux/amd64) on Docker Desktop, Apple M1 Pro host; network none; sources read-only"
  echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "# inputs (sha256, first 16 hex):"
  for f in ../mcl_core.hpp ../keyed_q30_PQ/mcl_keyed_q30.hpp mcl_vdf128_t4.hpp mcl_vdf128_t4_v3.hpp mcl_vdf128_t4_v4.hpp \
           p4_vdf128v4_kat.cpp vdf128_t4v4_standalone.cpp mcl_vdf128v4_xplat.cpp q30_lut_int32le.bin; do
    echo "#   $(sha256sum $f | cut -c1-16)  $f"; done; } > /out/linux_env_${S}v4.txt
g++ -std=c++17 -O3 -DNDEBUG -I.. p4_vdf128v4_kat.cpp -o /tmp/kat && /tmp/kat > /out/vdf128v4_kat_linux_glibc_${S}.log 2>&1 || exit 11
g++ -O2 -std=c++17 -o /tmp/sa4 vdf128_t4v4_standalone.cpp && { /tmp/sa4 q30_lut_int32le.bin && /tmp/sa4; } > /out/vdf128_t4v4_standalone_linux_glibc_${S}.log 2>&1 || exit 12
: > /out/vdf128v4_xplat_linux_glibc_${S}.log
for O in 0 1 2 3; do
  g++ -std=c++17 -O$O -I.. mcl_vdf128v4_xplat.cpp -o /tmp/xp_$O && /tmp/xp_$O > /tmp/cell_$O.txt 2>&1 || exit 13
  echo "cell x86_64-linux-gcc -O$O: $(sha256sum /tmp/cell_$O.txt | cut -c1-16)  # $(head -1 /tmp/cell_$O.txt)" >> /out/vdf128v4_xplat_linux_glibc_${S}.log
done
cat /tmp/cell_3.txt >> /out/vdf128v4_xplat_linux_glibc_${S}.log'
rc=$?; echo "container exit $rc"; exit $rc
