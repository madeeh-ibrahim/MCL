#!/usr/bin/env bash
# add_spdx_headers.sh  (v2 — handles pre-existing Apache/old license lines)
#
# PURPOSE
#   Bring every MCL source file to the correct, single licensing position:
#     SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#   and remove the legacy "Apache-2.0 (test code only)" / "Limited Research
#   License" wording that the project files currently contain.
#
# WHY v2
#   The project's existing files already carry, inside their top comment block:
#       SPDX-License-Identifier: Apache-2.0 (test code only)
#       ... Limited Research License. See mcl_core.hpp header for terms.
#   A naive "skip if SPDX present" script would LEAVE those Apache lines in
#   place — publishing the code under Apache-2.0 and granting a broad patent
#   license to everyone (Apache section 3), destroying the licensing strategy.
#   This version REWRITES the offending lines in place, surgically.
#
# WHAT IT DOES (per file)
#   1. Replaces a legacy "SPDX-License-Identifier: Apache-2.0..." line with the
#      correct PolyForm line (keeping the file's comment style).
#   2. Replaces a legacy "Limited Research License. See mcl_core.hpp..." line
#      with a pointer to LICENSE + SECURITY-RESEARCH-GRANT.md.
#   3. Leaves files that already have the correct PolyForm SPDX line untouched.
#   4. Prepends the correct header (full for mcl_core.hpp, short otherwise) to
#      files that have NO SPDX line at all.
#   It NEVER deletes whole comment blocks (no risk of removing code).
#
# USAGE
#   bash add_spdx_headers.sh /path/to/your/mcl/source   (defaults to ".")
#   Writes a .bak for every modified file. After review:  rm -f *.bak

set -euo pipefail

SRC_DIR="${1:-.}"
CORE_FILE="mcl_core.hpp"
YEAR="2026"
HOLDER="Madeeh Ibrahim"
EMAIL="madeeh.chaotic.lock@gmail.com"

cd "$SRC_DIR"
CORRECT_SPDX="SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0"

has_correct_spdx() { grep -q "$CORRECT_SPDX" "$1" 2>/dev/null; }
has_any_spdx()     { grep -q "SPDX-License-Identifier" "$1" 2>/dev/null; }
has_apache()       { grep -Eq 'SPDX-License-Identifier:[[:space:]]*Apache-2\.0' "$1" 2>/dev/null; }
has_lrl()          { grep -q 'Limited Research License' "$1" 2>/dev/null; }

core_header() {
cat <<EOF
// SPDX-FileCopyrightText: ${YEAR} ${HOLDER} <${EMAIL}>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation — Core
// Copyright (c) ${YEAR} ${HOLDER}. All rights reserved.
//
// LICENSE
//   Licensed under the PolyForm Noncommercial License 1.0.0:
//     https://polyformproject.org/licenses/noncommercial/1.0.0/
//   ADDITIONALLY, security research, evaluation, and break-attempts by ANY
//   party — including commercial organizations — are permitted free of charge
//   under the Security Research & Evaluation Grant (SECURITY-RESEARCH-GRANT.md).
//   You may rely on whichever instrument grants the permission you need.
//   Commercial production or integration use requires a separate paid license;
//   see COMMERCIAL.md.
//
// PATENT NOTICE
//   The methods implemented here are the subject of pending applications:
//     PCT/IB2026/052737 (22 Mar 2026), PCT/IB2026/053253 (1 Apr 2026),
//     PCT/IB2026/053673 (14 Apr 2026).
//   A noncommercial patent license, and a patent license for security
//   research, are granted; no patent license is granted for commercial use.
//   Asserting a patent against this software terminates granted rights.
//   See PATENTS.md.
//
// ADVERSARIAL VALIDATION INVITED — please try to break this and publish.
//   Coordinated disclosure: SECURITY.md. Citation required: CITATION.cff.
EOF
}
dep_header_cpp() {
cat <<EOF
// SPDX-FileCopyrightText: ${YEAR} ${HOLDER} <${EMAIL}>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
EOF
}
dep_header_py() {
cat <<EOF
# SPDX-FileCopyrightText: ${YEAR} ${HOLDER} <${EMAIL}>
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# MCL Reference Implementation. Free security research / evaluation for all
# (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
# a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
EOF
}
prepend() { cat "$2" "$1" > "$1.__tmp" && mv "$1.__tmp" "$1"; }

fix_legacy_lines() {  # $1 = file
  local f="$1"
  cp "$f" "$f.bak"
  # 1) Replace the Apache SPDX line. Handle BOTH commented leaders (// * #) AND
  #    leaderless lines (e.g. inside a Python """docstring"""). Preserve leader.
  perl -i -pe 's{^(\s*(?://|\*|\#)?\s*)SPDX-License-Identifier:\s*Apache-2\.0[^\n]*$}{$1 . "SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0"}e' "$f"
  # 2) Replace the full legacy two-line "NOTE ... Limited Research License ..."
  #    pattern with one clean sentence. First collapse the specific sentence:
  perl -0777 -i -pe 's{which is subject to a separate\s*\n(\s*(?://|\*|\#)?\s*)Limited Research License\.\s*See mcl_core\.hpp header for terms\.}{which is licensed under PolyForm Noncommercial 1.0.0 plus the Security Research and Evaluation Grant (see LICENSE and PATENTS.md).}g' "$f"
  # 3) Any remaining standalone "Limited Research License. See mcl_core.hpp header for terms."
  perl -i -pe 's{Limited Research License\.\s*See mcl_core\.hpp header for terms\.}{See LICENSE and PATENTS.md.}g' "$f"
}

echo "==== MCL header normalizer (v2) ===="
echo "Dir: $(pwd)"; echo
shopt -s nullglob
modified=0; prepended=0; ok=0; warn=0

process_file() {  # $1 = file, $2 = core|cpp|py
  local f="$1" kind="$2"
  if has_apache "$f" || has_lrl "$f"; then
    fix_legacy_lines "$f"
    echo "FIXED legacy Apache/LRL: $f   (backup: $f.bak)"
    modified=$((modified+1))
    if ! has_any_spdx "$f"; then
      case "$kind" in
        core) core_header > .__h;; py) dep_header_py > .__h;; *) dep_header_cpp > .__h;;
      esac
      prepend "$f" .__h; rm -f .__h
      echo "  + prepended header (none present after fix): $f"
    fi
  elif has_correct_spdx "$f"; then
    echo "OK (already PolyForm): $f"; ok=$((ok+1))
  elif has_any_spdx "$f"; then
    echo "WARN: non-Apache/non-PolyForm SPDX — review manually: $f"; warn=$((warn+1))
  else
    case "$kind" in
      core) core_header > .__h;; py) dep_header_py > .__h;; *) dep_header_cpp > .__h;;
    esac
    prepend "$f" .__h; rm -f .__h
    echo "PREPENDED header (none present): $f"; prepended=$((prepended+1))
  fi
}

[[ -f "$CORE_FILE" ]] && process_file "$CORE_FILE" core || echo "WARN: $CORE_FILE not found"
for f in *.hpp *.cpp *.h *.cc; do [[ "$f" == "$CORE_FILE" ]] && continue; process_file "$f" cpp; done
for f in *.py; do process_file "$f" py; done

echo
echo "Summary: fixed-legacy=$modified, prepended=$prepended, already-ok=$ok, warn=$warn"
echo "After review:"
echo "    grep -rn 'Apache-2.0\\|Limited Research' .   # should be empty"
echo "    rm -f *.bak"
