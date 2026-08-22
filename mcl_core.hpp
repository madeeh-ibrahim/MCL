/*
 * ============================================================================
 * MCL Core Engine -- mcl_core.hpp
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation — Core
 * ============================================================================
 *
 * Document ID:   MCL-CORE-2026-0712-001
 * Version:       8.1.1  (docs-only patent-list update over 8.1.0 additive: sec.4b device-bound keyed derivation;
 *                 no existing function modified — all v8.0.0 KATs unchanged)
 * Date:          August 21, 2026
 * ============================================================================
 *
 * Build:         live compile timestamp via mcl_build_timestamp()
 *                (string only — does not affect any CRC/KAT/numeric result)
 * Author:        Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:       madeeh.chaotic.lock@gmail.com
 * ORCID:         https://orcid.org/0009-0002-8562-8325
 * ============================================================================
 *
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Copyright (c) 2026 Madeeh Ibrahim. All rights reserved.
 *
 * MCL Reference Implementation. Free security research / evaluation for all
 * (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
 * a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673,
 *                 PCT/IB2026/058860 (filed 21 August 2026).
 * ============================================================================
 *
 * PATENT NOTICE: This software embodies and implements inventions
 * claimed in pending international patent applications PCT/IB2026/052737,
 * PCT/IB2026/053253, PCT/IB2026/053673, and PCT/IB2026/058860. The methods, systems,
 * and apparatus described in these applications are protected
 * independently of this software. See PATENTS.md for details.
 * ============================================================================
 *
 * NO WARRANTY / LIMITATION OF LIABILITY
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE,
 *   AND NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 *   LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN
 *   AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT
 *   OF, OR IN CONNECTION WITH THE SOFTWARE. TO THE FULLEST EXTENT
 *   PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE COPYRIGHT
 *   HOLDER BE LIABLE FOR ANY SPECIAL, INCIDENTAL, INDIRECT, OR
 *   CONSEQUENTIAL DAMAGES WHATSOEVER.
 * ============================================================================
 *
 * QUICK START -- typical usage examples
 * ============================================================================
 * (1) Hardware authentication:
 * #include "mcl_core.hpp"
 * // Server side: send 64-bit challenge to device
 * uint64_t challenge = secure_random_64bit();
 * // Device side: derive 16-byte response using device's secret (p,q)
 * std::vector<uint8_t> auth_response(uint64_t ch, int64_t p, int64_t q) {
 * MCL_T2 engine(ch, p, q); // construct + 10K-iteration burnin
 * std::vector<uint8_t> r(16);
 * engine.gen_bytes(r.data(), 16);
 * engine.erase();
 * return r;
 * }
 * (2) PRNG-style use (cryptographic stream generator):
 * MCL_T2 rng(seed, p, q); // K defaults to 12.0
 * uint8_t buf[1024];
 * rng.gen_bytes(buf, 1024);
 * (3) Choosing (p, q):
 *     REQUIRED:
 *     - 2 <= p, q <= 2^53  (v8.1.3; exact-double bound)
 *     - p != q
 *     RECOMMENDED:
 *     - gcd(p, q) = 1 (coprime weights are recommended for optimal channel
 *       orthogonality and security margin; non-coprime weights produce valid
 *       output but may exhibit reduced channel diversity in some applications).
 *     The constructor enforces only the REQUIRED conditions. See SECURITY note
 *     on (p,q) range selection (search "(p,q) RECOVERY ATTACK SCALING").
 * (4) Choosing K: K_DEFAULT = 12.0 is the validated default. Custom K must
 * satisfy K >= K_min(p,q) = MCL_K_MIN_NUMERATOR/(p+q). The constructor
 * enforces this. NOTE: K_min is necessary but not sufficient -- narrow
 * periodic/quasi-periodic windows persist ABOVE K_min for some topologies
 * (e.g. (3,5) at K~1.22/2.60/3.79/5.73; (2,3) across K~1.28-2.08). For
 * cryptographic safety, use K >= MCL_K_RECOMMENDED_FLOOR = 6.0 (the
 * empirically window-free floor for tested topologies), or K = 12 (default).
 * (5) Common errors and what they mean:
 * "FATAL: MCL seed must be non-zero" -> pass seed != 0
 * "FATAL: invalid coupling weights" -> check 2 <= p,q <= 2^53, p!=q
 * "FATAL: K below K_min" -> raise K (ideally to K_DEFAULT)
 * "FATAL: invalid K (=nan)" -> uninitialized K variable
 * (6) Higher-dimensional engines: MCL_T3, MCL_T4 use struct-based config:
 * CouplingTriple ct = {p12, q12, p13, q13, p23, q23};
 * MCL_T3 e(seed, ct);
 * (7) Alternative chaos engines (for comparative research):
 * CoupledHenon e(seed, p, q); // Henon map, default K=0.01
 * CoupledLogistic e(seed, p, q); // logistic map, default K=0.05
 * CoupledTent e(seed, p, q); // tent map, default K=0.05
 * Full API documentation continues below.
 * ============================================================================
 * ============================================================================
 * PURPOSE: Single source of truth for all MCL engines, constants, tables,
 * statistics, and mathematical computations. Every experiment file
 * includes this header instead of duplicating engine code.
 * This structurally enforces bit-identical engines across all tests.
 * SYSTEM: Coupled phase oscillators on T^n with integer-weighted sinusoidal
 * coupling and Gauss-Seidel (sequential) update. Produces
 * cryptographic-quality pseudorandom bytes via dual-zone extraction.
 * CONTENTS:
 * sec.1 Constants
 * sec.2 Topology / Coupling Tables
 * sec.3 Utility Functions
 * sec.4 Engines: MCL_T2, MCL_T2_Omega, MCL_T3, MCL_T4
 * sec.5 Generality Engines: CoupledHenon, CoupledLogistic, CoupledTent
 * sec.6 Statistics
 * sec.7 Lyapunov Computation (Benettin QR Jacobian)
 * sec.8 Spectral Test (Goertzel DFT)
 * sec.9 Regime Classification
 * sec.10 Topology Generation
 * sec.11 ECR Analysis Utilities
 * sec.12 Hierarchical Key Derivation
 * sec.13 Verifiable Delay Function
 * sec.15 Avalanche Measurement Utilities
 * sec.16 Q30 Fixed-Point Integer Engine
 * sec.17 One-Wayness Structural Evidence (empirical)
 * REFERENCES:
 * - Benettin et al. (1980): Lyapunov exponent computation via QR
 * - Szekely et al. (2007): Distance correlation
 * - NIST SP 800-22: Statistical tests for randomness
 * ============================================================================
 */

#ifndef MCL_CORE_HPP
#define MCL_CORE_HPP

// ============================================================================
// VERSION IDENTIFICATION
// ============================================================================
// Single source of truth for the MCL engine version. Test files print this
// in their banners; reviewers can pin numerical results to an exact engine
// version. The MAJOR.MINOR.PATCH triple follows semantic versioning:
//   MAJOR — incompatible API or numerical-output change
//   MINOR — added functionality, numerical output unchanged
//   PATCH — bug fixes / documentation, numerical output unchanged
//
// Update the date string whenever any of the three numbers change. The
// inline accessor functions are constexpr-friendly so they may be used
// in static_assert and at compile time.
#define MCL_VERSION_MAJOR  8
#define MCL_VERSION_MINOR  1
#define MCL_VERSION_PATCH  3
#define MCL_VERSION_STRING "8.1.3"
#define MCL_VERSION_DATE   "2026-08-22"
// 8.1.3 (2026-08-22): CONTRACT-NARROWING (no KAT/keystream change) --
//   MCL_PQ_MAX lowered from 2^62 to 2^53. Rationale: the Float64 path computes
//   (double)p * t, and integers above 2^53 are not exactly representable, so
//   the old bound ADMITTED inputs that silently lost precision (the old comment
//   at the MCL_T2 ctor already said so). The enforced bound now equals the
//   exact-integer bound of IEEE-754 double; the Q30 path keeps MCL_Q30_PQ_MAX
//   = 2^30. Any p,q in (2^53, 2^62] that previously constructed an engine now
//   aborts with the standard "invalid coupling weights" message. Every KAT,
//   CRC and keystream for in-range parameters is byte-identical (keyed
//   derivation draws weights in [2, 2^30)). The "~2^123 identity space" figure
//   (coprime pairs up to 2^62) is an ACCOUNTING number, not an engine bound;
//   the engine-enforced identity space is coprime pairs up to 2^53 (~2^105).
//   Also DOCS: header sweep count "919-pair" corrected to 489 (the corrected
//   figure of the 2026-07-11 periodic-window record). Prior bytes archived at
//   _backups/mcl_core_v8.1.2_pre_pqmax53_20260822.hpp (sha256 d630ed130df3...).
// 8.1.2 (2026-08-22): DOCS-ONLY -- SECURITY WARNING added to vdf_compute_q30()
//   (sec.16.1): the retired two-oscillator Q30 VDF path has a TRANSLATION
//   SYMMETRY that is reachable from the seed (for (p,q)=(3,5): an order-16
//   group; seeds <= 2^52 pass hash_seed unchanged and t_i = s*omega_i, so the
//   15 seeds s + k*2^28*omega1^-1 yield outputs equal to output(s) plus
//   constants, word for word). Measured on this engine 2026-08-22 (Doc IDs
//   MCL-T4-CYCLE-2026-0822-002/003/004, record
//   T4_CycleStructure/T4_CYCLE_RECORD_20260822.md sec.5a). The raw path was
//   already retired from every VDF role (Paper 4 sec.VII.E'); VDF128-T4
//   (SHA-256 injection + finalisation, public weights with a trivial symmetry
//   group) is the normative integer VDF. No code, KAT, or behavioral change;
//   bytes of the prior version archived at
//   _backups/mcl_core_v8.1.1_pre_vdfwarn_20260822.hpp (sha256 718d62658bcc...).
// 8.1.1 (2026-08-21): DOCS-ONLY -- banner patent list updated: fourth
//   application FILED as PCT/IB2026/058860 on 21 Aug 2026 (was the unfiled
//   "Patent-4" gate). No code, KAT, or behavioral change; bytes of the prior
//   version archived at _backups/mcl_core_v8.1.0_pre_patent4num_20260821.hpp
//   (sha256 c171af4c...).
// 8.1.0 (2026-07-17): ADDITIVE -- sec.4b device-bound keyed derivation
//   (Route-A realization of the PCT-04 device-binding embodiment): a 256-bit
//   device secret enters the WEIGHT DERIVATION, not the seed, via
//   K_eff = mcl_kdf256(key, "MCL-KeyDevice-v1", device_secret). Three new
//   inline functions only (mcl_keff_from_key_device,
//   mcl_t2_params_from_key_device, mcl_t4_params_from_key_device); NO
//   existing function is modified, the numerical output of every
//   pre-existing path is byte-for-byte UNCHANGED, and every v8.0.0 KAT/CRC
//   remains valid. MINOR bump per the policy above.
//   VERSION NOTE (metadata reconciliation, 2026-07-18): the 2026-07-17 build
//   that added sec.4b (sha256 647510e9..b4) carried the 8.1.0 banner but
//   still reported "8.0.0"/"2026-07-12" through the version macros, and
//   MCL_DOCUMENT_ID had remained at the pre-renumbering
//   MCL-CORE-2026-0526-001 (the 8.0.0 entry below records the advance to
//   -0712-001). This build reconciles both (comment/macro metadata only; no
//   code or numerical change). Pin release artifacts by SHA-256, never by
//   version string alone.
// 8.0.0 (2026-07-12): RELEASE RENUMBERING for the deposit/publication package
//   (author direction). NO code, API, or numerical change of any kind relative
//   to 7.0.4 (sha256 3c3909f7..d5a) beyond this version/Document-ID metadata:
//   output remains byte-for-byte identical to every 7.0.x / 6.1.0 build for
//   all valid inputs, and every KAT is unchanged. Collects the 2026-07-12
//   hardening campaign (7.0.3 + 7.0.4: F1-F7, QA-1/QA-2/QA-3) under a single
//   clean release number. Document ID advanced MCL-CORE-2026-0526-001 ->
//   MCL-CORE-2026-0712-001; the companion sidecar keyed_q30_PQ/
//   mcl_keyed_q30.hpp (v1.0.2) now references this engine of record.
// 7.0.4 (2026-07-12): HARDENING FOLLOW-UP (same-day QA round, items QA-2/QA-3).
//   Numerical output byte-for-byte UNCHANGED for every valid input
//   (re-verified: KATs, determinism fingerprint, cross-arch Q30). Contents:
//   - QA-2: mcl_make_validated_t2() now honors its "never aborts" contract for
//     POLICY arguments too: probe_iters <= 0 returns std::nullopt (previously
//     it fell through to compute_lyapunov's FATAL abort). A non-finite
//     sigma/min_lambda already rejected via the !(...) comparison. This is a
//     deliberate, documented exception to the fail-loud caller-bug convention:
//     this factory's whole contract is fail-closed validation.
//   - QA-3: vdf_verify_bounded() / vdf_verify_q30_bounded() -- caller-policy
//     N_delay ceilings for the PLAIN verifiers, mirroring
//     vdf_verify_transcript_bounded (F5): a shape-valid hostile claim with
//     N_delay ~ 2^62 otherwise recomputes "forever" (resource-exhaustion DoS).
//     Rejected fail-closed BEFORE the burn-in+delay loop; max_delay < 0
//     disables the bound. Additive API only.
//   - Doc: vdf_verify_transcript_bounded's comment now states that max_k < 0
//     likewise disables the checkpoint-count bound (behavior unchanged).
// 7.0.3 (2026-07-12): SECURITY-HARDENING PATCH from the full post-remediation
//   review + QA round (external report: FIXES_REPORT_20260712.md). Numerical
//   output byte-for-byte UNCHANGED for every valid input (float KATs, Q30 VDF,
//   keyed keystream, self-test KATs re-verified identical): every change is a
//   guard that only rejects inputs that previously crashed, aborted, or were
//   UB, or is additive API / documentation. Contents:
//   - F3: mcl_q30_K_phase() rejects non-finite K UNCONDITIONALLY (a NaN K
//     passed the (K<=0||K>12) release guard -- every NaN comparison is false --
//     and reached an undefined float->int64 cast in NDEBUG builds).
//   - F2: mcl_valid_t2_params() shared predicate; vdf_verify() now fails
//     closed (null expected / negative N / invalid params -> false, never
//     abort); vdf_verify_transcript() refactored onto the same predicate.
//   - F5: vdf_verify_transcript_bounded() -- caller-policy ceilings on
//     N_delay / checkpoint count, rejected fail-closed BEFORE the recompute.
//   - F4: mcl_kdf256() caps label/info at 1 MiB each (size_t wrap of the
//     preimage length -> under-allocation -> wild memcpy).
//   - F1: mcl_make_validated_t2() -- construction-time Lyapunov-validated
//     factory; the correct per-instance guard for the periodic/quasi-periodic
//     K-windows that persist above K_min (see its comment block). +<optional>.
//   - F6: T3/T4 constructor comments now carry the K-window caveat.
//   - F7: #warning (MSVC: pragma message) when MCL_UNSAFE_ALLOW_INVALID is
//     compiled in, so a research flag can never ship silently.
//   - QA-1 (new in this bump): vdf_verify_q30() -- the verifier documented for
//     CROSS-PLATFORM use, i.e. the most untrusted-input-facing one -- now
//     fails closed like its Float64 twin, via the shared predicate
//     mcl_valid_q30_vdf_params(). Previously a null `expected` was a SEGV and
//     a hostile (seed,p,q,K) tuple tripped vdf_compute_q30's abort guards: a
//     denial-of-service in the API meant to check untrusted claims.
//   VERSION NOTE: an interim 2026-07-12 build carried F1-F7 while still
//   labeled "7.0.2" (sha256 a7566473..d6). This 7.0.3 supersedes it. Pin
//   release artifacts by SHA-256, never by version string alone.
// 7.0.2 (2026-07-11): DOCUMENTATION/ADVISORY PATCH. Numerical output byte-for-
//   byte UNCHANGED -- no engine byte stream, KAT, or CRC is touched; the only
//   edits are comments, two advisory constants, and one stderr diagnostic
//   string, none of which are read by iterate()/gen_byte() (which use the
//   caller's K). MD5 of the file changes; the engine of record is numerically
//   identical to v7.0.1. Corrects a now-falsified safety claim:
//   - Independent multi-method verification (C++ QR; an independent Python
//     two-trajectory Lyapunov re-implemented from the map equations; and the
//     chi^2 byte metric) established that narrow periodic/quasi-periodic
//     windows persist ABOVE K=1.0 for some topologies -- e.g. (3,5) resonates
//     at K~1.22 (chi^2~1.7M, lambda<0) and K~2.595 (chi^2~3.1M), is quasi-
//     periodic at K~3.79/5.73 (lambda~0), and (2,3) has a band across
//     K~1.28-2.08. A fine (step 0.005) sweep confirms K in [6,20] is window-
//     free for the tested pairs. Evidence bundle in
//     05_Scientific_Papers/Reviews/FivePersona_Detailed_20260711/VERIFY_*.
//   - MCL_K_RECOMMENDED_FLOOR: 1.0 -> 6.0 (its old comment "above this, all
//     tested topologies are chaotic" was false). ADVISORY only; the hard
//     sentinel K_min = MCL_K_MIN_NUMERATOR/(p+q) is UNCHANGED.
//   - MCL_T2_K_RECOMMENDED: 2.0 -> 6.0 (its old comment "above empirical
//     periodic windows" was false: K=2.595 > 2.0 still resonates).
//   - K_min FATAL diagnostic now advises K >= 6.0 (was 1.0).
//   No claim is affected: the keyed Patent-4 engine fixes K=12 (window-free
//   range); a 489-pair weight-space sweep at K=12 found 0 non-chaotic pairs (v8.1.3: figure corrected from 919).
// 7.0.1 (2026-07-07): API-hardening PATCH from the external + internal review
//   round. Numerical output unchanged (differential harness re-verified
//   byte-identical); no frozen vector is affected.
//   - mcl_kdf256: unconditional FATAL guards for null key/label, and for
//     null info/out with nonzero lengths (strlen(nullptr)/memcpy(nullptr)
//     were reachable caller bugs).
//   - mcl_sha256: unconditional FATAL guards for (msg == nullptr && len > 0)
//     and for null out.
//   - vdf_compute_checkpointed: unconditional FATAL guard for a null
//     checkpoints array with k > 0 (writing through it is memory corruption,
//     never a research scenario), and the interval computation is k-safe
//     even under MCL_UNSAFE_ALLOW_INVALID (no k = 0 division).
//   - RELEASE GATE banner added (internal until Patent-4 filing);
//     removed 2026-07-10 by author instruction during release preparation.
//   - sec.16 cross-reference: the keyed fixed-point realization MCL_T4_Q30
//     lives in the companion sidecar keyed_q30_PQ/mcl_keyed_q30.hpp.
// 7.0.0 (2026-07-06): Pre-publication hardening release. The numerical output
//   of EVERY pre-existing valid path is byte-for-byte UNCHANGED (verified with
//   a differential baseline harness against v6.1.0 covering all seven engines,
//   the keyed paths, Q30, both VDFs, hierarchical derivation, and all
//   statistics) -- all frozen KAT/CRC vectors remain valid. MAJOR bump for the
//   API/behavioral additions:
//   - NEW vdf_verify_transcript(): seed-anchored, tamper-evident verification
//     of checkpointed VDF transcripts. Closes the vdf_verify_segment
//     fabricated-start-state soundness gap; the segment API now carries an
//     explicit UNSOUND-when-standalone warning.
//   - vdf_compute_checkpointed(): optional checkpoints_written out-param (the
//     previous doc promised a return count that did not exist; N < k now
//     reports 0 explicitly instead of failing silently).
//   - Stricter validation: MCL_T4 ctor enforces the 2^62 upper bound (T2/T3
//     parity); distance_correlation/spectral_test validate inputs and fail
//     closed on degenerate lengths (and the sample dCov^2 is clamped at 0,
//     so rare rounding on valid-length independent inputs can no longer
//     yield NaN); generate_topologies/compute_lyapunov guard non-positive
//     sizes; ALL ctor parameter asserts unified INSIDE the
//     MCL_UNSAFE_ALLOW_INVALID guard (debug research builds now behave as
//     documented without requiring -DNDEBUG).
//   - Key-material hygiene: SHA-256 rewritten as heap-free streaming
//     compression; the KDF and keyed factories secure_zero every intermediate
//     that carries key or key-derived secrets; MCL_T2_Omega move-assignment
//     now erases the source's w1_/w2_ (parity with its move constructor).
//   - Q30 hot path re-expressed in fully-defined unsigned arithmetic
//     (bit-identical output; removes C++17 implementation-defined
//     negative-shift/narrowing reliance).
//   - mcl_self_test(): new VDF-transcript positive + tamper/forgery negative
//     controls.
//   - Documentation corrections: integer-Q30 battery-testing status (BigCrush
//     Run 2 was the Float64 LUT multiplex, NOT the integer engine), keyspace
//     collision accounting, derive_child range [2, max_val-1], stale-comment
//     and residue sweep.
// 6.1.0 (2026-06-11): ADDED the 256-bit keyed post-quantum key path (SHA-256
//   KDF -> keyed MCL_T2_Omega / MCL_T4; sec.3.1 and the keyed factories).
//   MINOR bump: NEW functionality only -- the numerical output of every
//   pre-existing constructor/path is byte-for-byte UNCHANGED, so all frozen
//   KAT/CRC vectors (mcl_kat_vectors[], Q30 LUT/VDF) remain valid. NOTE for
//   manuscripts: the "engine of record" is now v6.1.0; the §-citations of
//   v6.0.0 numerical results are unaffected (same numbers).

// ---------------------------------------------------------------------------
// PROVENANCE / TRACEABILITY METADATA (per MCL Header Update Rules sec.3)
// ---------------------------------------------------------------------------
// - MCL_DOCUMENT_ID is FROZEN with the 2026-07-12 document series (unified
//   numbering per the rules: no independent per-file version numbers; it
//   advanced from the 2026-05-26 series at the 8.0.0 renumbering -- see the
//   8.0.0 changelog entry).
//   MCL_VERSION_DATE tracks the engine version above.
// - MCL_BUILD_TIMESTAMP is the LIVE compile time. It is a printed string only;
//   it NEVER enters any computation, so all CRC/KAT/numeric results are
//   unaffected by it. For a reproducible build that must not embed the wall
//   clock, define it on the command line, e.g.:
//       g++ ... -DMCL_BUILD_TIMESTAMP='"2026-05-26T00:00:00Z"' ...
#define MCL_DOCUMENT_ID    "MCL-CORE-2026-0712-001"
#ifndef MCL_BUILD_TIMESTAMP
#define MCL_BUILD_TIMESTAMP (__DATE__ " " __TIME__)
#endif

inline constexpr const char* mcl_version()      { return MCL_VERSION_STRING; }
inline constexpr const char* mcl_version_date() { return MCL_VERSION_DATE;   }
inline constexpr int         mcl_version_major(){ return MCL_VERSION_MAJOR;  }
inline constexpr int         mcl_version_minor(){ return MCL_VERSION_MINOR;  }
inline constexpr int         mcl_version_patch(){ return MCL_VERSION_PATCH;  }
inline constexpr const char* mcl_document_id()  { return MCL_DOCUMENT_ID;    }
// Not constexpr-forced: __DATE__/__TIME__ resolve at translation, but keeping
// this a plain inline lets a command-line override be any expression.
inline const char*           mcl_build_timestamp(){ return MCL_BUILD_TIMESTAMP; }


// ============================================================================
// IEEE 754 STRICT COMPLIANCE GUARD
// ============================================================================
// MCL requires strict IEEE 754 floating-point semantics. The Safe Zone [6-39]
// Gauss-Seidel sequential dependency (Eq. 2-3),
// bit-exact reproducibility (CRC-32), and challenge-response authentication
// all depend on deterministic floating-point evaluation
// order and correctly-rounded transcendental functions (sin, cos, fmod).

// -ffast-math (GCC/Clang) and /fp:fast (MSVC) permit the compiler to:
// - reorder floating-point operations (breaks Gauss-Seidel causality)
// - replace sin/cos with polynomial approximations (shifts Safe Zone)
// - assume no NaN/Inf (removes isfinite guards)
// - flush denormals to zero (alters low-K regime behavior)

// -Ofast implies -ffast-math. CUDA uses fast-math by default.
// Any of these silently invalidates all validated results (BigCrush, NIST,
// PractRand) and breaks authentication bit-identity without warning.

// GCC / Clang (existing guard, retained)
#if defined(__FAST_MATH__)
#error "MCL requires strict IEEE 754 compliance. Do not compile with -ffast-math or -Ofast."
#endif

// CUDA (existing guard, retained)
#if defined(__CUDA_ARCH__)
#error "MCL requires strict IEEE 754 compliance. CUDA fast-math is incompatible."
#endif

// MSVC /fp:fast
#if defined(_MSC_VER) && defined(_M_FP_FAST)
#error "MCL requires strict IEEE 754 compliance. Do not compile with /fp:fast on MSVC."
#endif

// Intel oneAPI / icpx fast-math
#if defined(__INTEL_LLVM_COMPILER) && defined(__FAST_RELAXED_MATH__)
#error "MCL requires strict IEEE 754 compliance. Disable fast-math on Intel compiler."
#endif

// x87 extended-precision evaluation
// FLT_EVAL_METHOD must be 0 (eval at type) or 1 (eval at double); == 2
// (eval at long double, x87 default on 32-bit x86) silently produces
// 80-bit intermediates that round to 64-bit, breaking bit-exactness.
#include <cfloat>
#if defined(FLT_EVAL_METHOD) && (FLT_EVAL_METHOD == 2)
#error "MCL requires FLT_EVAL_METHOD in {0,1}. x87 extended precision (=2) breaks bit-exactness."
#endif

// FP_CONTRACT must be OFF.
// FP_CONTRACT ON allows the compiler to fuse a*b+c into a single FMA
// instruction, producing a result that differs from the IEEE 754 result
// of the un-fused expression by up to 1/2 ULP. In a chaotic system with
// positive Lyapunov exponent this 1/2-ULP difference at one iteration
// is amplified to a completely different trajectory after burn-in.

// Note: GCC and some other compilers do not implement the C99 pragma
// STDC FP_CONTRACT directly (they use compiler-specific options instead).
// We emit it for compilers that DO honor it, with a warning suppressor
// for GCC, and add the GCC-specific optimize pragma below as a fallback.
#if defined(__clang__) || (defined(__INTEL_LLVM_COMPILER) && !defined(__GNUC__))
#pragma STDC FP_CONTRACT OFF
#endif
#if defined(__GNUC__) && !defined(__clang__) && !defined(__INTEL_LLVM_COMPILER)
#pragma GCC optimize("fp-contract=off")
#endif
#if defined(_MSC_VER)
#pragma fp_contract(off)
#endif

// BIT-EXACT FLOATING-POINT COMPARISONS:
// MCL deliberately uses `==` and `!=` on doubles in several categories of
// sites (v7.0.0: a clean `-Wfloat-equal` build reports 8 warnings with
// current g++/clang -- the double-vs-double sites; the kc_ == 0.0 sentinel
// comparisons against a literal are additional intentional sites that these
// compilers do not flag. All fall into the categories below):
// - Moved-from / erased sentinels (kc_/K_ == 0.0): detects the specific bit
// pattern set by erase()/erase_identity()/move-ctor and by is_invalid().
// This is NOT an approximate comparison; the IEEE 754 double 0.0 is the
// unique sentinel value, never produced by valid iteration.
// - broken-symmetry enforcement: w1 == w2 / w1 != w2. Bit-for-bit compare.
// - VDF verification: t1 == t1_end checks deterministic trajectory replay.
// Same IEEE 754 platform => bit-identical result.

// Compiling with `-Wfloat-equal` produces these warnings (8 measured on the
// v7.0.0 build with g++ 15 / Apple clang), all intentional. To silence:
// #pragma GCC diagnostic ignored "-Wfloat-equal" (GCC/Clang)
// MCL does NOT enable this warning by default in its build system.
// Every such site has a comment naming its role.

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cassert>
#include <limits>
#include <string>
#include <optional>
#include <vector>
#include <array>
#include <chrono>
#include <algorithm>
#include <set>

// ============================================================================
// Portable branch-prediction hints
// ============================================================================
// [[likely]] and [[unlikely]] are formally C++20 (P0479R5). GCC accepts them
// as an extension in C++17 mode, but the C++17 standard does not require it,
// and older Clang (<=12) or stricter compilers may warn or reject.

// We define MCL_UNLIKELY(x) that:
// - Uses __builtin_expect on GCC/Clang (available in every standard mode,
//   so C++17 and C++20 builds get the same branch hint)
// - Falls back to plain (x) on other compilers (zero hint, no harm)
// All cold guard paths in this file are written `if (MCL_UNLIKELY(cond)) {`.
#if defined(__GNUC__) || defined(__clang__)
  #define MCL_UNLIKELY(x) (__builtin_expect(!!(x), 0))
#else
  #define MCL_UNLIKELY(x) (x)
#endif

// ============================================================================
// IEEE 754 TYPE VERIFICATION
// ============================================================================
// The Safe Zone [6-39] is defined by the structure of IEEE 754 double-precision
// mantissa (52-bit fractional part). If double is not IEEE 754 or not 64-bit,
// the mantissa layout changes and all validated bit positions become invalid.
// This also breaks d2b() which assumes sizeof(double) == sizeof(uint64_t).
static_assert(std::numeric_limits<double>::is_iec559,
 "MCL requires IEEE 754 double-precision (Safe Zone depends on mantissa structure)");
static_assert(sizeof(double) == 8,
 "MCL requires 64-bit double");

// ============================================================================
// BYTE-ORDER (ENDIANNESS) DOCUMENTATION
// ============================================================================
// MCL's Float64 path is BIT-EXACT only on the same byte-order architecture.
// The Goldilocks extraction in gen_byte():

// uint64_t x = d2b(t1_) ^ d2b(t2_);
// return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);

// uses memcpy(double -> uint64_t) followed by integer shifts. The integer
// VALUE of x differs between little-endian and big-endian platforms,
// because IEEE 754 double bytes are stored differently in memory.

// CONSEQUENCES:
// - Float64 path output BYTES differ between LE and BE platforms.
// - Bit-exact regression and CRC-32 fingerprints assume LE.
// - Q30 path (uint32_t arithmetic only) IS byte-order independent.

// MITIGATION:
// - For cross-platform deterministic output (VDF),
// use the Q30 path explicitly -- see mcl_q30_iterate_raw().
// - For Float64 deployments on common platforms (x86_64, ARM64 LE,
// RISC-V LE, all modern phones, all macOS/Windows/Linux x86_64):
// bit-exact output is guaranteed.
// - Big-endian deployments (legacy PowerPC, SPARC, some MIPS):
// output is statistically equivalent but NOT bit-identical.

// Modern reality: 99%+ of deployments are little-endian. We refuse to
// silently produce wrong output on big-endian: emit a compile-time
// warning so the user is aware. (Hard error would block legitimate
// big-endian research compilation.)
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
  #if !defined(MCL_BIG_ENDIAN_ACK)
    #warning "MCL: big-endian platform detected. Float64 output will not be \
bit-identical to little-endian platforms. For cross-platform identity, \
use the Q30 path (mcl_q30_iterate_raw). Define MCL_BIG_ENDIAN_ACK to \
acknowledge and silence this warning."
  #endif
#endif

// ============================================================================
// PARAMETER VALIDATION (SECURE BY DEFAULT)
// ============================================================================
// Coupling parameter validation (p>0, q>0, p!=q) is enforced at runtime
// by default in ALL build modes, including release (-DNDEBUG). Invalid
// parameters cause immediate abort() with a diagnostic message.

// This follows the "secure by default" principle: a developer building
// a 5G-AKA, SIM authentication, hierarchical key derivation, or
// verifiable delay system gets full protection without needing to
// know about any special macro.

// PARAMETER VALIDATION:
// - derive_child: max_val >= 4 enforced (abort if violated).
// - vdf_compute: N_delay >= 0 enforced (abort if violated).
// - vdf_compute_checkpointed: N_delay >= 0, k > 0 enforced.
// - VDF checkpoint states expose theta1, theta2 by design --
// this is required for segment verification and is NOT a leak.
// - HD one-way security depends on BURNIN (10000 iterations).
// Reducing BURNIN weakens the chaos barrier exponentially.

// For RESEARCH use only (negative controls, edge-case exploration),
// compile with:
// g++ -O3 -DNDEBUG -DMCL_UNSAFE_ALLOW_INVALID ...
// This disables runtime parameter guards, allowing the engine to run
// with degenerate parameters and produce observable (weak) output.
// v7.0.0: ALL engine parameter asserts now sit INSIDE the macro guard, so a
// debug build with -DMCL_UNSAFE_ALLOW_INVALID behaves like the documented
// research mode without also requiring -DNDEBUG. (Before v7.0.0, several
// plain assert()s sat outside the guard and still fired in debug builds.)
// T2/T3/T4 are structurally safe with any p,q -- mod2pi+sin confines
// state to [0,2pi). Invalid parameters produce weak output but never
// UB, NaN, or memory corruption.

// seed=0 is ALWAYS fatal (abort in hash_seed, regardless of any macro).

// Emit a loud diagnostic if the unsafe research build is enabled, so a stray
// -DMCL_UNSAFE_ALLOW_INVALID in a production build system is never silent.
// (A hard #error in release builds is deliberately NOT added yet: the K-sweep
// research tools compile with this macro and must keep building.)
#if defined(MCL_UNSAFE_ALLOW_INVALID)
#  if defined(_MSC_VER)
#    pragma message("WARNING: MCL_UNSAFE_ALLOW_INVALID enabled -- runtime parameter validation is DISABLED (research build)")
#  else
#    warning "MCL_UNSAFE_ALLOW_INVALID enabled -- runtime parameter validation is DISABLED (research build)"
#  endif
#endif

// ============================================================================
// TIMING SIDE-CHANNEL NOTICE
// ============================================================================
// The MCL engine contains no data-dependent branches. However, the
// underlying libm functions (std::sin, std::cos, std::fmod) are NOT
// guaranteed constant-time by the C++ standard or any known libm
// implementation. Execution time may depend on input values.

// For remote authentication (5G network), network jitter (~1-10ms)
// masks any timing signal (~2ns/byte). For LOCAL authentication
// (eSIM/iSIM on same device), a co-located attacker could
// potentially measure timing differences across many challenges.

// For deployments requiring constant-time guarantees, replace
// std::sin() with a fixed-size lookup table (65536 entries).
// This configuration is validated in Paper 2, sec.VII.B (BigCrush
// 160/160 on lookup-table multiplex).

// TIMING CONSIDERATIONS:
// - VDF (sec.13): Elapsed time reveals N (the delay parameter).
// This is BY DESIGN -- VDF output is public and verifiable.
// N is not secret; it is an agreed-upon protocol parameter.
// - HD derive_child (sec.12): Constant-time (one burn-in + 32 bytes).
// No timing variation between different indices or parents.
// - HD derive_child_safe (sec.12): The retry loop for resonance
// avoidance may leak the NUMBER OF RETRIES via timing.
// At K >= 1.0 (all production configurations), retries = 0
// empirically. At low K (resonance region), retry count
// reveals resonance density -- not security-sensitive.

// ============================================================================
// sec.1 CONSTANTS -- System parameters (do not modify: reproducibility)
// ============================================================================

constexpr double MCL_TWO_PI = 6.283185307179586476925286766559;
constexpr double MCL_PI = 3.141592653589793238462643383280;

// Angular frequencies -- from distinct algebraic extensions over Q
constexpr double OMEGA_1 = 0.6180339887498949; // phi - 1 (Golden ratio minus 1)
constexpr double OMEGA_2 = 1.3247179572447460; // rho (Plastic constant)
constexpr double OMEGA_3 = 0.4142135623730950; // sqrt2 - 1
constexpr double OMEGA_4 = 0.7182818284590452; // e - 2

// Engine defaults
constexpr double K_DEFAULT = 12.0;
constexpr int BURNIN = 10000;
constexpr int GOLD_S1 = 20; // Goldilocks shift 1: bits [20-27]
constexpr int GOLD_S2 = 36; // Goldilocks shift 2: bits [36-43]
constexpr int DECIMATION = 2;

// Q30 engine: maximum (p,q) without int64_t overflow in
// uint32_t a1 = (uint32_t)((int64_t)p * (int64_t)t2 - (int64_t)q * (int64_t)t1)

// t1, t2 are uint32_t in [0, 2^32). For (int64_t)p * (int64_t)t2 to fit in
// int64_t (max 2^63-1) with worst-case t2 = 2^32-1, we need p * 2^32 < 2^63,
// i.e., p < 2^31. The subtraction can amplify by 2x, so to be safe across
// the full subtraction we require p, q <= 2^30.

// This is dramatically smaller than the
// nominal ACCOUNTING range [2, 2^62] (engine-enforced: [2, 2^53], v8.1.3). The accounting range describes the IDENTITY SPACE
// (number of distinct device IDs available); the Q30 engine implements the
// OPERATIONAL SECURITY range. The distinction between identity space and
// security level is documented in the accompanying paper (Section IV).

// Deployment guidance (range tiers):
// - Consumer (mobile/IoT/eSIM): p, q in [2, 10^9] (well within 2^30)
// - Enterprise: p, q in [2, 10^12] (exceeds 2^30 -- use Float64 path)
// - High-security: p, q in [2, 10^15] (Float64 path only)
// - Maximum security: p, q in [2, 10^18] (Float64 path only)

// For the Q30 path (used by VDF cross-platform verification),
// enforce p,q <= MCL_Q30_PQ_MAX. The Float64 path tolerates
// larger values with graceful precision loss.
constexpr int64_t MCL_Q30_PQ_MAX = (1LL << 30); // 2^30 = 1,073,741,824

// K_min DERIVATION (self-contained):
// The MCL update rule x_{n+1} = sin( K * (p*y_n + q*x_n) ) generates chaos
// when the Jacobian's spectral radius exceeds unity. Linearization around
// the fixed point yields the bifurcation boundary
//     K * sqrt(p^2 + q^2) ~ exp(L*) at the chaos onset,
// with L* = 3.24/2.00 = 1.62 the empirically-fitted Lyapunov shift between
// the linearized stability boundary and the dense-chaos threshold (see
// Paper 1, Section III.B for the fit). Solving for K and using the
// p+q-symmetric form gives
//     K_min(p,q) = exp(3.24/2.00) / (p + q)
// The constant exp(3.24/2.00) ~= 5.053090316563868 is truncated to 10
// decimals as MCL_K_MIN_NUMERATOR below.
//
// PRECISION NOTE: the 10-decimal truncation 5.0530903166 differs from the
// IEEE 754 rounding of exp(3.24/2.00) by ~3.6e-11 absolute, ~4 ULP at this
// magnitude. This is below any practical safety margin (the K_min check
// itself has a non-trivial empirical caveat, see EMPIRICAL CAVEAT block
// below). Using a literal avoids runtime computation; the truncated form
// is well-defined across all conforming C++ compilers.
#define MCL_K_MIN_NUMERATOR 5.0530903166 // 10-dec trunc of exp(3.24/2.00)

// EMPIRICAL CAVEAT on K_min(p,q):

// The K_min = MCL_K_MIN_NUMERATOR/(p+q) bound is a NECESSARY condition for
// chaos (lambda_max > 0 in the limit), but it is NOT a SUFFICIENT condition
// for dense chaoticity at finite simulation length. Empirical validation
// found:

// (p,q) K_min K = 1.05 * K_min lambda_1 chi^2
// ----- ----- ---------------- -------- ----------
// (2,3) 1.011 1.061 +0.87 229 OK
// (3,5) 0.632 0.663 -1.07 3,100,000 FAIL
// (5,7) 0.421 0.442 +0.75 230 OK
// (7,11) 0.281 0.295 +0.69 248 OK
// (11,17) 0.181 0.190 -0.09 1,119,048 FAIL
// (13,19) 0.158 0.166 +0.74 254 OK

// Topologies (3,5) and (11,17) fail catastrophically just 5% above K_min,
// producing output with chi^2 in the millions (vs 330 threshold) and
// negative lambda. The mathematical "K_min" admits regions of measure-zero
// chaos that are not achievable in practice for short observation windows.

// Recommendation: For default cryptographic usage, use K = K_DEFAULT = 12
// which passes statistical tests for ALL tested topologies. If you must
// use a lower K (e.g., for performance or for engineering an embedded
// system), test EACH (p,q) topology empirically -- do not rely on K_min
// alone.

// We do NOT lower the constructor sentinel below K_min, because:
// - Above K_min is mathematically valid per the formula.
// - Adding a stricter empirical floor would impose our specific test
// conditions (seed, simulation length) on all users.
// - The honest answer is that K_min is necessary, not sufficient.
#define MCL_K_RECOMMENDED_FLOOR 6.0 // Empirically window-free floor for tested
// topologies. CORRECTION (v7.0.2, 2026-07-11): the former value 1.0 with the
// comment "above this, all tested topologies are chaotic" was FALSE -- narrow
// periodic windows (lambda<0, chi^2 in the millions) persist above K=1.0 for
// some topologies: (3,5) at K~1.22 and 2.595, quasi-periodic at 3.79/5.73;
// (2,3) across K~1.28-2.08. A fine (step 0.005) sweep confirms K in [6,20] is
// window-free for the tested pairs, so 6.0 is the honest advisory floor. This
// is an ADVISORY constant only (not a runtime guard); the hard sentinel is
// K_min = MCL_K_MIN_NUMERATOR/(p+q), unchanged. Verified independently (C++ QR,
// an independent Python two-trajectory re-implementation from the map
// equations, and the chi^2 byte metric); see the Reviews/ evidence bundle.

// RUNTIME PARAMETER STATUS:

// lambda_max > 4.0 (sequential update)
// STATUS: VERIFIED EMPIRICALLY at K_DEFAULT=12 for all 8 default
// topologies (range 4.97-9.25). Not a runtime check; cost would be
// ~10^6 iterations per construction.

// GOLD_S1=20, GOLD_S2=36 for W=8.
// STATUS: HARDCODED in gen_byte() across all engines. Verified:
// shifts >= 52 hit IEEE exponent, producing chi^2 > 14000.

// bits [0-5] excluded (chi^2 > 10000 with 100M samples).
// STATUS: VERIFIED. Bit 0 measured chi^2 = 3.7M with 10M samples
// (= 37M extrapolated to 100M). Bits 0-5 are NOT extracted by gen_byte.

// K in [9.5, 10.5] -> theta_2 wider safe zone.
// STATUS: NOT REPRODUCED. Empirical measurement shows theta_1 has
// 37 safe bits, theta_2 has 36 at K=10. Claim may be artifact of
// different measurement methodology or specific (p,q) tested.
// Code does not depend on this claim (uses theta_1 XOR theta_2).

// lambda_GS / lambda_J > 1.5.
// STATUS: VERIFIED. Measured ratios 1.611-1.811 for all 8 topologies.

// gcd(p,q) = 1 (coprime).
// STATUS: ENFORCED via runtime sentinels in all 7 engine ctors
// AND in MCL_T2/MCL_T3/MCL_T4 hop() methods.

// Core claim: distinct (p,q) -> independent streams.
// STATUS: pearson_r-VERIFIED. 15/15 cross-pair pearson_r below 0.01.
// [caveat]: pearson_r tests LINEAR independence only.
// True statistical independence requires distance correlation, mutual
// information, or Bonferroni-corrected battery. The stronger validation
// (9,682 pairwise tests with Bonferroni correction at 99.9% family-wise
// confidence) is documented in the published reference, not reproduced
// in our internal test (which used 15 pairs * 1 test each).

// ADVERSARIAL CRYPTANALYSIS SUMMARY (informal, internal):

// The MCL system has been internally probed against 6 attack categories
// . Results are advisory; formal external cryptanalysis
// is still pending. Each test is reproducible from sources in the
// /test_*.cpp files of the v2 distribution.

// 1. State-recovery via brute force on seed:
// -> 2^64 search at 1099 candidates/sec = 5.32e+8 years.
// -> Infeasible (36x age of universe).

// 2. Distinguishing attack vs uniform random (Mersenne Twister ref):
// -> chi^2, entropy, bit_freq, autocorr at 5 lags, runs_z, pearson_r.
// -> All listed statistics fall within their respective noise bands
// when comparing MCL to MT19937 at N=1M. This is a NECESSARY
// condition for being "indistinguishable from random," not
// sufficient -- a determined attacker may construct distinguishers
// outside this set (e.g., DSAB, structural distinguishers from
// linear cryptanalysis). Stronger validation requires PractRand
// and TestU01 BigCrush. [caveat]

// 3. Related-seed attack (s, s+/-1, s^bit, s*2, ~s, rotations):
// -> 12 transformations tested at N=1M.
// -> All pearson_r below 99.9% noise floor (3.29 / sqrt(N)).

// 4. Forward prediction (n-gram k=1,2 over 5M bytes):
// -> Best predictor accuracy: 0.39%-0.40% (random = 0.39%).
// -> Bias from random < 0.01%, below noise floor 0.12%.

// 5. Side-channel timing (median per output value, 1M calls):
// -> Median spread across 256 outputs: 1 ns (~0.5%).
// -> No exploitable timing oracle in measured platform.

// 6. Per-bit-position bias (N=10M, all 8 bit positions):
// -> All 8 bits uniform at 99.9% confidence.
// -> No detectable bit-level structure.

// CAVEAT: Internal attacks are weaker than external cryptanalysis.
// Absence of internal attack does NOT prove absence of attack.
// External independent cryptanalysis remains the gold standard
// before mission-critical deployment.

// (p,q) RECOVERY ATTACK SCALING
// Threat model: attacker knows seed (e.g., public challenge in hardware
// authentication), but NOT the device-specific (p,q) coupling weights.
// Attack: brute-force (p,q) by reconstructing 64-byte output.

// Measured single-threaded rate: 868-1570 (p,q) pairs/sec depending on engine.
// Recommended (p,q) range [2, 10^9] gives ~10^18 coprime pairs.

// Security scaling at ~1000 pairs/sec:
// range pairs single-core years cluster (10^6 cores)
// ------ ----- ----------------- --------------------
// [2, 30] 496 ~0 sec ~0 sec
// [2, 10^3] ~6e5 ~10 minutes ~ms
// [2, 10^6] ~6e11 ~31 years ~10 hours <-- WEAK
// [2, 10^9] ~6e17 ~3.3e+7 years ~33 years <-- adequate

// PRODUCTION RANGE [2, 10^9]:
// Cluster cost ~33 years per device. Adequate against typical adversaries.
// For longer-than-device-lifetime security, use (p,q) > 10^9.

// EMBEDDED-COMPACT RANGE [2, 10^6]:
// Cluster cost only ~10 hours per device. NOT SAFE against well-funded
// adversaries. If embedded device cannot store 10^9-range (p,q), use
// ADDITIONAL secrecy (mix in device-secret salt to seed before MCL init).

// GPU/ASIC speedup is plausible (10x-100x), shifting the boundary further.
// MITIGATION: combine device-secret-salted seed with (p,q); attacker must
// brute-force BOTH spaces to recover either. This is good practice and
// matches typical hardware-authentication patterns.


// DYNAMICAL / PHYSICAL ANALYSIS

// The deeper physics question: GIVEN that the system is chaotic
// (Lyapunov lambda_max ~= 5.78), and IEEE 754 rounding errors compound
// exponentially, IS THE OUTPUT EVEN MEANINGFUL? Or is it just FP noise?

// Four physics-informed tests were run:

// 1. SHADOWING LEMMA TEST -- compare double vs long double trajectories
// for the same seed. Per Anosov shadowing, hyperbolic systems'
// finite-precision orbits are tracked by a TRUE orbit at slightly
// different initial conditions.
// Result: at iter 0, |delta_t1| = 0. At iter 10, |delta_t1| ~= 2.3
// (saturated at attractor diameter 2pi). After saturation, the
// pointwise trajectories diverge -- but their STATISTICAL
// distributions agree to KS = 0.0045 (vs CLT noise 0.0043) over
// N = 100,000 samples.
// VERDICT: System is properly hyperbolic. FP errors do not corrupt
// statistical properties -- they corrupt ONLY exact orbit identity,
// which is irrelevant for cryptographic use.

// 2. ERGODICITY ON T^2 -- time average of cos(m*t1 + n*t2) for 11
// distinct (m,n) modes converges to 0 within sqrt(N) noise floor.
// VERDICT: System is ergodic on the 2-torus.

// 3. CYCLE DETECTION -- 10^7 iterations stored in hash table; no
// collision (state repetition) found. Birthday bound is ~2^52
// = 4.5e+15 iterations.
// VERDICT: No exploitable cycle within practical compute.

// 4. PHASE-SPACE MEASURE -- 32x32 = 1024 bin chi^2 against uniform
// gives chi^2 ~= 13,755 at N = 10^6 (vs threshold ~1,172).
// Ratio chi^2/N stable at 0.013 across N.
// VERDICT: Invariant measure on T^2 is NOT Lebesgue (uniform).
// It is the SRB (Sinai-Ruelle-Bowen) measure of the system,
// with bounded density variation (max/min ratio ~1.6).
// This is NORMAL for chaotic maps -- output uniformity at byte
// level is achieved by the Goldilocks shift+XOR extraction acting
// as a UNIFORMIZER on the non-uniform phase distribution.

// COMBINED INTERPRETATION: The MCL system has the rigorous mathematical
// structure of a hyperbolic, ergodic chaotic map on T^2 with SRB
// invariant measure. Bit-level output uniformity is achieved by a
// well-designed extractor on the chaotic source. This is the same
// architecture as physical TRNGs (e.g., Intel RdRand): a non-uniform
// physical source + a deterministic extractor.

// CLASSICAL CRYPTANALYSIS RESULTS

// Output-level adversarial cryptanalysis is supplemented by tests at the
// ITERATION MAP level (mathematically deeper).
// Five classical attack families were attempted:

// 1. LINEAR CRYPTANALYSIS (output bytes):
// Tested 8 single-bit biases + 5 sliding-XOR combinations + 8 pair
// XORs (gap 1-100). N=1M. ALL biases < 1.4 sigma. PASS.

// 2. LINEAR CRYPTANALYSIS (raw state bits):
// Multi-bit scan of d2b(t1, t2, t1', t2'), 52 bits x 15 masks =
// 780 tests. Separated Goldilocks region (bits 20-43,
// attacker-visible after extraction) from non-extracted bits:
// Goldilocks region (360 tests): 0 biases > 5 sigma. PASS.
// Non-extracted (bits 0-5, 44-51): 76 biases (IEEE 754
// distributional, expected, NEVER exposed to attacker).
// The Goldilocks shifts (>>20, >>36) were designed empirically
// and CONFIRMED CRYPTANALYTICALLY to extract precisely
// the unbiased mantissa region.

// 3. DIFFERENTIAL CRYPTANALYSIS (iteration map):
// Single-step amplification of small input perturbations:
// delta_in 1e-15 -> delta_out 4e-14 (amp ~42x), saturating at 2pi
// after ~7 iterations. Matches expected Lyapunov characteristic
// |1 - K*q*cos|, RMS over attractor ~ sqrt(1 + (Kq)^2/2) ~ 42.
// No exploitable differential trail.

// 4. ALGEBRAIC CRYPTANALYSIS:
// sin() is transcendental -- NOT a polynomial over Q or any finite
// field. A degree-30 polynomial CAN match sin() to ULP precision
// (Taylor remainder ~3.1e-19). However, after T iterations, the
// composed polynomial has degree 30^T:
// T=4: 30^4 = 810,000 ~ 2^20 Groebner threshold
// T=5: 30^5 = 24M ~ 2^25 infeasible
// T=BURNIN=10000: astronomical
// Groebner / XL / XSL attacks become infeasible after T > 4. MCL's
// BURNIN=10000 >> 4, plus the mod2pi reduction is itself non-
// polynomial. INFEASIBLE BY ITERATION COMPOSITION.

// 5. SLIDE ATTACK / INVARIANT SUBSPACE:
// 1M consecutive (t1, t2) state pairs hashed: 0 collisions.
// State space ~2^104; birthday bound ~2^52. Searched linear
// combinations a*t1 + b*t2 mod 2pi: t1+t2 reflects the SRB
// measure (chi^2/N stable at 2.84e-4). This is a property of
// the chaotic source, NOT an output-level weakness -- the
// Goldilocks extractor uniformizes before output.

// SUMMARY: All five classical attack families fail to find exploitable
// structure at any level (output, raw state, iteration map). Combined
// with output-level adversarial testing and numerical/dynamical
// verification, MCL has passed cryptanalytic scrutiny
// at three distinct depths:
// - Output level
// - Internal state and map
// - Underlying dynamics

// External independent cryptanalysis remains the primary remaining gap.

// Performance characterization documented separately
// in MCL_v2_TECHNICAL_DOCUMENTATION.md (section: Performance).
// Benchmark suite: r34_performance/r34_bench_full_v2.cpp.

// Physical lower bound for K, derived from IEEE 754 arithmetic
// (independent of K_min(p,q) above; empirically determined).

// At K below ~ULP(2pi) ~= 1.4e-15, the term K*sin(x) becomes smaller than
// the ULP of t1_, t2_ (which live in [0, 2pi)). Thus K*sin(x) is rounded
// away in the iterate's addition -- K has NO effect on the trajectory,
// and the engine becomes deterministic (linear t += omega) regardless of K.

// Empirically verified for MCL_T3 with default coupling triple:
// K = 1e-300, 1e-200, 1e-100, 1e-50: produce IDENTICAL 32-byte streams
// K = 1e-15: 1 byte differs (ULP boundary)
// K = 1e-10: 25 bytes differ (K is now active)

// This silent K-disappearance is a SIDE-CHANNEL: an attacker who can
// observe the byte stream cannot tell which (very small) K was used.
// Worse, the chi^2 test passes (~217), so unit tests don't catch it.

// We set MCL_K_MIN_PHYS = 1e-12 -- three orders above the strict ULP
// threshold (safety margin) -- and apply it to T3, T4, CoupledHenon/
// Logistic/Tent. T2 and T2_Omega use the stricter K_min(p,q) =
// MCL_K_MIN_NUMERATOR/(p+q) bound.

// Default K = K_DEFAULT = 12.0 satisfies this trivially.

// ============================================================================
// EMPIRICALLY DISCOVERED RESONANCE WINDOWS -- DANGER ZONES
// ============================================================================
// A dense K sweep (step = 0.001) revealed empirical resonance windows
// (not deducible from the K_min stability bound alone). These are WARNING
// zones -- not blocked by code (would harm legitimate research), but users
// should AVOID:

// MCL_T3 default coupling (3,5;7,11;13,19), N=50K:
// DENSE FAILURE BAND: K in [0.030, 0.075] -- 15+ failures, max chi^2 ~= 5x10^5
// Sparse failures: K ~= 0.085, 0.132, 0.219, 0.353, 0.438, 0.471, 0.498,
// 0.541, 0.551, 0.574, 0.583, 0.638, 0.928, 0.937
// Recommendation: T3 K >= 1.0 is empirically clean across 200 K-values tested.

// MCL_T4 sextet 0, N=50K:
// Sparse marginal failures (chi^2 ~= 311-324) at K ~= 0.003, 0.138, 0.197, 0.444
// Recommendation: T4 K >= 0.5 is largely clean.

// CoupledLogistic (p=3, q=5), N=50K:
// DENSE FAILURE BAND: K in [0.0385, 0.0410] -- chi^2 up to 1.4x10^7
// Default LOGISTIC_K = 0.05 is OUTSIDE this window (chi^2 ~= 262 [OK]) but only
// ~15 milli-K away from the band edge. CAUTION at config time.
// Sparse failures: K ~= 0.078, 0.098, 0.160

// CoupledTent (p=3, q=5), N=50K:
// Single marginal window at K ~= 0.028 (chi^2 ~= 313); otherwise clean.

// CoupledHenon (p=3, q=5), N=50K:
// No statistical resonance windows found in the safe band [0.005, 0.015].
// Hard upper bound: K >= 0.02 -> attractor escape, divergence detection
// aborts the engine. HENON_K = 0.01 (default) is well-clear.

// Lesson: the chaos region of every engine is FRACTAL -- periodic windows
// (Feigenbaum-style) are dense at low K. The default K = 12 (T2/T3/T4) is
// chosen to be deep in the chaotic regime; the Coupled* defaults sit in
// narrow safe pockets. Use defaults unless you have a reason not to.
constexpr double MCL_K_MIN_PHYS = 1e-12;

// ============================================================================
// EMPIRICALLY-DERIVED RECOMMENDED MINIMUMS
// ============================================================================
// Design question: should a safe minimum K be set well clear of the
// resonance windows? Decision: YES -- as DOCUMENTATION, not a runtime block.

// Method: dense K sweep (step <= 0.001) per engine with default coupling,
// looking for chi^2 > 1000 (catastrophic, not statistical noise). The
// "RECOMMENDED MIN" is the smallest K above which NO catastrophic failure
// was observed up to K = 5.0 (or higher).

// These constants are FOR REFERENCE -- the runtime check uses MCL_K_MIN_PHYS
// (1e-12) which is the IEEE 754 floor. Users who pick K below
// MCL_T3_K_RECOMMENDED etc. get a working engine -- but it MAY land in a
// resonance window for their specific (p,q) or coupling. The defaults
// (K_DEFAULT = 12, HENON_K = 0.01, etc.) are above all recommendations.

// Empirical evidence behind each value:
// T3 default coupling: 32 catastrophic failures in [0.001, 0.20];
// 0 in [0.20, 2.0] (8% failure rate vs 0%)
// T4: sparse marginal only; safe above ~0.5
// CoupledLogistic: catastrophic bands at K=0.039-0.041, 0.20-0.34, 0.41,
// 1.58, 2.58-2.66, 3.70-3.75, 4.75-4.78. THIS ENGINE
// HAS NO UNIVERSAL SAFE K -- recommendation is "use the
// default LOGISTIC_K=0.05 EXACTLY, do not tune."
// CoupledTent: clean above K ~= 0.03
// CoupledHenon: bounded above by divergence (K >= 0.02 -> escape).

// IMPORTANT: these recommendations are for DEFAULT couplings / parameters.
// A different coupling triple may have its windows elsewhere. Users
// targeting non-default couplings MUST validate empirically.
constexpr double MCL_T2_K_RECOMMENDED = 6.0; // empirically window-free floor
// (v7.0.2, 2026-07-11): was 2.0 with the comment "above empirical periodic
// windows" -- FALSE: (3,5) at K=2.595 (> 2.0) still resonates (chi^2 ~3.1M,
// lambda<0). Only K >= 6.0 is confirmed window-free for the tested topologies.
constexpr double MCL_T3_K_RECOMMENDED = 0.2; // above the dense [0.03, 0.18] band
constexpr double MCL_T4_K_RECOMMENDED = 0.5; // above sparse marginal failures
constexpr double MCL_TENT_K_RECOMMENDED = 0.05; // matches TENT_K default
// CoupledLogistic intentionally has no MCL_LOGISTIC_K_RECOMMENDED:
// the engine has resonance bands across the entire (0, 5] range.
// Users MUST stick to LOGISTIC_K = 0.05 default or validate empirically.
// CoupledHenon intentionally has no MCL_HENON_K_RECOMMENDED:
// the safe band [0.005, 0.015] is so narrow that the default
// HENON_K = 0.01 IS the recommendation.

constexpr int64_t MCL_PQ_MAX = (int64_t{1} << 53); // 2^53 ~= 9.0e15 (v8.1.3; was 2^62 -- see changelog). Exact-integer bound of IEEE-754 double: (double)p*t is exact only for p <= 2^53.

// Named struct for MCL_T2 / MCL_T2_Omega construction.

// Rationale: clang-tidy's `bugprone-easily-swappable-parameters` flagged the
// existing constructors taking (uint64_t seed, int64_t p, int64_t q, double K)
// -- a user could mistakenly call MCL_T2(p, seed, q, K) and the compiler would
// silently accept it. With named-struct designated initializers (C++20) or
// explicit field assignment (C++17), the swap becomes a compile-time error.

// USAGE:
// MCL_T2_Config cfg;
// cfg.seed = 12345;
// cfg.p = 3;
// cfg.q = 5;
// cfg.K = 12.0;
// MCL_T2 eng(cfg);

// The original positional constructor is RETAINED for API compatibility with
// existing call sites (mcl_burnin_sweep_v2.cpp etc.). New code should prefer
// the named-struct API for type safety.
struct MCL_T2_Config {
    uint64_t seed;
    int64_t  p;
    int64_t  q;
    double   K = K_DEFAULT;
};

struct MCL_T2_Omega_Config {
    uint64_t seed;
    int64_t  p;
    int64_t  q;
    double   w1;
    double   w2;
    double   K = K_DEFAULT;
};

// Statistical thresholds (D2: from theory)
constexpr double BONFERRONI_ALPHA = 0.001; // 99.9% family-wise confidence

// Chi^2 critical values (df=255):
// alpha=0.01 -> 310.46 (99% confidence, stricter -- fewer false passes)
// alpha=0.001 -> 330.52 (99.9% confidence, more permissive)
// Rationale: with N channels tested, false-FAIL probability = 1-(1-alpha)^N.
// At alpha=0.01, N=6: ~5.9% false FAIL -- too high for automated regression.
// At alpha=0.001, N=6: ~0.6% false FAIL -- acceptable.
// Any data passing 310.46 automatically passes 330.52.
constexpr double CHI2_THRESHOLD = 330.52; // df=255, alpha=0.001 (default)
constexpr double CHI2_THRESHOLD_STRICT = 310.46; // df=255, alpha=0.01 (stricter)

// Spectral SNR threshold: for white noise of length N with K frequencies,
// the max spectral peak follows an extreme value distribution.
// SNR < 15 corresponds to p > 0.01 (conservative empirical bound).
// Validated by negative control in the spectral_test() self-check (sec.8).
// NOTE: spectral_test is a CLASSICAL white-noise/SNR randomness check, NOT a
// quantum-security test. For post-quantum work-factor accounting use
// mcl_pq_security() / mcl_pair_secret_bits() (sec.3.1). (The previously named
// "mcl_postquantum_verification" routine never existed in this header.)
constexpr double SPECTRAL_SNR_THRESHOLD = 15.0;

// Default seed (E6)
constexpr uint64_t DEFAULT_SEED = 12345678901234ULL;

// Multi-seed standard set (E6, D5)
inline const uint64_t* mcl_seeds() {
 static const uint64_t s[] = {
 12345678901234ULL, // Seed 0 (default)
 98765432109876ULL, // Seed 1
 31415926535897ULL, // Seed 2
 };
 return s;
}
constexpr int N_MCL_SEEDS = 3;

// Generality system parameters
constexpr double HENON_A = 1.4;
constexpr double HENON_B = 0.3;
constexpr double HENON_K = 0.01; // Small: Henon attractor basin is narrow
constexpr double LOGISTIC_R = 4.0; // Full chaos
constexpr double LOGISTIC_K = 0.05; // Coupling bounded to keep state in (0,1)
constexpr double TENT_K = 0.05;

// Frequency pool -- 12 irrational constants (E3b)
// Each from a distinct algebraic extension over Q (Kronecker independence).
// Do NOT substitute entries. sqrt5-2 deliberately excluded (dependent with phi-1).
// LITERAL-PRECISION NOTE: entries are FROZEN bit-exact AS WRITTEN. Some
// 16-digit decimals parse one ULP away from the correctly rounded double of
// the named mathematical constant; that is intentional -- all KATs and
// campaign results pin the parsed doubles, not the mathematical reals.
// BREAKING CHANGE: Field order is {name, value} -- differs from
// mcl_omega_independence v1.0.1 which used {value, name}.
// All files MUST use this definition via #include "mcl_core.hpp".
struct FreqEntry { const char* name; double value; };
inline const FreqEntry* freq_pool() {
 static const FreqEntry pool[] = {
 {"phi-1", 0.6180339887498949}, // phi - 1
 {"rho", 1.3247179572447460}, // Plastic constant (same double as OMEGA_2: 0x3FF5320B74ECA44B)
 {"sqrt2-1", 0.4142135623730950}, // sqrt2 - 1
 {"e-2", 0.7182818284590452}, // e - 2
 {"pi-3", 0.1415926535897932}, // pi - 3
 {"sqrt3-1", 0.7320508075688772}, // sqrt3 - 1
 {"sqrt11-3", 0.3166247903553998}, // sqrt11 - 3
 {"ln2", 0.6931471805599453}, // ln(2)
 {"cbrt2-1", 0.2599210498948732}, // cbrt2 - 1
 {"sqrt7-2", 0.6457513110645906}, // sqrt7 - 2
 {"ln(sqrt5)", 0.8047189562170503}, // ln(sqrt5)
 {"(1+sqrt13)/4", 1.1513878188659974}, // (1+sqrt13)/4
 };
 return pool;
}
constexpr int N_FREQ_POOL = 12;

// ============================================================================
// sec.2 TOPOLOGY / COUPLING TABLES (E5, E5b, E5c -- never modify existing entries)
// ============================================================================
// NOTE on {8,13}: INTENTIONAL, not a typo for {11,13}. It is the only entry
// with a composite p (8 and 13 are consecutive Fibonacci numbers, coprime by
// construction) and appears with identical results in every validation
// campaign since April 2026 (Lyapunov, VDF, and generality logs).

struct Topology { int64_t p, q; };

inline const Topology* t2_topos() {
 static const Topology t[] = {
 {2,3},{3,5},{5,7},{7,11},{8,13},{11,17},{13,19},{17,23},
 {19,29},{23,31},{29,37},{31,41},{37,43},{41,47},{43,53},
 {47,59},{53,61},{59,67},{61,71},{67,73}
 };
 return t;
}
constexpr int N_T2_TOPOS = 20;

struct CouplingTriple { int64_t p12,q12, p13,q13, p23,q23; };

inline const CouplingTriple* t3_triples() {
 static const CouplingTriple t[] = {
 {2,3, 3,5, 5,7}, // Triple 0 (primary)
 {3,5, 5,7, 7,11}, // Triple 1
 {5,7, 7,11, 11,13}, // Triple 2
 {7,11, 11,13, 13,17}, // Triple 3
 {2,3, 5,7, 7,11}, // Triple 4
 {3,5, 7,11, 11,13}, // Triple 5
 {2,3, 7,11, 13,17}, // Triple 6
 {5,7, 11,13, 17,23}, // Triple 7
 {2,5, 3,7, 5,11}, // Triple 8 (non-standard weights)
 {3,7, 5,11, 7,13}, // Triple 9
 {2,3, 11,17, 19,29}, // Triple 10 (wide range)
 {4,6, 6,9, 9,15}, // Triple 11 (NON-COPRIME stress test)
 };
 return t;
}
constexpr int N_T3_TRIPLES = 12;

struct CouplingSextet {
 int64_t p12,q12, p13,q13, p14,q14, p23,q23, p24,q24, p34,q34;
};

inline const CouplingSextet* t4_sextets() {
 static const CouplingSextet t[] = {
 {2,3, 3,5, 5,7, 7,11, 11,13, 13,17}, // Sextet 0 (primary)
 {3,5, 5,7, 7,11, 11,13, 13,17, 17,23}, // Sextet 1
 {2,3, 5,7, 11,13, 3,5, 7,11, 13,17}, // Sextet 2
 {5,7, 7,11, 13,17, 2,3, 11,13, 17,23}, // Sextet 3
 {2,3, 3,5, 5,7, 7,11, 13,17, 19,23}, // Sextet 4
 {7,11, 11,13, 13,17, 17,23, 23,29, 29,31}, // Sextet 5
 {4,6, 6,10, 8,14, 10,15, 14,21, 15,22}, // Sextet 6 (NON-COPRIME)
 {2,3, 7,11, 13,19, 5,7, 17,23, 11,17}, // Sextet 7
 };
 return t;
}
constexpr int N_T4_SEXTETS = 8;

// ============================================================================
// sec.3 UTILITY FUNCTIONS
// ============================================================================

// Phase reduction to [0, 2pi) -- handles negative values correctly
// Note on negative zero: mod2pi(-2kpi) = -0.0 for some k.
// IEEE 754 treats -0.0 == +0.0 numerically, but they have different bit
// patterns. This does NOT affect MCL output: the next iteration
// immediately adds omega + K.sin to t, producing a positive result and
// eliminating the sign bit (verified at -O3).
inline double mod2pi(double x) noexcept {
 x = std::fmod(x, MCL_TWO_PI);
 return x < 0.0 ? x + MCL_TWO_PI : x;
}

// IEEE 754 double -> uint64_t bit pattern (C4: always memcpy, never cast)
inline uint64_t d2b(double x) noexcept {
 uint64_t b;
 std::memcpy(&b, &x, sizeof(double));
 return b;
}

// Portable popcount (C3: no __builtin)
inline int popcount8(uint8_t x) noexcept {
 x = (uint8_t)(x - ((x >> 1) & 0x55));
 x = (uint8_t)((x & 0x33) + ((x >> 2) & 0x33));
 return (x + (x >> 4)) & 0x0F;
}

// secure_zero -- portable cryptographic memory erasure
// Required by the MCL cryptographic-erasure contract (see PATENTS.md):
// "wherein said coupled chaotic dynamical system engine performs
// cryptographic erasure of all internal dynamical state variables
// upon completion of each authentication tag computation, preventing
// recovery of intermediate state from residual memory contents."

// Implementation strategy:
// - volatile pointer prevents the compiler from removing the writes as
// dead-store optimization (a regular memset is legally elidable here
// because the object is being destroyed; volatile forces the writes).
// - asm("" ::: "memory") clobber is added on GCC/Clang as a belt-and-
// braces compiler barrier -- this prevents reordering of any memory
// access across the erasure point.
// - C23 standardizes memset_explicit() (a C primitive; no published C++
// standard provides an equivalent), so the volatile-pointer technique
// remains the portable approach for the C++17 compilation target used
// throughout this project.

// SECURITY NOTE: this erases the C++-visible state. It does NOT guarantee
// erasure of:
// - CPU register copies of the values (caller's responsibility -- function
// return discards registers naturally)
// - L1/L2/L3 cache lines (will be evicted naturally; for
// stronger guarantees use platform-
// specific cache-flush intrinsics)
// - DMA-mapped buffers (require platform-specific care)
// For HSM/TEE deployment, additional hardware-level
// erasure (e.g., ARMv8 DC ZVA, x86 CLFLUSH) should be layered on top.
inline void secure_zero(void* p, std::size_t n) noexcept {
    if (p == nullptr || n == 0) return;
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
 // Explicit counted loop: the equivalent n-- countdown wraps to SIZE_MAX
 // on its final iteration (defined behavior for unsigned arithmetic, but
 // flagged by -fsanitize=integer); the counted form is sanitizer-clean.
    for (std::size_t i = 0; i < n; ++i) {
        vp[i] = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" ::: "memory");
#endif
}

// DESIGN CONVENTION for FATAL error reporting:

// All FATAL paths in this file follow the pattern:
// std::fprintf(stderr, "FATAL: ...");
// std::abort();

// Note that std::fprintf returns int (number of characters written, or
// negative on error). We deliberately do NOT cast its return to (void)
// nor check its result, because:
// (1) Failure of stderr write does not change behavior -- std::abort()
// still terminates the process.
// (2) Casting the dozens of call sites (60 at the v7.0.0 count) to (void)
// clutters the code without improving correctness.
// (3) The static analyzer warning [cert-err33-c] flags this pattern,
// but it is a documentation/style suggestion in this context,
// not an actual defect.

// The MCL_FATAL_PRINT() helper below explicitly discards the fprintf
// return via (void); new code may prefer it over raw fprintf+abort. The
// existing call sites are NOT migrated because the change would inflate
// the diff and the convention is documented here.

// If a future refactor moves these fprintfs to non-fatal contexts, the
// (void) cast SHOULD be added, or the result checked.
#define MCL_FATAL_PRINT(...) do { (void)std::fprintf(stderr, __VA_ARGS__); } while (0)

// Buffer validation for gen_bytes() across all engines.

// Without this, gen_bytes(nullptr, 1) segfaults silently -- the caller
// gets a confusing crash with no indication that they passed a null
// pointer. With explicit validation, they get a clear error message.

// n <= 0 is not an error (no-op semantics, matches std::memcpy
// behavior). Only nullptr with n > 0 is an error.

// buf is `const uint8_t*` here because we only read it
// (specifically, we only check whether it is null). The actual buffer
// is written by gen_bytes; it's a separate operation post-validation.
inline void mcl_validate_buf(const uint8_t* buf, int64_t n) noexcept {
 if (n == 0) return; // legitimate "do nothing"
 // Negative n is a programming error (signed-vs-unsigned
 // bug at the call site). Distinguish from n=0 to make detection possible.
    if (n < 0) {
        std::fprintf(stderr, "FATAL: gen_bytes called with negative n=%lld. "
                     "Likely a signed/unsigned bug at the call site.\n",
                     (long long)n);
        std::abort();
    }
    if (buf == nullptr) {
        std::fprintf(stderr, "FATAL: gen_bytes called with nullptr buffer "
                     "(n=%lld). Allocate buffer first.\n", (long long)n);
        std::abort();
    }
 // Defensive sanity bound on n. Prevents accidental
 // huge requests (e.g., gen_bytes(buf, INT64_MAX) from misuse or
 // adversarial input) from causing unbounded execution / buffer overflow.
 // Cap at 16 GB which is well above any realistic single-call use
 // (typical: 16 bytes for auth tags, < 1 MB for stream segments).
 // Callers needing > 16 GB should chunk their request.
 constexpr int64_t MCL_GEN_BYTES_MAX = (int64_t)16 << 30; // 16 GB
    if (n > MCL_GEN_BYTES_MAX) {
        std::fprintf(stderr, "FATAL: gen_bytes called with n=%lld bytes, "
                     "exceeds defensive cap %lld bytes (16 GB). Chunk the "
                     "request if you really need this much in one call.\n",
                     (long long)n, (long long)MCL_GEN_BYTES_MAX);
        std::abort();
    }
}

// Seed hashing for seeds > 2^52 (E1: consistent across all engines)
// Prevents precision loss when converting large seeds to double.
// Seeds <= 2^52 are representable exactly in IEEE 754 double.
// NOTE: This is a distribution hash (MurmurHash3 fmix64), NOT a
// cryptographic hash. No collision resistance is needed here --
// the goal is uniform bit distribution from sequential seeds.
// SECURITY: seed=0 is fatal in both debug and release builds.
// A zero seed eliminates challenge entropy in auth protocols.
// std::abort() is used instead of assert() because assert is removed by NDEBUG.
inline uint64_t hash_seed(uint64_t seed) {
 if (seed == 0) {
 std::fprintf(stderr, "FATAL: MCL seed must be non-zero "
 "(zero seed eliminates challenge entropy)\n");
 std::abort();
 }
 if (seed > (1ULL << 52)) {
 seed = seed ^ (seed >> 33);
 seed *= 0xff51afd7ed558ccdULL; // MurmurHash3 fmix64
 seed ^= (seed >> 33);
 seed *= 0xc4ceb9fe1a85ec53ULL; // MurmurHash3 fmix64
 seed ^= (seed >> 33);
 }
 // WHY conditional on seed > 2^52:
 // The constructor computes (double)seed * OMEGA_1 to derive the initial
 // angular state. IEEE 754 double has 52-bit mantissa; seeds above 2^52
 // lose precision in the cast to double, mapping multiple input seeds to
 // the same initial state. The hash spreads such seeds before the cast.
 // For seeds in [1, 2^52], no hash is needed (cast is exact).
 // Verified: chi^2 distribution is statistically continuous across
 // the 2^52 boundary -- diff of mean chi^2 = 0.96 (well within 17.0
 // expected noise for chi^2(255)). No exploitable discontinuity.
 return seed;
}

// CRC-32 (O6: reproducibility hash) -- thread-safe, no global state
inline uint32_t compute_crc32(const uint8_t* data, size_t len) {
 static const auto table = []() {
 std::array<uint32_t, 256> t{};
 for (uint32_t i = 0; i < 256; i++) {
 uint32_t c = i;
 for (int j = 0; j < 8; j++)
 c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
 t[i] = c;
 }
 return t;
 }();
 uint32_t crc = 0xFFFFFFFF;
 for (size_t i = 0; i < len; i++)
 crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
 return crc ^ 0xFFFFFFFF;
}

// GCD computation (for topology generation and coprimality checks)
inline int64_t gcd_compute(int64_t a, int64_t b) {
 a = std::abs(a); b = std::abs(b);
 while (b) { int64_t t = b; b = a % b; a = t; }
 return a;
}

// ============================================================================
// sec.3.1 SHA-256 (FIPS 180-4) + 256-bit KEYED PARAMETER DERIVATION
// ============================================================================
// PURPOSE (post-quantum key path, added in 6.1.0):
// MCL is a SYMMETRIC primitive; its only generic quantum threat is Grover,
// which square-roots the search over the brute-forceable SECRET. The DEFAULT
// secret -- a single coprime pair (p,q) -- is only ~59 classical bits at the
// production range [2,1e9] (~30 bits post-Grover), below even NIST PQ Category 1
// (AES-128 = 64 post-Grover bits). The highest category, Category 5 (AES-256 =
// 128 post-Grover bits), needs a >=256-bit brute-forceable secret. The keyed
// paths below let the SECRET be a full 256-bit master key, expanded by a
// CRYPTOGRAPHIC KDF (SHA-256 in MGF1/counter mode) into the engine parameters
// that PERSIST through burn-in -- the coupling weights (p,q) and, for T2_Omega,
// the angular frequencies (w1,w2). Initial conditions are intentionally NOT
// used to carry secret bits: the 10^4-iteration burn-in (positive Lyapunov,
// shadowing) washes them out, so only map-defining PARAMETERS hold durable
// entropy.
//
// Grover then searches the 256-bit KEY (2^256 -> 2^128) rather than the
// parameters, PROVIDED the engine can faithfully CARRY >=256 bits of derived
// parameter entropy. T2_Omega's capacity is ~208 bits (p,q,w1,w2, each capped
// near 2^52 by the IEEE-754 mantissa / the 2^53 trajectory-collapse onset) ->
// ~104 post-Grover: meets Category 3 (AES-192 = 96) but BELOW Category 5 (128).
// T4's 12 independent weights carry >=256 bits comfortably -> the full 2^128
// post-Grover floor. Use mcl_t4_from_key() (sec.4) for NIST PQ Category 5 (the
// highest category, AES-256-equivalent).
//
// SHA-256 is a standard FIPS 180-4 primitive; this is a clean-room textbook
// implementation, self-tested against the "abc" KAT in mcl_self_test(). It is
// used ONLY by the keyed key-derivation path; the legacy seed/(p,q) engines
// and all frozen numerical KATs are unaffected.
inline void mcl_sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
 // Contract guards (v7.0.1): msg may be null ONLY when len == 0; out is
 // always required. Violations are caller bugs -> unconditional abort
 // (same policy as mcl_validate_buf; not gated by MCL_UNSAFE_ALLOW_INVALID).
 if (MCL_UNLIKELY((msg == nullptr && len > 0) || out == nullptr)) {
   std::fprintf(stderr, "FATAL: mcl_sha256 invalid arguments "
                "(msg=%p, len=%zu, out=%p)\n",
                (const void*)msg, len, (const void*)out);
   std::abort();
 }
 static const uint32_t Kc[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
 };
 uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 auto rotr = [](uint32_t x, int n) -> uint32_t { return (x >> n) | (x << (32 - n)); };
 // v7.0.0: streaming compression. Full 64-byte blocks are consumed directly
 // from the caller's buffer; only the final padded block(s) touch a stack
 // buffer, and every intermediate that can carry key material (padded tail,
 // message schedule w[], chaining state h[]) is secure_zero'd on exit. The
 // previous implementation heap-copied the whole padded message (including
 // the raw master key when called from the KDF) and freed it without
 // zeroing. The digest is byte-identical (same FIPS 180-4 algorithm).
 uint32_t w[64];
 auto compress = [&](const uint8_t* blk) {
   for (int i = 0; i < 16; i++)
     w[i] = ((uint32_t)blk[4*i]   << 24) | ((uint32_t)blk[4*i+1] << 16)
          | ((uint32_t)blk[4*i+2] <<  8) |  (uint32_t)blk[4*i+3];
   for (int i = 16; i < 64; i++) {
     uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
     uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
     w[i] = w[i-16] + s0 + w[i-7] + s1;
   }
   uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
   for (int i = 0; i < 64; i++) {
     uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
     uint32_t ch = (e & f) ^ (~e & g);
     uint32_t t1 = hh + S1 + ch + Kc[i] + w[i];
     uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
     uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
     uint32_t t2 = S0 + maj;
     hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
   }
   h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
 };
 size_t off = 0;
 for (; off + 64 <= len; off += 64) compress(msg + off);
 // FIPS 180-4 padding for the final partial block, built on the stack:
 // 0x80, zero fill, 64-bit big-endian bit length. rem <= 63, so the padded
 // tail is exactly one block (rem <= 55) or two blocks (rem >= 56).
 uint8_t tail[128];
 size_t rem = len - off;
 if (rem) std::memcpy(tail, msg + off, rem);
 tail[rem] = 0x80;
 size_t tlen = (rem <= 55) ? 64 : 128;
 for (size_t i = rem + 1; i < tlen - 8; i++) tail[i] = 0;
 uint64_t bitlen = (uint64_t)len * 8;
 for (int i = 0; i < 8; i++)
   tail[tlen - 1 - (size_t)i] = (uint8_t)(bitlen >> (i * 8));
 for (size_t o = 0; o < tlen; o += 64) compress(tail + o);
 for (int i = 0; i < 8; i++) {
   out[4*i]   = (uint8_t)(h[i] >> 24);
   out[4*i+1] = (uint8_t)(h[i] >> 16);
   out[4*i+2] = (uint8_t)(h[i] >>  8);
   out[4*i+3] = (uint8_t)(h[i]);
 }
 secure_zero(tail, sizeof(tail));
 secure_zero(w, sizeof(w));
 secure_zero(h, sizeof(h)); // digest already copied to out
}

// MGF1/counter-mode XOF over a 256-bit key with a domain-separation label and
// optional public "info" (e.g. an auth challenge -- binds it cryptographically):
//   block_i = SHA-256( key[32] || label || info || be32(i) )
//   output  = block_0 || block_1 || ...
// Standard mask-generation construction (PKCS#1 MGF1 shape). Each block hashes a
// distinct fixed-length preimage, so it is not length-extendable for this use.
inline void mcl_kdf256(const uint8_t key[32], const char* label,
                       const uint8_t* info, size_t infolen,
                       uint8_t* out, size_t outlen) {
 // Contract guards (v7.0.1): key and label must be non-null (strlen on a
 // null label is UB); info may be null only when infolen == 0; out may be
 // null only when outlen == 0. Caller bugs -> unconditional abort.
 if (MCL_UNLIKELY(key == nullptr || label == nullptr
                  || (info == nullptr && infolen > 0)
                  || (out == nullptr && outlen > 0))) {
   std::fprintf(stderr, "FATAL: mcl_kdf256 invalid arguments "
                "(key=%p, label=%p, info=%p infolen=%zu, out=%p outlen=%zu)\n",
                (const void*)key, (const void*)label,
                (const void*)info, infolen, (const void*)out, outlen);
   std::abort();
 }
 size_t lab = std::strlen(label);
 // v7.0.2 (F4): cap label/info lengths so 'total' below cannot wrap size_t
 // (a wrapped total under-allocates, then the memcpy writes wild). 1 MiB each
 // is astronomically above any legitimate KDF input; mirrors mcl_validate_buf.
 constexpr size_t MCL_KDF_MAX_LEN = 1u << 20; // 1 MiB
 if (MCL_UNLIKELY(lab > MCL_KDF_MAX_LEN || infolen > MCL_KDF_MAX_LEN)) {
   std::fprintf(stderr, "FATAL: mcl_kdf256 input too large "
                "(lab=%zu, infolen=%zu, max=%zu)\n",
                lab, infolen, (size_t)MCL_KDF_MAX_LEN);
   std::abort();
 }
 const size_t total = 32 + lab + infolen + 4;
 // v7.0.0: the preimage buffer holds the RAW MASTER KEY, so it lives on the
 // stack for every in-file use (labels <= 16 B, info = 8 B) with a heap
 // fallback only for oversized caller-supplied label/info; both paths are
 // secure_zero'd before return (previously a heap vector freed unzeroed).
 uint8_t stack_in[160];
 std::vector<uint8_t> heap_in;
 uint8_t* in = stack_in;
 if (total > sizeof(stack_in)) { heap_in.resize(total); in = heap_in.data(); }
 std::memcpy(in, key, 32);
 if (lab) std::memcpy(in + 32, label, lab);
 if (infolen) std::memcpy(in + 32 + lab, info, infolen);
 size_t cpos = 32 + lab + infolen;
 uint32_t counter = 0;
 size_t produced = 0;
 uint8_t block[32] = {};
 while (produced < outlen) {
   in[cpos + 0] = (uint8_t)(counter >> 24);
   in[cpos + 1] = (uint8_t)(counter >> 16);
   in[cpos + 2] = (uint8_t)(counter >>  8);
   in[cpos + 3] = (uint8_t)(counter);
   mcl_sha256(in, total, block);
   size_t take = std::min((size_t)32, outlen - produced);
   std::memcpy(out + produced, block, take);
   produced += take;
   counter++;
 }
 secure_zero(block, sizeof(block));
 secure_zero(in, total); // erase the key-bearing preimage (stack or heap)
}

// Post-quantum security accounting (replaces the informal "Grover sqrt on seed"
// note). Given the number of independent secret bits that actually reach the
// persistent engine parameters, report the post-Grover work factor and the NIST
// PQ category reached. NIST anchors Categories 1/3/5 to exhaustive key search on
// AES-128/192/256, i.e. >=64/96/128 post-Grover bits respectively (Category 5 is
// the highest). A 256-bit symmetric key => 128 post-Grover => Category 5 (the
// quantum cost equals AES-256's, NOT a 128-bit cipher's classical cost; the
// earlier "Level 1" label conflated those and was wrong by four categories).
// This is a quantitative quantum-cost helper; it does NOT certify against
// structural cryptanalysis.
struct MCL_PQReport {
 double secret_bits;       // brute-forceable classical secret bits
 double post_grover_bits;  // = secret_bits / 2  (Grover quadratic speedup)
 bool   meets_category1;   // post_grover_bits >= 64   (AES-128 equivalent)
 bool   meets_category3;   // post_grover_bits >= 96   (AES-192 equivalent)
 bool   meets_category5;   // post_grover_bits >= 128  (AES-256 equiv., highest)
};
inline MCL_PQReport mcl_pq_security(double secret_bits) {
 MCL_PQReport r;
 r.secret_bits = secret_bits;
 r.post_grover_bits = secret_bits * 0.5;
 r.meets_category1 = (r.post_grover_bits >= 64.0);
 r.meets_category3 = (r.post_grover_bits >= 96.0);
 r.meets_category5 = (r.post_grover_bits >= 128.0);
 return r;
}
// Classical secret bits of a single coprime (p,q) pair from [2, max_val]
// (ordered, density 6/pi^2) -- the DEFAULT (non-keyed) auth secret. Even
// max_val=1e18 gives only ~119 bits -> ~59 post-Grover (below even Category 1).
inline double mcl_pair_secret_bits(double max_val) {
 if (max_val <= 2.0) return 0.0;
 double pairs = (6.0 / (MCL_PI * MCL_PI)) * (max_val - 1.0) * (max_val - 1.0);
 return std::log2(pairs);
}

// Output section separator
inline void sep(const char* title) {
 std::printf("\n==============================================================================\n");
 std::printf(" %s\n", title);
 std::printf("==============================================================================\n\n");
}

// ============================================================================
// sec.4 ENGINES -- Phase Oscillators on T^n

// ALL engines use:
// - hash_seed() for seed > 2^52 (prevents IEEE 754 precision loss)
// - Gauss-Seidel sequential update (source of chaos -- lambda_1 = 5.78)
// - Goldilocks dual-zone extraction (bits 20-27 XOR 36-43 of XOR)
// - Decimation D=2
// - Burn-in = 10000

// THREAD SAFETY: Each engine instance must be used by a single
// thread. For multi-threaded use, create one instance per thread.
// The engine contains no internal synchronization (same as std::mt19937).

// Concurrent operations that ARE undefined behavior:
// - Two threads calling iterate() / gen_bytes() on the same engine
// - One thread calling gen_bytes() while another calls erase() / dtor / move
// - Two threads sharing an engine across read+write boundaries
// All such uses are detected by ThreadSanitizer (verified).

// Concurrent operations that ARE safe:
// - Multiple threads reading freq_pool() / t4_sextets() (immutable globals)
// - Multiple threads each holding their own engine instance
// - Static stat utilities (chi_square, shannon_entropy, popcount) on
// independent buffers
// ============================================================================

// ---------- MCL_T2: Two-Oscillator (Primary) ----------

// Coupled oscillator equations:
// theta_1(t+1) = [theta_1(t) + omega_1 + K.sin(p.theta_2(t) - q.theta_1(t))] mod 2pi
// theta_2(t+1) = [theta_2(t) + omega_2 + K.sin(p.theta_1(t+1) - q.theta_2(t))] mod 2pi
// ^^^^^ Gauss-Seidel: uses t+1
class MCL_T2 {
 double t1_, t2_;
 int64_t p_, q_;
 double kc_;
public:
 // Named-struct constructor -- type-safe alternative to
 // the positional constructor below. Delegates to the positional ctor.
 explicit MCL_T2(const MCL_T2_Config& cfg)
   : MCL_T2(cfg.seed, cfg.p, cfg.q, cfg.K) {}
 MCL_T2(uint64_t seed, int64_t p, int64_t q, double kc = K_DEFAULT)
 : p_(p), q_(q), kc_(kc)
 {
 assert(seed != 0 && "Seed must be non-zero");
 // Parameter contract (checked below; asserts live inside the
 // MCL_UNSAFE_ALLOW_INVALID guard together with the runtime checks):
 // The lower bound is a numerical / dynamical contract: p=1 produces
 // output that LOOKS uniform but is theoretically degenerate (reduced
 // state-space exploration). Block at the boundary.
 // Upper bound: 2 <= p, q <= 2^53 (v8.1.3). Beyond 2^53, the (double)p*t cast
 // loses precision (53-bit significand) and would produce deterministic output
 // that LOOKS statistically random but lies outside the operating regime.
 // K_min(p,q) = MCL_K_MIN_NUMERATOR/(p+q) — see derivation block above.
 // Below K_min, lambda_max < 0 and the system enters a non-chaotic regime.
 // Output may LOOK uniform statistically but is theoretically predictable.
 // This is the dynamical contract, distinct from K > 0 (numerical contract).

 // CAVEAT -- K_min is NECESSARY, not SUFFICIENT.
 // Empirical sweep shows that even K > K_min has occasional "periodic
 // windows" (Feigenbaum stability windows in chaotic systems). For
 // (p=3, q=5), a dense K sweep shows several K values where chi^2 > 10^7
 // (extremely degenerate output) interspersed with passing values. These
 // windows PERSIST WELL ABOVE K = 2.0 and above K_min for some topologies:
 // verified for (3,5) at K~1.22/2.60 (resonance, lambda<0) and K~3.79/5.73
 // (quasi-periodic, lambda~0), and for (2,3) across K~1.28-2.08. K >=
 // MCL_K_RECOMMENDED_FLOOR (6.0) is the empirically window-free advisory range
 // for the tested topology set; the default K = 12.0 is the validated
 // safe-for-all-tested value. (Supersedes the earlier "above K=2.0 almost all
 // uniform" note, which the 2.595/3.79/5.73 windows falsify; consistent with
 // the K-domain notes above and MCL_K_RECOMMENDED_FLOOR.)

 // This check enforces the LOWER bound (no negative-Lyapunov regime)
 // but does NOT guarantee chaos at every K above K_min. Users requiring
 // empirical chaos verification should run statistical tests on their
 // chosen K. The K_DEFAULT (12.0) is empirically validated.
 //
 // v5.0.0 moved the K_min assert INSIDE the MCL_UNSAFE_ALLOW_INVALID
 // guard; v7.0.0 moved the remaining p/q/K asserts inside as well, so a
 // debug build with -DMCL_UNSAFE_ALLOW_INVALID is fully permissive
 // (research mode) while default builds keep every check. K-sweep
 // verifiers (mcl_k_sweep_unified) require K below K_min(p,q) by design
 // and work with the standard MCL_UNSAFE_ALLOW_INVALID flag alone.
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(p >= 2 && q >= 2 && "coupling weights must be >= 2");
 assert(p <= MCL_PQ_MAX && q <= MCL_PQ_MAX && "p, q must be <= 2^53");
 assert(p != q && "p and q must be distinct");
 assert(std::isfinite(kc) && kc > 0.0 && "K must be finite and > 0");
 const double K_min_pq = MCL_K_MIN_NUMERATOR / ((double)p + (double)q); // avoid int64_t addition near INT64_MAX
 assert(kc >= K_min_pq
   && "K must be >= K_min(p,q) = MCL_K_MIN_NUMERATOR/(p+q) for chaotic regime");
 if (p < 2 || q < 2 || p > MCL_PQ_MAX || q > MCL_PQ_MAX || p == q) {
 std::fprintf(stderr, "FATAL: MCL_T2 invalid coupling weights "
 "(p=%lld, q=%lld). Required: 2 <= p,q <= 2^53, p != q.\n",
 (long long)p, (long long)q);
 std::abort();
 }
 if (!std::isfinite(kc) || kc <= 0.0) {
 std::fprintf(stderr, "FATAL: MCL_T2 invalid K (=%.17g). "
 "Must be finite and > 0.\n", kc);
 std::abort();
 }
 // runtime guard: K below K_min(p,q) = MCL_K_MIN_NUMERATOR/(p+q) is
 // non-chaotic (lambda_max < 0). Aborts even in NDEBUG.
 // Error message also notes the caveat: K_min is
 // necessary but not sufficient. User who picks K = K_min * 1.05 may pass
 // this sentinel but get statistically degenerate output for some (p,q).
 if (kc < K_min_pq) {
 std::fprintf(stderr, "FATAL: MCL_T2 K=%.6g below K_min=%.6g for "
 "(p=%lld, q=%lld). Below K_min, lambda_max < 0 and system "
 "is non-chaotic. NOTE: K_min is necessary "
 "but NOT sufficient -- narrow periodic windows persist above "
 "K_min for some topologies. Use K >= "
 "MCL_K_RECOMMENDED_FLOOR (6.0) for cryptographic safety, or "
 "K = K_DEFAULT (12) for the default setting.\n",
 kc, K_min_pq, (long long)p, (long long)q);
 std::abort();
 }
#endif
 uint64_t s = hash_seed(seed);
 t1_ = mod2pi((double)s * OMEGA_1);
 t2_ = mod2pi((double)s * OMEGA_2);
 for (int i = 0; i < BURNIN; i++) iterate();
 // numerical guard after burn-in (debug builds only)
 assert(std::isfinite(t1_) && std::isfinite(t2_) && "T2 diverged in burn-in");
 }

 // Destructor: cryptographic erasure of internal state, per the erasure
 // contract ("performs cryptographic erasure of all internal dynamical
 // state variables upon completion").
 // Note: this fires on scope exit, exception unwind, and explicit delete.
 ~MCL_T2() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&kc_, sizeof(kc_));
 // p_, q_ are device identity (not chaotic state); erasure of identity
 // is a separate policy decision left to the caller -- see erase_identity().
 }

 // Explicit cryptographic erasure for post-tag-computation cleanup.

 // CRITICAL: erase() MUST zero kc_ so that any
 // subsequent gen_byte() call triggers the sentinel and aborts.
 // Without this, two engines with same (p, q, K) but different seeds
 // produce IDENTICAL bytes after erase() -- a complete identity collapse.

 // Per the erasure contract ("upon completion of each authentication
 // tag computation"), erase() is FINAL. The engine must not be reused.
 // Re-use requires constructing a fresh engine with a new seed.
 void erase() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&kc_, sizeof(kc_)); // zero kc_ -> sentinel fires
 }

 // Full erasure including device-identity coupling parameters.
 // Use only when discarding the entire engine identity (e.g., on
 // device decommission).
 // erase_identity audit: erase() already zeros kc_, t1_, t2_;
 // here we add the identity parameters (p, q). Avoids redundant zero of kc_.
 void erase_identity() noexcept {
 erase();
 secure_zero(&p_, sizeof(p_));
 secure_zero(&q_, sizeof(q_));
 }

 // Make the engine non-copyable to prevent accidental state
 // duplication. Copy of an engine instance would create a second copy
 // of the secret state in memory, defeating erase semantics.

 // Custom move (NOT default).
 // Defaulted memberwise move on trivial types is just a copy -- it leaves
 // the source object's secret state intact until that source's destructor
 // fires. For strict compliance, the move-from object
 // must be erased *immediately* upon move, not deferred to its destructor.
 // We therefore explicitly erase the source after copying its values.
 MCL_T2(const MCL_T2&) = delete;
 MCL_T2& operator=(const MCL_T2&) = delete;

 MCL_T2(MCL_T2&& other) noexcept
   : t1_(other.t1_), t2_(other.t2_),
     p_(other.p_),  q_(other.q_),  kc_(other.kc_) {
 // Erase the source's secret state immediately. p_ and q_ stay
 // (they're identity, not state) but t1_, t2_, kc_ are erased.
   secure_zero(&other.t1_, sizeof(other.t1_));
   secure_zero(&other.t2_, sizeof(other.t2_));
   secure_zero(&other.kc_, sizeof(other.kc_));
 }

 MCL_T2& operator=(MCL_T2&& other) noexcept {
   if (this != &other) {
 // Erase our own state first, then absorb other's, then erase other's.
     secure_zero(&t1_, sizeof(t1_));
     secure_zero(&t2_, sizeof(t2_));
     secure_zero(&kc_, sizeof(kc_));
     t1_ = other.t1_;  t2_ = other.t2_;
     p_  = other.p_;   q_  = other.q_;
     kc_ = other.kc_;
     secure_zero(&other.t1_, sizeof(other.t1_));
     secure_zero(&other.t2_, sizeof(other.t2_));
     secure_zero(&other.kc_, sizeof(other.kc_));
   }
   return *this;
 }

 // After move, kc_ is zeroed. K=0 produces a linear
 // (non-chaotic) iteration that LOOKS random in chi^2 for small samples but
 // is fully deterministic. To prevent this fail-quiet hazard, gen_byte()
 // and iterate() check for the moved-from sentinel (kc_ == 0) and abort.

 // Why kc_ == 0 specifically: K=0 is forbidden by the parameter contract
 // (K must be positive and >= K_min), so it cannot occur via legitimate
 // construction. After move, kc_ is explicitly secure_zero'd, making it
 // a reliable sentinel.

 // The check is wrapped in #if !defined(MCL_UNSAFE_ALLOW_INVALID) because
 // negative-control test code may legitimately want to construct with K=0
 // (and accept the determinism that follows).

 void iterate() {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 if (MCL_UNLIKELY(kc_ == 0.0)) {
 std::fprintf(stderr, "FATAL: MCL_T2::iterate() called on moved-from, "
   "erased, or invalid instance (kc_ = 0)\n");
 std::abort();
 }
#endif
 double a1 = (double)p_ * t2_ - (double)q_ * t1_;
 t1_ = mod2pi(t1_ + OMEGA_1 + kc_ * std::sin(a1));
 double a2 = (double)p_ * t1_ - (double)q_ * t2_;
 t2_ = mod2pi(t2_ + OMEGA_2 + kc_ * std::sin(a2));
 }

 // [[nodiscard]] -- calling gen_byte() and discarding the result
 // wastes a byte AND advances internal state, almost always a bug.
 [[nodiscard]] uint8_t gen_byte() {
 // Note: iterate() below performs the kc_==0 sentinel check, so we
 // don't duplicate it here. The check happens within the first iterate()
 // call, before any state mutation.
 for (int d = 0; d < DECIMATION; d++) iterate();
 uint64_t x = d2b(t1_) ^ d2b(t2_);
 return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
 }

 void gen_bytes(uint8_t* buf, int64_t n) {
 mcl_validate_buf(buf, n); // nullptr check
 for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
 }

 // State accessors (for Lyapunov, diagnostics)
 double theta1() const { return t1_; }
 double theta2() const { return t2_; }

 // Dynamic parameter hopping: change (p,q) mid-stream, preserve state
 void hop(int64_t new_p, int64_t new_q, int warmup = 50) {
 // hop() validates the FULL contract for the NEW (p,q): lower bound,
 // upper bound (PQ_MAX), distinctness, and K_min validity under the
 // EXISTING K. Without the K_min check, hop() could silently move the
 // engine into a non-chaotic region. All checks live inside the
 // MCL_UNSAFE_ALLOW_INVALID guard (see the ctor for the rationale).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(new_p >= 2 && new_q >= 2 && new_p != new_q
   && "hop: p,q must be >= 2 and distinct");
 assert(new_p <= MCL_PQ_MAX && new_q <= MCL_PQ_MAX
   && "hop: p, q must be <= 2^53");
 const double new_K_min = MCL_K_MIN_NUMERATOR / ((double)new_p + (double)new_q);
 assert(kc_ >= new_K_min
   && "hop: existing K is below K_min for new (p,q) -- non-chaotic regime");
 if (new_p < 2 || new_q < 2 || new_p > MCL_PQ_MAX || new_q > MCL_PQ_MAX
     || new_p == new_q) {
 std::fprintf(stderr, "FATAL: MCL_T2::hop invalid weights "
   "(new_p=%lld, new_q=%lld). Required: 2 <= p,q <= 2^53, p != q.\n",
   (long long)new_p, (long long)new_q);
 std::abort();
 }
 if (kc_ < new_K_min) {
 std::fprintf(stderr, "FATAL: MCL_T2::hop existing K=%.6g below K_min=%.6g "
   "for new (p=%lld, q=%lld). Hop would enter non-chaotic regime.\n",
   kc_, new_K_min, (long long)new_p, (long long)new_q);
 std::abort();
 }
#endif
 p_ = new_p; q_ = new_q;
 for (int i = 0; i < warmup; i++) iterate();
 }

 // Parameter accessors (for parameter-space analysis and diagnostics).
 // [[nodiscard]] + is_invalid provide API uniformity across the 7 engines.
 [[nodiscard]] int64_t get_p() const noexcept { return p_; }
 [[nodiscard]] int64_t get_q() const noexcept { return q_; }
 [[nodiscard]] bool is_invalid() const noexcept { return kc_ == 0.0; }
};

// ---------- MCL_T2_Omega: Variable Angular Frequency ----------

// Standard MCL_T2 with omega_1, omega_2 as parameters instead of constants.
// Reproduces MCL_T2 when omega1=phi-1, omega2=rho.

// DESIGN NOTE: No hop() method. MCL_T2_Omega is designed for
// frequency-independence analysis (mcl_omega_independence EXP 12),
// not production use. For dynamic parameter hopping with forward
// secrecy, use MCL_T2 with the default
// omega values. Adding hop() here would require deciding whether hopping
// changes omega as well as (p,q) -- a design question outside the current
// experimental scope.
class MCL_T2_Omega {
 double t1_, t2_;
 int64_t p_, q_;
 double kc_, w1_, w2_;
public:
 // Named-struct constructor -- type-safe alternative.
 explicit MCL_T2_Omega(const MCL_T2_Omega_Config& cfg)
   : MCL_T2_Omega(cfg.seed, cfg.p, cfg.q, cfg.w1, cfg.w2, cfg.K) {}

 MCL_T2_Omega(uint64_t seed, int64_t p, int64_t q,
 double w1, double w2, double kc = K_DEFAULT)
 : p_(p), q_(q), kc_(kc), w1_(w1), w2_(w2)
 {
 assert(seed != 0 && "Seed must be non-zero");
 // w1 != w2 (broken-symmetry requirement):
 // w1 == w2 makes the two oscillators governed by an identical equation
 // (both flux invariants identical), losing the distinguishing dynamical
 // property. Output may look uniform but lies outside the operating regime.
 // All parameter asserts live INSIDE the MCL_UNSAFE_ALLOW_INVALID guard
 // (v7.0.0; see the MCL_T2 ctor for the rationale).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(p >= 2 && q >= 2 && p != q && "coupling weights p,q must be >= 2, distinct");
 assert(p <= MCL_PQ_MAX && q <= MCL_PQ_MAX && "p, q must be <= 2^53");
 assert(std::isfinite(kc) && kc > 0.0 && "K must be finite and > 0");
 assert(std::isfinite(w1) && std::isfinite(w2) && "w1, w2 must be finite");
 assert(w1 != w2 && "w1 != w2 (broken symmetry required)");
 // K_min(p,q) = MCL_K_MIN_NUMERATOR/(p+q) — chaos threshold
 const double K_min_pq = MCL_K_MIN_NUMERATOR / ((double)p + (double)q);
 assert(kc >= K_min_pq && "K must be >= K_min(p,q) = MCL_K_MIN_NUMERATOR/(p+q)");
 if (p < 2 || q < 2 || p > MCL_PQ_MAX || q > MCL_PQ_MAX || p == q) {
 std::fprintf(stderr, "FATAL: MCL_T2_Omega invalid coupling weights "
 "(p=%lld, q=%lld). Required: 2 <= p,q <= 2^53, p != q.\n",
 (long long)p, (long long)q);
 std::abort();
 }
 if (w1 == w2) {
 std::fprintf(stderr, "FATAL: MCL_T2_Omega w1 == w2 (=%.17g). "
 "w1 != w2 required (broken symmetry).\n", w1);
 std::abort();
 }
 // Order matters: validate finite/positive K BEFORE
 // comparing to K_min. Otherwise NaN K silently passes (NaN < anything = false)
 // and negative K produces a misleading "below K_min" message instead of
 // "K must be > 0".
 if (!std::isfinite(kc) || kc <= 0.0) {
 std::fprintf(stderr, "FATAL: MCL_T2_Omega invalid K (=%.17g). "
 "Must be finite and > 0.\n", kc);
 std::abort();
 }
 if (!std::isfinite(w1) || !std::isfinite(w2)) {
 std::fprintf(stderr, "FATAL: MCL_T2_Omega invalid w1=%.17g, w2=%.17g. "
 "Must be finite.\n", w1, w2);
 std::abort();
 }
 if (kc < K_min_pq) {
 std::fprintf(stderr, "FATAL: MCL_T2_Omega K=%.6g below K_min=%.6g for "
 "(p=%lld, q=%lld). Non-chaotic regime (lambda_max < 0).\n",
 kc, K_min_pq, (long long)p, (long long)q);
 std::abort();
 }
#endif
 uint64_t s = hash_seed(seed);
 // NOTE: seed init uses custom w1_/w2_ (not fixed OMEGA_1/2).
 // This means changing omega affects both initial conditions AND dynamics.
 // After 10K burn-in the trajectory converges to the chaotic attractor
 // regardless of initial conditions, so no practical impact on results.
 t1_ = mod2pi((double)s * w1_);
 t2_ = mod2pi((double)s * w2_);
 for (int i = 0; i < BURNIN; i++) iterate();
 assert(std::isfinite(t1_) && std::isfinite(t2_) && "T2_Omega diverged in burn-in");
 }
 void iterate() {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 if (MCL_UNLIKELY(kc_ == 0.0)) {
 std::fprintf(stderr, "FATAL: MCL_T2_Omega::iterate() on moved-from/invalid (kc_=0)\n");
 std::abort();
 }
#endif
 double a1 = (double)p_ * t2_ - (double)q_ * t1_;
 t1_ = mod2pi(t1_ + w1_ + kc_ * std::sin(a1));
 double a2 = (double)p_ * t1_ - (double)q_ * t2_;
 t2_ = mod2pi(t2_ + w2_ + kc_ * std::sin(a2));
 }
 [[nodiscard]] uint8_t gen_byte() {
 for (int d = 0; d < DECIMATION; d++) iterate();
 uint64_t x = d2b(t1_) ^ d2b(t2_);
 return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
 }
 void gen_bytes(uint8_t* buf, int64_t n) {
 mcl_validate_buf(buf, n); // nullptr check
 for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
 }

 // cryptographic erasure
 ~MCL_T2_Omega() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&kc_, sizeof(kc_));
 secure_zero(&w1_, sizeof(w1_));
 secure_zero(&w2_, sizeof(w2_));
 }
 void erase() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&kc_, sizeof(kc_)); // sentinel fire
 }
 // erase_identity for T2_Omega -- full decommission.
 // Note: includes w1, w2 (custom omega -- also part of identity).
 // erase() covers kc_.
 void erase_identity() noexcept {
 erase();
 secure_zero(&p_, sizeof(p_));
 secure_zero(&q_, sizeof(q_));
 secure_zero(&w1_, sizeof(w1_));
 secure_zero(&w2_, sizeof(w2_));
 }
 // Custom move erases source -- see MCL_T2 comments.
 MCL_T2_Omega(const MCL_T2_Omega&) = delete;
 MCL_T2_Omega& operator=(const MCL_T2_Omega&) = delete;
 MCL_T2_Omega(MCL_T2_Omega&& o) noexcept
   : t1_(o.t1_), t2_(o.t2_), p_(o.p_), q_(o.q_),
     kc_(o.kc_), w1_(o.w1_), w2_(o.w2_) {
   secure_zero(&o.t1_, sizeof(o.t1_));
   secure_zero(&o.t2_, sizeof(o.t2_));
   secure_zero(&o.kc_, sizeof(o.kc_));
   secure_zero(&o.w1_, sizeof(o.w1_));
   secure_zero(&o.w2_, sizeof(o.w2_));
 }
 MCL_T2_Omega& operator=(MCL_T2_Omega&& o) noexcept {
   if (this != &o) {
     secure_zero(&t1_, sizeof(t1_));
     secure_zero(&t2_, sizeof(t2_));
     secure_zero(&kc_, sizeof(kc_));
     t1_ = o.t1_; t2_ = o.t2_; p_ = o.p_; q_ = o.q_;
     kc_ = o.kc_; w1_ = o.w1_; w2_ = o.w2_;
     secure_zero(&o.t1_, sizeof(o.t1_));
     secure_zero(&o.t2_, sizeof(o.t2_));
     secure_zero(&o.kc_, sizeof(o.kc_));
     // w1_/w2_ are key-derived secrets on the keyed path: erase them from
     // the source exactly as the move CONSTRUCTOR does (v7.0.0 parity fix).
     secure_zero(&o.w1_, sizeof(o.w1_));
     secure_zero(&o.w2_, sizeof(o.w2_));
   }
   return *this;
 }

 // API uniformity additions (backward-compatible).
 [[nodiscard]] int64_t get_p() const noexcept { return p_; }
 [[nodiscard]] int64_t get_q() const noexcept { return q_; }
 [[nodiscard]] double get_w1() const noexcept { return w1_; }
 [[nodiscard]] double get_w2() const noexcept { return w2_; }
 [[nodiscard]] bool is_invalid() const noexcept { return kc_ == 0.0; }
};

// ============================================================================
// 256-bit KEYED CONSTRUCTION (post-quantum key path) -- MCL_T2_Omega
// ============================================================================
// Derives (p, q, w1, w2) from a 256-bit master key via the SHA-256 KDF (sec.3.1),
// so the brute-forceable SECRET is the 256-bit key, expanded into parameters
// that PERSIST through burn-in. K is fixed at K_DEFAULT (deriving K adds little
// entropy and risks the K_min boundary). Carried entropy:
//   p,q   each in [2, 2^52)  -> ~52 bits each (below the 2^53 collapse onset)
//   w1,w2 each a 53-bit mantissa fraction in (0, 1]
// raw span 52+52+53+53 ~= 210 bits; all security accounting uses the
// CONSERVATIVE floor ~208 classical bits -> ~104 post-Grover (the figure
// carried in the papers). This is a ~74-bit improvement
// over the default single-(p,q) auth secret (~30 post-Grover); it meets NIST
// Category 3 (AES-192 = 96 post-Grover) but is BELOW Category 5 (AES-256 = 128),
// because T2's parameter CAPACITY (~208 bits) cannot hold a full 256-bit secret.
// For Category 5 (the highest) use mcl_t4_from_key() below.
//
// `challenge` is an optional PUBLIC value (e.g. an auth nonce) bound into the
// derivation cryptographically; the secret is the key alone.
struct MCL_KeyedParamsT2 { int64_t p, q; double w1, w2; double K; };

inline MCL_KeyedParamsT2 mcl_t2_params_from_key(const uint8_t key[32],
                                                uint64_t challenge = 0) {
 uint8_t info[8];
 for (int i = 0; i < 8; i++) info[i] = (uint8_t)(challenge >> (i * 8));
 uint8_t kd[32];
 mcl_kdf256(key, "MCL-T2-Omega-v1", info, sizeof(info), kd, sizeof(kd));
 auto le64 = [](const uint8_t* b) -> uint64_t {
   uint64_t v = 0;
   for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (i * 8);
   return v;
 };
 const int64_t PQ_RANGE = (int64_t)((1ULL << 52) - 2); // p,q in [2, 2^52)
 // Modulo reduction of a 64-bit lane into PQ_RANGE carries a relative bias
 // of ~2^-12 (entropy loss < 0.001 bit per lane) -- negligible; documented
 // for adversarial review rather than "fixed" with rejection sampling,
 // which would break the frozen keyed KATs.
 int64_t p = 2 + (int64_t)(le64(kd +  0) % (uint64_t)PQ_RANGE);
 int64_t q = 2 + (int64_t)(le64(kd +  8) % (uint64_t)PQ_RANGE);
 if (q == p) q = 2 + ((q - 2 + 1) % PQ_RANGE);
 // make (p,q) coprime by bumping q (preserves ~full entropy; stays in range)
 while (gcd_compute(p, q) != 1) {
   q = 2 + ((q - 2 + 1) % PQ_RANGE);
   if (q == p) q = 2 + ((q - 2 + 1) % PQ_RANGE);
 }
 // w1,w2 in (0, 1]: 53-bit fraction from the high bits. The +1 avoids exact
 // 0; the upper boundary 1.0 is reachable with probability 2^-53 per lane
 // and is a valid angular frequency (finite, nonzero).
 double w1 = (double)((le64(kd + 16) >> 11) + 1) * (1.0 / 9007199254740992.0);
 double w2 = (double)((le64(kd + 24) >> 11) + 1) * (1.0 / 9007199254740992.0);
 if (w1 == w2) w2 = w1 * 0.5 + 0.25; // broken symmetry (astronomically rare)
 if (w1 == w2) w2 = 0.75; // remap fixed point (w1 == 0.5 exactly): force distinct
 MCL_KeyedParamsT2 out{p, q, w1, w2, K_DEFAULT};
 secure_zero(kd, sizeof(kd)); // erase the key-derived KDF lanes
 secure_zero(&p,  sizeof(p));  secure_zero(&q,  sizeof(q));   // erase the
 secure_zero(&w1, sizeof(w1)); secure_zero(&w2, sizeof(w2));  // local copies
 return out;
}

// Convenience factory: a burned-in MCL_T2_Omega keyed by a 256-bit master key.
// `seed` is a PUBLIC salt for the initial state (washed out by burn-in); the
// secret is `key`. Returns by move (MCL_T2_Omega is movable, non-copyable).
inline MCL_T2_Omega mcl_t2_from_key(const uint8_t key[32],
                                    uint64_t challenge = 0,
                                    uint64_t seed = DEFAULT_SEED) {
 MCL_KeyedParamsT2 kp = mcl_t2_params_from_key(key, challenge);
 MCL_T2_Omega eng(seed, kp.p, kp.q, kp.w1, kp.w2, kp.K);
 secure_zero(&kp, sizeof(kp)); // erase the key-derived parameter copy
 return eng;
}

// ---------- MCL_T3: Three-Oscillator Extension ----------

// E2b: theta_1 -> theta_2 -> theta_3 sequential update.
// Each oscillator couples to the other two via sin().
class MCL_T3 {
 double t1_, t2_, t3_;
 int64_t p12_, q12_, p13_, q13_, p23_, q23_;
 double kc_;
public:
 MCL_T3(uint64_t seed, const CouplingTriple& ct, double kc = K_DEFAULT)
 : p12_(ct.p12), q12_(ct.q12), p13_(ct.p13), q13_(ct.q13),
 p23_(ct.p23), q23_(ct.q23), kc_(kc)
 {
 assert(seed != 0 && "Seed must be non-zero");
 // Parameter asserts live INSIDE the MCL_UNSAFE_ALLOW_INVALID guard
 // (v7.0.0; see the MCL_T2 ctor for the rationale).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(ct.p12 != ct.q12 && ct.p13 != ct.q13 && ct.p23 != ct.q23);
 // all coupling weights must satisfy 2 <= p,q <= 2^53
 assert(ct.p12 >= 2 && ct.q12 >= 2 && ct.p13 >= 2 && ct.q13 >= 2
 && ct.p23 >= 2 && ct.q23 >= 2 && "T3 coupling weights must be >= 2");
 // enforce upper bound 2^53 (exact-double contract; see MCL_PQ_MAX)
 assert(ct.p12 <= MCL_PQ_MAX && ct.q12 <= MCL_PQ_MAX
   && ct.p13 <= MCL_PQ_MAX && ct.q13 <= MCL_PQ_MAX
   && ct.p23 <= MCL_PQ_MAX && ct.q23 <= MCL_PQ_MAX
   && "T3 coupling weights must be <= 2^53");
 // reject NaN/Inf/non-positive K
 assert(std::isfinite(kc) && kc > 0.0 && "K must be finite and > 0");
 // Empirically-derived physical lower bound. Below this,
 // K*sin(x) underflows the ULP of t and the engine becomes deterministic
 // (silent K-disappearance). Verified by direct
 // measurement. See MCL_K_MIN_PHYS comment for derivation.
 // T3-specific K_min(p,q) formula does not exist in any source we trust;
 // this physical bound is the most defensible ENFORCEMENT -- but note it sits
 // far below the dynamically-safe range. Like T2, T3 has periodic/quasi-periodic
 // windows ABOVE this floor (documented catastrophic band ~[0.03,0.18] for the
 // default coupling): MCL_K_MIN_PHYS only prevents ULP K-disappearance, it does
 // NOT guarantee chaos. Use K >= MCL_T3_K_RECOMMENDED (0.2) or K_DEFAULT (12),
 // and validate a custom K empirically. (No mcl_make_validated_t2 equivalent
 // exists for T3 yet -- a T3/T4 factory needs 3x3/4x4 Lyapunov machinery not in
 // this header; see mcl_make_validated_t2's note.)
 assert(kc >= MCL_K_MIN_PHYS && "T3 K must be >= MCL_K_MIN_PHYS (1e-12) "
   "to avoid silent K-disappearance below ULP(2pi)");
 if (ct.p12 < 2 || ct.q12 < 2 || ct.p13 < 2 || ct.q13 < 2
 || ct.p23 < 2 || ct.q23 < 2
 || ct.p12 > MCL_PQ_MAX || ct.q12 > MCL_PQ_MAX
 || ct.p13 > MCL_PQ_MAX || ct.q13 > MCL_PQ_MAX
 || ct.p23 > MCL_PQ_MAX || ct.q23 > MCL_PQ_MAX
 || ct.p12 == ct.q12 || ct.p13 == ct.q13 || ct.p23 == ct.q23) {
 std::fprintf(stderr, "FATAL: MCL_T3 invalid coupling weights "
 "(must be 2 <= p,q <= 2^53, p != q)\n");
 std::abort();
 }
 if (!std::isfinite(kc) || kc <= 0.0) {
 std::fprintf(stderr, "FATAL: MCL_T3 invalid K (=%.17g). "
 "Must be finite and > 0.\n", kc);
 std::abort();
 }
 if (kc < MCL_K_MIN_PHYS) {
 std::fprintf(stderr, "FATAL: MCL_T3 K=%.6e below MCL_K_MIN_PHYS=1e-12. "
 "Below this, K underflows ULP(t) and engine becomes deterministic.\n",
 kc);
 std::abort();
 }
#endif
 uint64_t s = hash_seed(seed);
 t1_ = mod2pi((double)s * OMEGA_1);
 t2_ = mod2pi((double)s * OMEGA_2);
 t3_ = mod2pi((double)s * OMEGA_3);
 for (int i = 0; i < BURNIN; i++) iterate();
 assert(std::isfinite(t1_) && std::isfinite(t2_) && std::isfinite(t3_)
 && "T3 diverged in burn-in");
 }

 void iterate() {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 if (MCL_UNLIKELY(kc_ == 0.0)) {
 std::fprintf(stderr, "FATAL: MCL_T3::iterate() on moved-from/invalid (kc_=0)\n");
 std::abort();
 }
#endif
 double c12 = (double)p12_ * t2_ - (double)q12_ * t1_;
 double c13 = (double)p13_ * t3_ - (double)q13_ * t1_;
 t1_ = mod2pi(t1_ + OMEGA_1 + kc_ * (std::sin(c12) + std::sin(c13)));

 double c21 = (double)p12_ * t1_ - (double)q12_ * t2_;
 double c23 = (double)p23_ * t3_ - (double)q23_ * t2_;
 t2_ = mod2pi(t2_ + OMEGA_2 + kc_ * (std::sin(c21) + std::sin(c23)));

 double c31 = (double)p13_ * t1_ - (double)q13_ * t3_;
 double c32 = (double)p23_ * t2_ - (double)q23_ * t3_;
 t3_ = mod2pi(t3_ + OMEGA_3 + kc_ * (std::sin(c31) + std::sin(c32)));
 }

 [[nodiscard]] uint8_t gen_byte() {
 for (int d = 0; d < DECIMATION; d++) iterate();
 uint64_t x = d2b(t1_) ^ d2b(t2_) ^ d2b(t3_);
 return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
 }

 void gen_bytes(uint8_t* buf, int64_t n) {
 mcl_validate_buf(buf, n); // nullptr check
 for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
 }

 std::array<double, 3> state() const { return {t1_, t2_, t3_}; }

 void hop(const CouplingTriple& ct, int warmup = 50) {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(ct.p12 != ct.q12 && ct.p13 != ct.q13 && ct.p23 != ct.q23);
 assert(ct.p12 >= 2 && ct.q12 >= 2 && ct.p13 >= 2 && ct.q13 >= 2
 && ct.p23 >= 2 && ct.q23 >= 2 && "T3 hop: coupling weights must be >= 2");
 if (ct.p12 < 2 || ct.q12 < 2 || ct.p13 < 2 || ct.q13 < 2
 || ct.p23 < 2 || ct.q23 < 2
 || ct.p12 > MCL_PQ_MAX || ct.q12 > MCL_PQ_MAX
 || ct.p13 > MCL_PQ_MAX || ct.q13 > MCL_PQ_MAX
 || ct.p23 > MCL_PQ_MAX || ct.q23 > MCL_PQ_MAX
 || ct.p12 == ct.q12 || ct.p13 == ct.q13 || ct.p23 == ct.q23) {
 std::fprintf(stderr, "FATAL: MCL_T3::hop invalid weights\n");
 std::abort();
 }
#endif
 p12_ = ct.p12; q12_ = ct.q12;
 p13_ = ct.p13; q13_ = ct.q13;
 p23_ = ct.p23; q23_ = ct.q23;
 for (int i = 0; i < warmup; i++) iterate();
 }

 // cryptographic erasure
 ~MCL_T3() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&t3_, sizeof(t3_));
 secure_zero(&kc_, sizeof(kc_));
 }
 void erase() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&t3_, sizeof(t3_));
 secure_zero(&kc_, sizeof(kc_)); // sentinel fire
 }
 // Full decommission -- zeros all 6 coupling weights. erase() covers kc_.
 void erase_identity() noexcept {
 erase();
 secure_zero(&p12_, sizeof(p12_)); secure_zero(&q12_, sizeof(q12_));
 secure_zero(&p13_, sizeof(p13_)); secure_zero(&q13_, sizeof(q13_));
 secure_zero(&p23_, sizeof(p23_)); secure_zero(&q23_, sizeof(q23_));
 }
 MCL_T3(const MCL_T3&) = delete;
 MCL_T3& operator=(const MCL_T3&) = delete;
 // Custom move erases source.
 MCL_T3(MCL_T3&& o) noexcept
   : t1_(o.t1_), t2_(o.t2_), t3_(o.t3_),
     p12_(o.p12_), q12_(o.q12_), p13_(o.p13_), q13_(o.q13_),
     p23_(o.p23_), q23_(o.q23_), kc_(o.kc_) {
   secure_zero(&o.t1_, sizeof(o.t1_));
   secure_zero(&o.t2_, sizeof(o.t2_));
   secure_zero(&o.t3_, sizeof(o.t3_));
   secure_zero(&o.kc_, sizeof(o.kc_));
 }
 MCL_T3& operator=(MCL_T3&& o) noexcept {
   if (this != &o) {
     secure_zero(&t1_, sizeof(t1_));
     secure_zero(&t2_, sizeof(t2_));
     secure_zero(&t3_, sizeof(t3_));
     secure_zero(&kc_, sizeof(kc_));
     t1_ = o.t1_; t2_ = o.t2_; t3_ = o.t3_;
     p12_ = o.p12_; q12_ = o.q12_; p13_ = o.p13_; q13_ = o.q13_;
     p23_ = o.p23_; q23_ = o.q23_; kc_ = o.kc_;
     secure_zero(&o.t1_, sizeof(o.t1_));
     secure_zero(&o.t2_, sizeof(o.t2_));
     secure_zero(&o.t3_, sizeof(o.t3_));
     secure_zero(&o.kc_, sizeof(o.kc_));
   }
   return *this;
 }

 // API uniformity additions (backward-compatible).
 // T3 has 3 coupling pairs; getters return them via a CouplingTriple struct.
 [[nodiscard]] CouplingTriple get_coupling() const noexcept {
   return CouplingTriple{p12_, q12_, p13_, q13_, p23_, q23_};
 }
 [[nodiscard]] bool is_invalid() const noexcept { return kc_ == 0.0; }
};

// ---------- MCL_T4: Four-Oscillator Extension ----------

// E2b: theta_1 -> theta_2 -> theta_3 -> theta_4 sequential update.
// 6 pairwise couplings (N(N-1)/2 = 6).
class MCL_T4 {
 double t1_, t2_, t3_, t4_;
 int64_t p12_,q12_, p13_,q13_, p14_,q14_;
 int64_t p23_,q23_, p24_,q24_, p34_,q34_;
 double kc_;
public:
 MCL_T4(uint64_t seed, const CouplingSextet& cs, double kc = K_DEFAULT)
 : p12_(cs.p12), q12_(cs.q12), p13_(cs.p13), q13_(cs.q13),
 p14_(cs.p14), q14_(cs.q14), p23_(cs.p23), q23_(cs.q23),
 p24_(cs.p24), q24_(cs.q24), p34_(cs.p34), q34_(cs.q34), kc_(kc)
 {
 assert(seed != 0 && "Seed must be non-zero");
 // Parameter asserts live INSIDE the MCL_UNSAFE_ALLOW_INVALID guard
 // (v7.0.0; see the MCL_T2 ctor for the rationale).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(cs.p12 != cs.q12 && cs.p13 != cs.q13 && cs.p14 != cs.q14);
 assert(cs.p23 != cs.q23 && cs.p24 != cs.q24 && cs.p34 != cs.q34);
 // all coupling weights must satisfy 2 <= p,q <= 2^53
 assert(cs.p12 >= 2 && cs.q12 >= 2 && cs.p13 >= 2 && cs.q13 >= 2
 && cs.p14 >= 2 && cs.q14 >= 2 && "T4 pairs 1-2,1-3,1-4 must be >= 2");
 assert(cs.p23 >= 2 && cs.q23 >= 2 && cs.p24 >= 2 && cs.q24 >= 2
 && cs.p34 >= 2 && cs.q34 >= 2 && "T4 pairs 2-3,2-4,3-4 must be >= 2");
 // reject NaN/Inf/non-positive K
 assert(std::isfinite(kc) && kc > 0.0 && "K must be finite and > 0");
 // physical lower bound (see MCL_K_MIN_PHYS comment). As with T2/T3 this only
 // prevents ULP K-disappearance and does NOT guarantee chaos -- T4 has sparse
 // marginal failures below ~0.5. Use K >= MCL_T4_K_RECOMMENDED (0.5) or
 // K_DEFAULT (12); validate a custom K empirically (no T4 validated factory yet).
 assert(kc >= MCL_K_MIN_PHYS && "T4 K must be >= MCL_K_MIN_PHYS (1e-12)");
 // v7.0.0: 2^62 upper bound enforced (T2/T3 parity; previously missing in
 // the T4 ctor although hop() already checked it).
 if (cs.p12 < 2 || cs.q12 < 2 || cs.p13 < 2 || cs.q13 < 2
 || cs.p14 < 2 || cs.q14 < 2 || cs.p23 < 2 || cs.q23 < 2
 || cs.p24 < 2 || cs.q24 < 2 || cs.p34 < 2 || cs.q34 < 2
 || cs.p12 > MCL_PQ_MAX || cs.q12 > MCL_PQ_MAX
 || cs.p13 > MCL_PQ_MAX || cs.q13 > MCL_PQ_MAX
 || cs.p14 > MCL_PQ_MAX || cs.q14 > MCL_PQ_MAX
 || cs.p23 > MCL_PQ_MAX || cs.q23 > MCL_PQ_MAX
 || cs.p24 > MCL_PQ_MAX || cs.q24 > MCL_PQ_MAX
 || cs.p34 > MCL_PQ_MAX || cs.q34 > MCL_PQ_MAX
 || cs.p12 == cs.q12 || cs.p13 == cs.q13 || cs.p14 == cs.q14
 || cs.p23 == cs.q23 || cs.p24 == cs.q24 || cs.p34 == cs.q34) {
 std::fprintf(stderr, "FATAL: MCL_T4 invalid coupling weights "
 "(required: 2 <= p,q <= 2^53 for all six pairs, p != q per pair)\n");
 std::abort();
 }
 // NOTE: coprimality gcd(p,q)=1 is RECOMMENDED but NOT enforced (matches
 // the T2/T3/Coupled* policy; Sextet 6 is a deliberate non-coprime entry).
 if (!std::isfinite(kc) || kc <= 0.0) {
 std::fprintf(stderr, "FATAL: MCL_T4 invalid K (=%.17g). "
 "Must be finite and > 0.\n", kc);
 std::abort();
 }
 if (kc < MCL_K_MIN_PHYS) {
 std::fprintf(stderr, "FATAL: MCL_T4 K=%.6e below MCL_K_MIN_PHYS=1e-12. "
 "Below this, K underflows ULP(t) and engine becomes deterministic.\n",
 kc);
 std::abort();
 }
#endif
 uint64_t s = hash_seed(seed);
 t1_ = mod2pi((double)s * OMEGA_1);
 t2_ = mod2pi((double)s * OMEGA_2);
 t3_ = mod2pi((double)s * OMEGA_3);
 t4_ = mod2pi((double)s * OMEGA_4);
 for (int i = 0; i < BURNIN; i++) iterate();
 assert(std::isfinite(t1_) && std::isfinite(t2_) &&
 std::isfinite(t3_) && std::isfinite(t4_) && "T4 diverged in burn-in");
 }

 void iterate() {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 if (MCL_UNLIKELY(kc_ == 0.0)) {
 std::fprintf(stderr, "FATAL: MCL_T4::iterate() on moved-from/invalid (kc_=0)\n");
 std::abort();
 }
#endif
 double c12 = (double)p12_*t2_ - (double)q12_*t1_;
 double c13 = (double)p13_*t3_ - (double)q13_*t1_;
 double c14 = (double)p14_*t4_ - (double)q14_*t1_;
 t1_ = mod2pi(t1_ + OMEGA_1 + kc_ * (std::sin(c12) + std::sin(c13) + std::sin(c14)));

 double c21 = (double)p12_*t1_ - (double)q12_*t2_;
 double c23 = (double)p23_*t3_ - (double)q23_*t2_;
 double c24 = (double)p24_*t4_ - (double)q24_*t2_;
 t2_ = mod2pi(t2_ + OMEGA_2 + kc_ * (std::sin(c21) + std::sin(c23) + std::sin(c24)));

 double c31 = (double)p13_*t1_ - (double)q13_*t3_;
 double c32 = (double)p23_*t2_ - (double)q23_*t3_;
 double c34 = (double)p34_*t4_ - (double)q34_*t3_;
 t3_ = mod2pi(t3_ + OMEGA_3 + kc_ * (std::sin(c31) + std::sin(c32) + std::sin(c34)));

 double c41 = (double)p14_*t1_ - (double)q14_*t4_;
 double c42 = (double)p24_*t2_ - (double)q24_*t4_;
 double c43 = (double)p34_*t3_ - (double)q34_*t4_;
 t4_ = mod2pi(t4_ + OMEGA_4 + kc_ * (std::sin(c41) + std::sin(c42) + std::sin(c43)));
 }

 [[nodiscard]] uint8_t gen_byte() {
 for (int d = 0; d < DECIMATION; d++) iterate();
 uint64_t x = d2b(t1_) ^ d2b(t2_) ^ d2b(t3_) ^ d2b(t4_);
 return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
 }

 void gen_bytes(uint8_t* buf, int64_t n) {
 mcl_validate_buf(buf, n); // nullptr check
 for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
 }

 void hop(const CouplingSextet& cs, int warmup = 50) {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(cs.p12 != cs.q12 && cs.p13 != cs.q13 && cs.p14 != cs.q14);
 assert(cs.p23 != cs.q23 && cs.p24 != cs.q24 && cs.p34 != cs.q34);
 assert(cs.p12 >= 2 && cs.q12 >= 2 && cs.p13 >= 2 && cs.q13 >= 2
 && cs.p14 >= 2 && cs.q14 >= 2 && "T4 hop: pairs 1-2,1-3,1-4 must be >= 2");
 assert(cs.p23 >= 2 && cs.q23 >= 2 && cs.p24 >= 2 && cs.q24 >= 2
 && cs.p34 >= 2 && cs.q34 >= 2 && "T4 hop: pairs 2-3,2-4,3-4 must be >= 2");
 if (cs.p12 < 2 || cs.q12 < 2 || cs.p13 < 2 || cs.q13 < 2
 || cs.p14 < 2 || cs.q14 < 2 || cs.p23 < 2 || cs.q23 < 2
 || cs.p24 < 2 || cs.q24 < 2 || cs.p34 < 2 || cs.q34 < 2
 || cs.p12 > MCL_PQ_MAX || cs.q12 > MCL_PQ_MAX
 || cs.p13 > MCL_PQ_MAX || cs.q13 > MCL_PQ_MAX
 || cs.p14 > MCL_PQ_MAX || cs.q14 > MCL_PQ_MAX
 || cs.p23 > MCL_PQ_MAX || cs.q23 > MCL_PQ_MAX
 || cs.p24 > MCL_PQ_MAX || cs.q24 > MCL_PQ_MAX
 || cs.p34 > MCL_PQ_MAX || cs.q34 > MCL_PQ_MAX
 || cs.p12 == cs.q12 || cs.p13 == cs.q13 || cs.p14 == cs.q14
 || cs.p23 == cs.q23 || cs.p24 == cs.q24 || cs.p34 == cs.q34) {
 std::fprintf(stderr, "FATAL: MCL_T4::hop invalid weights\n");
 std::abort();
 }
#endif
 p12_ = cs.p12; q12_ = cs.q12; p13_ = cs.p13; q13_ = cs.q13;
 p14_ = cs.p14; q14_ = cs.q14; p23_ = cs.p23; q23_ = cs.q23;
 p24_ = cs.p24; q24_ = cs.q24; p34_ = cs.p34; q34_ = cs.q34;
 for (int i = 0; i < warmup; i++) iterate();
 }

 // cryptographic erasure
 ~MCL_T4() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&t3_, sizeof(t3_));
 secure_zero(&t4_, sizeof(t4_));
 secure_zero(&kc_, sizeof(kc_));
 }
 void erase() noexcept {
 secure_zero(&t1_, sizeof(t1_));
 secure_zero(&t2_, sizeof(t2_));
 secure_zero(&t3_, sizeof(t3_));
 secure_zero(&t4_, sizeof(t4_));
 secure_zero(&kc_, sizeof(kc_)); // sentinel fire
 }
 // Full decommission -- zeros all 12 coupling weights. erase() covers kc_.
 void erase_identity() noexcept {
 erase();
 secure_zero(&p12_, sizeof(p12_)); secure_zero(&q12_, sizeof(q12_));
 secure_zero(&p13_, sizeof(p13_)); secure_zero(&q13_, sizeof(q13_));
 secure_zero(&p14_, sizeof(p14_)); secure_zero(&q14_, sizeof(q14_));
 secure_zero(&p23_, sizeof(p23_)); secure_zero(&q23_, sizeof(q23_));
 secure_zero(&p24_, sizeof(p24_)); secure_zero(&q24_, sizeof(q24_));
 secure_zero(&p34_, sizeof(p34_)); secure_zero(&q34_, sizeof(q34_));
 }
 MCL_T4(const MCL_T4&) = delete;
 MCL_T4& operator=(const MCL_T4&) = delete;
 // Custom move erases source.
 MCL_T4(MCL_T4&& o) noexcept
   : t1_(o.t1_), t2_(o.t2_), t3_(o.t3_), t4_(o.t4_),
     p12_(o.p12_), q12_(o.q12_), p13_(o.p13_), q13_(o.q13_),
     p14_(o.p14_), q14_(o.q14_), p23_(o.p23_), q23_(o.q23_),
     p24_(o.p24_), q24_(o.q24_), p34_(o.p34_), q34_(o.q34_),
     kc_(o.kc_) {
   secure_zero(&o.t1_, sizeof(o.t1_));
   secure_zero(&o.t2_, sizeof(o.t2_));
   secure_zero(&o.t3_, sizeof(o.t3_));
   secure_zero(&o.t4_, sizeof(o.t4_));
   secure_zero(&o.kc_, sizeof(o.kc_));
 }
 MCL_T4& operator=(MCL_T4&& o) noexcept {
   if (this != &o) {
     secure_zero(&t1_, sizeof(t1_));
     secure_zero(&t2_, sizeof(t2_));
     secure_zero(&t3_, sizeof(t3_));
     secure_zero(&t4_, sizeof(t4_));
     secure_zero(&kc_, sizeof(kc_));
     t1_ = o.t1_; t2_ = o.t2_; t3_ = o.t3_; t4_ = o.t4_;
     p12_ = o.p12_; q12_ = o.q12_; p13_ = o.p13_; q13_ = o.q13_;
     p14_ = o.p14_; q14_ = o.q14_; p23_ = o.p23_; q23_ = o.q23_;
     p24_ = o.p24_; q24_ = o.q24_; p34_ = o.p34_; q34_ = o.q34_;
     kc_ = o.kc_;
     secure_zero(&o.t1_, sizeof(o.t1_));
     secure_zero(&o.t2_, sizeof(o.t2_));
     secure_zero(&o.t3_, sizeof(o.t3_));
     secure_zero(&o.t4_, sizeof(o.t4_));
     secure_zero(&o.kc_, sizeof(o.kc_));
   }
   return *this;
 }

 // API uniformity additions (backward-compatible).
 // T4 has 6 coupling pairs; getter returns them via a CouplingSextet struct.
 [[nodiscard]] CouplingSextet get_coupling() const noexcept {
   return CouplingSextet{p12_, q12_, p13_, q13_, p14_, q14_,
                          p23_, q23_, p24_, q24_, p34_, q34_};
 }
 [[nodiscard]] bool is_invalid() const noexcept { return kc_ == 0.0; }
};

// ============================================================================
// 256-bit KEYED CONSTRUCTION (post-quantum key path) -- MCL_T4  [NIST PQ Cat 5]
// ============================================================================
// KEYSPACE PROOF -- why the keyed T4 path reaches NIST PQ Category 5 (highest):
//
//   1. The SECRET is a 256-bit master key (2^256 classical states).
//   2. mcl_t4_params_from_key expands it with the SHA-256 KDF (sec.3.1) into
//      12 coupling weights, one per disjoint 8-byte KDF lane, each reduced into
//      [2, 2^40). The 12 weights span a representation space of 12*40 = 480
//      bits >> 256. Collision accounting (stated precisely): for any FIXED
//      key, the probability that some OTHER key maps to the same 12-tuple is
//      ~2^256 / 2^480 = 2^-224 (union bound, KDF modeled as random). Over the
//      whole keyspace the EXPECTED number of colliding key pairs is
//      C(2^256,2)/2^480 ~= 2^31, so the map is not literally injective on all
//      2^256 keys -- but the expected key-entropy loss from those pairs is
//      ~2^-224 bits: negligible.
//   3. Hence the brute-forceable secret is the FULL 256-bit key, NOT the weight
//      tuple: a Grover key search costs sqrt(2^256) = 2^128 oracle calls.
//        => mcl_pq_security(256).post_grover_bits = 128 => meets_category5 = true.
//   4. No entropy is lost to IEEE-754 precision: each weight (< 2^40) is far
//      below the 2^53 trajectory-collapse onset (sec.3.1), so distinct weights
//      yield distinct dynamics; and burn-in does NOT erode the secret because
//      the 12 weights define the map at every iteration (unlike initial state).
//
//   CONTRAST (none reach Category 5): the default single-(p,q) auth secret is
//   ~30-59 post-Grover bits (below even Category 1 = 64); the keyed T2 path
//   (mcl_t2_from_key) is ~104 post-Grover = Category 3 but below Category 5
//   (T2 capacity ~208 bits < 256). Only the keyed T4 path carries a full
//   256-bit secret. A runnable check is in mcl_self_test() (keyspace assertion).
//
//   NOTE: the integer KDF/weight derivation is platform-independent and is
//   KAT-locked; the subsequent Float64 byte STREAM is libm-dependent (same as
//   every Float64 engine -- see the PLATFORM NOTE on mcl_kat_vectors).
inline CouplingSextet mcl_t4_params_from_key(const uint8_t key[32],
                                             uint64_t challenge = 0) {
 uint8_t info[8];
 for (int i = 0; i < 8; i++) info[i] = (uint8_t)(challenge >> (i * 8));
 uint8_t kd[96]; // 12 weights * 8 bytes
 mcl_kdf256(key, "MCL-T4-Sextet-v1", info, sizeof(info), kd, sizeof(kd));
 constexpr int64_t W_RANGE = (int64_t)((1ULL << 40) - 2); // weights in [2, 2^40)
 // 64-bit lane % W_RANGE carries ~2^-24 relative modulo bias (entropy loss
 // < 1e-6 bit per lane) -- negligible; documented for adversarial review
 // rather than "fixed" with rejection sampling (which would break the KATs).
 auto weight = [&](int lane) -> int64_t {
   uint64_t v = 0;
   for (int i = 0; i < 8; i++) v |= (uint64_t)kd[lane*8 + i] << (i * 8);
   return 2 + (int64_t)(v % (uint64_t)W_RANGE);
 };
 int64_t w[12];
 for (int i = 0; i < 12; i++) w[i] = weight(i);
 // Each coupling pair (p_ij, q_ij) must satisfy p != q (MCL_T4 contract). Bump
 // q within range on the rare collision (keeps the lane independent, in range).
 auto fix_pair = [](int64_t& p, int64_t& q) {
   if (p == q) q = 2 + ((q - 2 + 1) % W_RANGE);
 };
 fix_pair(w[0],  w[1]);  fix_pair(w[2],  w[3]);  fix_pair(w[4],  w[5]);
 fix_pair(w[6],  w[7]);  fix_pair(w[8],  w[9]);  fix_pair(w[10], w[11]);
 CouplingSextet out{ w[0],w[1], w[2],w[3], w[4],w[5],
                     w[6],w[7], w[8],w[9], w[10],w[11] };
 secure_zero(kd, sizeof(kd)); // erase key-derived KDF lanes
 secure_zero(w, sizeof(w));   // erase intermediate weight copies
 return out;
}

// Convenience factory: a burned-in MCL_T4 keyed by a 256-bit master key.
// This is the recommended NIST PQ Category 5 configuration (see proof above).
// `seed` is a PUBLIC salt (washed out by burn-in); the secret is `key`.
inline MCL_T4 mcl_t4_from_key(const uint8_t key[32],
                              uint64_t challenge = 0,
                              uint64_t seed = DEFAULT_SEED) {
 CouplingSextet cs = mcl_t4_params_from_key(key, challenge);
 MCL_T4 eng(seed, cs, K_DEFAULT);
 secure_zero(&cs, sizeof(cs)); // erase the key-derived parameter copy
 return eng;
}

// ============================================================================
// sec.4b DEVICE-BOUND KEYED DERIVATION (v8.1.0, additive)
// ============================================================================
// Route-A realization of the device-binding embodiment (PCT-04 [0018] /
// draft Claim 28): a 256-bit device-bound secret enters the WEIGHT
// DERIVATION, not the seed. Pattern 1 ("K_eff"): primary key and device
// secret are combined into an effective key by the same KDF under a
// dedicated domain label; the effective key then drives the unchanged
// derivation above. Purely additive: no existing function is modified,
// so every v8.0.0 KAT remains byte-identical.
// Contrast (measured): a device secret folded into the seed is capped by
// the uint64_t seed interface (<= 64 bits of effect); here the full
// 256 bits reach the durable map-defining weights.

inline void mcl_keff_from_key_device(const uint8_t key[32],
                                     const uint8_t device_secret[32],
                                     uint8_t keff_out[32]) {
 mcl_kdf256(key, "MCL-KeyDevice-v1", device_secret, 32, keff_out, 32);
}

inline MCL_KeyedParamsT2 mcl_t2_params_from_key_device(
        const uint8_t key[32], const uint8_t device_secret[32],
        uint64_t challenge = 0) {
 uint8_t keff[32];
 mcl_keff_from_key_device(key, device_secret, keff);
 MCL_KeyedParamsT2 kp = mcl_t2_params_from_key(keff, challenge);
 secure_zero(keff, sizeof(keff));
 return kp;
}

inline CouplingSextet mcl_t4_params_from_key_device(
        const uint8_t key[32], const uint8_t device_secret[32],
        uint64_t challenge = 0) {
 uint8_t keff[32];
 mcl_keff_from_key_device(key, device_secret, keff);
 CouplingSextet cs = mcl_t4_params_from_key(keff, challenge);
 secure_zero(keff, sizeof(keff));
 return cs;
}

inline MCL_T4 mcl_t4_from_key_device(const uint8_t key[32],
                                     const uint8_t device_secret[32],
                                     uint64_t challenge = 0,
                                     uint64_t seed = DEFAULT_SEED) {
 CouplingSextet cs = mcl_t4_params_from_key_device(key, device_secret, challenge);
 MCL_T4 eng(seed, cs, K_DEFAULT);
 secure_zero(&cs, sizeof(cs)); // erase the key-derived parameter copy
 return eng;
}

// ============================================================================
// sec.5 GENERALITY ENGINES -- Non-oscillator chaotic systems

// All use the SAME MCL framework: integer (p,q), sin() coupling,
// Gauss-Seidel update, Goldilocks extraction.
// ============================================================================

// ---------- Coupled Henon Maps (strange attractor, 2D) ----------
// x' = 1 - a.x^2 + y + K.sin(p.x_other - q.x_self)
// y' = b.x

// CTOR DIVERGENCE BEHAVIOR: If the burn-in detects
// attractor escape (|x1| or |x2| > 100), the constructor sets
// diverged_=true and RETURNS SILENTLY (does NOT abort). This is
// intentional: it allows research code to inspect the diverged engine.
// Production callers should:
// 1. Check engine.ok() (or engine.is_invalid()) before first use, OR
// 2. Rely on the fact that gen_byte()/gen_bytes() will abort with
// "FATAL: CoupledHenon diverged" if state is non-finite.
// This dual behavior (silent flag at construction, hard abort at first
// use) is a deliberate mixed error contract, preserved for backward
// compatibility with existing research callers.
class CoupledHenon {
 double x1_, y1_, x2_, y2_;
 int64_t p_, q_;
 double K_, a_, b_;
 bool diverged_;
public:
 CoupledHenon(uint64_t seed, int64_t p, int64_t q, double K = HENON_K)
 : p_(p), q_(q), K_(K), a_(HENON_A), b_(HENON_B), diverged_(false)
 {
 assert(seed != 0 && "Seed must be non-zero");
 // Runtime guard for coupling weights -- survives NDEBUG.
 // Unlike T2/T3/T4 where mod2pi constrains state to [0,2pi),
 // Henon's unbounded attractor basin makes invalid parameters
 // dangerous even without divergence detection during burn-in.
 // seed=0 is handled by hash_seed -> abort (separate protection).
 // Parameter asserts live INSIDE the guard (v7.0.0; see the MCL_T2 ctor).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(p >= 2 && q >= 2 && p != q && "coupling weights p,q must be >= 2, distinct");
 assert(p <= MCL_PQ_MAX && q <= MCL_PQ_MAX && "p, q must be <= 2^53");
 assert(std::isfinite(K) && K > 0.0 && "K must be finite and > 0");
 assert(K >= MCL_K_MIN_PHYS && "CoupledHenon K must be >= MCL_K_MIN_PHYS (1e-12)");
 if (p < 2 || q < 2 || p > MCL_PQ_MAX || q > MCL_PQ_MAX || p == q) {
 std::fprintf(stderr, "FATAL: CoupledHenon invalid coupling weights "
 "(p=%lld, q=%lld). Required: 2 <= p,q <= 2^53, p != q.\n",
 (long long)p, (long long)q);
 std::abort();
 }
 // NOTE: coprimality gcd(p,q)=1 is RECOMMENDED but NOT enforced here, for
 // consistency with MCL_T2 (which also only requires p,q>=2 and p!=q).
 if (!std::isfinite(K) || K <= 0.0) {
 std::fprintf(stderr, "FATAL: CoupledHenon invalid K (=%.17g). "
 "Must be finite and > 0.\n", K);
 std::abort();
 }
 if (K < MCL_K_MIN_PHYS) {
 std::fprintf(stderr, "FATAL: CoupledHenon K=%.6e below MCL_K_MIN_PHYS=1e-12. "
 "Below this, K underflows and engine becomes deterministic.\n", K);
 std::abort();
 }
#endif
 uint64_t s = hash_seed(seed);
 x1_ = std::fmod((double)s * OMEGA_1, 1.0) * 0.5;
 y1_ = 0.0;
 x2_ = std::fmod((double)s * OMEGA_2, 1.0) * 0.5;
 y2_ = 0.0;
 for (int i = 0; i < BURNIN; i++) {
 iterate();
 if (!std::isfinite(x1_) || !std::isfinite(x2_) ||
 std::abs(x1_) > 100.0 || std::abs(x2_) > 100.0) {
 diverged_ = true; return;
 }
 }
 }
 void iterate() {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 if (MCL_UNLIKELY(K_ == 0.0)) {
 std::fprintf(stderr, "FATAL: CoupledHenon::iterate() on moved-from/invalid (K_=0)\n");
 std::abort();
 }
#endif
 double a1 = (double)p_ * x2_ - (double)q_ * x1_;
 double nx1 = 1.0 - a_ * x1_ * x1_ + y1_ + K_ * std::sin(a1);
 double ny1 = b_ * x1_;
 x1_ = nx1; y1_ = ny1;
 double a2 = (double)p_ * x1_ - (double)q_ * x2_;
 double nx2 = 1.0 - a_ * x2_ * x2_ + y2_ + K_ * std::sin(a2);
 double ny2 = b_ * x2_;
 x2_ = nx2; y2_ = ny2;
 }
 [[nodiscard]] uint8_t gen_byte() {
 for (int d = 0; d < DECIMATION; d++) iterate();
 // Runtime divergence guard: NaN/Inf from attractor escape
 if (!std::isfinite(x1_) || !std::isfinite(x2_) ||
 std::abs(x1_) > 1e6 || std::abs(x2_) > 1e6) {
 diverged_ = true;
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 // SECURITY: abort instead of returning a constant value.
 // Returning 0 on every call leaks divergence state to an
 // observer, distinguishing failed output from genuine chaos.
 std::fprintf(stderr, "FATAL: CoupledHenon diverged "
 "(attractor escape)\n");
 std::abort();
#else
 return 0; // Research mode: allow caller to check ok()
#endif
 }
 uint64_t x = d2b(x1_) ^ d2b(x2_);
 return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
 }
 void gen_bytes(uint8_t* buf, int64_t n) {
 mcl_validate_buf(buf, n); // nullptr check
 for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
 }
 // ok() == "engine is healthy AND usable": false after attractor escape
 // (diverged_), and also false after erase()/move-from (K_ == 0 sentinel),
 // so ok() and is_invalid() can never contradict each other.
 bool ok() const { return !diverged_ && K_ != 0.0; }

 // API uniformity additions (backward-compatible).
 // get_p / get_q match MCL_T2 API; is_invalid mirrors moved-from sentinel
 // semantics from MCL_T2 (returns true after erase or move-from).
 [[nodiscard]] int64_t get_p() const noexcept { return p_; }
 [[nodiscard]] int64_t get_q() const noexcept { return q_; }
 [[nodiscard]] bool is_invalid() const noexcept { return K_ == 0.0 || diverged_; }

 // cryptographic erasure for generality engine.
 ~CoupledHenon() noexcept {
 secure_zero(&x1_, sizeof(x1_));
 secure_zero(&y1_, sizeof(y1_));
 secure_zero(&x2_, sizeof(x2_));
 secure_zero(&y2_, sizeof(y2_));
 secure_zero(&K_,  sizeof(K_));
 }
 void erase() noexcept {
 secure_zero(&x1_, sizeof(x1_));
 secure_zero(&y1_, sizeof(y1_));
 secure_zero(&x2_, sizeof(x2_));
 secure_zero(&y2_, sizeof(y2_));
 secure_zero(&K_, sizeof(K_)); // sentinel fire
 }
 // Full decommission -- zeros (p, q) device identity, plus a_, b_ for
 // consistency (though they are public constants). erase() covers K_.
 void erase_identity() noexcept {
 erase();
 secure_zero(&p_, sizeof(p_));
 secure_zero(&q_, sizeof(q_));
 secure_zero(&a_, sizeof(a_));
 secure_zero(&b_, sizeof(b_));
 secure_zero(&diverged_, sizeof(diverged_));
 }
 CoupledHenon(const CoupledHenon&) = delete;
 CoupledHenon& operator=(const CoupledHenon&) = delete;
 CoupledHenon(CoupledHenon&& o) noexcept
   : x1_(o.x1_), y1_(o.y1_), x2_(o.x2_), y2_(o.y2_),
     p_(o.p_), q_(o.q_), K_(o.K_), a_(o.a_), b_(o.b_),
     diverged_(o.diverged_) {
   secure_zero(&o.x1_, sizeof(o.x1_));
   secure_zero(&o.y1_, sizeof(o.y1_));
   secure_zero(&o.x2_, sizeof(o.x2_));
   secure_zero(&o.y2_, sizeof(o.y2_));
   secure_zero(&o.K_,  sizeof(o.K_));
 }
 // Move-ASSIGNMENT is deleted for the sec.5 generality engines (move-
 // construction suffices for factory returns); the sec.4 production
 // engines define both. Deliberate API asymmetry, not an oversight.
 CoupledHenon& operator=(CoupledHenon&&) = delete;
};

// ---------- Coupled Logistic Maps (interval map, 1D) ----------
// x' = r.x.(1-x) + K.sin(p.x_other - q.x_self)

// DESIGN NOTE: No diverged_ flag or ok() method.
// Unlike CoupledHenon (unbounded attractor basin, divergence possible),
// CoupledLogistic uses fmod + clamp to [1e-10, 1-1e-10] after every
// iteration, making divergence mathematically impossible for any finite
// input. The state is structurally confined to (0,1) by construction.
// Adding ok() would falsely imply a failure mode that cannot occur,
// misleading callers into unnecessary error handling.
class CoupledLogistic {
 double x1_, x2_;
 int64_t p_, q_;
 double K_, r_;
public:
 CoupledLogistic(uint64_t seed, int64_t p, int64_t q, double K = LOGISTIC_K)
 : p_(p), q_(q), K_(K), r_(LOGISTIC_R)
 {
 assert(seed != 0 && "Seed must be non-zero");
 // Parameter asserts live INSIDE the guard (v7.0.0; see the MCL_T2 ctor).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(p >= 2 && q >= 2 && p != q && "coupling weights p,q must be >= 2, distinct");
 assert(p <= MCL_PQ_MAX && q <= MCL_PQ_MAX && "p, q must be <= 2^53");
 assert(std::isfinite(K) && K > 0.0 && "K must be finite and > 0");
 assert(K >= MCL_K_MIN_PHYS && "CoupledLogistic K must be >= MCL_K_MIN_PHYS (1e-12)");
 if (p < 2 || q < 2 || p > MCL_PQ_MAX || q > MCL_PQ_MAX || p == q) {
 std::fprintf(stderr, "FATAL: CoupledLogistic invalid coupling weights "
 "(p=%lld, q=%lld). Required: 2 <= p,q <= 2^53, p != q.\n",
 (long long)p, (long long)q);
 std::abort();
 }
 // NOTE: coprimality gcd(p,q)=1 is RECOMMENDED but NOT enforced here, for
 // consistency with MCL_T2 (which also only requires p,q>=2 and p!=q).
 if (!std::isfinite(K) || K <= 0.0) {
 std::fprintf(stderr, "FATAL: CoupledLogistic invalid K (=%.17g). "
 "Must be finite and > 0.\n", K);
 std::abort();
 }
 if (K < MCL_K_MIN_PHYS) {
 std::fprintf(stderr, "FATAL: CoupledLogistic K=%.6e below MCL_K_MIN_PHYS=1e-12. "
 "Below this, K underflows and engine becomes deterministic.\n", K);
 std::abort();
 }
#endif
 uint64_t s = hash_seed(seed);
 x1_ = std::fmod((double)s * OMEGA_1, 1.0) * 0.8 + 0.1;
 x2_ = std::fmod((double)s * OMEGA_2, 1.0) * 0.8 + 0.1;
 for (int i = 0; i < BURNIN; i++) iterate();
 // defense-in-depth -- fmod+clamp prevents divergence mathematically,
 // but the assert guards against unforeseen edge cases
 assert(std::isfinite(x1_) && std::isfinite(x2_) && "Logistic diverged in burn-in");
 }
 // TIMING: The clamp branches below are data-dependent and
 // theoretically a timing side-channel. This is acceptable because
 // CoupledLogistic is a generality engine (Paper 1 sec.V) used only
 // to prove the MCL principle is system-agnostic, NOT the primary
 // production engine (MCL_T2 has no data-dependent branches).
 void iterate() {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 if (MCL_UNLIKELY(K_ == 0.0)) {
 std::fprintf(stderr, "FATAL: CoupledLogistic::iterate() on moved-from/invalid (K_=0)\n");
 std::abort();
 }
#endif
 double a1 = (double)p_ * x2_ - (double)q_ * x1_;
 x1_ = r_ * x1_ * (1.0 - x1_) + K_ * std::sin(a1);
 x1_ = std::fmod(x1_, 1.0);
 if (x1_ <= 0.0) x1_ += 1.0;
 if (x1_ < 1e-10) x1_ = 1e-10;
 if (x1_ > 1.0 - 1e-10) x1_ = 1.0 - 1e-10;
 double a2 = (double)p_ * x1_ - (double)q_ * x2_;
 x2_ = r_ * x2_ * (1.0 - x2_) + K_ * std::sin(a2);
 x2_ = std::fmod(x2_, 1.0);
 if (x2_ <= 0.0) x2_ += 1.0;
 if (x2_ < 1e-10) x2_ = 1e-10;
 if (x2_ > 1.0 - 1e-10) x2_ = 1.0 - 1e-10;
 }
 [[nodiscard]] uint8_t gen_byte() {
 for (int d = 0; d < DECIMATION; d++) iterate();
 uint64_t x = d2b(x1_) ^ d2b(x2_);
 return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
 }
 void gen_bytes(uint8_t* buf, int64_t n) {
 mcl_validate_buf(buf, n); // nullptr check
 for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
 }
 // API uniformity additions (backward-compatible).
 [[nodiscard]] int64_t get_p() const noexcept { return p_; }
 [[nodiscard]] int64_t get_q() const noexcept { return q_; }
 [[nodiscard]] bool is_invalid() const noexcept { return K_ == 0.0; }

 // cryptographic erasure
 ~CoupledLogistic() noexcept {
 secure_zero(&x1_, sizeof(x1_));
 secure_zero(&x2_, sizeof(x2_));
 secure_zero(&K_,  sizeof(K_));
 }
 void erase() noexcept {
 secure_zero(&x1_, sizeof(x1_));
 secure_zero(&x2_, sizeof(x2_));
 secure_zero(&K_, sizeof(K_)); // sentinel fire
 }
 // Full decommission -- zeros (p, q) device identity, plus r_ for
 // consistency (though it is a public constant). erase() covers K_.
 void erase_identity() noexcept {
 erase();
 secure_zero(&p_, sizeof(p_));
 secure_zero(&q_, sizeof(q_));
 secure_zero(&r_, sizeof(r_));
 }
 CoupledLogistic(const CoupledLogistic&) = delete;
 CoupledLogistic& operator=(const CoupledLogistic&) = delete;
 CoupledLogistic(CoupledLogistic&& o) noexcept
   : x1_(o.x1_), x2_(o.x2_), p_(o.p_), q_(o.q_), K_(o.K_), r_(o.r_) {
   secure_zero(&o.x1_, sizeof(o.x1_));
   secure_zero(&o.x2_, sizeof(o.x2_));
   secure_zero(&o.K_,  sizeof(o.K_));
 }
 CoupledLogistic& operator=(CoupledLogistic&&) = delete;
};

// ---------- Coupled Tent Maps (piecewise linear, 1D) ----------
// T(x) = 1 - |2x - 1| + K.sin(p.x_other - q.x_self)

// DESIGN NOTE: No diverged_ flag or ok() method -- same rationale as
// CoupledLogistic. The fmod + clamp to [1e-10, 1-1e-10] structurally
// prevents divergence for any finite input.
class CoupledTent {
 double x1_, x2_;
 int64_t p_, q_;
 double K_;
public:
 CoupledTent(uint64_t seed, int64_t p, int64_t q, double K = TENT_K)
 : p_(p), q_(q), K_(K)
 {
 assert(seed != 0 && "Seed must be non-zero");
 // Parameter asserts live INSIDE the guard (v7.0.0; see the MCL_T2 ctor).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 assert(p >= 2 && q >= 2 && p != q && "coupling weights p,q must be >= 2, distinct");
 assert(p <= MCL_PQ_MAX && q <= MCL_PQ_MAX && "p, q must be <= 2^53");
 assert(std::isfinite(K) && K > 0.0 && "K must be finite and > 0");
 assert(K >= MCL_K_MIN_PHYS && "CoupledTent K must be >= MCL_K_MIN_PHYS (1e-12)");
 if (p < 2 || q < 2 || p > MCL_PQ_MAX || q > MCL_PQ_MAX || p == q) {
 std::fprintf(stderr, "FATAL: CoupledTent invalid coupling weights "
 "(p=%lld, q=%lld). Required: 2 <= p,q <= 2^53, p != q.\n",
 (long long)p, (long long)q);
 std::abort();
 }
 // NOTE: coprimality gcd(p,q)=1 is RECOMMENDED but NOT enforced here, for
 // consistency with MCL_T2 (which also only requires p,q>=2 and p!=q).
 if (!std::isfinite(K) || K <= 0.0) {
 std::fprintf(stderr, "FATAL: CoupledTent invalid K (=%.17g). "
 "Must be finite and > 0.\n", K);
 std::abort();
 }
 if (K < MCL_K_MIN_PHYS) {
 std::fprintf(stderr, "FATAL: CoupledTent K=%.6e below MCL_K_MIN_PHYS=1e-12. "
 "Below this, K underflows and engine becomes deterministic.\n", K);
 std::abort();
 }
#endif
 uint64_t s = hash_seed(seed);
 x1_ = std::fmod((double)s * OMEGA_1, 1.0) * 0.8 + 0.1;
 x2_ = std::fmod((double)s * OMEGA_2, 1.0) * 0.8 + 0.1;
 for (int i = 0; i < BURNIN; i++) iterate();
 // defense-in-depth -- fmod+clamp prevents divergence mathematically,
 // but the assert guards against unforeseen edge cases
 assert(std::isfinite(x1_) && std::isfinite(x2_) && "Tent diverged in burn-in");
 }
 void iterate() {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
 if (MCL_UNLIKELY(K_ == 0.0)) {
 std::fprintf(stderr, "FATAL: CoupledTent::iterate() on moved-from/invalid (K_=0)\n");
 std::abort();
 }
#endif
 double a1 = (double)p_ * x2_ - (double)q_ * x1_;
 x1_ = 1.0 - std::abs(2.0 * x1_ - 1.0) + K_ * std::sin(a1);
 x1_ = std::fmod(x1_, 1.0);
 if (x1_ <= 0.0) x1_ += 1.0;
 if (x1_ < 1e-10) x1_ = 1e-10;
 if (x1_ > 1.0 - 1e-10) x1_ = 1.0 - 1e-10;
 double a2 = (double)p_ * x1_ - (double)q_ * x2_;
 x2_ = 1.0 - std::abs(2.0 * x2_ - 1.0) + K_ * std::sin(a2);
 x2_ = std::fmod(x2_, 1.0);
 if (x2_ <= 0.0) x2_ += 1.0;
 if (x2_ < 1e-10) x2_ = 1e-10;
 if (x2_ > 1.0 - 1e-10) x2_ = 1.0 - 1e-10;
 }
 [[nodiscard]] uint8_t gen_byte() {
 for (int d = 0; d < DECIMATION; d++) iterate();
 uint64_t x = d2b(x1_) ^ d2b(x2_);
 return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
 }
 void gen_bytes(uint8_t* buf, int64_t n) {
 mcl_validate_buf(buf, n); // nullptr check
 for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
 }
 // API uniformity additions (backward-compatible).
 [[nodiscard]] int64_t get_p() const noexcept { return p_; }
 [[nodiscard]] int64_t get_q() const noexcept { return q_; }
 [[nodiscard]] bool is_invalid() const noexcept { return K_ == 0.0; }

 // cryptographic erasure
 ~CoupledTent() noexcept {
 secure_zero(&x1_, sizeof(x1_));
 secure_zero(&x2_, sizeof(x2_));
 secure_zero(&K_,  sizeof(K_));
 }
 void erase() noexcept {
 secure_zero(&x1_, sizeof(x1_));
 secure_zero(&x2_, sizeof(x2_));
 secure_zero(&K_, sizeof(K_)); // sentinel fire
 }
 // Full decommission -- zeros (p, q) device identity. erase() covers K_.
 void erase_identity() noexcept {
 erase();
 secure_zero(&p_, sizeof(p_));
 secure_zero(&q_, sizeof(q_));
 }
 CoupledTent(const CoupledTent&) = delete;
 CoupledTent& operator=(const CoupledTent&) = delete;
 CoupledTent(CoupledTent&& o) noexcept
   : x1_(o.x1_), x2_(o.x2_), p_(o.p_), q_(o.q_), K_(o.K_) {
   secure_zero(&o.x1_, sizeof(o.x1_));
   secure_zero(&o.x2_, sizeof(o.x2_));
   secure_zero(&o.K_,  sizeof(o.K_));
 }
 CoupledTent& operator=(CoupledTent&&) = delete;
};

// ============================================================================
// sec.6 STATISTICS
// ============================================================================

// Pearson r -- 2-pass formula (never 1-pass for large N stability)
// Stat-utility input validator. Same hardening as
// gen_bytes : nullptr -> abort with explanatory message;
// n < 0 -> abort (likely signed/unsigned bug);
// n > 16 GB -> abort (likely INT64_MAX accident causing buffer overrun).
// n == 0 returns silently (caller's stat-of-empty-buffer is well-defined).
inline void mcl_validate_stat_buf(const void* p, int64_t n,
                                   const char* func) noexcept {
 if (n == 0) return; // legitimate: stat of empty buffer
    if (n < 0) {
        std::fprintf(stderr, "FATAL: %s called with negative n=%lld. "
                     "Likely signed/unsigned bug at the call site.\n",
                     func, (long long)n);
        std::abort();
    }
    if (p == nullptr) {
        std::fprintf(stderr, "FATAL: %s called with nullptr buffer "
                     "(n=%lld). Allocate buffer first.\n",
                     func, (long long)n);
        std::abort();
    }
 constexpr int64_t MCL_STAT_BUF_MAX = (int64_t)16 << 30; // 16 GB
    if (n > MCL_STAT_BUF_MAX) {
        std::fprintf(stderr, "FATAL: %s called with n=%lld bytes, exceeds "
                     "16 GB defensive cap. Likely INT64_MAX-from-unsigned bug.\n",
                     func, (long long)n);
        std::abort();
    }
}

[[nodiscard]] inline double pearson_r(const uint8_t* a, const uint8_t* b, int64_t n) {
 mcl_validate_stat_buf(a, n, "pearson_r (a)");
 mcl_validate_stat_buf(b, n, "pearson_r (b)");
 if (n == 0) return 0.0; // guard against n=0 -> NaN
 double ma = 0, mb = 0;
 for (int64_t i = 0; i < n; i++) { ma += a[i]; mb += b[i]; }
 ma /= (double)n; mb /= (double)n;
 double cov = 0, va = 0, vb = 0;
 for (int64_t i = 0; i < n; i++) {
 double da = a[i] - ma, db = b[i] - mb;
 cov += da * db; va += da * da; vb += db * db;
 }
 if (va < 1e-10 || vb < 1e-10) return 0;
 return cov / std::sqrt(va * vb);
}

// Shannon entropy
// freq[256] is int64_t to prevent silent overflow at N > 2^31.
// At PractRand 4 TB scale (N = 4e12 bytes), a single bin could receive
// > 2^31 entries even under uniform distribution, causing int wrap-around.
// Guard against n=0 (returns 0 entropy explicitly).
[[nodiscard]] inline double shannon_entropy(const uint8_t* data, int64_t n) {
 mcl_validate_stat_buf(data, n, "shannon_entropy");
 if (n == 0) return 0.0;
 int64_t freq[256] = {};
 for (int64_t i = 0; i < n; i++) freq[data[i]]++;
 double H = 0;
 for (int i = 0; i < 256; i++) {
 if (freq[i] > 0) {
 double p = (double)freq[i] / (double)n;
 H -= p * std::log2(p);
 }
 }
 return H;
}

// Chi-Square uniformity (df=255)
// freq[256] is int64_t (same rationale as shannon_entropy).
// Guard against n=0 (otherwise division by zero -> NaN).
[[nodiscard]] inline double chi_square(const uint8_t* data, int64_t n) {
 mcl_validate_stat_buf(data, n, "chi_square");
 if (n == 0) return 0.0;
 int64_t freq[256] = {};
 for (int64_t i = 0; i < n; i++) freq[data[i]]++;
 double expected = (double)n / 256.0;
 double chi2 = 0;
 for (int i = 0; i < 256; i++) {
 double d = (double)freq[i] - expected;
 chi2 += d * d / expected;
 }
 return chi2;
}

// Hamming distance (bit-level percentage)
// Guard against n=0 (otherwise 0/0 -> NaN).
[[nodiscard]] inline double hamming_pct(const uint8_t* a, const uint8_t* b, int64_t n) {
 mcl_validate_stat_buf(a, n, "hamming_pct (a)");
 mcl_validate_stat_buf(b, n, "hamming_pct (b)");
 if (n == 0) return 0.0;
 int64_t bits = 0;
 for (int64_t i = 0; i < n; i++) bits += popcount8(a[i] ^ b[i]);
 return 100.0 * (double)bits / ((double)n * 8.0);
}

// Bit frequency (proportion of 1-bits)
// Uses popcount8() (sec.3) rather than an inner bit-loop; identical
// numerical result.
// Guard against n=0 (otherwise 0/0 -> NaN).
[[nodiscard]] inline double bit_frequency(const uint8_t* data, int64_t n) {
 mcl_validate_stat_buf(data, n, "bit_frequency");
 if (n == 0) return 0.0;
 int64_t ones = 0;
 for (int64_t i = 0; i < n; i++) ones += popcount8(data[i]);
 return (double)ones / ((double)n * 8.0);
}

// p-value from |r| under H_0 (independence)
// For large n: z = |r|.sqrtn ~ N(0,1), p = erfc(z/sqrt2)
inline double pvalue_from_r(double abs_r, int64_t n) {
 double z = abs_r * std::sqrt((double)n);
 return std::erfc(z / std::sqrt(2.0));
}

// noise_floor: EVT expected max |r| for K independent comparisons (Eq. 6)
// sqrt(2.ln(K))/sqrtN -- valid for reporting/descriptive bounds, not sole pass/fail
// Guard against n_bytes <= 0 (otherwise inf/0).
inline double noise_floor(int n_pairs, int64_t n_bytes) {
 if (n_pairs <= 1) return 0;
 if (n_bytes <= 0) return 0;
 return std::sqrt(2.0 * std::log((double)n_pairs)) / std::sqrt((double)n_bytes);
}

// Autocorrelation at specified lag
inline double autocorrelation(const uint8_t* data, int64_t n, int lag) {
 mcl_validate_stat_buf(data, n, "autocorrelation");
 // negative lag is a programmer error
 if (lag < 0) {
 std::fprintf(stderr, "FATAL: autocorrelation called with negative lag=%d\n", lag);
 std::abort();
 }
 int64_t len = n - lag;
 if (len <= 0) return 0;
 double m = 0;
 for (int64_t i = 0; i < n; i++) m += data[i];
 m /= (double)n;
 double num = 0, den = 0;
 for (int64_t i = 0; i < len; i++) {
 double di = data[i] - m;
 double dj = data[i + lag] - m;
 num += di * dj;
 den += di * di;
 }
 for (int64_t i = len; i < n; i++) {
 double di = data[i] - m;
 den += di * di;
 }
 if (den < 1e-10) return 0;
 return num / den;
}

// Runs test Z-score (number-of-runs test).
// IMPLEMENTATION NOTE: the mean E[R]=2nπ(1-π)+1 and variance
// Var[R]=2nπ(1-π)(2π(1-π) - 1/n) are the EXACT runs-count (Wald-Wolfowitz)
// moments, not NIST SP 800-22's simplified σ=2√(2n)π(1-π) (which differs by
// ~√2). The form used here is the correctly-calibrated one: verified that z
// has std ~= 1.0 under H0 over thousands of random sequences, so |z| maps to
// a standard-normal p-value (the classical runs z statistic).
// Guard against n_bytes <= 0.
// int overflow fix: prev_byte/prev_bit kept as int64_t (a naive int cast
// truncates when n_bytes > INT_MAX/8 ~= 268MB), with an explicit guard
// against int64_t overflow in total_bits.
inline double runs_test_z(const uint8_t* data, int64_t n_bytes) {
 mcl_validate_stat_buf(data, n_bytes, "runs_test_z");
 if (n_bytes == 0) return 0.0;
 // Guard against int64_t overflow in n_bytes * 8 (n_bytes > 2^60)
 if (n_bytes > (int64_t{1} << 60)) {
 std::fprintf(stderr, "FATAL: runs_test_z n_bytes=%lld too large "
   "(would overflow int64_t in total_bits)\n", (long long)n_bytes);
 std::abort();
 }
 int64_t total_bits = n_bytes * 8;
 int64_t ones = 0;
 for (int64_t i = 0; i < n_bytes; i++)
 for (int bit = 0; bit < 8; bit++)
 ones += (data[i] >> bit) & 1;
 double pi = (double)ones / (double)total_bits;
 double tau = 2.0 / std::sqrt((double)total_bits);
 // SENTINEL: 999.0 signals "frequency precondition failed" (|pi - 0.5| >=
 // tau) -- it is NOT a z-score. Callers must treat 999.0 as
 // PRECONDITION-FAIL. (Kept numeric for API stability with existing
 // experiment files; a NaN return would break their comparisons.)
 if (std::abs(pi - 0.5) >= tau) return 999.0;

 int64_t runs = 1;
 for (int64_t i = 0; i < n_bytes; i++) {
 for (int bit = 0; bit < 8; bit++) {
 int64_t pos = i * 8 + bit;
 if (pos == 0) continue;
 int curr = (data[i] >> bit) & 1;
 // keep prev_byte and prev_bit as int64_t to avoid
 // truncation when n_bytes > INT_MAX/8. The (data[prev_byte] >> prev_bit)
 // operation works fine with int64_t indices and an int shift count
 // (after the implicit conversion within the bit operation).
 int64_t prev_byte = (pos - 1) / 8;
 int prev_bit = (int)((pos - 1) % 8); // % 8 in [0,7], safe to cast
 int prev = (data[prev_byte] >> prev_bit) & 1;
 if (curr != prev) runs++;
 }
 }
 double er = 2.0 * (double)total_bits * pi * (1.0 - pi) + 1.0;
 double var = 2.0 * (double)total_bits * pi * (1.0 - pi) *
 (2.0 * pi * (1.0 - pi) - 1.0 / (double)total_bits);
 if (var < 1e-10) var = 1.0;
 return ((double)runs - er) / std::sqrt(var);
}

// Distance Correlation (Szekely et al., 2007)
// Detects ANY dependence (linear and nonlinear). dCor=0 - independence.
// Subsampled to n_sub points for O(n_sub^2) computation.
inline double distance_correlation(const uint8_t* a, const uint8_t* b,
 int64_t N, int n_sub = 2000) {
 mcl_validate_stat_buf(a, N, "distance_correlation (a)");
 mcl_validate_stat_buf(b, N, "distance_correlation (b)");
 // v7.0.0 fail-closed guard: N == 0 previously reached an integer division
 // by zero (UB: SIGFPE on x86, silent garbage/NaN on ARM); n_sub <= 0
 // likewise. dCor of an empty sample is defined here as 0.
 if (N <= 0 || n_sub <= 0) return 0.0;
 size_t n = (size_t)std::min((int64_t)n_sub, N);
 int64_t stride = std::max((int64_t)1, N / (int64_t)n);
 std::vector<double> x(n), y(n);
 for (size_t i = 0; i < n; i++) {
 x[i] = (double)a[(int64_t)i * stride];
 y[i] = (double)b[(int64_t)i * stride];
 }
 std::vector<double> ax(n, 0), ay(n, 0);
 double ga = 0, gy_sum = 0;
 for (size_t i = 0; i < n; i++) {
 for (size_t j = 0; j < n; j++) {
 ax[i] += std::abs(x[i] - x[j]);
 ay[i] += std::abs(y[i] - y[j]);
 }
 ax[i] /= (double)n; ay[i] /= (double)n;
 ga += ax[i]; gy_sum += ay[i];
 }
 ga /= (double)n; gy_sum /= (double)n;
 double dcov2 = 0, dvarx2 = 0, dvary2 = 0;
 for (size_t i = 0; i < n; i++) {
 for (size_t j = 0; j < n; j++) {
 double Aij = std::abs(x[i] - x[j]) - ax[i] - ax[j] + ga;
 double Bij = std::abs(y[i] - y[j]) - ay[i] - ay[j] + gy_sum;
 dcov2 += Aij * Bij;
 dvarx2 += Aij * Aij;
 dvary2 += Bij * Bij;
 }
 }
 double nn = (double)n * (double)n;
 dcov2 /= nn; dvarx2 /= nn; dvary2 /= nn;
 if (dvarx2 < 1e-20 || dvary2 < 1e-20) return 0;
 // The sample dCov^2 can round to a tiny negative value for independent
 // inputs; clamp so the sqrt cannot return NaN.
 if (dcov2 < 0.0) dcov2 = 0.0;
 return std::sqrt(dcov2 / std::sqrt(dvarx2 * dvary2));
}

// ============================================================================
// sec.7 LYAPUNOV COMPUTATION (Benettin et al., 1980 -- QR Jacobian method)
// ============================================================================

// Forward declarations (defined in sec.11 -- needed here for DRY)
inline void mcl_init_state(uint64_t seed, double& t1, double& t2);
inline void mcl_iterate_raw(double& t1, double& t2,
                            int64_t p, int64_t q, double K = K_DEFAULT);
inline void mcl_iterate_jacobi(double& t1, double& t2,
                               int64_t p, int64_t q, double K);

struct Mat2 { double a[2][2]; };

inline Mat2 mat_mul(const Mat2& A, const Mat2& B) {
 Mat2 C;
 C.a[0][0] = A.a[0][0]*B.a[0][0] + A.a[0][1]*B.a[1][0];
 C.a[0][1] = A.a[0][0]*B.a[0][1] + A.a[0][1]*B.a[1][1];
 C.a[1][0] = A.a[1][0]*B.a[0][0] + A.a[1][1]*B.a[1][0];
 C.a[1][1] = A.a[1][0]*B.a[0][1] + A.a[1][1]*B.a[1][1];
 return C;
}

inline void qr_decompose_2x2(const Mat2& A, Mat2& Q, double& r11, double& r22) {
 double a0 = A.a[0][0], a1 = A.a[1][0];
 r11 = std::sqrt(a0*a0 + a1*a1);
 if (r11 < 1e-300) r11 = 1e-300;
 Q.a[0][0] = a0 / r11; Q.a[1][0] = a1 / r11;
 double b0 = A.a[0][1], b1 = A.a[1][1];
 double r12 = Q.a[0][0]*b0 + Q.a[1][0]*b1;
 double v0 = b0 - r12 * Q.a[0][0];
 double v1 = b1 - r12 * Q.a[1][0];
 r22 = std::sqrt(v0*v0 + v1*v1);
 if (r22 < 1e-300) r22 = 1e-300;
 Q.a[0][1] = v0 / r22; Q.a[1][1] = v1 / r22;
}

// Analytical Jacobian of the MCL Gauss-Seidel map (accounts for f_1 in f_2)
inline Mat2 jacobian_gs(double t1, double t2, int64_t p, int64_t q, double K) {
 double alpha1 = (double)p * t2 - (double)q * t1;
 double c1 = K * std::cos(alpha1);
 double J00 = 1.0 - (double)q * c1;
 double J01 = (double)p * c1;
 double f1 = mod2pi(t1 + OMEGA_1 + K * std::sin(alpha1));
 double alpha2 = (double)p * f1 - (double)q * t2;
 double c2 = K * std::cos(alpha2);
 double J10 = (double)p * c2 * J00;
 double J11 = 1.0 - (double)q * c2 + (double)p * c2 * J01;
 Mat2 J;
 J.a[0][0] = J00; J.a[0][1] = J01;
 J.a[1][0] = J10; J.a[1][1] = J11;
 return J;
}

struct LyapResult {
 double l1, l2;
 double l1_stderr, l2_stderr;
 int64_t iters;
};

// NOTE: This function is hardcoded to MCL_T2 with standard omega_1=phi-1, omega_2=rho.
// It cannot compute Lyapunov exponents for MCL_T2_Omega (custom omega) or T3/T4.
// Extending to T3/T4 requires a larger Jacobian (3x3 or 4x4) and QR.
inline LyapResult compute_lyapunov(uint64_t seed, int64_t p, int64_t q,
 double K, int64_t n_iter) {
 if (n_iter <= 0) { // v7.0.0: previously 0/0 -> NaN results
 std::fprintf(stderr, "FATAL: compute_lyapunov n_iter=%lld (must be >= 1)\n",
   (long long)n_iter);
 std::abort();
 }
 double t1, t2;
 mcl_init_state(seed, t1, t2);
 for (int i = 0; i < BURNIN; i++)
     mcl_iterate_raw(t1, t2, p, q, K);
 Mat2 Q;
 Q.a[0][0] = 1; Q.a[0][1] = 0;
 Q.a[1][0] = 0; Q.a[1][1] = 1;
 double sum1 = 0, sum2 = 0, sum1sq = 0, sum2sq = 0;
 for (int64_t n = 0; n < n_iter; n++) {
 Mat2 J = jacobian_gs(t1, t2, p, q, K); // Jacobian at current state
 mcl_iterate_raw(t1, t2, p, q, K); // then advance
 Mat2 M = mat_mul(J, Q);
 double r11, r22;
 qr_decompose_2x2(M, Q, r11, r22);
 double lr1 = std::log(std::abs(r11));
 double lr2 = std::log(std::abs(r22));
 sum1 += lr1; sum2 += lr2;
 sum1sq += lr1 * lr1; sum2sq += lr2 * lr2;
 }
 double N = (double)n_iter;
 LyapResult res;
 res.l1 = sum1 / N;
 res.l2 = sum2 / N;
 res.iters = n_iter;
 double var1 = sum1sq / N - res.l1 * res.l1;
 double var2 = sum2sq / N - res.l2 * res.l2;
 // stderr uses the iid formula var/N. This is CALIBRATED here, not
 // optimistic: QR re-orthonormalization decorrelates successive
 // log-stretches (measured autocorrelation time tau ~= 1.01), so no
 // effective-sample-size correction is needed. Applies to the Jacobi
 // variant below as well.
 // NOTE: sanitizer-instrumented builds (-fsanitize=undefined,address) may
 // perturb the QR pipeline's floating-point scheduling and shift lambda in
 // the 3rd decimal (~1 sigma; measured identically on v6.1.0 and v7.0.0).
 // Engine byte streams are unaffected even under sanitizers. Use plain
 // optimized builds for citable Lyapunov numbers.
 res.l1_stderr = std::sqrt(std::max(0.0, var1) / N);
 res.l2_stderr = std::sqrt(std::max(0.0, var2) / N);
 return res;
}

// ============================================================================
// JACOBI-MODE LYAPUNOV (for non-parallelizability evidence -- Paper 4 sec.VI.B)
// ============================================================================
//
// The Jacobi (parallel) iteration variant uses theta_1(t), NOT theta_1(t+1),
// in computing theta_2(t+1). This eliminates the sequential data dependency
// but produces a fundamentally different dynamical system with a different
// Lyapunov spectrum.
//
// Provided for adversarial comparison ONLY -- NOT used in any normal MCL
// operation (PRNG, authentication, VDF). The MCL system always uses the
// Gauss-Seidel update (mcl_iterate_raw / jacobian_gs).
//
// Empirical result (Paper 4 sec.VI.B, validated cross-platform; measured
// with compute_lyapunov / compute_lyapunov_jacobi at the default validation
// topology, K = K_DEFAULT, 10^7 iterations):
//   lambda_GS     = 5.78  (from jacobian_gs)
//   lambda_Jacobi = 3.59  (from this function)
//   ratio         = 1.61

inline Mat2 jacobian_jacobi(double t1, double t2, int64_t p, int64_t q, double K) {
 double alpha1 = (double)p * t2 - (double)q * t1;
 double alpha2 = (double)p * t1 - (double)q * t2;
 double c1 = K * std::cos(alpha1);
 double c2 = K * std::cos(alpha2);
 Mat2 J;
 J.a[0][0] = 1.0 - (double)q * c1;
 J.a[0][1] = (double)p * c1;
 J.a[1][0] = (double)p * c2;
 J.a[1][1] = 1.0 - (double)q * c2;
 return J;
}

inline LyapResult compute_lyapunov_jacobi(uint64_t seed, int64_t p, int64_t q,
 double K, int64_t n_iter) {
 if (n_iter <= 0) { // v7.0.0: previously 0/0 -> NaN results
 std::fprintf(stderr, "FATAL: compute_lyapunov_jacobi n_iter=%lld (must be >= 1)\n",
   (long long)n_iter);
 std::abort();
 }
 double t1, t2;
 mcl_init_state(seed, t1, t2);
 for (int i = 0; i < BURNIN; i++)
     mcl_iterate_jacobi(t1, t2, p, q, K);
 Mat2 Q;
 Q.a[0][0] = 1; Q.a[0][1] = 0;
 Q.a[1][0] = 0; Q.a[1][1] = 1;
 double sum1 = 0, sum2 = 0, sum1sq = 0, sum2sq = 0;
 for (int64_t n = 0; n < n_iter; n++) {
 Mat2 J = jacobian_jacobi(t1, t2, p, q, K);
 mcl_iterate_jacobi(t1, t2, p, q, K);
 Mat2 M = mat_mul(J, Q);
 double r11, r22;
 qr_decompose_2x2(M, Q, r11, r22);
 double lr1 = std::log(std::abs(r11));
 double lr2 = std::log(std::abs(r22));
 sum1 += lr1; sum2 += lr2;
 sum1sq += lr1 * lr1; sum2sq += lr2 * lr2;
 }
 double N = (double)n_iter;
 LyapResult res;
 res.l1 = sum1 / N;
 res.l2 = sum2 / N;
 res.iters = n_iter;
 double var1 = sum1sq / N - res.l1 * res.l1;
 double var2 = sum2sq / N - res.l2 * res.l2;
 res.l1_stderr = std::sqrt(std::max(0.0, var1) / N);
 res.l2_stderr = std::sqrt(std::max(0.0, var2) / N);
 return res;
}

// ============================================================================
// sec.8 SPECTRAL TEST (Goertzel DFT) -- CLASSICAL randomness/SNR test (orth_verify).
// Not a post-quantum test; see mcl_pq_security() (sec.3.1) for quantum accounting.
// ============================================================================

struct SpectralResult {
 double max_peak;
 int peak_freq;
 double noise_avg;
 double snr;
 bool pass;
};

inline SpectralResult spectral_test(const uint8_t* data, int64_t data_len,
 int num_freqs) {
 mcl_validate_stat_buf(data, data_len, "spectral_test");
 // v7.0.0 fail-closed guard: degenerate input previously produced a
 // SPURIOUS PASS (N = 0 -> noise = 0 -> snr = 0 < threshold -> "pass",
 // plus mean = 0/0 = NaN). Empty or too-short input now FAILS explicitly.
 if (data_len < 4 || num_freqs < 1) return {0.0, 0, 0.0, 0.0, false};
 int N = (int)std::min(data_len, (int64_t)65536);
 double mean = 0;
 for (int i = 0; i < N; i++) mean += data[i];
 mean /= N;

 double max_power = 0;
 int max_freq = 0;
 double total_power = 0;
 int freqs_done = 0;   // actual count (the loop stops early when k reaches N/2)

 for (int k = 1; k <= num_freqs && k < N / 2; k++) {
 double w = 2.0 * MCL_PI * k / N;
 double coeff = 2.0 * std::cos(w);
 // s0 is reassigned every iteration; only s1, s2 carry
 // state across iterations. s0 declared inside loop reduces scope.
 double s1 = 0, s2 = 0;
 for (int i = 0; i < N; i++) {
 double s0 = (data[i] - mean) + coeff * s1 - s2;
 s2 = s1; s1 = s0;
 }
 double power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
 power /= (double)N * N;
 total_power += power;
 freqs_done++;
 if (power > max_power) { max_power = power; max_freq = k; }
 }

 // Average over the frequencies ACTUALLY computed (freqs_done), not the
 // requested num_freqs -- they differ when num_freqs >= N/2, in which case
 // dividing by num_freqs would understate noise and inflate SNR.
 double noise = (freqs_done > 0) ? total_power / freqs_done : 0;
 double snr = (noise > 0) ? max_power / noise : 0;
 return {max_power, max_freq, noise, snr, (snr < SPECTRAL_SNR_THRESHOLD)};
}

// ============================================================================
// sec.9 REGIME CLASSIFICATION (D6)
// ============================================================================

// Classify dynamical regime based on K value, test results, and chi^2 severity.
// QUASI = quasiperiodic (K too low); RESON = resonance; MARGN = marginal;
// CHAOS = genuine chaos.
inline const char* classify_regime(double eff_k, bool pass, double chi2) {
 if (!pass) {
 if (chi2 > 1000.0) return "RESON";
 return "MARGN";
 }
 if (eff_k < 1.0) return "QUASI";
 return "CHAOS";
}

// ============================================================================
// sec.10 TOPOLOGY GENERATION (for scaling experiments beyond 20 entries)
// ============================================================================

inline std::vector<Topology> generate_topologies(int count) {
 std::vector<Topology> topos;
 // v7.0.0: count <= 0 returns empty (a negative count previously threw
 // std::length_error from reserve((size_t)negative)).
 if (count <= 0) return topos;
 topos.reserve((size_t)count);

 // Collision-free dedup using exact (p,q) pairs -- no hash function needed
 std::set<std::pair<int64_t,int64_t>> seen;

 // First 20: standard table (E5)
 const Topology* fixed = t2_topos();
 for (int i = 0; i < std::min(count, N_T2_TOPOS); i++) {
 topos.push_back(fixed[i]);
 seen.insert({fixed[i].p, fixed[i].q});
 }

 // Beyond 20: deterministic unique coprime pairs.
 // NOTE: Coprimality is NOT required for independence (verified experimentally
 // with gcd>1 pairs). Coprime filter is used here as a CONSERVATIVE choice for scaling tests --
 // it maximizes topological diversity and avoids ratio-duplicate pairs
 // (e.g., (4,6) and (2,3) have the same ratio). Non-coprime stress testing
 // is handled by dedicated entries in the standard tables (T3 Triple 11,
 // T4 Sextet 6) and by mcl_reference EXP 6.
 // Note on choice of seed 0xABCDEF0123456789ULL:
 // This is an "obviously arbitrary" readable hex pattern (literally
 // "abcdef0123456789"), used here as a deterministic seed for the
 // parameter-generation xorshift. It is NOT used cryptographically;
 // it only drives the search for coprime (p, q) topologies in this
 // helper. Choosing a memorable constant here aids reproducibility
 // and audit traceability over a "magic" random hex.
 uint64_t rng = 0xABCDEF0123456789ULL;
 auto next_rng = [&rng]() -> uint64_t {
 rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
 return rng;
 };
 int64_t range = std::max((int64_t)10000,
 (int64_t)std::sqrt((double)count) * 10);
 // Defensive attempt cap: if `count` ever approaches the number of coprime
 // pairs available in [2,range], the search could spin a very long time.
 // Cap attempts and widen the range if we stall, so the function always
 // terminates (returns fewer than `count` only in a truly pathological case).
 int64_t attempts = 0;
 const int64_t max_attempts = (int64_t)count * 1000 + 1000000;
 while ((int)topos.size() < count) {
 if (++attempts > max_attempts) {
 // Widen the search range once and reset the budget; if it still
 // cannot fill, return what we have rather than hang forever.
 if (range < (int64_t{1} << 40)) { range *= 4; attempts = 0; }
 else break;
 }
 int64_t p = 2 + (int64_t)(next_rng() % (uint64_t)range);
 int64_t q = 2 + (int64_t)(next_rng() % (uint64_t)range);
 if (p == q) continue;
 // Named result for readability; consumed by the coprimality filter below.
 int64_t gcd = gcd_compute(p, q);
 if (gcd != 1) continue;
 if (seen.insert({p, q}).second) {
 topos.push_back(Topology{p, q});
 }
 }
 return topos;
}

// ============================================================================
// sec.11 ECR ANALYSIS UTILITIES
// ============================================================================
// These functions expose mathematical analysis capabilities while keeping
// ALL MCL equations inside mcl_core.hpp (ECR compliance). Experiment files
// (the dependent .cpp files, under the same PolyForm Noncommercial license)
// call these instead of writing equations directly.

// Initialize raw state from seed (same as MCL_T2 constructor init, no burn-in)
inline void mcl_init_state(uint64_t seed, double& t1, double& t2) {
 uint64_t s = hash_seed(seed);
 t1 = mod2pi((double)s * OMEGA_1);
 t2 = mod2pi((double)s * OMEGA_2);
}

// Single Gauss-Seidel iterate on raw state (standard MCL update, no extraction)
inline void mcl_iterate_raw(double& t1, double& t2,
 int64_t p, int64_t q, double K) {
 // Debug-only assertion against pointer aliasing.
 // Caller bug: passing the same variable as both t1 and t2 makes the
 // sequential Gauss-Seidel update degenerate. Zero cost in NDEBUG.
 assert(&t1 != &t2 && "mcl_iterate_raw: t1 and t2 must be distinct");
 double a1 = (double)p * t2 - (double)q * t1;
 t1 = mod2pi(t1 + OMEGA_1 + K * std::sin(a1));
 double a2 = (double)p * t1 - (double)q * t2;
 t2 = mod2pi(t2 + OMEGA_2 + K * std::sin(a2));
}

// Jacobi (parallel) iterate -- intentionally WRONG variant for comparison.
// Both oscillators use OLD states (no sequential dependency).
// Used to prove Gauss-Seidel superiority in the non-parallelizability
// analysis (Paper 4): lambda_GS / lambda_Jacobi ~= 1.61. (This is a CLASSICAL
// dynamical comparison, not a quantum-security analysis.)
inline void mcl_iterate_jacobi(double& t1, double& t2,
 int64_t p, int64_t q, double K = K_DEFAULT) {
 double a1 = (double)p * t2 - (double)q * t1;
 double a2 = (double)p * t1 - (double)q * t2; // uses OLD t1
 t1 = mod2pi(t1 + OMEGA_1 + K * std::sin(a1));
 t2 = mod2pi(t2 + OMEGA_2 + K * std::sin(a2));
}

// Single iterate + local 2x2 Jacobian matrix computation.
// Updates state (t1,t2) and writes the step Jacobian to S[2][2].
// Used for condition number analysis and Newton-Raphson in attack tests.
inline void mcl_iterate_jacobian(double& t1, double& t2,
 int64_t p, int64_t q, double K,
 double S[2][2]) {
 double a1 = (double)p * t2 - (double)q * t1;
 double c1 = K * std::cos(a1);
 S[0][0] = 1.0 - (double)q * c1;
 S[0][1] = (double)p * c1;
 double f1 = mod2pi(t1 + OMEGA_1 + K * std::sin(a1));
 double a2 = (double)p * f1 - (double)q * t2;
 double c2 = K * std::cos(a2);
 S[1][0] = (double)p * c2 * S[0][0];
 S[1][1] = 1.0 - (double)q * c2 + (double)p * c2 * S[0][1];
 t1 = f1;
 t2 = mod2pi(t2 + OMEGA_2 + K * std::sin(a2));
}

// Extract individual Goldilocks zones for per-zone quality analysis.
inline uint8_t mcl_extract_zone1(double t1, double t2) {
 uint64_t x = d2b(t1) ^ d2b(t2);
 return (uint8_t)(x >> GOLD_S1);
}
inline uint8_t mcl_extract_zone2(double t1, double t2) {
 uint64_t x = d2b(t1) ^ d2b(t2);
 return (uint8_t)(x >> GOLD_S2);
}

// Extract byte from a SINGLE oscillator (for diagnostic -- not standard MCL output).
// Used to distinguish genuine chaos from XOR-masked quasiperiodicity.
inline uint8_t mcl_extract_single(double theta) {
 uint64_t b = d2b(theta);
 return (uint8_t)(b >> GOLD_S1) ^ (uint8_t)(b >> GOLD_S2);
}

// ============================================================================
// sec.12 HIERARCHICAL KEY DERIVATION

// Derives child coupling parameters from parent parameters using the
// chaotic engine output. One-wayness is supported by preimage branching
// (see sec.17): the inverse map is non-injective with constrained
// branching b_eff > 1, so a parent cannot be recovered from a child.
// The positive Lyapunov exponent provides FORWARD sensitivity only --
// a necessary precursor, but not by itself a proof of backward one-wayness.


// ============================================================================

// In-class member initializers ensure the struct is in
// a defined state even on early return paths -- defensive against future
// code changes that might add a return without explicit field assignment.
struct DerivedKey {
    int64_t p = 0;
    int64_t q = 0;
    bool valid = false;
 int64_t index = 0; // actual index used (may differ from requested if retried)
};

// fmix64: SplitMix64 finalizer (David Stafford variant 13).
// Bijective 64-bit hash with full avalanche. Public domain constants
// from Sebastiano Vigna's SplitMix64 / Stafford's "MIX13".
// Ensures that consecutive indices produce maximally different outputs.
// NOT MurmurHash3's fmix64: that finalizer uses different constants
// (0xff51afd7ed558ccd / 0xc4ceb9fe1a85ec53, which appear in hash_seed,
// sec.3). Named per Stafford's variant catalog for traceability.
inline uint64_t fmix64(uint64_t k) {
    k ^= k >> 30;
    k *= 0xBF58476D1CE4E5B9ULL;
    k ^= k >> 27;
    k *= 0x94D049BB133111EBULL;
    k ^= k >> 31;
    return k;
}

// derive_child: parent (p,q) + seed S + index i -> child (p_child, q_child)
// Each derived child is immediately usable for PRNG, auth, encrypt,
// multiplex, and forward secrecy (multi-function keys).
inline DerivedKey derive_child(uint64_t seed, int64_t p_parent, int64_t q_parent,
                               int64_t index, int64_t max_val = 1000000,
                               double K = K_DEFAULT) {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
    assert(max_val >= 4 && "max_val must be >= 4 for distinct p,q in [2,max_val-1]");
    if (max_val < 4) {
        std::fprintf(stderr, "FATAL: derive_child max_val must be >= 4 (got %lld)\n",
            (long long)max_val);
        std::abort();
    }
#endif
    DerivedKey result;
    result.index = index;
 // result.valid is set to true at the end; no path reaches return without it.

 // Steps 1-3: Initialize engine, burn-in, extract 32 bytes
    MCL_T2 eng(seed, p_parent, q_parent, K);
    uint8_t raw[32];
    eng.gen_bytes(raw, 32);

 // Step 4: Incorporate derivation index via fmix64 (full avalanche)
    uint64_t idx_h = fmix64((uint64_t)index);
 uint64_t idx_h2 = idx_h * 0x9E3779B97F4A7C15ULL; // second half
    for (int b = 0; b < 8; b++) {
        raw[b]     ^= (uint8_t)(idx_h  >> (b * 8));
        raw[8 + b] ^= (uint8_t)(idx_h2 >> (b * 8));
    }

 // Step 5: Map to valid coupling weights in [2, max_val-1] (the modulus is
 // max_val-2, so max_val itself is NOT reachable -- consistent with the
 // "Guaranteed" note below and the published child-range statements).
 // The c % (max_val-2) reduction carries ~2^-44 relative modulo bias at the
 // default max_val = 10^6 -- negligible; noted for adversarial review.
    uint64_t c1 = 0, c2 = 0;
    std::memcpy(&c1, raw, 8);
    std::memcpy(&c2, raw + 8, 8);
    int64_t pc = 2 + (int64_t)(c1 % (uint64_t)(max_val - 2));
    int64_t qc = 2 + (int64_t)(c2 % (uint64_t)(max_val - 2));
    if (pc == qc) { qc = 2 + ((qc - 2 + 1) % (max_val - 2)); }
 // Guaranteed: qc in [2, max_val-1] and qc != pc for max_val >= 4

 // derive_child must guarantee coprime (p, q) for downstream engine.
 // Without this loop, derived pairs may have gcd > 1 (e.g., (105272, 279950)
 // has gcd=2). Adjust q until gcd(p, q) = 1. We try at most max_val-2
 // candidates by incrementing q; for typical max_val=10^6 this terminates
 // in O(log) by prime density.
    {
        int64_t a = pc > qc ? pc : qc;
        int64_t b = pc > qc ? qc : pc;
        int64_t bumps = 0;
        while (true) {
            int64_t aa = a, bb = b;
            while (bb != 0) { int64_t t = bb; bb = aa % bb; aa = t; }
            if (aa == 1) break;
 // Bump q by 1 (guaranteed to find coprime; at worst hits a
 // coprime pair within q's domain)
            qc = 2 + ((qc - 2 + 1) % (max_val - 2));
            if (qc == pc) qc = 2 + ((qc - 2 + 1) % (max_val - 2));
            a = pc > qc ? pc : qc;
            b = pc > qc ? qc : pc;
            bumps++;
            if (bumps > max_val) {
 // Should never happen in practice, but defensive
                result.valid = false;
                return result;
            }
        }
    }

 // Step 6: Output
    result.p = pc;
    result.q = qc;
    result.valid = true;
    return result;
}

// derive_child_safe: resonance avoidance.
// If child params fall in a resonance island (non-chaotic at given K),
// the derivation index is incremented until a chaotic pair is found.
// Uses chi-square test on 100K bytes as the chaoticity criterion.
//
// SAFETY (v4.1.0): also skips (p,q) where K < K_min(p,q) = 5.053/(p+q).
// Previously, such pairs would trigger MCL_T2's K_min abort. Now they
// are silently retried like any other non-chaotic candidate.
inline DerivedKey derive_child_safe(uint64_t seed, int64_t p_parent,
                                    int64_t q_parent, int64_t index,
                                    int64_t max_val = 1000000,
                                    double K = K_DEFAULT,
                                    int max_attempts = 100) {
    int64_t try_idx = index;
 // v6.0.0: 100 KB buffer moved off the stack. A stack array this large can
 // overflow a small secondary-thread stack (256 KB-1 MB on some platforms,
 // smaller on embedded/eSIM targets this code is documented to serve).
 // std::vector heap-allocates once here (outside the retry loop), so the
 // "allocated once, reused across retries" property is preserved.
 std::vector<uint8_t> test_buf_vec(100000);
 uint8_t* test_buf = test_buf_vec.data();
    for (int a = 0; a < max_attempts; a++, try_idx++) {
        DerivedKey dk = derive_child(seed, p_parent, q_parent,
                                     try_idx, max_val, K);
 // K_min(p,q) safety check: skip pairs where K is below the chaos
 // threshold MCL_K_MIN_NUMERATOR/(p+q). Without this, MCL_T2 would
 // abort below. With this, the retry loop simply moves to the next idx.
        const double K_min_pq = MCL_K_MIN_NUMERATOR
                              / ((double)dk.p + (double)dk.q);
        if (K < K_min_pq) continue;
 // Verify chaoticity: generate test output and check chi-square
        MCL_T2 test_eng(seed, dk.p, dk.q, K);
        test_eng.gen_bytes(test_buf, 100000);
        double chi_val = chi_square(test_buf, 100000);
        if (chi_val < CHI2_THRESHOLD) {
            dk.index = try_idx;
            return dk;
        }
    }
 // All attempts exhausted -- return invalid
    DerivedKey fail;
    fail.p = 0; fail.q = 0; fail.valid = false; fail.index = index;
    return fail;
}

// derive_path: sequential multi-level derivation.
// Path m/0/3/17 = derive(derive(derive(master, 0), 3), 17).
// Returns the terminal node's coupling parameters.
inline DerivedKey derive_path(uint64_t seed, int64_t p_root, int64_t q_root,
                              const int64_t* path, int depth,
                              int64_t max_val = 1000000,
                              double K = K_DEFAULT) {
    int64_t p = p_root, q = q_root;
    DerivedKey dk;
    dk.p = p; dk.q = q; dk.valid = true; dk.index = -1;
    for (int d = 0; d < depth; d++) {
        dk = derive_child(seed, p, q, path[d], max_val, K);
        if (!dk.valid) return dk;
        p = dk.p;
        q = dk.q;
    }
    return dk;
}

// ============================================================================
// sec.13 VERIFIABLE DELAY FUNCTION

// Exploits non-parallelizable Gauss-Seidel sequential iteration.
// The delay parameter N is INDEPENDENT of burn-in B -- this is the
// key distinction from PRNG initialization.

// Verification: any party recomputes VDF(x, P, N) and compares.
// Non-parallelizability evidence (Paper 4, Section VI.B):
//   - Lyapunov exponent ratio: lambda_GS / lambda_Jacobi = 5.78 / 3.59 ~= 1.61
//   - Mean trajectory divergence after 10,000 iterations ~= 2.08 radians
//   - See compute_lyapunov() (GS) and compute_lyapunov_jacobi()
//     (defined below) for empirical reproduction.
// Post-quantum posture (v6.1.0):
//  - Shor is INAPPLICABLE: MCL is symmetric -- no factoring / discrete-log /
//    lattice / hidden-subgroup structure for period-finding to attack.
//  - VDF SEQUENTIALITY is quantum-robust: Grover speeds up SEARCH, not the
//    DEPTH of an inherently sequential recurrence, so the delay survives.
//  - The only generic quantum threat is GROVER over the brute-forceable SECRET,
//    which it square-roots. In auth that secret is the coupling weights (p,q),
//    NOT the seed (the seed is the PUBLIC challenge). A single (p,q) is only
//    ~59 classical / ~30 post-Grover bits at [2,1e9] (up to ~119/~59 at
//    [2,1e18]) -- below even NIST PQ Category 1 (AES-128 = 64 post-Grover). A
//    KEYED VDF inherits this: widen the secret to 256 bits via mcl_t4_from_key()
//    (sec.4) for Category 5 (AES-256, the highest). Use mcl_pq_security()
//    (sec.3.1) for the work-factor accounting. Note the secret in auth is
//    the coupling weights / key -- the seed is the PUBLIC challenge.


// ============================================================================

struct VDFResult {
 uint8_t output[32]; // extracted output bytes
 int64_t iterations; // actual N performed
 double elapsed_sec; // wall-clock time
};

// vdf_compute: verifiable delay computation.
// Input: seed x, coupling (p,q), delay N iterations.
// Output: deterministic 32-byte value after B burn-in + N delay iterations.
// N is freely configurable and independent of B (the burn-in constant).
inline VDFResult vdf_compute(uint64_t seed, int64_t p, int64_t q,
                             int64_t N_delay, double K = K_DEFAULT) {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
    assert(N_delay >= 0 && "VDF delay must be non-negative");
    if (N_delay < 0) {
        std::fprintf(stderr, "FATAL: VDF delay must be non-negative (N=%lld)\n",
            (long long)N_delay);
        std::abort();
    }
#endif
    VDFResult result;
    result.iterations = N_delay;

    auto t0 = std::chrono::steady_clock::now();

 // Phase 1: Standard burn-in (B = BURNIN iterations, in constructor)
    MCL_T2 eng(seed, p, q, K);

 // Phase 2: Delay iterations (N, operator-selected, independent of B)
 // This is the VDF computation -- strictly sequential, non-parallelizable.
    for (int64_t i = 0; i < N_delay; i++) {
        eng.iterate();
    }

 // Phase 3: Extract output from post-delay state
    eng.gen_bytes(result.output, 32);

    result.elapsed_sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();

    return result;
}

// VDFCheckpoint: intermediate state at a given iteration.
// Checkpoints enable SEGMENT-WISE verification WITHIN a seed-anchored
// transcript (see vdf_verify_transcript below). Checkpoint states expose
// theta1/theta2 by design -- required for verification, not a leak (VDF
// output is public).
struct VDFCheckpoint {
 double theta1, theta2; // internal oscillator state
 int64_t iteration; // iteration number at this checkpoint
};

// vdf_compute_checkpointed: VDF with intermediate state snapshots.
// Publishes k checkpoints at intervals of N/k iterations.
// Caller allocates checkpoints array of size k.
// The optional out-param checkpoints_written (v7.0.0) reports how many
// checkpoint slots were actually filled: exactly k when N_delay >= k, and 0
// when N_delay < k (the interval underflows to 0, no snapshots are taken,
// and the caller's array is left untouched -- previously this case was
// silent). The function returns the VDFResult; an earlier doc line wrongly
// promised the count as the return value.
inline VDFResult vdf_compute_checkpointed(
    uint64_t seed, int64_t p, int64_t q,
    int64_t N_delay, VDFCheckpoint* checkpoints, int k,
    double K = K_DEFAULT, int* checkpoints_written = nullptr) {
    // v7.0.1: a null checkpoint array with k > 0 is memory corruption, not a
    // research scenario -- unconditional abort (mcl_validate_buf policy;
    // the contract is "caller allocates checkpoints array of size k").
    if (MCL_UNLIKELY(checkpoints == nullptr && k > 0)) {
        std::fprintf(stderr, "FATAL: vdf_compute_checkpointed checkpoints "
            "array must be non-null (k=%d; caller allocates size k)\n", k);
        std::abort();
    }
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
    assert(N_delay >= 0 && k > 0);
    if (N_delay < 0 || k <= 0) {
        std::fprintf(stderr, "FATAL: VDF invalid params (N=%lld, k=%d)\n",
            (long long)N_delay, k);
        std::abort();
    }
#endif
    VDFResult result;
    result.iterations = N_delay;
    auto t0 = std::chrono::steady_clock::now();

    MCL_T2 eng(seed, p, q, K);

 // interval = 0 means no checkpoints will be saved (N_delay < k or
 // N_delay == 0). The k > 0 term keeps the division defined even under
 // MCL_UNSAFE_ALLOW_INVALID builds, where the k-validation guard is off.
    int64_t interval = (N_delay > 0 && k > 0) ? N_delay / k : 0;
    int cp_idx = 0;

    for (int64_t i = 0; i < N_delay; i++) {
        eng.iterate();
 // Snapshot at each interval boundary
        if (interval > 0 && ((i + 1) % interval == 0) && cp_idx < k) {
            checkpoints[cp_idx].theta1 = eng.theta1();
            checkpoints[cp_idx].theta2 = eng.theta2();
            checkpoints[cp_idx].iteration = i + 1;
            cp_idx++;
        }
    }

    eng.gen_bytes(result.output, 32);
    if (checkpoints_written) *checkpoints_written = cp_idx;
    result.elapsed_sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    return result;
}

// vdf_verify_segment: verify one segment between two checkpoints.
// Recomputes from start state for segment_iters iterations and
// compares the resulting state against the end checkpoint.
//
// SECURITY -- UNSOUND WHEN USED STANDALONE. Nothing in this function binds
// t*_start to the seed: a cheating prover can fabricate ANY self-consistent
// (start, end) state pair -- including an entire fabricated checkpoint
// chain -- and every segment will "verify". Segment checks are meaningful
// ONLY within a transcript whose head is anchored to the seed-derived
// post-burn-in trajectory and whose tail is bound to the 32-byte output.
// Use vdf_verify_transcript() below for sound verification; never accept a
// VDF transcript on the basis of segment checks alone.
inline bool vdf_verify_segment(double t1_start, double t2_start,
                               double t1_end, double t2_end,
                               int64_t p, int64_t q, int64_t segment_iters,
                               double K = K_DEFAULT) {
    double t1 = t1_start, t2 = t2_start;
    for (int64_t i = 0; i < segment_iters; i++) {
        mcl_iterate_raw(t1, t2, p, q, K);
    }
 // Exact equality is intentional: Gauss-Seidel iteration is
 // bit-deterministic on the same IEEE 754 platform.
 // Cross-platform verification requires lookup-table sin().
    return (t1 == t1_end && t2 == t2_end);
}

// vdf_verify_transcript (v7.0.0): SOUND end-to-end verification of a
// checkpointed VDF transcript, anchored to the PUBLIC inputs
// (seed, p, q, N_delay, K).
//
// Verifies, in order:
//   1. ANCHOR -- the trajectory is recomputed from the seed (constructor
//        burn-in), so a fabricated start state cannot verify;
//   2. CHAIN  -- every checkpoint (iteration number AND both state words,
//        bit-exact) must match the prover's schedule (interval = N/k);
//   3. OUTPUT -- the final 32-byte value must equal expected_output.
// Fails closed (returns false, never aborts) on any invalid parameter,
// shape, or content mismatch -- safe to call on fully untrusted transcript
// tuples. Total work is one full recomputation (B + N iterations): the
// checkpoints buy tamper LOCALIZATION and audit granularity, not a work
// discount -- this candidate VDF has no known shortcut verifier (Paper 4).
// N_delay = 0 produces no checkpoints, so a checkpointed transcript cannot
// represent it; verify N = 0 results with plain vdf_verify().
// Same-IEEE-754-platform contract as vdf_verify_segment; use the Q30 VDF
// (sec.16.1) for cross-platform verification.
// mcl_valid_t2_params: shared fail-closed predicate mirroring the MCL_T2
// constructor's dynamical contract (seed != 0, 2 <= p,q <= MCL_PQ_MAX (2^53), p != q,
// finite K > 0, K >= K_min(p,q)). Constructors abort() on violation (fail-loud);
// untrusted-input verifiers (vdf_verify, vdf_verify_transcript) call this to
// return false (fail-closed) instead of tripping those aborts and becoming a
// DoS vector. Note: like the ctor, this accepts any K >= K_min -- the K >= 6.0
// window-free floor is advisory only (see MCL_K_RECOMMENDED_FLOOR), never
// enforced here. Single source of the contract, shared by both verifiers.
inline bool mcl_valid_t2_params(uint64_t seed, int64_t p, int64_t q,
                                double K) noexcept {
    if (seed == 0 || p < 2 || q < 2 || p == q) return false;
    if (p > MCL_PQ_MAX || q > MCL_PQ_MAX) return false;
    if (!std::isfinite(K) || K <= 0.0) return false;
    const double K_min_pq = MCL_K_MIN_NUMERATOR / ((double)p + (double)q);
    return K >= K_min_pq;
}

inline bool vdf_verify_transcript(uint64_t seed, int64_t p, int64_t q,
                                  int64_t N_delay,
                                  const VDFCheckpoint* checkpoints, int k,
                                  const uint8_t expected_output[32],
                                  double K = K_DEFAULT) {
    if (N_delay < 0 || k <= 0 || checkpoints == nullptr
        || expected_output == nullptr)
        return false;
    // Reject invalid engine parameters HERE (shared predicate) so an adversarial
    // transcript tuple returns false instead of tripping the MCL_T2 ctor's
    // fprintf+abort guards -- a verifier must never be a DoS vector.
    if (!mcl_valid_t2_params(seed, p, q, K)) return false;
    // Anchor: burn-in from the public seed (same path as vdf_compute*).
    MCL_T2 eng(seed, p, q, K);
    // Reproduce the prover's checkpoint schedule exactly.
    int64_t interval = (N_delay > 0) ? N_delay / k : 0;
    int cp_idx = 0;
    for (int64_t i = 0; i < N_delay; i++) {
        eng.iterate();
        if (interval > 0 && ((i + 1) % interval == 0) && cp_idx < k) {
            // Bit-exact double comparison is intentional: deterministic
            // replay on the same IEEE 754 platform (see vdf_verify_segment).
            if (checkpoints[cp_idx].iteration != i + 1
                || checkpoints[cp_idx].theta1 != eng.theta1()
                || checkpoints[cp_idx].theta2 != eng.theta2())
                return false;
            cp_idx++;
        }
    }
    // Shape check: with interval > 0 the schedule fills exactly k slots. A
    // transcript claiming k > 0 checkpoints for N_delay < k (interval == 0)
    // is malformed and MUST fail -- none of its entries were checked above.
    if (cp_idx != k) return false;
    uint8_t out[32];
    eng.gen_bytes(out, 32);
    bool ok = (std::memcmp(out, expected_output, 32) == 0);
    secure_zero(out, sizeof(out));
    return ok;
}

// vdf_verify_transcript_bounded (F5): resource-policy wrapper. The core verifier
// does one full recomputation (B + N_delay iterations), so a hostile transcript
// with N_delay ~ 2^62 is "valid in shape" yet runs effectively forever -- a
// resource-exhaustion DoS distinct from the abort DoS the core already prevents.
// A ceiling is a DEPLOYMENT policy, not a property of the VDF, so it lives here
// rather than in the core math: the caller supplies its own max_delay (and a
// max_k cap on checkpoint count). Anything above is rejected fail-closed BEFORE
// the expensive loop. Pass max_delay < 0 to disable the delay bound; max_k < 0
// likewise disables the checkpoint-count bound (v7.0.4 doc fix).
inline bool vdf_verify_transcript_bounded(uint64_t seed, int64_t p, int64_t q,
                                          int64_t N_delay, int64_t max_delay,
                                          const VDFCheckpoint* checkpoints, int k,
                                          int max_k,
                                          const uint8_t expected_output[32],
                                          double K = K_DEFAULT) {
    if (max_delay >= 0 && (N_delay < 0 || N_delay > max_delay)) return false;
    if (max_k >= 0 && (k < 0 || k > max_k)) return false;
    return vdf_verify_transcript(seed, p, q, N_delay, checkpoints, k,
                                 expected_output, K);
}

// vdf_verify: recompute and compare. Any party can verify by independent
// recomputation. Fails closed (returns false, never aborts) on any invalid
// parameter or null pointer -- safe to call on fully untrusted (seed,p,q,N,K)
// tuples, matching vdf_verify_transcript's contract.
inline bool vdf_verify(uint64_t seed, int64_t p, int64_t q,
                       int64_t N_delay, const uint8_t* expected,
                       double K = K_DEFAULT) {
    if (expected == nullptr || N_delay < 0) return false;
    if (!mcl_valid_t2_params(seed, p, q, K)) return false;
    VDFResult r = vdf_compute(seed, p, q, N_delay, K);
    return std::memcmp(r.output, expected, 32) == 0;
}

// vdf_verify_bounded (v7.0.4, QA-3): resource-policy twin of
// vdf_verify_transcript_bounded (F5), for the PLAIN verifier. vdf_verify
// recomputes B + N_delay iterations, so a shape-valid hostile claim with
// N_delay ~ 2^62 runs effectively forever even though every parameter passes
// validation -- a resource-exhaustion DoS distinct from the abort DoS that F2
// already closed. As with F5, a ceiling is a DEPLOYMENT policy, not a property
// of the VDF, so it lives in this wrapper: the caller supplies max_delay, and
// anything above it is rejected fail-closed BEFORE the burn-in+delay
// recompute. Pass max_delay < 0 to disable the bound (the caller then owns
// the resource risk).
inline bool vdf_verify_bounded(uint64_t seed, int64_t p, int64_t q,
                               int64_t N_delay, int64_t max_delay,
                               const uint8_t* expected,
                               double K = K_DEFAULT) {
    if (max_delay >= 0 && (N_delay < 0 || N_delay > max_delay)) return false;
    return vdf_verify(seed, p, q, N_delay, expected, K);
}

// ---------------------------------------------------------------------------
// mcl_make_validated_t2: the CORRECT window guard -- validate, don't threshold.
//
// The MCL_T2 constructor enforces the NECESSARY bound K >= K_min(p,q), but it
// cannot see the periodic/quasi-periodic windows that persist ABOVE K_min for
// some topologies (e.g. (3,5) at K~1.22/2.60/3.79/5.73). A blanket K >= 6 floor
// is the WRONG fix: it is both too strict -- (5,7) at K=3.79 measures lambda_1
// ~= 4.5 and (7,11) at K=2.595 ~= 4.4, fully chaotic BELOW 6 -- and merely
// empirical (6.0 is a window-free floor for a tested topology SET, not a
// theorem). The safe K-set is a function of (p,q), so the only correct guard is
// a PER-INSTANCE empirical check on the actual (seed, p, q, K).
//
// This runs a construction-time Lyapunov probe and returns the engine only if
// lambda_1 is CONFIDENTLY above min_lambda: (l1 - sigma*l1_stderr) > min_lambda.
// The statistical margin is what rejects the quasi-periodic windows: their
// lambda_1 ~= 0 with a stderr band straddling 0, so they fail even though they
// PASS a chi^2 byte test (K=3.79 has chi^2 ~= 269, well within uniform, yet
// lambda_1 = 0 -- a chi^2-only guard would wrongly accept it).
//
// Fails closed: returns std::nullopt (never aborts) so the caller decides how to
// react -- and (v7.0.4, QA-2) that promise covers the POLICY arguments too:
// probe_iters <= 0 and non-finite sigma/min_lambda reject as nullopt rather
// than reaching any internal FATAL guard. (Deliberate exception to the
// fail-loud caller-bug convention: this factory IS the fail-closed path.)
// Cost: ~probe_iters extra iterations -- intended for key/VDF SETUP, not
// hot construction. WHAT THIS CERTIFIES: a CONFIDENTLY POSITIVE Lyapunov
// exponent -- i.e. genuine chaos (sensitive dependence), which rejects the
// resonance (lambda<0) and quasi-periodic (lambda~=0) windows. It does NOT
// certify a cryptographic STRENGTH level: min_lambda = 0.0 (default) accepts
// weakly-chaotic instances (e.g. (2,3) at K=1.5 measures lambda~=0.93 --
// legitimately chaotic yet far from K=12's lambda~=5.8). The default is
// deliberately 0.0 (the principled chaos boundary) and NOT a positive "safe"
// constant, because the line between legitimate weak chaos and a window is
// genuinely fuzzy and topology-dependent -- any fixed margin would wrongly
// reject some valid low-K configs. If your deployment needs a strength margin,
// pass an explicit min_lambda (in our (3,5)/(2,3)/(5,7)/(7,11) measurements 1.0
// cleanly separated every window from every healthy config); that threshold is
// YOUR security policy, not ours to hardcode. K defaults to K_DEFAULT (12.0),
// always validated -- the factory earns its keep on a custom K.
inline std::optional<MCL_T2> mcl_make_validated_t2(
        uint64_t seed, int64_t p, int64_t q, double K = K_DEFAULT,
        double min_lambda = 0.0,
        int64_t probe_iters = 2000000,
        double sigma = 6.0) {
    if (!mcl_valid_t2_params(seed, p, q, K)) return std::nullopt;
    // v7.0.4 (QA-2): policy args are fail-closed too -- a probe_iters <= 0
    // must not fall through to compute_lyapunov's FATAL abort.
    if (probe_iters <= 0) return std::nullopt;
    const LyapResult lr = compute_lyapunov(seed, p, q, K, probe_iters);
    if (!(lr.l1 - sigma * lr.l1_stderr > min_lambda)) return std::nullopt;
    return MCL_T2(seed, p, q, K);
}


// ============================================================================
// sec.15 AVALANCHE MEASUREMENT UTILITIES
// (sec.14 is intentionally unused -- historical numbering, preserved so
// that existing cross-references to sec.15-17 stay valid.)

// For measuring chaos propagation depth per mantissa bit position.
// ============================================================================

// Add 1 ULP (Unit in the Last Place) to a double.
// This is the smallest representable increment in IEEE 754.
// Safe only for positive finite values (theta in [0, 2pi) satisfies this).
inline double mcl_add_ulp(double v) noexcept {
    uint64_t bits;
    std::memcpy(&bits, &v, 8);
    bits += 1;
    double result;
    std::memcpy(&result, &bits, 8);
    return result;
}

// ============================================================================
// sec.16 Q30 FIXED-POINT INTEGER ENGINE

// Fully integer MCL implementation:
// - uint32_t phase angles: [0, 2^32) maps to [0, 2pi)
// Modular overflow of uint32_t provides mod 2pi for free.
// - int32_t sin lookup table: 65536 entries in Q30 fixed-point
// Q30 means value = integer / 2^30, range [-1.0, +1.0)
// - int64_t intermediates: prevent overflow in p*theta products
// - ZERO floating-point operations in the iteration hot path
// (mcl_q30_iterate_raw) and the Q30 VDF commitment (sec.16.1); doubles
// appear only in one-time setup (LUT build, K_phase conversion).

// Statistical validation of THIS integer engine: entropy 7.999796
// bits/byte, chi^2 = 282.41, max|r| = 0.002502 across 10 pairwise tests at
// 1M bytes/channel. NOTE: full battery testing (BigCrush / PractRand) of
// the integer Q30 engine is still PENDING. The published BigCrush 160/160
// result (Paper 1, Run 2) was measured on the Float64 two-channel
// multiplex with LUT-based sin -- a DIFFERENT realization; it does NOT
// cover this integer engine.

// Cross-platform bit-exactness validation (April 26, 2026):
// Comprehensive 18-test matrix covering:
// - 2 platforms: Linux x86_64 / glibc-libm
// macOS Apple-Silicon / Apple-libm
// - 3 compilers: GCC 13.3, Apple Clang, LLVM Clang 18.1.3
// - 4 opt levels: -O0, -O1, -O2, -O3 (on both platforms)
// - 3 sanitizers: -fsanitize=undefined, =address,
// =signed-integer-overflow (clean on both platforms)
// - 10 distinct seeds (range: 1 to 2^64 - 1)
// - 8 K values (K in {1, 2, 4, 6, 8, 10, 11, 12})
// - 10,000,000-iteration stability test (no divergence)
// - 10-run reproducibility test (all identical)
// ~1,500 measurement points; every Q30 fingerprint identical:
// For seed = 12345678901234:
// - mcl_q30_init_state: t1 = 0xc8afd74a, t2 = 0x0db2bac6 (all combos)
// - After 10,000 iterations: t1 = 0x6f88c52e, t2 = 0xe06c516c (all combos)
// - LUT CRC-32 (256 KB): 0xde1340cf (all combos)
// Float64 baseline (MCL_T2) for the same seed produces 0xF5E977E0 on
// Linux versus 0x1A734C6F on macOS -- confirming that the test
// discriminates correctly between the libm-dependent Float64 path
// and the libm-independent Q30 path. The Q30 engine is therefore
// suitable as the normative engine for cross-platform bit-exact
// protocols (VDF verification, public auditability, FPGA/ASIC
// reference comparison).

// Use cases:
// - Comparative analysis (LSB Paradox in Paper 1).
// - Constant-time authentication (no libm timing variation).
// - FPGA/ASIC reference (no transcendental hardware needed).
// - Cross-platform bit-exact deployment (the canonical engine for
// any protocol whose verifier is on a different platform from the
// prover).

// KEYED fixed-point realization: the 72-byte, FPU-free keyed engine
// MCL_T4_Q30 (256-bit master key -> twelve Q30 integer coupling weights;
// the Category-5 configuration referenced in Papers 4/5) is implemented in
// the companion sidecar header keyed_q30_PQ/mcl_keyed_q30.hpp, kept
// separate as Patent-4-gated material; it ships alongside this header in
// the public release after filing. THIS file provides the keyed Float64
// realization (mcl_t4_from_key, sec.4) and the raw Q30 substrate below.
// ============================================================================

// Static sin lookup table (shared across all Q30 instances)

// Cross-platform reproducibility: the LUT must be deterministic across
// libm implementations for the bit-exactness claim of sec.16 to hold. The
// std::sin() approach below IS reproducible for this LUT. Note that ~6676
// entries lie within 0.05 of a truncation boundary and the two sin extrema
// (i=16384, 49152) land EXACTLY on the boundary 2^30 -- yet none of this
// endangers reproducibility. The reasons it is robust (all measured
// directly):
// (1) The sin extrema evaluate to EXACTLY +/-1.0 (the true value 1 - ~2e-33
//     is within half a ULP of 1.0, so any sane libm returns 1.0 exactly);
//     sin*2^30 = +/-2^30 exactly, identical everywhere.
// (2) The zero crossing (i=32768, sin~1.3e-7) is immune under truncation
//     toward zero: every value in (-1,1) truncates to 0 regardless of sign.
// (3) The 1-ULP sin error is ~2.4e-7 in scaled units; the closest GENUINE
//     (non-special) entry sits 1.67e-5 from a boundary -- a ~70x margin.
// Net: ZERO entries are flippable by a 1-ULP libm difference. The runtime
// LUT is robustly cross-platform for any faithfully-rounded libm.

// Empirically validated: Linux x86_64 / glibc-libm / GCC 13.3 and
// macOS Apple-Silicon / Apple-libm / Clang -O3 produce LUTs with
// identical CRC-32 = 0xde1340cf over the full 256 KB LUT bytes.

// For deployments that demand a guaranteed bit-exact LUT regardless
// of libm behavior (e.g., adversarial cross-platform deployment, or
// audit environments where even ULP-level libm differences must be
// excluded), define MCL_Q30_USE_STATIC_LUT before including this
// header and provide the static array (see q30_lut_constants.hpp in
// the companion bundle).
struct MCL_Q30_Table {
    int32_t lut[65536];
    MCL_Q30_Table() {
        for (int i = 0; i < 65536; i++) {
            double angle = MCL_TWO_PI * (double)i / 65536.0;
 lut[i] = (int32_t)(std::sin(angle) * 1073741824.0); // 2^30
        }
    }
 // CACHE-TIMING NOTE: lut access is indexed by
 // `angle >> 16` where angle depends on the secret state. The full
 // table is 256 KB (65536 * 4 bytes), which exceeds typical L1 cache
 // (32-64 KB) but fits in L2/L3. An attacker with shared-CPU access
 // (e.g., colocated VM, hyperthreading) and fine-grained timing
 // measurement could potentially recover bits of the index from
 // cache-hit timing differences. MITIGATIONS for high-stakes use:
 // 1. Run MCL in an isolated CPU/process
 // 2. Use the constant-time Float64 path (does not use this LUT)
 // 3. On hardware: pre-warm the entire LUT before authentication
 // This is a known limitation of LUT-based sin approximation, shared
 // by AES T-tables (resolved in modern impls via AES-NI). MCL's LUT
 // version is intended for embedded / FPGA targets where constant-time
 // double precision is unavailable.
    int32_t sin_q30(uint32_t angle) const { return lut[angle >> 16]; }
};

inline const MCL_Q30_Table& mcl_q30_table() {
    static MCL_Q30_Table t;
    return t;
}

// omega_1, omega_2 as uint32_t constants (computed once)
inline uint32_t mcl_q30_omega1() {
    static const uint32_t w = (uint32_t)(OMEGA_1 / MCL_TWO_PI * 4294967296.0);
    return w;
}
inline uint32_t mcl_q30_omega2() {
    static const uint32_t w = (uint32_t)(OMEGA_2 / MCL_TWO_PI * 4294967296.0);
    return w;
}

// Raw single-step Q30 iterate on uint32_t state (no engine needed).
// Gauss-Seidel: t2 uses updated t1. Zero floating-point in hot path.
// K_phase = (int64_t)(K_real * 2^32 / 2pi) -- K expressed in phase units.
// Valid for K <= 12 (the enforced cap). int64_t overflow in the product
// K_phase * sin_q30 begins at K ~= 12.566 (measured: K_phase*2^30 reaches
// INT64_MAX at K = 12.566; K = 12.6 overflows). The K <= 12 cap therefore
// leaves only ~5% headroom -- do NOT raise it toward an imagined 13.x bound.

// PARAMETER OVERFLOW BOUND
// The expression (int64_t)p * (int64_t)t2 with t2 in [0, 2^32) requires
// p < 2^31 to fit in int64_t. The subtraction p*t2 - q*t1 can amplify
// by 2x in worst case, so we require p, q <= MCL_Q30_PQ_MAX = 2^30.

// The nominal range [2, 2^62] describes
// the IDENTITY space (number of distinct device IDs). The Q30 engine
// implements the OPERATIONAL range. This is consistent with MCL Tech
// Reference sec.11.1 (identity space != security level).

// Callers using p > 2^30 in Q30 mode will trigger an assertion / abort;
// they should use the Float64 path (mcl_iterate_raw) which tolerates
// larger p with graceful precision degradation.
// -fsanitize=integer flags the deliberate uint32_t wrap
// in `t += omega + inc`. This wrap is the Q30 mod-2^32 arithmetic -- the WHOLE
// POINT of the integer engine. Suppress the sanitizer here using the
// __attribute__((no_sanitize)) form, which is recognized by Clang.
// GCC ignores unknown attributes silently, which is the correct behavior.

// CAVEAT: this raw Q30 path does NOT enforce:
// - p != q (caller must check)
// - gcd(p,q) = 1 (caller must check)
// - K_phase above K_min (chaoticity)
// This is intentional: mcl_q30_iterate_raw is a low-level building block
// for expert callers who need fine control. The MCL_T2/MCL_T2_Omega/etc.
// classes wrap it with full validation. End-user code should use those
// classes, not call mcl_q30_iterate_raw directly.
#if defined(__clang__)
__attribute__((no_sanitize("integer")))
#endif
inline void mcl_q30_iterate_raw(uint32_t& t1, uint32_t& t2,
                                 int64_t p, int64_t q, int64_t K_phase) {
 // Q30 parameter bounds check -- survives NDEBUG via the runtime guard
 // pattern used elsewhere in this file (see MCL_T2 constructor).
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
    assert(p > 0 && q > 0 && p <= MCL_Q30_PQ_MAX && q <= MCL_Q30_PQ_MAX
           && "Q30: p, q must be in (0, 2^30]");
    if (p <= 0 || q <= 0 || p > MCL_Q30_PQ_MAX || q > MCL_Q30_PQ_MAX) {
        std::fprintf(stderr,
            "FATAL: mcl_q30_iterate_raw p=%lld, q=%lld out of [1, 2^30] "
            "(use Float64 path for larger parameters)\n",
            (long long)p, (long long)q);
        std::abort();
    }
#endif
    const MCL_Q30_Table& tab = mcl_q30_table();
 // Note on signed*unsigned cast: t2 is uint32_t, but (int64_t)t2 widens
 // to a non-negative int64_t with a value <= 2^32-1. With p <= 2^30, the
 // product p*t2 <= 2^62, well within int64_t range. The subtraction
 // p*t2 - q*t1 produces a value in [-2^62, 2^62], safely representable.
    uint32_t a1 = (uint32_t)((int64_t)p * (int64_t)t2
                            - (int64_t)q * (int64_t)t1);
 // K_phase x sin_q30(a1) is in Q30-phase hybrid:
 // K_phase has units [phase_int/radian], sin_q30 has units [Q30]
 // Product has units [phase_int x Q30], shift >>30 -> [phase_int]
    // v7.0.0 fully-defined-behavior form (bit-identical output, verified
    // against all frozen Q30 fingerprints and KATs): the signed product P
    // is converted to uint64_t (defined: reduction mod 2^64), logically
    // shifted, and truncated mod 2^32. For every int64 value P:
    //   (uint32_t)((uint64_t)P >> 30) == (uint32_t)(P >> 30)   [arithmetic]
    // because for negative P the logical shift adds exactly 2^34, and
    // 2^34 mod 2^32 = 0. This removes the previous reliance on arithmetic
    // right-shift of a negative value and on out-of-range int64 -> int32
    // narrowing, both implementation-defined until C++20.
    uint32_t inc1 = (uint32_t)(
        (uint64_t)((int64_t)K_phase * (int64_t)tab.sin_q30(a1)) >> 30);
    t1 += mcl_q30_omega1() + inc1;

    uint32_t a2 = (uint32_t)((int64_t)p * (int64_t)t1
                            - (int64_t)q * (int64_t)t2);
    uint32_t inc2 = (uint32_t)(
        (uint64_t)((int64_t)K_phase * (int64_t)tab.sin_q30(a2)) >> 30);
    t2 += mcl_q30_omega2() + inc2;
}

// Compute K_phase from K_real.
// Valid for K_real <= 12.0 (enforced). The product K_phase x sin_q30 in
// mcl_q30_iterate_raw reaches INT64_MAX at K ~= 12.566 and overflows beyond
// it; the 12.0 cap leaves ~5% headroom.
inline int64_t mcl_q30_K_phase(double K_real) {
    // NaN/Inf guard is UNCONDITIONAL (outside MCL_UNSAFE_ALLOW_INVALID):
    // research mode permits weak/degenerate DYNAMICAL parameters, but never a
    // non-finite K, which would make the float->int64 cast below undefined
    // behavior. A NaN slips past the (K<=0 || K>12) test below because every
    // comparison with NaN is false.
    if (!std::isfinite(K_real)) {
        std::fprintf(stderr, "FATAL: mcl_q30_K_phase K=%.17g must be finite\n",
            K_real);
        std::abort();
    }
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
    assert(K_real > 0.0 && K_real <= 12.0
        && "K_phase: K must be finite and in (0, 12] (int64_t overflow at K ~= 12.566)");
    if (K_real <= 0.0 || K_real > 12.0) {
        std::fprintf(stderr, "FATAL: mcl_q30_K_phase invalid K=%.17g "
            "(must be in (0, 12])\n", K_real);
        std::abort();
    }
#endif
    return (int64_t)(K_real * 4294967296.0 / MCL_TWO_PI);
}

// Initialize Q30 state from seed (matches MCL_T2 initialization logic).

// CRITICAL: The naive cast (uint32_t)((double)s * norm * 2^32) is
// undefined behavior in C++ when the double value exceeds 2^32. For
// seeds > 2^29 (typical hashed values are uint64_t-scale), the product
// can reach ~10^21, which is far outside the uint32_t range, leading
// to compiler-dependent results: -O0 may yield 0x00000000, -O3 may
// yield 0xFFFFFFFF, and behavior is undefined per the standard.

// We therefore reduce the value modulo 2^32 first, in a way that is
// itself bit-exact across platforms: split the seed into two 32-bit
// halves and use 64-bit integer multiplication. The result is the
// LOWER 32 bits of (s x OMEGA_QN_1) where OMEGA_QN_1 is the angular
// frequency expressed as a Q.32 fraction (i.e., omega/2pi x 2^32).
// (Low 32 bits == phase mod 2^32; the code below takes prod & 0xFFFFFFFF.
// Verified: this reproduces the documented init fingerprint t1=0xc8afd74a,
// t2=0x0db2bac6 for seed 12345678901234. The high 32 bits would NOT.)

// This implementation:
// - Eliminates the float->uint UB entirely.
// - Is bit-exact regardless of optimization level (-O0/-O2/-O3).
// - Is bit-exact across platforms (integer arithmetic only).
// - Reproduces MCL_T2's float64 initial conditions to within
// truncation precision (the Q30 engine intentionally truncates
// phase to 32 bits; this is by design).
inline void mcl_q30_init_state(uint64_t seed, uint32_t& t1, uint32_t& t2) {
    uint64_t s = hash_seed(seed);

 // Q.32 angular-frequency constants (TRUNCATING cast in mcl_q30_omega1/2,
 // matching the validated fingerprints):
 // OMEGA_Q32_1 = trunc(OMEGA_1 / 2pi x 2^32) = mcl_q30_omega1()
 // OMEGA_Q32_2 = trunc(OMEGA_2 / 2pi x 2^32) = mcl_q30_omega2()
 // Both are < 2^32, so the cast in mcl_q30_omega1/2 is safe.
    uint64_t w1 = (uint64_t)mcl_q30_omega1();
    uint64_t w2 = (uint64_t)mcl_q30_omega2();

 // Compute s x w (mod 2^64) using built-in 64-bit multiplication.
 // The lower 64 bits of the full product s x w are sufficient: we
 // only need the result modulo 2^32, and the high half of the
 // 128-bit product is discarded after the modular reduction.

 // s in [0, 2^64) and w in [0, 2^32), so s x w in [0, 2^96).
 // The low 64 bits ((s x w) mod 2^64) capture all the information
 // we need modulo 2^32:
 // ((s x w) mod 2^64) mod 2^32 == ((s x w) mod 2^32)

 // Wraparound in 64-bit unsigned multiplication is well-defined
 // by the C++ standard (unlike signed overflow), so this is
 // bit-exact across all platforms and optimization levels.
    uint64_t prod1 = s * w1;
    uint64_t prod2 = s * w2;

    t1 = (uint32_t)(prod1 & 0xFFFFFFFFULL);
    t2 = (uint32_t)(prod2 & 0xFFFFFFFFULL);
}

// ============================================================================
// sec.16.1 Q30 VERIFIABLE DELAY FUNCTION (cross-platform bit-exact)
// ============================================================================
// WHY THIS EXISTS (added in 6.0.0):
// The Float64 VDF in sec.13 (vdf_compute / vdf_verify) uses MCL_T2, whose
// std::sin() output differs at the ULP level between libm implementations
// (glibc vs Apple-libm -- see the dual-column KAT table below). Because the
// MCL map is chaotic (lambda_GS ~= 5.78), a single 1-ULP sin() difference
// diverges the trajectory completely within a few thousand iterations.
// CONSEQUENCE: a proof produced by vdf_compute() on one platform will NOT
// verify under vdf_verify() on a different-libm platform. That breaks the
// defining VDF property of universal (cross-platform) verifiability.
//
// This Q30 variant performs the SAME Gauss-Seidel sequential delay using the
// integer LUT engine (mcl_q30_iterate_raw), which is bit-identical across
// platforms (the sin LUT is platform-independent; see sec.16). It is the
// engine that should back any VDF whose verifier may run on a different
// platform / FPGA / ASIC from the prover.
//
// OUTPUT DEFINITION: rather than invent a Goldilocks-style byte extractor for
// the 32-bit phase state, the output is a direct 32-byte commitment to the
// sequentially-computed final state: four post-delay iterations, each
// serializing (t1,t2) little-endian VIA SHIFTS (so the bytes are also
// byte-order independent, unlike the d2b/memcpy Float64 path). This is a
// deterministic, integer-only, endian-independent function of the delay
// computation -- exactly what a VDF commitment needs.
//
// RANGE: mcl_q30_iterate_raw enforces p,q in [1, 2^30] and mcl_q30_K_phase
// enforces K in (0, 12]. These are the documented Q30 OPERATIONAL bounds
// (see MCL_Q30_PQ_MAX). For p,q > 2^30 the Float64 VDF must be used, and
// cross-platform verification is then NOT available (same-platform only).
//
// PARAMETER CONTRACT: this function enforces the SAME dynamical contract as
// the Float64 vdf_compute (which gets it from the MCL_T2 ctor): p,q >= 2,
// p != q, K >= K_min(p,q). The raw Q30 primitive deliberately does NOT check
// these (it is an expert building block), so vdf_compute_q30 adds the guard
// itself -- otherwise a VDF could be built on degenerate params (e.g. p==q).
//
// *** SECURITY WARNING (v8.1.2, 2026-08-22) -- RETIRED FROM EVERY VDF ROLE ***
// This two-oscillator raw-state path is NOT a usable VDF and is kept ONLY as
// a cross-platform DETERMINISM vector (Paper 4, Vector 4) and for the
// self-cryptanalysis record. Two measured breaks:
//   (1) cycle: at (3,5), K=12 the orbit closes at lambda = 1,671,196,332
//       (~2^30.6), so any N beyond the cycle scale is a ~constant-time shortcut;
//   (2) related inputs: every coupling argument is (p*t_j - q*t_i) mod 2^32,
//       so state translations b with p*b_2 == q*b_1 and p*b_1 == q*b_2 commute
//       with the map forever. For (3,5) that is an order-16 group
//       ((p^2-q^2)*a == 0 -> a = k*2^28), and because hash_seed(s) == s for
//       s <= 2^52 and t_i = s*omega_i, ALL 15 non-trivial elements are
//       reachable by seed offsets D = k*2^28*omega1^-1 (mod 2^32):
//       output(seed + D) == output(seed) + (a,b) word for word -- verified
//       (HD 20/256, N = 1e5). Sequential work is therefore not enforced for
//       the 15 related inputs of every seed.
// Use VDF128-T4 (VDF128_T4/mcl_vdf128_t4.hpp: SHA-256 input injection, 128-bit
// state, SHA-256-finalised output, public weights with a trivial symmetry group)
// for any VDF deployment. Record: T4_CycleStructure/T4_CYCLE_RECORD_20260822.md.
inline VDFResult vdf_compute_q30(uint64_t seed, int64_t p, int64_t q,
                                 int64_t N_delay, double K = K_DEFAULT) {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
    assert(N_delay >= 0 && "VDF delay must be non-negative");
    assert(p >= 2 && q >= 2 && p != q && "vdf_compute_q30: need p,q>=2 and p!=q");
    assert(p <= MCL_Q30_PQ_MAX && q <= MCL_Q30_PQ_MAX
        && "vdf_compute_q30: p,q must be <= 2^30 (Q30 operational range)");
    if (N_delay < 0) {
        std::fprintf(stderr, "FATAL: vdf_compute_q30 delay must be non-negative "
            "(N=%lld)\n", (long long)N_delay);
        std::abort();
    }
    // Coupling-weight contract (mirror MCL_T2): 2 <= p,q <= 2^30, p != q.
    // The raw Q30 primitive only checks p,q in [1,2^30] and never p!=q, so a
    // VDF on degenerate weights (p==q, or p/q == 1) would otherwise run.
    if (p < 2 || q < 2 || p == q || p > MCL_Q30_PQ_MAX || q > MCL_Q30_PQ_MAX) {
        std::fprintf(stderr, "FATAL: vdf_compute_q30 invalid coupling weights "
            "(p=%lld, q=%lld). Required: 2 <= p,q <= 2^30, p != q.\n",
            (long long)p, (long long)q);
        std::abort();
    }
    // Chaos threshold (mirror MCL_T2's K_min(p,q) check). K finiteness and the
    // (0,12] range are handled by mcl_q30_K_phase below; here we only reject a
    // finite, positive K that is nonetheless below the chaotic floor.
    {
        const double K_min_pq = MCL_K_MIN_NUMERATOR / ((double)p + (double)q);
        if (std::isfinite(K) && K > 0.0 && K < K_min_pq) {
            std::fprintf(stderr, "FATAL: vdf_compute_q30 K=%.6g below K_min=%.6g "
                "for (p=%lld, q=%lld) -- non-chaotic regime (lambda_max < 0).\n",
                K, K_min_pq, (long long)p, (long long)q);
            std::abort();
        }
    }
#endif
    VDFResult result;
    result.iterations = N_delay;
    auto t0 = std::chrono::steady_clock::now();

    uint32_t t1, t2;
    mcl_q30_init_state(seed, t1, t2);          // calls hash_seed (cross-platform)
    const int64_t kp = mcl_q30_K_phase(K);     // enforces K in (0,12]

    // Phase 1: burn-in (B = BURNIN), matching the Float64 VDF structure.
    for (int i = 0; i < BURNIN; i++) mcl_q30_iterate_raw(t1, t2, p, q, kp);
    // Phase 2: delay iterations (N, operator-selected) -- strictly sequential.
    for (int64_t i = 0; i < N_delay; i++) mcl_q30_iterate_raw(t1, t2, p, q, kp);

    // Phase 3: 32-byte commitment to the final state (endian-independent).
    for (int b = 0; b < 4; b++) {
        mcl_q30_iterate_raw(t1, t2, p, q, kp);
        for (int k = 0; k < 4; k++) result.output[b * 8 + k]     = (uint8_t)(t1 >> (k * 8));
        for (int k = 0; k < 4; k++) result.output[b * 8 + 4 + k] = (uint8_t)(t2 >> (k * 8));
    }

    result.elapsed_sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    return result;
}

// mcl_valid_q30_vdf_params (v7.0.3, QA-1): shared fail-closed predicate
// mirroring vdf_compute_q30's PRODUCTION contract exactly -- the shared
// dynamical contract (seed != 0, p,q >= 2, p != q, finite K > 0, K >=
// K_min(p,q); see mcl_valid_t2_params) plus the two Q30-specific bounds:
// p,q <= MCL_Q30_PQ_MAX (2^30 operational range) and K <= 12.0 (the
// mcl_q30_K_phase cap; int64 phase overflow at K ~= 12.566). Like the Float64
// predicate, this enforces the production contract even in a
// MCL_UNSAFE_ALLOW_INVALID build: a verifier of untrusted claims never
// loosens its contract for research convenience.
inline bool mcl_valid_q30_vdf_params(uint64_t seed, int64_t p, int64_t q,
                                     double K) noexcept {
    if (!mcl_valid_t2_params(seed, p, q, K)) return false;
    if (p > MCL_Q30_PQ_MAX || q > MCL_Q30_PQ_MAX) return false;
    return K <= 12.0;
}

// vdf_verify_q30: recompute via the integer engine and compare. Unlike
// vdf_verify (Float64), this verifies correctly ACROSS platforms. Fails closed
// (returns false, never aborts, never dereferences null) on any invalid
// parameter or null pointer -- safe to call on fully untrusted
// (seed,p,q,N,K) tuples, matching vdf_verify / vdf_verify_transcript.
// (v7.0.3, QA-1: previously this forwarded hostile tuples straight into
// vdf_compute_q30's fprintf+abort guards -- an abort-DoS in the one verifier
// documented for cross-platform use -- and memcmp'd through a null
// `expected`, a SEGV in release builds.)
inline bool vdf_verify_q30(uint64_t seed, int64_t p, int64_t q,
                           int64_t N_delay, const uint8_t* expected,
                           double K = K_DEFAULT) {
    if (expected == nullptr || N_delay < 0) return false;
    if (!mcl_valid_q30_vdf_params(seed, p, q, K)) return false;
    VDFResult r = vdf_compute_q30(seed, p, q, N_delay, K);
    return std::memcmp(r.output, expected, 32) == 0;
}

// vdf_verify_q30_bounded (v7.0.4, QA-3): resource-policy twin for the Q30
// (cross-platform) verifier -- same rationale and convention as
// vdf_verify_bounded above: caller-supplied N_delay ceiling, rejected
// fail-closed before the recompute; max_delay < 0 disables the bound.
inline bool vdf_verify_q30_bounded(uint64_t seed, int64_t p, int64_t q,
                                   int64_t N_delay, int64_t max_delay,
                                   const uint8_t* expected,
                                   double K = K_DEFAULT) {
    if (max_delay >= 0 && (N_delay < 0 || N_delay > max_delay)) return false;
    return vdf_verify_q30(seed, p, q, N_delay, expected, K);
}

// ============================================================================
// KNOWN ANSWER TESTS (KAT) — engine self-validation
// ============================================================================
// Per FIPS 140-3 self-test guidance, a cryptographic engine should expose
// a deterministic self-test that detects build/link/precision regressions
// before the engine is used in production. mcl_self_test() generates a
// fixed byte sequence from each KAT entry, computes its CRC-32, and
// compares against the reference value below. A mismatch indicates either
// (a) an unexpected build configuration (e.g. -ffast-math leaking in),
// (b) a libm difference (Apple-libm vs glibc-libm — see PLATFORM NOTE),
// or (c) a regression in mcl_core.hpp itself.
//
// PLATFORM NOTE on cross-platform reproducibility:
// The reference CRC values below were computed on Linux x86_64 with
// glibc-libm. macOS Apple Silicon uses Apple-libm (Accelerate framework)
// which produces ULP-level different sin() values than glibc; the byte
// stream therefore differs at the bit level even though the engine is
// deterministic on each platform individually. This is documented in
// Paper 1 Section IV.C and is the rationale for the optional Q30 (lookup-
// table sin) path which IS bit-identical across all platforms. The
// math.h sin() path used by these KATs is per-platform deterministic.
//
// USAGE:
//   if (!mcl_self_test()) { /* engine is misbuilt; abort */ }
//
// ADDING NEW KATS:
// Run the KAT generator (separate file, not included here) on a clean
// reference build to obtain the CRC, then append to mcl_kat_vectors[].
// Document both the platform and the engine version when adding.

struct MCL_KAT {
    uint32_t expected_crc_glibc; // CRC-32 on Linux x86_64 with glibc-libm
    uint32_t expected_crc_apple; // CRC-32 on macOS with Apple-libm
    uint64_t seed;
    int64_t  p;
    int64_t  q;
    size_t   n_bytes;
    const char* description;
};

// Dual-platform reference vectors. Both columns were originally computed on
// mcl_core.hpp v4.1.0 and re-validated through the 7.0.0 release (guard,
// erasure, and comment changes never alter numerical output for valid
// parameters; v7.0.0 additionally re-verified byte-identity against v6.1.0
// with a differential harness across every engine and path). The two
// CRCs differ because of
// ULP-level sin() differences between glibc-libm and Apple-libm; this is
// a known consequence of the math.h sin() path and is documented in
// Paper 1 Section IV.C. The Q30 lookup-table sin path (separate engine)
// produces bit-identical output across all platforms.
//
// Platform detection at compile time:
//   - __APPLE__ is defined on macOS / Darwin
//   - otherwise we assume glibc-libm (Linux x86_64, x86_64 BSD, etc.)
// On Apple Intel + Homebrew gcc, behavior depends on whether the gcc
// build links against Apple's libm or its own libm. The safer default
// on Apple platforms is the Apple-libm column.
inline constexpr MCL_KAT mcl_kat_vectors[] = {
    // glibc CRC   Apple CRC   seed                p   q   n_bytes  description
    {0xAFCF498F, 0x96C7D876, 12345678901234ULL,  3,  5,    1000, "T2 default seed, (3,5), 1KB"},
    {0xF5E977E0, 0x1A734C6F, 12345678901234ULL,  3,  5,   10000, "T2 default seed, (3,5), 10KB"},
    {0x97B8173B, 0x5C36C100, 12345678901234ULL,  3,  5,  100000, "T2 default seed, (3,5), 100KB"},
    {0x02D63EB8, 0x32119B53,         12345ULL,  3,  5,    1000, "T2 seed=12345, (3,5), 1KB"},
    {0x1B9C1486, 0xD7A3318B,         12345ULL,  7, 11,    1000, "T2 seed=12345, (7,11), 1KB"},
    {0x328F1E2F, 0xE2E24E6D, 31415926535897ULL,  3,  5,   10000, "T2 pi-seed, (3,5), 10KB"},
    {0x448EE93C, 0x8D4A3A4E, 27182818284590ULL,  3,  5,   10000, "T2 e-seed, (3,5), 10KB"},
};

// Returns the expected CRC for the current platform (compile-time selected).
inline constexpr uint32_t mcl_kat_expected_crc(const MCL_KAT& k) {
#if defined(__APPLE__)
    return k.expected_crc_apple;
#else
    return k.expected_crc_glibc;
#endif
}

// Human-readable platform identifier (for self-test diagnostic output).
inline constexpr const char* mcl_kat_platform() {
#if defined(__APPLE__)
    return "Apple-libm";
#else
    return "glibc-libm";
#endif
}

inline constexpr size_t mcl_kat_count() {
    return sizeof(mcl_kat_vectors) / sizeof(mcl_kat_vectors[0]);
}

// Returns true iff every KAT in mcl_kat_vectors[] reproduces its expected
// CRC. On failure, prints a diagnostic line per failing vector to stderr
// (silent on success, suitable for use in production startup checks).
//
// Cost: ~150 ms total on a modern CPU (dominated by the 100KB vector;
// remove that vector for ~10 ms total if startup latency matters).
inline bool mcl_self_test() {
    bool all_pass = true;
    for (size_t i = 0; i < mcl_kat_count(); i++) {
        const MCL_KAT& k = mcl_kat_vectors[i];
        MCL_T2 g(k.seed, k.p, k.q);
        // Stack buffer would limit to small vectors; use heap for flexibility.
        std::vector<uint8_t> buf(k.n_bytes);
        // gen_bytes() expects int64_t; cast from size_t (n_bytes is bounded).
        g.gen_bytes(buf.data(), static_cast<int64_t>(k.n_bytes));
        uint32_t got = compute_crc32(buf.data(), k.n_bytes);
        uint32_t expected = mcl_kat_expected_crc(k);
        if (got != expected) {
            std::fprintf(stderr,
                "MCL self-test FAIL [%zu/%zu] (%s): %s\n"
                "  expected=0x%08X got=0x%08X (seed=%llu, p=%lld, q=%lld, n=%zu)\n",
                i + 1, mcl_kat_count(), mcl_kat_platform(), k.description,
                expected, got,
                (unsigned long long)k.seed,
                (long long)k.p, (long long)k.q, k.n_bytes);
            all_pass = false;
        }
    }

    // v6.0.0: PLATFORM-INDEPENDENT checks. The Float64 KATs above are per-libm
    // (dual-column) and all use seeds <= 2^52, so they never exercise the
    // hash_seed() large-seed branch and never validate the integer Q30 engine.
    // The two checks below close both gaps with constants that are identical on
    // EVERY platform (integer-only / LUT-based), so they need no Apple column.

    // (a) Q30 sin LUT integrity. A divergent libm (or a miscompiled LUT) would
    //     silently break Q30 cross-platform bit-exactness; catch it here.
    {
        const MCL_Q30_Table& tab = mcl_q30_table();
        uint32_t lut_crc = compute_crc32(
            reinterpret_cast<const uint8_t*>(tab.lut), sizeof(tab.lut));
        if (lut_crc != 0xDE1340CFu) {
            std::fprintf(stderr,
                "MCL self-test FAIL (Q30 LUT): expected CRC=0xDE1340CF got=0x%08X "
                "-- libm sin() at the LUT build step disagrees with the reference; "
                "Q30 output will NOT be cross-platform bit-exact on this build.\n",
                lut_crc);
            all_pass = false;
        }
    }

    // (b) Q30 VDF KAT with a seed > 2^52 -> exercises hash_seed()'s MurmurHash
    //     branch (the path used by full-entropy 64-bit auth challenges) AND the
    //     integer Q30 delay engine + commitment output. Platform-independent.
    {
        const uint64_t BIG = 123456789012345678ULL; // > 2^52 (= 4.5e15)
        VDFResult r = vdf_compute_q30(BIG, 3, 5, 1000, 12.0);
        uint32_t got = compute_crc32(r.output, 32);
        if (got != 0x69B7BA8Au) {
            std::fprintf(stderr,
                "MCL self-test FAIL (Q30 VDF, seed>2^52): expected CRC=0x69B7BA8A "
                "got=0x%08X (seed=%llu, (3,5), N=1000)\n",
                got, (unsigned long long)BIG);
            all_pass = false;
        }
    }

    // v6.1.0: 256-BIT KEYED POST-QUANTUM PATH KATs (all platform-independent:
    // SHA-256 + integer KDF + integer parameter derivation are libm-free).

    // (c) SHA-256 against the FIPS 180-4 "abc" gold vector.
    {
        uint8_t h[32];
        mcl_sha256(reinterpret_cast<const uint8_t*>("abc"), 3, h);
        static const uint8_t want[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
        if (std::memcmp(h, want, 32) != 0) {
            std::fprintf(stderr, "MCL self-test FAIL (SHA-256 abc KAT): "
                "implementation disagrees with FIPS 180-4.\n");
            all_pass = false;
        }
    }

    // (d) Keyed derivation KAT for the fixed test key {0,1,...,31}: locks the
    //     SHA-256 KDF and the T2/T4 integer parameter mapping (labels included).
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

        uint8_t kd[64];
        mcl_kdf256(key, "MCL-KAT", nullptr, 0, kd, 64);
        uint32_t kdf_crc = compute_crc32(kd, 64);
        if (kdf_crc != 0x973472CAu) {
            std::fprintf(stderr, "MCL self-test FAIL (KDF KAT): expected "
                "CRC=0x973472CA got=0x%08X\n", kdf_crc);
            all_pass = false;
        }

        MCL_KeyedParamsT2 t2 = mcl_t2_params_from_key(key, 0);
        if (t2.p != 865118605453148LL || t2.q != 3657781221074353LL
            || gcd_compute(t2.p, t2.q) != 1) {
            std::fprintf(stderr, "MCL self-test FAIL (keyed T2 params): "
                "got p=%lld q=%lld (expected 865118605453148, 3657781221074353, coprime)\n",
                (long long)t2.p, (long long)t2.q);
            all_pass = false;
        }

        CouplingSextet cs = mcl_t4_params_from_key(key, 0);
        uint32_t t4_crc = compute_crc32(reinterpret_cast<const uint8_t*>(&cs), sizeof(cs));
        if (t4_crc != 0xC03CD1D4u) {
            std::fprintf(stderr, "MCL self-test FAIL (keyed T4 weights): "
                "expected CRC=0xC03CD1D4 got=0x%08X\n", t4_crc);
            all_pass = false;
        }
    }

    // (e) Post-quantum accounting sanity: keyed T4 (256-bit secret) meets NIST
    //     PQ Category 5 (highest); keyed T2 (~208-bit) meets Category 3 but not
    //     Category 5; the default single-(p,q) path meets no category.
    if (!mcl_pq_security(256.0).meets_category5
        || mcl_pq_security(208.0).meets_category5
        || !mcl_pq_security(208.0).meets_category3
        || mcl_pq_security(mcl_pair_secret_bits(1e9)).meets_category1) {
        std::fprintf(stderr, "MCL self-test FAIL (PQ accounting): "
            "mcl_pq_security category thresholds inconsistent with NIST "
            "(Cat1/3/5 = 64/96/128 post-Grover).\n");
        all_pass = false;
    }

    // (f) v7.0.0: VDF transcript verification -- one positive control and
    //     three negative controls (tampered checkpoint, tampered output,
    //     wrong-seed forgery: the historical vdf_verify_segment soundness
    //     gap). Platform-independent logic: the transcript is produced and
    //     verified in-process with the same libm, so no fixed vectors are
    //     needed.
    {
        VDFCheckpoint cps[4];
        int written = 0;
        VDFResult r = vdf_compute_checkpointed(DEFAULT_SEED, 3, 5, 1000,
                                               cps, 4, K_DEFAULT, &written);
        bool pos = (written == 4)
            && vdf_verify_transcript(DEFAULT_SEED, 3, 5, 1000, cps, 4,
                                     r.output);
        VDFCheckpoint saved = cps[1];
        cps[1].theta1 = mcl_add_ulp(cps[1].theta1);
        bool bad_cp = vdf_verify_transcript(DEFAULT_SEED, 3, 5, 1000, cps, 4,
                                            r.output);
        cps[1] = saved;
        uint8_t tampered[32];
        std::memcpy(tampered, r.output, 32);
        tampered[0] ^= 0x01;
        bool bad_out = vdf_verify_transcript(DEFAULT_SEED, 3, 5, 1000, cps, 4,
                                             tampered);
        bool forged = vdf_verify_transcript(DEFAULT_SEED + 1, 3, 5, 1000,
                                            cps, 4, r.output);
        if (!pos || bad_cp || bad_out || forged) {
            std::fprintf(stderr,
                "MCL self-test FAIL (VDF transcript): pos=%d tampered_cp=%d "
                "tampered_out=%d forged=%d (want 1,0,0,0)\n",
                pos ? 1 : 0, bad_cp ? 1 : 0, bad_out ? 1 : 0, forged ? 1 : 0);
            all_pass = false;
        }
    }

    return all_pass;
}


// ============================================================================
// sec.17 ONE-WAYNESS STRUCTURAL EVIDENCE (empirical -- documentation only)
//
// The hierarchical key derivation (sec.12) relies on the engine's inverse
// map being hard to invert. A positive Lyapunov exponent (sec.7) establishes
// forward sensitivity but does NOT establish backward one-wayness. The
// quantitative backing below comes from preimage-counting and information
// measurements performed in the extraction-security test harness.
//
//   measured property            value          role
//   ------------------------------------------------------------------------
//   forward preimage branching   b   ~= 38/step  necessary condition (b^2 ~= 1444)
//   constrained branching        b_eff ~= 6.5 > 1 *critical* one-wayness quantity
//   window independence          MI(A;B) ~= 0    confirms non-injectivity
//   avalanche (bits>=20 -> out)  0.50            full diffusion to output bits
//
// Interpretation: b_eff > 1 means that even after fixing the observable
// output, more than one parent preimage remains consistent at each step;
// the number of candidate histories grows rather than collapses, so the
// derivation cannot be run backward to a unique parent.
//
// SCOPE: this is empirical structural evidence, NOT a cryptographic proof
// of one-wayness. The LSB-absorption artifact noted in the test harness
// (output reads bits >= 20; the absorbed bit never reaches the output) has
// zero effect on the production engine and is documented under Exp5.
// ============================================================================

#endif // MCL_CORE_HPP
