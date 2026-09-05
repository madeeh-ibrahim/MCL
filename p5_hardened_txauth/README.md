# p5_hardened_txauth — مسار الورقة 5 المصلَّد (v2) + بطاريته الكاملة

**التاريخ:** 2026-08-21 · **المحرك:** `../mcl_core.hpp` v8.1.1 **بلا أي تعديل** · **التعمية:** ‏SHA-256/HMAC حقيقيان (CommonCrypto) لا FNV-1a.
**البند المنفَّذ:** رقم 6 من قائمة التجارب المطلوبة — ويغطي معه البنود 7 و8 و9.

## العيوب الثلاثة التي أُغلقت (أثبتها محكّمو E5/A في جولتي 07-11 و07-18)

| # | العيب في `mcl_txn_verify.cpp` المنشور | الإغلاق في v2 |
|---|---|---|
| **D1** | `Tag = MCL_T2(FNV1a(TX) ^ nonce, p, q)` — تجزئة **غير تعموية** مطويّة في بذرة **64 بت**، فمعاملتان مختلفتان تعطيان تاجًا 256-بت **متطابقًا بايتيًا** (جمّعه المحكّمون) | تجزئة المعاملة تدخل بعرضها الكامل 256 بت داخل سياق HMAC، لا عبر مدخل المحرك |
| **D2** | ‏`S_device` **غائب تمامًا** من المسار (grep = صفر)، فالنطاق «84–94 بت ما بعد Grover» الذي تربطه الورقة به غير مُختبَر | الـ256 بت الكاملة لـ(K, S_device) تقود **الأوزان الاثني عشر الدائمة** عبر مصنع المحرك نفسه `mcl_t4_from_key_device` (مسار §V.D بعينه) |
| **D3** | لا تقنين ولا دورة حياة: لا ربط ببايتات المعاملة القانونية، ولا منع لإعادة التشغيل/النقل/إعادة الاستخدام، ولا حماية لمسار الاسترداد | ترتيب حقول قانوني + دفتر nonce أحادي الاستخدام لكل حساب + ربط الحساب والمدقق داخل التاج + **إعادة الربط تشترط إثبات حضور الجهاز الحالي** |

## النتيجة — 16/16 PASS (`results_20260821.txt`، 52 دقيقة، حتمي)

**الدورة والهجمات:** ‏S_device ≠ 0 مؤكد · شرعي 1000/1000 · إعادة تشغيل/عبر-حساب/عبر-مدقق/بعد-فشل مرفوضة · تقديم مزدوج = قبول واحد بالضبط · **تحوير بايت واحد من calldata يغيّر التاج** (الربط القانوني) · **C-1a يستنسخ انهيار الطيّ 64-بت على المسار القديم وC-1b يفصله في الجديد** · **R-1 إعادة ربط بلا سرّ الجهاز مرفوضة، R-2 إعادة الربط بحضور الجهاز مقبولة**.

**بطارية §VI الإحصائية على المسار المربوط بالجهاز:** ‏S1 فرادة **5000/5000** · S2 انهيار **128.09/256** (min 98، max 152) · S3 ‏χ² بايتي **228.4** (df 255، حرج .001 ≈ 330.5) · **S4 صفر تزوير في 10⁶ محاولة** بجهاز عشوائي **حتى مع معرفة K_wrap**.

## قراءة صحيحة للأرقام (مهمة للنص)

‏S1–S3 تقيس **البروتوكول المركَّب** — وهو ما يراه المدقق فعلًا. حساسية المحرك نفسها تُقاس في S4 وفي الطبقة A من حملة FAR للورقة 2 (متوسط هامنغ 127.999/256 وصفر اقتراب عبر **10⁷** زوج معاملات خاطئ). خلط الطبقتين هو ما جعل المحكّمين يصفون أرقام §VI المنشورة بأنها «تقيس صحة التنفيذ لا الأمان» — الفصل بينهما شرط لقبولها.

## نتيجة معمارية تحتاج قرارك

إصلاح D1 **يستلزم** نقل تجزئة المعاملة خارج مدخل المحرك (لا يمكن ربط 256 بت عبر مدخل 64 بت)، فينتقل دور المحرك من «‏MAC لكل معاملة» إلى «اشتقاق مفتاح مربوط بالجهاز» — وهو اتجاه §V.D المعلن أصلًا. الخيارات الثلاثة وتوصيتي في `ARCHITECTURAL_FINDING_20260821.md`.

## البصمات والبناء

`mcl_txauth_hardened.cpp` = `f768c41e5fd1…` · `results_20260821.txt` = `aa379829376c…`
```
clang++ -std=c++17 -O2 mcl_txauth_hardened.cpp -o mcl_txauth_hardened
```

## المتبقي على هذا المسار

حملات الأحجام الكبيرة (10⁸ مصادقة، 40M ‏SIM-swap بالاستراتيجيات الـ16 + استراتيجيتَي التعداد الخارجي والطيّ) — هذه بطارية منطق + إحصاء متوسط الحجم ولا تعوّضها.

## 2026-09-04 — harness v3.1 (Doc ID MCL-P5-V3BATTERY-2026-0904-002)

Re-executed on the engine of record **v8.1.3** after the Paper-5 pre-publication review
(`05_Scientific_Papers/Paper_5_ACM_TOPS/Reviews/P5_PrePublication_Review_20260904.md`, items 4/11/32/33):

| change | why |
|---|---|
| Verifier = per-account **last-accepted counter**, `accept iff c > c_last && tag recomputes`, advanced **only on acceptance** | the 08-21 harness used a spent-nonce set and inserted the nonce *before* the tag check (a failed attempt burned the counter — inverted T6e semantics + trivial nonce-burning DoS); Paper 5 §V.A specifies the monotonic form |
| constant-time tag comparison (`ct_equal`) | §V.A Step 4 says constant-time; `std::array ==` is not |
| T6e re-specified: failed attempt does **not** consume the counter (valid retry accepted); new T6i: valid tag on a stale counter rejected | matches the specified state machine |
| T8 = tag generation; new **T8b = generation + `authorize()`** (true end-to-end) | the 08-21 "end-to-end" number was generation only |

**Result** (`results_v3_battery_v8.1.3_20260904.txt`): **18 PASS / 0 FAIL**. T1–T5 and T7 statistics are
**byte-identical** to the 08-21 (v8.1.1) and 08-22 (v8.1.3) records. Timing (Apple M1 Pro, single thread):
T8 3.658 ms/tag = 273 tags/s; T8b 7.326 ms/tx = 137 tx/s.
The 08-21 harness and its record are preserved in `_ARCHIVE/2026-09-04/p5_hardened_txauth_pre_v3.1/`.

### Q30 realization (same day) — `mcl_txauth_v3_battery_q30.cpp` (Doc ID MCL-P5-V3BATTERY-Q30-2026-0904-003)
Same harness with `MCL_T4_Q30` (keyed sidecar v1.0.6, twelve Q30 integer weights via `mcl_t4_q30_params_from_key`, no floating point) in place of the double-precision `MCL_T4`, plus T0 (1,000 recomputations bit-identical).
Build: `clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_txauth_v3_battery_q30.cpp -o mcl_txauth_v3_battery_q30`.
**Result** (`results_v3_battery_q30_v8.1.3_20260904.txt`): **19 PASS / 0 FAIL** — T2 128.098/256 (94–157), T3 χ² 273.7, T4 129.51 (112–143), T5 128.34 (100–147) 0 near-misses, T7 0/100000 mean 127.935 0 near-misses, **T8 0.395 ms/tag = 2,532 tags/s, T8b 0.788 ms/tx = 1,269 tx/s** (≈9× the double-precision engine: LUT sine, no std::sin). Closes the Paper-5 §VI/§X.2 disclosure «not yet re-executed on Q30».

### 2026-09-05 — harness v3.1.1 (Q30): T1 SHA-256 fingerprint + build architecture line
Built for arm64 and x86_64 (Rosetta 2) from the same source: 19/19 PASS on both, identical statistics, **identical fingerprint** `cf465420…3b80b30` over the 5,000 Test-1 tags (records `results_v3_battery_q30_v8.1.3_20260905_{arm64,x86_64}.txt`). Timing arm64 0.302/0.599 ms; x86_64 0.329/0.659 ms. Burn-in sweep (referee Q3) in `../P5_ReviewMeasurements_20260905/`.

## 2026-09-05 — harness **v3.2** (Doc IDs MCL-P5-V32BATTERY-2026-0905-001 / MCL-P5-V32BATTERY-Q30-2026-0905-002) — Paper 5 referee round 3

| change | why |
|---|---|
| SHA-256 taken from the engine (`mcl_sha256`); no CommonCrypto | builds on Linux/any libc (referee Y21: reproducibility) |
| T2 flips **one uniformly random bit of `canon(TX)`** (384 positions: chain_id, nonce, to, value, 16 bytes of calldata), position = SHA-256("MCL-P5-T2BIT" ‖ LE64(i)) mod 384 | v3.1 exercised only 16 fixed calldata positions (referee T8) |
| weak-set **re-draw census** (Q30): counts derivations whose RAW twelve-weight set had a reachable translation symmetry before the sidecar's deterministic re-draw | referee T10 (re-draw, not rejection; how often) |
| `-DMCL_TX_COMBINER`: **PRF-XOR combiner** `Tag = HMAC-SHA-256(K_mac, ctx) ⊕ G(KDF(S_device, "MCL-TxChallenge-v1", ctx))`, `K_mac = KDF(K, "MCL-TxMAC-v1", "")` (Paper 5 §V.E, Eq. 5–7) | the deployment form; measured on both realizations |
| banner: mode line (engine-native / combiner), CT-sine line, build architecture | record self-description |

Builds (`B=(clang++ -std=c++17 -O3 -DNDEBUG -I..)`): `"${B[@]}" mcl_txauth_v3_battery.cpp` (double, native) · `… -DMCL_TX_COMBINER` (double, combiner) · `… -arch arm64 mcl_txauth_v3_battery_q30.cpp` · `… -arch x86_64 …` (run under Rosetta 2) · `… -arch arm64 -DMCL_TX_COMBINER …`. Run: `./bat 100000 2`.

**Records** (all on engine v8.1.3 + sidecar v1.0.6, Apple M1 Pro; final runs on a near-idle machine — conditions in `quiet_rerun_conditions_20260905.txt` / `quiet_rerun_double_conditions_20260905.txt`):
`results_v32_double_native_20260905.txt` (18/18) · `results_v32_double_combiner_20260905.txt` (18/18) · `results_v32_q30_native_arm64_20260905.txt` (19/19) · `results_v32_q30_native_x86_64_20260905.txt` (19/19, **same statistics and same T1 fingerprint as arm64**) · `results_v32_q30_combiner_arm64_20260905.txt` (19/19). Statistics are deterministic (identical between the loaded first pass and the quiet re-run); only latencies differ.
**Constant-time sine** (`-DMCL_Q30_CONSTANT_TIME_SIN`): the sidecar's CT evaluator is an oblivious scan of the whole 65,536-entry table per sine, so a full battery is infeasible (an attempt was stopped after 70 min without finishing T7); its cost is measured on 3 tags by `../P5_ReviewMeasurements_20260905/p5_ct_sine_cost.cpp` — identical tags, ≈ 4.0 s per tag vs 0.39 ms.
The v3.1 / v3.1.1 sources are kept verbatim as `_v31_backup_mcl_txauth_v3_battery.cpp.txt` / `_v311_backup_mcl_txauth_v3_battery_q30.cpp.txt`; their records (`results_v3_battery_*`) remain the provenance of the 2026-09-04 numbers.
