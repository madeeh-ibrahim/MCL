# P5 review measurements — 2026-09-05 (TOPS-referee items Q3, Q4)

**Doc IDs:** MCL-P5-BURNIN-2026-0905-001 (burn-in sweep) · MCL-P5-V3BATTERY-Q30-2026-0904-003 / harness v3.1.1 (cross-ISA fingerprint)
**Engine of record:** `02_Engine_Code/mcl_core.hpp` v8.1.3 (md5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3`) · keyed sidecar v1.0.6 (md5 `dd5040376465876a86065bd498b98db1`) — **unmodified**. Platform: Apple M1 Pro, macOS, Apple clang, single thread.

## Q4 — cross-ISA bit-identity of the Q30 protocol (`mcl_txauth_v3_battery_q30.cpp` v3.1.1)
Same source built with `-arch arm64` and `-arch x86_64` (run under Rosetta 2). Both: **19 PASS / 0 FAIL**, every statistic identical, and the SHA-256 fingerprint over the 5,000 concatenated Test-1 tags is identical:
`cf465420f3431ffa4901271fab2216d0ff3d35ff5108e3f0fa685f8e93b80b30`.
Timing: arm64 T8 0.302 ms/tag (3,309/s), T8b 0.599 ms/tx (1,669/s); x86_64/Rosetta 0.329 / 0.659 ms. (The 2026-09-04 arm64 run of the same battery measured 0.395 / 0.788 ms — run-to-run variation ≈ ±25%; statistics bit-identical.)
Records: `results_v3_battery_q30_v8.1.3_20260905_{arm64,x86_64}.txt` (copies; originals in `p5_hardened_txauth/`).

## Q3 — burn-in sensitivity under Eq. (3) (`p5_burnin_curve.cpp`)
Built once per B ∈ {0, 1, 10, 50, 100, 500, 1000, 5000, 10000} against a **scratch copy** of the engine whose `constexpr int BURNIN = 10000;` was made overridable (`header_patch.diff`); the engine of record is untouched. Per B on the Q30 realization: 5,000 single-bit TX flips, byte χ² over 20,000 tags, 10 devices/45 pairs, 128 stride-4 neighbours of (K, S), 10⁴ random wrong devices, latency.
**Result** (`burnin_curve_20260905.log`): every statistic at its null-model value for every B — avalanche 127.8–128.3/256, χ² 232–276 (df 255), binding 126.4–129.5, neighbours 126.9–128.8 with 0 near-misses, wrong-device 0 accepts / 0 near-misses / mean HD ≈ 128 — while latency goes from 0.007 ms (B = 0) to 0.326 ms (B = 10,000): the burn-in is ≈ 98% of the per-tag cost. **Interpretation (as written in the paper §VI.C / §X.10):** the battery cannot resolve the burn-in length; the normative B = 10,000 is retained; the trade-off is an open cryptanalytic question, not a licence to shorten.

| file | md5 |
|---|---|
| `G_entropy_20260905.log` | `fcdc73d621f01fc435d1eb35471dbe85` |
| `README.md` | `8b6aee80357f40ed82cb535cb7f33f78` |
| `README_EN.md` | `b0dbeb5ec31bc515985b7d23ffdd7ecc` |
| `adversarial_20260905.log` | `4145c5ed87b6923a34830ad5e32f1df0` |
| `burnin_curve_20260905.log` | `050dad52defcd739c6938018cccb2a44` |
| `burnin_curve_v2_20260905.log` | `8eefc62721b9e237deb544a4cc471e95` |
| `ct_sine_cost_20260905.log` | `2b6e3f203ac2e7ce23af05426519a13f` |
| `hd_throughput_v1_quiet_20260905.log` | `5e76214cd2cc41dfc036ab9cd0941aa3` |
| `hd_throughput_v2_quiet_20260905.log` | `57002e19b5b8219b31a737e235ee60be` |
| `header_patch.diff` | `bfb2255376963a20713be61f1299a1c4` |
| `mcl_hd_throughput.cpp` | `b6f03a61af6e4d6645d51846dd7aacbf` |
| `p5_G_entropy.cpp` | `5acc317b5a423c70d754361034383167` |
| `p5_adversarial.cpp` | `3e1e7f34eb40d2c50ada0695457a5616` |
| `p5_burnin_curve.cpp` | `9f18a9a3b6dceb9b56f3aa1bff1cffc4` |
| `p5_burnin_curve_v2.cpp` | `ccabbe1d049a54a7d42f46dd4df9e220` |
| `p5_ct_sine_cost.cpp` | `59a64bab93e56f71418669cd1c800dbe` |
| `p5_parity_lock.cpp` | `c65e07ffe370ebbc0e65c20da699b638` |
| `p5_resonance_control.cpp` | `708270a63754b5a746898c32775a4d42` |
| `p5_system_eval.cpp` | `f5974ee0c591a3308cd3bf1b34bd9ed9` |
| `p5_v2_coprime_parity.cpp` | `28e5232de3e49a7ecf8f5ad35f426396` |
| `p5_weight_probe.cpp` | `30e3643026aed65609f8b26bef017427` |
| `redraw_rate.cpp` | `c8bc17a69ac89160f0c7b3376173ee1b` |
| `resonance_control_20260905.log` | `345cb0d44e0b52a2d1284b463fa4c11c` |
| `results_v3_battery_q30_v8.1.3_20260905_arm64.txt` | `826cc3b93f065fbd2a3310d34b55ec7b` |
| `results_v3_battery_q30_v8.1.3_20260905_x86_64.txt` | `528c97c3bfaab95b7089cf7fa6002a1e` |
| `sibling_recovery.cpp` | `215ed07eaa21b7c06180f8dd4e200298` |
| `sibling_recovery.log` | `1e76fa7aca34398e71dcce1a4c398da9` |
| `system_eval_20260905.log` | `9a35ae9ee5322c8510e5aa77dd00cda9` |
| `v2_coprime_parity_20260905.log` | `f9e601051a0897a6b57b530e50d6d22c` |
| `weight_probe_20260905.log` | `8050e87ac004fcf915bf5cbcda41dea4` |
| `weight_probe_sidecar_scratch_ctor.diff` | `162e6c220969c6c70e5da1d705127dbc` |

---
## 2026-09-05 (evening) — deep-examiner findings S1: parity lock + sibling recovery (engine of record, unmodified)
- `p5_parity_lock.cpp` — replicates Steps 2–3 of `derive_child` for parent (3,5), M = 10⁶: raw[0]=0x21, raw[8]=0xC9 (both odd), h₂ constant odd, M−2 even ⇒ pre-gcd parity classes over 2×10⁵ indices: **even-even 100,005 · odd-odd 99,995 · mixed 0**; after the gcd loop q is odd in **91.8 %** of children. Explains the measured 59.47 % (= ½ + ½·(1 − (6/π²)/(3/4)) = 0.5947).
- `sibling_recovery.cpp` / `sibling_recovery.log` — proof of concept for the referee finding: with M = 10⁹, from the p-values of children 0, 1, 2 alone, the parent's 64-bit block R_lo (= raw[0:8]) is recovered by enumerating k < 2⁶⁴/(M−2) (1.8 × 10¹⁰ candidates, **23.8 s single-thread**) — unique survivor, equal to the true block — and the p-value of the **unseen child 7 is predicted exactly**, without the seed, the parent pair or any engine evaluation.
| file | md5 |
|---|---|
| `G_entropy_20260905.log` | `fcdc73d621f01fc435d1eb35471dbe85` |
| `README.md` | `8b6aee80357f40ed82cb535cb7f33f78` |
| `README_EN.md` | `b0dbeb5ec31bc515985b7d23ffdd7ecc` |
| `adversarial_20260905.log` | `4145c5ed87b6923a34830ad5e32f1df0` |
| `burnin_curve_20260905.log` | `050dad52defcd739c6938018cccb2a44` |
| `burnin_curve_v2_20260905.log` | `8eefc62721b9e237deb544a4cc471e95` |
| `ct_sine_cost_20260905.log` | `2b6e3f203ac2e7ce23af05426519a13f` |
| `hd_throughput_v1_quiet_20260905.log` | `5e76214cd2cc41dfc036ab9cd0941aa3` |
| `hd_throughput_v2_quiet_20260905.log` | `57002e19b5b8219b31a737e235ee60be` |
| `header_patch.diff` | `bfb2255376963a20713be61f1299a1c4` |
| `mcl_hd_throughput.cpp` | `b6f03a61af6e4d6645d51846dd7aacbf` |
| `p5_G_entropy.cpp` | `5acc317b5a423c70d754361034383167` |
| `p5_adversarial.cpp` | `3e1e7f34eb40d2c50ada0695457a5616` |
| `p5_burnin_curve.cpp` | `9f18a9a3b6dceb9b56f3aa1bff1cffc4` |
| `p5_burnin_curve_v2.cpp` | `ccabbe1d049a54a7d42f46dd4df9e220` |
| `p5_ct_sine_cost.cpp` | `59a64bab93e56f71418669cd1c800dbe` |
| `p5_parity_lock.cpp` | `c65e07ffe370ebbc0e65c20da699b638` |
| `p5_resonance_control.cpp` | `708270a63754b5a746898c32775a4d42` |
| `p5_system_eval.cpp` | `f5974ee0c591a3308cd3bf1b34bd9ed9` |
| `p5_v2_coprime_parity.cpp` | `28e5232de3e49a7ecf8f5ad35f426396` |
| `p5_weight_probe.cpp` | `30e3643026aed65609f8b26bef017427` |
| `redraw_rate.cpp` | `c8bc17a69ac89160f0c7b3376173ee1b` |
| `resonance_control_20260905.log` | `345cb0d44e0b52a2d1284b463fa4c11c` |
| `results_v3_battery_q30_v8.1.3_20260905_arm64.txt` | `826cc3b93f065fbd2a3310d34b55ec7b` |
| `results_v3_battery_q30_v8.1.3_20260905_x86_64.txt` | `528c97c3bfaab95b7089cf7fa6002a1e` |
| `sibling_recovery.cpp` | `215ed07eaa21b7c06180f8dd4e200298` |
| `sibling_recovery.log` | `1e76fa7aca34398e71dcce1a4c398da9` |
| `system_eval_20260905.log` | `9a35ae9ee5322c8510e5aa77dd00cda9` |
| `v2_coprime_parity_20260905.log` | `f9e601051a0897a6b57b530e50d6d22c` |
| `weight_probe_20260905.log` | `8050e87ac004fcf915bf5cbcda41dea4` |
| `weight_probe_sidecar_scratch_ctor.diff` | `162e6c220969c6c70e5da1d705127dbc` |
- `redraw_rate.cpp` (2026-09-05 night) — empirical weak-key re-draw rate of `mcl_t4_q30_params_from_key` over 200,000 random 256-bit keys: **395 raw weight sets with a reachable translation symmetry (0.198 %, ≈ 2⁻⁹) → 0 after the sidecar's deterministic re-draw.** Confirms Tech Guide §308 (re-draw, not rejection) against Paper 5 §X.9 ("rejected"); implies ≈ 270 silent re-draws inside the Q30 battery. md5 `c8bc17a69ac89160f0c7b3376173ee1b`.


---
## 2026-09-05 — جولة الفاحص 3 («نفذ الكل»): القياسات التي تستهلكها الورقة بعد إعادة الكتابة (المحرّك 8.1.3 والحاشية 1.0.6 لم يُمسّا)
- `p5_v2_coprime_parity.cpp` / `v2_coprime_parity_20260905.log` — إحصاء `derive_child_v2` (`../hd_v2/mcl_hd_v2.hpp`) عند الأب (3,5)، M = 10⁶، 2×10⁵ فهرس: **78,585 زوجاً خاماً غير أوّلي (39.29 %؛ المتوقَّع لكلمتين مستقلّتين 39.21 %)**، 0 اصطدام p = q، وفئات التكافؤ للأطفال المُصدَرين 99,958 / 49,952 / 50,090 على (زوجي، فردي) / (فردي، زوجي) / (فردي، فردي) — لا قفل تكافؤ (v1: فئتان فقط).
- `p5_burnin_curve_v2.cpp` / `burnin_curve_v2_20260905.log` — إعادة مسح الـburn-in بطريقة T2 الجديدة (بت عشوائي من 384 موضعاً في canon(TX)) وSHA-256 المحرّك، B ∈ {0,1,2,4,8,16,64,1000,10000}: كل إحصاءة داخل الخطأ المعياري لنموذج الصفر؛ الكمون 0.007 → 0.482 ms/وسم (هذه الجولة أُجريت والآلة مشغولة بحملات أخرى — الكمون الحاكم في سجلات الحزمة v3.2 الهادئة).
- `p5_G_entropy.cpp` / `G_entropy_20260905.log` — **اختبار عيد الميلاد لخريطة المفتاح→الوسم G(U)** على Q30: 2²⁵ مفتاح منتظم، بتر الوسم إلى 42 بتاً، المتوقَّع المثالي 128.0 ± 11.3 تصادماً: B=0: 121 (0.945) · B=2: 130 (1.016) · B=8: 122 (0.953) · B=64: 137 (1.070) · B=10000: 145 (1.133؛ 1.5σ). هذا هو الحدّ الوحيد المعتمد على المحرّك في مبرهنة الورقة 1 (q_V·2^(−H∞(G(U)))): لا انهيار إجمالي للخريطة عند أي طول burn-in، بما في ذلك B = 0. (بناء خدشي بـ`-DMCL_BURNIN_OVERRIDE`، `header_patch.diff`؛ المحرّك المرجعي لم يُمسّ.)
- `p5_ct_sine_cost.cpp` / `ct_sine_cost_20260905.log` — كلفة الجيب الثابت الزمن الاختياري (`-DMCL_Q30_CONSTANT_TIME_SIN`؛ مسح كامل للجدول 65,536 لكل جيب): 3 وسوم بالاشتقاق نفسه، **بصمة مطابقة**، 4.03 ث/وسم مقابل 0.39 ms (≈ 10⁴×). بطارية كاملة تحت هذا البناء غير ممكنة (كانت لتستغرق أياماً)؛ محاولةٌ أُلغيت.
- `mcl_hd_throughput.cpp` (v1) و`../hd_v2/mcl_hd_throughput_v2.cpp` (v2) / `hd_throughput_v{1,2}_quiet_20260905.log` — إعادة توقيت الاشتقاق (تشغيلان لكل) والآلة شبه هادئة (عملية واحدة أخرى): v1 1.076–1.078 ms عارياً / 27.0 ms مع الخطوة 4؛ v2 1.079–1.081 / 27.1–28.2 ms — SHA-256 غير مرئية أمام تشغيل المحرّك.
- `p5_resonance_control.cpp` / `resonance_control_20260905.log` — ضابط موجب لشاشة χ² (الخطوة 4) على نافذة (3,5) قرب K ≈ 1.22: مُعلَّمة عند 1.218/1.220/1.221 (χ² 1.4–1.5×10⁶)، **330.0 عند 1.219 (تحت العتبة 330.52 بفارق 0.5)** — الشاشة تكشف النافذة لكن عتبتها غير حادّة عند حافّتها.
- `p5_weight_probe.cpp` / `weight_probe_20260905.log` / `weight_probe_sidecar_scratch_ctor.diff` — اضطراب الأوزان الاثني عشر مباشرة (±1 وقلب بت لكل وزن؛ 10,800 مسباراً/تحقيق): مزدوج 128.065/256 (97–156)، Q30 128.120/256 (95–158)، 0 near-miss.
- `p5_system_eval.cpp` / `system_eval_20260905.log` — **التقييم النظامي (§VII.B)**، أُعيد قياسه 2026-09-06 على مضيف هادئ بدقّة أعلى (عمليات MCL n=400، عمليات التجزئة n=400,000 لأنها دون الميكروثانية): الأدوار الثلاثة للمحفظة على مكدّس MCL مقابل مكدّس تجزئة (KDF1/SHA-256 + HMAC-SHA-256 + DRBG بعدّاد SHA-256) في العملية نفسها. تسجيل 0.862 ms مقابل 0.459 µs (≈1,880×)، ومع شاشة الخطوة 4 20.62 ms (≈44,900×)؛ مصادقة 0.295 ms مقابل 2.02 µs (≈146×)؛ توليد 1 KiB 0.351 ms مقابل 13.87 µs (≈25×)؛ حالة متغيّرة 72 B مقابل ≈104 B (0.69×)؛ جدول 262,144 B مقابل 0؛ أسرار 1 مقابل 1؛ **بدائيات 2 مقابل 1** (MCL يحتاج المحرّك + SHA-256 لـKDF). النتيجة **تُفنّد حجّة الدمج** والورقة تسحبها صراحةً.
- `p5_adversarial.cpp` / `adversarial_20260905.log` — **التقييم العدائي (§VI.E)**: (A1) حساسية ctx لكل حقل على حدة (قلب بت واحد في الحقل وحده، 2,000 محاولة/حقل): كل الحقول الستّة داخل 1.6 خطأ معياري من 128/256 ⇒ كل حقل يربط الوسم بعرضه الكامل؛ (A2) اختبار تسريب الأوزان من الدرجة الأولى: 20,000 مفتاح × 360 بت وزن × 256 بت وسم = 92,160 ارتباطاً، عند B = 10,000 وB = 0: أقصى |r| = 0.0309 (4.37σ) و0.0298 (4.22σ) مقابل قيمة قصوى متوقَّعة للنموذج الصفري ≈ 4.92σ ⇒ **لا تسريب من الدرجة الأولى عند أيّ من طولَي الـburn-in** (نتيجة سالبة؛ لا تستبعد الرتب الأعلى/الشبكية، §X.12).
- سجلات الحزمة v3.2 الحاكمة في `../p5_hardened_txauth/results_v32_*_20260905.txt` (+ `quiet_rerun_conditions_20260905.txt`).

| file | md5 |
|---|---|
| `G_entropy_20260905.log` | `fcdc73d621f01fc435d1eb35471dbe85` |
| `README.md` | `8b6aee80357f40ed82cb535cb7f33f78` |
| `README_EN.md` | `b0dbeb5ec31bc515985b7d23ffdd7ecc` |
| `adversarial_20260905.log` | `4145c5ed87b6923a34830ad5e32f1df0` |
| `burnin_curve_20260905.log` | `050dad52defcd739c6938018cccb2a44` |
| `burnin_curve_v2_20260905.log` | `8eefc62721b9e237deb544a4cc471e95` |
| `ct_sine_cost_20260905.log` | `2b6e3f203ac2e7ce23af05426519a13f` |
| `hd_throughput_v1_quiet_20260905.log` | `5e76214cd2cc41dfc036ab9cd0941aa3` |
| `hd_throughput_v2_quiet_20260905.log` | `57002e19b5b8219b31a737e235ee60be` |
| `header_patch.diff` | `bfb2255376963a20713be61f1299a1c4` |
| `mcl_hd_throughput.cpp` | `b6f03a61af6e4d6645d51846dd7aacbf` |
| `p5_G_entropy.cpp` | `5acc317b5a423c70d754361034383167` |
| `p5_adversarial.cpp` | `3e1e7f34eb40d2c50ada0695457a5616` |
| `p5_burnin_curve.cpp` | `9f18a9a3b6dceb9b56f3aa1bff1cffc4` |
| `p5_burnin_curve_v2.cpp` | `ccabbe1d049a54a7d42f46dd4df9e220` |
| `p5_ct_sine_cost.cpp` | `59a64bab93e56f71418669cd1c800dbe` |
| `p5_parity_lock.cpp` | `c65e07ffe370ebbc0e65c20da699b638` |
| `p5_resonance_control.cpp` | `708270a63754b5a746898c32775a4d42` |
| `p5_system_eval.cpp` | `f5974ee0c591a3308cd3bf1b34bd9ed9` |
| `p5_v2_coprime_parity.cpp` | `28e5232de3e49a7ecf8f5ad35f426396` |
| `p5_weight_probe.cpp` | `30e3643026aed65609f8b26bef017427` |
| `redraw_rate.cpp` | `c8bc17a69ac89160f0c7b3376173ee1b` |
| `resonance_control_20260905.log` | `345cb0d44e0b52a2d1284b463fa4c11c` |
| `results_v3_battery_q30_v8.1.3_20260905_arm64.txt` | `826cc3b93f065fbd2a3310d34b55ec7b` |
| `results_v3_battery_q30_v8.1.3_20260905_x86_64.txt` | `528c97c3bfaab95b7089cf7fa6002a1e` |
| `sibling_recovery.cpp` | `215ed07eaa21b7c06180f8dd4e200298` |
| `sibling_recovery.log` | `1e76fa7aca34398e71dcce1a4c398da9` |
| `system_eval_20260905.log` | `9a35ae9ee5322c8510e5aa77dd00cda9` |
| `v2_coprime_parity_20260905.log` | `f9e601051a0897a6b57b530e50d6d22c` |
| `weight_probe_20260905.log` | `8050e87ac004fcf915bf5cbcda41dea4` |
| `weight_probe_sidecar_scratch_ctor.diff` | `162e6c220969c6c70e5da1d705127dbc` |
