# P5 §IV.E — حملة FULL (9,702 مرشّحاً) على محرّك السجل v8.1.3

**Doc ID:** MCL-P5-HDFULL-2026-0904-001 · **التاريخ:** 2026-09-04
**السبب:** بند 🟡 15 في `Paper_5_ACM_TOPS/Reviews/P5_PrePublication_Review_20260904.md` — كانت الورقة تُبلّغ عن 9,702 مرشّحاً بينما كل السجلات المؤرشفة في المشروع `Mode: QUICK` بنطاق [2,20] = 342 مرشّحاً فقط.

## البناء والتشغيل
```bash
clang++ -O3 -std=c++17 mcl_hd_verify.cpp -o mcl_hd_verify   # مع mcl_core.hpp v8.1.3
./mcl_hd_verify --full
```
Apple M-series · 1,876.0 ثانية (31.3 دقيقة)

## البصمات
| الملف | MD5 |
|---|---|
| `02_Engine_Code/mcl_core.hpp` (v8.1.3، محرّك السجل) | `5d8b49ee11aa0bfb8b0bda3f47fa16e3` |
| `MCL_Public_Code/mcl_hd_verify.cpp` (غير معدَّل) | `37266ea7eed12a18659c9094812210d1` |
| `hd_verify_FULL_v8.1.3_20260904.log` | `4afbcd06575606e4dd75b6e3a3dd8481` |

## النتيجة
- **Test 4 (FULL):** النطاق [2,100]، `p ≠ q` ⇒ **9,702 مرشّحاً** · **Exact collisions: 0** · **correlated (|r| > 2×noise floor): 0**
- الطفل الهدف: `Derive(seed=12345678901234, 13, 19, 0) = (41475, 955466)` — **مطابق للقيمة المنشورة في §IV.E**
- **10/10 PASS** · Global Bonferroni 135 زوجاً / عتبة 7.41e-06 / 0 رفض

## التحقّق المتقاطع الحاسم
تشغيل v8.1.3 **متطابق سطراً بسطر** مع السجل المؤرشف `MCL_Public_Code/results/mcl_hd_verify.txt` (المُنتَج على محرّك v6.0.0) في **كل الأسطر** عدا أسطر وضع/نطاق Test 4 والتوقيت:
```bash
diff <(grep -v "Started:\|Time:\|Mode:\|search range\|candidate parents" hd_verify_FULL_v8.1.3_20260904.log) \
     <(grep -v "Started:\|Time:\|Mode:\|search range\|candidate parents" ../MCL_Public_Code/results/mcl_hd_verify.txt)
# لا فروق
```
⇒ **كل رقم في §IV من الورقة 5 يعيد إنتاج نفسه بايت-بايت على محرّك السجل v8.1.3.**

## ⚠️ فخّ إسناد
ترويسة اللوج تطبع `v6.0.0` **دائماً** — لأنها ثابت مُصلَّب في الشفرة (`mcl_hd_verify.cpp:76`: `static const char* DOC_VERSION = "6.0.0";`) **وليست نسخة المحرّك المربوط**. لا يُستدل بها على المحرّك؛ البصمة أعلاه هي المرجع.

---

# ملحق (نفس اليوم، الجولة الثانية) — قياس نسبة عدم التوافق ≈59.4% (§III.A)

**Doc ID:** MCL-P5-COPRIME-2026-0904-001 · **السبب:** بند 🟡 36 — الرقم «≈59.4% over 2 × 10⁵ indices» لم يكن له سجل قياس.

```bash
clang++ -O2 -std=c++17 coprime_frac.cpp -o coprime_frac   # مع mcl_core.hpp v8.1.3 (البصمة أعلاه)
./coprime_frac 200000
```
**الطريقة:** بالضبط كما في §III.A/`derive_child`: البايتات الخام من `MCL_T2(seed=12345678901234, 3, 5, K=12)` (32 بايت — **مستقلة عن الفهرس**)، ثم لكل فهرس i ∈ [0, 2×10⁵): خلط `fmix64(i)` و`fmix64(i)·0x9E3779B97F4A7C15` بـXOR في [0:8] و[8:16]، ثم `p = 2 + c₁ mod (M−2)`، `q = 2 + c₂ mod (M−2)` مع دفع p≠q — ثم مقارنة q الساذجة بـq الصادرة عن `derive_child()` الفعلية.

**النتيجة** (`coprime_frac_2e5.log`):
```
indices=200000  p_eq_q_bumps=0  raw_noncoprime=118933 (59.47%)  q_differs_from_naive=118933 (59.47%)  engine v8.1.3
```
- **59.47%** ⇒ الرقم المنشور «≈59.4%» **مؤكَّد** على محرّك السجل.
- `p` من `derive_child` طابق الخريطة الساذجة في **200,000/200,000** فهرس (كما تقول الورقة: «reproduces p_child correctly»).
- لا حالة p = q خام واحدة في 2×10⁵ فهرس (متوقَّع: احتمال ≈10⁻⁶ لكل فهرس).
- **ملاحظة بنيوية موثَّقة هنا:** البايتات الخام واحدة لكل أطفال الأب نفسه؛ الفهرس لا يدخل إلا عبر قناع XOR علني على أول 16 بايت (⇒ بند 🟡 35 في المراجعة).

| الملف | MD5 |
|---|---|
| `coprime_frac.cpp` | `cf6e143c48837be7863a433769a21ecd` |
| `coprime_frac_2e5.log` | `0f6ab5a6f268148a9b59f80b4a37610f` |

---

# ملحق 2 (نفس اليوم، التنفيذ) — إعادة قياس إنتاجية الاشتقاق على v8.1.3 (§IV.H، البند 13)

**السبب:** التعليق المضمَّن في §IV.H كان يدّعي «frozen engine v8.1.3» بينما `M1_M2_apple_verification/mcl_hd_throughput.cpp` ومحرّكه المجاور v6.0.0، ويذكر تشغيلين لا يوجد منهما إلا واحد في اللوج.

```bash
clang++ -O3 -std=c++17 mcl_hd_throughput.cpp -o mcl_hd_throughput   # المصدر غير معدَّل (Doc ID MCL-HD-THROUGHPUT-2026-0817-001) مع mcl_core.hpp v8.1.3
./mcl_hd_throughput > hd_throughput_v8.1.3_M1Pro_20260904_run1.log
./mcl_hd_throughput > hd_throughput_v8.1.3_M1Pro_20260904_run2.log
```
Apple M1 Pro (كانت بطارية §VI تعمل في الخلفية بخيطين أثناء التشغيل).

| | run 1 | run 2 |
|---|---|---|
| `derive_child` (bare) | 1097.5 µs = 911.2/s | 1079.1 µs = 926.7/s |
| `derive_child_safe` (+Step-4) | 27030.4 µs = 37.0/s | 27031.2 µs = 37.0/s |
| Step-4 overhead | 95.9% | 96.0% |
| `sink` | 244961982 | 244961982 |

`sink = 244961982` **مطابق** للوج v6.0.0 (M2 Max، 2026-08-18) ⇒ مخرجات `derive_child` متطابقة عبر المحرّكين والمنصّتين؛ الفرق توقيت فقط. الورقة §IV.H تنقل الآن هذه الأرقام حصراً.

| الملف | MD5 |
|---|---|
| `hd_throughput_v8.1.3_M1Pro_20260904_run1.log` | `95fadce5555268e11f342ce18aead4e2` |
| `hd_throughput_v8.1.3_M1Pro_20260904_run2.log` | `2531c2726f861790d6b94924a0bdab4e` |
| `M1_M2_apple_verification/mcl_hd_throughput.cpp` (غير معدَّل) | `b6f03a61af6e4d6645d51846dd7aacbf` |

---

# ملحق 3 — بطارية §VI على الحزمة v3.1 (البنود 4/11/32/33)
السجل: `02_Engine_Code/p5_hardened_txauth/results_v3_battery_v8.1.3_20260904.txt` (MD5 `3cf6ace4eb3cc2b56d7bb3b81543c1d6`)، الحزمة `mcl_txauth_v3_battery.cpp` v3.1 (MD5 `aa50b020759f73ce79196d3b8e071613`)؛ التفاصيل في `p5_hardened_txauth/README.md` (قسم 2026-09-04). **18/18 PASS**؛ T1–T5/T7 متطابقة بايت-بايت مع سجلَي 08-21 و08-22؛ T8 = 3.658 ms (273 tags/s)، T8b = 7.326 ms (137 tx/s).

**Q30 (نفس اليوم):** `p5_hardened_txauth/results_v3_battery_q30_v8.1.3_20260904.txt` — البطارية نفسها على `MCL_T4_Q30` (بلا فاصلة عائمة): **19/19 PASS**، T8 0.395 ms (2,532 tags/s)، T8b 0.788 ms (1,269 tx/s)، T0 1000/1000 متطابقة. يغلق إفصاح §VI/§X.2 «لم تُنفَّذ على Q30».
