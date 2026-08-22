> **Publication note (2026-08-22, MCL v0.2.0):** `mcl_simswap_v3.cpp` is **not** in the open archive — it is distributed under `TOOLKIT_ACCESS_POLICY.md` (Addendum 2026-08-22); its record `SIMSWAP_V3_RECORD_20260821.md` and logs are public here. All harnesses in this folder use Apple **CommonCrypto** for SHA-256/HMAC (macOS build only; the engine itself is portable). Compiled binaries are not shipped. Engine pins at run time: `mcl_core.hpp` v8.1.1 → v8.1.3 is KAT-identical (docs + contract narrowing only).

# p2_hardened_auth — الملف المصلَّد لمصادقة الورقة 2 (v2) + بطاريته العدائية

**التاريخ:** 2026-08-21 · **المحرك:** `../mcl_core.hpp` v8.1.1 (بلا أي تعديل) · **التبعيات:** CommonCrypto (macOS) — SHA-256/HMAC حقيقيان لا FNV.

## لماذا
جولة محكّم E2/TIFS (FivePersona ‏07-11/18) أثبتت ثلاث فجوات بروتوكولية في نسخة الورقة 2 المنشورة:
**G1** طيّ التحدي إلى بذرة 64-بت (تصادم الاستجابات)؛ **G2** الاستجابة الخام في النقل العلني تفتح تعدادًا خارجيًا لـ(p,q) من نسخة واحدة؛ **G3** لا دورة حياة للتحدي (إعادة تشغيل/نقل عبر الحسابات والمدققين/إعادة استخدام بعد فشل).

## الملف المصلَّد v2
تحدٍّ عريض 256-بت أحادي الاستخدام (يُستهلك عند أول محاولة نجاحًا أو فشلًا) + سياق `C‖IMSI‖verifier_id` + ‏`R = HMAC-SHA-256(K_wrap, ctx‖raw)` حيث raw = 32 بايت محرك لا تغادر العنصر الآمن أبدًا. دور المحرك محفوظ: (p,q) هوية الجهاز؛ ‏K_wrap يغلق سطح التعداد الخارجي.

## النتيجة — 12/12 PASS (سجل `results_20260821.txt`)
شرعي 1000/1000 · إعادة تشغيل/جلسة جديدة/عبر-مدقق/عبر-حساب/بعد-فشل/تقديم-مزدوج كلها مرفوضة · **T-H1 استنساخ هجوم الطيّ على الشكل القديم (زوج تحديين مختلفين بنفس XOR ⇒ استجابتان متطابقتان بايتيًا)** · **T-H2 الملف المصلَّد يفصلهما** · الخام غائب عن النسخة المنقولة · انهيار 127.79/256 وχ² بايتي 236.9.

## الحدود — مطلوب قبل تبنّي نص الورقة
هذه بطارية **منطق بروتوكول** (أحجام صغيرة حتمية). المطلوب المتبقي: إعادة حملات §VI الإحصائية الكاملة (التوزيعات/الاستقلال/FAR الكبيرة) على هذا الملف، ثم تحرير نص P2. البناء:
```
clang++ -std=c++17 -O2 mcl_auth_hardened.cpp -o mcl_auth_hardened
```
