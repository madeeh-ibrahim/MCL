#!/usr/bin/env python3
"""ت-309 analysis (2026-09-30). (b) window sweeps: per cell, lock class of the cell and of its partner
(period <= 256 or lambda_1 <= 0.02, as in Sec. III.C of the paper), failure to decorrelate (max |r_ens| >= 0.3
over the 200-step window, or time-series max |r_lag| > 0.5, or MI > 0.5 bit) -> counts per class, exceptions,
window list.  (a) decorrelation-time runs: robust t_dec (|r_ens| < 4/sqrt(n) for five consecutive steps,
recomputed from the per-step file), regression of t_dec on ln(1/delta_1), growth slope / lambda_1.
Writes window/window_summary.txt, window/window_table.md, decorr/decorr_fit_table.csv, decorr/decorr_summary.txt
and paper3_fig6.png."""
import csv, glob, math, os, sys
import numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt

LAMBDA_LOCK = 0.02
def locked(l1, per): return (per > 0) or (l1 <= LAMBDA_LOCK)
def fails(r): return (float(r["max_abs_r_ens"]) >= 0.3) or (float(r["rlag_max64"]) > 0.5) or (float(r["MI_MM_bits"]) > 0.5)

# ---------------- (b) windows: classification by the intrinsic mixing diagnostic ----------------
ACF_NONMIX = 0.1        # single-trajectory |rho(tau)| FAR tail (tau in [4001,4096]) at or above this = non-mixing (a periodic component that does not decay: periodic, quasi-periodic or banded chaos); the near tail [65,512] is reported alongside
def load_mixing(name):
    f = f"mixing/{name}_mixing.csv"
    if not os.path.exists(f): return {}
    return {round(float(r["param"]), 6): r for r in csv.DictReader(open(f))}
wout = []; wtab = ["| sweep | cells | non-mixing cells (runs) | of which locked (λ₁ ≤ 0.02 or periodic) / banded chaos (λ₁ > 0.02) | both non-mixing: n / fail | both mixing: n / fail | mixed pair: n / fail | mixing-cell maxima \\|r_lag\\| / MI (bit) / \\|r_ens\\| | expected null extreme \\|r_ens\\| |", "|---|---:|---|---|---|---|---|---|---|"]
sweeps = {}
for f in sorted(glob.glob("window/*.csv")):
    if "_slice" in os.path.basename(f): continue
    rows = [r for r in csv.DictReader(open(f))]
    if not rows: continue
    name = os.path.basename(f)[:-4]; rows.sort(key=lambda r: float(r["param"])); mix = load_mixing(name)
    fam = rows[0]["family"]; K = rows[0]["K"]; pn = {"henon": "a", "logistic": "r", "tent": "μ"}[fam]
    ok = [r for r in rows if int(r["escaped"]) == 0]; esc = len(rows) - len(ok)
    prm = np.array([float(r["param"]) for r in ok]); l1 = np.array([float(r["lambda1_A"]) for r in ok])
    lockA = np.array([locked(float(r["lambda1_A"]), int(r["period_A"])) for r in ok]); lockB = np.array([locked(float(r["lambda1_B"]), int(r["period_B"])) for r in ok])
    step = round(float(ok[1]["param"]) - float(ok[0]["param"]), 6); dl = round(float(ok[0]["paramB"]) - float(ok[0]["param"]), 6)
    def tail_of(v):
        r = mix.get(round(v, 6))
        if not r: return float("nan")
        return float(r["acf_far_max_4001_4096"]) if "acf_far_max_4001_4096" in r else float(r["acf_tail_max_65_512"])
    def near_of(v):
        r = mix.get(round(v, 6)); return float(r["acf_tail_max_65_512"]) if r else float("nan")
    tailA = np.array([tail_of(float(r["param"])) for r in ok]); nearA = np.array([near_of(float(r["param"])) for r in ok])
    # the partner c + delta (half a step) is not on the mixing grid: use the nearer grid neighbours (c and c + step), non-mixing if either is
    tailB = np.array([max(tail_of(float(r["param"])), tail_of(float(r["param"]) + step)) if not math.isnan(tail_of(float(r["param"]) + step)) else tail_of(float(r["param"])) for r in ok])
    have_mix = not np.isnan(tailA).all()
    nmA = (tailA >= ACF_NONMIX) | lockA if have_mix else lockA.copy(); nmB = (tailB >= ACF_NONMIX) | lockB if have_mix else lockB.copy()
    fl = np.array([fails(r) for r in ok])
    NN = nmA & nmB; MM = ~nmA & ~nmB; MX = ~(NN | MM)
    banded = nmA & ~lockA
    n = len(ok); n_seeds = int(ok[0]["n_seeds"]); W = int(ok[0]["W"])
    exp_ext = math.sqrt(2 * math.log(W * max(1, int(MM.sum())))) / math.sqrt(n_seeds)
    runs = []; i = 0
    while i < n:
        if nmA[i]:
            j = i
            while j + 1 < n and nmA[j + 1]: j += 1
            pers = sorted({int(r["period_A"]) for r in ok[i:j + 1] if int(r["period_A"]) > 0}); lags = sorted({int(mix[round(float(r["param"]), 6)]["acf_pos_peak_lag"]) for r in ok[i:j + 1] if round(float(r["param"]), 6) in mix and int(mix[round(float(r["param"]), 6)]["acf_pos_peak_lag"]) > 0})
            runs.append((prm[i], prm[j], j - i + 1, int(lockA[i:j + 1].sum()), pers, lags, float(np.median(l1[i:j + 1])))); i = j + 1
        else: i += 1
    mm_rl = max((float(r["rlag_max64"]) for r, c in zip(ok, MM) if c), default=float("nan")); mm_mi = max((float(r["MI_MM_bits"]) for r, c in zip(ok, MM) if c), default=float("nan"))
    mm_re = max((float(r["max_abs_r_ens"]) for r, c in zip(ok, MM) if c), default=float("nan"))
    wout.append(f"== {name}: {fam} (p,q)=({ok[0]['p']},{ok[0]['q']}) K={K}, {pn} in [{prm.min():.3f},{prm.max():.3f}] step {step}, partner {pn}+{dl}; cells {len(rows)} (escaped {esc}); n_seeds {n_seeds}, T {ok[0]['T']}, W {W}, N {ok[0]['N']}; mixing diagnostic {'joined' if have_mix else 'MISSING'} (non-mixing = acf tail >= {ACF_NONMIX} or locked)")
    wout.append(f"   non-mixing cells (A) {int(nmA.sum())} in {len(runs)} runs: locked {int(lockA.sum())}, banded-chaotic (λ₁>0.02, tail>={ACF_NONMIX}) {int(banded.sum())}; mixing cells {int((~nmA).sum())}")
    wout.append(f"   pairs: both non-mixing {int(NN.sum())} -> fail {int((fl & NN).sum())}; both mixing {int(MM.sum())} -> fail {int((fl & MM).sum())}; mixed {int(MX.sum())} -> fail {int((fl & MX).sum())}")
    wout.append(f"   paper's λ-criterion alone: locked&locked {int((lockA & lockB).sum())} -> fail {int((fl & lockA & lockB).sum())}; chaotic&chaotic {int((~lockA & ~lockB).sum())} -> fail {int((fl & ~lockA & ~lockB).sum())} (the failures among λ₁>0.02 cells are the banded ones)")
    wout.append(f"   mixing-cell maxima: |r_lag| {mm_rl:.4f}, MI {mm_mi:.4f} bit, |r_ens| {mm_re:.4f} (expected extreme of {W}x{int(MM.sum())} null values at n={n_seeds}: {exp_ext:.3f})")
    if have_mix:
        amb = int(((tailA >= 0.05) & (tailA < 0.3)).sum()); wout.append(f"   acf FAR-tail distribution (τ ∈ [4001,4096]): <0.05 {int((tailA < 0.05).sum())}, 0.05-0.1 {int(((tailA >= 0.05) & (tailA < 0.1)).sum())}, 0.1-0.3 {int(((tailA >= 0.1) & (tailA < 0.3)).sum())}, >=0.3 {int((tailA >= 0.3).sum())} (0.05-0.3: {amb} cells); near tail [65,512] >= 0.1: {int((nearA >= 0.1).sum())} cells")
        # graded view: failure rate of pairs versus the smaller far tail of the two members
        tmin = np.minimum(tailA, tailB); wout.append("   failure rate of pairs by min(far tail of the two members): " + "; ".join(f"[{lo},{hi}): {int((fl & (tmin >= lo) & (tmin < hi)).sum())}/{int(((tmin >= lo) & (tmin < hi)).sum())}" for lo, hi in [(0, 0.05), (0.05, 0.1), (0.1, 0.3), (0.3, 0.6), (0.6, 0.9), (0.9, 1.01)]))
        # slowly-decaying cells: near tail >= 0.1 but far tail < 0.1 (mixing, near a band merging)
        slow = (nearA >= 0.1) & (tailA < ACF_NONMIX); wout.append(f"   slowly-decaying (mixing) cells: near tail >= 0.1 but far tail < {ACF_NONMIX}: {int(slow.sum())} cells, of which fail {int((fl & slow).sum())}")
    for (a, b, w, nl, pers, lags, ml) in runs: wout.append(f"   non-mixing run {pn} = {a:.3f} .. {b:.3f} ({w} cells; locked {nl}, banded {w - nl}; median λ₁ {ml:+.3f}) periods {pers if pers else '-'} band-cycle lags {lags if lags else '-'}")
    for r, nn, mm, fz, ta, tb in zip(ok, NN, MM, fl, tailA, tailB):
        if (nn and not fz) or (mm and fz):
            wout.append(f"   EXCEPTION {pn}={float(r['param']):.4f}: class {'NN' if nn else 'MM'} fail={int(fz)} l1A={float(r['lambda1_A']):+.4f} perA={r['period_A']} tailA={ta:.3f} | l1B={float(r['lambda1_B']):+.4f} perB={r['period_B']} tailB={tb:.3f} | r_ens={float(r['max_abs_r_ens']):.3f} rlag={float(r['rlag_max64']):.3f} MI={float(r['MI_MM_bits']):.3f}")
    wtab.append(f"| {fam} K={K} ({pn} ∈ [{prm.min():.3f}, {prm.max():.3f}]) | {len(rows)}{' (' + str(esc) + ' escaped)' if esc else ''} | {int(nmA.sum())} ({len(runs)}) | {int(lockA.sum())} / {int(banded.sum())} | {int(NN.sum())} / {int((fl & NN).sum())} | {int(MM.sum())} / {int((fl & MM).sum())} | {int(MX.sum())} / {int((fl & MX).sum())} | {mm_rl:.3f} / {mm_mi:.3f} / {mm_re:.3f} | {exp_ext:.3f} |")
    sweeps[name] = dict(fam=fam, K=K, pn=pn, prm=prm, l1=l1, nmA=nmA, lockA=lockA, banded=banded, NN=NN, MM=MM, fl=fl, runs=runs, tail=tailA, near=nearA)
open("window/window_summary.txt", "w").write("\n".join(wout) + "\n"); open("window/window_table.md", "w").write("\n".join(wtab) + "\n")
print("\n".join(wout)); print(); print("\n".join(wtab))

# ---------------- (a) decorrelation time ----------------
def robust_tdec(steps_file, delta, n, persist=5, k=4.0):
    rs = [r for r in csv.DictReader(open(steps_file)) if abs(float(r["delta"]) - delta) <= 1e-15 + 1e-6 * delta]
    floor = k / math.sqrt(n); vals = [abs(float(r["r_x1"])) for r in rs]
    for t in range(len(vals) - persist + 1):
        if all(v < floor for v in vals[t:t + persist]): return t + 1
    return -1
drows = []; dfit = []; dsum = []
basemix = {}
for f in glob.glob("mixing/basepoints_*.csv"):
    for r in csv.DictReader(open(f)): basemix[(r["family"], r["p"], r["q"], round(float(r["param"]), 6))] = r
for f in sorted(glob.glob("decorr/res_*_summary.csv")):
    for r in csv.DictReader(open(f)):
        r["file"] = os.path.basename(f); r["t_dec_tool"] = r["t_dec"]; r["t_dec"] = str(robust_tdec(f.replace("_summary.csv", "_steps.csv"), float(r["delta"]), int(r["n_seeds"]))); drows.append(r)
groups = {}
for r in drows:
    if r["mode"] in ("zero", "pq"): continue
    groups.setdefault((r["file"], r["family"], r["p"], r["q"], r["K"], r["param"], r["mode"]), []).append(r)
for key, rs in sorted(groups.items()):
    lam = float(rs[0]["lambda1"]); x = np.array([-float(r["mean_ln_d1"]) for r in rs]); td = np.array([float(r["t_dec"]) for r in rs]); ts = np.array([float(r["t_sat"]) for r in rs])
    ok = (td > 0) & (ts > 0) & (x > 3)
    if ok.sum() >= 3:
        A = np.vstack([x[ok], np.ones(ok.sum())]).T; (a_d, b_d) = np.linalg.lstsq(A, td[ok], rcond=None)[0]; (a_s, b_s) = np.linalg.lstsq(A, ts[ok], rcond=None)[0]
    else: a_d = b_d = a_s = b_s = float("nan")
    t0 = float(np.mean(td[ok] - x[ok] / lam)) if ok.sum() else float("nan")           # intercept with slope fixed at 1/lambda_1
    gs = [float(r["growth_slope"]) for r in rs if r["growth_slope"] not in ("nan", "") and int(r["growth_pts"]) >= 3]
    lag = float(np.mean(td[ok] - ts[ok])) if ok.sum() else float("nan")
    bm = basemix.get((key[1], key[2], key[3], round(float(key[5]), 6))); far = float(bm["acf_far_max_4001_4096"]) if bm else float("nan"); dec = int(bm["acf_decay_lag_005"]) if bm else -1
    dfit.append({"file": key[0], "family": key[1], "p": key[2], "q": key[3], "K": key[4], "param": key[5], "mode": key[6], "lambda1": lam, "inv_lambda1": 1 / lam,
                 "growth_slope_mean": np.mean(gs) if gs else float("nan"), "growth_over_lambda_min": min(gs) / lam if gs else float("nan"), "growth_over_lambda_max": max(gs) / lam if gs else float("nan"), "n_growth": len(gs),
                 "slope_t_dec": a_d, "ratio_slope_tdec_x_lambda": a_d * lam, "intercept_t_dec": b_d, "t0_fixed_slope": t0, "slope_t_sat": a_s, "mean_tdec_minus_tsat": lag, "n_points": int(ok.sum()), "base_far_tail": far, "base_acf_decay_lag": dec, "base_nonmixing": int(far >= 0.1) if not math.isnan(far) else -1,
                 "tdec_list": " ".join(str(int(v)) for v in td), "delta_list": " ".join(r["delta"] for r in rs), "n_seeds": rs[0]["n_seeds"], "burnin": rs[0]["burnin"]})
with open("decorr/decorr_fit_table.csv", "w", newline="") as fo:
    w = csv.DictWriter(fo, fieldnames=list(dfit[0].keys())); w.writeheader(); w.writerows(dfit)
dsum.append(f"{'family':9s} {'(p,q)':6s} {'K':>6s} {'param':>7s} {'axis':6s} {'λ1':>7s} {'growth/λ1 min–max (n)':>24s} {'slope·λ1':>9s} {'t0':>5s} {'tdec−tsat':>9s} {'far-tail':>8s} {'τ_c':>4s} {'t_dec list':>28s}")
for o in dfit:
    dsum.append(f"{o['family']:9s} ({o['p']},{o['q']}) {o['K']:>6s} {o['param']:>7s} {o['mode']:6s} {o['lambda1']:7.4f} {o['growth_over_lambda_min']:9.4f}–{o['growth_over_lambda_max']:.4f} ({o['n_growth']}) {o['ratio_slope_tdec_x_lambda']:9.3f} {o['t0_fixed_slope']:5.2f} {o['mean_tdec_minus_tsat']:9.2f} {o['base_far_tail']:8.3f} {o['base_acf_decay_lag']:4d} {o['tdec_list']:>28s}{'   <- NON-MIXING base point (banded): separation grows at λ₁ but r_ens never collapses' if o['base_nonmixing'] == 1 else ''}")
ctrl = [r for r in drows if r["mode"] in ("zero", "pq")]
for r in ctrl: dsum.append(f"control {r['family']} {r['mode']} delta={r['delta']}: <ln d>(1)={r['mean_ln_d1']} t_dec={r['t_dec']} r(T)={r['r_at_T']}")
open("decorr/decorr_summary.txt", "w").write("\n".join(dsum) + "\n"); print(); print("\n".join(dsum))

# ---------------- figure (2 x 3) ----------------
plt.rcParams.update({"font.size": 7, "axes.titlesize": 7.5, "axes.labelsize": 7.5, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "legend.fontsize": 5.8})
fig, ax = plt.subplots(2, 3, figsize=(7.4, 5.3))
fams = ["henon", "logistic", "tent"]; titles = {"henon": "coupled Hénon (a)", "logistic": "coupled logistic (r)", "tent": "coupled tent (μ)"}
for j, fam in enumerate(fams):
    a = ax[0, j]; 
    for o in [d for d in dfit if d["family"] == fam and d["mode"] == "param" and d["p"] == "3" and "burnin0" not in d["file"] and d["base_nonmixing"] != 1]:
        rs = groups[(o["file"], o["family"], o["p"], o["q"], o["K"], o["param"], o["mode"])]
        x = np.array([-float(r["mean_ln_d1"]) for r in rs]); td = np.array([float(r["t_dec"]) for r in rs]); m = td > 0
        pn = {"henon": "a", "logistic": "r", "tent": "μ"}[fam]; lam = o["lambda1"]
        ln = a.plot(x[m], td[m], "o", ms=2.6, label=f"{pn} = {float(o['param']):g}: λ₁ = {lam:.3f}, slope×λ₁ = {o['ratio_slope_tdec_x_lambda']:.2f}")[0]
        xx = np.linspace(0, max(x[m]) if m.any() else 30, 10); a.plot(xx, o["t0_fixed_slope"] + xx / lam, "--", lw=1, color=ln.get_color())
    a.set_xlabel("ln(1/δ₁)"); a.set_ylabel("t_dec (iterations)"); a.set_title({"henon": "coupled Hénon: decorrelation time", "logistic": "coupled logistic: decorrelation time", "tent": "coupled tent: decorrelation time"}[fam]); a.legend(loc="upper left", frameon=False)
    b = ax[1, j]
    cand = [s_ for s_ in sweeps.values() if s_["fam"] == fam]
    Kmax = max(float(c["K"]) for c in cand)
    for s_ in sorted(cand, key=lambda s_: -float(s_["K"])):
        main = float(s_["K"]) == Kmax
        h1 = b.plot(s_["prm"], s_["l1"], "-", lw=0.6, color="tab:blue" if main else "tab:green")[0]
        h2 = b.plot(s_["prm"], s_["tail"], "-", lw=0.5, alpha=0.85, color="tab:orange" if main else "tab:red")[0] if not np.isnan(s_["tail"]).all() else None
        ff = s_["fl"]; h3 = b.plot(s_["prm"][ff], np.full(ff.sum(), -0.12 if main else -0.17), "r|", ms=3.5, mew=0.6)[0]
        lk = s_["lockA"]; bd = s_["banded"]
        h4 = b.fill_between(s_["prm"], -0.2, 1.05, where=lk, color="gray", alpha=0.22, lw=0, step="mid")
        h5 = b.fill_between(s_["prm"], -0.2, 1.05, where=bd, color="tab:red", alpha=0.12, lw=0, step="mid")
        if main and j == 0: legend_handles = [h1, h2, h3, h4, h5]
    b.axhline(0, color="k", lw=0.5); b.axhline(LAMBDA_LOCK, color="k", lw=0.5, ls=":"); b.set_ylim(-0.2, 1.05)
    b.set_xlabel({"henon": "a", "logistic": "r", "tent": "μ"}[fam]); b.set_ylabel("λ₁ ;  persistent |ρ|"); b.set_title({"henon": "coupled Hénon: mixing boundary", "logistic": "coupled logistic: mixing boundary", "tent": "coupled tent: mixing boundary"}[fam])
fig.legend(legend_handles, ["λ₁ of the cell", "persistent autocorrelation max |ρ(τ)|, τ ∈ [4001, 4096]", "pair (c, c + 0.0005) fails to decorrelate", "locked cells", "banded chaos (λ₁ > 0.02, non-mixing)"], loc="lower center", ncol=3, frameon=False, handlelength=1.6, columnspacing=1.2)
fig.tight_layout(); fig.subplots_adjust(bottom=0.15, hspace=0.45, wspace=0.32); fig.savefig("paper3_fig6.png", dpi=300); print("figure written: paper3_fig6.png")
