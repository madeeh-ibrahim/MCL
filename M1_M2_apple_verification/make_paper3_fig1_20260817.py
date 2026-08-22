import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import re

data = {}
pat = re.compile(r"^(\(\d+,\d+\)),([\d.]+),([\d.]+),(\w+)$")
with open("fig1_arnold_sweep_apple_20260817.csv") as f:
    for line in f:
        m = pat.match(line.strip())
        if not m: continue
        topo, K, chi, cls = m.group(1), float(m.group(2)), float(m.group(3)), m.group(4)
        data.setdefault(topo, []).append((K, chi, cls))

topos  = ["(2,3)", "(3,5)", "(5,7)", "(7,11)"]
titles = ["(p, q) = (2, 3)", "(p, q) = (3, 5)", "(p, q) = (5, 7)", "(p, q) = (7, 11)"]
colors = ["#3b76b8", "#2e8b57", "#c96f34", "#6a5fc9"]
shades = ["#3b76b8", "#2e8b57", "#c96f34", "#6a5fc9"]

fig, axes = plt.subplots(2, 2, figsize=(15.3, 11.0), dpi=200, sharex=True, sharey=True)
for i, (ax, tp) in enumerate(zip(axes.flat, topos)):
    pts = data[tp]
    Ks   = [p[0] for p in pts]
    chis = [p[1] for p in pts]
    # shaded resonance cells (grid step 0.02 -> cell = K +/- 0.01)
    for K, chi, cls in pts:
        if chi > 1000.0:
            ax.axvspan(K-0.01, K+0.01, color=shades[i], alpha=0.18, lw=0, zorder=1)
    ax.plot(Ks, chis, "-", color=colors[i], lw=1.3, alpha=0.65, zorder=2)
    ax.plot(Ks, chis, "o", color=colors[i], ms=5.5, zorder=3)
    ax.axhline(1000.0, color="#cc5555", ls="--", lw=1.4, zorder=2)
    ax.axvline(1.0, color="#999999", ls="--", lw=1.3, zorder=2)
    ax.set_yscale("log")
    ax.set_ylim(150, 1e8)
    ax.set_xlim(0.27, 1.03)
    ax.set_title(titles[i], fontsize=21)
    ax.grid(color="#e5e5e5", lw=0.7, which="both")
    ax.set_axisbelow(True)
    ax.tick_params(labelsize=16)
    n_res = sum(1 for _, c, _ in pts if c > 1000.0)
    ax.text(0.985, 0.955, f"resonant: {n_res}/36", transform=ax.transAxes,
            ha="right", va="top", fontsize=15.5,
            bbox=dict(fc="white", ec="#bbbbbb", boxstyle="round,pad=0.28"))
for ax in axes[1]: ax.set_xlabel("Coupling strength K", fontsize=20)
for ax in axes[:,0]: ax.set_ylabel(r"$\chi^2$ statistic (log scale)", fontsize=20)

fig.text(0.5, 0.012,
  "Shaded: resonance zones ($\\chi^2$ > 1000, worst of 3 seeds)  |  dashed red: $\\chi^2$ = 1000  |  "
  "step-0.02 grid, 500 KB per (K, seed)  |  Tongue density decreases with p+q",
  ha="center", fontsize=15.5)
plt.tight_layout(rect=(0, 0.035, 1, 1))
out = "/Users/madeehibrahim/Desktop/MCL Project Stage 2/05_Scientific_Papers/paper3_fig1.png"
plt.savefig(out, dpi=200, facecolor="white", bbox_inches="tight")
print("saved", out)
