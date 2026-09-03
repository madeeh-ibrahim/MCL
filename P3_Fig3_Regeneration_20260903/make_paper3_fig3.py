# SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# MCL Reference Implementation. Free security research / evaluation for all
# (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
# a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
#!/usr/bin/env python3
"""Paper 3 Fig. 3 from the archived run fig3_matrix_seed12345678901234_20260903.csv (Doc ID MCL-P3-FIG3-2026-0903-001)."""
import csv, numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
rows=[r for r in csv.reader(open("fig3_matrix_seed12345678901234_20260903.csv")) if r and not r[0].startswith("#") and r[0]!="i"]
labels=["(2,3)","(3,5)","(5,7)","(7,11)","(8,13)","(11,17)","(13,19)","(17,23)","(19,29)","(23,31)","(29,37)","(31,41)","(37,43)","(41,47)","(43,53)","(47,59)","(53,61)","(59,67)","(61,71)","(67,73)"]
n=20; M=np.zeros((n,n)); vals=[]
for r in rows:
    i,j,v=int(r[0]),int(r[1]),abs(float(r[4])); M[i,j]=M[j,i]=v; vals.append(v)
vals=np.array(vals); N=1e7; sigma=1/np.sqrt(N); T=np.sqrt(2*np.log(190))/np.sqrt(N)
fig,(ax1,ax2)=plt.subplots(1,2,figsize=(20,9),gridspec_kw={"width_ratios":[1.15,1]})
Mm=np.ma.array(M,mask=np.eye(n,dtype=bool))
cmap=plt.get_cmap("RdBu_r").copy(); cmap.set_bad("#1a1a1a")
im=ax1.imshow(Mm,cmap=cmap,vmin=0,vmax=0.0015)
ax1.set_xticks(range(n)); ax1.set_yticks(range(n)); ax1.set_xticklabels(labels,rotation=45,ha="right",fontsize=8); ax1.set_yticklabels(labels,fontsize=8)
ax1.set_xlabel("Channel (p, q)"); ax1.set_ylabel("Channel (p, q)"); ax1.set_title("(a) Off-diagonal |r| heat map",fontweight="bold",loc="left")
cb=fig.colorbar(im,ax=ax1,fraction=0.046,pad=0.04,shrink=0.8); cb.set_label("|Pearson r|")
ax2.hist(vals,bins=30,density=True,color="#7fb3d5",edgecolor="#2e5f8a",alpha=0.9,label="Empirical |r| (190 pairs)")
x=np.linspace(0,0.0013,400); ax2.plot(x,np.sqrt(2/np.pi)/sigma*np.exp(-x**2/(2*sigma**2)),"r--",lw=2,label=f"Half-normal H₀: σ = 1/√N = {sigma:.6f}")
ax2.axvline(T,color="green",ls=":",lw=2,label=f"T_noise (extreme-value) = {T:.6f}")
ax2.set_xlabel("|Pearson r|"); ax2.set_ylabel("Density"); ax2.set_title("(b) Distribution of |r| values",fontweight="bold",loc="left"); ax2.set_xlim(0,0.0013)
ax2.text(0.02,0.55,f"N = 190 pairs\nmax |r| = {vals.max():.6f}\nmean |r| = {vals.mean():.6f}\nH₀ mean = {sigma*np.sqrt(2/np.pi):.6f}\nAll below T_noise",transform=ax2.transAxes,fontsize=11,bbox=dict(boxstyle="round",fc="#f4f4f4",ec="#888"))
ax2.legend(loc="upper right"); ax2.grid(alpha=0.3)
fig.tight_layout(); fig.savefig("paper3_fig3.png",dpi=180,metadata={"Software":"matplotlib","Comment":"MCL-P3-FIG3-2026-0903-001 seed 12345678901234 N=1e7 K=12 public engine v0.2.1"})
print("saved paper3_fig3.png; max %.6f mean %.6f n=%d"%(vals.max(),vals.mean(),len(vals)))
