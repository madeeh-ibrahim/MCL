# Independent reference for the Grover model of mcl_grover_resource_estimate.cpp.
# Written from the model description (formulas), NOT transliterated from the
# C++ source.
#   usage: python3 grover_ref.py grover_rev3_20260928.log
import math, re, sys
L2 = math.log2
n, Lt, M = 32, 2**16, 32
iters = 10000 + 40*2
KDF_T = 6*228992; KDF_D = 2*70400
calls = L2(math.pi/4) + 128

def cuccaro(w): return max(0, 2*w-3) if w >= 2 else 0
def gidney(w):  return max(0, w-1)
prim = {}
# model A
prim['A'] = dict(t=7, d=3, add=(cuccaro(n), cuccaro(n)),
                 mul=(sum(2*w+cuccaro(w) for w in range(1,n+1)), sum(2+cuccaro(w) for w in range(1,n+1))),
                 look=(2*(Lt-1), 2*(Lt-1)), unl=(2*(Lt-1), 2*(Lt-1)))
# model B, unary
unl_b = min((math.ceil(Lt/k)+k) for k in [2**j for j in range(0,17)])
prim['Bu'] = dict(t=4, d=1, add=(gidney(n), gidney(n)),
                  mul=(sum(w+gidney(w) for w in range(1,n+1)), sum(1+gidney(w) for w in range(1,n+1))),
                  look=(Lt-1, Lt-1), unl=(unl_b, unl_b))
# model B, QROAM: minimise units, ties -> larger k
best=None
for j in range(0,17):
    k=2**j; u=math.ceil(Lt/k)+M*(k-1)
    if best is None or u <= best[0]: best=(u, math.ceil(Lt/k)+(k-1), k)
prim['Bq'] = dict(prim['Bu']); prim['Bq']['look']=(best[0],best[1])
names={'A':'A-unary','Bu':'B-unary','Bq':'B-QROAM'}
ref={}
for key in ['A','Bu','Bq']:
    p=prim[key]
    for narrow in (False,True):
        nm = 12 if narrow else 6
        units = nm*p['mul'][0] + 3*p['look'][0] + (2*p['unl'][0] if narrow else 0) + 3*p['add'][0]
        layers = (4 if narrow else 2)*p['mul'][1] + p['look'][1] + (p['unl'][1] if narrow else 0) + 3*p['add'][1]
        iterT = 4*units*p['t']; iterD = 4*layers*p['d']
        oT = 2*(iters*iterT + KDF_T); oD = 2*(iters*iterD + KDF_D)
        G = calls+L2(oT); D = calls+L2(oD)
        md = [G + max(0, D-m) for m in (40,64,96)]
        garb = iters*4*(32 if narrow else 192)
        ref[(names[key], 'NARROW' if narrow else 'WIDE')] = dict(iterT=L2(iterT), iterD=L2(iterD), oT=L2(oT), oD=L2(oD), G=G, D=D, md=md, garb=garb,
             prim=(p['add'][0],p['mul'][0],p['look'][0],p['unl'][0]))
# parse the C++ output
txt=open(sys.argv[1]).read()
blocks=re.split(r'\n== ', txt)
bad=0; checked=0
for b in blocks:
    m=re.match(r'(A-unary|B-unary|B-QROAM) / (WIDE|NARROW) ==', b)
    if not m: continue
    r=ref[(m.group(1),m.group(2))]
    def grab(pat):
        mm=re.search(pat,b); return float(mm.group(1))
    got=dict(iterT=grab(r'per-iteration T gates\s*: 2\^([\d.]+)'), iterD=grab(r'per-iteration T-depth\s*: 2\^([\d.]+)'),
             oT=grab(r'per-oracle gates\s*: 2\^([\d.]+)'), oD=grab(r'per-oracle depth\s*: 2\^([\d.]+)'),
             G=grab(r'serial search: gates 2\^([\d.]+)'), D=grab(r'depth 2\^([\d.]+)\n'))
    mds=[float(x) for x in re.findall(r'MAXDEPTH 2\^\d+ : 2\^([\d.]+) gates',b)]
    garb=float(re.search(r'garbage qubits \(no pebbling\): ([\d.e+]+)',b).group(1))
    for k in ['iterT','iterD','oT','oD','G','D']:
        checked+=1
        if abs(got[k]-r[k])>0.0051: bad+=1; print('MISMATCH',m.group(0),k,got[k],r[k])
    for a,bv in zip(mds,r['md']):
        checked+=1
        if abs(a-bv)>0.051: bad+=1; print('MISMATCH',m.group(0),'md',a,bv)
    checked+=1
    if abs(garb-r['garb'])/r['garb']>0.005: bad+=1; print('MISMATCH garbage',garb,r['garb'])
    print(f"{m.group(1):8s} {m.group(2):6s} iterT 2^{r['iterT']:.3f} oT 2^{r['oT']:.3f} oD 2^{r['oD']:.3f}  MD40 2^{r['md'][0]:.2f}  prim {r['prim']}")
# primitive table
for line in txt.splitlines():
    mm=re.match(r'\s+(A-unary|B-unary|B-QROAM)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',line)
    if mm:
        key={'A-unary':'A','B-unary':'Bu','B-QROAM':'Bq'}[mm.group(1)]; p=prim[key]
        exp=(p['add'][0],p['mul'][0],p['look'][0],p['unl'][0]); got=tuple(int(mm.group(i)) for i in (2,3,4,5))
        checked+=1
        if exp!=got: bad+=1; print('MISMATCH prim',mm.group(1),got,exp)
cm=re.search(r'Grover calls \(256-bit key\)\s*: 2\^([\d.]+)',txt); checked+=1
if abs(float(cm.group(1))-calls)>0.0051: bad+=1; print('MISMATCH calls')
print(f"checked {checked} values, mismatches {bad}")
print("AES JNRV log2(1.39*2^245) =",round(245+L2(1.39),3), " AES oracle T log2 =",round(L2(151164),3), " gates log2 =",round(L2(808071+231124+151164+37791),3))
