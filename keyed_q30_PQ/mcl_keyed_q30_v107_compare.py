#!/usr/bin/env python3
"""Compare the dumps of mcl_keyed_q30_v107_dump built against sidecar v1.0.6 and
against v1.0.7.

usage: mcl_keyed_q30_v107_compare.py dump_v106.txt dump_v107.txt

Expectations, written before the first comparison:
  E0  both dumps name the same engine        (guard against a build that picked
                                              up another mcl_core.hpp)
  E1  every T4W line is identical            (weight derivation untouched)
  E2  every T4C line is identical            (keystream and commitments untouched)
  E3  CEP lines differ exactly for the keys that v1.0.6 flags as class keys
  E4  v1.0.7 flags no key
  E5  COUT lines differ exactly for the class keys among the dumped outputs,
      and every class key is among them
Exit code 0 when all six hold.
"""
import sys
def load(p):
    d = {'T4W': {}, 'T4C': {}, 'CEP': {}, 'COUT': {}, 'engine': []}
    for ln in open(p, encoding='utf-8'):
        f = ln.split()
        if len(f) == 3 and f[0] == '#' and f[1] == 'engine':
            d['engine'].append(f[2])
        if not f or f[0].startswith('#'): continue
        if f[0] == 'T4W':  d['T4W'][int(f[1])] = tuple(f[2:])
        elif f[0] == 'T4C': d['T4C'][(int(f[1]), int(f[2]))] = tuple(f[3:])
        elif f[0] == 'CEP': d['CEP'][int(f[1])] = (int(f[2]), f[3])
        elif f[0] == 'COUT': d['COUT'][int(f[1])] = f[2]
    return d
a, b = load(sys.argv[1]), load(sys.argv[2])
ok = True
def check(name, cond, detail):
    global ok
    ok = ok and cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}: {detail}")
check('E0', len(a['engine']) == 1 and a['engine'] == b['engine'],
      f"engine named by the dumps: {a['engine']} and {b['engine']}")
t4w = [k for k in a['T4W'] if a['T4W'][k] != b['T4W'].get(k)]
check('E1', not t4w and len(a['T4W']) == len(b['T4W']) == 65536,
      f"{len(a['T4W'])} weight sets compared, {len(t4w)} differ")
t4c = [k for k in a['T4C'] if a['T4C'][k] != b['T4C'].get(k)]
check('E2', not t4c and len(a['T4C']) == len(b['T4C']) == 1024,
      f"{len(a['T4C'])} engine runs compared (keystream, commit32, commit32_oneway), {len(t4c)} differ")
cls_a = sorted(k for k, v in a['CEP'].items() if v[0] == 1)
cls_b = sorted(k for k, v in b['CEP'].items() if v[0] == 1)
cep = sorted(k for k in a['CEP'] if a['CEP'][k][1] != b['CEP'][k][1])
check('E3', cep == cls_a and len(a['CEP']) == len(b['CEP']) == 200000,
      f"{len(a['CEP'])} epoch lists compared, {len(cep)} differ; class keys under v1.0.6: {len(cls_a)}")
check('E4', not cls_b, f"class keys under v1.0.7: {len(cls_b)}")
cout = sorted(k for k in a['COUT'] if a['COUT'][k] != b['COUT'].get(k))
want = [k for k in cls_a if k in a['COUT']]
check('E5', cout == want and want == cls_a and set(a['COUT']) == set(b['COUT']),
      f"{len(a['COUT'])} cascade outputs compared, {len(cout)} differ; class keys among them: {len(want)} of {len(cls_a)}")
print("  class keys (v1.0.6):", cls_a)
print("ALL EXPECTATIONS MET" if ok else "AT LEAST ONE EXPECTATION FAILED")
sys.exit(0 if ok else 1)
