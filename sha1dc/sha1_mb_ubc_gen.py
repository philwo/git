#!/usr/bin/env python3
"""Generate a pure-C AVX-512 ubc_check_x16 from sha1dc/ubc_check.c.
Translates each scalar bit-expression into __m512i intrinsics. Subexpressions
with no W[] are scalar constants (broadcast with set1); the rest are vector."""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "ubc_check.c")
OUT = os.path.join(HERE, "sha1_mb_ubc.c")
src = open(SRC).read()
dv = re.findall(r'static const uint32_t DV_\w+_bit\s*=\s*\(uint32_t\)\(1\)\s*<<\s*\d+;', src)

# ---- expression translator -------------------------------------------------
def tok(s):
    t=[]; i=0
    while i<len(s):
        c=s[i]
        if c.isspace(): i+=1; continue
        if s[i:i+2] in ('<<','>>','||'): t.append(s[i:i+2]); i+=2; continue
        if c in '()[]^|&~-!': t.append(c); i+=1; continue
        m=re.match(r'[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+', s[i:])
        if not m: raise ValueError(f"bad char {c!r} in {s!r}")
        t.append(m.group()); i+=len(m.group())
    return t

PREC={'||':1,'|':2,'^':3,'&':4,'<<':5,'>>':5,'-':6}
class P:
    def __init__(self,toks): self.t=toks; self.i=0
    def peek(self): return self.t[self.i] if self.i<len(self.t) else None
    def next(self): x=self.t[self.i]; self.i+=1; return x
    def parse(self,mp=1):
        left=self.unary()
        while self.peek() in PREC and PREC[self.peek()]>=mp:
            op=self.next(); right=self.parse(PREC[op]+1); left=binop(op,left,right)
        return left
    def unary(self):
        op=self.peek()
        if op=='~': self.next(); return notbits(self.unary())
        if op=='!': self.next(); return lognot(self.unary())
        return self.primary()
    def primary(self):
        t=self.next()
        if t=='(':
            e=self.parse(1); assert self.next()==')'; return e
        if t=='W':
            assert self.next()=='['; idx=self.next(); assert self.next()==']'
            return ('v', f'W[{idx}]')
        return ('s', t)                       # number or DV_* constant

def tovec(n): return n[1] if n[0]=='v' else f'_mm512_set1_epi32({n[1]})'
def binop(op,L,R):
    if L[0]=='s' and R[0]=='s': return ('s', f'({L[1]} {op} {R[1]})')
    if op in ('<<','>>'):                     # vector shift by scalar constant
        fn='_mm512_slli_epi32' if op=='<<' else '_mm512_srli_epi32'
        return ('v', f'{fn}({tovec(L)}, {R[1]})')
    if op=='||':
        return ('v', f'_mm512_maskz_set1_epi32(_mm512_cmpneq_epi32_mask('
                     f'_mm512_or_si512({tovec(L)},{tovec(R)}), _mm512_setzero_si512()), -1)')
    fn={'^':'_mm512_xor_si512','&':'_mm512_and_si512','|':'_mm512_or_si512','-':'_mm512_sub_epi32'}[op]
    return ('v', f'{fn}({tovec(L)}, {tovec(R)})')
def notbits(x):
    if x[0]=='s': return ('s', f'(~{x[1]})')
    return ('v', f'_mm512_xor_si512({x[1]}, _mm512_set1_epi32(-1))')
def lognot(x):
    if x[0]=='s': return ('s', f'(!{x[1]})')
    return ('v', f'_mm512_maskz_set1_epi32(_mm512_cmpeq_epi32_mask({tovec(x)}, _mm512_setzero_si512()), -1)')
def T(expr): return tovec(P(tok(expr)).parse())

# ---- balanced-paren scanner over the scalar function body ------------------
body = src[src.index('void ubc_check('):]
body = body[body.index('{')+1 : body.index('\n\tdvmask[0]=mask;')]

def matchparen(s,i):        # s[i]=='(' -> index of matching ')'
    d=0
    while i<len(s):
        if s[i]=='(': d+=1
        elif s[i]==')':
            d-=1
            if d==0: return i
        i+=1
    raise ValueError("unbalanced")

out=[]
i=0
while i<len(body):
    if body.startswith('mask &= (', i):
        op=body.index('(', i); cl=matchparen(body,op)
        out.append(f'\tmask = _mm512_and_si512(mask, {T(body[op:cl+1])});')
        i=body.index(';',cl)+1
    elif body.startswith('if (mask & (', i):     # pattern-2 guard: drop it (proven identical)
        op=body.index('(', i+3); cl=matchparen(body,op)
        i=cl+1
    elif body.startswith('if (mask & DV', i):     # single-bit guard
        m=re.match(r'if \(mask & (DV_\w+)\)\s*', body[i:])
        dvbit=m.group(1); after=i+m.end()
        if body.startswith('if (', after):        # pattern-3: if(mask&DVbit) if(COND) mask &= ~DVbit;
            op=body.index('(', after); cl=matchparen(body,op); cond=body[op:cl+1]
            i=body.index(';', cl)+1                # past `mask &= ~DVbit;`
            out.append(f'\tmask = _mm512_andnot_si512(_mm512_and_si512({T(cond)}, '
                       f'_mm512_set1_epi32((int){dvbit})), mask);')
        else:                                      # pattern-2 guard: drop it, next mask&= handles
            i=after
    else:
        i+=1

hdr=['/* AUTO-GENERATED from sha1dc/ubc_check.c by ubc_gen_c.py. Pure C, AVX-512. */',
     '#include <immintrin.h>','#include <stdint.h>','']
hdr += dv + ['',
     'void ubc_check_x16(const __m512i W[65], __m512i dvmask[1]);',
     'void ubc_check_x16(const __m512i W[65], __m512i dvmask[1]) {',
     '\t__m512i mask = _mm512_set1_epi32(-1);']
open(OUT,"w").write('\n'.join(hdr)+'\n'+'\n'.join(out)+'\n\tdvmask[0]=mask;\n}\n')
sys.stderr.write(f"emitted {len(out)} statements, {len(dv)} DV constants\n")
