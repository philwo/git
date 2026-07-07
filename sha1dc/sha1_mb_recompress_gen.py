#!/usr/bin/env python3
"""Generate the 16-wide AVX-512 SHA-1 recompression header sha1_mb_recompress.h.
Input: the SHA1_RECOMPRESS(t) macro body in sha1dc/sha1.c. Every line of the
form "if (t > N) HASHCLASH_SHA1COMPRESS_ROUNDx_STEP[_BW](a,b,c,d,e, me2, N)"
is translated into an __m512i step. The "me2" operand only appears in that
macro, so scanning the whole sha1.c file safely picks out just those lines and
needs no separate extracted input file. Run this from anywhere:
    python3 sha1dc/sha1_mb_recompress_gen.py
It rewrites sha1dc/sha1_mb_recompress.h next to this script."""
import os, re
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sha1.c")
OUT = os.path.join(HERE, "sha1_mb_recompress.h")
lines = open(SRC).read().splitlines()
step = re.compile(r'if \(t (>|<=) (\d+)\) HASHCLASH_SHA1COMPRESS_ROUND(\d)_STEP(_BW)?\(([a-e]), ([a-e]), ([a-e]), ([a-e]), ([a-e]), me2, (\d+)\)')
K = {1:'0x5A827999',2:'0x6ED9EBA1',3:'0x8F1BBCDC',4:'0xCA62C1D6'}
V = {'a':'va','b':'vb','c':'vc','d':'vd','e':'ve'}

def emit(T):
    out=[]
    out.append(f'static inline __mmask16 recompress_x16_{T}(const __m512i me2[80], const __m512i st[5], const __m512i post[5]){{')
    out.append('\t__m512i va=st[0],vb=st[1],vc=st[2],vd=st[3],ve=st[4];')
    out.append('\t__m512i ia,ib,ic,id,ie,oa,ob,oc,od,oe;')
    # backward pass (active when T > k)
    for ln in lines:
        m=step.search(ln)
        if not m: continue
        op,k,r,bw,g1,g2,g3,g4,g5,kk = m.group(1),int(m.group(2)),int(m.group(3)),m.group(4),*[m.group(i) for i in range(5,10)],int(m.group(10))
        if bw and op=='>' and T>k:
            v1,v2,v3,v4,v5=V[g1],V[g2],V[g3],V[g4],V[g5]
            out.append(f'\t{v2}=RR30({v2}); {v5}=SUB({v5}, ADD(ADD(A5({v1}), F{r}({v2},{v3},{v4})), ADD(_mm512_set1_epi32({K[r]}), me2[{kk}])));')
    out.append('\tia=va;ib=vb;ic=vc;id=vd;ie=ve;')
    out.append('\tva=st[0];vb=st[1];vc=st[2];vd=st[3];ve=st[4];')
    # forward pass (active when T <= k)
    for ln in lines:
        m=step.search(ln)
        if not m: continue
        op,k,r,bw,g1,g2,g3,g4,g5,kk = m.group(1),int(m.group(2)),int(m.group(3)),m.group(4),*[m.group(i) for i in range(5,10)],int(m.group(10))
        if (not bw) and op=='<=' and T<=k:
            v1,v2,v3,v4,v5=V[g1],V[g2],V[g3],V[g4],V[g5]
            out.append(f'\t{v5}=ADD({v5}, ADD(ADD(A5({v1}), F{r}({v2},{v3},{v4})), ADD(_mm512_set1_epi32({K[r]}), me2[{kk}]))); {v2}=R30({v2});')
    out.append('\toa=ADD(ia,va);ob=ADD(ib,vb);oc=ADD(ic,vc);od=ADD(id,vd);oe=ADD(ie,ve);')
    out.append('\treturn _mm512_cmpeq_epi32_mask(oa,post[0]) & _mm512_cmpeq_epi32_mask(ob,post[1])'
               ' & _mm512_cmpeq_epi32_mask(oc,post[2]) & _mm512_cmpeq_epi32_mask(od,post[3])'
               ' & _mm512_cmpeq_epi32_mask(oe,post[4]);')
    out.append('}')
    return '\n'.join(out)

hdr=['/* AUTO-GENERATED 16-wide SHA-1 recompression from sha1dc SHA1_RECOMPRESS. */',
     '#pragma once','#include <immintrin.h>','#include <stdint.h>',
     '#define A5(x) _mm512_rol_epi32((x),5)','#define R30(x) _mm512_rol_epi32((x),30)','#define RR30(x) _mm512_ror_epi32((x),30)',
     '#define ADD(x,y) _mm512_add_epi32((x),(y))','#define SUB(x,y) _mm512_sub_epi32((x),(y))',
     '#define F1(b,c,d) _mm512_ternarylogic_epi32((b),(c),(d),0xCA)','#define F2(b,c,d) _mm512_ternarylogic_epi32((b),(c),(d),0x96)',
     '#define F3(b,c,d) _mm512_ternarylogic_epi32((b),(c),(d),0xE8)','#define F4(b,c,d) _mm512_ternarylogic_epi32((b),(c),(d),0x96)','']
open(OUT,"w").write('\n'.join(hdr)+'\n'+emit(58)+'\n'+emit(65)+'\n')
print("generated " + OUT)
