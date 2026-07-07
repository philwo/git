/* Batched multi-buffer SHA-1DC hasher (AVX-512, 16-way). Pure C.
 * Runtime path uses only AVX-512 + the sha1_dvs disturbance-vector table;
 * it never calls a scalar sha1dc routine. See sha1_mb.h. */
#include "sha1_mb.h"

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sha1_mb_recompress.h"
#include "ubc_check.h"     /* dv_info_t, extern sha1_dvs[] */

void ubc_check_x16(const __m512i W[65], __m512i dvmask[1]);   /* generated: ubc_x16_c.c */

#define ROL(x,n) _mm512_rol_epi32((x),(n))
#define CH(b,c,d)  _mm512_ternarylogic_epi32((b),(c),(d),0xCA)
#define PAR(b,c,d) _mm512_ternarylogic_epi32((b),(c),(d),0x96)
#define MAJ(b,c,d) _mm512_ternarylogic_epi32((b),(c),(d),0xE8)

static inline __m512i mbswap(void){ return _mm512_set_epi8(
	12,13,14,15,8,9,10,11,4,5,6,7,0,1,2,3, 12,13,14,15,8,9,10,11,4,5,6,7,0,1,2,3,
	12,13,14,15,8,9,10,11,4,5,6,7,0,1,2,3, 12,13,14,15,8,9,10,11,4,5,6,7,0,1,2,3); }
#define MBSWAP mbswap()

/* disturbance-vector table, transposed for gather: g_dmT[t][dvidx] */
static uint32_t g_dmT[80][40];
static int8_t   g_maskb2dv[32];
/* The whole TU is built with -mavx512*, so the compiler may auto-vectorize this
 * table fill into AVX-512 (clang emits vpscatterdd). But the constructor below
 * runs from .init_array at startup, before any sha1_mb_available() check, so on
 * a CPU without AVX-512 that would SIGILL. Force scalar codegen for init_dm. */
#if defined(__clang__)
__attribute__((optnone))
#elif defined(__GNUC__)
__attribute__((optimize("no-tree-vectorize")))
#endif
static void init_dm(void){
	for (int i = 0; sha1_dvs[i].dvType; i++){
		g_maskb2dv[sha1_dvs[i].maskb] = (int8_t)i;
		for (int t = 0; t < 80; t++) g_dmT[t][i] = sha1_dvs[i].dm[t];
	}
}
/* Fill the DV tables once, before any thread can call sha1_mb_hash(); this
 * avoids a data race since index-pack calls the hasher from many threads. */
static void __attribute__((constructor)) sha1_mb_init_tables(void){ init_dm(); }

/* gather word i of the current block from 16 per-lane 64-bit addresses */
static inline __m512i gather_word(const uint64_t addr[16], int i){
	__m512i off = _mm512_set1_epi64(4*i);
	__m512i lo = _mm512_add_epi64(_mm512_loadu_si512(addr), off);
	__m512i hi = _mm512_add_epi64(_mm512_loadu_si512(addr+8), off);
	__m256i gl = _mm512_i64gather_epi32(lo, (const void*)0, 1);
	__m256i gh = _mm512_i64gather_epi32(hi, (const void*)0, 1);
	__m512i g  = _mm512_inserti64x4(_mm512_castsi256_si512(gl), gh, 1);
	return _mm512_shuffle_epi8(g, MBSWAP);
}

struct MB {
	__m512i a,b,c,d,e;
	uint64_t blkaddr[16];
	uint64_t full_left[16];   /* block count; wide enough for len >= 256 GiB */
	uint64_t tailaddr[16];
	uint32_t tail_left[16];
	uint64_t headaddr[16];   /* block-0 scratch when a prefix is present, else 0 */
	uint64_t bodyaddr[16];   /* base of block 1 (first pure-body block) */
	int      out[16];
	unsigned char tail[16][128];
	unsigned char head[16][64];
	unsigned char (*digests)[20];
	unsigned char *collided;
};

static void mb_reset_lane(struct MB *m, int j){
	__mmask16 k = (__mmask16)(1u<<j);
	m->a=_mm512_mask_set1_epi32(m->a,k,0x67452301);
	m->b=_mm512_mask_set1_epi32(m->b,k,0xEFCDAB89);
	m->c=_mm512_mask_set1_epi32(m->c,k,0x98BADCFE);
	m->d=_mm512_mask_set1_epi32(m->d,k,0x10325476);
	m->e=_mm512_mask_set1_epi32(m->e,k,0xC3D2E1F0);
}
/* Lay out one message (prefix ++ body) into 64-byte blocks for lane j. The
 * prefix is shorter than a block, so the prefix/body seam falls inside block 0.
 * When there is a prefix and at least one full block, block 0 is assembled in
 * the per-lane head[] scratch and blocks >= 1 read the body at a shifted base;
 * the run loop switches head -> body -> tail as it advances. With no prefix this
 * reduces to the original body -> tail path. */
static void mb_load_job(struct MB *m, int j, const struct sha1_mb_job *job, int out_idx){
	size_t prefixlen = job->prefix ? job->prefixlen : 0;
	size_t total = prefixlen + job->len, full = total/64, r = total%64;
	int nt=(r<56)?1:2;
	uint64_t bits=(uint64_t)total*8;
	/* The prefix must be shorter than one block so the prefix/body seam
	 * falls inside block 0; a longer prefix would overrun head[64] below.
	 * Callers guarantee this, so hard-fail even under NDEBUG. */
	if (prefixlen >= 64)
		abort();
	m->out[j]=out_idx;
	memset(m->tail[j],0,128);
	/* the last r bytes of the message start at message offset full*64 */
	if (full)
		/* full*64 >= 64 > prefixlen, so the tail is pure body */
		memcpy(m->tail[j], job->data + (full*64 - prefixlen), r);
	else {
		/* whole message fits in the tail: prefix ++ body */
		if (prefixlen)
			memcpy(m->tail[j], job->prefix, prefixlen);
		/* r == prefixlen for an empty body; skip so we never pass a
		 * possibly-NULL job->data to memcpy (UB even for size 0). */
		if (r > prefixlen)
			memcpy(m->tail[j] + prefixlen, job->data, r - prefixlen);
	}
	m->tail[j][r]=0x80;
	for (int i=0;i<8;i++) m->tail[j][nt*64-1-i]=(unsigned char)(bits>>(8*i));
	m->full_left[j]=full;
	m->tailaddr[j]=(uint64_t)(uintptr_t)m->tail[j];
	m->tail_left[j]=(uint32_t)nt;
	m->headaddr[j]=0;
	if (prefixlen && full){
		/* block 0 = prefix ++ body[0 .. 64-prefixlen); read from head */
		memcpy(m->head[j], job->prefix, prefixlen);
		memcpy(m->head[j]+prefixlen, job->data, 64-prefixlen);
		m->headaddr[j]=(uint64_t)(uintptr_t)m->head[j];
		m->bodyaddr[j]=(uint64_t)(uintptr_t)(job->data + (64-prefixlen));
		m->blkaddr[j]=m->headaddr[j];
	} else if (full){
		m->blkaddr[j]=(uint64_t)(uintptr_t)job->data;
	} else {
		m->blkaddr[j]=m->tailaddr[j];
	}
	mb_reset_lane(m,j);
}
static inline void store_digest(unsigned char out[20], uint32_t h0,uint32_t h1,uint32_t h2,uint32_t h3,uint32_t h4){
	uint32_t h[5]={h0,h1,h2,h3,h4};
	for (int k=0;k<5;k++){ out[4*k]=h[k]>>24; out[4*k+1]=h[k]>>16; out[4*k+2]=h[k]>>8; out[4*k+3]=h[k]; }
}

struct Fired { int out; uint32_t pre[5], post[5], dvmask; unsigned char block[64]; };

/* Verify up to 16 buffered fired blocks: one 16-wide compression recovers the
 * states 58/65, then 16-wide recompression confirms/rejects each. */
static void flush_fired(struct Fired *fb, int n, unsigned char *collided){
	__attribute__((aligned(64))) uint32_t preT[5][16]={{0}}, blkT[16][16]={{0}}, postT[5][16]={{0}};
	__attribute__((aligned(64))) uint32_t S58[5][16], S65[5][16];
	__m512i W[80];
	__m512i A,B,C,D,E;
	__m512i st58v[5], st65v[5], postv[5];
	uint32_t rem[16];
	uint16_t hitj=0;
	if (n<=0) return;
	for (int j=0;j<n;j++){
		const uint32_t *bw=(const uint32_t*)fb[j].block;
		for (int k=0;k<5;k++){ preT[k][j]=fb[j].pre[k]; postT[k][j]=fb[j].post[k]; }
		for (int i=0;i<16;i++) blkT[i][j]=__builtin_bswap32(bw[i]);
	}
	for (int i=0;i<16;i++) W[i]=_mm512_load_si512(blkT[i]);
	for (int i=16;i<80;i++) W[i]=ROL(_mm512_xor_si512(_mm512_xor_si512(W[i-3],W[i-8]),_mm512_xor_si512(W[i-14],W[i-16])),1);
	A=_mm512_load_si512(preT[0]);B=_mm512_load_si512(preT[1]);C=_mm512_load_si512(preT[2]);D=_mm512_load_si512(preT[3]);E=_mm512_load_si512(preT[4]);
	#define RND(F,K,t){ __m512i tmp=_mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(ROL(A,5),F(B,C,D)),\
	                        _mm512_add_epi32(E,_mm512_set1_epi32(K))),W[t]); E=D;D=C;C=ROL(B,30);B=A;A=tmp; }
	for (int t=0;t<20;t++)  RND(CH ,0x5A827999,t)
	for (int t=20;t<40;t++) RND(PAR,0x6ED9EBA1,t)
	for (int t=40;t<58;t++) RND(MAJ,0x8F1BBCDC,t)
	_mm512_store_si512(S58[0],A);_mm512_store_si512(S58[1],B);_mm512_store_si512(S58[2],C);_mm512_store_si512(S58[3],D);_mm512_store_si512(S58[4],E);
	for (int t=58;t<60;t++) RND(MAJ,0x8F1BBCDC,t)
	for (int t=60;t<65;t++) RND(PAR,0xCA62C1D6,t)
	_mm512_store_si512(S65[0],A);_mm512_store_si512(S65[1],B);_mm512_store_si512(S65[2],C);_mm512_store_si512(S65[3],D);_mm512_store_si512(S65[4],E);
	for (int t=65;t<80;t++) RND(PAR,0xCA62C1D6,t)
	#undef RND

	st58v[0]=_mm512_load_si512(S58[3]);st58v[1]=_mm512_load_si512(S58[4]);st58v[2]=_mm512_load_si512(S58[0]);st58v[3]=_mm512_load_si512(S58[1]);st58v[4]=_mm512_load_si512(S58[2]);
	st65v[0]=_mm512_load_si512(S65[0]);st65v[1]=_mm512_load_si512(S65[1]);st65v[2]=_mm512_load_si512(S65[2]);st65v[3]=_mm512_load_si512(S65[3]);st65v[4]=_mm512_load_si512(S65[4]);
	postv[0]=_mm512_load_si512(postT[0]);postv[1]=_mm512_load_si512(postT[1]);postv[2]=_mm512_load_si512(postT[2]);postv[3]=_mm512_load_si512(postT[3]);postv[4]=_mm512_load_si512(postT[4]);

	for (int j=0;j<16;j++) rem[j]=(j<n)?fb[j].dvmask:0;
	for (;;){
		__attribute__((aligned(64))) int32_t dvidx[16]={0};
		__mmask16 has58=0, has65=0;
		__m512i idx, me2[80];
		for (int j=0;j<16;j++){
			if (rem[j] && !((hitj>>j)&1)){
				int bit=__builtin_ctz(rem[j]); int dv=g_maskb2dv[bit]; rem[j]&=rem[j]-1;
				dvidx[j]=dv;
				if (sha1_dvs[dv].testt==58) has58|=(__mmask16)(1u<<j); else has65|=(__mmask16)(1u<<j);
			}
		}
		if (!(has58|has65)) break;
		idx=_mm512_load_si512(dvidx);
		for (int t=0;t<80;t++) me2[t]=_mm512_xor_si512(W[t], _mm512_i32gather_epi32(idx, g_dmT[t], 4));
		if (has58) hitj |= (recompress_x16_58(me2,st58v,postv) & has58);
		if (has65) hitj |= (recompress_x16_65(me2,st65v,postv) & has65);
	}
	if (collided) for (int j=0;j<n;j++) if ((hitj>>j)&1) collided[fb[j].out]=1;
}

static void run(const struct sha1_mb_job *jobs, size_t njobs,
                unsigned char (*digests)[20], unsigned char *collided){
	struct MB mb;
	size_t next=0;
	__attribute__((aligned(64))) uint32_t A5[16],B5[16],C5[16],D5[16],E5[16];
	struct Fired fbuf[16];
	int fn=0;
	/* Idle lanes (njobs < 16) keep blkaddr pointing at their tail[] scratch,
	 * which gather_word reads every iteration. Zero it so those reads are
	 * deterministic instead of uninitialized (UB / MSan noise). */
	memset(&mb, 0, sizeof(mb));
	mb.digests=digests; mb.collided=collided;
	mb.a=mb.b=mb.c=mb.d=mb.e=_mm512_setzero_si512();
	for (int j=0;j<16;j++){ mb.out[j]=-1; mb.full_left[j]=mb.tail_left[j]=0; mb.headaddr[j]=0; mb.blkaddr[j]=(uint64_t)(uintptr_t)mb.tail[j]; }

	for (int j=0;j<16 && next<njobs;j++){ mb_load_job(&mb,j,&jobs[next],(int)next); next++; }

	for (;;){
		__mmask16 act=0;
		__m512i W[80];
		__m512i A,B,C,D,E;
		__m512i dv;
		__mmask16 fired;
		__attribute__((aligned(64))) uint32_t PRE[5][16];
		__mmask16 done;
		for (int j=0;j<16;j++) if (mb.full_left[j]||mb.tail_left[j]) act|=(__mmask16)(1u<<j);
		if (!act) break;

		for (int i=0;i<16;i++) W[i]=gather_word(mb.blkaddr,i);
		for (int i=16;i<80;i++)
			W[i]=ROL(_mm512_xor_si512(_mm512_xor_si512(W[i-3],W[i-8]),_mm512_xor_si512(W[i-14],W[i-16])),1);

		A=mb.a;B=mb.b;C=mb.c;D=mb.d;E=mb.e;
		#define RND(F,K,t){ __m512i tmp=_mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(ROL(A,5),F(B,C,D)),\
		                        _mm512_add_epi32(E,_mm512_set1_epi32(K))),W[t]); E=D;D=C;C=ROL(B,30);B=A;A=tmp; }
		for (int t=0;t<20;t++)  RND(CH ,0x5A827999,t)
		for (int t=20;t<40;t++) RND(PAR,0x6ED9EBA1,t)
		for (int t=40;t<60;t++) RND(MAJ,0x8F1BBCDC,t)
		for (int t=60;t<80;t++) RND(PAR,0xCA62C1D6,t)
		#undef RND

		ubc_check_x16(W,&dv);
		fired=_mm512_mask_cmpneq_epi32_mask(act,dv,_mm512_setzero_si512());
		if (fired){
			_mm512_store_si512(PRE[0],mb.a);_mm512_store_si512(PRE[1],mb.b);_mm512_store_si512(PRE[2],mb.c);_mm512_store_si512(PRE[3],mb.d);_mm512_store_si512(PRE[4],mb.e);
		}
		mb.a=_mm512_mask_add_epi32(mb.a,act,mb.a,A); mb.b=_mm512_mask_add_epi32(mb.b,act,mb.b,B);
		mb.c=_mm512_mask_add_epi32(mb.c,act,mb.c,C); mb.d=_mm512_mask_add_epi32(mb.d,act,mb.d,D);
		mb.e=_mm512_mask_add_epi32(mb.e,act,mb.e,E);
		if (fired){
			__attribute__((aligned(64))) uint32_t DV[16], PST[5][16];
			_mm512_store_si512(DV,dv);
			_mm512_store_si512(PST[0],mb.a);_mm512_store_si512(PST[1],mb.b);_mm512_store_si512(PST[2],mb.c);_mm512_store_si512(PST[3],mb.d);_mm512_store_si512(PST[4],mb.e);
			for (int j=0;j<16;j++) if (fired&(1u<<j)){
				struct Fired *f=&fbuf[fn++];
				f->out=mb.out[j]; f->dvmask=DV[j];
				for (int k=0;k<5;k++){ f->pre[k]=PRE[k][j]; f->post[k]=PST[k][j]; }
				memcpy(f->block, (const void*)(uintptr_t)mb.blkaddr[j], 64);
				if (fn==16){ flush_fired(fbuf,16,mb.collided); fn=0; }
			}
		}

		for (int j=0;j<16;j++){
			if (mb.full_left[j]){
				mb.full_left[j]--;
				/* block 0 lives in head[]; block 1 starts at bodyaddr */
				if (mb.blkaddr[j]==mb.headaddr[j]) mb.blkaddr[j]=mb.bodyaddr[j];
				else mb.blkaddr[j]+=64;
				if(!mb.full_left[j]) mb.blkaddr[j]=mb.tailaddr[j];
			}
			else if (mb.tail_left[j]){ if (--mb.tail_left[j]) mb.blkaddr[j]+=64; }
		}
		done=0;
		for (int j=0;j<16;j++) if (mb.out[j]>=0 && !mb.full_left[j] && !mb.tail_left[j]) done|=(__mmask16)(1u<<j);
		if (done){
			_mm512_store_si512(A5,mb.a);_mm512_store_si512(B5,mb.b);_mm512_store_si512(C5,mb.c);_mm512_store_si512(D5,mb.d);_mm512_store_si512(E5,mb.e);
			for (int j=0;j<16;j++) if (done&(1u<<j)){
				store_digest(mb.digests[mb.out[j]],A5[j],B5[j],C5[j],D5[j],E5[j]);
				mb.out[j]=-1;
				if (next<njobs){ mb_load_job(&mb,j,&jobs[next],(int)next); next++; }
			}
		}
	}
	flush_fired(fbuf,fn,mb.collided);
}

void sha1_mb_hash(const struct sha1_mb_job *jobs, size_t n,
                  unsigned char (*out)[20], unsigned char *collided){
	if (collided) memset(collided, 0, n);
	if (n) run(jobs, n, out, collided);
}

int sha1_mb_available(void){
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw")
	    && __builtin_cpu_supports("avx512vl") && __builtin_cpu_supports("avx512dq");
}

uint16_t sha1_mb_recompress_test(int testt, const uint32_t me2[80][16],
                                 const uint32_t st[5][16], const uint32_t post[5][16]){
	__m512i vme2[80], vst[5], vpost[5];
	for (int t=0;t<80;t++) vme2[t]=_mm512_loadu_si512(me2[t]);
	for (int k=0;k<5;k++){ vst[k]=_mm512_loadu_si512(st[k]); vpost[k]=_mm512_loadu_si512(post[k]); }
	return (testt==58) ? recompress_x16_58(vme2,vst,vpost)
	                   : recompress_x16_65(vme2,vst,vpost);
}

#else /* not GCC on x86: the AVX-512 engine is unavailable; provide stubs. */

int sha1_mb_available(void){ return 0; }
void sha1_mb_hash(const struct sha1_mb_job *jobs, size_t n,
                  unsigned char (*out)[20], unsigned char *collided){
	(void)jobs; (void)n; (void)out; (void)collided;
}
uint16_t sha1_mb_recompress_test(int testt, const uint32_t me2[80][16],
                                 const uint32_t st[5][16], const uint32_t post[5][16]){
	(void)testt; (void)me2; (void)st; (void)post; return 0;
}

#endif
