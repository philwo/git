#include "test-tool.h"
#include "git-compat-util.h"
#include "hash.h"
#include "trace.h"

#ifdef SHA1_MB
#include "sha1dc/sha1_mb.h"

/* scalar sha1dc reference (sha1dc/sha1.c): compress one block, exposing the
 * expanded message W[80] and the state (a,b,c,d,e) before each step. */
void sha1_compression_states(uint32_t ihv[5], const uint32_t m[16],
			     uint32_t W[80], uint32_t states[80][5]);

static uint32_t prng(uint32_t *s) { *s = *s * 1103515245u + 12345u; return *s; }

/*
 * Validate the generated 16-wide recompression (recompress_x16_58/65) against
 * the scalar sha1dc reference. No public SHA-1 collision exercises the testt=58
 * confirm path, so instead of a real collision we build genuine (message, state,
 * output) triples with sha1_compression_states and require the recompression to
 * confirm them -- and to reject a one-bit-perturbed output. This catches a
 * transcription error in either generated function without needing a collision.
 */
static int recompress_check(void)
{
	uint32_t seed = 0xC0FFEEu;
	int bad = 0;

	for (int rep = 0; rep < 64 && !bad; rep++) {
		uint32_t me2[80][16], st[5][16], post[5][16];
		int testt = (rep & 1) ? 65 : 58;
		uint16_t got;

		for (int j = 0; j < 16; j++) {
			uint32_t ihv[5], m[16], W[80], states[80][5];
			for (int k = 0; k < 5; k++)
				ihv[k] = prng(&seed);
			for (int k = 0; k < 16; k++)
				m[k] = prng(&seed);
			sha1_compression_states(ihv, m, W, states);
			for (int t = 0; t < 80; t++)
				me2[t][j] = W[t];
			for (int k = 0; k < 5; k++) {
				st[k][j] = states[testt][k];
				post[k][j] = ihv[k]; /* output IHV */
			}
		}

		got = sha1_mb_recompress_test(testt, me2, st, post);
		if (got != 0xFFFF) {
			bad = 1;
			fprintf(stderr, "recompress testt=%d confirm mask %04x != ffff\n",
				testt, got);
		}
		/* a one-bit change in lane 3's output must drop only that lane */
		post[0][3] ^= 1u;
		got = sha1_mb_recompress_test(testt, me2, st, post);
		if (got & (1u << 3)) {
			bad = 1;
			fprintf(stderr, "recompress testt=%d falsely confirmed a perturbed output\n",
				testt);
		}
	}
	printf("recompress: 58/65 vs scalar sha1dc, %s\n", bad ? "FAIL" : "OK");
	return bad;
}

/*
 * First 320 bytes (5 blocks) of t/t0013/shattered-1.pdf: the canonical
 * "shattered-1" colliding message. This is the minimal prefix that trips
 * sha1dc's collision detection. sha1_mb_hash() must set collided[i] for it and
 * still return the plain SHA-1 f92d74e3874587aaf443d1db961d4e26dde13e9c.
 */
static const unsigned char shattered1_block[320] = {
	0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x33, 0x0a, 0x25, 0xe2, 0xe3,
	0xcf, 0xd3, 0x0a, 0x0a, 0x0a, 0x31, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a,
	0x0a, 0x3c, 0x3c, 0x2f, 0x57, 0x69, 0x64, 0x74, 0x68, 0x20, 0x32, 0x20,
	0x30, 0x20, 0x52, 0x2f, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x20, 0x33,
	0x20, 0x30, 0x20, 0x52, 0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x34, 0x20,
	0x30, 0x20, 0x52, 0x2f, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x20,
	0x35, 0x20, 0x30, 0x20, 0x52, 0x2f, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x20, 0x36, 0x20, 0x30, 0x20, 0x52, 0x2f, 0x43, 0x6f, 0x6c, 0x6f, 0x72,
	0x53, 0x70, 0x61, 0x63, 0x65, 0x20, 0x37, 0x20, 0x30, 0x20, 0x52, 0x2f,
	0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20, 0x38, 0x20, 0x30, 0x20, 0x52,
	0x2f, 0x42, 0x69, 0x74, 0x73, 0x50, 0x65, 0x72, 0x43, 0x6f, 0x6d, 0x70,
	0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x20, 0x38, 0x3e, 0x3e, 0x0a, 0x73, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x0a, 0xff, 0xd8, 0xff, 0xfe, 0x00, 0x24, 0x53,
	0x48, 0x41, 0x2d, 0x31, 0x20, 0x69, 0x73, 0x20, 0x64, 0x65, 0x61, 0x64,
	0x21, 0x21, 0x21, 0x21, 0x21, 0x85, 0x2f, 0xec, 0x09, 0x23, 0x39, 0x75,
	0x9c, 0x39, 0xb1, 0xa1, 0xc6, 0x3c, 0x4c, 0x97, 0xe1, 0xff, 0xfe, 0x01,
	0x73, 0x46, 0xdc, 0x91, 0x66, 0xb6, 0x7e, 0x11, 0x8f, 0x02, 0x9a, 0xb6,
	0x21, 0xb2, 0x56, 0x0f, 0xf9, 0xca, 0x67, 0xcc, 0xa8, 0xc7, 0xf8, 0x5b,
	0xa8, 0x4c, 0x79, 0x03, 0x0c, 0x2b, 0x3d, 0xe2, 0x18, 0xf8, 0x6d, 0xb3,
	0xa9, 0x09, 0x01, 0xd5, 0xdf, 0x45, 0xc1, 0x4f, 0x26, 0xfe, 0xdf, 0xb3,
	0xdc, 0x38, 0xe9, 0x6a, 0xc2, 0x2f, 0xe7, 0xbd, 0x72, 0x8f, 0x0e, 0x45,
	0xbc, 0xe0, 0x46, 0xd2, 0x3c, 0x57, 0x0f, 0xeb, 0x14, 0x13, 0x98, 0xbb,
	0x55, 0x2e, 0xf5, 0xa0, 0xa8, 0x2b, 0xe3, 0x31, 0xfe, 0xa4, 0x80, 0x37,
	0xb8, 0xb5, 0xd7, 0x1f, 0x0e, 0x33, 0x2e, 0xdf, 0x93, 0xac, 0x35, 0x00,
	0xeb, 0x4d, 0xdc, 0x0d, 0xec, 0xc1, 0xa8, 0x64, 0x79, 0x0c, 0x78, 0x2c,
	0x76, 0x21, 0x56, 0x60, 0xdd, 0x30, 0x97, 0x91, 0xd0, 0x6b, 0xd0, 0xaf,
	0x3f, 0x98, 0xcd, 0xa4, 0xbc, 0x46, 0x29, 0xb1
};

/*
 * Validate the two-segment (prefix ++ body) path against scalar sha1dc. Sweeps
 * prefixlen 0..32 by body length 0..~300, which crosses several 64-byte block
 * and padding boundaries, plus prefixlen 0 (NULL prefix) as a control. Requires
 * bit-exact digests and no spurious collision flags.
 */
static int prefix_sweep(const struct git_hash_algo *algo)
{
	const size_t maxpl = 32, maxbl = 300;
	size_t n = (maxpl + 1) * (maxbl + 1), idx = 0;
	uint32_t seed = 0x9e3779b9u;
	struct sha1_mb_job *jobs;
	unsigned char **prefixes, **bodies, (*out)[20], *coll;
	int fails = 0;

	ALLOC_ARRAY(jobs, n);
	ALLOC_ARRAY(prefixes, n);
	ALLOC_ARRAY(bodies, n);
	ALLOC_ARRAY(out, n);
	ALLOC_ARRAY(coll, n);
	for (size_t pl = 0; pl <= maxpl; pl++)
		for (size_t bl = 0; bl <= maxbl; bl++, idx++) {
			unsigned char *pfx = xmalloc(pl ? pl : 1);
			unsigned char *body = xmalloc(bl ? bl : 1);
			for (size_t k = 0; k < pl; k++) pfx[k] = prng(&seed) >> 24;
			for (size_t k = 0; k < bl; k++) body[k] = prng(&seed) >> 24;
			prefixes[idx] = pfx;
			bodies[idx] = body;
			jobs[idx].prefix = pl ? pfx : NULL;
			jobs[idx].prefixlen = pl;
			jobs[idx].data = body;
			jobs[idx].len = bl;
		}

	sha1_mb_hash(jobs, n, out, coll);

	idx = 0;
	for (size_t pl = 0; pl <= maxpl; pl++)
		for (size_t bl = 0; bl <= maxbl; bl++, idx++) {
			struct git_hash_ctx c;
			unsigned char ref[GIT_MAX_RAWSZ];
			algo->init_fn(&c);
			git_hash_update(&c, prefixes[idx], pl);
			git_hash_update(&c, bodies[idx], bl);
			git_hash_final(ref, &c);
			if (coll[idx] || memcmp(out[idx], ref, 20)) {
				if (++fails <= 3)
					fprintf(stderr,
						"prefix mismatch: prefixlen %"PRIuMAX" body %"PRIuMAX"%s\n",
						(uintmax_t)pl, (uintmax_t)bl,
						coll[idx] ? " (spurious collided)" : "");
			}
			free(prefixes[idx]);
			free(bodies[idx]);
		}

	printf("prefix-sweep: %"PRIuMAX" cases, %s vs the_hash_algo\n",
	       (uintmax_t)n, fails ? "FAIL" : "OK");
	free(jobs);
	free(prefixes);
	free(bodies);
	free(out);
	free(coll);
	return fails;
}

int cmd__sha1_mb(int argc, const char **argv)
{
	const struct git_hash_algo *algo = &hash_algos[GIT_HASH_SHA1];
	int probe = argc > 1 && !strcmp(argv[1], "--probe");
	size_t n = argc > 1 && !probe ? strtoul(argv[1], NULL, 10) : 20000;
	int reps = argc > 2 ? atoi(argv[2]) : 20;
	uint32_t seed = 1;
	struct sha1_mb_job *jobs;
	unsigned char **bufs, (*out)[20], *coll;
	size_t *lens, total = 0;
	int fails = 0;
	uint64_t t0;
	double mb, sc;

	if (!sha1_mb_available()) {
		printf("sha1_mb: AVX-512 not available on this CPU; skipping\n");
		return 0;
	}

	/*
	 * Availability-only probe: report that the hasher is built and usable
	 * without running prefix_sweep or the correctness corpus. The test's
	 * SHA1_MB prereq greps for this line, so a hasher regression fails the
	 * correctness tests loudly instead of silently skipping the file.
	 */
	if (probe) {
		printf("sha1_mb: available\n");
		return 0;
	}

	if (argc > 1 && !strcmp(argv[1], "--recompress"))
		return recompress_check();

	/*
	 * Collision path: feed a known collision block and require the batched
	 * engine to flag it. Without this the random corpus below never trips
	 * the UBC check, so a regression in the collision detection would go
	 * unnoticed -- defeating the whole point of sha1dc.
	 */
	if (argc > 1 && !strcmp(argv[1], "--collision")) {
		static const char expect_hex[] =
			"f92d74e3874587aaf443d1db961d4e26dde13e9c";
		const size_t bn = 20, kbad = 10;
		struct sha1_mb_job job, *bjobs;
		unsigned char out[1][20], coll[1];
		unsigned char **bbufs, (*bout)[20], *bcoll;
		char got_hex[41];
		uint32_t bseed = 0x1234u;
		int bad = 0;

		/* single object: basic detect + digest */
		job.prefix = NULL;
		job.prefixlen = 0;
		job.data = shattered1_block;
		job.len = sizeof(shattered1_block);
		sha1_mb_hash(&job, 1, out, coll);
		printf("collision: %s ", coll[0] ? "detected" : "MISSED");
		for (int k = 0; k < 20; k++)
			printf("%02x", out[0][k]);
		printf("\n");
		if (!coll[0])
			bad = 1;

		/*
		 * Multi-lane path: a real collision must be flagged even when it
		 * is not in lane 0, and the flag must be attributed to the right
		 * object. Put the collision block at index kbad among bn > 16
		 * objects, all longer than it so its lane finishes first and gets
		 * refilled, then require exactly that object to be flagged and to
		 * carry shattered-1's digest.
		 */
		ALLOC_ARRAY(bjobs, bn);
		ALLOC_ARRAY(bbufs, bn);
		ALLOC_ARRAY(bout, bn);
		ALLOC_ARRAY(bcoll, bn);
		for (size_t i = 0; i < bn; i++) {
			bjobs[i].prefix = NULL;
			bjobs[i].prefixlen = 0;
			if (i == kbad) {
				bbufs[i] = NULL;
				bjobs[i].data = shattered1_block;
				bjobs[i].len = sizeof(shattered1_block);
			} else {
				size_t len = 400 + prng(&bseed) % 2000;
				bbufs[i] = xmalloc(len);
				for (size_t k = 0; k < len; k++)
					bbufs[i][k] = prng(&bseed) >> 24;
				bjobs[i].data = bbufs[i];
				bjobs[i].len = len;
			}
		}
		sha1_mb_hash(bjobs, bn, bout, bcoll);

		for (size_t i = 0; i < bn; i++)
			if (!!bcoll[i] != (i == kbad)) {
				bad = 1;
				fprintf(stderr,
					"batch collision flag wrong at %"PRIuMAX" (got %d)\n",
					(uintmax_t)i, bcoll[i]);
			}
		for (int k = 0; k < 20; k++)
			xsnprintf(got_hex + 2 * k, 3, "%02x", bout[kbad][k]);
		if (strcmp(got_hex, expect_hex))
			bad = 1;
		printf("collision-batch: %s lane %"PRIuMAX" %s\n",
		       bcoll[kbad] ? "detected" : "MISSED",
		       (uintmax_t)kbad, got_hex);

		for (size_t i = 0; i < bn; i++)
			free(bbufs[i]);
		free(bjobs);
		free(bbufs);
		free(bout);
		free(bcoll);
		return bad;
	}

	if (prefix_sweep(algo))
		return 1;

	ALLOC_ARRAY(jobs, n);
	ALLOC_ARRAY(bufs, n);
	ALLOC_ARRAY(lens, n);
	ALLOC_ARRAY(out, n);
	ALLOC_ARRAY(coll, n);
	for (size_t i = 0; i < n; i++) {
		/* realistic git-object size mix */
		uint32_t p = prng(&seed) % 1000, len;
		if (p < 600) len = 40 + prng(&seed) % 560;
		else if (p < 950) len = 600 + prng(&seed) % 11400;
		else len = 12000 + prng(&seed) % 388000;
		bufs[i] = xmalloc(len);
		for (uint32_t k = 0; k < len; k++) bufs[i][k] = prng(&seed) >> 24;
		jobs[i].prefix = NULL;
		jobs[i].prefixlen = 0;
		jobs[i].data = bufs[i];
		jobs[i].len = lens[i] = len;
		total += len;
	}

	/* correctness: batched vs git's own the_hash_algo (sha1dc) */
	sha1_mb_hash(jobs, n, out, coll);
	for (size_t i = 0; i < n; i++) {
		struct git_hash_ctx c;
		unsigned char ref[GIT_MAX_RAWSZ];
		algo->init_fn(&c);
		git_hash_update(&c, bufs[i], lens[i]);
		git_hash_final(ref, &c);
		if (coll[i] || memcmp(out[i], ref, 20)) {
			if (++fails <= 3)
				fprintf(stderr, "mismatch at object %"PRIuMAX" (len %"PRIuMAX")%s\n",
					(uintmax_t)i, (uintmax_t)lens[i],
					coll[i] ? " (spurious collided)" : "");
		}
	}
	printf("correctness: %"PRIuMAX" objects, %s vs the_hash_algo\n",
	       (uintmax_t)n, fails ? "FAIL" : "OK");
	if (fails)
		return 1;

	/* throughput: batched */
	t0 = getnanotime();
	for (int r = 0; r < reps; r++)
		sha1_mb_hash(jobs, n, out, coll);
	mb = (double)total * reps / ((getnanotime() - t0) / 1e9) / (1 << 30);

	/* throughput: per-object the_hash_algo (what git does today) */
	t0 = getnanotime();
	for (int r = 0; r < reps; r++)
		for (size_t i = 0; i < n; i++) {
			struct git_hash_ctx c;
			unsigned char ref[GIT_MAX_RAWSZ];
			algo->init_fn(&c);
			git_hash_update(&c, bufs[i], lens[i]);
			git_hash_final(ref, &c);
		}
	sc = (double)total * reps / ((getnanotime() - t0) / 1e9) / (1 << 30);

	printf("throughput: batched %.3f GB/s, per-object %.3f GB/s (%.2fx)\n",
	       mb, sc, mb / sc);
	return 0;
}
#else
int cmd__sha1_mb(int argc UNUSED, const char **argv UNUSED)
{
	printf("sha1_mb: not built (compile with SHA1_MB=YesPlease)\n");
	return 0;
}
#endif
