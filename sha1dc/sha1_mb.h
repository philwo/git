/* Batched multi-buffer SHA-1DC (collision-detecting) hasher.
 *
 * Hashes up to many independent messages in parallel using AVX-512 (16 lanes),
 * with full sha1collisiondetection semantics. Produces the same digest that
 * git_SHA1DCFinal would for each message; if a real collision block is found,
 * collided[i] is set (callers treat that as fatal, like scalar sha1dc). */
#ifndef SHA1_MB_H
#define SHA1_MB_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sha1_mb_job {
	const unsigned char *prefix;   /* optional header; NULL for none */
	size_t prefixlen;              /* 0..63 (git object headers are <= 32) */
	const unsigned char *data;     /* body */
	size_t len;                    /* body length */
};

/* The hashed message is prefix[0..prefixlen) followed by data[0..len), so the
 * total length is prefixlen + len. Callers hashing "<type> <size>\0" + body set
 * prefix to the formatted header, which avoids copying the body. */

/* 1 if the CPU supports the AVX-512 subset this engine needs, else 0.
 * Callers must check this before sha1_mb_hash(); otherwise fall back to
 * per-object git_SHA1DC*. */
int sha1_mb_available(void);

/* Hash n jobs. out[i] receives the 20-byte SHA-1 digest of jobs[i]; if
 * collided is non-NULL, collided[i] is set to 1 iff a collision was detected. */
void sha1_mb_hash(const struct sha1_mb_job *jobs, size_t n,
                  unsigned char (*out)[20], unsigned char *collided);

/* Test hook: run the 16-wide recompression for testt (58 or 65) over 16 lanes
 * of plain (non-vector) inputs and return its confirm mask (bit j set iff lane
 * j's recompressed IHV equals post[..][j]). Exposed so t/helper can validate
 * the generated recompression against a scalar SHA-1 reference. Lane-major
 * inputs: me2[t][j], st[k][j], post[k][j]. */
uint16_t sha1_mb_recompress_test(int testt, const uint32_t me2[80][16],
                                 const uint32_t st[5][16],
                                 const uint32_t post[5][16]);

#ifdef __cplusplus
}
#endif
#endif
