#include "git-compat-util.h"
#include "sha1dc_git.h"
#include "hex.h"

#ifdef DC_SHA1_EXTERNAL
/*
 * Same as SHA1DCInit, but with default save_hash=0
 */
void git_SHA1DCInit(SHA1_CTX *ctx)
{
	SHA1DCInit(ctx);
	SHA1DCSetSafeHash(ctx, 0);
}
#endif

/*
 * Same as the regular init, but with collision detection disabled: for
 * unsafe (non-cryptographic) hashing, where it makes SHA1DCUpdate run
 * at the speed of the plain SHA-1 compression (in hardware where the
 * library has a fast path).
 */
void git_SHA1DCInit_unsafe(SHA1_CTX *ctx)
{
	git_SHA1DCInit(ctx);
	SHA1DCSetUseDetectColl(ctx, 0);
}

/*
 * Same as SHA1DCFinal, but convert collision attack case into a verbose die().
 */
void git_SHA1DCFinal(unsigned char hash[20], SHA1_CTX *ctx)
{
	if (!SHA1DCFinal(hash, ctx))
		return;
	die("SHA-1 appears to be part of a collision attack: %s",
	    hash_to_hex_algop(hash, &hash_algos[GIT_HASH_SHA1]));
}

/*
 * Same as SHA1DCUpdate, but adjust types to match git's usual interface.
 */
void git_SHA1DCUpdate(SHA1_CTX *ctx, const void *vdata, unsigned long len)
{
	const char *data = vdata;
	/* We expect an unsigned long, but sha1dc only takes an int */
	while (len > INT_MAX) {
		SHA1DCUpdate(ctx, data, INT_MAX);
		data += INT_MAX;
		len -= INT_MAX;
	}
	SHA1DCUpdate(ctx, data, len);
}
