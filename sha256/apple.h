/* wrappers for Apple CommonCrypto's SHA-256 */
#ifndef SHA256_APPLE_H
#define SHA256_APPLE_H

#include <CommonCrypto/CommonDigest.h>

typedef CC_SHA256_CTX apple_SHA256_CTX;

static inline void apple_SHA256_Init(apple_SHA256_CTX *ctx)
{
	CC_SHA256_Init(ctx);
}

static inline void apple_SHA256_Update(apple_SHA256_CTX *ctx,
				       const void *data, size_t len)
{
	const unsigned char *p = data;
	/* CC_LONG is only 32 bits wide, so feed large inputs in chunks */
	const size_t max_chunk = 1024L * 1024L * 1024L;

	while (len > max_chunk) {
		CC_SHA256_Update(ctx, p, (CC_LONG)max_chunk);
		p += max_chunk;
		len -= max_chunk;
	}
	CC_SHA256_Update(ctx, p, (CC_LONG)len);
}

static inline void apple_SHA256_Final(unsigned char *digest,
				      apple_SHA256_CTX *ctx)
{
	CC_SHA256_Final(digest, ctx);
}

#define platform_SHA256_CTX apple_SHA256_CTX
#define platform_SHA256_Init apple_SHA256_Init
#define platform_SHA256_Update apple_SHA256_Update
#define platform_SHA256_Final apple_SHA256_Final

#endif /* SHA256_APPLE_H */
