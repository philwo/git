#ifndef OBJECT_FILE_H
#define OBJECT_FILE_H

#include "git-zlib.h"
#include "object.h"
#include "odb.h"
#include "odb/source-loose.h"

/* The maximum size for an object header. */
#define MAX_HEADER_LEN 32

struct index_state;

enum {
	INDEX_WRITE_OBJECT = (1 << 0),
	INDEX_FORMAT_CHECK = (1 << 1),
	INDEX_RENORMALIZE  = (1 << 2),
};

int index_fd(struct index_state *istate, struct object_id *oid, int fd, struct stat *st, enum object_type type, const char *path, unsigned flags);
int index_path(struct index_state *istate, struct object_id *oid, const char *path, struct stat *st, unsigned flags);

struct object_info;
struct odb_source;

/*
 * Write the given stream into the loose object source. The only difference
 * from the generic implementation of this function is that we don't perform an
 * object existence check here.
 *
 * TODO: We should stop exposing this function altogether and move it into
 * "odb/source-loose.c". This requires a couple of refactorings though to make
 * `force_object_loose()` generic and is thus postponed to a later point in
 * time.
 */
int odb_source_loose_write_stream(struct odb_source_loose *source,
				  struct odb_write_stream *stream, size_t len,
				  struct object_id *oid);

/*
 * Put in `buf` the name of the file in the local object database that
 * would be used to store a loose object with the specified oid.
 */
const char *odb_loose_path(struct odb_source_loose *source,
			   struct strbuf *buf,
			   const struct object_id *oid);

/*
 * Iterate over the files in the loose-object parts of the object
 * directory "path", triggering the following callbacks:
 *
 *  - loose_object is called for each loose object we find.
 *
 *  - loose_cruft is called for any files that do not appear to be
 *    loose objects. Note that we only look in the loose object
 *    directories "objects/[0-9a-f]{2}/", so we will not report
 *    "objects/foobar" as cruft.
 *
 *  - loose_subdir is called for each top-level hashed subdirectory
 *    of the object directory (e.g., "$OBJDIR/f0"). It is called
 *    after the objects in the directory are processed.
 *
 * Any callback that is NULL will be ignored. Callbacks returning non-zero
 * will end the iteration.
 *
 * In the "buf" variant, "path" is a strbuf which will also be used as a
 * scratch buffer, but restored to its original contents before
 * the function returns.
 */
typedef int each_loose_object_fn(const struct object_id *oid,
				 const char *path,
				 void *data);
typedef int each_loose_cruft_fn(const char *basename,
				const char *path,
				void *data);
typedef int each_loose_subdir_fn(unsigned int nr,
				 const char *path,
				 void *data);
int for_each_loose_file_in_source(struct odb_source *source,
				  each_loose_object_fn obj_cb,
				  each_loose_cruft_fn cruft_cb,
				  each_loose_subdir_fn subdir_cb,
				  void *data);
int for_each_file_in_obj_subdir(unsigned int subdir_nr,
				struct strbuf *path,
				const struct git_hash_algo *algop,
				each_loose_object_fn obj_cb,
				each_loose_cruft_fn cruft_cb,
				each_loose_subdir_fn subdir_cb,
				void *data);

/**
 * format_object_header() is a thin wrapper around s xsnprintf() that
 * writes the initial "<type> <obj-len>" part of the loose object
 * header. It returns the size that snprintf() returns + 1.
 */
int format_object_header(char *str, size_t size, enum object_type type,
			 size_t objsize);

int force_object_loose(struct odb_source *source,
		       const struct object_id *oid, time_t mtime);

/**
 * With in-core object data in "buf", rehash it to make sure the
 * object name actually matches "oid" to detect object corruption.
 *
 * A negative value indicates an error, usually that the OID is not
 * what we expected, but it might also indicate another error.
 */
int check_object_signature(struct repository *r, const struct object_id *oid,
			   void *map, unsigned long size,
			   enum object_type type);

/**
 * A streaming version of check_object_signature().
 * Try reading the object named with "oid" using
 * the streaming interface and rehash it to do the same.
 */
int stream_object_signature(struct repository *r,
			    struct odb_read_stream *stream,
			    const struct object_id *oid);

enum finalize_object_file_flags {
	FOF_SKIP_COLLISION_CHECK = 1,
};

int finalize_object_file(struct repository *repo,
			 const char *tmpfile, const char *filename);
int finalize_object_file_flags(struct repository *repo,
			       const char *tmpfile, const char *filename,
			       enum finalize_object_file_flags flags);

void hash_object_file(const struct git_hash_algo *algo, const void *buf,
		      unsigned long len, enum object_type type,
		      struct object_id *oid);

#ifdef SHA1_MB
/*
 * 1 if the batched AVX-512 SHA-1DC hasher can be used for algo: it must be
 * available on this CPU, algo must be SHA-1, and GIT_TEST_NO_SHA1_MB must be
 * unset. Hashing-bound callers (index-pack, fsck) use it to hash many objects
 * at once.
 */
int hash_object_batch_available(const struct git_hash_algo *algo);

/*
 * Compute the oids of n objects at once. bufs[i]/sizes[i]/types[i] describe the
 * in-core object payloads; out[i] receives the oid. Buffers are not copied and
 * stay owned by the caller. On a detected collision for object i, this falls
 * back to hash_object_file(), which fires git's normal collision handling.
 * Only call when hash_object_batch_available(algo) is true.
 */
void hash_object_file_batch(const struct git_hash_algo *algo,
			    const void **bufs, const size_t *sizes,
			    const enum object_type *types, size_t n,
			    struct object_id *out);

/*
 * A sliding window of in-core objects whose hashing is deferred so it can run
 * many-at-once through hash_object_file_batch(). Callers (index-pack, fsck)
 * queue objects with object_hash_batch_add(); the window is flushed when it
 * fills (max_n objects or max_bytes of payload) or on demand with
 * object_hash_batch_flush(). Each slot owns its data[] until flushed. The two
 * scalar-per-slot fields, cookie[] and oid[], are for the caller to use as it
 * needs: index-pack stashes the object_entry in cookie[]; fsck stashes the
 * expected oid in oid[].
 *
 * One batch holds up to OBJECT_HASH_BATCH_SZ objects and is hashed in a single
 * sha1_mb_hash() call, i.e. one 16-wide SIMD round. That round runs until its
 * longest lane finishes, so a batch that mixes one large object with small ones
 * wastes the other lanes -- on a size-skewed pack a naive single window can run
 * SLOWER than the scalar hasher. A caller that sees a wide object-size spread
 * should therefore group objects into size classes and fill a separate batch
 * per class, so every round hashes similar-sized objects (fsck does this; see
 * pack-check.c). That reaches SHA-NI throughput independent of object ordering.
 *
 * max_bytes is a per-caller payload cap (0 = the default below); a caller that
 * keeps many batches alive at once (fsck's size bins) sets it to bound memory.
 */
#define OBJECT_HASH_BATCH_SZ 16
struct object_hash_batch {
	int n;
	size_t max_bytes;		/* flush at this many payload bytes (0 = default) */
	size_t buffered_bytes;
	void *data[OBJECT_HASH_BATCH_SZ];
	size_t size[OBJECT_HASH_BATCH_SZ];
	enum object_type type[OBJECT_HASH_BATCH_SZ];
	void *cookie[OBJECT_HASH_BATCH_SZ];
	struct object_id oid[OBJECT_HASH_BATCH_SZ];
};

/*
 * Called once per flush after the window's objects have been hashed; computed[i]
 * is the oid of queued object i. The callback consumes each slot (data[i]/size[i]/
 * type[i]/cookie[i]/oid[i]) and MUST free b->data[i]. Its return value is passed
 * back out through object_hash_batch_add()/object_hash_batch_flush() (fsck ORs
 * error bits into it; index-pack returns 0).
 */
typedef int (*object_hash_batch_flush_fn)(struct object_hash_batch *b,
					  const struct object_id *computed,
					  void *cb_data);

/*
 * Queue one in-core object (data/size/type, plus the caller's cookie and/or
 * expected oid) for batched hashing, flushing through flush_fn when the window
 * fills. Returns any error flush_fn reported (0 if it did not flush).
 */
int object_hash_batch_add(const struct git_hash_algo *algo,
			  struct object_hash_batch *b,
			  void *data, size_t size, enum object_type type,
			  void *cookie, const struct object_id *oid,
			  object_hash_batch_flush_fn flush_fn, void *cb_data);

/* Flush any objects still queued in the window through flush_fn. */
int object_hash_batch_flush(const struct git_hash_algo *algo,
			    struct object_hash_batch *b,
			    object_hash_batch_flush_fn flush_fn, void *cb_data);
#endif
void write_object_file_prepare(const struct git_hash_algo *algo,
			       const void *buf, unsigned long len,
			       enum object_type type, struct object_id *oid,
			       char *hdr, int *hdrlen);
int write_loose_object(struct odb_source_loose *loose,
		       const struct object_id *oid, char *hdr,
		       int hdrlen, const void *buf, unsigned long len,
		       time_t mtime, unsigned flags);

/* Helper to check and "touch" a file */
int check_and_freshen_file(const char *fn, int freshen);

/*
 * Open the loose object at path, check its hash, and return the contents,
 * use the "oi" argument to assert things about the object, or e.g. populate its
 * type, and size. If the object is a blob, then "contents" may return NULL,
 * to allow streaming of large blobs.
 *
 * Returns 0 on success, negative on error (details may be written to stderr).
 */
int read_loose_object(struct repository *repo,
		      const char *path,
		      const struct object_id *expected_oid,
		      struct object_id *real_oid,
		      void **contents,
		      struct object_info *oi);

enum unpack_loose_header_result {
	ULHR_OK,
	ULHR_BAD,
	ULHR_TOO_LONG,
};

/**
 * unpack_loose_header() initializes the data stream needed to unpack
 * a loose object header.
 *
 * Returns:
 *
 * - ULHR_OK on success
 * - ULHR_BAD on error
 * - ULHR_TOO_LONG if the header was too long
 *
 * It will only parse up to MAX_HEADER_LEN bytes.
 */
enum unpack_loose_header_result unpack_loose_header(git_zstream *stream,
						    unsigned char *map,
						    unsigned long mapsize,
						    void *buffer,
						    unsigned long bufsiz);
void *unpack_loose_rest(git_zstream *stream,
			void *buffer, unsigned long size,
			const struct object_id *oid);

int parse_loose_header(const char *hdr, struct object_info *oi);

struct odb_transaction;

/*
 * Tell the object database to optimize for adding
 * multiple objects. odb_transaction_files_commit must be called
 * to make new objects visible. If a transaction is already
 * pending, NULL is returned.
 */
struct odb_transaction *odb_transaction_files_begin(struct odb_source *source);

#endif /* OBJECT_FILE_H */
