#define DISABLE_SIGN_COMPARE_WARNINGS

#include "git-compat-util.h"
#include "environment.h"
#include "hex.h"
#include "repository.h"
#include "pack.h"
#include "progress.h"
#include "packfile.h"
#include "object-file.h"
#include "odb.h"
#include "odb/streaming.h"

struct idx_entry {
	off_t                offset;
	unsigned int nr;
};

static int compare_entries(const void *e1, const void *e2)
{
	const struct idx_entry *entry1 = e1;
	const struct idx_entry *entry2 = e2;
	if (entry1->offset < entry2->offset)
		return -1;
	if (entry1->offset > entry2->offset)
		return 1;
	return 0;
}

int check_pack_crc(struct packed_git *p, struct pack_window **w_curs,
		   off_t offset, off_t len, unsigned int nr)
{
	const uint32_t *index_crc;
	uint32_t data_crc = crc32(0, NULL, 0);

	do {
		unsigned long avail;
		void *data = use_pack(p, w_curs, offset, &avail);
		if (avail > len)
			avail = len;
		data_crc = crc32(data_crc, data, avail);
		offset += avail;
		len -= avail;
	} while (len);

	index_crc = p->index_data;
	index_crc += 2 + 256 + (size_t)p->num_objects * (p->repo->hash_algo->rawsz/4) + nr;

	return data_crc != ntohl(*index_crc);
}

/*
 * Hand one verified object to the caller's verify_fn, honoring its "eaten"
 * out-param: if the callback took ownership of the buffer, clear *data so the
 * caller does not also free it.
 */
static int verify_call_fn(verify_fn fn, void *fn_data,
			  const struct object_id *oid, enum object_type type,
			  size_t size, void **data)
{
	int eaten = 0;
	int err = fn(oid, type, size, *data, &eaten, fn_data);
	if (eaten)
		*data = NULL;
	return err;
}

#ifdef SHA1_MB
/*
 * Context for verify_batch_flush(): the pack and verify_fn that verify_packfile()
 * would otherwise pass straight through to each per-object check.
 */
struct verify_batch_cb {
	struct packed_git *p;
	verify_fn fn;
	void *fn_data;
};

/*
 * object_hash_batch flush callback. For each queued object, compare its computed
 * oid against the expected oid stashed in oid[] -- the batched equivalent of
 * check_object_signature() with a precomputed hash (hash_object_file_batch()
 * produces the identical oid) -- then run the verify_fn and free the buffer.
 */
static int verify_batch_flush(struct object_hash_batch *b,
			      const struct object_id *computed, void *cb_data)
{
	struct verify_batch_cb *cb = cb_data;
	int err = 0;
	int i;

	for (i = 0; i < b->n; i++) {
		void *data = b->data[i];

		if (!oideq(&computed[i], &b->oid[i]))
			err |= error("packed %s from %s is corrupt",
				     oid_to_hex(&b->oid[i]), cb->p->pack_name);
		else if (cb->fn)
			err |= verify_call_fn(cb->fn, cb->fn_data, &b->oid[i],
					      b->type[i], b->size[i], &data);
		free(data);
	}
	return err;
}

/*
 * A real pack's objects span tens of bytes to hundreds of KB. Hashing 16 at a
 * time, a batch runs at the speed of its longest lane, so mixing one large
 * object with small ones wastes lanes -- a naive single window can even run
 * slower than the scalar hasher. Route each object into a log2 size-class bin
 * and hash a bin once it holds 16 similar-sized objects, so every SIMD round
 * has balanced lanes. This reaches ~SHA-NI throughput regardless of the order
 * objects appear in the pack. VERIFY_HASH_BIN_MAX_BYTES bounds total pinned
 * in-core data across all bins.
 */
#define VERIFY_HASH_NR_BINS 24
#define VERIFY_HASH_BIN_MAX_BYTES ((size_t)64 * 1024 * 1024)

static int verify_size_bin(size_t size)
{
	int b = 0;
	while (size > 64 && b < VERIFY_HASH_NR_BINS - 1) {
		size >>= 1;
		b++;
	}
	return b;
}

static int verify_bins_flush_all(const struct git_hash_algo *algo,
				 struct object_hash_batch *bins,
				 object_hash_batch_flush_fn flush_fn, void *cb_data)
{
	int err = 0, k;

	for (k = 0; k < VERIFY_HASH_NR_BINS; k++)
		err |= object_hash_batch_flush(algo, &bins[k], flush_fn, cb_data);
	return err;
}

/*
 * Add one object to its size bin (which self-flushes at 16 objects), then bound
 * memory: if the bins together hold more than VERIFY_HASH_BIN_MAX_BYTES, flush
 * the largest one. That only bites when several bins fill with large objects at
 * once; the common case is a bin reaching 16 and flushing on its own.
 */
static int verify_bins_add(const struct git_hash_algo *algo,
			   struct object_hash_batch *bins,
			   void *data, size_t size, enum object_type type,
			   const struct object_id *oid,
			   object_hash_batch_flush_fn flush_fn, void *cb_data)
{
	int err, k, maxk = 0;
	size_t total = 0, maxb = 0;

	err = object_hash_batch_add(algo, &bins[verify_size_bin(size)], data,
				    size, type, NULL, oid, flush_fn, cb_data);
	for (k = 0; k < VERIFY_HASH_NR_BINS; k++) {
		total += bins[k].buffered_bytes;
		if (bins[k].buffered_bytes > maxb) {
			maxb = bins[k].buffered_bytes;
			maxk = k;
		}
	}
	if (total > VERIFY_HASH_BIN_MAX_BYTES)
		err |= object_hash_batch_flush(algo, &bins[maxk], flush_fn, cb_data);
	return err;
}
#endif

static int verify_packfile(struct repository *r,
			   struct packed_git *p,
			   struct pack_window **w_curs,
			   verify_fn fn,
			   void *fn_data,
			   struct progress *progress, uint32_t base_count)

{
	off_t index_size = p->index_size;
	const unsigned char *index_base = p->index_data;
	struct git_hash_ctx ctx;
	unsigned char hash[GIT_MAX_RAWSZ], *pack_sig;
	off_t offset = 0, pack_sig_ofs = 0;
	uint32_t nr_objects, i;
	int err = 0;
	struct idx_entry *entries;
#ifdef SHA1_MB
	/*
	 * Hash in-core objects 16-wide, grouped into size-class bins so each
	 * SIMD round has balanced lanes (see verify_bins_add). This path
	 * (git fsck) is single-threaded and hash-bound, so it is worth it.
	 * (git verify-pack does not reach here; it shells out to
	 * "index-pack --verify".)
	 */
	struct object_hash_batch bins[VERIFY_HASH_NR_BINS] = { 0 };
	struct verify_batch_cb batch_cb = { p, fn, fn_data };
	int use_batch = hash_object_batch_available(r->hash_algo);
	for (int k = 0; k < VERIFY_HASH_NR_BINS; k++)
		bins[k].max_bytes = VERIFY_HASH_BIN_MAX_BYTES;
#endif

	if (!is_pack_valid(p))
		return error("packfile %s cannot be accessed", p->pack_name);

	r->hash_algo->init_fn(&ctx);
	do {
		unsigned long remaining;
		unsigned char *in = use_pack(p, w_curs, offset, &remaining);
		offset += remaining;
		if (!pack_sig_ofs)
			pack_sig_ofs = p->pack_size - r->hash_algo->rawsz;
		if (offset > pack_sig_ofs)
			remaining -= (unsigned int)(offset - pack_sig_ofs);
		git_hash_update(&ctx, in, remaining);
	} while (offset < pack_sig_ofs);
	git_hash_final(hash, &ctx);
	pack_sig = use_pack(p, w_curs, pack_sig_ofs, NULL);
	if (!hasheq(hash, pack_sig, r->hash_algo))
		err = error("%s pack checksum mismatch",
			    p->pack_name);
	if (!hasheq(index_base + index_size - r->hash_algo->hexsz, pack_sig,
		    r->hash_algo))
		err = error("%s pack checksum does not match its index",
			    p->pack_name);
	unuse_pack(w_curs);

	/* Make sure everything reachable from idx is valid.  Since we
	 * have verified that nr_objects matches between idx and pack,
	 * we do not do scan-streaming check on the pack file.
	 */
	nr_objects = p->num_objects;
	ALLOC_ARRAY(entries, nr_objects + 1);
	entries[nr_objects].offset = pack_sig_ofs;
	/* first sort entries by pack offset, since unpacking them is more efficient that way */
	for (i = 0; i < nr_objects; i++) {
		entries[i].offset = nth_packed_object_offset(p, i);
		entries[i].nr = i;
	}
	QSORT(entries, nr_objects, compare_entries);

	for (i = 0; i < nr_objects; i++) {
		struct odb_read_stream *stream = NULL;
		void *data;
		struct object_id oid;
		enum object_type type;
		size_t size;
		off_t curpos;
		int data_valid;

		if (nth_packed_object_id(&oid, p, entries[i].nr) < 0)
			BUG("unable to get oid of object %lu from %s",
			    (unsigned long)entries[i].nr, p->pack_name);

		if (p->index_version > 1) {
			off_t offset = entries[i].offset;
			off_t len = entries[i+1].offset - offset;
			unsigned int nr = entries[i].nr;
			if (check_pack_crc(p, w_curs, offset, len, nr))
				err = error("index CRC mismatch for object %s "
					    "from %s at offset %"PRIuMAX"",
					    oid_to_hex(&oid),
					    p->pack_name, (uintmax_t)offset);
		}

		curpos = entries[i].offset;
		type = unpack_object_header(p, w_curs, &curpos, &size);
		unuse_pack(w_curs);

		if (type == OBJ_BLOB &&
		    repo_settings_get_big_file_threshold(r) <= size) {
			/*
			 * Let stream_object_signature() check it with
			 * the streaming interface; no point slurping
			 * the data in-core only to discard.
			 */
			data = NULL;
			data_valid = 0;
		} else {
			data = unpack_entry(r, p, entries[i].offset, &type,
					    &size);
			data_valid = 1;
		}

#ifdef SHA1_MB
		if (use_batch && data_valid && data) {
			/*
			 * In-core object: defer its oid check so a size bin of
			 * them can be hashed 16-wide. The bin owns data now and
			 * frees it after the (sequential) fn callback.
			 */
			err |= verify_bins_add(r->hash_algo, bins, data,
					       size, type, &oid,
					       verify_batch_flush, &batch_cb);
			if (((base_count + i) & 1023) == 0)
				display_progress(progress, base_count + i);
			continue;
		}
		/* non-batchable object: drain all pending bins first */
		if (use_batch)
			err |= verify_bins_flush_all(r->hash_algo, bins,
						     verify_batch_flush, &batch_cb);
#endif

		if (data_valid && !data)
			err = error("cannot unpack %s from %s at offset %"PRIuMAX"",
				    oid_to_hex(&oid), p->pack_name,
				    (uintmax_t)entries[i].offset);
		else if (data && check_object_signature(r, &oid, data, size,
							type) < 0)
			err = error("packed %s from %s is corrupt",
				    oid_to_hex(&oid), p->pack_name);
		else if (!data &&
			 (packfile_read_object_stream(&stream, &oid, p, entries[i].offset) < 0 ||
			  stream_object_signature(r, stream, &oid) < 0))
			err = error("packed %s from %s is corrupt",
				    oid_to_hex(&oid), p->pack_name);
		else if (fn)
			err |= verify_call_fn(fn, fn_data, &oid, type, size, &data);
		if (((base_count + i) & 1023) == 0)
			display_progress(progress, base_count + i);

		if (stream)
			odb_read_stream_close(stream);
		free(data);
	}

#ifdef SHA1_MB
	err |= verify_bins_flush_all(r->hash_algo, bins,
				     verify_batch_flush, &batch_cb);
#endif

	display_progress(progress, base_count + i);
	free(entries);
	return err;
}

int verify_pack_index(struct packed_git *p)
{
	int err = 0;

	if (open_pack_index(p))
		return error("packfile %s index not opened", p->pack_name);

	/* Verify SHA1 sum of the index file */
	if (!hashfile_checksum_valid(p->repo->hash_algo, p->index_data, p->index_size))
		err = error("Packfile index for %s hash mismatch",
			    p->pack_name);
	return err;
}

int verify_pack(struct repository *r, struct packed_git *p, verify_fn fn, void *fn_data,
		struct progress *progress, uint32_t base_count)
{
	int err = 0;
	struct pack_window *w_curs = NULL;

	err |= verify_pack_index(p);
	if (!p->index_data)
		return -1;

	err |= verify_packfile(r, p, &w_curs, fn, fn_data, progress, base_count);
	unuse_pack(&w_curs);

	return err;
}
