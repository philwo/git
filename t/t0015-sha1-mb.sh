#!/bin/sh

test_description='batched multi-buffer SHA-1DC hasher (AVX-512)'

. ./test-lib.sh

# The batched hasher is an optional build (SHA1_MB=YesPlease) and needs AVX-512
# at runtime. The --probe mode only reports availability. It does not run the
# correctness corpus, so a hasher regression fails the tests below loudly
# instead of unsetting this prereq and skipping the whole file.
test_lazy_prereq SHA1_MB '
	test-tool sha1-mb --probe >out &&
	grep "^sha1_mb: available" out
'

if ! test_have_prereq SHA1_MB
then
	skip_all="sha1-mb not built or no AVX-512; skipping"
	test_done
fi

test_expect_success 'batched SHA-1DC matches the_hash_algo over many objects' '
	test-tool sha1-mb 5000 1 >out &&
	grep "correctness: 5000 objects, OK" out
'

test_expect_success 'two-segment (prefix + body) path matches scalar sha1dc' '
	test-tool sha1-mb 1 1 >out &&
	grep "prefix-sweep: .* OK" out
'

test_expect_success 'batched SHA-1DC flags a known collision block' '
	test-tool sha1-mb --collision >out &&
	grep "^collision: detected f92d74e3874587aaf443d1db961d4e26dde13e9c" out
'

test_expect_success 'batched SHA-1DC flags a collision at a non-zero lane' '
	test-tool sha1-mb --collision >out &&
	grep "^collision-batch: detected lane 10 f92d74e3874587aaf443d1db961d4e26dde13e9c" out
'

test_expect_success 'generated recompression matches scalar sha1dc (testt 58 and 65)' '
	test-tool sha1-mb --recompress >out &&
	grep "^recompress: .* OK" out
'

test_done
