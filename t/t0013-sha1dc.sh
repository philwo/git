#!/bin/sh

test_description='test sha1 collision detection'

. ./test-lib.sh
TEST_DATA="$TEST_DIRECTORY/t0013"

test_lazy_prereq SHA1_IS_SHA1DC 'test-tool sha1-is-sha1dc'

if ! test_have_prereq SHA1_IS_SHA1DC
then
	skip_all='skipping sha1 collision tests, not using sha1collisiondetection'
	test_done
fi

test_lazy_prereq SHA1_UNSAFE_NO_DC '
	test-tool sha1-unsafe <"$TEST_DIRECTORY/t0013/shattered-1.pdf"
'

test_expect_success 'test-sha1 detects shattered pdf' '
	test_must_fail test-tool sha1 <"$TEST_DATA/shattered-1.pdf" 2>err &&
	test_grep collision err &&
	grep 38762cf7f55934b34d179ae6a4c80cadccbb7f0a err
'

# The shattered PDFs only trigger detection when hashed from the very
# start of the stream. Object hashing prepends a "<type> <len>" header,
# so no public collision data can trigger detection inside a repository.
# The runtime switch is therefore tested on raw streams via test-tool,
# and the config plumbing is tested via its trace2 event.

test_expect_success SHA1_UNSAFE_NO_DC 'runtime switch disables collision detection' '
	echo 38762cf7f55934b34d179ae6a4c80cadccbb7f0a >expect &&
	test-tool sha1 --no-collision-check <"$TEST_DATA/shattered-1.pdf" >actual &&
	test_cmp expect actual
'

test_expect_success !SHA1_UNSAFE_NO_DC 'runtime switch is a no-op without an unsafe backend' '
	test_must_fail test-tool sha1 --no-collision-check \
		<"$TEST_DATA/shattered-1.pdf" 2>err &&
	test_grep collision err
'

test_expect_success 'hash.collisionDetection config reaches the hash layer' '
	git init --object-format=sha1 sha1repo &&
	GIT_TRACE2_EVENT="$(pwd)/trace" git -C sha1repo \
		-c hash.collisionDetection=false hash-object --stdin </dev/null &&
	test_grep "\"category\":\"hash\"" trace &&
	test_grep "\"key\":\"sha1-collision-detection\"" trace
'

test_done
