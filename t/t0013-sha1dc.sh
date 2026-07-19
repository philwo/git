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
	test_grep "\"key\":\"sha1-collision-detection\",\"value\":\"0\"" trace
'

test_expect_success 'setup small pack' '
	test_commit -C sha1repo one &&
	git -C sha1repo pack-objects --all --stdout >small.pack </dev/null
'

test_expect_success 'index-pack --no-collision-check disables detection' '
	GIT_TRACE2_EVENT="$(pwd)/trace-ip" \
		git -C sha1repo index-pack --no-collision-check \
		-o "$(pwd)/small1.idx" "$(pwd)/small.pack" &&
	test_grep "\"key\":\"sha1-collision-detection\",\"value\":\"0\"" trace-ip
'

test_expect_success 'index-pack --collision-check overrides config' '
	GIT_TRACE2_EVENT="$(pwd)/trace-ip2" \
		git -C sha1repo -c hash.collisionDetection=false \
		index-pack --collision-check \
		-o "$(pwd)/small2.idx" "$(pwd)/small.pack" &&
	grep "sha1-collision-detection" trace-ip2 | tail -n 1 >last &&
	test_grep "\"value\":\"1\"" last
'

test_expect_success !SHA1_UNSAFE_NO_DC '--no-collision-check warns without an unsafe backend' '
	git -C sha1repo index-pack --no-collision-check \
		-o "$(pwd)/small3.idx" "$(pwd)/small.pack" 2>err &&
	test_grep "no effect" err
'

test_expect_success 'unpack-objects --no-collision-check disables detection' '
	git init --object-format=sha1 unpackrepo &&
	GIT_TRACE2_EVENT="$(pwd)/trace-uo" \
		git -C unpackrepo unpack-objects -q --no-collision-check \
		<small.pack &&
	test_grep "\"key\":\"sha1-collision-detection\",\"value\":\"0\"" trace-uo
'

test_expect_success 'unpack-objects --collision-check overrides config' '
	git init --object-format=sha1 unpackrepo2 &&
	GIT_TRACE2_EVENT="$(pwd)/trace-uo2" \
		git -C unpackrepo2 -c hash.collisionDetection=false \
		unpack-objects -q --collision-check <small.pack &&
	grep "sha1-collision-detection" trace-uo2 | tail -n 1 >last &&
	test_grep "\"value\":\"1\"" last
'

test_done
