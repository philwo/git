#!/bin/sh

test_description='per-URL SHA-1 collision detection configuration for fetching'

. ./test-lib.sh

# These tests verify the plumbing: the hash.<url>.collisionDetection
# config must be resolved against the remote URL and passed to the
# spawned index-pack or unpack-objects as --[no-]collision-check. The
# effect of the option on SHA-1 hashing itself is tested in t0013.

test_expect_success 'setup' '
	git init server &&
	test_commit -C server one &&
	URL="file://$PWD/server"
'

test_expect_success 'fetch without config passes no collision option' '
	git init client1 &&
	GIT_TRACE2_EVENT="$(pwd)/trace1" git -C client1 fetch "$URL" &&
	! grep collision-check trace1
'

test_expect_success 'per-URL config disables collision detection' '
	git init client2 &&
	GIT_TRACE2_EVENT="$(pwd)/trace2" git -C client2 \
		-c "hash.$URL.collisionDetection=false" fetch "$URL" &&
	test_grep "\"--no-collision-check\"" trace2 &&
	test_grep "\"key\":\"sha1-collision-detection\",\"value\":\"0\"" trace2
'

test_expect_success 'per-URL config reaches index-pack' '
	git init client3 &&
	GIT_TRACE2_EVENT="$(pwd)/trace3" git -C client3 \
		-c transfer.unpackLimit=1 \
		-c "hash.$URL.collisionDetection=false" fetch "$URL" &&
	grep "child_start" trace3 | grep "index-pack" >child &&
	test_grep "\"--no-collision-check\"" child
'

test_expect_success 'per-URL true overrides a global false' '
	git init client4 &&
	GIT_TRACE2_EVENT="$(pwd)/trace4" git -C client4 \
		-c hash.collisionDetection=false \
		-c "hash.$URL.collisionDetection=true" fetch "$URL" &&
	test_grep "\"--collision-check\"" trace4 &&
	! grep "no-collision-check" trace4
'

test_expect_success 'plain hash.collisionDetection is the fallback' '
	git init client5 &&
	GIT_TRACE2_EVENT="$(pwd)/trace5" git -C client5 \
		-c hash.collisionDetection=false fetch "$URL" &&
	test_grep "\"--no-collision-check\"" trace5
'

test_expect_success 'config for an unrelated URL has no effect' '
	git init client6 &&
	GIT_TRACE2_EVENT="$(pwd)/trace6" git -C client6 \
		-c "hash.https://example.com.collisionDetection=false" \
		fetch "$URL" &&
	! grep collision-check trace6
'

test_expect_success 'URL matching happens after insteadOf rewriting' '
	git init client7 &&
	git -C client7 config "url.file://$PWD/.insteadOf" trusted: &&
	git -C client7 config "hash.$URL.collisionDetection" false &&
	GIT_TRACE2_EVENT="$(pwd)/trace7" git -C client7 fetch trusted:server &&
	test_grep "\"--no-collision-check\"" trace7
'

test_expect_success 'clone honors the per-URL config' '
	GIT_TRACE2_EVENT="$(pwd)/trace8" git \
		-c "hash.$URL.collisionDetection=false" clone "$URL" client8 &&
	test_grep "\"--no-collision-check\"" trace8
'

test_expect_success 'fetch-pack resolves the per-URL config itself' '
	git init client9 &&
	GIT_TRACE2_EVENT="$(pwd)/trace9" git -C client9 \
		-c "hash.$URL.collisionDetection=false" \
		fetch-pack "$URL" HEAD &&
	test_grep "\"--no-collision-check\"" trace9
'

test_expect_success 'fetch-pack --collision-check overrides the config' '
	git init client10 &&
	GIT_TRACE2_EVENT="$(pwd)/trace10" git -C client10 \
		-c "hash.$URL.collisionDetection=false" \
		fetch-pack --collision-check "$URL" HEAD &&
	test_grep "\"--collision-check\"" trace10 &&
	! grep "no-collision-check" trace10
'

test_done
