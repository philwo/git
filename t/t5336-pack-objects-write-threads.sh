#!/bin/sh

test_description='pack-objects produces identical packs with optimized write and read paths'

. ./test-lib.sh

test_expect_success 'setup a repository with delta chains' '
	test_commit_bulk --id=file 64 &&
	git repack -ad
'

# The parallel write phase must produce bytes identical to the
# single-threaded writer, whether the payloads are produced afresh or
# copied from the source pack.
test_expect_success 'parallel write phase produces an identical pack' '
	git -c pack.threads=1 -c pack.writeThreads=1 \
		pack-objects --all --no-reuse-object serial </dev/null >name1 &&
	git -c pack.threads=1 -c pack.writeThreads=8 \
		pack-objects --all --no-reuse-object threaded </dev/null >name2 &&
	test_cmp name1 name2 &&
	test_cmp serial-$(cat name1).pack threaded-$(cat name2).pack &&
	git verify-pack threaded-$(cat name2).idx
'

test_expect_success 'parallel write phase reuses pack data identically' '
	git -c pack.threads=1 -c pack.writeThreads=1 \
		pack-objects --all reuse1 </dev/null >name3 &&
	git -c pack.threads=1 -c pack.writeThreads=8 \
		pack-objects --all reuse2 </dev/null >name4 &&
	test_cmp name3 name4 &&
	test_cmp reuse1-$(cat name3).pack reuse2-$(cat name4).pack
'

# Byte identity alone also holds when the option is silently ignored;
# check via trace2 that the parallel writer ran and its workers
# prepared at least one entry.
test_expect_success PTHREADS 'parallel write phase actually uses workers' '
	GIT_TRACE2_EVENT="$(pwd)/trace-write.txt" \
	git -c pack.threads=1 -c pack.writeThreads=8 \
		pack-objects --all --no-reuse-object workers </dev/null >name7 &&
	grep "\"key\":\"write_prep/stolen\"" trace-write.txt &&
	prepared=$(sed -n "s/.*\"key\":\"write_prep\/prepared\",\"value\":\"\([0-9]*\)\".*/\1/p" trace-write.txt) &&
	test "$prepared" -gt 0
'

test_done
