#!/bin/sh
#
# Verify that the vendored sha1dc/ files are identical to the ones in
# the sha1collisiondetection submodule at its pinned commit. This keeps
# the default build and the DC_SHA1_SUBMODULE=1 build compiling the
# same code.
#
# Needs the submodule to be initialized:
#     git submodule update --init sha1collisiondetection

set -e

cd "$(git rev-parse --show-toplevel)"

pin=$(git rev-parse --verify HEAD:sha1collisiondetection)

if ! git -C sha1collisiondetection cat-file -e "$pin^{commit}" 2>/dev/null
then
	echo >&2 "error: submodule commit $pin not available;" \
		"run 'git submodule update --init sha1collisiondetection'"
	exit 1
fi

status=0
for f in $(git ls-files sha1dc)
do
	name=${f#sha1dc/}
	case "$name" in
	check-vendored.sh|.gitattributes)
		# Not part of the vendored library.
		continue
		;;
	LICENSE.txt)
		# The submodule keeps the license at the repository root.
		theirs="$pin:LICENSE.txt"
		;;
	*)
		theirs="$pin:lib/$name"
		;;
	esac

	ours=$(git hash-object "$f")
	if ! theirs=$(git -C sha1collisiondetection rev-parse --verify \
		"$theirs" 2>/dev/null)
	then
		echo "MISSING   $f (not in submodule at $pin)"
		status=1
	elif test "$ours" = "$theirs"
	then
		echo "IDENTICAL $f"
	else
		echo "DIFFER    $f"
		status=1
	fi
done

if test $status -ne 0
then
	echo >&2 "error: sha1dc/ has drifted from the submodule pin"
fi
exit $status
