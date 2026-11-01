#!/bin/sh
# Print the body of the "## <version>" section of CHANGELOG.md.
#
#   scripts/release-notes.sh <version>
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <version>" >&2; exit 2; }
changelog=$(dirname "$0")/../CHANGELOG.md

notes=$(awk -v v="$1" '
	/^## / { if (on) exit; on = ($2 == v) ; next }
	on { print }
' "$changelog")

# Trim leading/trailing blank lines and refuse an empty section.
notes=$(printf '%s\n' "$notes" | sed '/./,$!d')
if [ -z "$notes" ]; then
	echo "no CHANGELOG.md section for $1" >&2
	exit 1
fi
printf '%s\n' "$notes"
