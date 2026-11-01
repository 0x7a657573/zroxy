#!/bin/sh
# Cross-compile a static musl zroxy binary with Zig and package it.
#
#   scripts/release-build.sh <arch>
#
# Output: dist/zroxy-<version>-linux-<arch>.tar.gz
# Environment: ZIG (path to zig, default "zig"), SOURCE_DATE_EPOCH.
set -eu

ARCHES="x86_64 i686 aarch64 armv7 mips mipsel riscv64"

# arch -> "zig target;zig cpu".  Single source of truth for the release targets.
case "${1:-}" in
x86_64)  target='x86_64-linux-musl;baseline' ;;
i686)    target='x86-linux-musl;i686' ;;
aarch64) target='aarch64-linux-musl;baseline' ;;
armv7)   target='arm-linux-musleabihf;generic+v7a' ;;
mips)    target='mips-linux-musleabi;mips32r2' ;;
mipsel)  target='mipsel-linux-musleabi;mips32r2' ;;
riscv64) target='riscv64-linux-musl;baseline_rv64' ;;
*)
	echo "usage: $0 <arch>" >&2
	echo "arches: $ARCHES" >&2
	exit 2
	;;
esac
arch=$1
zig_target=${target%%;*}
zig_cpu=${target#*;}

root=$(cd "$(dirname "$0")/.." && pwd)
ZIG=${ZIG:-zig}
command -v "$ZIG" >/dev/null 2>&1 || { echo "zig not found (set ZIG)" >&2; exit 1; }
ZIG=$(command -v "$ZIG")

version=$(sed -n 's/^#define[[:space:]]*version[[:space:]]*"\([^"]*\)".*/\1/p' \
	"$root/include/zroxy/version.h" | head -n 1)
[ -n "$version" ] || { echo "cannot read version from version.h" >&2; exit 1; }

: "${SOURCE_DATE_EPOCH:=$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

build="$root/build-release/$arch"
dist="$root/dist"
name="zroxy-$version-linux-$arch"
rm -rf "$build"
mkdir -p "$build/bin" "$dist"

# CMake wants single-path executables for the compiler, ar and ranlib.
wrap() {
	printf '#!/bin/sh\nexec "%s" %s "$@"\n' "$ZIG" "$2" > "$build/bin/$1"
	chmod +x "$build/bin/$1"
}
wrap cc "cc -target $zig_target -mcpu=$zig_cpu"
wrap ar ar
wrap ranlib ranlib

cmake -S "$root" -B "$build" \
	-DCMAKE_SYSTEM_NAME=Linux \
	-DCMAKE_SYSTEM_PROCESSOR="$arch" \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_TESTING=OFF \
	-DCMAKE_C_COMPILER="$build/bin/cc" \
	-DCMAKE_AR="$build/bin/ar" \
	-DCMAKE_RANLIB="$build/bin/ranlib" \
	-DCMAKE_EXE_LINKER_FLAGS="-static -s"
cmake --build "$build" --parallel

stage="$build/stage/$name"
mkdir -p "$stage"
cp "$build/zroxy" "$stage/"
for f in LICENSE README.md CHANGELOG.md simple-zroxy.conf; do
	cp "$root/$f" "$stage/"
done

tar -C "$build/stage" --sort=name --owner=0 --group=0 --numeric-owner \
	--mtime="@$SOURCE_DATE_EPOCH" -cf - "$name" | gzip -n -9 > "$dist/$name.tar.gz"
echo "$dist/$name.tar.gz"
