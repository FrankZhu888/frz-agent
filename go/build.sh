#!/bin/bash
# Build frza release packages for macOS and Linux with version info injected.
# Requires: Go toolchain in PATH (https://go.dev/dl/).
#
#   ./build.sh            # build all packages with VERSION below
#   VERSION=v0.2.0 ./build.sh
#
# Output: dist/frza_<VERSION>_<os>_<arch>.tar.gz (binary + LICENSE) + checksums.txt
set -e

VERSION=${VERSION:-v0.1.0}
BUILD_TIME=$(date +%Y-%m-%d)
# -s -w strips the symbol table and debug info; -trimpath removes local build paths
LDFLAGS="-s -w -X main.version=$VERSION -X main.buildTime=$BUILD_TIME"

cd "$(dirname "$0")"
DIST=dist/$VERSION
rm -rf "$DIST"
mkdir -p "$DIST"

pack() { # GOOS GOARCH
	local out=frza-$1-$2
	echo "building $out ..."
	CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -trimpath -ldflags "$LDFLAGS" -o "$DIST/$out" .
	# release tarball: just the binary + LICENSE (starter skills are embedded
	# in the binary and released to ~/.frza/skills on first run)
	local pkgdir=$DIST/pkg-frza_${VERSION}_$1_$2
	mkdir -p "$pkgdir"
	mv "$DIST/$out" "$pkgdir/frza"
	[ -f ../LICENSE ] && cp ../LICENSE "$pkgdir/" || true
	tar -C "$DIST" -czf "$DIST/frza_${VERSION}_$1_$2.tar.gz" "pkg-frza_${VERSION}_$1_$2"
	rm -rf "$pkgdir"
}

pack linux amd64
pack linux arm64
pack darwin amd64
pack darwin arm64

# local dev binary (not packaged)
go build -trimpath -ldflags "$LDFLAGS" -o frza .

(cd "$DIST" && shasum -a 256 frza_${VERSION}_*.tar.gz > checksums.txt)

echo "built $VERSION ($BUILD_TIME):"
ls -lh "$DIST"/*.tar.gz | awk '{print "  " $5, $9}'
