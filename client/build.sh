#!/bin/bash
set -e

# Configuration
OUTDIR="build"
LDFLAGS="-s -w"

# Clean previous builds
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# Parallel build function
build_target() {
    local os=$1 arch=$2 out=$3
    echo "Building $os/$arch -> $out"
    
    EXT=""
    [ "$os" = "windows" ] && EXT=".exe"
    
    GOOS="$os" GOARCH="$arch" go build -ldflags="$LDFLAGS" -o "$OUTDIR/$os/$out$EXT" client.go
    
    if [ -f "$OUTDIR/$os/$out$EXT" ] && command -v upx >/dev/null; then
        upx --best "$OUTDIR/$os/$out$EXT"
    fi
}

# Main build targets
build_target linux 386 x86 &
build_target linux arm 7 armv7l &
build_target linux arm 5 armv5l &
build_target linux arm64 armv8l &
build_target linux mips mips &
build_target linux mipsle mipsel &
build_target windows 386 x86 &
build_target windows amd64 x64 &
build_target darwin amd64 darwin-amd64 &
build_target darwin arm64 darwin-arm64 &

wait

# Generate checksums
(cd "$OUTDIR" && find . -type f -exec sha256sum {} \; > checksums.txt)

# Size report
echo -e "\nBuild complete. Binary sizes:"
find "$OUTDIR" -type f -exec du -h {} \;