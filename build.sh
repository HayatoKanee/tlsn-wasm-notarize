#!/bin/sh

# This crate must be built using the nightly Rust compiler with specific flags.
# This script automates the build process.

set -e

# Check wasm-pack version (0.14.0+ required for custom profile support)
if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "Error: wasm-pack not found. Install with: cargo install wasm-pack"
    exit 1
fi
WASM_PACK_VERSION=$(wasm-pack --version | sed 's/wasm-pack //')
REQUIRED_VERSION="0.14.0"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$WASM_PACK_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: wasm-pack $WASM_PACK_VERSION is too old. Version $REQUIRED_VERSION+ required."
    echo "Install with: cargo install wasm-pack"
    exit 1
fi

# Clean up older builds
rm -rf pkg

# Configure WASM-compatible C compiler for ring crate.
# Apple clang doesn't support wasm32 targets; LLVM clang does.
if [ -z "$CC_wasm32_unknown_unknown" ]; then
    LLVM_CLANG=""
    for path in /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang; do
        if [ -x "$path" ]; then
            LLVM_CLANG="$path"
            break
        fi
    done
    if [ -n "$LLVM_CLANG" ]; then
        export CC_wasm32_unknown_unknown="$LLVM_CLANG"
        export AR_wasm32_unknown_unknown="$(dirname "$LLVM_CLANG")/llvm-ar"
    fi
fi

# Build the package
wasm-pack build \
    --profile wasm \
    --target web \
    .

# Patch import in spawn.js snippet and copy it to the main folder
file=$(find ./pkg/snippets -name "spawn.js" -print -quit)
if [ -z "$file" ]; then
    echo "Warning: spawn.js snippet not found, skipping patch"
else
    temp=$(mktemp)
    sed 's|../../..|../../../tlsn_wasm_notarize.js|' "$file" >"$temp" && mv "$temp" "$file"
    cp "${file}" ./pkg
fi

# Add extra files to package.json
file="pkg/package.json"
if command -v jq >/dev/null 2>&1; then
    temp=$(mktemp)
    jq '.files += ["tlsn_wasm_notarize_bg.wasm.d.ts"]' "$file" >"$temp" && mv "$temp" "$file"
    jq '.files += ["spawn.js"]' "$file" >"$temp" && mv "$temp" "$file"
    jq '.files += ["snippets/"]' "$file" >"$temp" && mv "$temp" "$file"
fi

echo "Build complete! Output in pkg/"
