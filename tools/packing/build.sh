#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
DOCKERFILE="$SCRIPT_DIR/docker/Dockerfile"
PACK_SCRIPT="$SCRIPT_DIR/pack-to-ts.ts"
GENERATED_DIR="$PROJECT_DIR/dist/lib/generated"
TMP_DIR="$SCRIPT_DIR/tmp"

build_native() {
	platform="$1"
	output_name="$2"

	docker buildx build \
		--platform "$platform" \
		--target artifact \
		--output "type=local,dest=$TMP_DIR" \
		-f "$DOCKERFILE" \
		"$PROJECT_DIR"

	mv "$TMP_DIR/syscall.node" "$TMP_DIR/$output_name"
}

pack_to_ts() {
	binary_path="$1"
	export_name="$2"
	output_path="$3"

	node "$PACK_SCRIPT" "$binary_path" "$export_name" > "$output_path"
}

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
mkdir -p "$GENERATED_DIR"

build_native linux/amd64 syscall-x64.node
build_native linux/arm64 syscall-arm64.node

pack_to_ts "$TMP_DIR/syscall-x64.node" syscallAddonX64 "$GENERATED_DIR/syscall-x64.js"
pack_to_ts "$TMP_DIR/syscall-arm64.node" syscallAddonArm64 "$GENERATED_DIR/syscall-arm64.js"

rm -rf "$TMP_DIR"

echo "Done: generated TypeScript files in $GENERATED_DIR"
