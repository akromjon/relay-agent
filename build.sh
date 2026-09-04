#!/usr/bin/env bash
# Cross-compile static binaries + sha256 into dist/. Usage: ./build.sh [version]
set -Eeuo pipefail
cd "$(dirname "$0")"
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
mkdir -p dist
for ARCH in amd64 arm64; do
	OUT="dist/relay-agent-linux-${ARCH}"
	CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
		go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}" .
	(cd dist && shasum -a 256 "relay-agent-linux-${ARCH}" > "relay-agent-linux-${ARCH}.sha256")
	ls -la "${OUT}"
done
echo "built ${VERSION}"
