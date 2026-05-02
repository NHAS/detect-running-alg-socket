#!/bin/bash

APP_NAME="detect-running-alg-socket"
BUILD_DIR="build"
ARCHS="amd64 arm arm64 386 mips mipsle mips64 mips64le ppc64 ppc64le s390x riscv64 loong64"

mkdir -p "$BUILD_DIR"

for ARCH in $ARCHS; do
    echo "Building for linux/$ARCH..."
    GOOS=linux GOARCH=$ARCH go build -o "$BUILD_DIR/${APP_NAME}-linux-${ARCH}" .
    if [ $? -ne 0 ]; then
        echo "Failed to build for linux/$ARCH"
    fi
done

echo "Done"