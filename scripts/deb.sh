#!/bin/sh

set -e

[ -z "$1" ] && echo 'no build directory given' && exit 1
if [ -d "$1" ] || [ -f "$1" ]; then
    echo 'build directory already exists' && exit 1
fi

BUILD_DIR="$1"

GOFILES="$(find . -name '*.go' -type f | sort)"
VERSION="$(git describe --tags --abbrev=0)-$(git rev-parse --short HEAD)"
COMMIT="$(git rev-parse HEAD)"
HASH="$(cat $GOFILES go.mod go.sum | sha256sum | sed -Ee 's/\s|-//g')"

mkdir "$BUILD_DIR/DEBIAN" -p

cat > "$BUILD_DIR/DEBIAN/control" <<- EOF
Package: vine
Version: 0.0.1
Architecture: amd64
Maintainer: $(git config --global --get user.name) <$(git config --global --get user.email)>
Essential: no
Priority: optional
Description: A toy blockchain.
EOF

make bin/vine

mkdir -p "$BUILD_DIR/usr/local/bin"
mkdir -p "$BUILD_DIR/lib/systemd/system"
mkdir -p "$BUILD_DIR/usr/local/share/vine"

cp ./bin/vine "$BUILD_DIR/usr/local/bin"
cp ./systemd/vine.service "$BUILD_DIR/lib/systemd/system/vine.service"
cp README.md LICENSE "$BUILD_DIR/usr/local/share/vine"

dpkg-deb --build "$BUILD_DIR"
rm -r "$BUILD_DIR"

