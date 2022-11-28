#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

# This script works on Ubuntu 20.04 and must be run with sudo

set -euo pipefail
set -x

TMPDIR=/tmp/distro_tc/setup

rm -rf $TMPDIR
mkdir -p $TMPDIR/gcc-4.8-debs
mkdir -p $TMPDIR/gcc-clang-latest-debs

PKG_CACHE_DIR=${PKG_CACHE_DIR:-}

if [ -d "$PKG_CACHE_DIR" ]; then
	cp $PKG_CACHE_DIR/gcc-4.8-debs/*deb $TMPDIR/gcc-4.8-debs
	cp $PKG_CACHE_DIR/gcc-clang-latest-debs/*deb $TMPDIR/gcc-clang-latest-debs
else
	# Install GCC-4.8
	echo "deb http://archive.ubuntu.com/ubuntu/ xenial multiverse" >> /etc/apt/sources.list
	echo "deb http://archive.ubuntu.com/ubuntu/ xenial universe" >> /etc/apt/sources.list
	echo "deb http://archive.ubuntu.com/ubuntu/ xenial main" >> /etc/apt/sources.list
	apt-get update -y
	DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends --download-only \
		-o Dir::Cache::archives="$TMPDIR/gcc-4.8-debs" install \
		gcc-4.8 gcc-4.8-aarch64-linux-gnu

	head -n -3 /etc/apt/sources.list > list.tmp
	mv list.tmp /etc/apt/sources.list
	apt-get update -y

	DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends --download-only \
		-o Dir::Cache::archives="$TMPDIR/gcc-clang-latest-debs" install \
		gcc clang gcc-aarch64-linux-gnu

	if [ -n "$PKG_CACHE_DIR" ]; then
		mkdir -p $PKG_CACHE_DIR/gcc-4.8-debs
		mkdir -p $PKG_CACHE_DIR/gcc-clang-latest-debs
		cp $TMPDIR/gcc-4.8-debs/*deb $PKG_CACHE_DIR/gcc-4.8-debs
		cp $TMPDIR/gcc-clang-latest-debs/*deb $PKG_CACHE_DIR/gcc-clang-latest-debs
	fi
fi

dpkg -i $TMPDIR/gcc-4.8-debs/*deb
dpkg -i $TMPDIR/gcc-clang-latest-debs/*deb

TEMPDIR=$(mktemp -d)
cd $TEMPDIR

# Test the installation
cat <<EOF >hello.c
#include <stdio.h>

int main()
{
printf("Hello World\n");
return 0;
}
EOF

set -x
gcc-4.8 --version
gcc-4.8 -o hello hello.c
./hello

gcc --version
gcc -o hello hello.c
./hello

clang --version
clang -o hello hello.c
./hello
clang -target aarch64-linux-gnu -isystem /usr/aarch64-linux-gnu/include -o hello hello.c

aarch64-linux-gnu-gcc --version
aarch64-linux-gnu-gcc -o hello hello.c
aarch64-linux-gnu-gcc-4.8 --version
aarch64-linux-gnu-gcc-4.8 -o hello hello.c
set +x

rm -rf hello*
