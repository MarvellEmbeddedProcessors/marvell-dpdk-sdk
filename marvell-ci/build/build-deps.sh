#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.
#

set -euo pipefail
set -x

function help() {
	set +x
	echo "Build DPDK Dependencies"
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [ARGUMENTS]..."
	echo ""
	echo "Mandatory Arguments"
	echo "==================="
	echo "--build-root | -r            : Build root directory"
	echo ""
	echo "Optional Arguments"
	echo "==================="
	echo "--jobs | -j                  : Number of parallel jobs [Default: 4]"
	echo "--install-root | -i          : Install directory"
	echo "--project-root | -p          : DPDK Project root [Default: PWD]"
	echo "--help | -h                  : Print this help and exit"
	set -x
}

function fetch_dep() {
	local url=$1
	local fname=$(basename $url)
	local cache_dir=${PKG_CACHE_DIR:-}

	if [ ! -z "$cache_dir" ]; then
		if [ -e "$cache_dir/$fname" ]; then
			echo "Copying from: $cache_dir/$fname."
			cp $cache_dir/$fname .
		else
			mkdir -p "$cache_dir"
			echo "Downloading $url"
			wget $url
			echo "Copying $fname to $cache_dir/"
			cp $fname $cache_dir/
		fi
	else
		echo "Downloading $url"
		wget $url
	fi
}

function setup_libpcap()
{
	mkdir -p $BUILD_ROOT/libpcap

	pushd $BUILD_ROOT/libpcap
	fetch_dep https://github.com/the-tcpdump-group/libpcap/archive/libpcap-1.10.0.tar.gz
	tar -zxf libpcap-1.10.0.tar.gz
	cd libpcap-libpcap-1.10.0
	CC=aarch64-marvell-linux-gnu-gcc  ./configure \
		--host=aarch64-linux-gnu \
		--without-libnl \
		--prefix=$INSTALL_ROOT
	make -j${MAKE_J}
	make install -j${MAKE_J}
	popd
}

function setup_ipsec_mb()
{
	mkdir -p $BUILD_ROOT/ipsec_mb

	pushd $BUILD_ROOT/ipsec_mb
	fetch_dep https://gitlab.arm.com/arm-reference-solutions/ipsec-mb/-/archive/SECLIB-IPSEC-2023.3.21/ipsec-mb-SECLIB-IPSEC-2023.3.21.tar.gz
	tar -zxvf ipsec-mb-SECLIB-IPSEC-2023.3.21.tar.gz --strip-components=1
	SHARED=y CC=aarch64-marvell-linux-gnu-gcc \
		make -C lib AESNI_EMU=y ARCH=aarch64 PREFIX=$INSTALL_ROOT NOLDCONFIG=y
	SHARED=y CC=aarch64-marvell-linux-gnu-gcc \
		make -C lib AESNI_EMU=y ARCH=aarch64 PREFIX=$INSTALL_ROOT NOLDCONFIG=y install
	popd
}

function setup_openssl()
{
	mkdir -p $BUILD_ROOT/libopenssl

	pushd $BUILD_ROOT/libopenssl
	fetch_dep https://www.openssl.org/source/openssl-1.1.1g.tar.gz
	tar -zxvf openssl-1.1.1g.tar.gz --strip-components=1
	./Configure --cross-compile-prefix=aarch64-marvell-linux-gnu- \
		--openssldir=etc/ssl \
		--prefix=$INSTALL_ROOT \
		shared \
		linux-aarch64
	make -j${MAKE_J}
	make install -j${MAKE_J}
	popd
}

function setup_mlutils()
{
       mkdir -p $BUILD_ROOT/mlutils

       pushd $BUILD_ROOT/mlutils
       MRVL_GIT_USERNAME=${MRVL_GIT_USERNAME:-sa_ip-sw-jenkins}
       rm -rf mlutils
       git clone ssh://${MRVL_GIT_USERNAME}@sj1git1.cavium.com:29418/IP/SW/ML/cdk/ml-compiler-rel.git \
       --depth=1 --single-branch -b ml-compiler-rel-devel mlutils
       cd mlutils
       make -f demo/Makefile install_headers INSTALL_PREFIX=$INSTALL_ROOT
       popd
}

function setup_libtmc()
{
	mkdir -p $BUILD_ROOT/libtmc

	pushd $BUILD_ROOT/libtmc
	fetch_dep https://github.com/PavanNikhilesh/libtmc/archive/refs/tags/pthread_timed_join.tar.gz
	tar -zxvf pthread_timed_join.tar.gz --strip-components=1
	./bootstrap
	./configure --host=aarch64-marvell-linux-gnu \
		--prefix=$INSTALL_ROOT
	make -j${MAKE_J}
	make install -j${MAKE_J}
	popd
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "i:r:j:p:h" \
	-l "install-root:,build-root:,jobs:,project-root:,help" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

BUILD_ROOT=
INSTALL_ROOT=
MAKE_J=4
PROJECT_ROOT="$PWD"

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build-root) shift; BUILD_ROOT=$1;;
		-i|--install-root) shift; INSTALL_ROOT=$1;;
		-j|--jobs) shift; MAKE_J=$1;;
		-p|--project-root) shift; PROJECT_ROOT=$1;;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done


if [[ -z $BUILD_ROOT ]]; then
	echo "Build root directory should be given !!"
	help
	exit 1
fi

PROJECT_ROOT=$(realpath $PROJECT_ROOT)
mkdir -p $BUILD_ROOT
BUILD_ROOT=$(realpath $BUILD_ROOT)

if [[ -z $INSTALL_ROOT ]]; then
	INSTALL_ROOT=$BUILD_ROOT/prefix
fi

cd $PROJECT_ROOT

setup_libpcap
setup_ipsec_mb
setup_openssl
setup_mlutils
setup_libtmc
