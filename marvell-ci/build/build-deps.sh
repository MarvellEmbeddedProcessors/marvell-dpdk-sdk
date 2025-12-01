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
	echo "--enable-tvm                 : Enable building ML TVM driver dependencies"
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
			rsync -a $cache_dir/$fname .
		else
			mkdir -p "$cache_dir"
			echo "Downloading $url"
			wget $url
			echo "Copying $fname to $cache_dir/"
			rsync -a $fname $cache_dir/
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
	CC=${CROSS_HOST}-gcc ./configure \
		--host=${CROSS_HOST} \
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
	fetch_dep https://gitlab.arm.com/arm-reference-solutions/ipsec-mb/-/archive/SECLIB-IPSEC-2024.07.08/ipsec-mb-SECLIB-IPSEC-2024.07.08.tar.gz
	tar -zxvf ipsec-mb-SECLIB-IPSEC-2024.07.08.tar.gz --strip-components=1
	SHARED=y CC=${CROSS_HOST}-gcc \
		make -C lib AESNI_EMU=y ARCH=aarch64 PREFIX=$INSTALL_ROOT NOLDCONFIG=y
	SHARED=y CC=${CROSS_HOST}-gcc \
		make -C lib AESNI_EMU=y ARCH=aarch64 PREFIX=$INSTALL_ROOT NOLDCONFIG=y install
	popd
}

function setup_openssl()
{
	mkdir -p $BUILD_ROOT/libopenssl

	pushd $BUILD_ROOT/libopenssl
	fetch_dep https://www.openssl.org/source/openssl-1.1.1g.tar.gz
	tar -zxvf openssl-1.1.1g.tar.gz --strip-components=1
	./Configure --cross-compile-prefix=${CROSS_HOST}- \
		--openssldir=etc/ssl \
		--prefix=$INSTALL_ROOT \
		shared \
		linux-aarch64
	make -j${MAKE_J}
	make install -j${MAKE_J}
	popd
}

function setup_libtmc()
{
	mkdir -p $BUILD_ROOT/libtmc

	pushd $BUILD_ROOT/libtmc
	fetch_dep https://github.com/PavanNikhilesh/libtmc/archive/refs/tags/pthread_timed_join.tar.gz
	tar -zxvf pthread_timed_join.tar.gz --strip-components=1
	./bootstrap
	CC=${CROSS_HOST}-gcc ./configure \
		--host=${CROSS_HOST} \
		--prefix=$INSTALL_ROOT
	make -j${MAKE_J}
	make install -j${MAKE_J}
	popd
}

function setup_libarchive()
{
	mkdir -p $BUILD_ROOT/libarchive

	pushd $BUILD_ROOT/libarchive
	fetch_dep https://github.com/libarchive/libarchive/releases/download/v3.6.1/libarchive-3.6.1.tar.gz
	tar -zxvf libarchive-3.6.1.tar.gz
	cd libarchive-3.6.1
	CFLAGS="-I$INSTALL_ROOT/include" \
	LDFLAGS="-L$INSTALL_ROOT/lib" \
	CC=${CROSS_HOST}-gcc ./configure \
		--host=${CROSS_HOST} \
		--without-xml2 \
		--without-lzma \
		--without-zlib \
		--without-zstd \
		--prefix=$INSTALL_ROOT
	make -j${MAKE_J}
	make install -j${MAKE_J}
	popd
}

function setup_cmake()
{
	mkdir -p $BUILD_ROOT/cmake

	pushd $BUILD_ROOT/cmake
	fetch_dep https://github.com/Kitware/CMake/releases/download/v3.26.3/cmake-3.26.3.tar.gz
	tar -zxvf cmake-3.26.3.tar.gz --strip-components=1
	./configure --prefix=$INSTALL_ROOT --parallel=${MAKE_J}
	make -j${MAKE_J}
	make install -j${MAKE_J}
	popd
}

function setup_jansson()
{
	mkdir -p $BUILD_ROOT/jansson

	pushd $BUILD_ROOT/jansson
	fetch_dep http://digip.org/jansson/releases/jansson-2.13.tar.gz
	tar -zxvf jansson-2.13.tar.gz --strip-components=1

	mkdir -p $BUILD_ROOT/jansson/build
	$INSTALL_ROOT/bin/cmake \
		-S $BUILD_ROOT/jansson/ \
		-B $BUILD_ROOT/jansson/build \
		-DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT \
		-DCMAKE_C_COMPILER=${CROSS_HOST}-gcc \
		-DJANSSON_BUILD_SHARED_LIBS=ON
	make -j${MAKE_J} -C $BUILD_ROOT/jansson/build
	make install -j${MAKE_J} -C $BUILD_ROOT/jansson/build
	popd
}

function setup_tvm()
{
	cd $BUILD_ROOT
	MRVL_GIT_USERNAME=${MRVL_GIT_USERNAME:-sa_ip-sw-jenkins}
	git clone "ssh://${MRVL_GIT_USERNAME}@sj1git1.cavium.com:29418/IP/SW/ML/cdk/tvm" \
		--depth=1 --single-branch -b tvm-devel

	pushd $BUILD_ROOT/tvm

	git submodule update --init -f 3rdparty/dlpack
	git submodule update --init -f 3rdparty/dmlc-core
	git submodule update --init -f 3rdparty/libbacktrace
	git submodule update --init -f 3rdparty/rang

	mkdir -p $BUILD_ROOT/dlpack/
	cd $BUILD_ROOT/tvm
	$INSTALL_ROOT/bin/cmake \
		-S $BUILD_ROOT/tvm/3rdparty/dlpack \
		-B $BUILD_ROOT/dlpack/ \
		-DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT \
		-DCMAKE_C_COMPILER=${CROSS_HOST}-gcc \
		-DCMAKE_CXX_COMPILER=${CROSS_HOST}-g++ \
		-DBUILD_MOCK=OFF
	make -j${MAKE_J} -C $BUILD_ROOT/dlpack/
	make install -j${MAKE_J} -C $BUILD_ROOT/dlpack/

	mkdir -p $BUILD_ROOT/dmlc-core
	cd $BUILD_ROOT/tvm
	$INSTALL_ROOT/bin/cmake \
		-S $BUILD_ROOT/tvm/3rdparty/dmlc-core \
		-B $BUILD_ROOT/dmlc-core \
		-DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT \
		-DCMAKE_C_COMPILER=${CROSS_HOST}-gcc \
		-DCMAKE_CXX_COMPILER=${CROSS_HOST}-g++ \
		-DUSE_OPENMP=OFF
	make -j${MAKE_J} -C $BUILD_ROOT/dmlc-core
	make install -j${MAKE_J} -C $BUILD_ROOT/dmlc-core

	mkdir -p $BUILD_ROOT/tvm/build
	cd $BUILD_ROOT/tvm
	$INSTALL_ROOT/bin/cmake \
		-S $BUILD_ROOT/tvm \
		-B $BUILD_ROOT/tvm/build \
		-DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT \
		-DCMAKE_C_COMPILER=${CROSS_HOST}-gcc \
		-DCMAKE_CXX_COMPILER=${CROSS_HOST}-g++ \
		-DMACHINE_NAME=${CROSS_HOST} \
		-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
		-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
		-DUSE_ALTERNATIVE_LINKER=OFF \
		-DUSE_MRVL=ON \
		-DUSE_MRVL_RUNTIME=ON \
		-DUSE_LIBBACKTRACE=ON \
		-DUSE_RPC=OFF \
		-DUSE_GRAPH_EXECUTOR=OFF \
		-DUSE_PROFILER=OFF \
		-DBUILD_STATIC_RUNTIME=OFF

	make -j${MAKE_J} -C $BUILD_ROOT/tvm/build
	make install -j${MAKE_J} -C $BUILD_ROOT/tvm/build
	popd
}

function setup_tvmdp()
{
	cd $BUILD_ROOT
	MRVL_GIT_USERNAME=${MRVL_GIT_USERNAME:-sa_ip-sw-jenkins}
	git clone "ssh://${MRVL_GIT_USERNAME}@sj1git1.cavium.com:29418/IP/SW/ML/cdk/tvm/tvmdp" \
		--depth=1 --single-branch -b tvmdp-devel

	pushd $BUILD_ROOT/tvmdp

	mkdir -p $BUILD_ROOT/tvmdp/build

	$INSTALL_ROOT/bin/cmake \
		-S $BUILD_ROOT/tvmdp \
		-B $BUILD_ROOT/tvmdp/build \
		-DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT \
		-DCMAKE_C_COMPILER=${CROSS_HOST}-gcc \
		-DCMAKE_CXX_COMPILER=${CROSS_HOST}-g++ \
		-DBUILD_SHARED_LIBS=ON

	make -C $BUILD_ROOT/tvmdp/build
	make -C $BUILD_ROOT/tvmdp/build install
	popd
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "i:r:j:p:h" \
	-l "install-root:,build-root:,jobs:,project-root:,enable-tvm,help" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

CROSS_HOST=${CROSS_HOST:-aarch64-none-linux-gnu}
BUILD_ROOT=
INSTALL_ROOT=
MAKE_J=4
PROJECT_ROOT="$PWD"
ENABLE_TVM=0

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build-root) shift; BUILD_ROOT=$1;;
		-i|--install-root) shift; INSTALL_ROOT=$1;;
		-j|--jobs) shift; MAKE_J=$1;;
		-p|--project-root) shift; PROJECT_ROOT=$1;;
		--enable-tvm) ENABLE_TVM=1;;
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
setup_libtmc

if [[ $ENABLE_TVM -eq 1 ]]; then
	setup_libarchive
	setup_cmake
	setup_jansson
	setup_tvm
	setup_tvmdp
fi
