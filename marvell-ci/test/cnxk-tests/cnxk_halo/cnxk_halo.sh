#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2025 Marvell.

set -e

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

echo "TEST NAME : $DPDK_TEST"
echo "TEST DIR  : $PWD"
echo "TEST ARGS : $@"

# Find the cnxk-test application
if [[ -f $SCRIPTPATH/../../../../app/test/dpdk-test ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../app/test/dpdk-test
elif [[ -f $SCRIPTPATH/../../dpdk-test ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-test
else
	DPDK_TEST_BIN=$(which dpdk-test)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-test not found !!"
		exit 1
	fi
fi

# Get PCI ID for NPA
NPA_ID=$(lspci -d :a0fb | tail -n1 | awk '{print $1}')
if [[ -z $NPA_ID ]]; then
	echo "NPA device not found !!"
	exit 1
fi

# Testing mempool_autotest with halo_ena = 1
DPDK_TEST=mempool_autotest $DPDK_TEST_BIN -a ${NPA_ID},halo_ena=1
# Testing mempool_autotest with halo_ena = 0
DPDK_TEST=mbuf_autotest $DPDK_TEST_BIN -a ${NPA_ID},halo_ena=0
# Testing mbuf_autotest with halo_ena = 1
DPDK_TEST=mempool_autotest $DPDK_TEST_BIN -a ${NPA_ID},halo_ena=1
# Testing mbuf_autotest with halo_ena = 0
DPDK_TEST=mbuf_autotest $DPDK_TEST_BIN -a ${NPA_ID},halo_ena=0
