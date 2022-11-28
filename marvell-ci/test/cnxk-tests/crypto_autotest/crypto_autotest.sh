#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

CN10K_CRYPTO_DEVICE="0002:20:00.1"
CN10K_MEMPOOL_DEVICE="0002:1f:00.0"
CN10K_EAL_ARGS="-a $CN10K_CRYPTO_DEVICE,max_qps_limit=4 -a $CN10K_MEMPOOL_DEVICE"
CN10K_EAL_ARGS+=" --log-level=7"

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

run_cn10k_crypto_autotest() {
	DPDK_TEST=cryptodev_cn10k_autotest $DPDK_TEST_BIN $CN10K_EAL_ARGS
	DPDK_TEST=cryptodev_cn10k_asym_autotest $DPDK_TEST_BIN $CN10K_EAL_ARGS
}

run_cn9k_crypto_autotest() {
	DPDK_TEST=cryptodev_cn9k_autotest $DPDK_TEST_BIN
	DPDK_TEST=cryptodev_cn9k_asym_autotest $DPDK_TEST_BIN
}

run_crypto_autotest() {
	case $PLAT in
		cn9*) run_cn9k_crypto_autotest ;;
		cn10*) run_cn10k_crypto_autotest ;;
	esac
}

run_crypto_autotest
