#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

MEMPOOL_DEVICE=$(lspci -d :a0fb | tail -1 | awk -e '{ print $1 }')

NIX_INL_DEV=${NIX_INL_DEV:-$(lspci -d :a0f0 | tail -1 | awk -e '{ print $1 }')}
NIX_INL_DEVICE="$NIX_INL_DEV"

ETH_DEV=${ETH_DEV:-$(lspci -d :a0f8 | head -1 | awk -e '{ print $1 }')}
ETHERNET_DEVICE="$ETH_DEV"

CRYPTO_DEV=${CRYPTO_DEV:-$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')}
CRYPTO_DEVICE="$CRYPTO_DEV"

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_DEVICE="$SSO_DEV"

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

declare -A t106_mode_test_args

! $(cat /sys/bus/pci/devices/0002:20:00.0/revision | grep -q "0x54")
IS_CN10K_B0=$?

register_t106_mode_test() {
        t106_mode_test_args[$1]="${2-}"
}

run_t106_mode_tests() {
	echo 0 >/sys/bus/pci/devices/0002\:20\:00.0/sriov_numvfs
	echo "0002:20:00.0" > /sys/bus/pci/drivers/rvu_cptpf/unbind
	echo "0002:20:00.0" > /sys/bus/pci/drivers/rvu_cptpf/bind
	devlink dev param set pci/0002:20:00.0 name t106_mode value 1 cmode runtime
	echo 1 >/sys/bus/pci/devices/0002\:20\:00.0/sriov_numvfs
	dmesg | grep "OCPT-04"

	echo "177d a0f3" > /sys/bus/pci/drivers/vfio-pci/new_id
	echo "0002:20:00.1" > /sys/bus/pci/devices/0002\:20\:00.1/driver/unbind
	echo "0002:20:00.1" > /sys/bus/pci/drivers/vfio-pci/bind

	for test in ${!t106_mode_test_args[@]}; do
		DPDK_TEST=$test $DPDK_TEST_BIN ${t106_mode_test_args[$test]}
	done

	echo "Restoring the CPT firmware to CPT05"
	echo 0 >/sys/bus/pci/devices/0002\:20\:00.0/sriov_numvfs
	echo "0002:20:00.0" > /sys/bus/pci/drivers/rvu_cptpf/unbind
	echo "0002:20:00.0" > /sys/bus/pci/drivers/rvu_cptpf/bind
	devlink dev param set pci/0002:20:00.0 name t106_mode value 0 cmode runtime
	echo 1 >/sys/bus/pci/devices/0002\:20\:00.0/sriov_numvfs
}

#					DPDK TEST NAME		TEST ARGS
register_t106_mode_test		inline_ipsec_autotest	"-a $ETHERNET_DEVICE -a $NIX_INL_DEVICE -a $CRYPTO_DEVICE"
register_t106_mode_test		event_inline_ipsec_autotest	"-a $ETHERNET_DEVICE -a $NIX_INL_DEVICE -a $CRYPTO_DEVICE -a $EVENT_DEVICE"
register_t106_mode_test		cryptodev_cn10k_autotest	"-a $CRYPTO_DEVICE,max_qps_limit=4 -a $MEMPOOL_DEVICE --log-level=7"
register_t106_mode_test		cryptodev_cn10k_asym_autotest	"-a $CRYPTO_DEVICE,max_qps_limit=4 -a $MEMPOOL_DEVICE --log-level=7"

if [[ $IS_CN10K_B0 -ne 0 ]]
then
	run_t106_mode_tests
else
	echo "Skipped the test as it is not CN10K B0 chip"
fi
