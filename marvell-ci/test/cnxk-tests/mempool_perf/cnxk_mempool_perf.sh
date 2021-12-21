#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -e

SUDO=${SUDO:-"sudo"}
TEST_LOG=$(mktemp)
PREFIX="cmpt"
TOLERANCE=${TOLERANCE:-5}
REF_FILE=${REF_FILE:-ref_numbers/cn96xx_rclk2200_sclk1100}
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# Find the cnxk-test application
if [[ -f $SCRIPTPATH/../../../../app/test/dpdk-test ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../app/test/dpdk-test
elif [[ -f $SCRIPTPATH/../../dpdk-test ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-test
else
	DPDK_TEST_BIN=$(command -v dpdk-test)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-test not found !!"
		exit 1
	fi
fi

function kill_dpdk_test()
{
	local test_name="$DPDK_TEST_BIN.*$PREFIX"

	# Issue kill
	$SUDO pkill --signal SIGKILL -f "$test_name" \
		&> /dev/null || true

	# Wait until the process is killed
	sleep 1
	while (pgrep -f "$test_name"); do
		sleep 1
		continue
	done
}

function test_cleanup()
{
	rm -f $TEST_LOG
	kill_dpdk_test
}

trap test_cleanup EXIT

function test_mempool_perf()
{
	local unbuffer="stdbuf -o0"
	local pattern='s/mempool_autotest cache=0 cores=1 n_get_bulk=32 n_put_bulk=32 n_keep=128 rate_persec=([0-9]+)/\1/p'
	local expected
	local result

	expected=$(<$REF_FILE)

	# Run test until expected combination is found
	$SUDO DPDK_TEST=mempool_perf_autotest $unbuffer $DPDK_TEST_BIN \
		--file-prefix $PREFIX &> $TEST_LOG &
	while true; do
		result=$(sed -nr "$pattern" $TEST_LOG | head -n1)
		if [[ -n $result ]]; then
			break;
		fi
		sleep 1
	done
	kill_dpdk_test

	# compare results
	if (( $(echo "$result < ($expected * (100 - $TOLERANCE) / 100)" | bc -l) )); then
		echo "test_mempool_perf failed: result is too low ($result < $expected)"
		exit 1
	fi
	echo "test_mempool_perf passed"
}

test_mempool_perf
