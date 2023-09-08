#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -ou pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

NIX_INL_DEV=${NIX_INL_DEV:-$(lspci -d :a0f0 | tail -1 | awk -e '{ print $1 }')}
NIX_INL_DEVICE="$NIX_INL_DEV"

ETH_DEV=${ETH_DEV:-$(lspci -d :a0f8 | head -1 | awk -e '{ print $1 }')}
ETHERNET_DEVICE="$ETH_DEV"

CRYPTO_DEV=${CRYPTO_DEV:-$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')}
CRYPTO_DEVICE="$CRYPTO_DEV"

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_DEVICE="$SSO_DEV"

TEST_TYPE=$1

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

declare -A cn10k_inline_ipsec_test_args

register_cn10k_inline_ipsec_test() {
        cn10k_inline_ipsec_test_args[$1]="${2-}"
}

run_cn10k_inline_ipsec_tests() {
	unbuffer="$(command -v stdbuf) -o 0" || unbuffer=
	local out=ipsec_out.txt
	local parse=log_ipsec_parse_out.txt
	for test in ${!cn10k_inline_ipsec_test_args[@]}; do
		DPDK_TEST=$test $unbuffer $DPDK_TEST_BIN ${cn10k_inline_ipsec_test_args[$test]} >$out 2>&1
		cat $out
		cat $out | grep "failed" > temp.txt
		awk '!/failed:/' temp.txt > $parse
		if [[ $test == "event_inline_ipsec_autotest" ]]; then
			awk '!/Inbound Out-Of-Place processing failed/' $parse > $parse
		fi
		rm -rf temp.txt
	done
	count=`grep -c "failed" $parse`
	if [[ $count -ne 0 ]]; then
		exit 1;
	fi
}

run_inline_ipsec_tests() {
	case $PLAT in
		cn10*) run_cn10k_inline_ipsec_tests ;;
	esac
}

#					DPDK TEST NAME		TEST ARGS
register_cn10k_inline_ipsec_test	inline_ipsec_autotest	"-a $ETHERNET_DEVICE -a $NIX_INL_DEVICE -a $CRYPTO_DEVICE"
register_cn10k_inline_ipsec_test	event_inline_ipsec_autotest	"-a $ETHERNET_DEVICE -a $NIX_INL_DEVICE -a $CRYPTO_DEVICE -a $EVENT_DEVICE"

case $TEST_TYPE in
	inline_ipsec_tests)
		run_inline_ipsec_tests
		;;
esac
