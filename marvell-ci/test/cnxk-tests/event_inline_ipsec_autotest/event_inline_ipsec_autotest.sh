#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

LBK_DEV=${ETH_DEV:-$(lspci -d :a0f8 | head -1 | awk -e '{ print $1 }')}
LBK_DEVICE="$LBK_DEV"

CRYPTO_DEV=${CRYPTO_DEV:-$(lspci -d :a0fe | head -1 | awk -e '{ print $1 }')}
CRYPTO_DEVICE="$CRYPTO_DEV"

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
SSO_DEVICE="$SSO_DEV"

TEST_TYPE=$1
EVENT_INLINE_IPSEC_OUT=event_inline_ipsec_tests.txt

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

declare -A event_inline_ipsec_test_args

register_event_inline_ipsec_test() {
        event_inline_ipsec_test_args[$1]="${2-}"
}

run_event_inline_ipsec_tests() {
	unbuffer="$(command -v stdbuf) -o 0" || unbuffer=
	local in=event_inline_ipsec_in.txt
	local out=event_inline_ipsec_out.txt
	local parse=log_ipsec_parse_out.txt
	itr=0
	touch $in
	rm -rf $parse
	for test in ${!event_inline_ipsec_test_args[@]}; do
		tail -f $in | $unbuffer $DPDK_TEST_BIN \
		${event_inline_ipsec_test_args[$test]} &>$out 2>&1 &
		while ! (tail -n1 $out | grep -q "RTE>>") do
			sleep 0.1
			((itr+=1))
			if [[ itr -eq 1000 ]]
			then
				echo "Timeout waiting for dpdk-test";
				exit 1;
			fi
			continue;
		done
	done
	echo "$test" >>$in
	sleep 10
	echo "quit" >>$in
	sleep 2

	cat $out | grep "failed" > one.txt
	awk '!/soft expiry/' one.txt > two.txt
	awk '!/DSCP 0/' two.txt > three.txt
	awk '!/DSCP 1/' three.txt > $parse
	rm -rf one.txt two.txt three.txt

	while IFS= read -r line
	do
		check=`echo "$line" | awk '{print $NF}'`
		if [ $check == "failed" ]; then
			echo "Evenet inline ipsec autotest failed"
			exit 1
		fi
	done < $parse
	echo "Event inline ipsec autotest success"
}

run_inline_ipsec_tests() {
	case $PLAT in
		cn9*) run_event_inline_ipsec_tests ;;
	esac
}


#					DPDK TEST NAME		TEST ARGS
register_event_inline_ipsec_test	event_inline_ipsec_autotest	"-a $LBK_DEVICE -a $SSO_DEVICE -a $CRYPTO_DEVICE,max_qps_limit=2"

case $TEST_TYPE in
	inline_ipsec_tests)
		run_inline_ipsec_tests
		;;
esac
