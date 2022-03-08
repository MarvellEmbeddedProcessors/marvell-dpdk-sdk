#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="pktgen"
CAP_PRFX="dut"
TXPORT="0002:01:00.2"
RXPORT="0002:01:00.1"
COREMASK="0xC"
CAP_COREMASK="0x3"

function sig_handler()
{
	local status=$?
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		echo "$1 Handler"
	fi

	testpmd_quit $CAP_PRFX
	testpmd_quit $PRFX
	testpmd_cleanup $CAP_PRFX
	testpmd_cleanup $PRFX
	exit $status
}


function ingress_policer_test()
{
	if [ "$1" == "level_3" ]; then
		testpmd_cmd "add port meter profile srtcm_rfc2697 0 100 1000000000 5000 10000 0"
		testpmd_cmd "add port meter policy 0 200 g_actions void / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 300 100 200 yes 0 0 0"
		testpmd_cmd "add port meter policy 0 201 g_actions meter mtr_id 300 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 301 100 201 yes 0 0 0"
		testpmd_cmd "add port meter policy 0 202 g_actions meter mtr_id 300 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 302 100 202 yes 0 0 0"
		testpmd_cmd "add port meter policy 0 203 g_actions meter mtr_id 301 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 303 100 203 yes 0 0 0"
		testpmd_cmd "add port meter policy 0 204 g_actions meter mtr_id 301 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 304 100 204 yes 0 0 0"
		testpmd_cmd "add port meter policy 0 205 g_actions meter mtr_id 302 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 305 100 205 yes 0 0 0"
		testpmd_cmd "add port meter policy 0 206 g_actions meter mtr_id 302 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 306 100 206 yes 0 0 0"
		testpmd_cmd "flow create 0 ingress pattern eth / end actions meter mtr_id 303 / queue index 0 / end"
		testpmd_cmd "flow create 0 ingress pattern eth / end actions meter mtr_id 304 / queue index 1 / end"
		testpmd_cmd "flow create 0 ingress pattern eth / end actions meter mtr_id 305 / queue index 2 / end"
		testpmd_cmd "flow create 0 ingress pattern eth / end actions meter mtr_id 306 / queue index 3 / end"

	fi

	if [ "$1" == "level_1" ]; then
		testpmd_cmd "add port meter profile srtcm_rfc2697 0 100 1000000000 5000 10000 0"
		testpmd_cmd "add port meter policy 0 200 g_actions void / end y_actions drop / end r_actions drop / end"
		testpmd_cmd "create port meter 0 300 100 200 yes 0 0 0"
		testpmd_cmd "flow create 0 ingress pattern eth / end actions meter mtr_id 300 / queue index 1 / end"
	fi

	testpmd_cmd $CAP_PRFX "port start all"
	testpmd_cmd $CAP_PRFX "start"
	sleep 5
	testpmd_cmd $CAP_PRFX "show port stats all"
	sleep 1
	testpmd_cmd $CAP_PRFX "show port stats all"
	sleep 1
	testpmd_rxbps_stats $CAP_PRFX
}

function testpmd_rxbps_stats()
{
	local prefix=$1
	local out=testpmd.out.$prefix

	val=`cat $out | grep "Rx-bps:" | awk -e '{print $4}' | tail -1`
	if [[ $val -le 8000000000 && $val -ge 7800000000 ]] ;then
		echo "Ingress policy $1 success"
	else
		echo "Ingress policy $1 failed"
		exit 1
	fi
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT


echo "Testpmd running with $PORT0, Coremask=$COREMASK"

testpmd_launch $PRFX \
	"-c $COREMASK -a $TXPORT" \
	"--no-flush-rx --nb-cores=1 --forward-mode=txonly --txonly-multi-flow"

testpmd_cmd $PRFX "start"

# Launch capture testpmd
testpmd_launch $CAP_PRFX \
	"-c $CAP_COREMASK -a $RXPORT" \
        "--no-flush-rx --nb-cores=1 --forward-mode=rxonly"

echo "Ingress policer with 4 leaf nodes 2 mid nodes 1 root node"
ingress_policer_test level_3
echo "Ingress policer with single node"
ingress_policer_test level_1
