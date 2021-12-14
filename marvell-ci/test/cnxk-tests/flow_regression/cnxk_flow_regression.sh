#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

#set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
PRFX="rte_flow_regr"

source $CNXKTESTPATH/common/testpmd/pktgen.env
source $CNXKTESTPATH/common/testpmd/lbk.env
source $CNXKTESTPATH/common/pcap/pcap.env

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

	testpmd_cleanup $PRFX
	pktgen_cleanup
	exit $status
}

PKTGEN_PORT="0002:01:00.1"
PKTGEN_COREMASK="0x5"
TESTPMD_PORT="0002:01:00.2"
TESTPMD_COREMASK="0x3"
PKTGEN_OUTPCAP="out.pcap"

#trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

function pktgen_send_flow()
{
	local pcapfile=$1

	echo "Starting pktgen with Port=$PKTGEN_PORT, Coremask=$PKTGEN_COREMASK, Pcap=$pcapfile"
	pktgen_launch -c $PKTGEN_COREMASK -p $PKTGEN_PORT -i $pcapfile
	pktgen_start

	sleep 3

	pktgen_stats > /dev/null
	echo "-------------------------PKTGEN LOG-----------------------------"
	pktgen_log
}

function testpmd_check_hits()
{
	local prefix=$1
	local out=testpmd.out.$prefix

	testpmd_cmd $prefix "flow query 0 0 count"

	testpmd_prompt $prefix
	COUNT=`cat $out | tail -n4 | grep "hits:" | cut -d':' -f2`

	echo -e "hit count:$COUNT \n"

	if [[ "$COUNT" -gt "0" ]]; then
		return 0
	fi

	return -1
}

function testpmd_test_flow()
{
	local prefix=$1
	local name=$2
	local flow=$3
	local pcapfile=$4
	local in=testpmd.in.$prefix
	echo "$cmd" >> $in
	testpmd_prompt $prefix

	#Add rule
	testpmd_cmd $prefix "$flow"

	testpmd_cmd $prefix "start"

	pktgen_send_flow $pcapfile

	sleep 3

	pktgen_quit
	pktgen_cleanup

	echo "-------------------------TESTPMD LOG-----------------------------"
	testpmd_cmd $PRFX "show port stats all"
	testpmd_log $prefix

	if testpmd_check_hits $1; then
		echo "$name passed"
		#Delete rule
		testpmd_cmd $prefix "flow destroy 0 rule 0"
		return 0
	else
		echo "$name failed"
		exit -1
	fi
}

echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
		" -c $TESTPMD_COREMASK -a $TESTPMD_PORT" \
		" --no-flush-rx --nb-cores=1 --rxq 8 --txq 8"

testpmd_test_flow $PRFX FLOW_ETH "flow create 0 ingress pattern eth dst is \
 aa:bb:cc:dd:ee:ff / end actions queue index 3 / \
 count / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_VLAN "flow create 0 ingress pattern vlan \
 vid is 0x123 inner_type is 0x800 / end actions queue index 3 / count \
 / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_2VLAN "flow create 0 ingress pattern vlan \
 vid is 0x123 / vlan / end actions queue index 4 / count / end" \
 "pcap/eth_qinq_ipv4_udp.pcap"

testpmd_test_flow $PRFX FLOW_IPV4_1 "flow create 0 ingress pattern ipv4 src \
 is 10.11.12.13 / end actions queue index 1 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_IPV4_2 "flow create 0 ingress pattern ipv4 src \
 is 10.11.12.13 dst is 10.10.10.10 tos is 4 / end actions queue index 1 / \
 count / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_IPV6 "flow create 0 ingress pattern ipv6 tc is \
 123 hop is 5 proto is 6 flow is 700 / end actions queue index 5 / count / \
 end" "pcap/eth_vlan_ipv6_tcp.pcap"

testpmd_test_flow $PRFX FLOW_TCP "flow create 0 ingress pattern tcp src is \
 0x345 / end actions queue index 1 / count / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_UDP "flow create 0 ingress pattern udp src is \
 0x345 / end actions queue index 2 / count / end" "pcap/eth_vlan_ipv4_udp.pcap"

testpmd_test_flow $PRFX FLOW_ALL "flow create 0 ingress pattern eth dst is \
 aa:bb:cc:dd:ee:ff  type is 0x800 / ipv4 src is 10.11.12.13 dst is 10.10.10.10 \
 tos is 4 / tcp src is 0x345 / end actions queue index 1 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_LTYPE_TEST1 "flow create 0 ingress pattern eth / \
 vlan / ipv4 / udp / end actions queue index 2 / count / end" \
 "pcap/eth_vlan_ipv4_udp.pcap"

testpmd_test_flow $PRFX FLOW_LTYPE_TEST2 "flow create 0 ingress pattern eth / \
 vlan / ipv4 / tcp / end actions queue index 2 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_LTYPE_TEST3 "flow create 0 ingress pattern eth / \
 vlan / ipv6 / tcp / end actions queue index 2 / count / end" \
 "pcap/eth_vlan_ipv6_tcp.pcap"

testpmd_quit  $PRFX

echo "SUCCESS: flow regression tests completed"
exit 0
