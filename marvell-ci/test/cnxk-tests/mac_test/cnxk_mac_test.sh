#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="mac-test"
PORT0="0002:01:00.1"
PORT1="0002:02:00.0"
COREMASK="0xC"
OFF=0

UCAST_MAC="02:00:00:00:00:01"
MCAST_MAC="01:00:5E:01:01:01"

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

if [ -f $1/marvell-ci/test/board/oxk-devbind-basic.sh ]
then
	VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
	if [[ -z $VFIO_DEVBIND ]]; then
		echo "oxk-devbind-basic.sh not found !!"
		exit 1
	fi
fi

#Bind port 1
$VFIO_DEVBIND -b vfio-pci $PORT1

function cleanup_interface()
{
	$VFIO_DEVBIND -b $NICVF $PORT1
}

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

	testpmd_quit $PRFX
	testpmd_cleanup $PRFX
	cleanup_interface
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

function get_new_mac()
{
	ADDR=$(( 0x$TEST_MAC + $1 ))
	ADDR=$(printf "%012x" $ADDR | sed 's/../&:/g;s/:$//')
	echo $ADDR
}

function get_mac()
{
	testpmd_cmd $PRFX "show device info $PORT0"
	sleep 1
	val=`testpmd_log $PRFX | tail -7 | grep -a "MAC address: "| \
		cut --complement -f 1 -d ":"`
	echo $val
}

echo "Testpmd running with $PORT0 and $PORT1, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0 -a $PORT1" \
	"--nb-cores=1 --rxq 1 --txq 1"

DEF_MAC=`get_mac`

testpmd_cmd $PRFX "mac_addr set 0 $UCAST_MAC"
NEW_MAC=`get_mac`

if [[ "$NEW_MAC" == "$UCAST_MAC" ]]
then
	echo "MAC address set successful"
else
	echo "MAC address set failure"
	exit 1
fi

#Set back original MAC
testpmd_cmd $PRFX "mac_addr set 0 $DEF_MAC"

#Add 31 MAC addresses, 1 MAC is already set as default
mac=0
TEST_MAC=$(echo $UCAST_MAC | tr -d ':')
while [ $mac -lt 31 ]
do
	ADDR=`get_new_mac $mac`
	testpmd_cmd $PRFX "mac_addr add 1 $ADDR"
	mac=`expr $mac + 1`
done

testpmd_cmd $PRFX "show port 1 macs"
sleep 1
CNT=`testpmd_log $PRFX | tail -34 | grep -a "Number of MAC address added: "| \
	cut --complement -f 1 -d ":"`
if [[ $CNT -gt 1 ]]
then
	echo "Total $CNT MAC addresses add successful"
else
	echo "Total $CNT MAC addresses add failure"
	exit 1
fi

#Remove last 31 MAC addresses from the list
mac=0
while [ $mac -lt 31 ]
do
	ADDR=`get_new_mac $mac`
	testpmd_cmd $PRFX "mac_addr remove 1 $ADDR"
	mac=`expr $mac + 1`
done

testpmd_cmd $PRFX "show port 1 macs"
sleep 1
CNT=`testpmd_log $PRFX | tail -34 | grep -a "Number of MAC address added: "| \
	cut --complement -f 1 -d ":"`
if [[ $CNT -eq 1 ]]
then
	echo "MAC addresses remove successful"
else
	echo "MAC address remove failure"
	exit 1
fi

testpmd_cmd $PRFX "set allmulti all on"
testpmd_cmd $PRFX "set allmulti all off"

#Add multicast addresses
mac=0
TEST_MAC=$(echo $MCAST_MAC | tr -d ':')
while [ $mac -lt 31 ]
do
	ADDR=`get_new_mac $mac`
	testpmd_cmd $PRFX "mcast_addr add 1 $ADDR"
	mac=`expr $mac + 1`
done

testpmd_cmd $PRFX "show port 1 mcast_macs"
sleep 1
CNT=`testpmd_log $PRFX | tail -34 | grep -a "Multicast MAC address added: "| \
	cut --complement -f 1 -d ":"`
if [[ $CNT -gt 1 ]]
then
	echo "Total $CNT multicast MAC addresses add successful"
else
	echo "Total $CNT multicast MAC addresses add failure"
	exit 1
fi

#Remove last 32 multicast MAC addresses from the list
mac=0
while [ $mac -lt 31 ]
do
	ADDR=`get_new_mac $mac`
	testpmd_cmd $PRFX "mcast_addr remove 1 $ADDR"
	mac=`expr $mac + 1`
done

testpmd_cmd $PRFX "show port 1 mcast_macs"
sleep 1
CNT=`testpmd_log $PRFX | tail -34 | grep -a "Multicast MAC address added: "| \
	cut --complement -f 1 -d ":"`
if [[ $CNT -eq 0 ]]
then
	echo "Multicast MAC addresses remove successful"
else
	echo "Multicast MAC addresses remove failure"
	exit 1
fi

#Dump logs till now
testpmd_log_off $PRFX $OFF
OFF=`testpmd_log_sz $PRFX`

#Close after all tests
testpmd_quit $PRFX
testpmd_cleanup $PRFX
#Bind interface back to kernel
cleanup_interface

echo "SUCCESS: testpmd mac test completed"
