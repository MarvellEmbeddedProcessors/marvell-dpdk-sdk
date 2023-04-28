#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="fc-config"
PRFX_VF="vf_fc-config"

TESTPMD_PORT="0002:02:00.0"
TESTPMD_VF_PORT="0002:02:00.1"
TESTPMD_COREMASK="0xfff"

if [ -f $CNXKTESTPATH/../board/oxk-devbind-basic.sh ]
then
	VFIO_DEVBIND="$CNXKTESTPATH/../board/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
	if [[ -z $VFIO_DEVBIND ]]; then
		echo "oxk-devbind-basic.sh not found !!"
		exit 1
	fi
fi

function bind_interface()
{
	echo "port $TESTPMD_PORT is bound to VFIO"
	$VFIO_DEVBIND -b vfio-pci $TESTPMD_PORT
	echo 1 > /sys/bus/pci/devices/$TESTPMD_PORT/sriov_numvfs
	sleep 1
}

function check_fc_state()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	cq_ctx="$debug_dir/nix/cq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	if $SUDO test -f "$cq_ctx"; then
		$SUDO echo "$nix_lf 0" > $cq_ctx
		bp_ena=$(echo "`$SUDO cat $cq_ctx`" | grep "bp_ena" | awk '{print $3}')
	else
		echo "$cq_ctx is not available"
		exit 1
	fi

	if [[ $bp_ena -ne $1 ]]; then
		echo "flow control validation failed."
		exit 1
	fi
}

function check_pfc_state()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	cq_id=0
	cq_ctx="$debug_dir/nix/cq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	while [[ $cq_id -ne 8 ]]; do
		if $SUDO test -f "$cq_ctx"; then
			$SUDO echo "$nix_lf $cq_id" > $cq_ctx
			bp_ena=$(echo "`$SUDO cat $cq_ctx`" | grep "bp_ena" | awk '{print $3}')
		else
			echo "$cq_ctx is not available"
			exit 1
		fi

		if [[ $bp_ena -ne $1 ]]; then
			echo "priority flow control validation failed."
			exit 1
		fi

		cq_id=`expr $cq_id + 1`
	done
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

	testpmd_cleanup $PRFX
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

bind_interface

echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
	"-c $TESTPMD_COREMASK -a $TESTPMD_PORT,flow_max_priority=8" \
	"--no-flush-rx --rxq=8 --txq=8 --nb-cores=8"

# Part - 1: Validate priority flow control (802.3x)
# Test case - 1: Validate flow control default configuration. Must be enable
check_fc_state 1

testpmd_cmd $PRFX "port stop all"
# Test case - 2: Validate flow control configuration after disabling
testpmd_cmd $PRFX "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
sleep 3
check_fc_state 0

# Test case - 3: Validate flow control configuration after re-enable
testpmd_cmd $PRFX "set flow_ctrl rx on tx on 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
sleep 3
check_fc_state 1

# Part - 2: Validate priority flow control (802.1Qbb)
# Test case - 4: Validate priority flow control
testpmd_cmd $PRFX "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
sleep 1

testpmd_cmd $PRFX "flow create 0 priority 7 ingress pattern vlan pcp is 0 / end actions queue index 0 / end"
sleep 1
testpmd_cmd $PRFX "flow create 0 priority 6 ingress pattern vlan pcp is 1 / end actions queue index 1 / end"
sleep 1
testpmd_cmd $PRFX "flow create 0 priority 5 ingress pattern vlan pcp is 2 / end actions queue index 2 / end"
sleep 1
testpmd_cmd $PRFX "flow create 0 priority 4 ingress pattern vlan pcp is 3 / end actions queue index 3 / end"
sleep 1
testpmd_cmd $PRFX "flow create 0 priority 3 ingress pattern vlan pcp is 4 / end actions queue index 4 / end"
sleep 1
testpmd_cmd $PRFX "flow create 0 priority 2 ingress pattern vlan pcp is 5 / end actions queue index 5 / end"
sleep 1
testpmd_cmd $PRFX "flow create 0 priority 1 ingress pattern vlan pcp is 6 / end actions queue index 6 / end"
sleep 1
testpmd_cmd $PRFX "flow create 0 priority 0 ingress pattern vlan pcp is 7 / end actions queue index 7 / end"
sleep 1

testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 0 0 tx on 0 0 2047"
sleep 1
testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 1 1 tx on 1 1 2047"
sleep 1
testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 2 2 tx on 2 2 2047"
sleep 1
testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 3 3 tx on 3 3 2047"
sleep 1
testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 4 4 tx on 4 4 2047"
sleep 1
testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 5 5 tx on 5 5 2047"
sleep 1
testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 6 6 tx on 6 6 2047"
sleep 1
testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 7 7 tx on 7 7 2047"
sleep 1

testpmd_cmd $PRFX "port start all"
testpmd_cmd $PRFX "start"
sleep 1

check_pfc_state 1

testpmd_quit $PRFX
sleep 1
testpmd_cleanup $PRFX
sleep 1

testpmd_log $PRFX

echo "SUCCESS: testpmd flow control configuration test suit completed"

function verify_fc_state()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	cq_ctx="$debug_dir/nix/cq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		if [ $1 == "pf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
		fi
		if [ $1 == "vf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1:VF0" | awk '{print $3}' | head -1)
		fi
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	if $SUDO test -f "$cq_ctx"; then
		$SUDO echo "$nix_lf 0" > $cq_ctx
		bp_ena=$(echo "`$SUDO cat $cq_ctx`" | grep "bp_ena" | awk '{print $3}')
	else
		echo "$cq_ctx is not available"
		exit 1
	fi

	if [[ $bp_ena -ne $2 ]]; then
		echo "flow control validation failed."
		exit 1
	fi
}

function verify_pfc_state()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	cq_id=0
	cq_ctx="$debug_dir/nix/cq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		if [ $1 == "pf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
		fi
		if [ $1 == "vf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1:VF0" | awk '{print $3}' | head -1)
		fi
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	if $SUDO test -f "$cq_ctx"; then
		$SUDO echo "$nix_lf $cq_id" > $cq_ctx
		bp_ena=$(echo "`$SUDO cat $cq_ctx`" | grep "bp_ena" | awk '{print $3}')
	else
		echo "$cq_ctx is not available"
		exit 1
	fi

	if [[ $bp_ena -ne $2 ]]; then
		echo "priority flow control validation failed."
		exit 1
	fi
}

function stop_testpmd()
{
	testpmd_quit $PRFX_VF
	sleep 1
	testpmd_cleanup $PRFX_VF
	sleep 3
	testpmd_quit $PRFX
	sleep 1
	testpmd_cleanup $PRFX
	sleep 1
}

function configure_fc()
{
	testpmd_cmd $PRFX "set flow_ctrl rx on tx on 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
	testpmd_cmd $PRFX_VF "set flow_ctrl rx on tx on 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
	verify_fc_state pf 1
	sleep 1
	verify_fc_state vf 1
	sleep 1
	echo "PF and VF flow control configuration Success"
}

function configure_pfc()
{
	testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 0 0 tx on 0 0 2047"
	sleep 1
	testpmd_cmd $PRFX_VF "set pfc_queue_ctrl 0 rx on 0 0 tx on 0 0 2047"
	sleep 1
	verify_pfc_state pf 1
	sleep 1
	verify_pfc_state vf 1
	sleep 1
	echo "PF and VF Priority flow control configuration Success"
}

function configure_pf_vf()
{
	echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
	testpmd_launch $PRFX \
		"-c $TESTPMD_COREMASK -a $TESTPMD_PORT,flow_max_priority=8 \
		--vfio-vf-token=b9d20911-e43f-4115-83f5-dfa0181277fb --file-prefix=pf" \
		"--no-flush-rx --rxq=1 --txq=1 --nb-cores=1"
	sleep 1
	testpmd_cmd $PRFX "port stop all"
	sleep 1
	testpmd_cmd $PRFX "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
	echo "Testpmd running with $TESTPMD_VF_PORT, Coremask=$TESTPMD_COREMASK"
	testpmd_launch $PRFX_VF \
		"-c $TESTPMD_COREMASK -a $TESTPMD_VF_PORT,flow_max_priority=8 \
		--vfio-vf-token=b9d20911-e43f-4115-83f5-dfa0181277fb --file-prefix=vf" \
		"--no-flush-rx --rxq=1 --txq=1 --nb-cores=1"
	testpmd_cmd $PRFX_VF "port stop all"
	sleep 1
	testpmd_cmd $PRFX_VF "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
}

function configure_pf_dpdk()
{
	set +x
	echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
	testpmd_launch $PRFX \
		"-c $TESTPMD_COREMASK -a $TESTPMD_PORT,flow_max_priority=8 \
		--vfio-vf-token=b9d20911-e43f-4115-83f5-dfa0181277fb --file-prefix=pf" \
		"--no-flush-rx --rxq=1 --txq=1 --nb-cores=1"
	sleep 1
	testpmd_cmd $PRFX "port stop all"
	sleep 1
	testpmd_cmd $PRFX "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1


	echo $TESTPMD_VF_PORT > /sys/bus/pci/devices/$TESTPMD_VF_PORT/driver/unbind
	sleep 2
	echo rvu_nicvf > /sys/bus/pci/devices/$TESTPMD_VF_PORT/driver_override
	sleep 2
	echo $TESTPMD_VF_PORT > /sys/bus/pci/drivers/rvu_nicvf/bind
	sleep 2
}

function configure_fc_dpdk_kernel()
{
	local intf=`ls /sys/bus/pci/devices/$TESTPMD_VF_PORT/net/`
	local status

	testpmd_cmd $PRFX "set flow_ctrl rx on tx on 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
	verify_fc_state pf 1
	sleep 2
	status=`ethtool -a $intf | grep RX | awk '{print $2}'`
	if [[ $status == "on" ]]; then
		echo "flow control validation success."
	else
		echo "flow control validation failed."
		exit 1;
	fi
}

echo "Starting PFC & FC Test for PF and VF with DPDK"

configure_pf_vf

configure_fc

stop_testpmd

configure_pf_vf

configure_pfc

stop_testpmd

echo "Starting FC Test for PF DPDK and VF with kernel"
configure_pf_dpdk

configure_fc_dpdk_kernel

testpmd_quit $PRFX
sleep 1
testpmd_cleanup $PRFX

