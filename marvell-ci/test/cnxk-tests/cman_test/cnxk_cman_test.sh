#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="cman-config"

TESTPMD_PORT="0002:02:00.0"
TESTPMD_COREMASK="0x3"

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
}

qsize=0
function convert_cman_queue_size_to_val()
{
	if [[ $qsize -eq 0 ]]; then
		qsize=16
	elif [[ $qsize -eq 1 ]]; then
		qsize=64
	elif [[ $qsize -eq 2 ]]; then
		qsize=256
	elif [[ $qsize -eq 3 ]]; then
		qsize=1024 #1K
	elif [[ $qsize -eq 4 ]]; then
		qsize=4096 #4K
	elif [[ $qsize -eq 5 ]]; then
		qsize=16384 #16K
	elif [[ $qsize -eq 6 ]]; then
		qsize=65536 #64K
	elif [[ $qsize -eq 7 ]]; then
		qsize=262144 #256K
	elif [[ $qsize -eq 8 ]]; then
		qsize=1048576 #1M
	else
		echo "invalid queue size $qsize"
	fi
}

function check_cman_queue_config()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	rq_ctx="$debug_dir/nix/rq_ctx"
	cq_ctx="$debug_dir/nix/cq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	if $SUDO test -f "$rq_ctx"; then
		$SUDO echo "$nix_lf 0" > $rq_ctx
		xqe_pass=$(echo "`$SUDO cat $rq_ctx`" | grep "W3: xqe_pass" | awk '{print $3}')
		xqe_drop=$(echo "`$SUDO cat $rq_ctx`" | grep "W3: xqe_drop" | awk '{print $3}')
	else
		echo "$rq_ctx is not available"
		exit 1
	fi

	if $SUDO test -f "$cq_ctx"; then
		$SUDO echo "$nix_lf 0" > $cq_ctx
		qsize=$(echo "`$SUDO cat $cq_ctx`" | grep "qsize" | awk '{print $3}')
	else
		echo "$cq_ctx is not available"
		exit 1
	fi

	convert_cman_queue_size_to_val

	shift_cnt=$(echo $qsize | awk  '{print log($qsize) / log(2)}')

	if [[ $shift_cnt -lt 8 ]]; then
		shift_cnt=0
	else
		shift_cnt=$(($shift_cnt - 8))
	fi

	pass=$(($qsize * $1 / 100))
	drop=$(($qsize * $2 / 100))

	pass=$(($pass >> $shift_cnt))
	drop=$(($drop >> $shift_cnt))

	pass=$((256-$pass))
	drop=$((256-$drop))

	if [[ $xqe_pass -ne $pass ]]; then
		echo "invalid xqe_pass threshold configured on RQ 0"
		exit 1
	fi

	if [[ $drop -ne $xqe_drop ]]; then
		echo "invalid xqe_drop threshold configured on RQ 0"
		exit 1
	fi
}

function check_cman_queue_mempool_config()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	rq_ctx="$debug_dir/nix/rq_ctx"
	aura_ctx="$debug_dir/npa/aura_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
		npa_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $2}' | head -1)
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	if $SUDO test -f "$rq_ctx"; then
		$SUDO echo "$nix_lf 0" > $rq_ctx
		lpb_pool_pass=$(echo "`$SUDO cat $rq_ctx`" | grep "lpb_pool_pass" | awk '{print $3}')
		lpb_pool_drop=$(echo "`$SUDO cat $rq_ctx`" | grep "lpb_pool_drop" | awk '{print $3}')
		lpb_aura=$(echo "`$SUDO cat $rq_ctx`" | grep "W1: lpb_aura" | awk '{print $3}')
		spb_pool_pass=$(echo "`$SUDO cat $rq_ctx`" | grep "spb_pool_pass" | awk '{print $3}')
		spb_pool_drop=$(echo "`$SUDO cat $rq_ctx`" | grep "spb_pool_drop" | awk '{print $3}')
		spb_aura=$(echo "`$SUDO cat $rq_ctx`" | grep "W1: spb_aura" | awk '{print $3}')
		spb_ena=$(echo "`$SUDO cat $rq_ctx`" | grep "spb_ena" | awk '{print $3}')
	else
		echo "$rq_ctx is not available"
		exit 1
	fi

	if $SUDO test -f "$aura_ctx"; then
		if [[ $spb_ena -ne 0 ]]; then
			$SUDO echo "$npa_lf $spb_aura" > $aura_ctx
			shift_cnt=$(echo "`$SUDO cat $aura_ctx`" | grep "shift" | awk '{print $4}')
			limit=$(echo "`$SUDO cat $aura_ctx`" | grep "limit" | awk '{print $3}')

			max=$(($limit >> $shift_cnt))
			pass=$(($limit * $1 / 100))
			drop=$(($limit * $2 / 100))

			pass=$(($pass >> $shift_cnt))
			drop=$(($drop >> $shift_cnt))

			pass=$(($max-$pass))
			drop=$(($max-$drop))

			if [[ $spb_pool_pass -ne $pass ]]; then
				echo "invalid spb_pool_pass threshold configured on RQ 0"
				exit 1
			fi

			if [[ $spb_pool_drop -ne $drop ]]; then
				echo "invalid spb_pool_drop threshold configured on RQ 0"
				exit 1
			fi
		fi

		$SUDO echo "$npa_lf $lpb_aura" > $aura_ctx
		shift_cnt=$(echo "`$SUDO cat $aura_ctx`" | grep "shift" | awk '{print $4}')
		limit=$(echo "`$SUDO cat $aura_ctx`" | grep "limit" | awk '{print $3}')

		max=$(($limit >> $shift_cnt))
		pass=$(($limit * $1 / 100))
		drop=$(($limit * $2 / 100))

		pass=$(($pass >> $shift_cnt))
		drop=$(($drop >> $shift_cnt))

		pass=$(($max-$pass))
		drop=$(($max-$drop))

		if [[ $lpb_pool_pass -ne $pass ]]; then
			echo "invalid lpb_pool_pass threshold configured on RQ 0"
			exit 1
		fi

		if [[ $lpb_pool_drop -ne $drop ]]; then
			echo "invalid lpb_pool_drop threshold configured on RQ 0"
			exit 1
		fi
	else
		echo "$aura_ctx is not available"
		exit 1
	fi
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
	"-c $TESTPMD_COREMASK -a $TESTPMD_PORT" \
	"--no-flush-rx --nb-cores=1"

testpmd_cmd $PRFX "port stop all"
testpmd_cmd $PRFX "set verbose 10"

# Test case - 1: Validate congestion management default configuration
testpmd_cmd $PRFX "set port cman config 0 0 default"
sleep 3
check_cman_queue_config 75 95

# Test case - 2: Validate congestion management configuration for queue mode
testpmd_cmd $PRFX "set port cman config 0 0 obj queue mode red 10 60 1"
sleep 3
check_cman_queue_config 10 60

testpmd_cmd $PRFX "set port cman config 0 0 obj queue mode red 40 90 1"
sleep 3
check_cman_queue_config 40 90

# Test case - 3: Validate congestion management configuration for queue_mempool mode
testpmd_cmd $PRFX "set port cman config 0 0 obj queue_mempool mode red 10 60 1"
sleep 3
check_cman_queue_mempool_config 10 60

testpmd_cmd $PRFX "set port cman config 0 0 obj queue_mempool mode red 40 90 1"
sleep 3
check_cman_queue_mempool_config 40 90

testpmd_cmd $PRFX "port start all"
testpmd_cmd $PRFX "start"

testpmd_log $PRFX

echo "SUCCESS: testpmd cman configuration test suit completed"
