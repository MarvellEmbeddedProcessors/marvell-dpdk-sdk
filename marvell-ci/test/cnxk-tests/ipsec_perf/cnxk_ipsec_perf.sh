#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
PKT_LIST="64 380 1410"
NUM_CAPTURE=3
MAX_TRY_CNT=5
CORES=(1)
COREMASK="0x10000"
NUM_MODES=3
TXWAIT=15
RXWAIT=5
WS=2

source $CNXKTESTPATH/../common/testpmd/pktgen.env
source $CNXKTESTPATH/../common/testpmd/lbk.env
source $CNXKTESTPATH/../common/testpmd/common.env

IPSEC_PREFIX="ipsec_dpdk"
TPMD_RX_PREFIX="tpmd_rx"
TPMD_TX_PREFIX="tpmd_tx"

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A PASS_PPS_TABLE

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

if [[ $IS_CN10K -ne 0 ]]; then
	HW="106xx"
	CDEV_VF=$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')
	INLINE_DEV=0002:1d:00.0
else
	# Get CPU PART NUMBER
	PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')
	if [[ $PARTNUM == $PARTNUM_98XX ]]; then
		HW="98xx"
	else
		HW="96xx"
	fi
	CDEV_VF=$(lspci -d :a0fe | head -1 | awk -e '{ print $1 }')
fi

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

# Find the dpdk-ipsec-secgw application
if [[ -f $CNXKTESTPATH/../../../../examples/dpdk-ipsec-secgw ]]; then
	# This is running from build directory
	IPSECGW_BIN=$CNXKTESTPATH/../../../../examples/dpdk-ipsec-secgw
elif [[ -f $CNXKTESTPATH/../../dpdk-ipsec-secgw ]]; then
	# This is running from install directory
	IPSECGW_BIN=$CNXKTESTPATH/../../dpdk-ipsec-secgw
else
	IPSECGW_BIN=$(which dpdk-ipsec-secgw)
	if [[ -z $IPSECGW_BIN ]]; then
		echo "dpdk-ipsec-secgw not found !!"
		exit 1
	fi
fi

CFG=(
	"ep0_lookaside_crypto.cfg"
	"ep0_lookaside_protocol.cfg"
	"ep0_inline_protocol.cfg"
)

TYPE=(
	"lc"
	"lp"
	"ip"
)

TN=(
	"Lookaside Crypto"
	"Lookaside Protocol"
	"Inline Protocol"
)

function get_system_info()
{
	local sysclk_dir
	local fp_rclk
	local fp_sclk
	local fp_cptclk
	local div=1000000

	sysclk_dir="/sys/kernel/debug/clk"
if [[ $IS_CN10K -ne 0 ]]; then
	fp_rclk="$sysclk_dir/coreclk/clk_rate"
else
	fp_rclk="$sysclk_dir/rclk/clk_rate"
	fp_cptclk="$sysclk_dir/cptclk/clk_rate"
fi
	fp_sclk="$sysclk_dir/sclk/clk_rate"

	if $SUDO test -f "$fp_rclk"; then
		RCLK=$(echo "`$SUDO cat $fp_rclk` / $div" | bc)
	else
		echo "$fp_rclk not available"
		exit 1
	fi

	if $SUDO test -f "$fp_sclk"; then
		SCLK=$(echo "`$SUDO cat $fp_sclk` / $div" | bc)
	else
		echo "$fp_sclk not available"
		exit 1
	fi

if [[ $IS_CN10K -ne 0 ]]; then
	echo "CORECLK:   $RCLK Mhz"
	echo "SCLK:      $SCLK Mhz"
	return
fi
	if $SUDO test -f "$fp_cptclk"; then
		CPTCLK=$(echo "`$SUDO cat $fp_cptclk` / $div" | bc)
	else
		echo "$fp_cptclk not available"
		exit 1
	fi

	echo "RCLK:   $RCLK Mhz"
	echo "SCLK:   $SCLK Mhz"
	echo "CPTCLK: $CPTCLK Mhz"
}

function run_test()
{
	local cmd=$1
	eval "nohup $1 >> $IPSEC_LOG 2>&1 &"
	PT1="IPSEC: entering main loop on lcore"
	PT2="IPSEC: Launching event mode worker"

	local itr=0
	while ! (cat $IPSEC_LOG | grep -q -e "$PT1" -e "$PT2")
	do
		sleep 1
		((itr+=1))

		if [[ $itr -eq 100 ]]
		then
			echo "Timeout waiting for IPSEC main loop"
			exit 2
		fi

		if [[ $((itr%5)) -eq 0 ]]
		then echo "Waiting for IPSEC main loop"; fi
	done
}

function run_ipsec_secgw()
{
	local config="(0,0,16),(1,0,16)"

	echo "ipsec-secgw outb"
	if [[ $Y -eq 2 ]]; then
		if [[ $IS_CN10K -ne 0 ]]; then
			run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
		else
			run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
		fi
	else
		run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -f ${CFG[$Y]} --config=$config'
	fi
	sleep $WS
}

function run_ipsec_secgw_inb()
{
	local config="(0,0,16),(1,0,16)"

	echo "ipsec-secgw inb"

	if [[ $Y -eq 2 ]]; then
		if [[ $IS_CN10K -ne 0 ]]; then
			run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x1 -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
		else
			run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x1 -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
		fi
	else
		run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x1 -f ${CFG[$Y]} --config=$config'
	fi
	sleep $WS
}

function ipsec_exit()
{
	killall dpdk-ipsec-secgw
	# Wait until the process is killed
	while (ps -ef | grep dpdk-ipsec-secgw | grep -q $IPSEC_PREFIX); do
		continue
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
		ipsec_exit
		testpmd_quit "$TPMD_TX_PREFIX"
		testpmd_quit "$TPMD_RX_PREFIX"
		awk ' { print FILENAME": " $0 } ' $IPSEC_LOG
		awk ' { print FILENAME": " $0 } ' testpmd.in.$TPMD_TX_PREFIX
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_TX_PREFIX
		awk ' { print FILENAME": " $0 } ' testpmd.in.$TPMD_RX_PREFIX
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_RX_PREFIX
	fi
	cleanup_interfaces
	exit $status
}

function pmd_tx_launch()
{
	testpmd_launch "$TPMD_TX_PREFIX" \
		"-c 0x3800 -a $LIF1" \
		"--nb-cores=2 --forward-mode=txonly --tx-ip=192.168.$X.1,192.168.$X.2"
}

function pmd_tx_launch_for_inb()
{
	testpmd_launch "$TPMD_TX_PREFIX" \
	"-c 0x3800 --vdev net_pcap0,rx_pcap=$CNXKTESTPATH/pcap/enc_$1_$2.pcap,infinite_rx=1 -a $LIF1" \
	"--nb-cores=2 --no-flush-rx"
}

function pmd_rx_launch()
{
	testpmd_launch "$TPMD_RX_PREFIX" \
		"-c 0x700 -a $LIF4" \
		"--nb-cores=2 --forward-mode=rxonly"
}

function pmd_rx_dry_run()
{
	local prefix=$1
	local port=$2
	local in=testpmd.in.$prefix

	echo "show port stats $port" >> $in
	testpmd_prompt $prefix
}

function rx_stats()
{
	local prefix=$1
	local port=$2
	local in=testpmd.in.$prefix
	local out=testpmd.out.$prefix

	echo "show port stats $port" >> $in
	testpmd_prompt $prefix
	cat $out | tail -n4 | head -n1
}

function capture_rx_pps()
{
	local stats
	stats=$(rx_stats "$TPMD_RX_PREFIX" "0")
	echo $stats | awk '{print $2}'
}

# Configure interfaces
function setup_interfaces()
{
	echo -e "dev bind $LIF1 $LIF2 $LIF3 $LIF4"

	$VFIO_DEVBIND -b vfio-pci $LIF1
	$VFIO_DEVBIND -b vfio-pci $LIF2
	$VFIO_DEVBIND -b vfio-pci $LIF3
	$VFIO_DEVBIND -b vfio-pci $LIF4
}

function cleanup_interfaces()
{
	# Bind the vfio-pci binded devices back to nicvf
	$VFIO_DEVBIND -b $NICVF $LIF1
	$VFIO_DEVBIND -b $NICVF $LIF2
	$VFIO_DEVBIND -b $NICVF $LIF3
	$VFIO_DEVBIND -b $NICVF $LIF4
}

function stop_testpmd()
{
	testpmd_cmd "$TPMD_TX_PREFIX" "stop"
	testpmd_cmd "$TPMD_RX_PREFIX" "stop"
}

function outb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local rn
	local i

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		testpmd_cmd "$TPMD_TX_PREFIX" "set txpkts $pktsz"

		tcnt=1
		while [ $tcnt -le $MAX_TRY_CNT ]; do
			echo "Try $tcnt"
			i=1
			rx_pps=0
			if [[ $tcnt -gt 1 ]]; then
				# Restart ipsec-secgw
				ipsec_exit
				sleep $WS
				echo "Restart ipsec-secgw"
				run_ipsec_secgw
			fi
			testpmd_cmd "$TPMD_RX_PREFIX" "start"
			testpmd_cmd "$TPMD_TX_PREFIX" "start"
			pmd_rx_dry_run "$TPMD_RX_PREFIX" "0"
			# Wait for few seconds for traffic to stabilize
			sleep $TXWAIT
			while [ $i -le $NUM_CAPTURE ]; do
				rx_pps=$rx_pps+$(capture_rx_pps)
				((++i))
				sleep $RXWAIT
			done
			stop_testpmd
			avg_pps=$(echo "(($rx_pps) / $NUM_CAPTURE)" | bc)
			p=${PASS_PPS_TABLE[$rn,$2]}
			echo "pktsize: $pktsz avg_pps: $avg_pps"
			echo "pass_pps $p"
			if (( $(echo "$avg_pps < $p" | bc) )); then
				echo "$1:Low numbers for packet size $pktsz " \
					"($avg_pps < $p) for $3 cores">&2
			else
				echo "Test Passed"
				break
			fi
			((++tcnt))
			sleep $WS
		done
		if [[ $tcnt -gt $MAX_TRY_CNT ]]; then
			echo "Test Failed"
			exit 1
		fi
		((++rn))
	done
}

function inb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local rn
	local i

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		sleep $WS
		pmd_tx_launch_for_inb $1 $pktsz

		tcnt=1
		while [ $tcnt -le $MAX_TRY_CNT ]; do
			echo "Try $tcnt"
			i=1
			rx_pps=0
			if [[ $tcnt -gt 1 ]]; then
				# Restart ipsec-secgw
				ipsec_exit
				sleep $WS
				echo "Restart ipsec-secgw"
				run_ipsec_secgw_inb
			fi
			testpmd_cmd "$TPMD_RX_PREFIX" "start"
			testpmd_cmd "$TPMD_TX_PREFIX" "start"
			pmd_rx_dry_run "$TPMD_RX_PREFIX" "0"
			# Wait for few seconds for traffic to stabilize
			sleep $TXWAIT
			while [ $i -le $NUM_CAPTURE ]; do
				rx_pps=$rx_pps+$(capture_rx_pps)
				((++i))
				sleep $RXWAIT
			done
			stop_testpmd
			avg_pps=$(echo "(($rx_pps) / $NUM_CAPTURE)" | bc)
			p=${PASS_PPS_TABLE[$rn,$2]}
			echo "pktsize: $pktsz avg_pps: $avg_pps"
			echo "pass_pps $p"
			if (( $(echo "$avg_pps < $p" | bc) )); then
				echo "$1:Low numbers for packet size $pktsz " \
					"($avg_pps < $p) for $3 cores">&2
			else
				echo "Test Passed"
				testpmd_quit "$TPMD_TX_PREFIX"
				break
			fi
			((++tcnt))
			sleep $WS
		done
		if [[ $tcnt -gt $MAX_TRY_CNT ]]; then
			echo "Test Failed"
			exit 1
		fi
		((++rn))
	done
}

function get_ref_mops()
{
	local ref_mops
	ref_mops=$(awk -v pat=$1 '$0~pat','/end/' \
			$FPATH.$3 | grep $2: | tr -s ' ')
	echo $ref_mops
}

function populate_pass_mops()
{
	local rn=0
	local cn

	for i in ${PKT_LIST[@]}
	do
		cn=0
		ref_mops=$(get_ref_mops $1 $i $2)
		for j in ${CORES[@]}
		do
			tmp=$(( $cn + 2 ))
			ref_n=$(echo "$ref_mops" | cut -d " " -f $tmp)
			PASS_PPS_TABLE[$rn,$cn]=$(echo "($ref_n * .97)" | bc)
			((++cn))
		done
		((++rn))
	done
}

function aes_cbc_sha1_hmac_outb()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
	local cn

	echo "Outbound Perf Test: $algo_str"
	populate_pass_mops $algo_str "${TYPE[$Y]}.outb"

	cn=0
	for j in ${CORES[@]}
	do
		outb_perf $algo_str $cn $j
		((++cn))
	done
}

function aes_cbc_sha1_hmac_inb()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
	local cn

	echo "Inbound Perf Test: $algo_str"
	populate_pass_mops $algo_str "${TYPE[$Y]}.inb"

	cn=0
	for j in ${CORES[@]}
	do
		inb_perf $algo_str $cn $j
		((++cn))
	done
}

function aes_gcm_outb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
	local cn

	echo "Outbound Perf Test: $algo_str"
	populate_pass_mops $algo_str "${TYPE[$Y]}.outb"

	cn=0
	for j in ${CORES[@]}
	do
		# Run ipsec-secgw application
		outb_perf $algo_str $cn $j
		((++cn))
	done
}

function aes_gcm_inb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
	local cn

	echo "Inbound Perf Test: $algo_str"
	populate_pass_mops $algo_str "${TYPE[$Y]}.inb"

	cn=0
	for j in ${CORES[@]}
	do
		inb_perf $algo_str $cn $j
		((++cn))
	done
}

get_system_info

if [[ $IS_CN10K -ne 0 ]]; then
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${HW}
	FPATH="$CNXKTESTPATH/ref_numbers/cn10k/$FNAME"
else
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"_cptclk"${CPTCLK}"."${HW}
	FPATH="$CNXKTESTPATH/ref_numbers/cn9k/$FNAME"
fi


if [[ ! -f "$FPATH.lc.outb" ]]; then
	echo "File $FPATH.lc.outb not present"
	exit 1
fi

if [[ ! -f "$FPATH.lc.inb" ]]; then
	echo "File $FPATH.lc.inb not present"
	exit 1
fi

if [[ ! -f "$FPATH.lp.outb" ]]; then
	echo "File $FPATH.lp.outb not present"
	exit 1
fi

if [[ ! -f "$FPATH.lp.inb" ]]; then
	echo "File $FPATH.lp.inb not present"
	exit 1
fi

if [[ ! -f "$FPATH.ip.outb" ]]; then
	echo "File $FPATH.ip.outb not present"
	exit 1
fi

if [[ ! -f "$FPATH.ip.inb" ]]; then
	echo "File $FPATH.ip.inb not present"
	exit 1
fi

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT


LIF1=0002:01:00.5
LIF2=0002:01:00.6
LIF3=0002:01:00.7
LIF4=0002:01:01.0

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_VF=$SSO_DEV

IPSEC_LOG=ipsec.log
VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"

rm -f $IPSEC_LOG
setup_interfaces

Y=0

while [ $Y -lt $NUM_MODES ]; do
	echo ""
	echo "Test: ${TN[$Y]}"
	echo "----------------------"
	# Outbound
	sleep $WS
	run_ipsec_secgw

	# aes-cbc sha1-hmac
	X=1
	pmd_rx_launch
	pmd_tx_launch
	aes_cbc_sha1_hmac_outb
	testpmd_quit "$TPMD_TX_PREFIX"
	testpmd_quit "$TPMD_RX_PREFIX"

	sleep $WS

	echo ""
	# aes-gcm
	X=2
	pmd_rx_launch
	pmd_tx_launch
	aes_gcm_outb
	testpmd_quit "$TPMD_TX_PREFIX"
	testpmd_quit "$TPMD_RX_PREFIX"
	ipsec_exit
	sleep $WS

	echo ""
	# Inbound
	run_ipsec_secgw_inb
	pmd_rx_launch
	aes_cbc_sha1_hmac_inb
	testpmd_quit "$TPMD_RX_PREFIX"

	sleep $WS

	echo ""
	pmd_rx_launch
	aes_gcm_inb
	testpmd_quit "$TPMD_RX_PREFIX"
	ipsec_exit
	((++Y))
done

exit 0
