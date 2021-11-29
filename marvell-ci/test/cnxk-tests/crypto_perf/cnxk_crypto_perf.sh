#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -e

SUDO=${SUDO:-"sudo"}
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
CORES=(1 2 4)
COREMASK="0x1f00"
BUFSIZE=(64 384 1504)
BUFFERSZ="64,384,1504"
PREFIX="cpt"
IN="cryptoperf.in.$PREFIX"
OUT="cryptoperf.out.$PREFIX"
DEVTYPE="crypto_cn9k"
BURSTSZ=32
POOLSZ=16384
NUMOPS=10000000
DL=","
MAX_TRY_CNT=20
CRYPTO_DEVICE="0002:10:00.1"
PARTNUM_98XX=0x0b1
# Get CPU PART NUMBER
PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')
if [[ $PARTNUM == $PARTNUM_98XX ]]; then
	FEXT="98xx"
else
	FEXT="96xx"
fi
EAL_ARGS="-c $COREMASK -a $CRYPTO_DEVICE"

# Error Patterns in cryptoperf run.
CPT_PERF_ERROR_PATTERNS=(
	"EAL: Error"
	"invalid option"
	"Test run constructor failed"
)

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A PASS_MOPS_TABLE
declare -A ACT_MOPS_TABLE

# Find the dpdk-test-crypto-perf application
if [[ -f $SCRIPTPATH/../../../../app/dpdk-test-crypto-perf ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../app/dpdk-test-crypto-perf
elif [[ -f $SCRIPTPATH/../../dpdk-test-crypto-perf ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-test-crypto-perf
else
	DPDK_TEST_BIN=$(which dpdk-test-crypto-perf)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-test-crypto-perf not found !!"
		exit 1
	fi
fi

function remove_files()
{
	rm -f "$SCRIPTPATH/$OUT"
	rm -f "$SCRIPTPATH/$IN"
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
	remove_files
	exit $status
}

function get_system_info()
{
	local sysclk_dir
	local fp_rclk
	local fp_sclk
	local fp_cptclk
	local div=1000000

	sysclk_dir="/sys/kernel/debug/clk"
	fp_rclk="$sysclk_dir/rclk/clk_rate"
	fp_sclk="$sysclk_dir/sclk/clk_rate"
	fp_cptclk="$sysclk_dir/cptclk/clk_rate"

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

function get_ref_mops()
{
	local ref_mops
	ref_mops=$(awk -v pat=$1 '$0~pat','/end/' \
			$FPATH | grep $2: | tr -s ' ')
	echo $ref_mops
}

function cryptoperf_cleanup()
{
	# Issue kill
	ps -eo "pid,args" | grep dpdk-test-crypto-perf | grep $PREFIX | \
		awk '{print $2}' | xargs -I[] -n1 kill -9 [] 2>/dev/null || true

	# Wait until the process is killed
	while (ps -ef | grep dpdk-test-crypto-perf | grep -q $PREFIX); do
		continue
	done
}

function cryptoperf_run()
{
	local eal_args=$1
	local cryptoperf_args=$2
	local unbuffer="stdbuf -o0"

	cryptoperf_cleanup $PREFIX
	remove_files
	sleep 1
	touch $IN
	tail -f $IN | \
		($unbuffer $DPDK_TEST_BIN $eal_args --file-prefix $PREFIX -- \
			$cryptoperf_args &>$OUT) &
	# Wait till out file is created
	while [[ ! -f $OUT ]]; do
		continue
	done
	# Wait until the process exits
	while (ps -ef | grep dpdk-test-crypto-perf | grep -q $PREFIX); do
		continue
	done
}

function check_mops()
{
	local mops=0
	local i=1
	local j

	while [ $i -le $1 ]; do
		j=$((i+8))
		mops=$mops+$(grep "$j$DL$2$DL$BURSTSZ$DL$NUMOPS" $OUT | \
			tr -s ' ' | cut -d "$DL" -f 8)
		let i=i+1
	done
	echo "$mops" | bc
}

function compare_pass_mops()
{
	local ret=0
	local rn=0
	local cn

	for i in ${BUFSIZE[@]}
	do
		cn=0
		for j in ${CORES[@]}
		do
			a=${ACT_MOPS_TABLE[$rn,$cn]}
			e=${PASS_MOPS_TABLE[$rn,$cn]}
			if (( $(echo "$a < $e" | bc) )); then
				echo "$1:Low numbers for buffer size $i " \
					"($a < $e) for $j cores">&2
				ret=1
				break 2
			fi
			let cn=cn+1
		done
		let rn=rn+1
	done

	echo "$ret"
}

function populate_pass_mops()
{
	local rn=0
	local cn

	for i in ${BUFSIZE[@]}
	do
		cn=0
		ref_mops=$(get_ref_mops $1 $i)
		for j in ${CORES[@]}
		do
			tmp=$(( $cn + 2 ))
			ref_n=$(echo "$ref_mops" | cut -d " " -f $tmp)
			PASS_MOPS_TABLE[$rn,$cn]=$(echo "($ref_n * .97)" | bc)
			let cn=cn+1
		done
		let rn=rn+1
	done
}

function populate_act_mops()
{
	local rn=0
	local cn

	for i in ${BUFSIZE[@]}
	do
		cn=0
		for j in ${CORES[@]}
		do
			ACT_MOPS_TABLE[$rn,$cn]=$(check_mops $j $i)
			let cn=cn+1
		done
		let rn=rn+1
	done
}

function check_errors()
{
	local ret=0
	local err

	for err in "${CPT_PERF_ERROR_PATTERNS[@]}"; do
		grep -i "$err" $OUT 2>/dev/null 1>/dev/null
		if [ $? -eq 0 ]; then
			echo "Error running crypto perf">&2
			ret=2
			break
		fi
	done

	echo "$ret"
}

function post_run()
{
	local ret

	ret=$(check_errors)
	if [ "$ret" != "2" ]; then
		populate_act_mops
		ret=$(compare_pass_mops $1)
	fi
	echo "$ret"
}

function aes_cbc_perf()
{
	local cipher="aes-cbc-only"
	local cipharg="aes-cbc"
	local try_cnt=1
	local ret

	echo "Perf Test: $cipher"
	populate_pass_mops $cipher

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput \
		--optype cipher-only --cipher-algo $cipharg \
		--pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 32 \
		--cipher-iv-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"
	cat $OUT

	ret=$(post_run $cipher)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}

function aes_sha1_hmac_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
	local try_cnt=1
	local ret

	echo "Perf Test: $algo_str"
	populate_pass_mops $algo_str

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput \
		--optype cipher-then-auth --cipher-algo $cipher \
		--pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 32 \
		--cipher-iv-sz 16 --auth-algo $auth --auth-op generate \
		--auth-key-sz 64 --digest-sz 20 --buffer-sz $BUFFERSZ \
		--total-ops $NUMOPS --burst-sz $BURSTSZ --silent \
		--csv-friendly"
	cat $OUT

	ret=$(post_run $algo_str)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}

function aead_perf()
{
	local cipher="aes-gcm"
	local try_cnt=1
	local ret

	echo "Perf Test: $cipher"
	populate_pass_mops $cipher

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype aead \
		--aead-algo $cipher --pool-sz $POOLSZ --aead-op encrypt \
		--aead-key-sz 32 --aead-iv-sz 12 --aead-aad-sz 64 \
		--digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"
	cat $OUT

	ret=$(post_run $cipher)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}

function aes_sha1_hmac_ipsec_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}-ipsec"
	local try_cnt=1
	local ret

	echo "Perf Test: $algo_str"
	populate_pass_mops $algo_str

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput \
		--optype ipsec --cipher-algo $cipher \
		--pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 16 \
		--cipher-iv-sz 16 --auth-algo $auth --auth-op generate \
		--auth-key-sz 20 --digest-sz 16 --buffer-sz $BUFFERSZ \
		--total-ops $NUMOPS --burst-sz $BURSTSZ --silent \
		--csv-friendly"
	cat $OUT

	ret=$(post_run $algo_str)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}

function aead_ipsec_perf()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}-ipsec"
	local try_cnt=1
	local ret

	echo "Perf Test: $algo_str"
	populate_pass_mops $algo_str

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype ipsec \
		--aead-algo $cipher --pool-sz $POOLSZ --aead-op encrypt \
		--aead-key-sz 32 --aead-iv-sz 12 --aead-aad-sz 64 \
		--digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"
	cat $OUT

	ret=$(post_run $algo_str)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}


function zuc_eia3_perf()
{
	local auth="zuc-eia3"
	local try_cnt=1
	local ret

	echo "Perf Test: $auth"
	populate_pass_mops $auth

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype auth-only \
		--auth-algo $auth --pool-sz $POOLSZ --auth-op generate \
		--auth-key-sz 16 --digest-sz 4 --auth-iv-sz 16 \
		--buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ \
		--silent --csv-friendly"
	cat $OUT

	ret=$(post_run $auth)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}

function zuc_eea3_perf()
{
	local cipher="zuc-eea3"
	local try_cnt=1
	local ret

	echo "Perf Test: $cipher"
	populate_pass_mops $cipher

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype cipher-only \
		--cipher-algo $cipher --pool-sz $POOLSZ --cipher-op decrypt \
		--cipher-key-sz 16 --cipher-iv-sz 16 --buffer-sz $BUFFERSZ \
		--total-ops $NUMOPS --burst-sz $BURSTSZ --silent \
		--csv-friendly"
	cat $OUT

	ret=$(post_run $cipher)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}

function ae_modex_perf()
{
	local optype="modex"
	local try_cnt=1
	local ret

	echo "Perf Test: $optype"
	populate_pass_mops $optype

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype $optype \
		--pool-sz $POOLSZ --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"
	cat $OUT

	ret=$(post_run $optype)
	if [ "$ret" == "0" ]; then
		echo "Test Passed"
		break
	fi

	let try_cnt=try_cnt+1
	done

	if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
		echo "Test Failed"
		exit 1
	fi
}

echo "Starting crypto perf application"

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

get_system_info
FNAME="rclk"${RCLK}"_sclk"${SCLK}"_cptclk"${CPTCLK}"."${FEXT}
FPATH="$SCRIPTPATH/ref_numbers/cn9k/$FNAME"

if [[ ! -f "$FPATH" ]]; then
	exit 1
fi

aes_cbc_perf
aes_sha1_hmac_perf
aead_perf
aes_sha1_hmac_ipsec_perf
aead_ipsec_perf
zuc_eia3_perf
zuc_eea3_perf
ae_modex_perf

echo "Crypto perf application completed"
exit 0
