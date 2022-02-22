#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

SUDO=${SUDO:-"sudo"}
SCRIPTPATH=$1
CORES=(1 2 4)
COREMASK="0x1f00"
BUFSIZE=(64 384 1504)
BUFFERSZ="64,384,1504"
PREFIX="cpt"
IN="cryptoperf.in.$PREFIX"
OUT="cryptoperf.out.$PREFIX"
BURSTSZ=32
POOLSZ=16384
NUMOPS=10000000
DL=","
MAX_TRY_CNT=5
PARTNUM_98XX=0x0b1
! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

if [[ $IS_CN10K -ne 0 ]]; then
	DEVTYPE="crypto_cn10k"
	CRYPTO_DEVICE=$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')
	FEXT="106xx"
else
	DEVTYPE="crypto_cn9k"
	CRYPTO_DEVICE=$(lspci -d :a0fe | head -1 | awk -e '{ print $1 }')
	# Get CPU PART NUMBER
	PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')
	if [[ $PARTNUM == $PARTNUM_98XX ]]; then
		FEXT="98xx"
	else
		FEXT="96xx"
	fi
fi

if [ -z "$CRYPTO_DEVICE" ]
then
	echo "Crypto device not found"
	exit 1
fi

EAL_ARGS="-c $COREMASK -a $CRYPTO_DEVICE"

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A ACT_MOPS_TABLE

DPDK_TEST_BIN=$SCRIPTPATH/dpdk-test-crypto-perf

function remove_files()
{
	rm -f "$SCRIPTPATH/$OUT"
	rm -f "$SCRIPTPATH/$IN"
}

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
	touch $IN
	tail -f $IN | ($unbuffer $SUDO $DPDK_TEST_BIN $eal_args \
		--file-prefix $PREFIX -- $cryptoperf_args &>$OUT) &
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

function write_mops()
{
	local rn=0
	local cn
	local val
	local a

	echo $1 >> $FPATH
	for i in ${BUFSIZE[@]}
	do
		cn=0
		str=$i":"
		for j in ${CORES[@]}
		do
			val="0"
			for (( k=0; k < $MAX_TRY_CNT; k++ ))
			do
				val=$val+${ACT_MOPS_TABLE[$k,$rn,$cn]}
			done

			a=$(echo "scale=3; (($val) / $MAX_TRY_CNT)" | bc)
			str+=" $a"
			let cn=cn+1
		done
		echo $str >> $FPATH
		let rn=rn+1
	done
	echo "<end>" >> $FPATH
}

function populate_act_mops()
{
	local rn=0
	local cn
	cat $OUT

	for i in ${BUFSIZE[@]}
	do
		cn=0
		for j in ${CORES[@]}
		do
			ACT_MOPS_TABLE[$1,$rn,$cn]=""
			ACT_MOPS_TABLE[$1,$rn,$cn]=$(check_mops $j $i)
			let cn=cn+1
		done
		let rn=rn+1
	done
}

function aes_cbc_perf()
{
	local cipher="aes-cbc-only"
	local cipharg="aes-cbc"
	local try_cnt=1

	echo "Perf Test: $cipher"

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput \
		--optype cipher-only --cipher-algo $cipharg \
		--pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 32 \
		--cipher-iv-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $cipher
}

function aes_sha1_hmac_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
	local try_cnt=1

	echo "Perf Test: $algo_str"

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

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $algo_str
}

function aead_perf()
{
	local cipher="aes-gcm"
	local try_cnt=1

	echo "Perf Test: $cipher"

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype aead \
		--aead-algo $cipher --pool-sz $POOLSZ  --aead-op encrypt \
		--aead-key-sz 32 --aead-iv-sz 12 --aead-aad-sz 64 \
		--digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $cipher
}

function aes_sha1_hmac_ipsec_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}-ipsec"
	local try_cnt=1

	echo "Perf Test: $algo_str"

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

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $algo_str
}

function aead_ipsec_perf()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}-ipsec"
	local try_cnt=1

	echo "Perf Test: $algo_str"

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype ipsec \
		--aead-algo $cipher --pool-sz $POOLSZ  --aead-op encrypt \
		--aead-key-sz 32 --aead-iv-sz 12 --aead-aad-sz 64 \
		--digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $algo_str
}


function zuc_eia3_perf()
{
	local auth="zuc-eia3"
	local try_cnt=1

	echo "Perf Test: $auth"

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype auth-only \
		--auth-algo $auth --pool-sz $POOLSZ --auth-op generate \
		--auth-key-sz 16 --digest-sz 4 --auth-iv-sz 16 \
		--buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ \
		--silent --csv-friendly"

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $auth
}

function zuc_eea3_perf()
{
	local cipher="zuc-eea3"
	local try_cnt=1

	echo "Perf Test: $cipher"

	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype cipher-only \
		--cipher-algo $cipher --pool-sz $POOLSZ --cipher-op decrypt \
		--cipher-key-sz 16 --cipher-iv-sz 16 --buffer-sz $BUFFERSZ \
		--total-ops $NUMOPS --burst-sz $BURSTSZ --silent \
		--csv-friendly"

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $cipher
}

function ae_modex_perf()
{
	local optype="modex"
	local try_cnt=1

	echo "Perf Test: $optype"

	if [[ $IS_CN10K -ne 0 ]]; then
		MAX_TRY_CNT=1
	fi
	while [ $try_cnt -le $MAX_TRY_CNT ]; do
	echo "Run $try_cnt"
	cryptoperf_run "$EAL_ARGS" \
		"--devtype $DEVTYPE --ptest throughput --optype $optype \
		--pool-sz $POOLSZ --buffer-sz $BUFFERSZ --total-ops $NUMOPS \
		--burst-sz $BURSTSZ --silent --csv-friendly"

	populate_act_mops $((try_cnt-1))
	let try_cnt=try_cnt+1
	done

	write_mops $optype
}

get_system_info
if [[ $IS_CN10K -ne 0 ]]; then
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${FEXT}
else
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"_cptclk"${CPTCLK}"."${FEXT}
fi

FPATH="$SCRIPTPATH/$FNAME"
rm -f "$FPATH"

aes_cbc_perf
aes_sha1_hmac_perf
aead_perf
aes_sha1_hmac_ipsec_perf
aead_ipsec_perf
zuc_eia3_perf
zuc_eea3_perf
ae_modex_perf
remove_files
