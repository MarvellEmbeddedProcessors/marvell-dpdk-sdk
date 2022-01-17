#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -e

if [[ ! -f cnxk-extbuf ]]; then
	echo "cnxk-extbuf not found !!"
	exit 1
fi

RX_LOG=rx.txt
TX_LOG=tx.txt

rm -rf $RX_LOG
rm -rf $TX_LOG

timeout 15 stdbuf -o 0 ./cnxk-extbuf \
	--file-prefix rx \
	-c 0x3 \
	-a 0002:01:00.2 \
	-- \
	--rx > $RX_LOG &

echo "================================"
while [[ ! -f $RX_LOG ]]; do
	echo "Waiting for RX log"
	sleep 1
	continue
done
echo "================================"

sleep 5

echo "================================"
echo "Starting TX"
echo "================================"
./cnxk-extbuf \
	--file-prefix tx \
	-c 0x5 \
	-a 0002:01:00.1 \
	-- \
	--max-tx 100 > $TX_LOG

echo "================================"
echo "Waiting for RX to complete"
echo "================================"
wait

TX_PKTS=$(grep "TOTAL PACKETS" $TX_LOG | awk '{print $5}')
RX_PKTS=$(grep "TOTAL PACKETS" $RX_LOG | awk '{print $5}')

if [[ $TX_PKTS != $RX_PKTS ]]; then
	echo "TX and RX Packets not matching $TX_PKTS != $RX_PKTS"
	exit 1
fi

echo "TEST SUCCESSFUL Rx=Tx $TX_PKTS"
