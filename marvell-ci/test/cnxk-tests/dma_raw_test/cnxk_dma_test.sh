#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2026 Marvell.

set -e

PLAT=${PLAT:?}

if [[ "$PLAT" != "cn9k" && "$PLAT" != "cn10k" ]]; then
	exit 0
fi

if [[ ! -f cnxk_dma_test ]]; then
	echo "cnxk_dma_test not found !!"
	exit 1
fi

LOG=./log.txt

rm -rf $LOG

sh ./dpi-test-setup.sh

timeout 15 stdbuf -o 0 ./cnxk_dma_test -l 0-4 -- -r 0x400000000 \
                          -m 0 -p -t 1 -s 64 -b 128 -i 5 > $LOG &

sleep 8
echo "================================"
while [[ ! -f $LOG ]]; do
	echo "Waiting for log"
	sleep 1
	continue
done
echo "================================"

sh ./dpi-test-setup.sh unbind
sleep 2
cat $LOG

echo "CNXK_DMA_TEST SUCCESSFUL"
