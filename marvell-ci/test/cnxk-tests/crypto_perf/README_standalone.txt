Crypto perf standalone application
==================================

The crypto_test_standalone.sh and crypto_perf_standalone.sh can be
used by developers to generate crypto performance numbers. It uses
the dpdk-test-crypto-perf application to generate the numbers.

How to run
==========
cd <dpdk_dir>
export PROJROOT=$PWD
export BUILD_DIR=$PWD/build
export TARGET_BOARD=<user@target ip>
./marvell-ci/test/cnxk-tests/crypto_perf/crypto_test_standalone.sh

By default the files will be copied in /tmp/dpdk directory on target board.
This can be changed by exporting REMOTE_DIR variable.
