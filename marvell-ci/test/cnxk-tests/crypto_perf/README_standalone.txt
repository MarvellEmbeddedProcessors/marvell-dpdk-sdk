Crypto perf standalone application
==================================

The crypto_perf_host.sh and crypto_perf_target.sh can be
used by developers to generate crypto performance numbers. It uses
the dpdk-test-crypto-perf application to generate the numbers.

The crypto_perf_host.sh runs on the host machine and does the following:

1. Prints system info about the target.

2. Creates the remote directory on target board(96xx/106xx), copies the required
   files like dpdk-test-crypto-perf application, the crypto_perf_target.sh script
   and oxk-devbind-basic.sh script on the target board.
   By default the files will be copied in /tmp/dpdk directory on target board.
   This can be changed by exporting REMOTE_DIR variable.

3. Do the target setup by calling cnxk-target-setup.sh script. This can be skipped
   if the target is already setup once by exporting SKIP_TARGET_SETUP=y.

4. Then executes the crypto_perf_target.sh script on the target board.


The crypto_perf_target.sh script runs on the target board and executes the dpdk-test-crypto-perf
application for various cipher algos combinations, and generates the output in a file on the
target board.


How to run
==========
cd <dpdk_dir>
export PROJROOT=$PWD
export BUILD_DIR=$PWD/build
export REMOTE_DIR=<target dir> (optional)
export SKIP_TARGET_SETUP=y (optional)
export TARGET_BOARD=<user@target ip>
./marvell-ci/test/cnxk-tests/crypto_perf/crypto_perf_host.sh


Output File
===========

The output file containing the ops per second in millions(Mops) for different cipher algo combination
is generated on the target board.

The output file is named according to following format:
rclk<rclk freq>_sclk<sclk freq>_cptclk<cptclk freq>.HW.

For 96xx:  rclk2200_sclk1100_cptclk1000.96xx.
For 106xx: rclk2000_sclk1000.10xx.

The following is the snippet of output file for aes-cbc-only algorithm.
aes-cbc-only
64: 14.379 28.758 57.513
384: 7.910 15.821 31.647
1504: 2.922 5.844 11.691
<end>

The 1st column (64, 384, 1504) is the buffer size. The 2nd column shows the Mops for 1 core,
the 3rd column shows the Mops for 2 cores and the 3rd column shows the Mops for 4 cores.
