# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021, Marvell

if not get_option('tests')
    subdir_done()
endif

if not host_machine.cpu_family().startswith('aarch')
    subdir_done()
endif

subdir('common')

# The developer is expected to add new scripts in subdirectories and add it to
# test_subdirs list below. The subdirectory must contain a meson.build doing the
# following.
# 1. Copy the required scripts and files to the build directory. A helper
#    copy.py script is provided for this.
# 2. Add a meson test with following properties.
#    a. Test executable MUST be 'cnxk_test_script_wrapper'.
#    b. DPDK_TEST env var to be set to the desired test name.
#    c. TEST_DIR env var to be set to the directory where the test is
#       supposed to run from. This should be relative to build dir as later
#       during the actual run, a substitution of build dir with run dir is
#       performed.
#    d. The arguments should be the script name followed by script arguments.
# 3. Give explicit meson instructions for installation if the script is to be
#    installed.
#
# Refer marvell-ci/test/common/exe_wrapper.sh to see how the meson test is
# handled in the marvell-ci exe_wrapper.
# Refer app/test-cnxk-scripts/sample/meson.build for a sample cnxk script
# meson test.
# Refer https://mesonbuild.com/Reference-manual.html#test to see how to use
# meson tests.
#
# Note: These cnxk test scripts will only run with marvell-ci exe_wrapper.sh.
# These will be skipped when run without the exe_wrapper.

# Add cnxk test script subdirectories to the below list.
test_subdirs = [
        'ptp_test',
        'fwd_perf',
        'crypto_perf',
        'event_perf',
        'ipsec_secgw',
        'l2fwd_simple',
        'ipsec_perf',
        'sample',
        'tx_chksum',
        'rx_chksum',
        'dpdk_test',
        'port_ctrl',
        'crypto_autotest',
        'inline_ipsec_autotest',
        'tm_test',
        'flow_perf',
        'txrx_stats',
        'flow_regression',
        'cpt_2nd_pass_flow',
        'read_config',
        'mempool_perf',
        'mac_test',
        'extbuf',
        'gpio_test',
        'meter_test',
        'bphy_irq',
        'queue_intr_test',
        'dpdk_config_test',
        'trace_autotest',
        'mbuf_perf',
        'hotplug_test',
        'l2fwd_tmc',
        'l2fwd_event_pfc',
        'tx_vlan',
        'ipsec_reassembly_perf',
        'lso_test',
        'cman_test',
        'multi_pool_pkt_tx',
        'flow_ctrl',
        'multi_mempool',
        'ipsec_msns',
        'hwpool',
]

foreach dir:test_subdirs
    subdir(dir)
endforeach
