# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2025 Marvell.

# Test script
test_script = 'cnxk_halo.sh'

# Test name
test_name = 'cnxk_halo'

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Copy the required scripts to build directory.
run_command(copy_data, test_script)

# Add the meson test
test(
    test_name,
    cnxk_test_script_wrapper,
    env: ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args: [test_script, '$REMOTE_DIR'],
    is_parallel : false,
    suite : 'cnxk-tests')

install_data(
    'cnxk_halo.sh',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/cnxk_halo')
