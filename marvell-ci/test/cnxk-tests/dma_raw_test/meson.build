# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2026 Marvell.

# Test name
test_name = 'cnxk_dma_test'

# Test script
test_script = 'cnxk_dma_test.sh'

# Arguments to the test scripts
test_args = '$REMOTE_DIR'

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='cnxk_dma_test'

# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'dpi-test-setup.sh')

# Create the test executable
cnxk_dma_test=executable(
    test_exec,
    files('main.c'),
    link_whole: link_libs,
    include_directories: includes,
    dependencies: [cnxk_test_dep_objs, get_variable(def_lib + '_rte_dma_cnxk')],
    c_args: cflags,
    install_dir: 'bin/cnxk/dma_test',
    install: true
)

# Add the meson test
test(
    test_name,
    cnxk_dma_test,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')

# Install the script
install_data(
    'cnxk_dma_test.sh',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/dma_test')
install_data(
    'dpi-test-setup.sh',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/dma_test')
