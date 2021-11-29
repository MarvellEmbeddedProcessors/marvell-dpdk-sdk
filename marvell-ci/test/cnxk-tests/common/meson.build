# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021, Marvell

if not get_option('tests')
    subdir_done()
endif

# This executable is used as a workaround to make sure that the exe_wrapper gets
# called for scripts also. In the exe_wrapper, this executable is ignored. Note
# that the test_dep_objs is inherited from app/test/meson.build.
cnxk_test_script_wrapper = executable(
    'cnxk-test-script-wrapper',
    files('cnxk_test_script_wrapper.c'),
    dependencies: test_dep_objs,
    install: false)

# Helper command to copy files to build dir
copy_data = find_program('copy_data.py')

subdir('scapy')
subdir('pcap')
subdir('testpmd')
