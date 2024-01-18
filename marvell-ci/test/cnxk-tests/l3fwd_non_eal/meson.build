# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.
#

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec = 'l3fwd-non-eal'

allow_experimental_apis = true
deps += ['acl', 'fib', 'lpm']

includes = include_directories('common')
# Create the test executable
l3fwd_non_eal_test=executable(
    test_exec,
    files('l3fwd_acl.c',
      'l3fwd_em.c',
      'l3fwd_event.c',
      'l3fwd_event_internal_port.c',
      'l3fwd_event_generic.c',
      'l3fwd_fib.c',
      'l3fwd_lpm.c',
      'main.c'
      ),
    include_directories: includes,
    link_whole: link_libs,
    dependencies: test_dep_objs,
    c_args: cflags,
    install_dir: 'bin/cnxk/l3fwd',
    install: true
)
