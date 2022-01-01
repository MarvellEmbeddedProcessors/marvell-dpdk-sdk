# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell

if not is_linux or not dpdk_conf.get('RTE_ARCH_64')
    build = false
    reason = 'only supported on 64-bit Linux'
    subdir_done()
endif

sources = files(
        'cnxk_mldev.c',
        'cn10k_mldev.c',
)

headers = files(
        'cn10k_mldev.h',
        'cnxk_mldev.h',
)

deps += ['common_cnxk', 'mldev']
