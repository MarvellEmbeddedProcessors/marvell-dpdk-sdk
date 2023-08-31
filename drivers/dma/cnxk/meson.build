# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell International Ltd.

error_cflags = ['-Wno-uninitialized']
foreach flag: error_cflags
    if cc.has_argument(flag)
        cflags += flag
    endif
endforeach

deps += ['bus_pci', 'common_cnxk', 'dmadev']
sources = files('cnxk_dmadev.c', 'cnxk_dmadev_fp.c')
pmd_supports_disable_iova_as_pa = true
