# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Marvell

sources = files(
        'mldev_pmd.c',
        'rte_mldev.c',
)

headers = files(
        'rte_mldev.h',
)

driver_sdk_headers += files(
        'mldev_pmd.h',
)

deps += ['kvargs', 'mbuf', 'rcu', 'telemetry']
