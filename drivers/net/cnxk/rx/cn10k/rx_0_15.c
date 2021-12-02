/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn10k_ethdev.h"
#include "cn10k_rx.h"

#define R(name, flags) NIX_RX_RECV(cn10k_nix_recv_pkts_##name, flags)

NIX_RX_FASTPATH_MODES_0_15
#undef R
