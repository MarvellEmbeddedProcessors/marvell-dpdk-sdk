/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn9k_ethdev.h"
#include "cn9k_tx.h"

#define T(name, sz, flags)                                                     \
	NIX_TX_XMIT_VEC(cn9k_nix_xmit_pkts_vec_##name, sz, flags)

NIX_TX_FASTPATH_MODES_112_127
#undef T
