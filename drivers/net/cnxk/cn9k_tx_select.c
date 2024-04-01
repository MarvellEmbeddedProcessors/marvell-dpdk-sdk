/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn9k_ethdev.h"
#include "cn9k_tx.h"

static __rte_used void
pick_tx_func(struct rte_eth_dev *eth_dev,
	     const eth_tx_burst_t tx_burst[NIX_TX_OFFLOAD_MAX])
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);

	/* [TS] [TSO] [NOFF] [VLAN] [OL3_OL4_CSUM] [IL3_IL4_CSUM] */
	eth_dev->tx_pkt_burst =
		tx_burst[dev->tx_offload_flags & (NIX_TX_OFFLOAD_MAX - 1)];

	if (eth_dev->data->dev_started)
		rte_eth_fp_ops[eth_dev->data->port_id].tx_pkt_burst =
			eth_dev->tx_pkt_burst;
}

static void
cn9k_eth_set_tx_tmplt_func(struct rte_eth_dev *eth_dev)
{
#if defined(RTE_ARCH_ARM64) && !defined(CNXK_DIS_TMPLT_FUNC)
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);

	const eth_tx_burst_t nix_eth_tx_burst[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn9k_nix_xmit_pkts_##name,
		NIX_TX_FASTPATH_MODES
#undef T
	};

	const eth_tx_burst_t nix_eth_tx_burst_mseg[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn9k_nix_xmit_pkts_mseg_##name,
		NIX_TX_FASTPATH_MODES
#undef T
	};

	const eth_tx_burst_t nix_eth_tx_vec_burst[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn9k_nix_xmit_pkts_vec_##name,
		NIX_TX_FASTPATH_MODES
#undef T
	};

	const eth_tx_burst_t nix_eth_tx_vec_burst_mseg[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn9k_nix_xmit_pkts_vec_mseg_##name,
		NIX_TX_FASTPATH_MODES
#undef T
	};

	if (dev->scalar_ena || dev->tx_mark) {
		pick_tx_func(eth_dev, nix_eth_tx_burst);
		if (dev->tx_offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
			pick_tx_func(eth_dev, nix_eth_tx_burst_mseg);
	} else {
		pick_tx_func(eth_dev, nix_eth_tx_vec_burst);
		if (dev->tx_offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
			pick_tx_func(eth_dev, nix_eth_tx_vec_burst_mseg);
	}
#else
	RTE_SET_USED(eth_dev);
#endif
}

static void
cn9k_eth_set_tx_blk_func(struct rte_eth_dev *eth_dev)
{
#if defined(CNXK_DIS_TMPLT_FUNC)
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);

	if (dev->scalar_ena || dev->tx_mark)
		eth_dev->tx_pkt_burst = cn9k_nix_xmit_pkts_all_offload;
	else
		eth_dev->tx_pkt_burst = cn9k_nix_xmit_pkts_vec_all_offload;

	if (eth_dev->data->dev_started)
		rte_eth_fp_ops[eth_dev->data->port_id].tx_pkt_burst = eth_dev->tx_pkt_burst;
#else
	RTE_SET_USED(eth_dev);
#endif
}

void
cn9k_eth_set_tx_function(struct rte_eth_dev *eth_dev)
{
#if defined(RTE_ARCH_ARM64)
	cn9k_eth_set_tx_blk_func(eth_dev);
	cn9k_eth_set_tx_tmplt_func(eth_dev);

	rte_atomic_thread_fence(__ATOMIC_RELEASE);
#else
	RTE_SET_USED(eth_dev);
#endif
}
