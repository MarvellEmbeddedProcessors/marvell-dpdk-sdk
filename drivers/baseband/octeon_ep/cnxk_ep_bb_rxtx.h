/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _CNXK_EP_BB_RXTX_H_
#define _CNXK_EP_BB_RXTX_H_

#include <rte_byteorder.h>

#define CNXK_EP_BB_RXD_ALIGN 2
#define CNXK_EP_BB_TXD_ALIGN 2

#define CNXK_EP_BB_IQ_SEND_FAILED      (-1)
#define CNXK_EP_BB_IQ_SEND_SUCCESS     (0)

#define CNXK_EP_BB_MAX_DELAYED_PKT_RETRIES 10000

#define CNXK_EP_BB_FSZ 28
#define OTX2_EP_FSZ_LOOP 0
#define OTX2_EP_FSZ_NIC 24
#define CNXK_EP_BB_MAX_INSTR 16

static inline void
cnxk_ep_bb_swap_8B_data(uint64_t *data, uint32_t blocks)
{
	/* Swap 8B blocks */
	while (blocks) {
		*data = rte_bswap64(*data);
		blocks--;
		data++;
	}
}

static inline uint32_t
cnxk_ep_bb_incr_index(uint32_t index, uint32_t count, uint32_t max)
{
	return ((index + count) & (max - 1));
}
#ifdef TODO_ADD_FOR_OTX
uint16_t
otx_bb_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts);
#endif
uint16_t
cnxk_ep_bb_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts);
uint16_t
cnxk_ep_bb_recv_pkts(void *rx_queue,
		  struct rte_mbuf **rx_pkts,
		  uint16_t budget);
#endif /* _CNXK_EP_BB_RXTX_H_ */
