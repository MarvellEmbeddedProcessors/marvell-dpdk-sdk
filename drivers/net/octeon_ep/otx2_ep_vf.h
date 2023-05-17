/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#ifndef _OTX2_EP_VF_H_
#define _OTX2_EP_VF_H_

#include <rte_io.h>

/* IO Access */
#define otx2_read64(addr) rte_read64_relaxed((void *)(addr))
#define otx2_write64(val, addr) rte_write64_relaxed((val), (void *)(addr))

#define PCI_DEVID_OCTEONTX2_EP_NET_VF		0xB203 /* OCTEON 9 EP mode */
#define PCI_DEVID_CN98XX_EP_NET_VF		0xB103
#define PCI_DEVID_CNF95N_EP_NET_VF		0xB403
#define PCI_DEVID_CNF95O_EP_NET_VF		0xB603
#define PCI_DEVID_LIO3_EP_NET_VF		0x3383
#define PCI_DEVID_CNF95XXN_EP_NET_VF		0xB403
#define PCI_DEVID_CNF95XXO_EP_NET_VF		0xB603

#define OTX2_EP_MAX_RX_PKT_LEN			(16384)

#define OTX2_EP_BUSY_LOOP_COUNT                 (10000)
#define OTX2_EP_RING_OFFSET                     (1ULL << 17)
#define OTX2_EP_R_OUT_CNTS_IN_INT               (1ULL << 61)
#define OTX2_EP_R_OUT_CNTS_OUT_INT               (1ULL << 62)

#define OTX2_EP_R_OUT_ENABLE_START               (0x10160)

#define OTX2_EP_R_OUT_ENABLE(ring) \
	(OTX2_EP_R_OUT_ENABLE_START + (OTX2_EP_RING_OFFSET * (ring)))
int
otx2_ep_vf_setup_device(struct otx_ep_device *sdpvf);

struct otx2_ep_instr_64B {
	/* Pointer where the input data is available. */
	uint64_t dptr;

	/* OTX_EP Instruction Header. */
	union otx_ep_instr_ih ih;

	/** Pointer where the response for a RAW mode packet
	 * will be written by OCTEON TX.
	 */
	uint64_t rptr;

	/* Input Request Header. */
	union otx_ep_instr_irh irh;

	/* Additional headers available in a 64-byte instruction. */
	uint64_t exhdr[4];
};

#define OTX2_EP_IQ_ISM_OFFSET(queue)	(RTE_CACHE_LINE_SIZE * (queue) + 4)
#define OTX2_EP_OQ_ISM_OFFSET(queue)	(RTE_CACHE_LINE_SIZE * (queue))
#define OTX2_EP_ISM_EN			(0x1)
#define OTX2_EP_ISM_MSIX_DIS		(0x2)
#define OTX2_EP_MAX_RX_PKT_LEN		(16384)

static inline int is_otx2_ep_vf(uint16_t chip_id)
{
	return (chip_id == PCI_DEVID_OCTEONTX2_EP_NET_VF ||
		chip_id == PCI_DEVID_LIO3_EP_NET_VF ||
		chip_id == PCI_DEVID_CNF95N_EP_NET_VF ||
		chip_id == PCI_DEVID_CNF95O_EP_NET_VF ||
		chip_id == PCI_DEVID_CN98XX_EP_NET_VF);
}

union out_int_lvl_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timet:22;
		uint64_t max_len:7;
		uint64_t max_len_en:1;
		uint64_t time_cnt_en:1;
		uint64_t bmode:1;
	} s;
};

union out_cnts_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timer:22;
		uint64_t rsvd:5;
		uint64_t resend:1;
		uint64_t mbox_int:1;
		uint64_t in_int:1;
		uint64_t out_int:1;
		uint64_t send_ism:1;
	} s;
};

#define OTX2_EP_64B_INSTR_SIZE	(sizeof(otx2_ep_instr_64B))

#define NIX_MAX_HW_FRS			9212
#define NIX_MAX_VTAG_INS		2
#define NIX_MAX_VTAG_ACT_SIZE		(4 * NIX_MAX_VTAG_INS)
#define NIX_MAX_FRS	\
	(NIX_MAX_HW_FRS + RTE_ETHER_CRC_LEN - NIX_MAX_VTAG_ACT_SIZE)

#define CN93XX_INTR_R_OUT_INT        (1ULL << 62)
#define CN93XX_INTR_R_IN_INT         (1ULL << 61)
#define OTX_EP_R_MBOX_PF_VF_INT_START        (0x10220)
#define OTX_EP_RING_OFFSET                   (0x1ull << 17)
#define OTX_EP_R_MBOX_PF_VF_INT(ring) \
	(OTX_EP_R_MBOX_PF_VF_INT_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_MBOX_PF_VF_DATA_START        (0x10210)
#define OTX_EP_R_MBOX_PF_VF_DATA(ring)           \
	(OTX_EP_R_MBOX_PF_VF_DATA_START + ((ring) * OTX_EP_RING_OFFSET))

#endif /*_OTX2_EP_VF_H_ */
