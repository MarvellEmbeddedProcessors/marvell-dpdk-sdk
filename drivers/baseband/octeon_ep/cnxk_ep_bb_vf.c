/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_common.h>

#include "cnxk_ep_bb_common.h"
#include "cnxk_ep_bb_vf.h"

static void
cnxk_ep_bb_vf_setup_global_iq_reg(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, int q_no)
{
	volatile uint64_t reg_val = 0ull;

	/* Select ES, RO, NS, RDSIZE,DPTR Format#0 for IQs
	 * IS_64B is by default enabled.
	 */
	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_IN_CONTROL(q_no));

	reg_val |= CNXK_EP_R_IN_CTL_RDSIZE;
	reg_val |= CNXK_EP_R_IN_CTL_IS_64B;
	reg_val |= CNXK_EP_R_IN_CTL_ESR;

	oct_ep_write64(reg_val, cnxk_ep_bb_vf->hw_addr +
		       CNXK_EP_R_IN_CONTROL(q_no));
}

static void
cnxk_ep_bb_vf_setup_global_oq_reg(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, int q_no)
{
	volatile uint64_t reg_val = 0ull;

	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_OUT_CONTROL(q_no));

	reg_val &= ~(CNXK_EP_R_OUT_CTL_IMODE);
	reg_val &= ~(CNXK_EP_R_OUT_CTL_ROR_P);
	reg_val &= ~(CNXK_EP_R_OUT_CTL_NSR_P);
	reg_val &= ~(CNXK_EP_R_OUT_CTL_ROR_I);
	reg_val &= ~(CNXK_EP_R_OUT_CTL_NSR_I);
	reg_val &= ~(CNXK_EP_R_OUT_CTL_ROR_D);
	reg_val &= ~(CNXK_EP_R_OUT_CTL_NSR_D);
	reg_val &= ~(CNXK_EP_R_OUT_CTL_ES_I | CNXK_EP_R_OUT_CTL_ES_D);

	/* INFO/DATA ptr swap is required  */
	reg_val |= (CNXK_EP_R_OUT_CTL_ES_P);
	oct_ep_write64(reg_val, cnxk_ep_bb_vf->hw_addr +
		       CNXK_EP_R_OUT_CONTROL(q_no));
}

static int
cnxk_ep_bb_vf_setup_global_input_regs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	uint64_t q_no = 0ull;
	int ret = 0;

	for (q_no = 0; q_no < (cnxk_ep_bb_vf->sriov_info.rings_per_vf); q_no++)
		cnxk_ep_bb_vf_setup_global_iq_reg(cnxk_ep_bb_vf, q_no);

	return ret;
}

static int
cnxk_ep_bb_vf_setup_global_output_regs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	uint32_t q_no;
	int ret = 0;

	for (q_no = 0; q_no < (cnxk_ep_bb_vf->sriov_info.rings_per_vf); q_no++)
		cnxk_ep_bb_vf_setup_global_oq_reg(cnxk_ep_bb_vf, q_no);

	return ret;
}

static int
cnxk_ep_bb_vf_setup_device_regs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	int ret;
	ret = cnxk_ep_bb_vf_setup_global_input_regs(cnxk_ep_bb_vf);
	if (ret)
		return ret;
	ret = cnxk_ep_bb_vf_setup_global_output_regs(cnxk_ep_bb_vf);

	return ret;
}

static int
cnxk_ep_bb_vf_setup_iq_regs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t iq_no)
{
	struct cnxk_ep_bb_instr_queue *iq = cnxk_ep_bb_vf->instr_queue[iq_no];
	volatile uint64_t reg_val = 0ull;
	uint64_t ism_addr;

	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_IN_CONTROL(iq_no));

	/* Wait till IDLE to set to 1, not supposed to configure BADDR
	 * as long as IDLE is 0
	 */
	if (!(reg_val & CNXK_EP_R_IN_CTL_IDLE)) {
		do {
			reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
					      CNXK_EP_R_IN_CONTROL(iq_no));
		} while (!(reg_val & CNXK_EP_R_IN_CTL_IDLE));
	}

	/* Write the start of the input queue's ring and its size  */
	oct_ep_write64(iq->base_addr_dma, cnxk_ep_bb_vf->hw_addr +
		     CNXK_EP_R_IN_INSTR_BADDR(iq_no));
	oct_ep_write64(iq->nb_desc, cnxk_ep_bb_vf->hw_addr +
		     CNXK_EP_R_IN_INSTR_RSIZE(iq_no));

	/* Remember the doorbell & instruction count register addr
	 * for this queue
	 */
	iq->doorbell_reg = (uint8_t *)cnxk_ep_bb_vf->hw_addr +
			   CNXK_EP_R_IN_INSTR_DBELL(iq_no);
	iq->inst_cnt_reg = (uint8_t *)cnxk_ep_bb_vf->hw_addr +
			   CNXK_EP_R_IN_CNTS(iq_no);

	cnxk_ep_bb_dbg("InstQ[%d]:dbell reg @ 0x%p instcnt_reg @ 0x%p",
		   iq_no, iq->doorbell_reg, iq->inst_cnt_reg);

	do {
		reg_val = rte_read32(iq->inst_cnt_reg);
		rte_write32(reg_val, iq->inst_cnt_reg);
	} while (reg_val != 0);

	/* IN INTR_THRESHOLD is set to max(FFFFFFFF) which disable the IN INTR
	 * to raise
	 */
	oct_ep_write64(CNXK_EP_BB_CLEAR_SDP_IN_INT_LVLS,
		     cnxk_ep_bb_vf->hw_addr + CNXK_EP_R_IN_INT_LEVELS(iq_no));
	/* Set up IQ ISM registers and structures */
	ism_addr = (cnxk_ep_bb_vf->ism_buffer_mz->iova | CNXK_EP_ISM_EN
		    | CNXK_EP_ISM_MSIX_DIS)
		    + CNXK_EP_IQ_ISM_OFFSET(iq_no);
	rte_write64(ism_addr, (uint8_t *)cnxk_ep_bb_vf->hw_addr +
		    CNXK_EP_R_IN_CNTS_ISM(iq_no));
	iq->inst_cnt_ism =
		(uint32_t *)((uint8_t *)cnxk_ep_bb_vf->ism_buffer_mz->addr
			     + CNXK_EP_IQ_ISM_OFFSET(iq_no));
	cnxk_ep_bb_err("SDP_R[%d] INST Q ISM virt: %p, dma: %p", iq_no,
		   (void *)iq->inst_cnt_ism, (void *)ism_addr);
	*iq->inst_cnt_ism = 0;
	iq->inst_cnt_ism_prev = 0;

	return 0;
}

static int
cnxk_ep_bb_vf_setup_oq_regs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t oq_no)
{
	volatile uint64_t reg_val = 0ull;
	uint64_t oq_ctl = 0ull;
	struct cnxk_ep_bb_droq *droq = cnxk_ep_bb_vf->droq[oq_no];
	uint64_t ism_addr;

	/* Wait on IDLE to set to 1, supposed to configure BADDR
	 * as log as IDLE is 0
	 */
	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_OUT_CONTROL(oq_no));

	while (!(reg_val & CNXK_EP_R_OUT_CTL_IDLE)) {
		reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_OUT_CONTROL(oq_no));
	}

	oct_ep_write64(droq->desc_ring_dma, cnxk_ep_bb_vf->hw_addr +
			CNXK_EP_R_OUT_SLIST_BADDR(oq_no));
	oct_ep_write64(droq->nb_desc, cnxk_ep_bb_vf->hw_addr +
			CNXK_EP_R_OUT_SLIST_RSIZE(oq_no));

	oq_ctl = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
			CNXK_EP_R_OUT_CONTROL(oq_no));

	/* Clear the ISIZE and BSIZE (22-0) */
	oq_ctl &= ~(CNXK_EP_BB_CLEAR_ISIZE_BSIZE);

	/* Populate the BSIZE (15-0) */
	oq_ctl |= (droq->buffer_size & CNXK_EP_BB_DROQ_BUFSZ_MASK);

	oct_ep_write64(oq_ctl, cnxk_ep_bb_vf->hw_addr +
			CNXK_EP_R_OUT_CONTROL(oq_no));

	/* Mapped address of the pkt_sent and pkts_credit regs */
	droq->pkts_sent_reg = (uint8_t *)cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_OUT_CNTS(oq_no);
	droq->pkts_credit_reg = (uint8_t *)cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_OUT_SLIST_DBELL(oq_no);

	rte_write64(CNXK_EP_BB_CLEAR_OUT_INT_LVLS,
			cnxk_ep_bb_vf->hw_addr + CNXK_EP_R_OUT_INT_LEVELS(oq_no));

	/* Clear PKT_CNT register */
	rte_write64(CNXK_EP_BB_CLEAR_SDP_OUT_PKT_CNT, (uint8_t *)cnxk_ep_bb_vf->hw_addr +
			CNXK_EP_R_OUT_PKT_CNT(oq_no));

	/* Clear the OQ doorbell  */
	rte_write32(CNXK_EP_BB_CLEAR_SLIST_DBELL, droq->pkts_credit_reg);
	while ((rte_read32(droq->pkts_credit_reg) != 0ull)) {
		rte_write32(CNXK_EP_BB_CLEAR_SLIST_DBELL, droq->pkts_credit_reg);
		rte_delay_ms(1);
	}
	cnxk_ep_bb_dbg("SDP_R[%d]_credit:%x", oq_no,
			rte_read32(droq->pkts_credit_reg));

	/* Clear the OQ_OUT_CNTS doorbell  */
	reg_val = rte_read32(droq->pkts_sent_reg);
	rte_write32((uint32_t)reg_val, droq->pkts_sent_reg);

	cnxk_ep_bb_dbg("SDP_R[%d]_sent: %x", oq_no,
			rte_read32(droq->pkts_sent_reg));
	/* Set up ISM registers and structures */
	ism_addr = (cnxk_ep_bb_vf->ism_buffer_mz->iova | CNXK_EP_ISM_EN
			| CNXK_EP_ISM_MSIX_DIS)
			+ CNXK_EP_OQ_ISM_OFFSET(oq_no);
	rte_write64(ism_addr, (uint8_t *)cnxk_ep_bb_vf->hw_addr +
			CNXK_EP_R_OUT_CNTS_ISM(oq_no));
	droq->pkts_sent_ism =
			(uint32_t *)((uint8_t *)cnxk_ep_bb_vf->ism_buffer_mz->addr
			+ CNXK_EP_OQ_ISM_OFFSET(oq_no));
	cnxk_ep_bb_err("SDP_R[%d] OQ ISM virt: %p, dma: %p", oq_no,
		(void *)droq->pkts_sent_ism, (void *)ism_addr);
	*droq->pkts_sent_ism = 0;
	droq->pkts_sent_ism_prev = 0;

	while (((rte_read32(droq->pkts_sent_reg)) != 0ull)) {
		reg_val = rte_read32(droq->pkts_sent_reg);
		rte_write32((uint32_t)reg_val, droq->pkts_sent_reg);
		rte_delay_ms(1);
	}
	cnxk_ep_bb_dbg("SDP_R[%d]_sent: %x", oq_no,
			rte_read32(droq->pkts_sent_reg));

	return 0;
}

static int
cnxk_ep_bb_vf_enable_iq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no)
{
	uint64_t loop = CNXK_EP_BB_BUSY_LOOP_COUNT;
	uint64_t reg_val = 0ull;

	/* Resetting doorbells during IQ enabling also to handle abrupt
	 * guest reboot. IQ reset does not clear the doorbells.
	 */
	oct_ep_write64(0xFFFFFFFF, cnxk_ep_bb_vf->hw_addr +
		     CNXK_EP_R_IN_INSTR_DBELL(q_no));

	while (((oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
		 CNXK_EP_R_IN_INSTR_DBELL(q_no))) != 0ull) && loop--) {
		rte_delay_ms(1);
	}

	if (!loop) {
		cnxk_ep_bb_err("INSTR DBELL not coming back to 0\n");
		return -EIO;
	}

	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr + CNXK_EP_R_IN_ENABLE(q_no));
	reg_val |= 0x1ull;

	oct_ep_write64(reg_val, cnxk_ep_bb_vf->hw_addr + CNXK_EP_R_IN_ENABLE(q_no));

	cnxk_ep_bb_info("IQ[%d] enable done", q_no);

	return 0;
}

static int
cnxk_ep_bb_vf_enable_oq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no)
{
	uint64_t reg_val = 0ull;

	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_OUT_ENABLE(q_no));
	reg_val |= 0x1ull;
	oct_ep_write64(reg_val, cnxk_ep_bb_vf->hw_addr +
		       CNXK_EP_R_OUT_ENABLE(q_no));

	cnxk_ep_bb_info("OQ[%d] enable done", q_no);

	return 0;
}

static int
cnxk_ep_bb_vf_enable_io_queues(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	uint32_t q_no = 0;
	int ret;

	for (q_no = 0; q_no < cnxk_ep_bb_vf->nb_tx_queues; q_no++) {
		ret = cnxk_ep_bb_vf_enable_iq(cnxk_ep_bb_vf, q_no);
		if (ret)
			return ret;
	}

	for (q_no = 0; q_no < cnxk_ep_bb_vf->nb_rx_queues; q_no++)
		cnxk_ep_bb_vf_enable_oq(cnxk_ep_bb_vf, q_no);

	return 0;
}

static void
cnxk_ep_bb_vf_disable_iq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no)
{
	uint64_t reg_val = 0ull;

	/* Reset the doorbell register for this Input Queue. */
	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr + CNXK_EP_R_IN_ENABLE(q_no));
	reg_val &= ~0x1ull;

	oct_ep_write64(reg_val, cnxk_ep_bb_vf->hw_addr + CNXK_EP_R_IN_ENABLE(q_no));
}

static void
cnxk_ep_bb_vf_disable_oq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no)
{
	volatile uint64_t reg_val = 0ull;

	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_R_OUT_ENABLE(q_no));
	reg_val &= ~0x1ull;

	oct_ep_write64(reg_val, cnxk_ep_bb_vf->hw_addr +
		       CNXK_EP_R_OUT_ENABLE(q_no));
}

static void
cnxk_ep_bb_vf_disable_io_queues(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	uint32_t q_no = 0;

	for (q_no = 0; q_no < cnxk_ep_bb_vf->sriov_info.rings_per_vf; q_no++) {
		cnxk_ep_bb_vf_disable_iq(cnxk_ep_bb_vf, q_no);
		cnxk_ep_bb_vf_disable_oq(cnxk_ep_bb_vf, q_no);
	}
}

static const struct cnxk_ep_bb_config default_cnxk_ep_bb_conf = {
	/* IQ attributes */
	.iq                        = {
		.max_iqs           = CNXK_EP_BB_CFG_IO_QUEUES,
		.instr_type        = CNXK_EP_BB_64BYTE_INSTR,
		.pending_list_size = (CNXK_EP_BB_MAX_IQ_DESCRIPTORS *
				      CNXK_EP_BB_CFG_IO_QUEUES),
	},

	/* OQ attributes */
	.oq                        = {
		.max_oqs           = CNXK_EP_BB_CFG_IO_QUEUES,
		.info_ptr          = CNXK_EP_BB_OQ_INFOPTR_MODE,
		.refill_threshold  = CNXK_EP_BB_OQ_REFIL_THRESHOLD,
	},

	.num_iqdef_descs           = CNXK_EP_BB_MAX_IQ_DESCRIPTORS,
	.num_oqdef_descs           = CNXK_EP_BB_MAX_OQ_DESCRIPTORS,
	.oqdef_buf_size            = CNXK_EP_BB_OQ_BUF_SIZE,
};

static const struct cnxk_ep_bb_config*
cnxk_ep_bb_get_defconf(struct cnxk_ep_bb_device *cnxk_ep_bb_dev __rte_unused)
{
	const struct cnxk_ep_bb_config *default_conf = NULL;

	default_conf = &default_cnxk_ep_bb_conf;

	return default_conf;
}

static int
cnxk_ep_bb_register_interrupt(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
		rte_intr_callback_fn cb, void *data, unsigned int vec)
{
	int rc = -1;

	rc = cnxk_ep_bb_register_irq(cnxk_ep_bb_vf, cb, data, vec);
	return rc;
}

static int
cnxk_ep_bb_unregister_interrupt(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
		rte_intr_callback_fn cb, void *data)
{
	int rc = -1;

	rc = cnxk_ep_bb_unregister_irq(cnxk_ep_bb_vf, cb, data);
	return rc;
}

int
cnxk_ep_bb_vf_setup_device(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	uint64_t reg_val = 0ull;

	/* If application doesn't provide its conf, use driver default conf */
	if (cnxk_ep_bb_vf->conf == NULL) {
		cnxk_ep_bb_vf->conf = cnxk_ep_bb_get_defconf(cnxk_ep_bb_vf);
		if (cnxk_ep_bb_vf->conf == NULL) {
			cnxk_ep_bb_err("SDP VF default config not found");
			return -ENOENT;
		}
		cnxk_ep_bb_info("Default config is used");
	}

	/* Get IOQs (RPVF] count */
	reg_val = oct_ep_read64(cnxk_ep_bb_vf->hw_addr + CNXK_EP_R_IN_CONTROL(0));

	cnxk_ep_bb_vf->sriov_info.rings_per_vf =
		((reg_val >> CNXK_EP_R_IN_CTL_RPVF_POS) &
		 CNXK_EP_R_IN_CTL_RPVF_MASK);

	cnxk_ep_bb_info("SDP RPVF: %d", cnxk_ep_bb_vf->sriov_info.rings_per_vf);

	cnxk_ep_bb_vf->fn_list.setup_iq_regs		= cnxk_ep_bb_vf_setup_iq_regs;
	cnxk_ep_bb_vf->fn_list.setup_oq_regs		= cnxk_ep_bb_vf_setup_oq_regs;

	cnxk_ep_bb_vf->fn_list.setup_device_regs	= cnxk_ep_bb_vf_setup_device_regs;

	cnxk_ep_bb_vf->fn_list.enable_io_queues		= cnxk_ep_bb_vf_enable_io_queues;
	cnxk_ep_bb_vf->fn_list.disable_io_queues	= cnxk_ep_bb_vf_disable_io_queues;

	cnxk_ep_bb_vf->fn_list.enable_iq		= cnxk_ep_bb_vf_enable_iq;
	cnxk_ep_bb_vf->fn_list.disable_iq		= cnxk_ep_bb_vf_disable_iq;

	cnxk_ep_bb_vf->fn_list.enable_oq		= cnxk_ep_bb_vf_enable_oq;
	cnxk_ep_bb_vf->fn_list.disable_oq		= cnxk_ep_bb_vf_disable_oq;
	cnxk_ep_bb_vf->fn_list.register_interrupt	= cnxk_ep_bb_register_interrupt;
	cnxk_ep_bb_vf->fn_list.unregister_interrupt	= cnxk_ep_bb_unregister_interrupt;

	return 0;
}
