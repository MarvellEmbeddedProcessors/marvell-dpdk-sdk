/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <rte_spinlock.h>
#include <rte_interrupts.h>

#include "otx_ep_common.h"
#include "otx_ep_vf.h"

static int
otx_ep_setup_global_iq_reg(struct otx_ep_device *otx_ep, int q_no)
{
	volatile uint64_t reg_val = 0ull;
	int loop = OTX_EP_BUSY_LOOP_COUNT;

	/* Select ES, RO, NS, RDSIZE,DPTR Format#0 for IQs
	 * IS_64B is by default enabled.
	 */
	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_IN_CONTROL(q_no));

	reg_val |= OTX_EP_R_IN_CTL_RDSIZE;
	reg_val |= OTX_EP_R_IN_CTL_IS_64B;
	reg_val |= OTX_EP_R_IN_CTL_ESR;

	otx_ep_write64(reg_val, otx_ep->hw_addr, OTX_EP_R_IN_CONTROL(q_no));
	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_IN_CONTROL(q_no));

	if (!(reg_val & OTX_EP_R_IN_CTL_IDLE)) {
		do {
			reg_val = rte_read64(otx_ep->hw_addr +
					      OTX_EP_R_IN_CONTROL(q_no));
		} while (!(reg_val & OTX_EP_R_IN_CTL_IDLE) && loop--);
		if (loop < 0)
			return -EIO;
	}
	return 0;
}

static void
otx_ep_setup_global_oq_reg(struct otx_ep_device *otx_ep, int q_no)
{
	volatile uint64_t reg_val = 0ull;

	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_OUT_CONTROL(q_no));

	reg_val &= ~(OTX_EP_R_OUT_CTL_IMODE);
	reg_val &= ~(OTX_EP_R_OUT_CTL_ROR_P);
	reg_val &= ~(OTX_EP_R_OUT_CTL_NSR_P);
	reg_val &= ~(OTX_EP_R_OUT_CTL_ROR_I);
	reg_val &= ~(OTX_EP_R_OUT_CTL_NSR_I);
	reg_val &= ~(OTX_EP_R_OUT_CTL_ES_I);
	reg_val &= ~(OTX_EP_R_OUT_CTL_ROR_D);
	reg_val &= ~(OTX_EP_R_OUT_CTL_NSR_D);
	reg_val &= ~(OTX_EP_R_OUT_CTL_ES_D);

	/* INFO/DATA ptr swap is required  */
	reg_val |= (OTX_EP_R_OUT_CTL_ES_P);

	otx_ep_write64(reg_val, otx_ep->hw_addr, OTX_EP_R_OUT_CONTROL(q_no));
}

static int
otx_ep_setup_global_input_regs(struct otx_ep_device *otx_ep)
{
	uint64_t q_no = 0ull;
	int ret = 0;

	for (q_no = 0; q_no < (otx_ep->sriov_info.rings_per_vf); q_no++) {
		ret = otx_ep_setup_global_iq_reg(otx_ep, q_no);
		if (ret)
			return ret;
	}

	return 0;
}

static void
otx_ep_setup_global_output_regs(struct otx_ep_device *otx_ep)
{
	uint32_t q_no;

	for (q_no = 0; q_no < (otx_ep->sriov_info.rings_per_vf); q_no++)
		otx_ep_setup_global_oq_reg(otx_ep, q_no);
}

static int
otx_ep_setup_device_regs(struct otx_ep_device *otx_ep)
{
	int ret;
	ret = otx_ep_setup_global_input_regs(otx_ep);
	if (ret)
		return ret;
	otx_ep_setup_global_output_regs(otx_ep);

	return 0;
}

static int
otx_ep_setup_iq_regs(struct otx_ep_device *otx_ep, uint32_t iq_no)
{
	struct otx_ep_instr_queue *iq = otx_ep->instr_queue[iq_no];
	volatile uint64_t reg_val = 0ull;
	int loop = OTX_EP_BUSY_LOOP_COUNT;

	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_IN_CONTROL(iq_no));

	/* Wait till IDLE to set to 1, not supposed to configure BADDR
	 * as long as IDLE is 0
	 */
	if (!(reg_val & OTX_EP_R_IN_CTL_IDLE)) {
		do {
			reg_val = rte_read64(otx_ep->hw_addr +
					      OTX_EP_R_IN_CONTROL(iq_no));
		} while (!(reg_val & OTX_EP_R_IN_CTL_IDLE) && loop--);
		if (loop < 0)
			return -EIO;
	}

	/* Write the start of the input queue's ring and its size  */
	otx_ep_write64(iq->base_addr_dma, otx_ep->hw_addr,
		       OTX_EP_R_IN_INSTR_BADDR(iq_no));
	otx_ep_write64(iq->nb_desc, otx_ep->hw_addr,
		       OTX_EP_R_IN_INSTR_RSIZE(iq_no));

	/* Remember the doorbell & instruction count register addr
	 * for this queue
	 */
	iq->doorbell_reg = (uint8_t *)otx_ep->hw_addr +
			   OTX_EP_R_IN_INSTR_DBELL(iq_no);
	iq->inst_cnt_reg = (uint8_t *)otx_ep->hw_addr +
			   OTX_EP_R_IN_CNTS(iq_no);

	otx_ep_dbg("InstQ[%d]:dbell reg @ 0x%p inst_cnt_reg @ 0x%p\n",
		     iq_no, iq->doorbell_reg, iq->inst_cnt_reg);

	loop = OTX_EP_BUSY_LOOP_COUNT;
	do {
		reg_val = rte_read32(iq->inst_cnt_reg);
		rte_write32(reg_val, iq->inst_cnt_reg);
	} while ((reg_val != 0) && loop--);
	if (loop < 0)
		return -EIO;

	/* IN INTR_THRESHOLD is set to max(FFFFFFFF) which disable the IN INTR
	 * to raise
	 */
	/* reg_val = rte_read64(otx_ep->hw_addr +
	 * OTX_EP_R_IN_INT_LEVELS(iq_no));
	 */
	otx_ep_write64(OTX_EP_CLEAR_IN_INT_LVLS, otx_ep->hw_addr,
		       OTX_EP_R_IN_INT_LEVELS(iq_no));

	return 0;
}

static int
otx_ep_setup_oq_regs(struct otx_ep_device *otx_ep, uint32_t oq_no)
{
	volatile uint64_t reg_val = 0ull;
	uint64_t oq_ctl = 0ull;
	int loop = OTX_EP_BUSY_LOOP_COUNT;

	struct otx_ep_droq *droq = otx_ep->droq[oq_no];

	/* Wait on IDLE to set to 1, supposed to configure BADDR
	 * as log as IDLE is 0
	 */
	otx_ep_write64(0ULL, otx_ep->hw_addr, OTX_EP_R_OUT_ENABLE(oq_no));

	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_OUT_CONTROL(oq_no));

	while (!(reg_val & OTX_EP_R_OUT_CTL_IDLE) && loop--) {
		reg_val = rte_read64(otx_ep->hw_addr +
				      OTX_EP_R_OUT_CONTROL(oq_no));
	}
	if (loop < 0)
		return -EIO;

	otx_ep_write64(droq->desc_ring_dma, otx_ep->hw_addr,
		       OTX_EP_R_OUT_SLIST_BADDR(oq_no));
	otx_ep_write64(droq->nb_desc, otx_ep->hw_addr,
		       OTX_EP_R_OUT_SLIST_RSIZE(oq_no));

	oq_ctl = rte_read64(otx_ep->hw_addr + OTX_EP_R_OUT_CONTROL(oq_no));

	/* Clear the ISIZE and BSIZE (22-0) */
	oq_ctl &= ~(OTX_EP_CLEAR_ISIZE_BSIZE);

	/* Populate the BSIZE (15-0) */
	oq_ctl |= (droq->buffer_size & OTX_EP_DROQ_BUFSZ_MASK);

	otx_ep_write64(oq_ctl, otx_ep->hw_addr, OTX_EP_R_OUT_CONTROL(oq_no));

	/* Mapped address of the pkt_sent and pkts_credit regs */
	droq->pkts_sent_reg = (uint8_t *)otx_ep->hw_addr +
			      OTX_EP_R_OUT_CNTS(oq_no);
	droq->pkts_credit_reg = (uint8_t *)otx_ep->hw_addr +
				OTX_EP_R_OUT_SLIST_DBELL(oq_no);

	otx_ep_write64(OTX_EP_CLEAR_OUT_INT_LVLS, otx_ep->hw_addr,
		       OTX_EP_R_OUT_INT_LEVELS(oq_no));

	/* Clear the OQ doorbell  */
	loop = OTX_EP_BUSY_LOOP_COUNT;
	rte_write32(OTX_EP_CLEAR_SLIST_DBELL, droq->pkts_credit_reg);
	while ((rte_read32(droq->pkts_credit_reg) != 0ull) && loop--) {
		rte_write32(OTX_EP_CLEAR_SLIST_DBELL, droq->pkts_credit_reg);
		rte_delay_ms(1);
	}
	if (loop < 0)
		return -EIO;
	otx_ep_dbg("OTX_EP_R[%d]_credit:%x\n", oq_no,
		     rte_read32(droq->pkts_credit_reg));

	/* Clear the OQ_OUT_CNTS doorbell  */
	reg_val = rte_read32(droq->pkts_sent_reg);
	rte_write32((uint32_t)reg_val, droq->pkts_sent_reg);

	otx_ep_dbg("OTX_EP_R[%d]_sent: %x\n", oq_no,
		     rte_read32(droq->pkts_sent_reg));

	loop = OTX_EP_BUSY_LOOP_COUNT;
	while (((rte_read32(droq->pkts_sent_reg)) != 0ull) && loop--) {
		reg_val = rte_read32(droq->pkts_sent_reg);
		rte_write32((uint32_t)reg_val, droq->pkts_sent_reg);
		rte_delay_ms(1);
	}
	if (loop < 0)
		return -EIO;

	return 0;
}

static int
otx_ep_enable_iq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	volatile uint64_t reg_val = 0ull;
	int loop = OTX_EP_BUSY_LOOP_COUNT;

	/* Resetting doorbells during IQ enabling also to handle abrupt
	 * guest reboot. IQ reset does not clear the doorbells.
	 */
	otx_ep_write64(0xFFFFFFFF, otx_ep->hw_addr,
		       OTX_EP_R_IN_INSTR_DBELL(q_no));

	while (((rte_read64(otx_ep->hw_addr +
		 OTX_EP_R_IN_INSTR_DBELL(q_no))) != 0ull) && loop--) {
		rte_delay_ms(1);
	}

	if (loop < 0) {
		otx_ep_err("dbell reset failed\n");
		return -EIO;
	}


	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_IN_ENABLE(q_no));
	reg_val |= 0x1ull;

	otx_ep_write64(reg_val, otx_ep->hw_addr, OTX_EP_R_IN_ENABLE(q_no));

	otx_ep_info("IQ[%d] enable done\n", q_no);

	return 0;
}

static int
otx_ep_enable_oq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	volatile uint64_t reg_val = 0ull;
	int loop = OTX_EP_BUSY_LOOP_COUNT;

	/* Resetting doorbells during IQ enabling also to handle abrupt
	 * guest reboot. IQ reset does not clear the doorbells.
	 */
	otx_ep_write64(0xFFFFFFFF, otx_ep->hw_addr,
		       OTX_EP_R_OUT_SLIST_DBELL(q_no));
	while (((rte_read64(otx_ep->hw_addr +
		 OTX_EP_R_OUT_SLIST_DBELL(q_no))) != 0ull) && loop--) {
		rte_delay_ms(1);
	}

	if (loop < 0) {
		otx_ep_err("dbell reset failed\n");
		return -EIO;
	}


	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_OUT_ENABLE(q_no));
	reg_val |= 0x1ull;
	otx_ep_write64(reg_val, otx_ep->hw_addr, OTX_EP_R_OUT_ENABLE(q_no));

	otx_ep_info("OQ[%d] enable done\n", q_no);

	return 0;
}

static int
otx_ep_enable_io_queues(struct otx_ep_device *otx_ep)
{
	uint32_t q_no = 0;
	int ret;

	for (q_no = 0; q_no < otx_ep->nb_tx_queues; q_no++) {
		ret = otx_ep_enable_iq(otx_ep, q_no);
		if (ret)
			return ret;
	}

	for (q_no = 0; q_no < otx_ep->nb_rx_queues; q_no++) {
		ret = otx_ep_enable_oq(otx_ep, q_no);
		if (ret)
			return ret;
	}

	return 0;
}

static void
otx_ep_disable_iq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	uint64_t reg_val = 0ull;

	/* Reset the doorbell register for this Input Queue. */
	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_IN_ENABLE(q_no));
	reg_val &= ~0x1ull;

	otx_ep_write64(reg_val, otx_ep->hw_addr, OTX_EP_R_IN_ENABLE(q_no));
}

static void
otx_ep_disable_oq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	uint64_t reg_val = 0ull;

	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_OUT_ENABLE(q_no));
	reg_val &= ~0x1ull;

	otx_ep_write64(reg_val, otx_ep->hw_addr, OTX_EP_R_OUT_ENABLE(q_no));
}

static void
otx_ep_disable_io_queues(struct otx_ep_device *otx_ep)
{
	uint32_t q_no = 0;

	for (q_no = 0; q_no < otx_ep->sriov_info.rings_per_vf; q_no++) {
		otx_ep_disable_iq(otx_ep, q_no);
		otx_ep_disable_oq(otx_ep, q_no);
	}
}

/* OTX_EP default configuration */
static const struct otx_ep_config default_otx_ep_conf = {
	/* IQ attributes */
	.iq                        = {
		.max_iqs           = OTX_EP_CFG_IO_QUEUES,
		.instr_type        = OTX_EP_64BYTE_INSTR,
		.pending_list_size = (OTX_EP_MAX_IQ_DESCRIPTORS *
				      OTX_EP_CFG_IO_QUEUES),
	},

	/* OQ attributes */
	.oq                        = {
		.max_oqs           = OTX_EP_CFG_IO_QUEUES,
		.info_ptr          = OTX_EP_OQ_INFOPTR_MODE,
		.refill_threshold  = OTX_EP_OQ_REFIL_THRESHOLD,
	},

	.num_iqdef_descs           = OTX_EP_MAX_IQ_DESCRIPTORS,
	.num_oqdef_descs           = OTX_EP_MAX_OQ_DESCRIPTORS,
	.oqdef_buf_size            = OTX_EP_OQ_BUF_SIZE,

};


static const struct otx_ep_config*
otx_ep_get_defconf(struct otx_ep_device *otx_ep_dev __rte_unused)
{
	const struct otx_ep_config *default_conf = NULL;

	default_conf = &default_otx_ep_conf;

	return default_conf;
}

static int
otx_vf_send_mbox_cmd(struct otx_ep_device *otx_ep,
			 union otx_vf_mbox_word cmd,
			 union otx_vf_mbox_word *rsp)
{
	volatile uint64_t reg_val = 0ull;
	int retry_count = 0;
	int count = 0;

	rsp->u64 = 0;
	cmd.s.type = OTX_VF_MBOX_TYPE_CMD;
	cmd.s.version = OTX_VF_MBOX_VERSION;
	rte_spinlock_lock(&otx_ep->mbox_lock);
	/* only 1 outstanding cmd at a time */
	otx_ep->mbox_cmd_id = ~otx_ep->mbox_cmd_id;
	cmd.s.id = otx_ep->mbox_cmd_id;
retry:
	otx_ep_dbg("send mbox cmd %p\n", (void *)cmd.u64);
	otx_ep_write64(cmd.u64, otx_ep->hw_addr, OTX_EP_R_MBOX_VF_PF_DATA(0));
	for (count = 0; count < OTX_VF_MBOX_TIMEOUT_MS; count++) {
		rte_delay_ms(1);
		reg_val = rte_read64(otx_ep->hw_addr +
				      OTX_EP_R_MBOX_VF_PF_DATA(0));
		if (reg_val != cmd.u64) {
			rsp->u64 = reg_val;
			if (rsp->s.id == cmd.s.id)
				break;
			/* resp for previous cmd. retry */
			retry_count++;
			if (retry_count == OTX_VF_MBOX_MAX_RETRIES)
				break;
			goto retry;
		}
	}
	rte_spinlock_unlock(&otx_ep->mbox_lock);
	if (count == OTX_VF_MBOX_TIMEOUT_MS ||
	    retry_count == OTX_VF_MBOX_MAX_RETRIES) {
		otx_ep_err("mbox timeout failure\n");
		return -ETIMEDOUT;
	}
	rsp->u64 = reg_val;
	otx_ep_dbg("mbox success\n");
	return 0;
}

static int
otx_vf_send_mbox_cmd_nolock(struct otx_ep_device *otx_ep,
			 union otx_vf_mbox_word cmd,
			 union otx_vf_mbox_word *rsp)
{
	volatile uint64_t reg_val = 0ull;
	int retry_count = 0;
	int count = 0;

	rsp->u64 = 0;
	cmd.s.type = OTX_VF_MBOX_TYPE_CMD;
	cmd.s.version = OTX_VF_MBOX_VERSION;
	/* only 1 outstanding cmd at a time */
	otx_ep->mbox_cmd_id = ~otx_ep->mbox_cmd_id;
	cmd.s.id = otx_ep->mbox_cmd_id;
retry:
	otx_ep_dbg("send mbox cmd nolock %p\n", (void *)cmd.u64);
	otx_ep_write64(cmd.u64, otx_ep->hw_addr, OTX_EP_R_MBOX_VF_PF_DATA(0));
	for (count = 0; count < OTX_VF_MBOX_TIMEOUT_MS; count++) {
		rte_delay_ms(1);
		reg_val = rte_read64(otx_ep->hw_addr +
				      OTX_EP_R_MBOX_VF_PF_DATA(0));
		if (reg_val != cmd.u64) {
			rsp->u64 = reg_val;
			if (rsp->s.id == cmd.s.id)
				break;
			/* resp for previous cmd. retry */
			retry_count++;
			if (retry_count == OTX_VF_MBOX_MAX_RETRIES)
				break;
			goto retry;
		}
	}
	if (count == OTX_VF_MBOX_TIMEOUT_MS ||
	    retry_count == OTX_VF_MBOX_MAX_RETRIES) {
		otx_ep_err("mbox timeout failure\n");
		return -ETIMEDOUT;
	}
	rsp->u64 = reg_val;
	otx_ep_dbg("mbox success\n");
	return 0;
}

static void
otx_ep_vf_enable_mbox_interrupt(struct otx_ep_device *otx_ep)
{
	rte_write64(0x2, (uint8_t *)otx_ep->hw_addr +
		   OTX_EP_R_MBOX_PF_VF_INT(0));
}

static void
otx_ep_vf_disable_mbox_interrupt(struct otx_ep_device *otx_ep)
{
	rte_write64(0x00, (uint8_t *)otx_ep->hw_addr +
		   OTX_EP_R_MBOX_PF_VF_INT(0));
}

static int
otx_ep_register_interrupt(struct otx_ep_device *otx_ep,
			rte_intr_callback_fn cb,
			void *data, unsigned int vec)
{
	int rc = -1;

	rc = otx_ep_register_irq(otx_ep, cb, data, vec);
	return rc;
}

static int
otx_ep_unregister_interrupt(struct otx_ep_device *otx_ep,
				rte_intr_callback_fn cb,
				void *data)
{
	int rc = -1;

	rc = otx_ep_unregister_irq(otx_ep, cb, data);
	return rc;
}

int
otx_ep_vf_setup_device(struct otx_ep_device *otx_ep)
{
	uint64_t reg_val = 0ull;

	/* If application doesn't provide its conf, use driver default conf */
	if (otx_ep->conf == NULL) {
		otx_ep->conf = otx_ep_get_defconf(otx_ep);
		if (otx_ep->conf == NULL) {
			otx_ep_err("OTX_EP VF default config not found\n");
			return -ENOENT;
		}
		otx_ep_info("Default config is used\n");
	}

	/* Get IOQs (RPVF] count */
	reg_val = rte_read64(otx_ep->hw_addr + OTX_EP_R_IN_CONTROL(0));

	otx_ep->sriov_info.rings_per_vf = ((reg_val >> OTX_EP_R_IN_CTL_RPVF_POS)
					  & OTX_EP_R_IN_CTL_RPVF_MASK);

	otx_ep_info("OTX_EP RPVF: %d\n", otx_ep->sriov_info.rings_per_vf);

	otx_ep->fn_list.setup_iq_regs       = otx_ep_setup_iq_regs;
	otx_ep->fn_list.setup_oq_regs       = otx_ep_setup_oq_regs;

	otx_ep->fn_list.setup_device_regs   = otx_ep_setup_device_regs;

	otx_ep->fn_list.enable_io_queues    = otx_ep_enable_io_queues;
	otx_ep->fn_list.disable_io_queues   = otx_ep_disable_io_queues;

	otx_ep->fn_list.enable_iq           = otx_ep_enable_iq;
	otx_ep->fn_list.disable_iq          = otx_ep_disable_iq;

	otx_ep->fn_list.enable_oq           = otx_ep_enable_oq;
	otx_ep->fn_list.disable_oq          = otx_ep_disable_oq;

	otx_ep->fn_list.send_mbox_cmd       =  otx_vf_send_mbox_cmd;
	otx_ep->fn_list.send_mbox_cmd_nolock    = otx_vf_send_mbox_cmd_nolock;

	otx_ep->fn_list.enable_mbox_interrupt   = otx_ep_vf_enable_mbox_interrupt;
	otx_ep->fn_list.disable_mbox_interrupt  = otx_ep_vf_disable_mbox_interrupt;
	otx_ep->fn_list.register_interrupt        = otx_ep_register_interrupt;
	otx_ep->fn_list.unregister_interrupt      = otx_ep_unregister_interrupt;
	return 0;
}
