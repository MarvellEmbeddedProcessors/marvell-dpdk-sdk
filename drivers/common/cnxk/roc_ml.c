/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

#define TIME_SEC_IN_MS 1000

#define ROC_ML_DEV_NAME	    "roc_ml_dev_"
#define ROC_ML_DEV_NAME_LEN (128)

#define RVU_BLOCK_ADDR_E_BGENX(a) (0x20 + 8 * (a))

uint16_t
roc_ml_pf_func_get(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct dev *dev = &ml->dev;

	return dev->pf_func;
}

bool
roc_ml_is_pf(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	return !dev_is_vf(&ml->dev);
}

int
roc_ml_get_pf(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct dev *dev = &ml->dev;

	return dev_get_pf(dev->pf_func);
}

int
roc_ml_get_vf(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct dev *dev = &ml->dev;

	return dev_get_vf(dev->pf_func);
}

static int
roc_ml_af_reg_read64(struct roc_ml *roc_ml, uint64_t reg, uint64_t *val)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct ml_rd_wr_reg_msg *msg;
	struct dev *dev = &ml->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	int rc;

	msg = mbox_alloc_msg_ml_rd_wr_register(mbox);
	if (msg == NULL) {
		rc = -EIO;
		goto exit;
	}

	msg->hdr.pcifunc = dev->pf_func;

	msg->is_write = 0;
	msg->reg_offset = reg;
	msg->ret_val = val;

	rc = mbox_process_msg(dev->mbox, (void *)&msg);
	if (rc) {
		rc = -EIO;
		goto exit;
	}

	*val = msg->val;

	rc = 0;
exit:
	mbox_put(mbox);

	return rc;
}

static int
roc_ml_af_reg_write64(struct roc_ml *roc_ml, uint64_t reg, uint64_t val)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct ml_rd_wr_reg_msg *msg;
	struct dev *dev = &ml->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	int rc;

	msg = mbox_alloc_msg_ml_rd_wr_register(mbox);
	if (msg == NULL) {
		rc = -EIO;
		goto exit;
	}

	msg->hdr.pcifunc = dev->pf_func;

	msg->is_write = 1;
	msg->reg_offset = reg;
	msg->val = val;

	rc = mbox_process_msg(dev->mbox, (void *)&msg);
	if (rc) {
		rc = -EIO;
		goto exit;
	}

	rc = 0;
exit:
	mbox_put(mbox);

	return rc;
}

uint64_t
roc_ml_lf_reg_read64(struct roc_ml_lf *lf, uint64_t offset)
{
	return plt_read64(lf->rbase + offset);
}

void
roc_ml_lf_reg_write64(struct roc_ml_lf *lf, uint64_t val, uint64_t offset)
{
	plt_write64(val, lf->rbase + offset);
}

static uint64_t
roc_ml_reg_read64_cnxk(struct roc_ml *roc_ml, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	return plt_read64(PLT_PTR_ADD(ml->ml_reg_addr, offset));
}

static void
roc_ml_reg_write64_cnxk(struct roc_ml *roc_ml, uint64_t val, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	plt_write64(val, PLT_PTR_ADD(ml->ml_reg_addr, offset));
}

static uint64_t
roc_ml_reg_read64_cn20ka(struct roc_ml *roc_ml, uint64_t offset)
{
	uint64_t val = 0;

	roc_ml_af_reg_read64(roc_ml, offset, &val);

	return val;
}

static void
roc_ml_reg_write64_cn20ka(struct roc_ml *roc_ml, uint64_t val, uint64_t offset)
{
	roc_ml_af_reg_write64(roc_ml, offset, val);
}

uint64_t
roc_ml_reg_read64(struct roc_ml *roc_ml, uint64_t offset)
{
	return roc_ml->reg_read64(roc_ml, offset);
}

void
roc_ml_reg_write64(struct roc_ml *roc_ml, uint64_t val, uint64_t offset)
{
	roc_ml->reg_write64(roc_ml, val, offset);
}

static int
roc_ml_reg_wait_to_clear(struct roc_ml *roc_ml, uint64_t offset, uint64_t mask)
{
	uint64_t start_cycle;
	uint64_t wait_cycles;
	uint64_t reg_val;

	wait_cycles = (ROC_ML_TIMEOUT_MS * plt_tsc_hz()) / TIME_SEC_IN_MS;
	start_cycle = plt_tsc_cycles();
	do {
		reg_val = roc_ml_reg_read64(roc_ml, offset);

		if (!(reg_val & mask))
			return 0;
	} while (plt_tsc_cycles() - start_cycle < wait_cycles);

	return -ETIME;
}

uint32_t
roc_ml_reg_read32(struct roc_ml *roc_ml, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	return plt_read32(PLT_PTR_ADD(ml->ml_reg_addr, offset));
}

void
roc_ml_reg_write32(struct roc_ml *roc_ml, uint32_t val, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	plt_write32(val, PLT_PTR_ADD(ml->ml_reg_addr, offset));
}

void
roc_ml_reg_save(struct roc_ml *roc_ml, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	if (offset == roc_ml->mlr_base) {
		ml->ml_mlr_base =
			FIELD_GET(ROC_ML_MLR_BASE_BASE, roc_ml_reg_read64(roc_ml, offset));
		ml->ml_mlr_base_saved = true;
	}
}

void *
roc_ml_addr_ap2mlip(struct roc_ml *roc_ml, void *addr)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	uint64_t ml_mlr_base;

	if (ml->ml_mlr_base_saved)
		ml_mlr_base = ml->ml_mlr_base;
	else
		ml_mlr_base = FIELD_GET(ROC_ML_MLR_BASE_BASE,
					roc_ml_reg_read64(roc_ml, roc_ml->mlr_base));

	return PLT_PTR_ADD(addr, ML_AXI_START_ADDR - ml_mlr_base);
}

void *
roc_ml_addr_mlip2ap(struct roc_ml *roc_ml, void *addr)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	uint64_t ml_mlr_base;

	if (ml->ml_mlr_base_saved)
		ml_mlr_base = ml->ml_mlr_base;
	else
		ml_mlr_base = FIELD_GET(ROC_ML_MLR_BASE_BASE,
					roc_ml_reg_read64(roc_ml, roc_ml->mlr_base));

	return PLT_PTR_ADD(addr, ml_mlr_base - ML_AXI_START_ADDR);
}

uint64_t
roc_ml_addr_pa_to_offset(struct roc_ml *roc_ml, uint64_t phys_addr)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	if (roc_model_is_cn10ka())
		return phys_addr - ml->pci_dev->mem_resource[0].phys_addr;
	else
		return phys_addr - ml->pci_dev->mem_resource[0].phys_addr - MLAB_BLK_OFFSET_CNF10KB;
}

uint64_t
roc_ml_addr_offset_to_pa(struct roc_ml *roc_ml, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	if (roc_model_is_cn10ka())
		return ml->pci_dev->mem_resource[0].phys_addr + offset;
	else
		return ml->pci_dev->mem_resource[0].phys_addr + MLAB_BLK_OFFSET_CNF10KB + offset;
}

void
roc_ml_scratch_write_job(struct roc_ml *roc_ml, void *work_ptr)
{
	union ml_scratch_work_ptr_s reg_work_ptr;
	union ml_scratch_fw_ctrl_s reg_fw_ctrl;

	reg_work_ptr.u64 = 0;
	reg_work_ptr.s.work_ptr = PLT_U64_CAST(roc_ml_addr_ap2mlip(roc_ml, work_ptr));

	reg_fw_ctrl.u64 = 0;
	reg_fw_ctrl.s.valid = 1;

	roc_ml_reg_write64(roc_ml, reg_work_ptr.u64, ML_SCRATCH_WORK_PTR);
	roc_ml_reg_write64(roc_ml, reg_fw_ctrl.u64, ML_SCRATCH_FW_CTRL);
}

bool
roc_ml_scratch_is_valid_bit_set(struct roc_ml *roc_ml)
{
	union ml_scratch_fw_ctrl_s reg_fw_ctrl;

	reg_fw_ctrl.u64 = roc_ml_reg_read64(roc_ml, ML_SCRATCH_FW_CTRL);

	if (reg_fw_ctrl.s.valid == 1)
		return true;

	return false;
}

bool
roc_ml_scratch_is_done_bit_set(struct roc_ml *roc_ml)
{
	union ml_scratch_fw_ctrl_s reg_fw_ctrl;

	reg_fw_ctrl.u64 = roc_ml_reg_read64(roc_ml, ML_SCRATCH_FW_CTRL);

	if (reg_fw_ctrl.s.done == 1)
		return true;

	return false;
}

bool
roc_ml_scratch_enqueue(struct roc_ml *roc_ml, void *work_ptr)
{
	union ml_scratch_work_ptr_s reg_work_ptr;
	union ml_scratch_fw_ctrl_s reg_fw_ctrl;
	bool ret = false;

	reg_work_ptr.u64 = 0;
	reg_work_ptr.s.work_ptr = PLT_U64_CAST(roc_ml_addr_ap2mlip(roc_ml, work_ptr));

	reg_fw_ctrl.u64 = 0;
	reg_fw_ctrl.s.valid = 1;

	if (plt_spinlock_trylock(&roc_ml->sp_spinlock) != 0) {
		bool valid = roc_ml_scratch_is_valid_bit_set(roc_ml);
		bool done = roc_ml_scratch_is_done_bit_set(roc_ml);

		if (valid == done) {
			roc_ml_clk_force_on(roc_ml);
			roc_ml_dma_stall_off(roc_ml);

			roc_ml_reg_write64(roc_ml, reg_work_ptr.u64, ML_SCRATCH_WORK_PTR);
			roc_ml_reg_write64(roc_ml, reg_fw_ctrl.u64, ML_SCRATCH_FW_CTRL);

			ret = true;
		}
		plt_spinlock_unlock(&roc_ml->sp_spinlock);
	}

	return ret;
}

bool
roc_ml_scratch_dequeue(struct roc_ml *roc_ml, void *work_ptr)
{
	union ml_scratch_work_ptr_s reg_work_ptr;
	bool ret = false;

	if (plt_spinlock_trylock(&roc_ml->sp_spinlock) != 0) {
		bool valid = roc_ml_scratch_is_valid_bit_set(roc_ml);
		bool done = roc_ml_scratch_is_done_bit_set(roc_ml);

		if (valid && done) {
			reg_work_ptr.u64 = roc_ml_reg_read64(roc_ml, ML_SCRATCH_WORK_PTR);
			if (work_ptr ==
			    roc_ml_addr_mlip2ap(roc_ml, PLT_PTR_CAST(reg_work_ptr.u64))) {
				roc_ml_dma_stall_on(roc_ml);
				roc_ml_clk_force_off(roc_ml);

				roc_ml_reg_write64(roc_ml, 0, ML_SCRATCH_WORK_PTR);
				roc_ml_reg_write64(roc_ml, 0, ML_SCRATCH_FW_CTRL);
				ret = true;
			}
		}
		plt_spinlock_unlock(&roc_ml->sp_spinlock);
	}

	return ret;
}

void
roc_ml_scratch_queue_reset(struct roc_ml *roc_ml)
{
	if (plt_spinlock_trylock(&roc_ml->sp_spinlock) != 0) {
		roc_ml_dma_stall_on(roc_ml);
		roc_ml_clk_force_off(roc_ml);
		roc_ml_reg_write64(roc_ml, 0, ML_SCRATCH_WORK_PTR);
		roc_ml_reg_write64(roc_ml, 0, ML_SCRATCH_FW_CTRL);
		plt_spinlock_unlock(&roc_ml->sp_spinlock);
	}
}

bool
roc_ml_jcmdq_enqueue_nolock(struct roc_ml *roc_ml, struct ml_job_cmd_s *job_cmd)
{
	bool ret = false;

	if (FIELD_GET(ROC_ML_JCMDQ_STATUS_AVAIL_COUNT,
		      roc_ml_reg_read64(roc_ml, ML_JCMDQ_STATUS)) != 0) {
		roc_ml_reg_write64(roc_ml, job_cmd->w0.u64, ML_JCMDQ_INX(0));
		roc_ml_reg_write64(roc_ml, job_cmd->w1.u64, ML_JCMDQ_INX(1));
		ret = true;
	}

	return ret;
}

bool
roc_ml_jcmdq_enqueue_splock(struct roc_ml *roc_ml, struct ml_job_cmd_s *job_cmd)
{
	bool ret = false;

	if (plt_spinlock_trylock(&roc_ml->fp_spinlock) != 0) {
		if (FIELD_GET(ROC_ML_JCMDQ_STATUS_AVAIL_COUNT,
			      roc_ml_reg_read64(roc_ml, ML_JCMDQ_STATUS)) != 0) {
			roc_ml_reg_write64(roc_ml, job_cmd->w0.u64, ML_JCMDQ_INX(0));
			roc_ml_reg_write64(roc_ml, job_cmd->w1.u64, ML_JCMDQ_INX(1));
			ret = true;
		}
		plt_spinlock_unlock(&roc_ml->fp_spinlock);
	}

	return ret;
}

void
roc_ml_clk_force_on(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	reg_val = roc_ml_reg_read64(roc_ml, roc_ml->cfg);
	reg_val |= ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(roc_ml, reg_val, roc_ml->cfg);
}

void
roc_ml_clk_force_off(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	roc_ml_reg_write64(roc_ml, 0, ML_SCRATCH_WORK_PTR);

	reg_val = roc_ml_reg_read64(roc_ml, roc_ml->cfg);
	reg_val &= ~ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(roc_ml, reg_val, roc_ml->cfg);
}

void
roc_ml_dma_stall_on(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	reg_val = roc_ml_reg_read64(roc_ml, roc_ml->job_mgr_ctrl);
	reg_val |= ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(roc_ml, reg_val, roc_ml->job_mgr_ctrl);
}

void
roc_ml_dma_stall_off(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	reg_val = roc_ml_reg_read64(roc_ml, roc_ml->job_mgr_ctrl);
	reg_val &= ~ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(roc_ml, reg_val, roc_ml->job_mgr_ctrl);
}

bool
roc_ml_mlip_is_enabled(struct roc_ml *roc_ml)
{
	uint64_t reg_val;

	reg_val = roc_ml_reg_read64(roc_ml, roc_ml->cfg);
	if ((reg_val & ROC_ML_CFG_MLIP_ENA) != 0)
		return true;

	return false;
}

int
roc_ml_mlip_reset(struct roc_ml *roc_ml, bool force)
{
	uint64_t reg_val;

	/* Force reset */
	if (force) {
		/* Set CFG[ENA] = 0. */
		reg_val = roc_ml_reg_read64(roc_ml, roc_ml->cfg);
		reg_val &= ~ROC_ML_CFG_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, roc_ml->cfg);

		/* Set CFG[MLIP_ENA] = 0. */
		reg_val = roc_ml_reg_read64(roc_ml, roc_ml->cfg);
		reg_val &= ~ROC_ML_CFG_MLIP_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, roc_ml->cfg);

		/* Clear MLR_BASE */
		roc_ml_reg_write64(roc_ml, 0, roc_ml->mlr_base);
	}

	if (roc_model_is_cn10ka()) {
		/* Wait for all active jobs to finish.
		 * ML_CFG[ENA] : When set, MLW will accept job commands. This
		 * bit can be cleared at any time. If [BUSY] is set, software
		 * must wait until [BUSY] == 0 before setting this bit.
		 */
		roc_ml_reg_wait_to_clear(roc_ml, ML_CFG, ROC_ML_CFG_BUSY);

		/* (1) Set ML(0)_AXI_BRIDGE_CTRL(0..1)[FENCE] = 1 to instruct
		 * the AXI bridge not to accept any new transactions from MLIP.
		 */
		reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRLX(0));
		reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FENCE;
		roc_ml_reg_write64(roc_ml, reg_val, ML_AXI_BRIDGE_CTRLX(0));

		reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRLX(1));
		reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FENCE;
		roc_ml_reg_write64(roc_ml, reg_val, ML_AXI_BRIDGE_CTRLX(1));

		/* (2) Wait until ML(0)_AXI_BRIDGE_CTRL(0..1)[BUSY] = 0 which
		 * indicates that there is no outstanding transactions on
		 * AXI-NCB paths.
		 */
		roc_ml_reg_wait_to_clear(roc_ml, ML_AXI_BRIDGE_CTRLX(0),
					 ROC_ML_AXI_BRIDGE_CTRL_BUSY);
		roc_ml_reg_wait_to_clear(roc_ml, ML_AXI_BRIDGE_CTRLX(1),
					 ROC_ML_AXI_BRIDGE_CTRL_BUSY);

		/* (3) Wait until ML(0)_JOB_MGR_CTRL[BUSY] = 0 which indicates
		 * that there are no pending jobs in the MLW's job manager.
		 */
		roc_ml_reg_wait_to_clear(roc_ml, ML_JOB_MGR_CTRL, ROC_ML_JOB_MGR_CTRL_BUSY);

		/* (4) Set ML(0)_CFG[ENA] = 0. */
		reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
		reg_val &= ~ROC_ML_CFG_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);

		/* (5) Set ML(0)_CFG[MLIP_ENA] = 0. */
		reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
		reg_val &= ~ROC_ML_CFG_MLIP_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);

		/* (6) Set ML(0)_AXI_BRIDGE_CTRL(0..1)[FENCE] = 0.*/
		reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRLX(0));
		reg_val &= ~ROC_ML_AXI_BRIDGE_CTRL_FENCE;
		roc_ml_reg_write64(roc_ml, reg_val, ML_AXI_BRIDGE_CTRLX(0));
		roc_ml_reg_write64(roc_ml, reg_val, ML_AXI_BRIDGE_CTRLX(1));
	}

	if (roc_model_is_cnf10kb()) {
		/* (1) Clear MLAB(0)_CFG[ENA]. Any new jobs will bypass the job
		 * execution stages and their completions will be returned to
		 * PSM.
		 */
		reg_val = roc_ml_reg_read64(roc_ml, MLAB_CFG);
		reg_val &= ~ROC_ML_CFG_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_CFG);

		/* (2) Quiesce the ACC and DMA AXI interfaces: For each of the
		 * two MLAB(0)_AXI_BRIDGE_CTRL(0..1) registers:
		 *
		 * (a) Set MLAB(0)_AXI_BRIDGE_CTRL(0..1)[FENCE] to block new AXI
		 * commands from MLIP.
		 *
		 * (b) Poll MLAB(0)_AXI_BRIDGE_CTRL(0..1)[BUSY] == 0.
		 */
		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(0));
		reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FENCE;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(0));

		roc_ml_reg_wait_to_clear(roc_ml, MLAB_AXI_BRIDGE_CTRLX(0),
					 ROC_ML_AXI_BRIDGE_CTRL_BUSY);

		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(1));
		reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FENCE;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(1));

		roc_ml_reg_wait_to_clear(roc_ml, MLAB_AXI_BRIDGE_CTRLX(1),
					 ROC_ML_AXI_BRIDGE_CTRL_BUSY);

		/* (3) Clear MLAB(0)_CFG[MLIP_ENA] to reset MLIP.
		 */
		reg_val = roc_ml_reg_read64(roc_ml, MLAB_CFG);
		reg_val &= ~ROC_ML_CFG_MLIP_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_CFG);

cnf10kb_mlip_reset_stage_4a:
		/* (4) Flush any outstanding jobs in MLAB's job execution
		 * stages:
		 *
		 * (a) Wait for completion stage to clear:
		 *   - Poll MLAB(0)_STG(0..2)_STATUS[VALID] == 0.
		 */
		roc_ml_reg_wait_to_clear(roc_ml, MLAB_STGX_STATUS(0), ROC_ML_STG_STATUS_VALID);
		roc_ml_reg_wait_to_clear(roc_ml, MLAB_STGX_STATUS(1), ROC_ML_STG_STATUS_VALID);
		roc_ml_reg_wait_to_clear(roc_ml, MLAB_STGX_STATUS(2), ROC_ML_STG_STATUS_VALID);

cnf10kb_mlip_reset_stage_4b:
		/* (4b) Clear job run stage: Poll
		 * MLAB(0)_STG_CONTROL[RUN_TO_COMP] == 0.
		 */
		roc_ml_reg_wait_to_clear(roc_ml, MLAB_STG_CONTROL,
					 ROC_MLAB_STG_CONTROL_RUN_TO_COMP);

		/* (4b) Clear job run stage: If MLAB(0)_STG(1)_STATUS[VALID] ==
		 * 1:
		 *     - Set MLAB(0)_STG_CONTROL[RUN_TO_COMP].
		 *     - Poll MLAB(0)_STG_CONTROL[RUN_TO_COMP] == 0.
		 *     - Repeat step (a) to clear job completion stage.
		 */
		reg_val = roc_ml_reg_read64(roc_ml, MLAB_STGX_STATUS(1));
		if (reg_val & ROC_ML_STG_STATUS_VALID) {
			reg_val = roc_ml_reg_read64(roc_ml, MLAB_STG_CONTROL);
			reg_val |= ROC_MLAB_STG_CONTROL_RUN_TO_COMP;
			roc_ml_reg_write64(roc_ml, reg_val, MLAB_STG_CONTROL);

			roc_ml_reg_wait_to_clear(roc_ml, MLAB_STG_CONTROL,
						 ROC_MLAB_STG_CONTROL_RUN_TO_COMP);

			goto cnf10kb_mlip_reset_stage_4a;
		}

		/* (4c) Clear job fetch stage: Poll
		 * MLAB(0)_STG_CONTROL[FETCH_TO_RUN] == 0.
		 */
		roc_ml_reg_wait_to_clear(roc_ml, MLAB_STG_CONTROL,
					 ROC_MLAB_STG_CONTROL_FETCH_TO_RUN);

		/* (4c) Clear job fetch stage: If
		 * MLAB(0)_STG(0..2)_STATUS[VALID] == 1:
		 *     - Set MLAB(0)_STG_CONTROL[FETCH_TO_RUN].
		 *     - Poll MLAB(0)_STG_CONTROL[FETCH_TO_RUN] == 0.
		 *     - Repeat step (b) to clear job run and completion stages.
		 */
		reg_val = (roc_ml_reg_read64(roc_ml, MLAB_STGX_STATUS(0)) |
			   roc_ml_reg_read64(roc_ml, MLAB_STGX_STATUS(1)) |
			   roc_ml_reg_read64(roc_ml, MLAB_STGX_STATUS(2)));

		if (reg_val & ROC_ML_STG_STATUS_VALID) {
			reg_val = roc_ml_reg_read64(roc_ml, MLAB_STG_CONTROL);
			reg_val |= ROC_MLAB_STG_CONTROL_RUN_TO_COMP;
			roc_ml_reg_write64(roc_ml, reg_val, MLAB_STG_CONTROL);

			roc_ml_reg_wait_to_clear(roc_ml, MLAB_STG_CONTROL,
						 ROC_MLAB_STG_CONTROL_RUN_TO_COMP);

			goto cnf10kb_mlip_reset_stage_4b;
		}

		/* (5) Reset the ACC and DMA AXI interfaces: For each of the two
		 * MLAB(0)_AXI_BRIDGE_CTRL(0..1) registers:
		 *
		 * (5a) Set and then clear
		 * MLAB(0)_AXI_BRIDGE_CTRL(0..1)[FLUSH_WRITE_DATA].
		 *
		 * (5b) Clear MLAB(0)_AXI_BRIDGE_CTRL(0..1)[FENCE].
		 */
		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(0));
		reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FLUSH_WRITE_DATA;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(0));

		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(0));
		reg_val &= ~ROC_ML_AXI_BRIDGE_CTRL_FLUSH_WRITE_DATA;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(0));

		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(0));
		reg_val &= ~ROC_ML_AXI_BRIDGE_CTRL_FENCE;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(0));

		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(1));
		reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FLUSH_WRITE_DATA;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(1));

		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(1));
		reg_val &= ~ROC_ML_AXI_BRIDGE_CTRL_FLUSH_WRITE_DATA;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(1));

		reg_val = roc_ml_reg_read64(roc_ml, MLAB_AXI_BRIDGE_CTRLX(1));
		reg_val &= ~ROC_ML_AXI_BRIDGE_CTRL_FENCE;
		roc_ml_reg_write64(roc_ml, reg_val, MLAB_AXI_BRIDGE_CTRLX(1));
	}

	return 0;
}

int
roc_ml_num_engines_get(uint8_t rvu_idx)
{
	struct roc_rvu_lf *roc_rvu_lf = NULL;
	struct rvu_lf *rvu;
	uint64_t pf_disc;

	roc_rvu_lf = roc_idev_rvu_lf_get(rvu_idx);
	if (roc_rvu_lf == NULL)
		return 0;

	if ((roc_rvu_lf->pci_dev->id.device_id != PCI_DEVID_CNXK_RVU_BPHY_PF) &&
	    (roc_rvu_lf->pci_dev->id.device_id != PCI_DEVID_CN20K_RVU_BPHY_RF_PF))
		return 0;

	rvu = roc_rvu_lf_to_rvu_priv(roc_rvu_lf);
	pf_disc = plt_read64(rvu->dev.bar2 + RVU_PF_DISC);

	if (pf_disc & (1ull << RVU_BLOCK_ADDR_E_BGENX(1)))
		return 2;

	return 1;
}

static int
roc_ml_dev_init_cn10k(struct roc_ml *roc_ml)
{
	struct ml *ml;

	ml = roc_ml_to_ml_priv(roc_ml);
	ml->ml_reg_addr = ml->pci_dev->mem_resource[0].addr;
	ml->ml_mlr_base = 0x0;
	ml->ml_mlr_base_saved = false;

	plt_ml_dbg("ML: PCI Physical Address : 0x%" PRIx64,
		   PLT_U64_CAST(ml->pci_dev->mem_resource[0].phys_addr));
	plt_ml_dbg("ML: PCI Virtual Address : 0x%" PRIx64,
		   PLT_U64_CAST(ml->pci_dev->mem_resource[0].addr));

	roc_ml->reg_read64 = roc_ml_reg_read64_cnxk;
	roc_ml->reg_write64 = roc_ml_reg_write64_cnxk;

	roc_ml->cfg = ML_CFG;
	roc_ml->mlr_base = ML_MLR_BASE;
	roc_ml->job_mgr_ctrl = ML_JOB_MGR_CTRL;

	return 0;
}

static int
ml_hardware_caps_get(struct dev *dev, struct roc_ml *roc_ml)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct ml_caps_rsp_msg *rsp;
	struct msg_req *req;
	int rc;

	req = mbox_alloc_msg_ml_caps_get(mbox);
	if (req == NULL) {
		rc = -ENOSPC;
		goto exit;
	}

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc) {
		rc = -EIO;
		goto exit;
	}

	mbox_memcpy(&roc_ml->ml_af_const, &rsp->ml_af_const, sizeof(union ml_af_const));

	rc = 0;

exit:
	mbox_put(mbox);

	return rc;
}

static int
ml_available_lfs_get(struct dev *dev, uint16_t *nb_lf)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct ml_free_rsrcs_rsp *rsp;
	struct msg_req *req;
	int rc;

	req = mbox_alloc_msg_ml_free_rsrc_cnt(mbox);
	if (req == NULL) {
		rc = -ENOSPC;
		goto exit;
	}

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc) {
		rc = -EIO;
		goto exit;
	}

	*nb_lf = rsp->ml;
	rc = 0;

exit:
	mbox_put(mbox);

	return rc;
}

static int
ml_lfs_attach(struct dev *dev, uint8_t blkaddr, bool modify, uint16_t nb_lf, uint64_t *lf_map)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct ml_rsrc_attach_req *req;
	struct ml_rsrc_attach_rsp *rsp;
	int rc;

	if (blkaddr != RVU_BLOCK_ADDR_ML) {
		rc = -EINVAL;
		goto exit;
	}

	/* Attach ML (lf) */
	req = mbox_alloc_msg_ml_attach_resources(mbox);
	if (req == NULL) {
		rc = -ENOSPC;
		goto exit;
	}

	req->mllfs = nb_lf;
	req->modify = modify;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc) {
		rc = -EIO;
		goto exit;
	}

	mbox_memcpy(lf_map, rsp->lf_map, ML_NUM_LF_MAPS * sizeof(uint64_t));
	rc = 0;

exit:
	mbox_put(mbox);

	return rc;
}

static int
ml_lfs_detach(struct dev *dev)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct msg_req *req;
	int rc;

	req = mbox_alloc_msg_ml_detach_resources(mbox);
	if (req == NULL) {
		rc = -ENOSPC;
		goto exit;
	}

	rc = mbox_process(mbox);

exit:
	mbox_put(mbox);

	return rc;
}

static int
ml_get_msix_offset(struct dev *dev, struct ml_msix_offset_rsp **msix_rsp)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	int rc;

	/* Get MSIX vector offsets */
	mbox_alloc_msg_ml_msix_offset(mbox);
	rc = mbox_process_msg(mbox, (void *)msix_rsp);
	mbox_put(mbox);

	return rc;
}

static int
ml_lfs_alloc(struct dev *dev, uint8_t blkaddr)
{
	struct ml_lf_alloc_req *req;
	struct mbox *mbox = mbox_get(dev->mbox);
	int rc;

	if (blkaddr != RVU_BLOCK_ADDR_ML) {
		rc = -EINVAL;
		goto exit;
	}

	req = mbox_alloc_msg_ml_lf_alloc(mbox);
	if (!req) {
		rc = -ENOSPC;
		goto exit;
	}

	req->sso_pf_func = idev_sso_pffunc_get();
	rc = mbox_process(mbox);

exit:
	mbox_put(mbox);

	return rc;
}

static int
ml_lfs_free(struct dev *dev)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	int rc;

	mbox_alloc_msg_ml_lf_free(mbox);

	rc = mbox_process(mbox);
	mbox_put(mbox);

	return rc;
}

static int
ml_pid_lf_map(struct dev *dev, uint16_t lf_id, uint8_t pid, bool enable)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct ml_pid_lf_map_req *req;
	int rc;

	req = mbox_alloc_msg_ml_pid_lf_map(mbox);
	if (!req) {
		rc = -ENOSPC;
		goto exit;
	}

	req->lf_id = lf_id;
	req->pid = pid;
	req->enable = enable ? 1 : 0;

	rc = mbox_process(mbox);

exit:
	mbox_put(mbox);

	return rc;
}

static int
roc_ml_dev_init_cn20k(struct roc_ml *roc_ml)
{
	const struct plt_memzone *mz = NULL;
	uint64_t lf_map[ML_NUM_LF_MAPS];
	char name[ROC_ML_DEV_NAME_LEN];
	struct plt_pci_device *pci_dev;
	struct ml_msix_offset_rsp *rsp;
	uint16_t nb_lf_avail = 0;
	struct dev *dev;
	uint16_t lf_bit;
	uint16_t lf_id;
	uint16_t slot;
	struct ml *ml;
	uint8_t i;
	int rc;

	ml = roc_ml_to_ml_priv(roc_ml);
	pci_dev = roc_ml->pci_dev;
	dev = &ml->dev;

	/* Initialize device */
	rc = dev_init(dev, pci_dev);
	if (rc) {
		plt_err("Failed to initialize ROC device");
		return rc;
	}

	rc = ml_available_lfs_get(dev, &nb_lf_avail);
	if (rc) {
		plt_err("Could not get available lfs");
		goto err_exit;
	}

	if (nb_lf_avail == 0) {
		plt_err("No ML LFs available");
		return -ENOTSUP;
	}

	roc_ml->nb_lf_avail = nb_lf_avail;

	if (roc_ml->nb_lf > roc_ml->nb_lf_avail) {
		plt_err("Number of slots requested (%d) > available LF's slots (%d)", roc_ml->nb_lf,
			roc_ml->nb_lf_avail);
		return -ENODEV;
	}

	snprintf(name, sizeof(name), "%s" PCI_PRI_FMT, ROC_ML_DEV_NAME, pci_dev->addr.domain,
		 pci_dev->addr.bus, pci_dev->addr.devid, pci_dev->addr.function);
	mz = plt_memzone_reserve_cache_align(name, roc_ml->nb_lf * sizeof(struct roc_ml_lf));
	if (!mz)
		return -ENOMEM;

	roc_ml->lf = mz->addr;

	memset(lf_map, 0, ML_NUM_LF_MAPS * sizeof(uint64_t));
	rc = ml_lfs_attach(dev, RVU_BLOCK_ADDR_ML, true, roc_ml->nb_lf, lf_map);
	if (rc) {
		plt_err("Could not attach LFs");
		goto err_exit;
	}

	memcpy(roc_ml->lf_map, lf_map, sizeof(lf_map));
	for (slot = 0; slot < roc_ml->nb_lf; slot++) {
		lf_id = 0;
		lf_bit = 0;
		for (i = 0; i < ML_NUM_LF_MAPS; i++) {
			if (lf_map[i] == 0)
				continue;

			lf_bit = ffs(lf_map[i]) - 1;
			lf_id = i * ML_NUM_LF_MAPS * sizeof(uint64_t) + lf_bit;
			break;
		}

		roc_ml_lf_init(roc_ml, &roc_ml->lf[slot], slot, lf_id);
		lf_map[i] &= ~(1 << lf_bit);
	}

	rc = ml_get_msix_offset(&ml->dev, &rsp);
	if (rc)
		goto lfs_detach;

	for (slot = 0; slot < roc_ml->nb_lf; slot++)
		ml->lf_msix_off[slot] = rsp->mllf_msixoff[slot];

	/* Set idev if not already present */
	if (!roc_idev_ml_get())
		roc_idev_ml_set(roc_ml);

	rc = ml_lfs_alloc(&ml->dev, RVU_BLOCK_ADDR_ML);
	if (rc)
		goto lfs_detach;

	rc = ml_hardware_caps_get(dev, roc_ml);
	if (rc) {
		plt_err("Failed to get hardware capabilities");
		goto lfs_detach;
	}

	roc_ml->reg_read64 = roc_ml_reg_read64_cn20ka;
	roc_ml->reg_write64 = roc_ml_reg_write64_cn20ka;

	roc_ml->cfg = ML_AF_CFG;
	roc_ml->mlr_base = ML_AF_MLR_BASE;
	roc_ml->mlr_size = ML_AF_MLR_SIZE;
	roc_ml->job_mgr_ctrl = ML_AF_JOB_MGR_CTRL;

	return rc;

lfs_detach:
	for (slot = 0; slot < roc_ml->nb_lf; slot++)
		roc_ml_lf_fini(&roc_ml->lf[slot]);

	ml_lfs_detach(&ml->dev);

err_exit:
	if (mz)
		plt_memzone_free(mz);

	dev_fini(dev, pci_dev);

	return rc;
}

int
roc_ml_dev_init(struct roc_ml *roc_ml)
{
	struct ml *ml;
	int rc = 0;

	if (roc_ml == NULL || roc_ml->pci_dev == NULL)
		return -EINVAL;

	PLT_STATIC_ASSERT(sizeof(struct ml) <= ROC_ML_MEM_SZ);

	ml = roc_ml_to_ml_priv(roc_ml);
	memset(ml, 0, sizeof(*ml));

	ml->pci_dev = roc_ml->pci_dev;
	ml->dev.roc_ml = roc_ml;

	if (roc_model_is_cn10k())
		rc = roc_ml_dev_init_cn10k(roc_ml);
	else if (roc_model_is_cn20k())
		rc = roc_ml_dev_init_cn20k(roc_ml);
	else
		return -ENOTSUP;

	plt_spinlock_init(&roc_ml->sp_spinlock);
	plt_spinlock_init(&roc_ml->fp_spinlock);

	return rc;
}

static int
roc_ml_dev_fini_cn10k(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	if (ml == NULL)
		return -EINVAL;

	return 0;
}

static int
roc_ml_dev_fini_cn20k(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	const struct plt_memzone *mz = NULL;
	char name[ROC_ML_DEV_NAME_LEN];
	struct plt_pci_device *pci_dev;
	uint16_t i;

	ml_lfs_free(&ml->dev);

	/* Remove idev references */
	if (roc_idev_ml_get() == roc_ml)
		roc_idev_ml_set(NULL);

	for (i = 0; i < roc_ml->nb_lf; i++) {
		ml->lf_msix_off[i] = 0;
		roc_ml_lf_fini(&roc_ml->lf[i]);
	}

	ml_lfs_detach(&ml->dev);

	/* Release memory */
	pci_dev = ml->pci_dev;
	snprintf(name, sizeof(name), "%s" PCI_PRI_FMT, ROC_ML_DEV_NAME, pci_dev->addr.domain,
		 pci_dev->addr.bus, pci_dev->addr.devid, pci_dev->addr.function);
	mz = plt_memzone_lookup(name);
	if (mz)
		plt_memzone_free(mz);

	roc_ml->nb_lf_avail = 0;

	return dev_fini(&ml->dev, ml->pci_dev);
}

int
roc_ml_dev_fini(struct roc_ml *roc_ml)
{
	if (roc_model_is_cn10k())
		return roc_ml_dev_fini_cn10k(roc_ml);
	else if (roc_model_is_cn20k())
		return roc_ml_dev_fini_cn20k(roc_ml);

	return -ENOTSUP;
}

int
roc_ml_blk_init(struct roc_ml *roc_ml, int id)
{
	uint8_t *mlab_pa;
	uint8_t *mlab_va;
	struct dev *dev;
	struct ml *ml;

	if (roc_ml == NULL)
		return -EINVAL;

	PLT_STATIC_ASSERT(sizeof(struct ml) <= ROC_ML_MEM_SZ);

	ml = roc_ml_to_ml_priv(roc_ml);
	memset(ml, 0, sizeof(*ml));

	dev = &ml->dev;
	dev->roc_ml = roc_ml;
	roc_ml->nb_lf = 0;

	if (roc_ml->pci_dev->id.device_id == PCI_DEVID_CNXK_RVU_BPHY_VF)
		return 0;

	mlab_pa = PLT_PTR_CAST(roc_ml->pci_dev->mem_resource[0].phys_addr);
	mlab_va = PLT_PTR_CAST(roc_ml->pci_dev->mem_resource[0].addr);

	if (roc_model_is_cnf10kb()) {
		mlab_pa = PLT_PTR_ADD(mlab_pa, MLAB_BLK_OFFSET_CNF10KB);
		mlab_va = PLT_PTR_ADD(mlab_va, MLAB_BLK_OFFSET_CNF10KB);

		roc_ml->cfg = MLAB_CFG;
		roc_ml->mlr_base = MLAB_MLR_BASE;
		roc_ml->job_mgr_ctrl = MLAB_JOB_MGR_CTRL;
	} else if (roc_model_is_cnf20ka()) {
		mlab_pa = MLAB_BLK_ADDR(id, PLT_PTR_ADD(mlab_pa, MLAB_BLK_OFFSET_CNF20KA));
		mlab_va = MLAB_BLK_ADDR(id, PLT_PTR_ADD(mlab_va, MLAB_BLK_OFFSET_CNF20KA));

		roc_ml->cfg = MLAB_AF_CFG;
		roc_ml->mlr_base = MLAB_AF_MLR_BASE;
		roc_ml->mlr_size = MLAB_AF_MLR_SIZE;
		roc_ml->job_mgr_ctrl = MLAB_AF_JOB_MGR_CTRL;
	}

	plt_ml_dbg("MLAB: Physical Address : 0x%" PRIx64, PLT_U64_CAST(mlab_pa));
	plt_ml_dbg("MLAB: Virtual Address : 0x%" PRIx64, PLT_U64_CAST(mlab_va));

	ml->ml_reg_addr = mlab_va;
	ml->ml_mlr_base = 0;
	ml->ml_mlr_base_saved = false;

	roc_ml->reg_read64 = roc_ml_reg_read64_cnxk;
	roc_ml->reg_write64 = roc_ml_reg_write64_cnxk;

	plt_spinlock_init(&roc_ml->sp_spinlock);
	plt_spinlock_init(&roc_ml->fp_spinlock);

	return 0;
}

int
roc_ml_blk_fini(struct roc_ml *roc_ml, int id)
{
	PLT_SET_USED(roc_ml);
	PLT_SET_USED(id);

	return 0;
}

int
roc_ml_dev_configure(struct roc_ml *roc_ml __plt_unused)
{
	return 0;
}

void
roc_ml_dev_close(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	if (ml == NULL)
		return;
}

int
roc_ml_lf_init(struct roc_ml *roc_ml, struct roc_ml_lf *lf, uint16_t slot, uint16_t lf_id)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	lf->slot = slot;
	lf->lf_id = lf_id;
	lf->pci_dev = ml->pci_dev;
	lf->dev = &ml->dev;
	lf->roc_ml = roc_ml;
	lf->rbase = lf->dev->bar2 + (((uint64_t)RVU_BLOCK_ADDR_ML << RVU_FUNC_BLKADDR_SHIFT) |
				     ((uint64_t)slot << RVU_FUNC_LFSLOT_SHIFT));
	lf->msixoff = ml->lf_msix_off[slot];
	lf->pf_func = lf->dev->pf_func;
	lf->blk_addr = RVU_BLOCK_ADDR_ML;

	return 0;
}

void
roc_ml_lf_fini(struct roc_ml_lf *lf)
{
	if (lf == NULL)
		return;
}

uint16_t
roc_ml_sso_pf_func_get(void)
{
	return idev_sso_pffunc_get();
}

int
roc_ml_pid_lf_map(struct roc_ml *roc_ml, uint16_t lf_id, uint8_t pid, bool enable)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	return ml_pid_lf_map(&ml->dev, lf_id, pid, enable);
}

bool
roc_ml_lf_jcmdq_enqueue_nolock(struct roc_ml_lf *lf, struct ml_job_cmd_s *job_cmd)
{
	bool ret = false;

	if (FIELD_GET(ROC_ML_LF_JCMDQ_STATUS_AVAIL_COUNT,
		      roc_ml_lf_reg_read64(lf, ML_LF_JCMDQ_STATUS)) != 0) {
		roc_ml_lf_reg_write64(lf, job_cmd->w0.u64, ML_LF_JCMDQ_INX(0));
		roc_ml_lf_reg_write64(lf, job_cmd->w1.u64, ML_LF_JCMDQ_INX(1));
		ret = true;
	}

	return ret;
}

bool
roc_ml_lf_jcmdq_enqueue_splock(struct roc_ml_lf *lf, struct ml_job_cmd_s *job_cmd)
{
	bool ret = false;

	if (plt_spinlock_trylock(&lf->roc_ml->fp_spinlock) != 0) {
		if (FIELD_GET(ROC_ML_LF_JCMDQ_STATUS_AVAIL_COUNT,
			      roc_ml_lf_reg_read64(lf, ML_LF_JCMDQ_STATUS)) != 0) {
			roc_ml_lf_reg_write64(lf, job_cmd->w0.u64, ML_LF_JCMDQ_INX(0));
			roc_ml_lf_reg_write64(lf, job_cmd->w1.u64, ML_LF_JCMDQ_INX(1));
			ret = true;
		}
		plt_spinlock_unlock(&lf->roc_ml->fp_spinlock);
	}

	return ret;
}
