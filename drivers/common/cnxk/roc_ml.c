/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

#define TIME_SEC_IN_MS 1000

uint64_t
roc_ml_reg_read64(struct roc_ml *roc_ml, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	return plt_read64(PLT_PTR_ADD(ml->ml_reg_addr, offset));
}

void
roc_ml_reg_write64(struct roc_ml *roc_ml, uint64_t val, uint64_t offset)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	plt_write64(val, PLT_PTR_ADD(ml->ml_reg_addr, offset));
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

void *
roc_ml_addr_ap2mlip(struct roc_ml *roc_ml, void *addr)
{
	uint64_t mlr_base;

	mlr_base = FIELD_GET(ROC_ML_MLR_BASE_BASE,
			     roc_ml_reg_read64(roc_ml, ML_MLR_BASE));

	return PLT_PTR_ADD(addr, ML_AXI_START_ADDR - mlr_base);
}

void *
roc_ml_addr_mlip2ap(struct roc_ml *roc_ml, void *addr)
{
	uint64_t mlr_base;

	mlr_base = FIELD_GET(ROC_ML_MLR_BASE_BASE,
			     roc_ml_reg_read64(roc_ml, ML_MLR_BASE));

	return PLT_PTR_ADD(addr, mlr_base - ML_AXI_START_ADDR);
}

void
roc_ml_scratch_write_job(struct roc_ml *roc_ml, void *jd)
{
	union ml_scratch_ap_fw_comm reg_ap_fw_comm;
	union ml_scratch_work_ptr reg_work_ptr;

	reg_work_ptr.u = 0;
	reg_work_ptr.s.work_cmd_ptr = (uint64_t)roc_ml_addr_ap2mlip(roc_ml, jd);

	reg_ap_fw_comm.u = 0x0;
	reg_ap_fw_comm.s.valid = 0x1;

	roc_ml_reg_write64(roc_ml, reg_work_ptr.u, ML_SCRATCH_WORK_PTR);
	roc_ml_reg_write64(roc_ml, reg_ap_fw_comm.u, ML_SCRATCH_AP_FW_COMM);
}

bool
roc_ml_scratch_is_valid_bit_set(struct roc_ml *roc_ml)
{
	union ml_scratch_ap_fw_comm reg_ap_fw_comm;

	reg_ap_fw_comm.u = roc_ml_reg_read64(roc_ml, ML_SCRATCH_AP_FW_COMM);

	if (reg_ap_fw_comm.s.valid == 1)
		return true;

	return false;
}

bool
roc_ml_scratch_is_done_bit_set(struct roc_ml *roc_ml)
{
	union ml_scratch_ap_fw_comm reg_ap_fw_comm;

	reg_ap_fw_comm.u = roc_ml_reg_read64(roc_ml, ML_SCRATCH_AP_FW_COMM);

	if (reg_ap_fw_comm.s.done == 1)
		return true;

	return false;
}

uint16_t
roc_ml_jcmdq_avail_count_get(struct roc_ml *roc_ml)
{
	return FIELD_GET(ROC_ML_JCMDQ_STATUS_AVAIL_COUNT,
			 roc_ml_reg_read64(roc_ml, ML_JCMDQ_STATUS));
}

bool
roc_ml_scratch_enqueue(struct roc_ml *roc_ml, void *jd)
{
	union ml_scratch_ap_fw_comm reg_ap_fw_comm;
	union ml_scratch_work_ptr reg_work_ptr;
	bool rval = false;

	reg_work_ptr.u = 0;
	reg_work_ptr.s.work_cmd_ptr = (uint64_t)roc_ml_addr_ap2mlip(roc_ml, jd);

	reg_ap_fw_comm.u = 0x0;
	reg_ap_fw_comm.s.valid = 0x1;

	if (plt_spinlock_trylock(&roc_ml->sp_spinlock) != 0) {
		bool valid = roc_ml_scratch_is_valid_bit_set(roc_ml);
		bool done = roc_ml_scratch_is_done_bit_set(roc_ml);

		if (valid == done) {
			roc_ml_clk_force_on(roc_ml);
			roc_ml_dma_stall_off(roc_ml);

			roc_ml_reg_write64(roc_ml, reg_work_ptr.u,
					   ML_SCRATCH_WORK_PTR);
			roc_ml_reg_write64(roc_ml, reg_ap_fw_comm.u,
					   ML_SCRATCH_AP_FW_COMM);

			rval = true;
		}
		plt_spinlock_unlock(&roc_ml->sp_spinlock);
	}

	return rval;
}

bool
roc_ml_scratch_dequeue(struct roc_ml *roc_ml, void *jd)
{
	union ml_scratch_work_ptr reg_work_ptr;
	bool rval = false;

	if (plt_spinlock_trylock(&roc_ml->sp_spinlock) != 0) {
		bool valid = roc_ml_scratch_is_valid_bit_set(roc_ml);
		bool done = roc_ml_scratch_is_done_bit_set(roc_ml);

		if (valid && done) {
			reg_work_ptr.u =
				roc_ml_reg_read64(roc_ml, ML_SCRATCH_WORK_PTR);
			if (jd == roc_ml_addr_mlip2ap(roc_ml,
						      (void *)reg_work_ptr.u)) {
				roc_ml_dma_stall_on(roc_ml);
				roc_ml_clk_force_off(roc_ml);

				roc_ml_reg_write64(roc_ml, 0x0,
						   ML_SCRATCH_WORK_PTR);
				roc_ml_reg_write64(roc_ml, 0x0,
						   ML_SCRATCH_AP_FW_COMM);
				rval = true;
			}
		}
		plt_spinlock_unlock(&roc_ml->sp_spinlock);
	}

	return rval;
}

void
roc_ml_scratch_queue_reset(struct roc_ml *roc_ml)
{
	if (plt_spinlock_trylock(&roc_ml->sp_spinlock) != 0) {
		roc_ml_dma_stall_on(roc_ml);
		roc_ml_clk_force_off(roc_ml);
		roc_ml_reg_write64(roc_ml, 0x0, ML_SCRATCH_WORK_PTR);
		roc_ml_reg_write64(roc_ml, 0x0, ML_SCRATCH_AP_FW_COMM);
		plt_spinlock_unlock(&roc_ml->sp_spinlock);
	}
}

bool
roc_ml_jcmdq_enqueue(struct roc_ml *roc_ml, void *jd)
{
	bool rval = false;

	if (plt_spinlock_trylock(&roc_ml->fp_spinlock) != 0) {
		if (FIELD_GET(ROC_ML_JCMDQ_STATUS_AVAIL_COUNT,
			      roc_ml_reg_read64(roc_ml, ML_JCMDQ_STATUS)) !=
		    0) {
			roc_ml_reg_write64(roc_ml, 0x0, ML_JCMDQ_IN(0));
			roc_ml_reg_write64(roc_ml, (uint64_t)jd,
					   ML_JCMDQ_IN(1));
			rval = true;
		}
		plt_spinlock_unlock(&roc_ml->fp_spinlock);
	}

	return rval;
}

void
roc_ml_clk_force_on(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
	reg_val |= ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);
}

void
roc_ml_clk_force_off(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	roc_ml_reg_write64(roc_ml, 0x0, ML_SCRATCH_WORK_PTR);

	reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
	reg_val &= ~ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);
}

void
roc_ml_dma_stall_on(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	reg_val = roc_ml_reg_read64(roc_ml, ML_JOB_MGR_CTRL);
	reg_val |= ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(roc_ml, reg_val, ML_JOB_MGR_CTRL);
}

void
roc_ml_dma_stall_off(struct roc_ml *roc_ml)
{
	uint64_t reg_val = 0;

	reg_val = roc_ml_reg_read64(roc_ml, ML_JOB_MGR_CTRL);
	reg_val &= ~ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(roc_ml, reg_val, ML_JOB_MGR_CTRL);
}

bool
roc_ml_mlip_is_enabled(struct roc_ml *roc_ml)
{
	uint64_t reg_val64;

	reg_val64 = roc_ml_reg_read64(roc_ml, ML_CFG);
	if ((reg_val64 & ROC_ML_CFG_MLIP_ENA) != 0)
		return true;

	return false;
}

int
roc_ml_mlip_reset(struct roc_ml *roc_ml, bool force)
{
	uint64_t start_cycle;
	uint64_t wait_cycles;
	uint64_t reg_val;
	bool timeout;

	/* Force reset */
	if (force) {
		/* Set ML(0)_CFG[ENA] = 0. */
		reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
		reg_val &= ~ROC_ML_CFG_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);

		/* Set ML(0)_CFG[MLIP_ENA] = 0. */
		reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
		reg_val &= ~ROC_ML_CFG_MLIP_ENA;
		roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);

		/* Clear ML_MLR_BASE */
		roc_ml_reg_write64(roc_ml, 0, ML_MLR_BASE);
	}

	wait_cycles = (ROC_ML_TIMEOUT_MS * plt_tsc_hz()) / TIME_SEC_IN_MS;

	/* Wait for all active jobs to finish.
	 * ML_CFG[ENA] : When set, MLW will accept job commands. This bit can be
	 * cleared at any time. If [BUSY] is set, software must wait until
	 * [BUSY] == 0 before setting this bit.
	 */
	timeout = true;
	start_cycle = plt_tsc_cycles();
	do {
		reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);

		if (!(reg_val & ROC_ML_CFG_BUSY)) {
			timeout = false;
			break;
		}
	} while (plt_tsc_cycles() - start_cycle < wait_cycles);

	/* (1) Set ML(0)_AXI_BRIDGE_CTRL(0..1)[FENCE] = 1 to instruct the AXI
	 * bridge not to accept any new transactions from MLIP.
	 */
	reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRL(0));
	reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FENCE;
	roc_ml_reg_write64(roc_ml, reg_val, ML_AXI_BRIDGE_CTRL(0));

	reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRL(1));
	reg_val |= ROC_ML_AXI_BRIDGE_CTRL_FENCE;
	roc_ml_reg_write64(roc_ml, reg_val, ML_AXI_BRIDGE_CTRL(1));

	/* (2) Wait until ML(0)_AXI_BRIDGE_CTRL(0..1)[BUSY] = 0 which indicates
	 * that there is no outstanding transactions on AXI-NCB paths.
	 */
	timeout = true;
	start_cycle = plt_tsc_cycles();
	do {
		reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRL(0));

		if (!(reg_val & ROC_ML_AXI_BRIDGE_CTRL_BUSY)) {
			timeout = false;
			break;
		}
	} while (plt_tsc_cycles() - start_cycle < wait_cycles);

	timeout = true;
	start_cycle = plt_tsc_cycles();
	do {
		reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRL(1));

		if (!(reg_val & ROC_ML_AXI_BRIDGE_CTRL_BUSY)) {
			timeout = false;
			break;
		}
	} while (plt_tsc_cycles() - start_cycle < wait_cycles);

	/* (3) Wait until ML(0)_JOB_MGR_CTRL[BUSY] = 0 which indicates that
	 * there are no pending jobs in the MLW’s job manager.
	 */
	timeout = true;
	start_cycle = plt_tsc_cycles();
	do {
		reg_val = roc_ml_reg_read64(roc_ml, ML_JOB_MGR_CTRL);

		if (!(reg_val & ROC_ML_JOB_MGR_CTRL_BUSY)) {
			timeout = false;
			break;
		}
	} while (plt_tsc_cycles() - start_cycle < wait_cycles);

	/* (4) Set ML(0)_CFG[ENA] = 0. */
	reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
	reg_val &= ~ROC_ML_CFG_ENA;
	roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);

	/* (5) Set ML(0)_CFG[MLIP_ENA] = 0. */
	reg_val = roc_ml_reg_read64(roc_ml, ML_CFG);
	reg_val &= ~ROC_ML_CFG_MLIP_ENA;
	roc_ml_reg_write64(roc_ml, reg_val, ML_CFG);

	/* Reset ML(0)_AXI_BRIDGE_CTRL(0..1)[FENCE] = 0 .*/
	reg_val = roc_ml_reg_read64(roc_ml, ML_AXI_BRIDGE_CTRL(0));
	reg_val &= ~ROC_ML_AXI_BRIDGE_CTRL_FENCE;
	roc_ml_reg_write64(roc_ml, reg_val, ML_AXI_BRIDGE_CTRL(0));

	if (timeout)
		return -1;

	return 0;
}

int
roc_ml_dev_init(struct roc_ml *roc_ml)
{
	struct plt_pci_device *pci_dev;
	struct dev *dev;
	struct ml *ml;

	if (roc_ml == NULL || roc_ml->pci_dev == NULL)
		return -EINVAL;

	PLT_STATIC_ASSERT(sizeof(struct ml) <= ROC_ML_MEM_SZ);

	ml = roc_ml_to_ml_priv(roc_ml);
	memset(ml, 0, sizeof(*ml));
	pci_dev = roc_ml->pci_dev;
	dev = &ml->dev;

	ml->pci_dev = pci_dev;
	dev->roc_ml = roc_ml;

	ml->ml_reg_addr = ml->pci_dev->mem_resource[0].addr;

	plt_ml_dbg("ML: PCI Physical Address : 0x%016lx",
		   ml->pci_dev->mem_resource[0].phys_addr);
	plt_ml_dbg("ML: PCI Virtual Address : 0x%016lx",
		   (uint64_t)ml->pci_dev->mem_resource[0].addr);

	plt_spinlock_init(&roc_ml->sp_spinlock);
	plt_spinlock_init(&roc_ml->fp_spinlock);

	return 0;
}

int
roc_ml_dev_fini(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	if (ml == NULL)
		return -EINVAL;

	return 0;
}

int
roc_ml_blk_init(struct roc_bphy *roc_bphy, struct roc_ml *roc_ml)
{
	struct dev *dev;
	struct ml *ml;

	if ((roc_ml == NULL) || (roc_bphy == NULL))
		return -EINVAL;

	PLT_STATIC_ASSERT(sizeof(struct ml) <= ROC_ML_MEM_SZ);

	ml = roc_ml_to_ml_priv(roc_ml);
	memset(ml, 0, sizeof(*ml));

	dev = &ml->dev;

	ml->pci_dev = roc_bphy->pci_dev;
	dev->roc_ml = roc_ml;

	plt_ml_dbg("MLAB: Physical Address : 0x%016lx",
		   (uint64_t)PLT_PTR_ADD(ml->pci_dev->mem_resource[0].phys_addr,
					 ML_MLAB_BLK_OFFSET));
	plt_ml_dbg("MLAB: Virtual Address : 0x%016lx",
		   (uint64_t)PLT_PTR_ADD(ml->pci_dev->mem_resource[0].addr,
					 ML_MLAB_BLK_OFFSET));

	ml->ml_reg_addr = PLT_PTR_ADD(ml->pci_dev->mem_resource[0].addr,
				      ML_MLAB_BLK_OFFSET);

	plt_spinlock_init(&roc_ml->sp_spinlock);
	plt_spinlock_init(&roc_ml->fp_spinlock);

	return 0;
}

int
roc_ml_blk_fini(struct roc_bphy *roc_bphy, struct roc_ml *roc_ml)
{
	struct ml *ml;

	if ((roc_ml == NULL) || (roc_bphy == NULL))
		return -EINVAL;

	ml = roc_ml_to_ml_priv(roc_ml);

	if (ml == NULL)
		return -EINVAL;

	return 0;
}
