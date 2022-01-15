/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <eal_firmware.h>
#include <mldev_pmd.h>
#include <rte_eal.h>
#include <rte_mldev.h>

#include "cn10k_mldev.h"
#include "cn10k_mldev_ops.h"
#include "cnxk_mldev.h"

#include "roc_api.h"

#define ML_MEMZONE_FIRMWARE "cn10k_ml_firmware_mz"

/* ML firmware macros */
#define FW_BUFFER_SIZE	 0x2800000
#define FW_LINKER_OFFSET 0x80000
#define FW_WAIT_CYCLES	 100

/* Timeout */
#define ML_TIMEOUT_FW_LOAD_S 10

/* Job status */
#define ML_STATUS_SUCCESS 0x0
#define ML_STATUS_FAILURE 0xFF

static void
cn10k_ml_fw_print_info(struct cnxk_ml_dev *cnxk_dev)
{
	plt_ml_dbg("Firmware capabilities = 0x%016lx",
		   cnxk_dev->load_fw->cap.u);
	plt_ml_dbg("Version = %s", cnxk_dev->load_fw->version);
	plt_ml_dbg("fw_core0_dbg_ptr = 0x%016lx",
		   cnxk_dev->load_fw->debug_cap.fw_core0_dbg_ptr);
	plt_ml_dbg("fw_core1_dbg_ptr = 0x%016lx",
		   cnxk_dev->load_fw->debug_cap.fw_core1_dbg_ptr);
	plt_ml_dbg("fw_core0_exception_state = 0x%016lx",
		   cnxk_dev->load_fw->debug_cap.fw_core0_exception_buffer);
	plt_ml_dbg("fw_core1_exception_state = 0x%016lx",
		   cnxk_dev->load_fw->debug_cap.fw_core1_exception_buffer);
	plt_ml_dbg("fw_exception_state_size = 0x%016lx",
		   cnxk_dev->load_fw->debug_cap.fw_exception_state_size);
}

static int
cn10k_ml_fw_load(void *buffer, size_t size, struct cnxk_ml_dev *cnxk_dev)
{
	uint64_t wait_cycles;
	uint64_t start_cycle;
	uint64_t reg_val64;
	uint32_t reg_val32;
	uint64_t offset;
	bool timeout;
	uint32_t w0;
	uint32_t w1;
	int ret = 0;
	uint8_t i;

	/* Reset HEAD and TAIL debug pointer registers */
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C0);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C0);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C1);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C1);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_EXCEPTION_SP_C0);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_EXCEPTION_SP_C1);

	/* (1) Write firmware images for ACC's two A35 cores to the ML region in
	 * LLC / DRAM.
	 */
	memcpy(PLT_PTR_ADD(cnxk_dev->data_fw, FW_LINKER_OFFSET), buffer, size);

	/* (2) Set ML(0)_MLR_BASE = Base IOVA of the ML region in LLC/DRAM.
	 */
	reg_val64 =
		PLT_PTR_SUB_U64_CAST(cnxk_dev->data_fw, rte_eal_get_baseaddr());
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_MLR_BASE);
	plt_ml_dbg("ML_MLR_BASE => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_MLR_BASE));

	/* (3) Set ML(0)_AXI_BRIDGE_CTRL(1) = 0x184003 to remove backpressure
	 * check on DMA AXI bridge.
	 */
	reg_val64 = (ROC_ML_AXI_BRIDGE_CTRL_AXI_RESP_CTRL |
		     ROC_ML_AXI_BRIDGE_CTRL_BRIDGE_CTRL_MODE |
		     ROC_ML_AXI_BRIDGE_CTRL_NCB_WR_BLK |
		     ROC_ML_AXI_BRIDGE_CTRL_FORCE_WRESP_OK |
		     ROC_ML_AXI_BRIDGE_CTRL_FORCE_RRESP_OK);
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_AXI_BRIDGE_CTRL(1));
	plt_ml_dbg("ML_AXI_BRIDGE_CTRL(1) => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_AXI_BRIDGE_CTRL(1)));

	/* (4) Set ML(0)_ANB(0..2)_BACKP_DISABLE = 0x3 to remove backpressure on
	 * the AXI to NCB bridges.
	 */
	for (i = 0; i < ML_ANBX_NR; i++) {
		reg_val64 = (ROC_ML_ANBX_BACKP_DISABLE_EXTMSTR_B_BACKP_DISABLE |
			     ROC_ML_ANBX_BACKP_DISABLE_EXTMSTR_R_BACKP_DISABLE);
		roc_ml_reg_write64(&cnxk_dev->ml, reg_val64,
				   ML_ANBX_BACKP_DISABLE(i));
		plt_ml_dbg("ML_ANBX_BACKP_DISABLE(%d) => 0x%016lx", i,
			   roc_ml_reg_read64(&cnxk_dev->ml,
					     ML_ANBX_BACKP_DISABLE(i)));
	}

	/* (5) Set ML(0)_ANB(0..2)_NCBI_P_OVR = 0x3000 and
	 * ML(0)_ANB(0..2)_NCBI_NP_OVR = 0x3000 to signal all ML transactions as
	 * non-secure.
	 */
	for (i = 0; i < ML_ANBX_NR; i++) {
		reg_val64 = (ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_NS_OVR |
			     ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_NS_OVR_VLD);
		roc_ml_reg_write64(&cnxk_dev->ml, reg_val64,
				   ML_ANBX_NCBI_P_OVR(i));
		plt_ml_dbg("ML_ANBX_NCBI_P_OVR(%d) => 0x%016lx", i,
			   roc_ml_reg_read64(&cnxk_dev->ml,
					     ML_ANBX_NCBI_P_OVR(i)));

		reg_val64 |= (ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_NS_OVR |
			      ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_NS_OVR_VLD);
		roc_ml_reg_write64(&cnxk_dev->ml, reg_val64,
				   ML_ANBX_NCBI_NP_OVR(i));
		plt_ml_dbg("ML_ANBX_NCBI_NP_OVR(%d) => 0x%016lx", i,
			   roc_ml_reg_read64(&cnxk_dev->ml,
					     ML_ANBX_NCBI_NP_OVR(i)));
	}

	/* (6) Set ML(0)_CFG[MLIP_CLK_FORCE] = 1, to force turning on the MLIP
	 * clock.
	 */
	reg_val64 = roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG);
	reg_val64 |= ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG));

	/* (7) Set ML(0)_JOB_MGR_CTRL[STALL_ON_IDLE] = 0, to make sure the boot
	 * request is accepted when there is no job in the command queue.
	 */
	reg_val64 = roc_ml_reg_read64(&cnxk_dev->ml, ML_JOB_MGR_CTRL);
	reg_val64 &= ~ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_JOB_MGR_CTRL);
	plt_ml_dbg("ML_JOB_MGR_CTRL => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_JOB_MGR_CTRL));

	/* (8) Set ML(0)_CFG[ENA] = 0 and ML(0)_CFG[MLIP_ENA] = 1 to bring MLIP
	 * out of reset while keeping the job manager disabled.
	 */
	reg_val64 = roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG);
	reg_val64 |= ROC_ML_CFG_MLIP_ENA;
	reg_val64 &= ~ROC_ML_CFG_ENA;
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG));

	/* (9) Wait at least 70 coprocessor clock cycles.
	 */
	plt_delay_us(FW_WAIT_CYCLES);

	/* Update FW load completion structure */
	cnxk_dev->load_fw->hdr.compl_W1.status_ptr =
		PLT_U64_CAST(&cnxk_dev->status_ptr);
	cnxk_dev->load_fw->hdr.command = CNXK_ML_JOB_CMD_FW_LOAD;
	cnxk_dev->load_fw->hdr.job_result =
		roc_ml_addr_ap2mlip(&cnxk_dev->ml, &cnxk_dev->job_result);
	plt_write64(ML_CN10K_POLL_JOB_START, &cnxk_dev->status_ptr);
	plt_wmb();

	/* Enqueue FW load through scratch registers */
	roc_ml_scratch_enqueue(&cnxk_dev->ml, cnxk_dev->load_fw);

	/* (10) Write ML outbound addresses pointing to the firmware images
	 * written in step 1 to the following registers:
	 * ML(0)_A35_0_RST_VECTOR_BASE_W(0..1) for core 0,
	 * ML(0)_A35_1_RST_VECTOR_BASE_W(0..1) for core 1. The value written to
	 * each register is the AXI outbound address divided by 4. Read after
	 * write.
	 */
	offset = PLT_PTR_ADD_U64_CAST(
		cnxk_dev->data_fw,
		FW_LINKER_OFFSET -
			roc_ml_reg_read64(&cnxk_dev->ml, ML_MLR_BASE));
	offset = (offset + ML_AXI_START_ADDR) / 4;
	w0 = PLT_U32_CAST(offset & 0xFFFFFFFFLL);
	w1 = PLT_U32_CAST(offset >> 32);

	roc_ml_reg_write32(&cnxk_dev->ml, w0, ML_A35_0_RST_VECTOR_BASE_W(0));
	reg_val32 =
		roc_ml_reg_read32(&cnxk_dev->ml, ML_A35_0_RST_VECTOR_BASE_W(0));
	plt_ml_dbg("ML_A35_0_RST_VECTOR_BASE_W(0) => 0x%08x", reg_val32);

	roc_ml_reg_write32(&cnxk_dev->ml, w1, ML_A35_0_RST_VECTOR_BASE_W(1));
	reg_val32 =
		roc_ml_reg_read32(&cnxk_dev->ml, ML_A35_0_RST_VECTOR_BASE_W(1));
	plt_ml_dbg("ML_A35_0_RST_VECTOR_BASE_W(1) => 0x%08x", reg_val32);

	roc_ml_reg_write32(&cnxk_dev->ml, w0, ML_A35_1_RST_VECTOR_BASE_W(0));
	reg_val32 =
		roc_ml_reg_read32(&cnxk_dev->ml, ML_A35_1_RST_VECTOR_BASE_W(0));
	plt_ml_dbg("ML_A35_1_RST_VECTOR_BASE_W(0) => 0x%08x", reg_val32);

	roc_ml_reg_write32(&cnxk_dev->ml, w1, ML_A35_1_RST_VECTOR_BASE_W(1));
	reg_val32 =
		roc_ml_reg_read32(&cnxk_dev->ml, ML_A35_1_RST_VECTOR_BASE_W(1));
	plt_ml_dbg("ML_A35_1_RST_VECTOR_BASE_W(1) => 0x%08x", reg_val32);

	/* (11) Clear MLIP’s ML(0)_SW_RST_CTRL[ACC_RST]. This will bring the ACC
	 * cores and other MLIP components out of reset. The cores will execute
	 * firmware from the ML region as written in step 1.
	 */
	reg_val32 = roc_ml_reg_read32(&cnxk_dev->ml, ML_SW_RST_CTRL);
	reg_val32 &= ~ROC_ML_SW_RST_CTRL_ACC_RST;
	roc_ml_reg_write32(&cnxk_dev->ml, reg_val32, ML_SW_RST_CTRL);
	reg_val32 = roc_ml_reg_read32(&cnxk_dev->ml, ML_SW_RST_CTRL);
	plt_ml_dbg("ML_SW_RST_CTRL => 0x%08x", reg_val32);

	/* (12) Wait for notification from firmware that ML is ready for job
	 * execution.
	 */
	timeout = true;
	wait_cycles = ML_TIMEOUT_FW_LOAD_S * plt_tsc_hz();
	start_cycle = plt_tsc_cycles();
	plt_rmb();
	do {
		if (roc_ml_scratch_is_done_bit_set(&cnxk_dev->ml) &&
		    (plt_read64(&cnxk_dev->status_ptr) ==
		     ML_CN10K_POLL_JOB_FINISH)) {
			timeout = false;
			break;
		}
	} while (plt_tsc_cycles() - start_cycle < wait_cycles);

	/* Check firmware load status, clean-up and exit on failure. */
	if ((!timeout) && (cnxk_dev->job_result.status == ML_STATUS_SUCCESS)) {
		cn10k_ml_fw_print_info(cnxk_dev);
	} else {
		/* Set ML to disable new jobs */
		reg_val64 = (ROC_ML_CFG_JD_SIZE | ROC_ML_CFG_MLIP_ENA);
		roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_CFG);

		/* Clear scratch registers */
		roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_WORK_PTR);
		roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_AP_FW_COMM);

		if (timeout) {
			plt_err("Firmware load timeout");
			ret = -ETIME;
		} else {
			plt_err("Firmware load failed");
			ret = -1;
		}

		return ret;
	}

	/* (13) Set ML(0)_JOB_MGR_CTRL[STALL_ON_IDLE] = 0x1; this is needed to
	 * shut down the MLIP clock when there are no more jobs to process.
	 */
	reg_val64 = roc_ml_reg_read64(&cnxk_dev->ml, ML_JOB_MGR_CTRL);
	reg_val64 |= ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_JOB_MGR_CTRL);
	plt_ml_dbg("ML_JOB_MGR_CTRL => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_JOB_MGR_CTRL));

	/* (14) Set ML(0)_CFG[MLIP_CLK_FORCE] = 0; the MLIP clock will be turned
	 * on/off based on job activities.
	 */
	reg_val64 = roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG);
	reg_val64 &= ~ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG));

	/* (15) Set ML(0)_CFG[ENA] to enable ML job execution. */
	reg_val64 = roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG);
	reg_val64 |= ROC_ML_CFG_ENA;
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_CFG));

	/* Reset scratch registers */
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_AP_FW_COMM);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_WORK_PTR);

	return ret;
}

int
cn10k_ml_dev_config(struct rte_mldev *dev,
		    __rte_unused struct rte_mldev_config *conf)
{
	struct cnxk_ml_dev *cnxk_dev = dev->data->dev_private;
	const struct plt_memzone *mz;
	uint64_t reg_val64;
	uint64_t mz_size;
	size_t bufsz;
	void *buf;

	/* Reserve memzone for firmware load completion and data */
	mz_size = sizeof(struct cnxk_ml_fw_load_compl) + FW_BUFFER_SIZE;
	mz = plt_memzone_reserve_aligned(ML_MEMZONE_FIRMWARE, mz_size, 0,
					 ML_CN10K_ALIGN_SIZE);
	if (!mz) {
		plt_err("plt_memzone_reserve failed : %s", ML_MEMZONE_FIRMWARE);
		return -1;
	}
	cnxk_dev->load_fw = mz->addr;
	cnxk_dev->data_fw =
		PLT_PTR_ADD(mz->addr, sizeof(struct cnxk_ml_fw_load_compl));

	/* Reset firmware load completion */
	memset(cnxk_dev->load_fw, 0, sizeof(struct cnxk_ml_fw_load_compl));
	memset(&cnxk_dev->load_fw->version[0], '\0', ML_FW_VERSION_STRLEN);

	/* Enable ML device */
	reg_val64 = (ROC_ML_CFG_JD_SIZE | ROC_ML_CFG_MLIP_ENA);
	roc_ml_reg_write64(&cnxk_dev->ml, reg_val64, ML_CFG);

	if (rte_firmware_read(cnxk_dev->firmware, &buf, &bufsz) < 0) {
		plt_err("Can't read firmware data: %s\n", cnxk_dev->firmware);
		return -1;
	}

	/* Load firmware */
	cn10k_ml_fw_load(buf, bufsz, cnxk_dev);

	free(buf);

	return 0;
}

int
cn10k_ml_dev_close(struct rte_mldev *dev)
{
	struct cnxk_ml_dev *cnxk_dev = dev->data->dev_private;
	const struct plt_memzone *mz;
	int ret = 0;

	/* Set MLIP clock off and stall on */
	roc_ml_clk_force_off(&cnxk_dev->ml);
	roc_ml_dma_stall_on(&cnxk_dev->ml);
	ret = roc_ml_mlip_reset(&cnxk_dev->ml);

	/* Clear scratch registers */
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_WORK_PTR);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_AP_FW_COMM);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C0);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C0);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C1);
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C1);

	/* Reset ML_MLR_BASE */
	roc_ml_reg_write64(&cnxk_dev->ml, 0, ML_MLR_BASE);
	plt_ml_dbg("ML_MLR_BASE = 0x%016lx",
		   roc_ml_reg_read64(&cnxk_dev->ml, ML_MLR_BASE));

	mz = plt_memzone_lookup(ML_MEMZONE_FIRMWARE);
	if (mz)
		plt_memzone_free(mz);

	return ret;
}

struct rte_mldev_ops cn10k_ml_ops = {
	/* Device control ops */
	.dev_configure = cn10k_ml_dev_config,
	.dev_close = cn10k_ml_dev_close,
};
