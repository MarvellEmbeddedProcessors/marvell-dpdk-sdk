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

/* ML firmware macros */
#define FW_MEMZONE_NAME	 "ml_cn10k_fw_mz"
#define FW_BUFFER_SIZE	 0x800000
#define FW_LINKER_OFFSET 0x80000
#define FW_WAIT_CYCLES	 100

/* ML configuration macros */
#define ML_CONFIG_MEMZONE_NAME "ml_cn10k_config_mz"

/* ML model macros */
#define ML_MODEL_MEMZONE_NAME "ml_cn10k_model_mz"

/* Timeout */
#define ML_TIMEOUT_FW_LOAD_S 10

/* Job status */
#define ML_STATUS_SUCCESS 0x0
#define ML_STATUS_FAILURE 0xFF

static void
cn10k_ml_fw_print_info(struct cnxk_ml_fw *ml_fw)
{
	plt_ml_dbg("Firmware capabilities = 0x%016lx", ml_fw->load_fw->cap.u);
	plt_ml_dbg("Version = %s", ml_fw->load_fw->version);
	plt_ml_dbg("fw_core0_dbg_ptr = 0x%016lx",
		   ml_fw->load_fw->debug_cap.fw_core0_dbg_ptr);
	plt_ml_dbg("fw_core1_dbg_ptr = 0x%016lx",
		   ml_fw->load_fw->debug_cap.fw_core1_dbg_ptr);
	plt_ml_dbg("fw_dbg_buffer_size = 0x%08x",
		   ml_fw->load_fw->debug_cap.fw_dbg_buffer_size);
	plt_ml_dbg("fw_core0_exception_state = 0x%016lx",
		   ml_fw->load_fw->debug_cap.fw_core0_exception_buffer);
	plt_ml_dbg("fw_core1_exception_state = 0x%016lx",
		   ml_fw->load_fw->debug_cap.fw_core1_exception_buffer);
	plt_ml_dbg("fw_exception_state_size = 0x%08x",
		   ml_fw->load_fw->debug_cap.fw_exception_state_size);
}

static int
cn10k_ml_fw_load(struct cnxk_ml_fw *ml_fw, void *buffer, uint64_t size)
{
	struct cnxk_ml_dev *ml_dev;
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

	ml_dev = ml_fw->ml_dev;

	/* Reset HEAD and TAIL debug pointer registers */
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C0);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C0);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C1);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C1);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_EXCEPTION_SP_C0);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_EXCEPTION_SP_C1);

	/* (1) Write firmware images for ACC's two A35 cores to the ML region in
	 * LLC / DRAM.
	 */
	memcpy(PLT_PTR_ADD(ml_fw->data_fw, FW_LINKER_OFFSET), buffer, size);

	/* (2) Set ML(0)_MLR_BASE = Base IOVA of the ML region in LLC/DRAM.
	 */
	reg_val64 =
		PLT_PTR_SUB_U64_CAST(ml_fw->data_fw, rte_eal_get_baseaddr());
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_MLR_BASE);
	plt_ml_dbg("ML_MLR_BASE => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_MLR_BASE));

	/* (3) Set ML(0)_AXI_BRIDGE_CTRL(1) = 0x184003 to remove backpressure
	 * check on DMA AXI bridge.
	 */
	reg_val64 = (ROC_ML_AXI_BRIDGE_CTRL_AXI_RESP_CTRL |
		     ROC_ML_AXI_BRIDGE_CTRL_BRIDGE_CTRL_MODE |
		     ROC_ML_AXI_BRIDGE_CTRL_NCB_WR_BLK |
		     ROC_ML_AXI_BRIDGE_CTRL_FORCE_WRESP_OK |
		     ROC_ML_AXI_BRIDGE_CTRL_FORCE_RRESP_OK);
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_AXI_BRIDGE_CTRL(1));
	plt_ml_dbg("ML_AXI_BRIDGE_CTRL(1) => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_AXI_BRIDGE_CTRL(1)));

	/* (4) Set ML(0)_ANB(0..2)_BACKP_DISABLE = 0x3 to remove backpressure on
	 * the AXI to NCB bridges.
	 */
	for (i = 0; i < ML_ANBX_NR; i++) {
		reg_val64 = (ROC_ML_ANBX_BACKP_DISABLE_EXTMSTR_B_BACKP_DISABLE |
			     ROC_ML_ANBX_BACKP_DISABLE_EXTMSTR_R_BACKP_DISABLE);
		roc_ml_reg_write64(&ml_dev->roc, reg_val64,
				   ML_ANBX_BACKP_DISABLE(i));
		plt_ml_dbg("ML_ANBX_BACKP_DISABLE(%d) => 0x%016lx", i,
			   roc_ml_reg_read64(&ml_dev->roc,
					     ML_ANBX_BACKP_DISABLE(i)));
	}

	/* (5) Set ML(0)_ANB(0..2)_NCBI_P_OVR = 0x3000 and
	 * ML(0)_ANB(0..2)_NCBI_NP_OVR = 0x3000 to signal all ML transactions as
	 * non-secure.
	 */
	for (i = 0; i < ML_ANBX_NR; i++) {
		reg_val64 = (ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_NS_OVR |
			     ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_NS_OVR_VLD);
		roc_ml_reg_write64(&ml_dev->roc, reg_val64,
				   ML_ANBX_NCBI_P_OVR(i));
		plt_ml_dbg(
			"ML_ANBX_NCBI_P_OVR(%d) => 0x%016lx", i,
			roc_ml_reg_read64(&ml_dev->roc, ML_ANBX_NCBI_P_OVR(i)));

		reg_val64 |= (ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_NS_OVR |
			      ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_NS_OVR_VLD);
		roc_ml_reg_write64(&ml_dev->roc, reg_val64,
				   ML_ANBX_NCBI_NP_OVR(i));
		plt_ml_dbg("ML_ANBX_NCBI_NP_OVR(%d) => 0x%016lx", i,
			   roc_ml_reg_read64(&ml_dev->roc,
					     ML_ANBX_NCBI_NP_OVR(i)));
	}

	/* (6) Set ML(0)_CFG[MLIP_CLK_FORCE] = 1, to force turning on the MLIP
	 * clock.
	 */
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 |= ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_CFG));

	/* (7) Set ML(0)_JOB_MGR_CTRL[STALL_ON_IDLE] = 0, to make sure the boot
	 * request is accepted when there is no job in the command queue.
	 */
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_JOB_MGR_CTRL);
	reg_val64 &= ~ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_JOB_MGR_CTRL);
	plt_ml_dbg("ML_JOB_MGR_CTRL => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_JOB_MGR_CTRL));

	/* (8) Set ML(0)_CFG[ENA] = 0 and ML(0)_CFG[MLIP_ENA] = 1 to bring MLIP
	 * out of reset while keeping the job manager disabled.
	 */
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 |= ROC_ML_CFG_MLIP_ENA;
	reg_val64 &= ~ROC_ML_CFG_ENA;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_CFG));

	/* (9) Wait at least 70 coprocessor clock cycles.
	 */
	plt_delay_us(FW_WAIT_CYCLES);

	/* Update FW load completion structure */
	ml_fw->load_fw->hdr.compl_W1.status_ptr =
		PLT_U64_CAST(&ml_fw->status_ptr);
	ml_fw->load_fw->hdr.command = CNXK_ML_JOB_CMD_FW_LOAD;
	ml_fw->load_fw->hdr.job_result =
		roc_ml_addr_ap2mlip(&ml_dev->roc, &ml_fw->job_result);
	plt_write64(ML_CN10K_POLL_JOB_START, &ml_fw->status_ptr);
	plt_wmb();

	/* Enqueue FW load through scratch registers */
	roc_ml_scratch_enqueue(&ml_dev->roc, ml_fw->load_fw);

	/* (10) Write ML outbound addresses pointing to the firmware images
	 * written in step 1 to the following registers:
	 * ML(0)_A35_0_RST_VECTOR_BASE_W(0..1) for core 0,
	 * ML(0)_A35_1_RST_VECTOR_BASE_W(0..1) for core 1. The value written to
	 * each register is the AXI outbound address divided by 4. Read after
	 * write.
	 */
	offset = PLT_PTR_ADD_U64_CAST(
		ml_fw->data_fw,
		FW_LINKER_OFFSET -
			roc_ml_reg_read64(&ml_dev->roc, ML_MLR_BASE));
	offset = (offset + ML_AXI_START_ADDR) / 4;
	w0 = PLT_U32_CAST(offset & 0xFFFFFFFFLL);
	w1 = PLT_U32_CAST(offset >> 32);

	roc_ml_reg_write32(&ml_dev->roc, w0, ML_A35_0_RST_VECTOR_BASE_W(0));
	reg_val32 =
		roc_ml_reg_read32(&ml_dev->roc, ML_A35_0_RST_VECTOR_BASE_W(0));
	plt_ml_dbg("ML_A35_0_RST_VECTOR_BASE_W(0) => 0x%08x", reg_val32);

	roc_ml_reg_write32(&ml_dev->roc, w1, ML_A35_0_RST_VECTOR_BASE_W(1));
	reg_val32 =
		roc_ml_reg_read32(&ml_dev->roc, ML_A35_0_RST_VECTOR_BASE_W(1));
	plt_ml_dbg("ML_A35_0_RST_VECTOR_BASE_W(1) => 0x%08x", reg_val32);

	roc_ml_reg_write32(&ml_dev->roc, w0, ML_A35_1_RST_VECTOR_BASE_W(0));
	reg_val32 =
		roc_ml_reg_read32(&ml_dev->roc, ML_A35_1_RST_VECTOR_BASE_W(0));
	plt_ml_dbg("ML_A35_1_RST_VECTOR_BASE_W(0) => 0x%08x", reg_val32);

	roc_ml_reg_write32(&ml_dev->roc, w1, ML_A35_1_RST_VECTOR_BASE_W(1));
	reg_val32 =
		roc_ml_reg_read32(&ml_dev->roc, ML_A35_1_RST_VECTOR_BASE_W(1));
	plt_ml_dbg("ML_A35_1_RST_VECTOR_BASE_W(1) => 0x%08x", reg_val32);

	/* (11) Clear MLIP’s ML(0)_SW_RST_CTRL[ACC_RST]. This will bring the ACC
	 * cores and other MLIP components out of reset. The cores will execute
	 * firmware from the ML region as written in step 1.
	 */
	reg_val32 = roc_ml_reg_read32(&ml_dev->roc, ML_SW_RST_CTRL);
	reg_val32 &= ~ROC_ML_SW_RST_CTRL_ACC_RST;
	roc_ml_reg_write32(&ml_dev->roc, reg_val32, ML_SW_RST_CTRL);
	reg_val32 = roc_ml_reg_read32(&ml_dev->roc, ML_SW_RST_CTRL);
	plt_ml_dbg("ML_SW_RST_CTRL => 0x%08x", reg_val32);

	/* (12) Wait for notification from firmware that ML is ready for job
	 * execution.
	 */
	timeout = true;
	wait_cycles = ML_TIMEOUT_FW_LOAD_S * plt_tsc_hz();
	start_cycle = plt_tsc_cycles();
	plt_rmb();
	do {
		if (roc_ml_scratch_is_done_bit_set(&ml_dev->roc) &&
		    (plt_read64(&ml_fw->status_ptr) ==
		     ML_CN10K_POLL_JOB_FINISH)) {
			timeout = false;
			break;
		}
	} while (plt_tsc_cycles() - start_cycle < wait_cycles);

	/* Check firmware load status, clean-up and exit on failure. */
	if ((!timeout) && (ml_fw->job_result.status == ML_STATUS_SUCCESS)) {
		cn10k_ml_fw_print_info(ml_fw);
	} else {
		/* Set ML to disable new jobs */
		reg_val64 = (ROC_ML_CFG_JD_SIZE | ROC_ML_CFG_MLIP_ENA);
		roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);

		/* Clear scratch registers */
		roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_WORK_PTR);
		roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_AP_FW_COMM);

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
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_JOB_MGR_CTRL);
	reg_val64 |= ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_JOB_MGR_CTRL);
	plt_ml_dbg("ML_JOB_MGR_CTRL => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_JOB_MGR_CTRL));

	/* (14) Set ML(0)_CFG[MLIP_CLK_FORCE] = 0; the MLIP clock will be turned
	 * on/off based on job activities.
	 */
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 &= ~ROC_ML_CFG_MLIP_CLK_FORCE;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_CFG));

	/* (15) Set ML(0)_CFG[ENA] to enable ML job execution. */
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 |= ROC_ML_CFG_ENA;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_CFG));

	/* Reset scratch registers */
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_AP_FW_COMM);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_WORK_PTR);

	/* Disable job execution, to be enabled in start */
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 &= ~ROC_ML_CFG_ENA;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_CFG));

	return ret;
}

int
cn10k_ml_dev_configure(struct rte_mldev *dev, struct rte_mldev_config *conf)
{
	struct cnxk_ml_config *ml_config;
	const struct plt_memzone *mz;
	struct cnxk_ml_dev *ml_dev;
	struct cnxk_ml_fw *ml_fw;
	uint64_t ml_models_size;
	uint64_t reg_val64;
	uint32_t model_id;
	uint64_t mz_size;
	uint64_t fw_size;
	void *fw_buffer;
	int ret = 0;

	if (dev == NULL || conf == NULL)
		return -EINVAL;

	/* Update device reference in firmware and set handles */
	ml_dev = dev->data->dev_private;
	ml_fw = &ml_dev->ml_fw;
	ml_fw->ml_dev = ml_dev;

	/* Reserve memzone for firmware load completion and data */
	mz_size = sizeof(struct cnxk_ml_fw_load_compl) + FW_BUFFER_SIZE;
	mz = plt_memzone_reserve_aligned(FW_MEMZONE_NAME, mz_size, 0,
					 ML_CN10K_ALIGN_SIZE);
	if (mz == NULL) {
		plt_err("plt_memzone_reserve failed : %s", FW_MEMZONE_NAME);
		return -ENOMEM;
	}
	ml_fw->load_fw = mz->addr;
	ml_fw->data_fw =
		PLT_PTR_ADD(mz->addr, sizeof(struct cnxk_ml_fw_load_compl));

	/* Reset firmware load completion */
	memset(ml_fw->load_fw, 0, sizeof(struct cnxk_ml_fw_load_compl));
	memset(&ml_fw->load_fw->version[0], '\0', ML_FW_VERSION_STRLEN);

	/* Enable ML device */
	reg_val64 = (ROC_ML_CFG_JD_SIZE | ROC_ML_CFG_MLIP_ENA);
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);

	/* Read firmware binary to a local buffer */
	ret = rte_firmware_read(ml_fw->filepath, &fw_buffer, &fw_size);
	if (ret < 0) {
		plt_err("Can't read firmware data: %s\n", ml_fw->filepath);
		goto err_exit;
	}

	/* Load firmware */
	ret = cn10k_ml_fw_load(ml_fw, fw_buffer, fw_size);
	free(fw_buffer);
	if (ret != 0)
		goto err_exit;

	ml_config = &ml_dev->ml_config;
	ml_config->ml_dev = ml_dev;
	ml_config->max_models_created = ML_CN10K_MAX_MODELS;

	/* Reserve memzone for configuration data and update ml_config */
	ml_models_size = PLT_ALIGN_CEIL(sizeof(struct cnxk_ml_model *) *
						ML_CN10K_MAX_MODELS,
					ML_CN10K_ALIGN_SIZE);
	mz_size = ml_models_size;
	mz = plt_memzone_reserve_aligned(ML_CONFIG_MEMZONE_NAME, mz_size, 0,
					 ML_CN10K_ALIGN_SIZE);
	if (mz == NULL) {
		plt_err("plt_memzone_reserve failed : %s",
			ML_CONFIG_MEMZONE_NAME);
		goto err_exit;
	}

	ml_config->ml_models = mz->addr;
	for (model_id = 0; model_id < ml_config->max_models_created; model_id++)
		ml_config->ml_models[model_id] = NULL;

	rte_spinlock_init(&ml_config->scratch_lock);
	rte_spinlock_init(&ml_config->run_lock);

	ml_config->active = true;

	return 0;

err_exit:
	/* Clear resources */
	mz = plt_memzone_lookup(ML_CONFIG_MEMZONE_NAME);
	if (mz != NULL)
		plt_memzone_free(mz);

	mz = plt_memzone_lookup(FW_MEMZONE_NAME);
	if (mz != NULL)
		plt_memzone_free(mz);

	/* Disable device */
	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 &= ~ROC_ML_CFG_MLIP_ENA;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);

	return ret;
}

int
cn10k_ml_dev_close(struct rte_mldev *dev)
{
	struct cnxk_ml_config *ml_config;
	const struct plt_memzone *mz;
	struct cnxk_ml_dev *ml_dev;
	int ret = 0;

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;

	/* Set config inactive */
	ml_config->active = false;

	/* Set MLIP clock off and stall on */
	roc_ml_clk_force_off(&ml_dev->roc);
	roc_ml_dma_stall_on(&ml_dev->roc);
	ret = roc_ml_mlip_reset(&ml_dev->roc);

	/* Clear scratch registers */
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_WORK_PTR);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_AP_FW_COMM);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C0);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C0);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_HEAD_C1);
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_SCRATCH_DBG_BUFFER_TAIL_C1);

	/* Reset ML_MLR_BASE */
	roc_ml_reg_write64(&ml_dev->roc, 0, ML_MLR_BASE);
	plt_ml_dbg("ML_MLR_BASE = 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_MLR_BASE));

	/* Clear resources */
	mz = plt_memzone_lookup(ML_CONFIG_MEMZONE_NAME);
	if (mz != NULL)
		plt_memzone_free(mz);

	mz = plt_memzone_lookup(FW_MEMZONE_NAME);
	if (mz)
		plt_memzone_free(mz);

	return ret;
}

int
cn10k_ml_dev_start(struct rte_mldev *dev)
{
	struct cnxk_ml_dev *ml_dev;
	uint64_t reg_val64;

	ml_dev = dev->data->dev_private;

	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 |= ROC_ML_CFG_ENA;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_CFG));

	return 0;
}

void
cn10k_ml_dev_stop(struct rte_mldev *dev)
{
	struct cnxk_ml_dev *ml_dev;
	uint64_t reg_val64;

	ml_dev = dev->data->dev_private;

	reg_val64 = roc_ml_reg_read64(&ml_dev->roc, ML_CFG);
	reg_val64 &= ~ROC_ML_CFG_ENA;
	roc_ml_reg_write64(&ml_dev->roc, reg_val64, ML_CFG);
	plt_ml_dbg("ML_CFG => 0x%016lx",
		   roc_ml_reg_read64(&ml_dev->roc, ML_CFG));
}

int
cn10k_ml_dev_model_create(struct rte_mldev *dev, struct rte_mldev_model *model,
			  uint8_t *model_id)
{
	struct cnxk_ml_config *ml_config;
	struct cnxk_ml_model *ml_model;
	struct cnxk_ml_dev *ml_dev;

	const struct plt_memzone *mz;
	char str[PATH_MAX] = {0};

	uint64_t mz_size;
	uint8_t idx;

	PLT_ASSERT(model != NULL);
	PLT_ASSERT(model_id != NULL);

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;

	/* Assign model ID */
	for (idx = 0; idx < ml_config->max_models_created; idx++) {
		if (ml_config->ml_models[idx] == NULL)
			break;
	}

	if (idx >= ml_config->max_models_created) {
		plt_err("No slots available to load new model");
		return -1;
	}

	/* Get MZ size */
	mz_size = PLT_ALIGN_CEIL(sizeof(struct cnxk_ml_model),
				 ML_CN10K_ALIGN_SIZE);

	/* Allocate memzone for model object and model data */
	snprintf(str, PATH_MAX, "%s_%d", ML_MODEL_MEMZONE_NAME, idx);
	mz = plt_memzone_reserve_aligned(str, mz_size, 0, ML_CN10K_ALIGN_SIZE);
	if (!mz) {
		plt_err("plt_memzone_reserve failed : %s", str);
		goto err_exit;
	}

	ml_model = mz->addr;
	ml_model->ml_config = ml_config;
	ml_model->model_id = idx;
	if (model->model_name) {
		plt_strlcpy(ml_model->name, model->model_name,
			    sizeof(ml_model->name));
		plt_ml_dbg("ml_model->name = %s", ml_model->name);
	}

	ml_model->state = CNXK_ML_MODEL_STATE_CREATED;
	ml_config->ml_models[idx] = ml_model;

	plt_ml_dbg("model = 0x%016lx", PLT_U64_CAST(ml_model));
	*model_id = idx;
	return 0;

err_exit:
	snprintf(str, PATH_MAX, "%s_%d", ML_MODEL_MEMZONE_NAME, idx);
	mz = plt_memzone_lookup(str);
	if (mz)
		plt_memzone_free(mz);

	return -1;
}

int
cn10k_ml_dev_model_destroy(struct rte_mldev *dev, uint8_t model_id)
{
	struct cnxk_ml_config *ml_config;
	struct cnxk_ml_dev *ml_dev;
	struct cnxk_ml_model *ml_model;
	char str[PATH_MAX] = {0};

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;
	ml_model = ml_config->ml_models[model_id];

	if (ml_model->state != CNXK_ML_MODEL_STATE_CREATED) {
		plt_err("Cannot destroy. Model in use.");
		return -EBUSY;
	}

	ml_config->ml_models[model_id] = NULL;

	snprintf(str, PATH_MAX, "%s_%d", ML_MODEL_MEMZONE_NAME, model_id);
	return plt_memzone_free(plt_memzone_lookup(str));
}

struct rte_mldev_ops cn10k_ml_ops = {
	/* Device control ops */
	.dev_configure = cn10k_ml_dev_configure,
	.dev_close = cn10k_ml_dev_close,
	.dev_start = cn10k_ml_dev_start,
	.dev_stop = cn10k_ml_dev_stop,
	.dev_model_create = cn10k_ml_dev_model_create,
	.dev_model_destroy = cn10k_ml_dev_model_destroy,
};
