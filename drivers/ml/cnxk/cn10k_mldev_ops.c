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
#define ML_MODEL_JD_POOL_SIZE 0x20
#define JD_LOAD		      (ML_MODEL_JD_POOL_SIZE - 2)
#define JD_UNLOAD	      (ML_MODEL_JD_POOL_SIZE - 1)

/* ML Job descriptor flags */
#define ML_FLAGS_POLL_COMPL BIT(0)
#define ML_FLAGS_SSO_COMPL  BIT(1)
#define ML_FLAGS_CMPC_COMPL BIT(2)

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

static int
cnxk_ml_io_type_get_size(enum rte_mldev_io_type type)
{
	switch (type) {
	case RTE_MLDEV_IO_TYPE_INT8:
	case RTE_MLDEV_IO_TYPE_UINT8:
		return sizeof(uint8_t);
	case RTE_MLDEV_IO_TYPE_INT16:
	case RTE_MLDEV_IO_TYPE_UINT16:
		return sizeof(uint16_t);
	case RTE_MLDEV_IO_TYPE_INT32:
	case RTE_MLDEV_IO_TYPE_UINT32:
		return sizeof(uint32_t);
	case RTE_MLDEV_IO_TYPE_FP16:
		return sizeof(float) / 2;
	case RTE_MLDEV_IO_TYPE_FP32:
		return sizeof(float);
	default:
		return -EINVAL;
	}
}

static int
cnxk_ml_metadata_check(struct cnxk_ml_model_metadata *metadata)
{
	uint8_t version[4];
	char str[PATH_MAX] = {0};

	if (strncmp((char *)metadata->metadata_header.magic,
		    ML_MODEL_MAGIC_STRING, 4) != 0) {
		plt_err("Invalid model, magic = %s",
			metadata->metadata_header.magic);
		return -1;
	}

	if (metadata->metadata_header.target_architecture !=
	    ML_MODEL_TARGET_ARCH) {
		plt_err("Model target architecture (%d) not supported",
			metadata->metadata_header.target_architecture);
		return -1;
	}

	memcpy(version, metadata->metadata_header.version, 4 * sizeof(uint8_t));
	snprintf(str, PATH_MAX, "%d.%d.%d.%d", version[0], version[1],
		 version[2], version[3]);
	if (version[0] * 1000 + version[1] * 100 < ML_MODEL_VERSION) {
		plt_err("Metadata version = %s (< %d.%d.%d.%d) not supported",
			str, (ML_MODEL_VERSION / 1000) % 10,
			(ML_MODEL_VERSION / 100) % 10,
			(ML_MODEL_VERSION / 10) % 10, ML_MODEL_VERSION % 10);
		return -1;
	}

	return 0;
}

static int
cnxk_ml_model_addr_update(struct cnxk_ml_model_metadata *model_metadata,
			  struct cnxk_ml_model_addr *model_addr, char **dmaaddr)
{
	int output_type_size, model_output_type_size;
	int input_type_size, model_input_type_size;
	uint32_t w, x, y, z;
	uint8_t i;

	/* Inputs */
	for (i = 0; i < model_metadata->model.num_input; i++) {
		input_type_size = cnxk_ml_io_type_get_size(
			model_metadata->input[i].input_type);
		if (input_type_size <= 0) {
			plt_err("input[%d] - invalid metadata, input_type = %d",
				i, model_metadata->input[i].input_type);
			return -EINVAL;
		}

		model_input_type_size = cnxk_ml_io_type_get_size(
			model_metadata->input[i].model_input_type);
		if (model_input_type_size <= 0) {
			plt_err("input[%d] - invalid metadata, model_input_type = %d",
				i, model_metadata->input[i].model_input_type);
			return -EINVAL;
		}

		if (model_metadata->input[i].relocatable != 1) {
			plt_err("input[%d] - invalid metadata, relocatable = %d",
				i, model_metadata->input[i].relocatable);
			return -EINVAL;
		}

		w = model_metadata->input[i].shape.w;
		x = model_metadata->input[i].shape.x;
		y = model_metadata->input[i].shape.y;
		z = model_metadata->input[i].shape.z;

		if (w == 0)
			w = 1;
		if (x == 0)
			x = 1;
		if (y == 0)
			y = 1;
		if (z == 0)
			z = 1;

		model_addr->input[i].sz = (w * x * y * z) * input_type_size;
		model_addr->input[i].sz_q =
			(w * x * y * z) * model_input_type_size;
		plt_ml_dbg("input[%d] - w:%d x:%d y:%d z:%d, sz = %d sz_q = %d",
			   i, w, x, y, z, model_addr->input[i].sz,
			   model_addr->input[i].sz_q);

		model_addr->input[i].addr_base = PLT_PTR_SUB(
			*dmaaddr, model_metadata->input[i].mem_offset);
		*dmaaddr = PLT_PTR_ADD(model_addr->input[i].addr_base,
				       model_metadata->input[i].mem_offset);

		model_addr->input[i].addr = *dmaaddr;
		*dmaaddr += model_addr->input[i].sz;
	}

	/* Outputs */
	for (i = 0; i < model_metadata->model.num_output; i++) {
		output_type_size = cnxk_ml_io_type_get_size(
			model_metadata->output[i].output_type);
		if (output_type_size <= 0) {
			plt_err("output[%d] - invalid metadata, output_type = %d",
				i, model_metadata->output[i].output_type);
			return -EINVAL;
		}

		model_output_type_size = cnxk_ml_io_type_get_size(
			model_metadata->output[i].model_output_type);
		if (model_output_type_size <= 0) {
			plt_err("output[%d] - invalid metadata, model_output_type = %d",
				i, model_metadata->output[i].model_output_type);
			return -EINVAL;
		}

		if (model_metadata->output[i].relocatable != 1) {
			plt_err("output[%d] - invalid metadata, relocatable = %d",
				i, model_metadata->output[i].relocatable);
			return -EINVAL;
		}

		model_addr->output[i].sz =
			model_metadata->output[i].size * output_type_size;
		model_addr->output[i].sz_q =
			model_metadata->output[i].size * model_output_type_size;

		plt_ml_dbg("output[%d] - sz = %d, sz_q = %d", i,
			   model_addr->output[i].sz,
			   model_addr->output[i].sz_q);

		model_addr->output[i].addr_base = PLT_PTR_SUB(
			*dmaaddr, model_metadata->output[i].mem_offset);
		*dmaaddr = PLT_PTR_ADD(model_addr->output[i].addr_base,
				       model_metadata->output[i].mem_offset);

		model_addr->output[i].addr = *dmaaddr;
		*dmaaddr += model_addr->output[i].sz;
	}

	return 0;
}

static void
cnxk_ml_jd_init(struct rte_mldev *dev, struct cnxk_ml_model *ml_model)
{
	struct cnxk_ml_model_metadata *model_metadata;
	struct cnxk_ml_model_addr *model_addr;
	struct cnxk_ml_dev *ml_dev;
	uint8_t i;

	ml_dev = dev->data->dev_private;
	model_addr = &ml_model->model_addr;
	model_metadata = &ml_model->model_metadata;

	/* Initialize load job descriptor */
	ml_model->jd[JD_LOAD].hdr.compl_W0.u = 0;
	ml_model->jd[JD_LOAD].hdr.compl_W1.status_ptr = 0; /* Updated at load */
	ml_model->jd[JD_LOAD].hdr.model_id = ml_model->model_id;
	ml_model->jd[JD_LOAD].hdr.command = CNXK_ML_JOB_CMD_LOAD;
	ml_model->jd[JD_LOAD].hdr.flags = 0;
	ml_model->jd[JD_LOAD].hdr.job_result = NULL; /* Updated at load */
	ml_model->jd[JD_LOAD].load.model_src_ddr_addr = PLT_U64_CAST(
		roc_ml_addr_ap2mlip(&ml_dev->roc, model_addr->init_load_addr));
	ml_model->jd[JD_LOAD].load.model_dst_ddr_addr = PLT_U64_CAST(
		roc_ml_addr_ap2mlip(&ml_dev->roc, model_addr->init_run_addr));
	ml_model->jd[JD_LOAD].load.model_init_offset = 0x0;
	ml_model->jd[JD_LOAD].load.model_main_offset =
		model_metadata->init_model.file_size;
	ml_model->jd[JD_LOAD].load.model_finish_offset =
		model_metadata->init_model.file_size +
		model_metadata->main_model.file_size;
	ml_model->jd[JD_LOAD].load.model_init_size =
		model_metadata->init_model.file_size;
	ml_model->jd[JD_LOAD].load.model_main_size =
		model_metadata->main_model.file_size;
	ml_model->jd[JD_LOAD].load.model_finish_size =
		model_metadata->finish_model.file_size;
	ml_model->jd[JD_LOAD].load.model_wb_offset =
		model_metadata->init_model.file_size +
		model_metadata->main_model.file_size +
		model_metadata->finish_model.file_size;
	ml_model->jd[JD_LOAD].load.num_layers =
		model_metadata->model.num_layers;
	ml_model->jd[JD_LOAD].load.num_gather_entries = 0;
	ml_model->jd[JD_LOAD].load.num_scatter_entries = 0;
	ml_model->jd[JD_LOAD].load.tilemask = 0x0; /* Updated at load */
	ml_model->jd[JD_LOAD].load.ocm_wb_base_address =
		0x0; /* Updated at load */
	ml_model->jd[JD_LOAD].load.ocm_wb_range_start =
		model_metadata->model.ocm_wb_range_start;
	ml_model->jd[JD_LOAD].load.ocm_wb_range_end =
		model_metadata->model.ocm_wb_range_end;
	ml_model->jd[JD_LOAD].load.ddr_wb_base_address =
		PLT_U64_CAST(roc_ml_addr_ap2mlip(
			&ml_dev->roc,
			PLT_PTR_ADD(model_addr->finish_load_addr,
				    model_metadata->finish_model.file_size)));
	ml_model->jd[JD_LOAD].load.ddr_wb_range_start =
		model_metadata->model.ddr_wb_range_start;
	ml_model->jd[JD_LOAD].load.ddr_wb_range_end =
		model_metadata->model.ddr_wb_range_end;
	ml_model->jd[JD_LOAD].load.input.s.ddr_range_start =
		model_metadata->model.ddr_input_range_start;
	ml_model->jd[JD_LOAD].load.input.s.ddr_range_end =
		model_metadata->model.ddr_input_range_end;
	ml_model->jd[JD_LOAD].load.output.s.ddr_range_start =
		model_metadata->model.ddr_output_range_start;
	ml_model->jd[JD_LOAD].load.output.s.ddr_range_end =
		model_metadata->model.ddr_output_range_end;

	/* Initialize unload job descriptor */
	memset(&ml_model->jd[JD_UNLOAD], 0, sizeof(struct cnxk_ml_jd));
	ml_model->jd[JD_UNLOAD].hdr.model_id = ml_model->model_id;
	ml_model->jd[JD_UNLOAD].hdr.command = CNXK_ML_JOB_CMD_UNLOAD;
	ml_model->jd[JD_UNLOAD].hdr.compl_W1.status_ptr =
		0; /* Updated at unload */

	/* Initialize run job descriptors */
	for (i = 0; i < ML_MODEL_JD_POOL_SIZE - 2; i++) {
		ml_model->jd[i].hdr.model_id = ml_model->model_id;
		ml_model->jd[i].hdr.command = CNXK_ML_JOB_CMD_RUN;
		ml_model->jd[i].hdr.flags = ML_FLAGS_SSO_COMPL;
		ml_model->jd[i].hdr.job_result = NULL;	 /* Updated at run */
		ml_model->jd[i].hdr.compl_W0.u = 0;	 /* Updated at run */
		ml_model->jd[i].hdr.compl_W1.W1 = 0;	 /* Updated at run */
		ml_model->jd[i].run.input_ddr_addr = 0;	 /* Updated at run */
		ml_model->jd[i].run.output_ddr_addr = 0; /* Updated at run */
	}
}

int
cn10k_ml_dev_configure(struct rte_mldev *dev, struct rte_mldev_config *conf)
{
	struct cn10k_ml_ocm_tile_info *ocm_tile_info;
	struct cnxk_ml_config *ml_config;
	const struct plt_memzone *mz;
	uint64_t ocm_tile_info_size;
	struct cnxk_ml_dev *ml_dev;
	struct cnxk_ml_fw *ml_fw;
	uint64_t ml_models_size;
	uint64_t reg_val64;
	uint32_t model_id;
	uint16_t tile_id;
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
	ocm_tile_info_size = PLT_ALIGN_CEIL(
		sizeof(struct cn10k_ml_ocm_tile_info) * ML_CN10K_OCM_NUMTILES,
		ML_CN10K_ALIGN_SIZE);
	mz_size = ml_models_size + ocm_tile_info_size;
	mz = plt_memzone_reserve_aligned(ML_CONFIG_MEMZONE_NAME, mz_size, 0,
					 ML_CN10K_ALIGN_SIZE);
	if (mz == NULL) {
		plt_err("plt_memzone_reserve failed : %s",
			ML_CONFIG_MEMZONE_NAME);
		goto err_exit;
	}

	ml_config->ml_models = mz->addr;
	ml_config->ocm_tile_info =
		PLT_PTR_ADD(ml_config->ml_models, ml_models_size);
	ml_config->max_models_created = ML_CN10K_MAX_MODELS;
	ml_config->ocm_num_tiles = ML_CN10K_OCM_NUMTILES;
	ml_config->ocm_size = ML_CN10K_OCM_TILESIZE;
	ml_config->ocm_page_size = ML_CN10K_OCM_PAGESIZE;
	ml_config->ocm_pages = ml_config->ocm_size / ml_config->ocm_page_size;
	ml_config->ocm_mask_words =
		ml_config->ocm_pages / (8 * sizeof(uint8_t));

	for (model_id = 0; model_id < ml_config->max_models_created; model_id++)
		ml_config->ml_models[model_id] = NULL;

	ocm_tile_info =
		(struct cn10k_ml_ocm_tile_info *)(ml_config->ocm_tile_info);
	for (tile_id = 0; tile_id < ml_config->ocm_num_tiles; tile_id++)
		ocm_tile_info[tile_id].last_wb_page = -1;

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
	struct cnxk_ml_model_metadata *model_metadata;
	struct cnxk_ml_model_metadata metadata;
	struct cnxk_ml_model_addr *model_addr;
	struct cnxk_ml_config *ml_config;
	struct cnxk_ml_model *ml_model;
	struct cnxk_ml_dev *ml_dev;

	const struct plt_memzone *mz;
	char str[PATH_MAX] = {0};
	uint64_t mz_size;
	uint8_t *buffer;
	uint8_t idx;

	uint8_t *base_dma_addr_load;
	uint8_t *base_dma_addr_run;
	size_t model_data_size;
	uint8_t *base_dma_addr;
	uint8_t *dma_addr_load;
	uint8_t *dma_addr_run;
	uint8_t *wb_load_addr;
	int blobsz;
	int fpos;

	uint16_t scratch_pages;
	uint64_t scratch_size;
	uint16_t wb_pages;
	uint64_t wb_size;

	PLT_ASSERT(model != NULL);
	PLT_ASSERT(model_id != NULL);

	buffer = model->model_buffer;
	memcpy(&metadata, buffer, sizeof(struct cnxk_ml_model_metadata));
	if (cnxk_ml_metadata_check(&metadata) != 0)
		return -1;

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
	model_data_size = metadata.init_model.file_size +
			  metadata.main_model.file_size +
			  metadata.finish_model.file_size +
			  metadata.weights_bias.file_size;
	model_data_size = PLT_ALIGN_CEIL(model_data_size, ML_CN10K_ALIGN_SIZE);
	mz_size = PLT_ALIGN_CEIL(sizeof(struct cnxk_ml_model),
				 ML_CN10K_ALIGN_SIZE) +
		  2 * model_data_size +
		  PLT_ALIGN_CEIL(ML_MODEL_JD_POOL_SIZE *
					 sizeof(struct cnxk_ml_jd),
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

	model_addr = &ml_model->model_addr;
	model_metadata = &ml_model->model_metadata;
	memcpy(model_metadata, &metadata,
	       sizeof(struct cnxk_ml_model_metadata));

	wb_size = model_metadata->model.ocm_wb_range_end -
		  model_metadata->model.ocm_wb_range_start + 1;
	if (wb_size % ml_config->ocm_page_size)
		wb_pages = wb_size / ml_config->ocm_page_size + 1;
	else
		wb_pages = wb_size / ml_config->ocm_page_size;
	plt_ml_dbg("wb_size = %" PRIu64 ", wb_pages = %" PRIu16, wb_size,
		   wb_pages);

	scratch_size =
		ml_config->ocm_size - model_metadata->model.ocm_tmp_range_floor;
	if (model_metadata->model.ocm_tmp_range_floor %
	    ml_config->ocm_page_size)
		scratch_pages = scratch_size / ml_config->ocm_page_size + 1;
	else
		scratch_pages = scratch_size / ml_config->ocm_page_size;
	plt_ml_dbg("scratch_size = %" PRIu64 ", scratch_pages = %" PRIu16,
		   scratch_size, scratch_pages);

	/* Check if the model can be loaded on OCM */
	if ((wb_pages + scratch_pages) > ML_CN10K_OCM_NUMPAGES) {
		plt_err("Cannot create model, OCM pages required = %d (> %d)",
			wb_pages + scratch_pages, ML_CN10K_OCM_NUMPAGES);
		goto err_exit;
	}

	/* Set DMA base address */
	base_dma_addr = PLT_PTR_ADD(mz->addr,
				    PLT_ALIGN_CEIL(sizeof(struct cnxk_ml_model),
						   ML_CN10K_ALIGN_SIZE));
	base_dma_addr_load = base_dma_addr;
	base_dma_addr_run = base_dma_addr + model_data_size;
	dma_addr_load = base_dma_addr_load;
	dma_addr_run = base_dma_addr_run;

	/* Init Section */
	fpos = sizeof(struct cnxk_ml_model_metadata);
	blobsz = model_metadata->init_model.file_size;
	if (blobsz <= 0) {
		plt_err("Invalid metadata, init_model.file_size = %d", blobsz);
		goto err_exit;
	}
	model_addr->init_load_addr = dma_addr_load;
	model_addr->init_run_addr = dma_addr_run;
	memcpy(dma_addr_load, buffer + fpos, blobsz);

	/* Main Section */
	dma_addr_load += blobsz;
	dma_addr_run += blobsz;
	fpos += blobsz;
	blobsz = model_metadata->main_model.file_size;
	if (blobsz <= 0) {
		plt_err("Invalid metadata, main_model.file_size = %d", blobsz);
		goto err_exit;
	}
	model_addr->main_load_addr = dma_addr_load;
	model_addr->main_run_addr = dma_addr_run;
	memcpy(dma_addr_load, buffer + fpos, blobsz);

	/* Finish Section */
	dma_addr_load += blobsz;
	dma_addr_run += blobsz;
	fpos += blobsz;
	blobsz = model_metadata->finish_model.file_size;
	if (blobsz <= 0) {
		plt_err("Invalid metadata, finish_model.file_size = %d",
			blobsz);
		goto err_exit;
	}
	model_addr->finish_load_addr = dma_addr_load;
	model_addr->finish_run_addr = dma_addr_run;
	memcpy(dma_addr_load, buffer + fpos, blobsz);

	/* Weights & Bias Section*/
	dma_addr_load += blobsz;
	dma_addr_run += blobsz;
	fpos += blobsz;
	blobsz = model_metadata->weights_bias.file_size;
	if (blobsz <= 0) {
		plt_err("Invalid metadata, weights_bias.file_size = %d",
			blobsz);
		goto err_exit;
	}
	if (model_metadata->weights_bias.relocatable == 1) {
		model_addr->wb_base_addr = PLT_PTR_SUB(
			dma_addr_load, model_metadata->weights_bias.mem_offset);
		dma_addr_load =
			PLT_PTR_ADD(model_addr->wb_base_addr,
				    model_metadata->weights_bias.mem_offset);
		wb_load_addr = dma_addr_load;
		dma_addr_load += blobsz;
		plt_ml_dbg("wb_load_addr = 0x%016lx", (uint64_t)wb_load_addr);
	} else {
		plt_err("Non-relocatable models not supported");
		goto err_exit;
	}
	model_addr->wb_load_addr = wb_load_addr;
	memcpy(wb_load_addr, buffer + fpos, blobsz);

	dma_addr_load += blobsz;
	if (cnxk_ml_model_addr_update(model_metadata, model_addr,
				      (char **)dma_addr_load) < 0)
		goto err_exit;

	/* Copy data from load to run. run address to be used by MLIP */
	memcpy(base_dma_addr_run, base_dma_addr_load, model_data_size);

	memset(&ml_model->model_mem_map, 0,
	       sizeof(struct cnxk_ml_ocm_model_map));
	ml_model->model_mem_map.ocm_reserved = false;
	ml_model->model_mem_map.tilemask = 0;
	ml_model->model_mem_map.wb_page_start = -1;
	ml_model->model_mem_map.wb_pages = wb_pages;
	ml_model->model_mem_map.scratch_pages = scratch_pages;

	/* Update run JD pool */
	ml_model->jd = PLT_PTR_ADD(mz->addr,
				   PLT_ALIGN_CEIL(sizeof(struct cnxk_ml_model),
						  ML_CN10K_ALIGN_SIZE) +
					   2 * model_data_size);
	ml_model->jd_index = 0;
	cnxk_ml_jd_init(dev, ml_model);

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
