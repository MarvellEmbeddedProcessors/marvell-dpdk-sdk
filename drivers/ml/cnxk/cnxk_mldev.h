/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _CNXK_MLDEV_H_
#define _CNXK_MLDEV_H_

#include "roc_ml.h"

#define ML_FIRMWARE_STRLEN   512
#define ML_FW_VERSION_STRLEN 32

#define ML_MODEL_NAME_LEN 64

/* ML Job commands */
enum cnxk_ml_job_cmd {
	CNXK_ML_JOB_CMD_RUN = 0,
	CNXK_ML_JOB_CMD_UNLOAD,
	CNXK_ML_JOB_CMD_LOAD,
	CNXK_ML_JOB_CMD_FW_LOAD,
};

/* Model states */
enum cnxk_ml_model_state {
	CNXK_ML_MODEL_STATE_CREATED,
	CNXK_ML_MODEL_STATE_LOAD_ACTIVE,
	CNXK_ML_MODEL_STATE_LOADED,
	CNXK_ML_MODEL_STATE_UNLOAD_ACTIVE,
};

/* Event mode compl_W0 structure */
union cnxk_ml_compl_W0 {
	uint64_t u;
	struct {
		uint64_t rsvd : 6;
		uint64_t tag_type : 2;
		uint64_t pffunc : 16;
		uint64_t group : 8;
		uint64_t tag : 32;
	} s;
};

/* Job descriptor header (32 bytes) */
struct cnxk_ml_jd_header {
	/* W0 */
	union cnxk_ml_compl_W0 compl_W0;

	/* W1 / Completion status pointer */
	union compl_W1 {
		uint64_t W1;
		uint64_t status_ptr;
	} compl_W1;

	/* Model ID */
	uint64_t model_id : 8;

	/* Job command to be passed, MLIP_JD_CMD_[LOAD | RUN | UNLOAD] */
	uint64_t command : 8;

	/* Information about the job */
	uint64_t flags : 16;

	uint64_t rsvd1 : 32;

	/* Job completion status and stats */
	uint64_t *job_result;
};

/* ML Firmware capability structure */
union cnxk_ml_fw_cap {
	uint64_t u;

	struct {
		/* CMPC completion support */
		uint64_t cmpc_completions : 1;

		/* Poll mode completion support */
		uint64_t poll_completions : 1;

		/* SSO completion support */
		uint64_t sso_completions : 1;

		/* Support for model side loading */
		uint64_t side_load_model : 1;

		/* Batch execution */
		uint64_t batch_run : 1;

		/* Max number of models to be loaded in parallel */
		uint64_t max_models : 8;

		/* Firmware statistics */
		uint64_t fw_stats : 1;

		/* Hardware statistics */
		uint64_t hw_stats : 1;
		uint64_t rsvd : 46;
	} s;
};

/* ML Firmware debug capability structure */
struct cnxk_ml_fw_debug_cap {
	/* ACC core 0 debug buffer */
	uint64_t fw_core0_dbg_ptr;

	/* ACC core 1 debug buffer */
	uint64_t fw_core1_dbg_ptr;

	/* ACC core 0 exception state buffer */
	uint64_t fw_core0_exception_buffer;

	/* ACC core 1 exception state buffer */
	uint64_t fw_core1_exception_buffer;

	/* Debug buffer size per core */
	uint32_t fw_dbg_buffer_size;

	/* Exception state dump size */
	uint32_t fw_exception_state_size;
};

/* ML firmware stats */
struct cnxk_ml_fw_stats {
	/* Firmware start cycle */
	uint64_t fw_start;

	/* Firmware end cycle */
	uint64_t fw_end;

	/* Hardware start cycle */
	uint64_t hw_start;

	/* Hardware end cycle */
	uint64_t hw_end;
};

/* ML internal result structure */
struct cnxk_ml_job_result {
	/* Job status, success = ML_STATUS_SUCCESS, failure = ML_STATUS_FAILURE
	 */
	uint64_t status;

	/* Job error code, if status = ML_STATUS_FAILURE */
	uint64_t error_code;

	/* Firmware stats */
	struct cnxk_ml_fw_stats fw_stats;

	/* User context pointer */
	void *user_ptr;
};

/* Firmware Load completion structure */
struct cnxk_ml_fw_load_compl {
	/* Entry header (32 bytes) */
	struct cnxk_ml_jd_header hdr;

	/* Firmware capability structure (8 bytes) */
	union cnxk_ml_fw_cap cap;

	/* Firmware version (32 bytes) */
	uint8_t version[ML_FW_VERSION_STRLEN];

	/* Debug capability structure (40 bytes) */
	struct cnxk_ml_fw_debug_cap debug_cap;

	uint8_t rsvd[16];
};

/* Memory resources */
struct cnxk_ml_mem {
	/* Memory for BAR0 */
	struct rte_mem_resource res0;

	/* Memory for BAR4 */
	struct rte_mem_resource res4;
};

/* ML firmware structure */
struct cnxk_ml_fw {
	/* Device reference */
	struct cnxk_ml_dev *ml_dev;

	/* Firmware file path */
	char filepath[ML_FIRMWARE_STRLEN];

	/* Load completion structure */
	struct cnxk_ml_fw_load_compl *load_fw;

	/* Data buffer */
	uint8_t *data_fw;

	/* Load status pointer */
	volatile uint64_t status_ptr;

	/* Result structure */
	struct cnxk_ml_job_result job_result;
};

/* ML Model Object */
struct cnxk_ml_model {
	/* Configuration reference */
	struct cnxk_ml_config *ml_config;

	/* Model name */
	char name[ML_MODEL_NAME_LEN];

	/* Model ID */
	uint32_t model_id;

	/* Model state */
	enum cnxk_ml_model_state state;
};

/* Configuration object */
struct cnxk_ml_config {
	/* Device reference */
	struct cnxk_ml_dev *ml_dev;

	/* Active flag */
	bool active;

	/* Maximum number of models to be created */
	uint32_t max_models_created;

	/* ML model array */
	struct cnxk_ml_model **ml_models;

	/* Spin lock for slow path
	 * Enqueue / access through scratch registers
	 */
	rte_spinlock_t scratch_lock;

	/* Spin lock for fastpath
	 * Enqueue through JCMDQ
	 */
	rte_spinlock_t run_lock;
};

/* ML Device private data */
struct cnxk_ml_dev {
	/* Device ROC */
	struct roc_ml roc;

	/* Device memory resources */
	struct cnxk_ml_mem mem;

	/* Firmware handle */
	struct cnxk_ml_fw ml_fw;

	/* Configuration handle */
	struct cnxk_ml_config ml_config;
};

int cnxk_mldev_parse_devargs(struct rte_devargs *devargs,
			     struct cnxk_ml_dev *ml_dev);

#endif /* _CNXK_MLDEV_H_ */
