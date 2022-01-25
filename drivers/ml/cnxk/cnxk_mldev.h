/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _CNXK_MLDEV_H_
#define _CNXK_MLDEV_H_

#include "roc_ml.h"

#define ML_FIRMWARE_STRLEN   512
#define ML_FW_VERSION_STRLEN 32

/* Model Metadata : v 2.1.0.2 */
#define ML_MODEL_MAGIC_STRING "MRVL"
#define ML_MODEL_TARGET_ARCH  128
#define ML_MODEL_VERSION      2100
#define ML_MODEL_NAME_LEN     64
#define ML_INPUT_NAME_LEN     16
#define ML_OUTPUT_NAME_LEN    16
#define ML_INPUT_OUTPUT_SIZE  8
#define ML_FW_VERSION_STRLEN  32

/* Model file metadata structure */
struct cnxk_ml_model_metadata {
	/* Header (256-byte) */
	struct {
		/* Magic string (‘M’, ‘R’, ‘V’, ‘L’) */
		uint8_t magic[4];

		/* Metadata version */
		uint8_t version[4];

		/* Metadata size */
		uint32_t metadata_size;

		/* Unique ID */
		uint8_t uuid[128];

		/* Model target architecture
		 * 0 = Undefined
		 * 1 = M1K
		 * 128 = MLIP
		 * 256 = Experimental
		 */
		uint32_t target_architecture;
		uint8_t reserved[112];
	} metadata_header;

	/* Model information (256-byte) */
	struct {
		/* Model name string */
		uint8_t name[ML_MODEL_NAME_LEN];

		/* Model version info (xx.xx.xx.xx) */
		uint8_t version[4];

		/* Model code size (init + main + finish) */
		uint32_t code_size;

		/* Model data size (Weights and Bias) */
		uint32_t data_size;

		/* OCM start offset, set to ocm_wb_range_start */
		uint32_t ocm_start;

		/* OCM start offset, set to max OCM size */
		uint32_t ocm_end;

		/* Relocatable flag (always yes)
		 * 0 = Not relocatable
		 * 1 = Relocatable
		 */
		uint8_t ocm_relocatable;

		/* Tile relocatable flag (always yes)
		 * 0 = Not relocatable
		 * 1 = Relocatable
		 */
		uint8_t tile_relocatable;

		/* Start tile (Always 0) */
		uint8_t tile_start;

		/* End tile (num_tiles - 1) */
		uint8_t tile_end;

		/* Inference batch size */
		uint8_t batch_size;

		/* Number of input tensors (Max 8) */
		uint8_t num_input;

		/* Number of output tensors (Max 8) */
		uint8_t num_output;
		uint8_t reserved1;

		/* Total input size in bytes */
		uint32_t input_size;

		/* Total output size in bytes */
		uint32_t output_size;

		/* Table size in bytes */
		uint32_t table_size;

		/* Number of layers in the network */
		uint32_t num_layers;
		uint32_t reserved2;

		/* Floor of absolute OCM region */
		uint64_t ocm_tmp_range_floor;

		/* Relative OCM start address of WB data block */
		uint64_t ocm_wb_range_start;

		/* Relative OCM end address of WB data block */
		uint64_t ocm_wb_range_end;

		/* Relative DDR start address of WB data block */
		uint64_t ddr_wb_range_start;

		/* Relative DDR end address of all outputs */
		uint64_t ddr_wb_range_end;

		/* Relative DDR start address of all inputs */
		uint64_t ddr_input_range_start;

		/* Relative DDR end address of all inputs */
		uint64_t ddr_input_range_end;

		/* Relative DDR start address of all outputs */
		uint64_t ddr_output_range_start;

		/* Relative ddr end address of all outputs */
		uint64_t ddr_output_range_end;
		uint8_t compiler_version[8];
		uint8_t cdk_version[4];

		/* Lower batch optimization support
		 * 0 – No,
		 * 1 – Yes
		 */
		uint8_t supports_lower_batch_size_optimization;
		uint8_t reserved[59];
	} model;

	/* Init section (64-byte) */
	struct {
		uint32_t file_offset;
		uint32_t file_size;
		uint8_t reserved[56];
	} init_model;

	/* Main section (64-byte) */
	struct {
		uint32_t file_offset;
		uint32_t file_size;
		uint8_t reserved[56];
	} main_model;

	/* Finish section (64-byte) */
	struct {
		uint32_t file_offset;
		uint32_t file_size;
		uint8_t reserved[56];
	} finish_model;

	uint8_t reserved1[512]; /* End of 2k bytes */

	/* Weights and Biases (64-byte) */
	struct {
		/* Memory offset, Set to ddr_wb_range_start */
		uint64_t mem_offset;
		uint32_t file_offset;
		uint32_t file_size;

		/* Relocatable flag for WB
		 * 1 = Relocatable
		 * 2 = Not relocatable
		 */
		uint8_t relocatable;
		uint8_t reserved[47];
	} weights_bias;

	/* Input (512-byte, 64-byte per input) provisioned for 8 inputs */
	struct {
		/* DDR offset (in ocm absolute addresses for input) */
		uint64_t mem_offset;

		/* Relocatable flag
		 * 1 = Relocatable
		 * 2 = Not relocatable
		 */
		uint8_t relocatable;

		/* Input quantization
		 * 1 = Requires quantization
		 * 2 = Pre-quantized
		 */
		uint8_t quantize;

		/* Type of incoming input
		 * 1 = INT8, 2 = UINT8, 3 = INT16, 4 = UINT16,
		 * 5 = INT32, 6 = UINT32, 7 = FP16, 8 = FP32
		 */
		uint8_t input_type;

		/* Type of input required by model
		 * 1 = INT8, 2 = UINT8, 3 = INT16, 4 = UINT16,
		 * 5 = INT32, 6 = UINT32, 7 = FP16, 8 = FP32
		 */
		uint8_t model_input_type;

		/* float_32 qscale value
		 * quantized = nonquantized * qscale
		 */
		float qscale;

		/* Input shape */
		struct {
			/* Input format
			 * 1 = NCHW
			 * 2 = NHWC
			 */
			uint8_t format;
			uint8_t reserved[3];
			uint32_t w;
			uint32_t x;
			uint32_t y;
			uint32_t z;
		} shape;
		uint8_t reserved[4];

		/* Name of input */
		uint8_t input_name[ML_INPUT_NAME_LEN];

		/* DDR range end
		 * new = mem_offset + size_bytes - 1
		 */
		uint64_t ddr_range_end;
	} input[ML_INPUT_OUTPUT_SIZE];

	/* Output (512 byte, 64-byte per input) provisioned for 8 outputs */
	struct {
		/* DDR offset in ocm absolute addresses for output */
		uint64_t mem_offset;

		/* Relocatable flag
		 * 1 = Relocatable
		 * 2 = Not relocatable
		 */
		uint8_t relocatable;

		/* Output dequantization
		 * 1 = De-quantization required
		 * 2 = De-quantization not required
		 */
		uint8_t dequantize;

		/* Type of outgoing output
		 * 1 = INT8, 2 = UINT8, 3 = INT16, 4 = UINT16
		 * 5 = INT32, 6 = UINT32, 7 = FP16, 8 = FP32
		 */
		uint8_t output_type;

		/* Type of output produced by model
		 * 1 = INT8, 2 = UINT8, 3 = INT16, 4 = UINT16
		 * 5 = INT32, 6 = UINT32, 7 = FP16, 8 = FP32
		 */
		uint8_t model_output_type;

		/* float_32 dscale value
		 * dequantized = quantized * dscale
		 */
		float dscale;

		/* Number of items in the output */
		uint32_t size;
		uint8_t reserved[20];

		/* DDR range end
		 * new = mem_offset + size_bytes - 1
		 */
		uint64_t ddr_range_end;
		uint8_t output_name[ML_OUTPUT_NAME_LEN];
	} output[ML_INPUT_OUTPUT_SIZE];

	uint8_t reserved2[1792];

	/* Model data */
	struct {
		uint8_t reserved1[4068];

		/* Beta: xx.xx.xx.xx,
		 * Later: YYYYMM.xx.xx
		 */
		uint8_t compiler_version[8];

		/* M1K CDK version (xx.xx.xx.xx) */
		uint8_t m1k_cdk_version[4];
	} data;

	/* Hidden 16 bytes of magic code */
	uint8_t reserved3[16];
};

/* Model address structure */
struct cnxk_ml_model_addr {
	/* Init section load address */
	void *init_load_addr;

	/* Init section run address */
	void *init_run_addr;

	/* Main section load address */
	void *main_load_addr;

	/* Main section run address */
	void *main_run_addr;

	/* Finish section load address */
	void *finish_load_addr;

	/* Finish section run address */
	void *finish_run_addr;

	/* Weights and Bias base address */
	void *wb_base_addr;

	/* Weights and bias load address */
	void *wb_load_addr;

	/* Start tile */
	uint8_t tile_start;

	/* End tile */
	uint8_t tile_end;

	/* Input address and size */
	struct {
		/* Input size */
		uint32_t sz;

		/* Quantized input size */
		uint32_t sz_q;

		/* Input base address */
		void *addr_base;

		/* Input DMA address */
		void *addr;
	} input[ML_INPUT_OUTPUT_SIZE];

	/* Output address and size */
	struct {
		/* Output size */
		uint32_t sz;

		/* Quantized output size */
		uint32_t sz_q;

		/* Output base address */
		void *addr_base;

		/* Output DMA address */
		void *addr;
	} output[ML_INPUT_OUTPUT_SIZE];
};

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

/* ML job structure
 *
 * A buffer of size cnxk_ml_job_compl_t is required for every ML job. For poll
 * mode jobs, the buffer is created by the library and returned the user. For
 * event mode jobs, the buffer is handled by the user. For sync mode jobs, the
 * buffer is created by the library and destroyed before return.
 */
struct cnxk_ml_job_compl {
	/* Job completion result */
	struct cnxk_ml_job_result job_result;

	/* Job status pointer */
	volatile uint64_t status_ptr;

	/* Job start time */
	uint64_t start_time;
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

struct cnxk_ml_jd {
	/* Job descriptor header (32 bytes) */
	struct cnxk_ml_jd_header hdr;

	union {
		struct cnxk_ml_jd_section_load {
			/* Source model start address in DDR
			 * relative to MLAB_MLR_BASE
			 */
			uint64_t model_src_ddr_addr;

			/* Destination model start address in DDR
			 * relative to MLAB_MLR_BASE
			 */
			uint64_t model_dst_ddr_addr;

			/* Offset to model init section in the model */
			uint64_t model_init_offset : 32;

			/* Size of init section in the model */
			uint64_t model_init_size : 32;

			/* Offset to model main section in the model */
			uint64_t model_main_offset : 32;

			/* Size of main section in the model */
			uint64_t model_main_size : 32;

			/* Offset to model finish section in the model */
			uint64_t model_finish_offset : 32;

			/* Size of finish section in the model */
			uint64_t model_finish_size : 32;

			/* Offset to WB in model bin */
			uint64_t model_wb_offset : 32;

			/* Number of model layers */
			uint64_t num_layers : 8;

			/* Number of gather entries
			 * 0 means linear input mode(= no gather)
			 */
			uint64_t num_gather_entries : 8;

			/* Number of scatter entries
			 * 0 means linear input mode (= no scatter)
			 */
			uint64_t num_scatter_entries : 8;

			/* Tile mask to load model */
			uint64_t tilemask : 8;

			/* OCM WB base address */
			uint64_t rsvd : 32;
			uint64_t ocm_wb_base_address : 32;

			/* OCM WB range start */
			uint64_t ocm_wb_range_start : 32;

			/* OCM WB range End */
			uint64_t ocm_wb_range_end : 32;

			/* DDR WB address */
			uint64_t ddr_wb_base_address;

			/* DDR WB range start */
			uint64_t ddr_wb_range_start : 32;

			/* DDR WB range end */
			uint64_t ddr_wb_range_end : 32;

			union {
				/* Pointer to gather list,
				 * if num_gather_entries > 0
				 */
				void *gather_list;
				struct {
					/* Linear input mode */
					uint64_t ddr_range_start : 32;
					uint64_t ddr_range_end : 32;
				} s;
			} input;

			union {
				/* Pointer to scatter list,
				 * if num_scatter_entries > 0
				 */
				void *scatter_list;
				struct {
					/* Linear output mode */
					uint64_t ddr_range_start : 32;
					uint64_t ddr_range_end : 32;
				} s;
			} output;
		} load;

		struct cnxk_ml_jd_section_unload {
			uint8_t rsvd[96];
		} unload;

		struct cnxk_ml_jd_section_run {
			/* Address of the input for the run
			 * relative to MLAB_MLR_BASE
			 */
			uint64_t input_ddr_addr;

			/* Address of the output for the run
			 * relative to MLAB_MLR_BASE
			 */
			uint64_t output_ddr_addr;
			uint8_t rsvd[80];
		} run;
	};
};

/* Memory resources */
struct cnxk_ml_mem {
	/* Memory for BAR0 */
	struct rte_mem_resource res0;

	/* Memory for BAR4 */
	struct rte_mem_resource res4;
};

/* ML Model OCM map structure */
struct cnxk_ml_ocm_model_map {
	/* status of OCM reservation */
	bool ocm_reserved;

	/* Mask of OCM tiles for the model */
	uint64_t tilemask;

	/* Start page for the model load, default = -1 */
	int wb_page_start;

	/* Number of pages required for weights and bias */
	uint16_t wb_pages;

	/* Number of pages required for scratch memory */
	uint16_t scratch_pages;
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

	/* Tile and memory information object */
	struct cnxk_ml_ocm_model_map model_mem_map;

	/* Model metadata */
	struct cnxk_ml_model_metadata model_metadata;

	/* Model address structure */
	struct cnxk_ml_model_addr model_addr;

	/* Model state */
	enum cnxk_ml_model_state state;

	/* Job descriptors pool
	 * Size of the pool is ML_MODEL_JD_POOL_SIZE.
	 * JD's  0 to ML_MODEL_JD_POOL_SIZE - 3 are reserved for run
	 * Last two JD's in the pool are reserved for load and unload
	 */
	struct cnxk_ml_jd *jd;

	/* Run Job descriptor index, initial value is 2. */
	uint8_t jd_index;
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

	/* Number of OCM tiles */
	uint8_t ocm_num_tiles;

	/* OCM size per each tile */
	uint64_t ocm_size;

	/* OCM page size */
	uint64_t ocm_page_size;

	/* OCM pages */
	uint16_t ocm_pages;

	/* Words per OCM mask */
	uint16_t ocm_mask_words;

	/* OCM memory info and status*/
	void *ocm_tile_info;

	/* Internal job pool, for sync and poll mode */
	struct rte_mempool *job_pool;
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
