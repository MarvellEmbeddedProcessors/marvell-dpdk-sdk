/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#ifndef _RTE_ML_H_
#define _RTE_ML_H_

/**
 * @file rte_ml.h
 *
 * RTE Machine Learning Common Definitions.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

/** Input / Output datatype enumeration. */
enum rte_ml_io_type {
	/** 8-bit integer. */
	RTE_ML_IO_TYPE_INT8 = 1,

	/** 8-bit unsigned integer. */
	RTE_ML_IO_TYPE_UINT8,

	/** 16-bit integer. */
	RTE_ML_IO_TYPE_INT16,

	/** 16-bit unsigned integer. */
	RTE_ML_IO_TYPE_UINT16,

	/** 32-bit integer. */
	RTE_ML_IO_TYPE_INT32,

	/** 32-bit unsigned integer. */
	RTE_ML_IO_TYPE_UINT32,

	/** 16-bit floating point number. */
	RTE_ML_IO_TYPE_FP16,

	/** 32-bit floating point number. */
	RTE_ML_IO_TYPE_FP32
};

/** Input / Output tensor format */
enum rte_ml_io_format {
	/** Batch size (N) x channels (C) x height (H) x width (W) */
	RTE_ML_IO_FORMAT_NCHW = 1,

	/** Batch size (N) x height (H) x width (W) x channels (C) */
	RTE_ML_IO_FORMAT_NHWC,

	/** Channels (C) x height (H) x width (W) x batch size (N) */
	RTE_ML_IO_FORMAT_CHWN
};

/** Input / Output shape */
struct rte_ml_io_shape {
	/** Format */
	enum rte_ml_io_format format;

	/** First component of shape */
	uint32_t w;

	/** Second component of shape. */
	uint32_t x;

	/** Third component of shape. */
	uint32_t y;

	/** Fourth component of shape. */
	uint32_t z;
};

/** ML model configuration structure */
struct rte_ml_model {
	char *model_name;
	/**< Model name */

	void *model_buffer;
	/**< Model buffer address */

	size_t model_size;
	/**< Model buffer size */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Create an ML model.
 *
 * Memory and other resources are reserved for the new model. Model binary is
 * copied, checked and prepared for loading. Model should be loaded after
 * calling this API.
 *
 * @param[in] dev_id
 *   Device identifier
 * @param[in] model
 *   Parameters for the model to be created
 * @param[out] model_id
 *   Identifier for the model created
 *
 * @return
 *   - Returns 0 on success
 *   - Returns negative value on failure
 */
__rte_experimental
int
rte_ml_model_create(uint8_t dev_id, struct rte_ml_model *model,
		    uint8_t *model_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Destroy an ML model.
 *
 * Model host memory and other resources are released for the model. Model
 * should be unloaded prior to calling this API.
 *
 * @param[out] model_id
 *   Identifier for the model created
 *
 * @return
 *   - Returns 0 on success
 *   - Returns negative value on failure
 */
__rte_experimental
int
rte_ml_model_destroy(uint8_t dev_id, uint8_t model_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Load model into HW engines.
 *
 * This function blocks until load is finished. Model is ready for inference
 * requests after load has finished. The same model can be later unloaded and
 * loaded again.
 *
 * @param[in] dev_id
 *   Device identifier
 * @param[in] model_id
 *   Identifier for the model created
 *
 * @return
 *   - Returns 0 on success
 *   - Returns negative value on failure
 */
__rte_experimental
int
rte_ml_model_load(uint8_t dev_id, uint8_t model_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Unload model.
 *
 * This function blocks until unload is finished. Host memory and other
 * resources are kept for future reloading. All inference jobs must have been
 * completed before model unload is attempted.
 *
 * @param[in] dev_id
 *   Device identifier
 * @param[in] model_id
 *   Identifier for the model created
 *
 * @return
 *   - Returns 0 on success
 *   - Returns negative value on failure
 */
__rte_experimental
int
rte_ml_model_unload(uint8_t dev_id, uint8_t model_id);

/** Maximum length model / input / output name string */
#define RTE_ML_NAME_LEN 64

/** Input information structure */
struct rte_ml_input_info {
	/** Input name */
	char name[RTE_ML_NAME_LEN];

	/** Type of input */
	enum rte_ml_io_type model_input_type;

	/** Input shape */
	struct rte_ml_io_shape shape;

	/** Size in bytes */
	uint64_t size;
};

/** Output information structure. */
struct rte_ml_output_info {
	/** Output name */
	char name[RTE_ML_NAME_LEN];

	/** Type of output */
	enum rte_ml_io_type model_output_type;

	/** Output shape */
	struct rte_ml_io_shape shape;

	/** Output size in bytes */
	uint64_t size;
};

/** Model information structure */
struct rte_ml_model_info {
	/** Model name. */
	char name[RTE_ML_NAME_LEN];

	/** Model version */
	char version[RTE_ML_NAME_LEN];

	/** Model ID */
	uint32_t index;

	/** Number of inputs */
	uint32_t num_inputs;

	/** Total size of all inputs in bytes */
	uint32_t total_input_size;

	/* Input info array. Array size is equal to num_inputs */
	struct rte_ml_input_info *input_info;

	/** Number of outputs */
	uint32_t num_outputs;

	/** Total size of all outputs in bytes */
	uint32_t total_output_size;

	/* Input info array. Array size is equal to num_inputs */
	struct rte_ml_output_info *output_info;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get ML model information.
 *
 * @param[in] dev_id
 *   Device identifier
 * @param[in] model_id
 *   Identifier for the model created
 * @param[in] model_info
 *   Pointer to a model info structure
 *
 * @return
 *   - Returns 0 on success
 *   - Returns negative value on failure
 */
__rte_experimental
int
rte_ml_model_info_get(uint8_t dev_id, uint8_t model_id, struct rte_ml_model_info *model_info);

/** ML job statistics. */
struct rte_ml_op_stats {
	/** Firmware latency. */
	uint64_t fw_latency_ns;

	/** Hardware latency. */
	uint64_t hw_latency_ns;
};

/** ML job result structure. */
struct rte_ml_op_result {
	/** Job status, when true the job is completed successfully. */
	bool success;

	/** Job error code, if unsuccessful. */
	uint64_t error_code;

	/** Job stats. */
	struct rte_ml_op_stats stats;
};

/**
 * The generic *rte_ml_op* structure to hold the ML attributes
 * for enqueue and dequeue operation.
 */
struct rte_ml_op {
	/** Model ID */
	int model_id;

	/** Input size */
	uint64_t isize;

	/** Input buffer */
	void *ibuffer;

	/** Output size */
	uint64_t osize;

	/** Output buffer */
	void *obuffer;

	/** Result structure */
	struct rte_ml_op_result result;

	/** User context pointer value from job parameters. */
	void *user_ptr;
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ML_H_ */
