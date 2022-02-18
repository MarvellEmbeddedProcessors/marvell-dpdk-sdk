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

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ML_H_ */
