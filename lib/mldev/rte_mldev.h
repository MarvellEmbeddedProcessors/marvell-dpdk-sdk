/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#ifndef _RTE_MLDEV_H_
#define _RTE_MLDEV_H_

/**
 * @file rte_mldev.h
 *
 * Machine Learning Device APIs.
 *
 * Defines RTE Machine Learning Device APIs for the provisioning of machine
 * learning inference operations.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_log.h>

/* Logging Macros */

#define MLDEV_LOG_ERR(...)                                                     \
	RTE_LOG(ERR, MLDEV,                                                    \
		RTE_FMT("%s() line %u: " RTE_FMT_HEAD(__VA_ARGS__, ) "\n",     \
			__func__, __LINE__, RTE_FMT_TAIL(__VA_ARGS__, )))

#define MLDEV_LOG_INFO(...)                                                    \
	RTE_LOG(INFO, MLDEV,                                                   \
		RTE_FMT(RTE_FMT_HEAD(__VA_ARGS__, ) "\n",                      \
			RTE_FMT_TAIL(__VA_ARGS__, )))

#define MLDEV_LOG_DEBUG(...)                                                   \
	RTE_LOG(DEBUG, MLDEV,                                                  \
		RTE_FMT("%s() line %u: " RTE_FMT_HEAD(__VA_ARGS__, ) "\n",     \
			__func__, __LINE__, RTE_FMT_TAIL(__VA_ARGS__, )))

#define MLDEV_PMD_TRACE(...)                                                   \
	RTE_LOG(DEBUG, MLDEV,                                                  \
		RTE_FMT("[%s] %s: " RTE_FMT_HEAD(__VA_ARGS__, ) "\n", dev,     \
			__func__, RTE_FMT_TAIL(__VA_ARGS__, )))

#define RTE_MLDEV_DETACHED (0)
#define RTE_MLDEV_ATTACHED (1)

/** Input / Output datatype enumeration. */
enum rte_mldev_io_type {
	/** 8-bit integer. */
	RTE_MLDEV_IO_TYPE_INT8 = 1,

	/** 8-bit unsigned integer. */
	RTE_MLDEV_IO_TYPE_UINT8,

	/** 16-bit integer. */
	RTE_MLDEV_IO_TYPE_INT16,

	/** 16-bit unsigned integer. */
	RTE_MLDEV_IO_TYPE_UINT16,

	/** 32-bit integer. */
	RTE_MLDEV_IO_TYPE_INT32,

	/** 32-bit unsigned integer. */
	RTE_MLDEV_IO_TYPE_UINT32,

	/** 16-bit floating point number. */
	RTE_MLDEV_IO_TYPE_FP16,

	/** 32-bit floating point number. */
	RTE_MLDEV_IO_TYPE_FP32
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the device identifier for the named ML device.
 *
 * @param name
 *   ML device name to select the device identifier.
 *
 * @return
 *   - Returns ML device identifier on success.
 *   - Return -1 on failure to find named ML device.
 */
__rte_experimental
extern int
rte_mldev_get_dev_id(const char *name);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the ML device name given a device identifier.
 *
 * @param dev_id
 *   The identifier of the device
 *
 * @return
 *   - Returns ML device name.
 *   - Returns NULL if ML device is not present.
 */
__rte_experimental
extern const char *
rte_mldev_name_get(uint8_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the total number of ML devices that have been successfully initialised.
 *
 * @return
 *   - The total number of usable ML devices.
 */
__rte_experimental
extern uint8_t
rte_mldev_count(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Return the NUMA socket to which a device is connected
 *
 * @param dev_id
 *   The identifier of the device
 *
 * @return
 *   The NUMA socket id to which the device is connected or a default of zero if
 * the socket could not be determined. -1 if returned is the dev_id value is out
 * of range.
 */
__rte_experimental
extern int
rte_mldev_socket_id(uint8_t dev_id);

/** ML device configuration structure */
struct rte_mldev_config {
	/**< Socket to allocate resources on */
	int socket_id;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Validate if the ML device index is valid attached ML device.
 *
 * @param dev_id
 *   ML device index
 *
 * @return
 *   - If the device index is valid (1) or not (0).
 */
__rte_experimental
unsigned int
rte_mldev_is_valid_dev(uint8_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Configure a device.
 *
 * This function must be invoked first before any other function in the API.
 * This function can also be re-invoked when a device is in the stopped state.
 *
 * @param dev_id
 *   The identifier of the device to configure
 * @param config
 *   The ML device configuration structure
 *
 * @return
 *   - 0: Success, device configured.
 *   - <0: Error code returned by the driver configuration function.
 */
__rte_experimental
extern int
rte_mldev_configure(uint8_t dev_id, struct rte_mldev_config *config);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Close an device. The device cannot be restarted!
 *
 * @param dev_id
 *   The identifier of the device
 *
 * @return
 *  - 0 on successfully closing device
 *  - <0 on failure to close device
 */
__rte_experimental
extern int
rte_mldev_close(uint8_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Start an device.
 *
 * The device start step consists of setting the configured offload features and
 * in starting accepting the ML inferences jobs on the device.
 *
 * @param dev_id
 *   The identifier of the device
 * @return
 *   - 0: Success, device started.
 *   - <0: Error code of the driver device start function.
 */
__rte_experimental
extern int rte_mldev_start(uint8_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Stop an ML device. The device can be restarted with a call to
 * rte_mldev_start()
 *
 * @param dev_id
 *   The identifier of the device.
 */
__rte_experimental
extern void
rte_mldev_stop(uint8_t dev_id);

/** ML model configuration structure */
struct rte_mldev_model {
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
rte_mldev_model_create(uint8_t dev_id, struct rte_mldev_model *model,
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
rte_mldev_model_destroy(uint8_t dev_id, uint8_t model_id);

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
rte_mldev_model_load(uint8_t dev_id, uint8_t model_id);

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
rte_mldev_model_unload(uint8_t dev_id, uint8_t model_id);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MLDEV_H_ */
