/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#ifndef _MLDEV_PMD_H_
#define _MLDEV_PMD_H_

/**
 * @file
 *
 * ML Device PMD interface
 *
 * Driver facing interface for a ML device. These are not to be called directly
 * by any application.
 */

#include "rte_dev.h"
#include "rte_ml.h"
#include "rte_mldev.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 * Initialisation parameters for ML devices
 */
struct rte_mldev_pmd_init_params {
	char name[RTE_MLDEV_NAME_LEN];
	size_t private_data_size;
	int socket_id;
};

struct rte_mldev;

/**< @internal Enqueue a burst of inference jobs to a queue on ML device. */
typedef uint16_t (*mldev_enqueue_t)(struct rte_mldev *dev, uint16_t qp_id,
				    struct rte_ml_op **ops, uint16_t nb_ops);

/**< @internal Dequeue a burst of inference jobs fromn a queue on ML device. */
typedef uint16_t (*mldev_dequeue_t)(struct rte_mldev *dev, uint16_t qp_id,
				    struct rte_ml_op **ops, uint16_t nb_ops);

/**
 * @internal
 * The data part, with no function pointers, associated with each device. This
 * structure is safe to place in shared memory to be common among different
 * processes in a multi-process configuration.
 */
struct rte_mldev_data {
	/** Device ID for this instance */
	uint8_t dev_id;

	/** Socket ID where memory is allocated */
	uint8_t socket_id;

	/** Unique identifier name */
	char name[RTE_MLDEV_NAME_LEN];

	__extension__
	/** Device state: STARTED(1) / STOPPED(0) */
	uint8_t dev_started : 1;

	/** Array of pointers to queue pairs. */
	void **queue_pairs;

	/** Number of device queue pairs. */
	uint16_t nb_queue_pairs;

	/** PMD-specific private data */
	void *dev_private;
} __rte_cache_aligned;

/** @internal The data structure associated with each ML device. */
struct rte_mldev {
	/** Pointer to PMD enqueue function. */
	mldev_enqueue_t dequeue_burst;

	/** Pointer to PMD dequeue function. */
	mldev_dequeue_t enqueue_burst;

	/** Pointer to device data */
	struct rte_mldev_data *data;

	/** Functions exported by PMD */
	struct rte_mldev_ops *dev_ops;

	/** Backing device */
	struct rte_device *device;

	__extension__
	/** Flag indicating the device is attached */
	uint8_t attached : 1;
} __rte_cache_aligned;

/** @internal
 * Global structure used for maintaining state of allocated ML devices
 */
struct rte_mldev_global {
	/**< Device information array */
	struct rte_mldev *devs;

	/**< Device data array */
	struct rte_mldev_data *data[RTE_ML_MAX_DEVS];

	/**< Number of devices found */
	uint8_t nb_devs;
};

/**
 * Get the rte_mldev structure device pointer for the device. Assumes a valid
 * device index.
 *
 * @param dev_id
 *   Device ID value to select the device structure.
 *
 * @return
 *   The rte_mldev pointer for the given device ID.
 */
__rte_internal
struct rte_mldev *
rte_mldev_pmd_get_dev(uint8_t dev_id);

/**
 * Get the rte_mldev structure device pointer for the named device.
 *
 * @param name
 *   Device name to select the device structure.
 *
 * @return
 *   The rte_mldev pointer for the given device ID.
 */
__rte_internal
struct rte_mldev *
rte_mldev_pmd_get_named_dev(const char *name);

/**
 * Definitions of all functions exported by a driver through the generic
 * structure of type *ml_dev_ops* supplied in the *rte_mldev* structure
 * associated with a device.
 */

/**
 * Function used to configure device.
 *
 * @param dev
 *   ML device pointer
 * @param config
 *   ML device configurations
 *
 * @return
 *   Returns 0 on success
 */
typedef int (*mldev_configure_t)(struct rte_mldev *dev,
				 struct rte_mldev_config *config);

/**
 * Function used to close a configured device.
 *
 * @param dev
 *   ML device pointer
 *
 * @return
 *   - 0 on success.
 *   - EAGAIN if can't close as device is busy
 */
typedef int (*mldev_close_t)(struct rte_mldev *dev);

/**
 * Function used to start a configured device.
 *
 * @param dev
 *   ML device pointer
 *
 * @return
 *   Returns 0 on success
 */
typedef int (*mldev_start_t)(struct rte_mldev *dev);

/**
 * Function used to stop a configured device.
 *
 * @param dev
 *   ML device pointer
 */
typedef void (*mldev_stop_t)(struct rte_mldev *dev);

/**
 * Function used to get specific information of a device.
 *
 * @param dev
 *   ML device pointer
 * @param dev_info
 *   Pointer to infos structure to populate
 */
typedef int (*mldev_info_get_t)(struct rte_mldev *dev,
				struct rte_mldev_info *dev_info);

/**
 * Setup a queue pair for a device.
 *
 * @param dev
 *   ML device pointer
 * @param qp_id
 *    Queue Pair Index
 * @param qp_conf
 *    Queue configuration structure
 * @param socket_id
 *   Socket Index
 *
 * @return
 *   Returns 0 on success.
 */
typedef int (*mldev_queue_pair_setup_t)(struct rte_mldev *dev, uint16_t qp_id,
					const struct rte_mldev_qp_conf *qp_conf,
					int socket_id);

/**
 * Release memory resources allocated by given queue pair.
 *
 * @param dev
 *   ML device pointer
 * @param qp_id
 *   Queue Pair Index
 *
 * @return
 *   - 0 on success.
 *   - EAGAIN if can't close as device is busy
 */
typedef int (*mldev_queue_pair_release_t)(struct rte_mldev *dev, uint16_t qp_id);

/**
 * Function used to create an ML model.
 *
 * @param dev
 *   ML device pointer
 * @param model
 *   Pointer to model structure
 * @param model_id
 *   Model ID returned by the library
 *
 * @return
 *   - 0 on success.
 *   - < 0 on failure.
 *
 */
typedef int (*ml_model_create_t)(struct rte_mldev *dev,
				 struct rte_ml_model *model, uint8_t *model_id);

/**
 * Function used to destroy an ML model.
 *
 * @param dev
 *   ML device pointer
 * @param model_id
 *   Model ID to use
 *
 * @return
 *   - 0 on success
 *   - < 0 on failure
 */
typedef int (*ml_model_destroy_t)(struct rte_mldev *dev, uint8_t model_id);

/**
 * Function used to load an ML model.
 *
 * @param dev
 *   ML device pointer
 * @param model_id
 *   Model ID to use
 */
typedef int (*ml_model_load_t)(struct rte_mldev *dev, uint8_t model_id);

/**
 * Function used to unload an ML model.
 *
 * @param dev
 *   ML device pointer
 * @param model_id
 *   Model ID to use
 */
typedef int (*ml_model_unload_t)(struct rte_mldev *dev, uint8_t model_id);

/**
 * Function used to get model info.
 *
 * @param dev
 *   ML device pointer
 * @param model_id
 *   Model ID to use
 * @param model_info
 *   Pointer to model info structure
 */
typedef int (*ml_model_info_get_t)(struct rte_mldev *dev, uint8_t model_id,
				   struct rte_ml_model_info *model_info);

/** @internal ML device operations function pointer table */
struct rte_mldev_ops {
	/**< Configure device. */
	mldev_configure_t dev_configure;

	/**< Close device. */
	mldev_close_t dev_close;

	/**< Start device. */
	mldev_start_t dev_start;

	/**< Stop device. */
	mldev_stop_t dev_stop;

	/**< Get device information. */
	mldev_info_get_t dev_info_get;

	/**< Set up a device queue pair. */
	mldev_queue_pair_setup_t queue_pair_setup;

	/**< Release a queue pair. */
	mldev_queue_pair_release_t queue_pair_release;

	/**< Create model. */
	ml_model_create_t ml_model_create;

	/**< Destroy model. */
	ml_model_destroy_t ml_model_destroy;

	/**< Load model. */
	ml_model_load_t ml_model_load;

	/**< Unload model. */
	ml_model_unload_t ml_model_unload;

	/**< Get model info. */
	ml_model_info_get_t ml_model_info_get;
};

/**
 * Function for internal use by dummy drivers primarily, e.g. ring-based driver.
 * Allocates a new mldev slot for an ml device and returns the pointer to that
 * slot for the driver to use.
 *
 * @param name
 *   Unique identifier name for each device
 * @param socket_id
 *   Socket to allocate resources on.
 *
 * @return
 *   - Slot in the rte_dev_devices array for a new device;
 */
__rte_internal
struct rte_mldev *
rte_mldev_pmd_allocate(const char *name, int socket_id);

/**
 * Function for internal use by dummy drivers primarily, e.g. ring-based driver.
 * Release the specified mldev device.
 *
 * @param mldev
 *   The *mldev* pointer is the address of the *rte_mldev* structure.
 *
 * @return
 *   - 0 on success, negative on error
 */
__rte_internal
extern int
rte_mldev_pmd_release_device(struct rte_mldev *mldev);

/**
 * @internal
 *
 * PMD assist function to provide boiler plate code for ml driver to create and
 * allocate resources for a new ml PMD device instance.
 *
 * @param name
 *   ML device name.
 * @param device
 *   Base device instance
 * @param params
 *   PMD initialisation parameters
 *
 * @return
 *   - ML device instance on success
 *   - NULL on creation failure
 */
__rte_internal
struct rte_mldev *
rte_mldev_pmd_create(const char *name, struct rte_device *device,
		     struct rte_mldev_pmd_init_params *params);

/**
 * @internal
 *
 * PMD assist function to provide boiler plate code for ml driver to destroy and
 * free resources associated with a ml PMD device instance.
 *
 * @param mldev
 *   ML device handle.
 *
 * @return
 *   - 0 on success
 *   - errno on failure
 */
__rte_internal
int
rte_mldev_pmd_destroy(struct rte_mldev *mldev);

/**
 * @internal
 * This is the last step of device probing. It must be called after a mldev is
 * allocated and initialized successfully.
 *
 * @param dev
 *   Pointer to mldev struct
 */
__rte_internal
void
rte_mldev_pmd_probing_finish(struct rte_mldev *dev);

#ifdef __cplusplus
}
#endif

#endif /* _MLDEV_PMD_H */
