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

/**
 * @internal
 * The data part, with no function pointers, associated with each device.
 *
 * This structure is safe to place in shared memory to be common among
 * different processes in a multi-process configuration.
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

	/** PMD-specific private data */
	void *dev_private;
} __rte_cache_aligned;

/** @internal The data structure associated with each ML device. */
struct rte_mldev {
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

/** Global structure used for maintaining state of allocated ML devices */
struct rte_mldev_global {
	/**< Device information array */
	struct rte_mldev *devs;

	/**< Device data array */
	struct rte_mldev_data *data[RTE_ML_MAX_DEVS];

	/**< Number of devices found */
	uint8_t nb_devs;
};

/**
 * Get the rte_mldev structure device pointer for the device. Assumes a
 * valid device index.
 *
 * @param dev_id	Device ID value to select the device structure.
 *
 * @return		The rte_mldev pointer for the given device ID.
 */
__rte_internal
struct rte_mldev *rte_mldev_pmd_get_dev(uint8_t dev_id);

/**
 * Get the rte_mldev structure device pointer for the named device.
 *
 * @param name	Device name to select the device structure.
 *
 * @return	The rte_mldev pointer for the given device ID.
 */
__rte_internal
struct rte_mldev *rte_mldev_pmd_get_named_dev(const char *name);

/**
 * Definitions of all functions exported by a driver through the
 * generic structure of type *ml_dev_ops* supplied in the
 * *rte_mldev* structure associated with a device.
 */

/**
 * Function used to configure device.
 *
 * @param	dev	ML device pointer
 * @param	config	ML device configurations
 *
 * @return	Returns 0 on success
 */
typedef int (*mldev_configure_t)(struct rte_mldev *dev,
		struct rte_mldev_config *config);

/**
 * Function used to close a configured device.
 *
 * @param	dev	ML device pointer
 * @return
 * - 0 on success.
 * - EAGAIN if can't close as device is busy
 */
typedef int (*mldev_close_t)(struct rte_mldev *dev);

/** ML device operations function pointer table */
struct rte_mldev_ops {
	/**< Configure device. */
	mldev_configure_t dev_configure;

	/**< Close device. */
	mldev_close_t dev_close;
};

/**
 * Function for internal use by dummy drivers primarily, e.g. ring-based
 * driver.
 * Allocates a new mldev slot for an ml device and returns the pointer
 * to that slot for the driver to use.
 *
 * @param name		Unique identifier name for each device
 * @param socket_id	Socket to allocate resources on.
 * @return
 *   - Slot in the rte_dev_devices array for a new device;
 */
__rte_internal
struct rte_mldev *rte_mldev_pmd_allocate(const char *name, int socket_id);

/**
 * Function for internal use by dummy drivers primarily, e.g. ring-based
 * driver.
 * Release the specified mldev device.
 *
 * @param mldev
 * The *mldev* pointer is the address of the *rte_mldev* structure.
 * @return
 *   - 0 on success, negative on error
 */
__rte_internal
extern int rte_mldev_pmd_release_device(struct rte_mldev *mldev);

/**
 * @internal
 *
 * PMD assist function to provide boiler plate code for ml driver to create
 * and allocate resources for a new ml PMD device instance.
 *
 * @param name		ML device name.
 * @param device	Base device instance
 * @param params	PMD initialisation parameters
 *
 * @return
 *  - ml device instance on success
 *  - NULL on creation failure
 */
__rte_internal
struct rte_mldev *
rte_mldev_pmd_create(const char *name, struct rte_device *device,
		     struct rte_mldev_pmd_init_params *params);

/**
 * @internal
 *
 * PMD assist function to provide boiler plate code for ml driver to
 * destroy and free resources associated with a ml PMD device instance.
 *
 * @param mldev	ML device handle.
 *
 * @return
 *  - 0 on success
 *  - errno on failure
 */
__rte_internal
int rte_mldev_pmd_destroy(struct rte_mldev *mldev);

/**
 * @internal
 * This is the last step of device probing. It must be called after a
 * mldev is allocated and initialized successfully.
 *
 * @param dev	Pointer to mldev struct
 *
 * @return
 *  void
 */
__rte_internal
void rte_mldev_pmd_probing_finish(struct rte_mldev *dev);

#ifdef __cplusplus
}
#endif

#endif /* _MLDEV_PMD_H */
