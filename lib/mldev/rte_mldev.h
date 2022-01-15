/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#ifndef _RTE_MLDEV_H_
#define _RTE_MLDEV_H_

/**
 * @file rte_mldev.h
 *
 * Machine Learning inference API.
 *
 * Defines RTE Machine Learning Device APIs for the provisioning of ML inference
 * operations.
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

/**
 * Get the device identifier for the named ML device.
 *
 * @param name	Device name to select the device structure.
 *
 * @return
 *   - Returns ML device identifier on success.
 *   - Return -1 on failure to find named ML device.
 */
__rte_experimental
extern int
rte_mldev_get_dev_id(const char *name);

/**
 * Get the ML device name given a device identifier.
 *
 * @param dev_id	The identifier of the device
 *
 * @return
 *   - Returns ML device name.
 *   - Returns NULL if ML device is not present.
 */
__rte_experimental
extern const char *
rte_mldev_name_get(uint8_t dev_id);

/**
 * Get the total number of ML devices that have been successfully
 * initialised.
 *
 * @return
 *   - The total number of usable ML devices.
 */
__rte_experimental
extern uint8_t
rte_mldev_count(void);

/**
 * Return the NUMA socket to which a device is connected
 *
 * @param dev_id	The identifier of the device
 * @return
 *   The NUMA socket id to which the device is connected or
 *   a default of zero if the socket could not be determined.
 *   -1 if returned is the dev_id value is out of range.
 */
__rte_experimental
extern int
rte_mldev_socket_id(uint8_t dev_id);

/**
 * Validate if the ML device index is valid attached ML device.
 *
 * @param dev_id	ML device index
 *
 * @return
 *   - If the device index is valid (1) or not (0).
 */
__rte_experimental
unsigned int
rte_mldev_is_valid_dev(uint8_t dev_id);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MLDEV_H_ */
