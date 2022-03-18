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

	/**< Number of queue pairs to configure on this device. This value
	 * cannot exceed the max_queue_pairs which previously provided in
	 * rte_mldev_info_get().
	 */
	uint16_t nb_queue_pairs;
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
 * Get number and identifiers of attached ML devices that
 * use the same ML driver.
 *
 * @param driver_name
 *    Driver name
 * @param devices
 *    Output devices identifiers
 * @param nb_devices
 *    Maximum number of devices
 *
 * @return
 *   Returns number of attached ML device.
 */
uint8_t
rte_mldev_devices_get(const char *driver_name, uint8_t *devices, uint8_t nb_devices);

/**
 * Get number of ML device defined type.
 *
 * @param driver_id
 *    Driver identifier
 *
 * @return
 *   Returns number of ML device.
 */
extern uint8_t
rte_mldev_device_count_by_driver(uint8_t driver_id);

/**
 * Provide driver identifier.
 *
 * @param name
 *   The pointer to a driver name
 * @return
 *  The driver type identifier or -1 if no driver found
 */
__rte_experimental
int
rte_mldev_driver_id_get(const char *name);

/**
 * Provide driver name.
 *
 * @param driver_id
 *   The driver identifier.
 * @return
 *  The driver name or null if no driver found
 */
__rte_experimental
const char *
rte_mldev_driver_name_get(uint8_t driver_id);

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

/**  ML device information */
struct rte_mldev_info {
	/**< Driver name. */
	const char *driver_name;

	/**< Driver identifier */
	uint8_t driver_id;

	/**< Generic device information. */
	struct rte_device *device;

	/**< Maximum number of queues pairs supported by device. */
	uint32_t max_nb_queue_pairs;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Retrieve the information of a device.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param dev_info
 *   A pointer to a structure of type *rte_mldev_info* to be filled with the
 * information of the device.
 *
 * @return
 *   - 0: Success, driver updates the information of the ML device
 *   - <0: Error code returned by the driver info get function.
 */
__rte_experimental
extern int
rte_mldev_info_get(uint8_t dev_id, struct rte_mldev_info *dev_info);

/** ML device queue pair configuration structure. */
struct rte_mldev_qp_conf {
	/**< Number of descriptors per queue pair */
	uint32_t nb_desc;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate and set up a receive queue pair for a device.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_pair_id
 *   The index of the queue pairs to set up. The value must be in the range [0,
 * nb_queue_pair - 1] previously supplied to rte_mldev_configure().
 * @param qp_conf
 *   The pointer to the configuration data to be used for the queue pair.
 * @param socket_id
 *   The *socket_id* argument is the socket identifier in case of NUMA. The
 * value can be *SOCKET_ID_ANY* if there is no NUMA constraint for the DMA
 * memory allocated for the receive queue pair.
 *
 * @return
 *   - 0: Success, queue pair correctly set up.
 *   - <0: Queue pair configuration failed
 */
__rte_experimental
extern int
rte_mldev_queue_pair_setup(uint8_t dev_id, uint16_t queue_pair_id,
			   const struct rte_mldev_qp_conf *qp_conf,
			   int socket_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Enqueue a burst of ML inferences for processing on an ML device.
 *
 * The rte_mldev_enqueue_burst() function is invoked to place ML inference
 * operations on the queue *qp_id* of the device designated by its *dev_id*.
 *
 * The *nb_ops* parameter is the number of inferences to process which are
 * supplied in the *ops* array of *rte_ml_op* structures.
 *
 * The rte_mldev_enqueue_burst() function returns the number of inferences it
 * actually enqueued for processing. A return value equal to *nb_ops* means that
 * all packets have been enqueued.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param qp_id
 *   The index of the queue pair which inferences are to be enqueued for
 * processing. The value must be in the range [0, nb_queue_pairs - 1] previously
 * supplied to *rte_mldev_configure*.
 * @param ops
 *   The address of an array of *nb_ops* pointers to *rte_ml_op* structures
 * which contain the ml inferences to be processed.
 * @param nb_ops
 *   The number of operations to process.
 *
 * @return
 *   The number of inference operations actually enqueued to the ML device. The
 * return value can be less than the value of the *nb_ops* parameter when the ML
 * devices queue is full or if invalid parameters are specified in a
 * *rte_ml_op*.
 */
__rte_experimental
uint16_t
rte_mldev_enqueue_burst(uint8_t dev_id, uint16_t qp_id, struct rte_ml_op **ops,
			uint16_t nb_ops);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Dequeue a burst of processed ML inferences operations from a queue on the ML
 * device. The dequeued operations are stored in *rte_ml_op* structures
 * whose pointers are supplied in the *ops* array.
 *
 * The rte_mldev_dequeue_burst() function returns the number of inferences
 * actually dequeued, which is the number of *rte_ml_op* data structures
 * effectively supplied into the *ops* array.
 *
 * A return value equal to *nb_ops* indicates that the queue contained at least
 * *nb_ops* operations, and this is likely to signify that other processed
 * operations remain in the devices output queue. Applications implementing a
 * "retrieve as many processed operations as possible" policy can check this
 * specific case and keep invoking the rte_mldev_dequeue_burst() function until
 * a value less than *nb_ops* is returned.
 *
 * The rte_mldev_dequeue_burst() function does not provide any error
 * notification to avoid the corresponding overhead.
 *
 * @param dev_id
 *   The symmetric ML device identifier
 * @param qp_id
 *   The index of the queue pair from which to retrieve processed packets. The
 * value must be in the range [0, nb_queue_pair - 1] previously supplied to
 * rte_mldev_configure().
 * @param ops
 *   The address of an array of pointers to *rte_ml_op* structures that must be
 * large enough to store *nb_ops* pointers in it.
 * @param nb_ops
 *   The maximum number of inferences to dequeue.
 *
 * @return
 *   The number of operations actually dequeued, which is the number of pointers
 * to *rte_ml_op* structures effectively supplied to the *ops* array.
 */
__rte_experimental
uint16_t
rte_mldev_dequeue_burst(uint8_t dev_id, uint16_t qp_id, struct rte_ml_op **ops,
			uint16_t nb_ops);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MLDEV_H_ */
