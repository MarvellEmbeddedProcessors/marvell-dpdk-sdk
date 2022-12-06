/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 NXP.
 * Copyright(c) 2017 Intel Corporation.
 */

#ifndef _RTE_SECURITY_DRIVER_H_
#define _RTE_SECURITY_DRIVER_H_

/**
 * @file rte_security_driver.h
 *
 * RTE Security Common Definitions
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "rte_security.h"

/**
 * Configure a security session on a device.
 *
 * @param	device		Crypto/eth device pointer
 * @param	conf		Security session configuration
 * @param	sess		Pointer to Security private session structure
 * @param	mp		Mempool where the private session is allocated
 *
 * @return
 *  - Returns 0 if private session structure have been created successfully.
 *  - Returns -EINVAL if input parameters are invalid.
 *  - Returns -ENOTSUP if crypto device does not support the crypto transform.
 *  - Returns -ENOMEM if the private session could not be allocated.
 */
typedef int (*security_session_create_t)(void *device,
		struct rte_security_session_conf *conf,
		struct rte_security_session *sess,
		struct rte_mempool *mp);

/**
 * Free driver private session data.
 *
 * @param	device		Crypto/eth device pointer
 * @param	sess		Security session structure
 */
typedef int (*security_session_destroy_t)(void *device,
		struct rte_security_session *sess);

/**
 * Update driver private session data.
 *
 * @param	device		Crypto/eth device pointer
 * @param	sess		Pointer to Security private session structure
 * @param	conf		Security session configuration
 *
 * @return
 *  - Returns 0 if private session structure have been updated successfully.
 *  - Returns -EINVAL if input parameters are invalid.
 *  - Returns -ENOTSUP if crypto device does not support the crypto transform.
 */
typedef int (*security_session_update_t)(void *device,
		struct rte_security_session *sess,
		struct rte_security_session_conf *conf);

/**
 * Get the size of a security session
 *
 * @param	device		Crypto/eth device pointer
 *
 * @return
 *  - On success returns the size of the session structure for device
 *  - On failure returns 0
 */
typedef unsigned int (*security_session_get_size)(void *device);

/**
 * Get stats from the PMD.
 *
 * @param	device		Crypto/eth device pointer
 * @param	sess		Pointer to Security private session structure
 * @param	stats		Security stats of the driver
 *
 * @return
 *  - Returns 0 if private session structure have been updated successfully.
 *  - Returns -EINVAL if session parameters are invalid.
 */
typedef int (*security_session_stats_get_t)(void *device,
		struct rte_security_session *sess,
		struct rte_security_stats *stats);

__rte_internal
int rte_security_dynfield_register(void);

/**
 * @internal
 * Register mbuf dynamic field for Security inline ingress Out-of-Place(OOP)
 * processing.
 */
__rte_internal
int rte_security_oop_dynfield_register(void);

/**
 * Update the mbuf with provided metadata.
 *
 * @param	device		Crypto/eth device pointer
 * @param	sess		Security session structure
 * @param	mb		Packet buffer
 * @param	params		Metadata
 *
 * @return
 *  - Returns 0 if metadata updated successfully.
 *  - Returns -ve value for errors.
 */
typedef int (*security_set_pkt_metadata_t)(void *device,
		struct rte_security_session *sess, struct rte_mbuf *mb,
		void *params);

/**
 * Get application specific userdata associated with the security session.
 * Device specific metadata provided would be used to uniquely identify
 * the security session being referred to.
 *
 * @param	device		Crypto/eth device pointer
 * @param	md		Metadata
 * @param	userdata	Pointer to receive userdata
 *
 * @return
 *  - Returns 0 if userdata is retrieved successfully.
 *  - Returns -ve value for errors.
 */
typedef int (*security_get_userdata_t)(void *device,
		uint64_t md, void **userdata);

/**
 * Get security capabilities of the device.
 *
 * @param	device		crypto/eth device pointer
 *
 * @return
 *  - Returns rte_security_capability pointer on success.
 *  - Returns NULL on error.
 */
typedef const struct rte_security_capability *(*security_capabilities_get_t)(
		void *device);

/**
 * Configure security device to inject packets to an ethdev port.
 *
 * @param	device		Crypto/eth device pointer
 * @param	port_id		Port identifier of the ethernet device to which packets need to be
 *				injected.
 * @param	enable		Flag to enable and disable connection between a security device and
 *				an ethdev port.
 * @return
 *   - 0 if successful.
 *   - -EINVAL if context NULL or port_id is invalid.
 *   - -EBUSY if devices are not in stopped state.
 *   - -ENOTSUP if security device does not support injecting to the ethdev port.
 */
typedef int (*security_rx_inject_configure)(void *device, uint16_t port_id, bool enable);

/**
 * Perform security processing of packets and inject the processed packet to
 * ethdev Rx.
 *
 * Rx inject would behave similarly to ethdev loopback but with the additional
 * security processing.
 *
 * @param	device		Crypto/eth device pointer
 * @param	pkts		The address of an array of *nb_pkts* pointers to
 *				*rte_mbuf* structures which contain the packets.
 * @param	sess		The address of an array of *nb_pkts* pointers to
 *				*rte_security_session* structures corresponding
 *				to each packet.
 * @param	nb_pkts		The maximum number of packets to process.
 *
 * @return
 *   The number of packets successfully injected to ethdev Rx. The return
 *   value can be less than the value of the *nb_pkts* parameter when the
 *   PMD internal queues have been filled up.
 */
typedef uint16_t (*security_inb_pkt_rx_inject)(void *device,
		struct rte_mbuf **pkts, struct rte_security_session **sess,
		uint16_t nb_pkts);

/** Security operations function pointer table */
struct rte_security_ops {
	security_session_create_t session_create;
	/**< Configure a security session. */
	security_session_update_t session_update;
	/**< Update a security session. */
	security_session_get_size session_get_size;
	/**< Return size of security session. */
	security_session_stats_get_t session_stats_get;
	/**< Get security session statistics. */
	security_session_destroy_t session_destroy;
	/**< Clear a security sessions private data. */
	security_set_pkt_metadata_t set_pkt_metadata;
	/**< Update mbuf metadata. */
	security_get_userdata_t get_userdata;
	/**< Get userdata associated with session which processed the packet. */
	security_capabilities_get_t capabilities_get;
	/**< Get security capabilities. */
	security_rx_inject_configure rx_inject_configure;
	/**< Rx inject configure. */
	security_inb_pkt_rx_inject inb_pkt_rx_inject;
	/**< Perform security processing and do Rx inject. */
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_SECURITY_DRIVER_H_ */
