/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

/**
 * @file rte_pmd_cnxk_crypto.h
 * Marvell CNXK Crypto PMD specific functions.
 *
 **/

#ifndef _PMD_CNXK_CRYPTO_H_
#define _PMD_CNXK_CRYPTO_H_

#include <stdint.h>

/* Forward declarations */

/**
 * @brief Crypto CNXK PMD QPTR opaque pointer.
 *
 * This structure represents the queue pair structure that would be the input to APIs that use
 * hardware queues.
 */
struct rte_pmd_cnxk_crypto_qptr;

/**
 * Get queue pointer of a specific queue in a cryptodev.
 *
 * @param dev_id
 *   Device identifier of cryptodev device.
 * @param qp_id
 *   Index of the queue pair.
 * @return
 *   - On success, pointer to queue pair structure that would be the input to submit APIs.
 *   - NULL on error.
 */
__rte_experimental
struct rte_pmd_cnxk_crypto_qptr *rte_pmd_cnxk_crypto_qptr_get(uint8_t dev_id, uint16_t qp_id);

/**
 * Submit CPT instruction (cpt_inst_s) to hardware (CPT).
 *
 * The ``qp`` is a pointer obtained from ``rte_pmd_cnxk_crypto_qp_get``. Application should make
 * sure it doesn't overflow the internal hardware queues. It may do so by making sure the inflight
 * packets are not more than the number of descriptors configured.
 *
 * This API may be called only after the cryptodev and queue pair is configured and is started.
 *
 * @param qptr
 *   Pointer obtained with ``rte_pmd_cnxk_crypto_qptr_get``.
 * @param inst
 *   Pointer to an array of instructions prepared by application.
 * @param nb_inst
 *   Number of instructions.
 */
__rte_experimental
void rte_pmd_cnxk_crypto_submit(struct rte_pmd_cnxk_crypto_qptr *qptr, void *inst,
				uint16_t nb_inst);

#endif /* _PMD_CNXK_CRYPTO_H_ */
