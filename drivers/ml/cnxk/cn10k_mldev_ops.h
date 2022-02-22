/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _CN10K_MLDEV_OPS_H_
#define _CN10K_MLDEV_OPS_H_

#include <rte_ml.h>
#include <rte_mldev.h>

extern struct rte_mldev_ops cn10k_ml_ops;

struct cn10k_ml_req {
	/**< Op handle */
	uintptr_t op_handle;

	/**< Job completion handle */
	uintptr_t job_handle;
};

struct cn10k_ml_pending_queue {
	/**< Pending requests count */
	uint64_t pending_count;

	/**< Array of pending requests */
	struct cn10k_ml_req *req_queue;

	/**< Tail of the queue to be used for enqueue */
	uint64_t enq_tail;

	/**< Head of the queue to be used for dequeue */
	uint64_t deq_head;
};

struct cn10k_ml_qp {
	/**< Queue pair ID */
	uint32_t id;

	/**< Number of descriptors */
	uint64_t nb_desc;

	/**< Base address where BAR is mapped */
	struct cn10k_ml_pending_queue pend_q;
};

int cn10k_ml_dev_configure(struct rte_mldev *dev,
			   struct rte_mldev_config *conf);

int cn10k_ml_dev_close(struct rte_mldev *dev);

int cn10k_ml_dev_start(struct rte_mldev *dev);

void cn10k_ml_dev_stop(struct rte_mldev *dev);

int cn10k_ml_queue_pair_setup(struct rte_mldev *dev, uint16_t qp_id,
			      const struct rte_mldev_qp_conf *qp_conf,
			      int socket_id);

int cn10k_ml_queue_pair_release(struct rte_mldev *dev, uint16_t qp_id);

int cn10k_ml_model_create(struct rte_mldev *dev, struct rte_ml_model *model,
			  uint8_t *model_id);

int cn10k_ml_model_destroy(struct rte_mldev *dev, uint8_t model_id);

int cn10k_ml_model_load(struct rte_mldev *dev, uint8_t model_id);

int cn10k_ml_model_unload(struct rte_mldev *dev, uint8_t model_id);

uint16_t cn10k_ml_enqueue_burst(struct rte_mldev *dev, uint16_t qp_id,
				struct rte_ml_op **op, uint16_t nb_ops);

uint16_t cn10k_ml_dequeue_burst(struct rte_mldev *dev, uint16_t qp_id,
				struct rte_ml_op **op, uint16_t nb_ops);

#endif /* _CNXK_MLDEV_OPS_H_ */
