/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _TVM_MLDEV_OPS_H_
#define _TVM_MLDEV_OPS_H_

#include <rte_ml.h>
#include <rte_mldev.h>

extern struct rte_mldev_ops tvm_ml_ops;

struct tvm_ml_req {
	/**< Op handle */
	uintptr_t op_handle;

	/**< Job completion handle */
	uintptr_t job_handle;
};

struct tvm_ml_pending_queue {
	/**< Pending requests count */
	uint64_t pending_count;

	/**< Array of pending requests */
	struct tvm_ml_req *req_queue;

	/**< Tail of the queue to be used for enqueue */
	uint64_t enq_tail;

	/**< Head of the queue to be used for dequeue */
	uint64_t deq_head;
};

struct tvm_ml_qp {
	/**< Queue pair ID */
	uint32_t id;

	/**< Number of descriptors */
	uint64_t nb_desc;

	/**< Base address where BAR is mapped */
	struct tvm_ml_pending_queue pend_q;
};

int tvm_ml_dev_configure(struct rte_mldev *dev, struct rte_mldev_config *conf);

int tvm_ml_dev_close(struct rte_mldev *dev);

int tvm_ml_dev_start(struct rte_mldev *dev);

void tvm_ml_dev_stop(struct rte_mldev *dev);

int tvm_ml_model_create(struct rte_mldev *dev, struct rte_ml_model *model,
			uint8_t *model_id);

int tvm_ml_model_destroy(struct rte_mldev *dev, uint8_t model_id);

int tvm_ml_model_load(struct rte_mldev *dev, uint8_t model_id);

int tvm_ml_model_unload(struct rte_mldev *dev, uint8_t model_id);

int tvm_ml_inference_sync(struct rte_mldev *dev, struct rte_ml_op *op);

#endif /* _CNXK_MLDEV_OPS_H_ */
