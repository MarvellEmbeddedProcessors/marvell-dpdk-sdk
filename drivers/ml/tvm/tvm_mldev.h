/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Marvell.
 */

#ifndef _TVM_MLDEV_H_
#define _TVM_MLDEV_H_

/* TVM ML PMD device name */
#define MLDEV_NAME_TVM_PMD ml_tvm

/* Driver ID */
extern uint8_t tvm_mldev_driver_id;

/** private data structure for each TVM ML device */
struct tvm_ml_dev {
	/**< Max number of queue pairs */
	unsigned int max_nb_qpairs;
};

int mldev_tvm_probe(struct rte_vdev_device *vdev);
int mldev_tvm_remove(struct rte_vdev_device *vdev);

#endif /* _TVM_MLDEV_H_ */
