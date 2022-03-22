/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Marvell.
 */

#ifndef _TVM_MLDEV_H_
#define _TVM_MLDEV_H_

#include <rte_bus_vdev.h>

/* TVM ML PMD device name */
#define MLDEV_NAME_TVM_PMD ml_tvm

/* Driver ID */
extern uint8_t tvm_mldev_driver_id;

/* Device macros */
#define ML_TVM_ALIGN_SIZE 64
#define ML_TVM_MAX_MODELS 16

/* Number of Queue-Pairs per device */
#define ML_TVM_QP_PER_DEVICE 8

/* Model name length */
#define ML_MODEL_NAME_LEN 64

/* Model states */
enum tvm_ml_model_state {
	TVM_ML_MODEL_STATE_CREATED,
	TVM_ML_MODEL_STATE_LOADED,
	TVM_ML_MODEL_STATE_UNKNOWN,
};

/* Model file metadata structure */
struct tvm_ml_model_metadata {
};

/* ML Model Object */
struct tvm_ml_model {
	/* Configuration reference */
	struct tvm_ml_config *ml_config;

	/* Model name */
	char name[ML_MODEL_NAME_LEN];

	/* Model ID */
	uint32_t model_id;

	/* Model metadata */
	struct tvm_ml_model_metadata model_metadata;

	/* Model state */
	enum tvm_ml_model_state state;

	/* Internal model_info structure */
	uint8_t *model_info;
};

/* Configuration object */
struct tvm_ml_config {
	/* Device reference */
	struct tvm_ml_dev *ml_dev;

	/* Active flag */
	bool active;

	/* Maximum number of models to be created */
	uint32_t max_models_created;

	/* ML model array */
	struct tvm_ml_model **ml_models;
};

/** private data structure for each TVM ML device */
struct tvm_ml_dev {
	/**< Max number of queue pairs */
	unsigned int max_nb_qpairs;

	/* Configuration handle */
	struct tvm_ml_config ml_config;
};

int mldev_tvm_probe(struct rte_vdev_device *vdev);
int mldev_tvm_remove(struct rte_vdev_device *vdev);

#endif /* _TVM_MLDEV_H_ */
