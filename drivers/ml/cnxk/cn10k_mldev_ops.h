/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _CN10K_MLDEV_OPS_H_
#define _CN10K_MLDEV_OPS_H_

#include <rte_ml.h>
#include <rte_mldev.h>

extern struct rte_mldev_ops cn10k_ml_ops;

int cn10k_ml_dev_configure(struct rte_mldev *dev,
			   struct rte_mldev_config *conf);

int cn10k_ml_dev_close(struct rte_mldev *dev);

int cn10k_ml_dev_start(struct rte_mldev *dev);

void cn10k_ml_dev_stop(struct rte_mldev *dev);

int cn10k_ml_model_create(struct rte_mldev *dev, struct rte_ml_model *model,
			  uint8_t *model_id);

int cn10k_ml_model_destroy(struct rte_mldev *dev, uint8_t model_id);

int cn10k_ml_model_load(struct rte_mldev *dev, uint8_t model_id);

int cn10k_ml_model_unload(struct rte_mldev *dev, uint8_t model_id);

#endif /* _CNXK_MLDEV_OPS_H_ */
