/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>

#include "mldev_pmd.h"
#include "rte_mldev.h"

int
rte_ml_model_create(uint8_t dev_id, struct rte_ml_model *model,
		    uint8_t *model_id)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id = %x", dev_id);
		return -EINVAL;
	}

	dev = rte_mldev_pmd_get_dev(dev_id);

	return (*dev->dev_ops->ml_model_create)(dev, model, model_id);
}

int
rte_ml_model_destroy(uint8_t dev_id, uint8_t model_id)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id = %x", dev_id);
		return -EINVAL;
	}

	dev = rte_mldev_pmd_get_dev(dev_id);

	return (*dev->dev_ops->ml_model_destroy)(dev, model_id);
}

int
rte_ml_model_load(uint8_t dev_id, uint8_t model_id)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id = %x", dev_id);
		return -EINVAL;
	}

	dev = rte_mldev_pmd_get_dev(dev_id);

	return (*dev->dev_ops->ml_model_load)(dev, model_id);
}

int
rte_ml_model_unload(uint8_t dev_id, uint8_t model_id)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id = %x", dev_id);
		return -EINVAL;
	}

	dev = rte_mldev_pmd_get_dev(dev_id);

	return (*dev->dev_ops->ml_model_unload)(dev, model_id);
}

int
rte_ml_model_info_get(uint8_t dev_id, uint8_t model_id,
		      struct rte_ml_model_info *model_info)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id = %x", dev_id);
		return -EINVAL;
	}

	dev = rte_mldev_pmd_get_dev(dev_id);

	return (*dev->dev_ops->ml_model_info_get)(dev, model_id, model_info);
}
