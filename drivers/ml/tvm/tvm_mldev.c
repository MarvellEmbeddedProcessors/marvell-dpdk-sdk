/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Marvell.
 */

#include <mldev_pmd.h>
#include <rte_bus_vdev.h>
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_mldev.h>

#include "tvm_mldev.h"
#include "tvm_mldev_ops.h"

uint8_t tvm_mldev_driver_id;

/** Create TVM ML device */
static int
mldev_tvm_create(const char *name, struct rte_vdev_device *vdev,
		 struct rte_mldev_pmd_init_params *init_params)
{
	struct rte_mldev *dev;
	struct tvm_ml_dev *ml_dev;

	dev = rte_mldev_pmd_create(name, &vdev->device, init_params);
	if (dev == NULL) {
		MLDEV_LOG_ERR("failed to create mldev vdev");
		goto init_error;
	}

	dev->driver_id = tvm_mldev_driver_id;
	dev->dev_ops = &tvm_ml_ops;

	ml_dev = dev->data->dev_private;
	ml_dev->max_nb_qpairs = init_params->max_nb_queue_pairs;

	rte_mldev_pmd_probing_finish(dev);

	return 0;

init_error:
	MLDEV_LOG_ERR("driver %s: create failed", init_params->name);

	mldev_tvm_remove(vdev);
	return -EFAULT;
}

/** Probe / initialize TVM ML device */
int
mldev_tvm_probe(struct rte_vdev_device *vdev)
{
	const char *input_args;
	const char *name;

	struct rte_mldev_pmd_init_params init_params = {
		.name = "",
		.socket_id = rte_socket_id(),
		.private_data_size = sizeof(struct tvm_ml_dev),
		.max_nb_queue_pairs = RTE_MLDEV_PMD_DEFAULT_MAX_NB_QUEUE_PAIRS};

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;
	input_args = rte_vdev_device_args(vdev);

	rte_mldev_pmd_parse_input_args(&init_params, input_args);

	return mldev_tvm_create(name, vdev, &init_params);
}

/** Remove / uninitialize TVM ML device */
int
mldev_tvm_remove(struct rte_vdev_device *vdev)
{
	struct rte_mldev *mldev;
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	mldev = rte_mldev_pmd_get_named_dev(name);
	if (mldev == NULL)
		return -ENODEV;

	return rte_mldev_pmd_destroy(mldev);
}

static struct rte_vdev_driver tvm_mldev_pmd = {.probe = mldev_tvm_probe,
					       .remove = mldev_tvm_remove};

static struct mldev_driver tvm_mldev_drv;

RTE_PMD_REGISTER_VDEV(MLDEV_NAME_TVM_PMD, tvm_mldev_pmd);
RTE_PMD_REGISTER_PARAM_STRING(MLDEV_NAME_TVM_PMD, "max_nb_queue_pairs=<int> "
						  "socket_id=<int>");
RTE_PMD_REGISTER_ML_DRIVER(tvm_mldev_drv, tvm_mldev_pmd.driver,
			   tvm_mldev_driver_id);
