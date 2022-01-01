/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell
 */

#include <rte_eal.h>
#include <rte_malloc.h>

#include "mldev_pmd.h"

struct rte_mldev *
rte_mldev_pmd_create(const char *name, struct rte_device *device,
		     struct rte_mldev_pmd_init_params *params)
{
	struct rte_mldev *mldev;

	if (params->name[0] != '\0') {
		MLDEV_LOG_INFO("User specified device name = %s\n",
			       params->name);
		name = params->name;
	}
	MLDEV_LOG_INFO("ML device initialisation - name: %s,"
		       " socket_id: %d",
		       name, params->socket_id);

	/* allocate device structure */
	mldev = rte_mldev_pmd_allocate(name, params->socket_id);
	if (mldev == NULL) {
		MLDEV_LOG_ERR("Failed to allocate ML device for %s", name);
		return NULL;
	}

	/* allocate private device structure */
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		mldev->data->dev_private = rte_zmalloc_socket(
			"mldev device private", params->private_data_size,
			RTE_CACHE_LINE_SIZE, params->socket_id);

		if (mldev->data->dev_private == NULL) {
			MLDEV_LOG_ERR("Cannot allocate memory for mldev %s"
				      " private data",
				      name);

			rte_mldev_pmd_release_device(mldev);
			return NULL;
		}
	}

	mldev->device = device;

	return mldev;
}

int
rte_mldev_pmd_destroy(struct rte_mldev *mldev)
{
	int retval;
	void *dev_priv = mldev->data->dev_private;

	MLDEV_LOG_INFO("Closing ML device %s", mldev->device->name);

	/* free ml device */
	retval = rte_mldev_pmd_release_device(mldev);
	if (retval)
		return retval;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		rte_free(dev_priv);

	mldev->device = NULL;
	mldev->data = NULL;

	return 0;
}

void
rte_mldev_pmd_probing_finish(struct rte_mldev *mldev)
{
	if (mldev == NULL)
		return;
}
