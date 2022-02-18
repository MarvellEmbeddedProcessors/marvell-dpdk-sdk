/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>

#include "mldev_pmd.h"
#include "rte_mldev.h"

static struct rte_mldev rte_ml_devices[RTE_ML_MAX_DEVS];

static struct rte_mldev_global mldev_globals = {
	.devs = rte_ml_devices, .data = {NULL}, .nb_devs = 0};

struct rte_mldev *
rte_mldev_pmd_get_dev(uint8_t dev_id)
{
	return &mldev_globals.devs[dev_id];
}

struct rte_mldev *
rte_mldev_pmd_get_named_dev(const char *name)
{
	struct rte_mldev *dev;
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < RTE_ML_MAX_DEVS; i++) {
		dev = &mldev_globals.devs[i];

		if ((dev->attached == RTE_MLDEV_ATTACHED) &&
		    (strcmp(dev->data->name, name) == 0))
			return dev;
	}

	return NULL;
}

static inline uint8_t
rte_mldev_is_valid_device_data(uint8_t dev_id)
{
	if (dev_id >= RTE_ML_MAX_DEVS || rte_ml_devices[dev_id].data == NULL)
		return 0;

	return 1;
}

unsigned int
rte_mldev_is_valid_dev(uint8_t dev_id)
{
	struct rte_mldev *dev = NULL;

	if (!rte_mldev_is_valid_device_data(dev_id))
		return 0;

	dev = rte_mldev_pmd_get_dev(dev_id);
	if (dev->attached != RTE_MLDEV_ATTACHED)
		return 0;
	else
		return 1;
}

int
rte_mldev_get_dev_id(const char *name)
{
	unsigned int i;

	if (name == NULL)
		return -1;

	for (i = 0; i < RTE_ML_MAX_DEVS; i++) {
		if (!rte_mldev_is_valid_device_data(i))
			continue;
		if ((strcmp(mldev_globals.devs[i].data->name, name) == 0) &&
		    (mldev_globals.devs[i].attached == RTE_MLDEV_ATTACHED))
			return i;
	}

	return -1;
}

uint8_t
rte_mldev_count(void)
{
	return mldev_globals.nb_devs;
}

int
rte_mldev_socket_id(uint8_t dev_id)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id))
		return -1;

	dev = rte_mldev_pmd_get_dev(dev_id);

	return dev->data->socket_id;
}

static inline int
rte_mldev_data_alloc(uint8_t dev_id, struct rte_mldev_data **data,
		     int socket_id)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	int n;

	/* generate memzone name */
	n = snprintf(mz_name, sizeof(mz_name), "rte_mldev_data_%u", dev_id);
	if (n >= (int)sizeof(mz_name))
		return -EINVAL;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		mz = rte_memzone_reserve(mz_name, sizeof(struct rte_mldev_data),
					 socket_id, 0);
		MLDEV_LOG_DEBUG("PRIMARY: reserved memzone for %s (%p)",
				mz_name, mz);
	} else {
		mz = rte_memzone_lookup(mz_name);
		MLDEV_LOG_DEBUG("SECONDARY: looked up memzone for %s (%p)",
				mz_name, mz);
	}

	if (mz == NULL)
		return -ENOMEM;

	*data = mz->addr;
	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		memset(*data, 0, sizeof(struct rte_mldev_data));

	return 0;
}

static inline int
rte_mldev_data_free(uint8_t dev_id, struct rte_mldev_data **data)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	int n;

	/* generate memzone name */
	n = snprintf(mz_name, sizeof(mz_name), "rte_mldev_data_%u", dev_id);
	if (n >= (int)sizeof(mz_name))
		return -EINVAL;

	mz = rte_memzone_lookup(mz_name);
	if (mz == NULL)
		return -ENOMEM;

	RTE_ASSERT(*data == mz->addr);
	*data = NULL;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		MLDEV_LOG_DEBUG("PRIMARY: free memzone of %s (%p)", mz_name,
				mz);
		return rte_memzone_free(mz);
	} else {
		MLDEV_LOG_DEBUG("SECONDARY: don't free memzone of %s (%p)",
				mz_name, mz);
	}

	return 0;
}

static uint8_t
rte_mldev_find_free_device_index(void)
{
	uint8_t dev_id;

	for (dev_id = 0; dev_id < RTE_ML_MAX_DEVS; dev_id++) {
		if (rte_ml_devices[dev_id].attached == RTE_MLDEV_DETACHED)
			return dev_id;
	}
	return RTE_ML_MAX_DEVS;
}

struct rte_mldev *
rte_mldev_pmd_allocate(const char *name, int socket_id)
{
	struct rte_mldev *mldev;
	uint8_t dev_id;

	if (rte_mldev_pmd_get_named_dev(name) != NULL) {
		MLDEV_LOG_ERR("ML device with name %s already allocated!",
			      name);
		return NULL;
	}

	dev_id = rte_mldev_find_free_device_index();
	if (dev_id == RTE_ML_MAX_DEVS) {
		MLDEV_LOG_ERR("Reached maximum number of ML devices");
		return NULL;
	}

	mldev = rte_mldev_pmd_get_dev(dev_id);
	if (mldev->data == NULL) {
		struct rte_mldev_data **mldev_data =
			&mldev_globals.data[dev_id];

		int retval =
			rte_mldev_data_alloc(dev_id, mldev_data, socket_id);

		if (retval < 0 || *mldev_data == NULL)
			return NULL;

		mldev->data = *mldev_data;

		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			strlcpy(mldev->data->name, name, RTE_MLDEV_NAME_LEN);

			mldev->data->dev_id = dev_id;
			mldev->data->socket_id = socket_id;
			mldev->data->dev_started = 0;
			MLDEV_LOG_DEBUG("PRIMARY: init data");
		}

		MLDEV_LOG_DEBUG("Data for %s: dev_id %d, socket %d",
				mldev->data->name, mldev->data->dev_id,
				mldev->data->socket_id);

		mldev->attached = RTE_MLDEV_ATTACHED;

		mldev_globals.nb_devs++;
	}

	return mldev;
}

int
rte_mldev_pmd_release_device(struct rte_mldev *mldev)
{
	int ret;
	uint8_t dev_id;

	if (mldev == NULL)
		return -EINVAL;

	dev_id = mldev->data->dev_id;

	ret = rte_mldev_data_free(dev_id, &mldev_globals.data[dev_id]);
	if (ret < 0)
		return ret;

	mldev->attached = RTE_MLDEV_DETACHED;
	mldev_globals.nb_devs--;
	return 0;
}

const char *
rte_mldev_name_get(uint8_t dev_id)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_device_data(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id=%x", dev_id);
		return NULL;
	}

	dev = rte_mldev_pmd_get_dev(dev_id);
	if (dev == NULL)
		return NULL;

	return dev->data->name;
}

int
rte_mldev_configure(uint8_t dev_id, struct rte_mldev_config *config)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id = %x", dev_id);
		return -EINVAL;
	}

	dev = &rte_ml_devices[dev_id];

	if (dev->data->dev_started) {
		MLDEV_LOG_ERR(
			"device %d must be stopped to allow configuration",
			dev_id);
		return -EBUSY;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_configure, -ENOTSUP);

	return (*dev->dev_ops->dev_configure)(dev, config);
}

int
rte_mldev_close(uint8_t dev_id)
{
	struct rte_mldev *dev;
	int retval;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id=%x", dev_id);
		return -1;
	}

	dev = &rte_ml_devices[dev_id];

	/* Device must be stopped before it can be closed */
	if (dev->data->dev_started == 1) {
		MLDEV_LOG_ERR("Device %u must be stopped before closing",
			      dev_id);
		return -EBUSY;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_close, -ENOTSUP);
	retval = (*dev->dev_ops->dev_close)(dev);

	if (retval < 0)
		return retval;

	return 0;
}

int
rte_mldev_start(uint8_t dev_id)
{
	struct rte_mldev *dev;
	int retval;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id=%x", dev_id);
		return -1;
	}

	dev = &rte_ml_devices[dev_id];

	/* Device must be stopped before it can be closed */
	if (dev->data->dev_started != 0) {
		MLDEV_LOG_ERR("Device %u is already started", dev_id);
		return -EBUSY;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_start, -ENOTSUP);
	retval = (*dev->dev_ops->dev_start)(dev);

	if (retval == 0)
		dev->data->dev_started = 1;
	else
		return retval;

	return 0;
}

void
rte_mldev_stop(uint8_t dev_id)
{
	struct rte_mldev *dev;

	if (!rte_mldev_is_valid_dev(dev_id)) {
		MLDEV_LOG_ERR("Invalid dev_id = %x", dev_id);
		return;
	}

	dev = &rte_ml_devices[dev_id];

	/* Device must be stopped before it can be closed */
	if (dev->data->dev_started == 0) {
		MLDEV_LOG_ERR("Device %u is not started", dev_id);
		return;
	}

	(*dev->dev_ops->dev_stop)(dev);
	dev->data->dev_started = 0;
}
