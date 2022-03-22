/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <eal_firmware.h>
#include <mldev_pmd.h>
#include <rte_eal.h>
#include <rte_mldev.h>

#include <rte_common.h>
#include <rte_io.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>

#include "tvm_mldev.h"
#include "tvm_mldev_ops.h"

/* ML configuration macros */
#define ML_CONFIG_MEMZONE_NAME "ml_tvm_config_mz"

/* ML model macros */
#define ML_MODEL_MEMZONE_NAME "ml_tvm_model_mz"

__rte_used static int
tvm_ml_io_type_get_size(enum rte_ml_io_type type)
{
	switch (type) {
	case RTE_ML_IO_TYPE_INT8:
	case RTE_ML_IO_TYPE_UINT8:
		return sizeof(uint8_t);
	case RTE_ML_IO_TYPE_INT16:
	case RTE_ML_IO_TYPE_UINT16:
		return sizeof(uint16_t);
	case RTE_ML_IO_TYPE_INT32:
	case RTE_ML_IO_TYPE_UINT32:
		return sizeof(uint32_t);
	case RTE_ML_IO_TYPE_FP16:
		return sizeof(float) / 2;
	case RTE_ML_IO_TYPE_FP32:
		return sizeof(float);
	default:
		return -EINVAL;
	}
}

static int
tvm_ml_metadata_check(struct tvm_ml_model_metadata *metadata)
{
	RTE_SET_USED(metadata);

	return 0;
}

static void
tvm_ml_model_info_set(struct tvm_ml_model *ml_model)
{

	struct tvm_ml_model_metadata *model_metadata;
	struct rte_ml_output_info *output_info;
	struct rte_ml_input_info *input_info;
	struct rte_ml_model_info *model_info;

	model_info = (struct rte_ml_model_info *)(ml_model->model_info);
	input_info = RTE_PTR_ADD(model_info, sizeof(struct rte_ml_model_info));
	output_info = RTE_PTR_ADD(input_info, sizeof(struct rte_ml_input_info));

	model_metadata = &ml_model->model_metadata;

	/* Set model info */
	memset(model_info, 0, sizeof(struct rte_ml_model_info));

	RTE_SET_USED(output_info);
	RTE_SET_USED(model_metadata);
}

int
tvm_ml_dev_configure(struct rte_mldev *dev, struct rte_mldev_config *conf)
{
	struct tvm_ml_config *ml_config;
	const struct rte_memzone *mz;
	struct tvm_ml_dev *ml_dev;
	uint32_t model_id;
	uint64_t mz_size;
	int ret = 0;

	if (dev == NULL || conf == NULL)
		return -EINVAL;

	/* Update device reference in firmware and set handles */
	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;
	ml_config->ml_dev = ml_dev;
	ml_config->max_models_created = ML_TVM_MAX_MODELS;

	/* Reserve memzone for configuration data and update ml_config */
	mz_size = RTE_ALIGN_CEIL(sizeof(struct tvm_ml_model *) *
					 ML_TVM_MAX_MODELS,
				 ML_TVM_ALIGN_SIZE);
	mz = rte_memzone_reserve_aligned(ML_CONFIG_MEMZONE_NAME, mz_size, 0, 0,
					 ML_TVM_ALIGN_SIZE);
	if (mz == NULL) {
		MLDEV_LOG_ERR("rte_memzone_reserve failed : %s",
			      ML_CONFIG_MEMZONE_NAME);
		goto err_exit;
	}
	ml_config->ml_models = mz->addr;

	for (model_id = 0; model_id < ml_config->max_models_created; model_id++)
		ml_config->ml_models[model_id] = NULL;

	dev->inference_sync = tvm_ml_inference_sync;

	ml_config->active = true;

	return 0;

err_exit:
	/* Clear resources */
	mz = rte_memzone_lookup(ML_CONFIG_MEMZONE_NAME);
	if (mz != NULL)
		rte_memzone_free(mz);

	return ret;
}

int
tvm_ml_dev_close(struct rte_mldev *dev)
{
	struct tvm_ml_config *ml_config;
	const struct rte_memzone *mz;
	struct tvm_ml_dev *ml_dev;
	int ret = 0;

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;

	/* Set config inactive */
	ml_config->active = false;

	/* Clear resources */
	mz = rte_memzone_lookup(ML_CONFIG_MEMZONE_NAME);
	if (mz != NULL)
		rte_memzone_free(mz);

	return ret;
}

int
tvm_ml_dev_start(struct rte_mldev *dev)
{
	struct tvm_ml_dev *ml_dev;

	RTE_SET_USED(ml_dev);

	ml_dev = dev->data->dev_private;

	return 0;
}

void
tvm_ml_dev_stop(struct rte_mldev *dev)
{
	struct tvm_ml_dev *ml_dev;

	RTE_SET_USED(ml_dev);

	ml_dev = dev->data->dev_private;
}

static int
tvm_ml_dev_info_get(struct rte_mldev *dev, struct rte_mldev_info *info)
{
	RTE_SET_USED(dev);

	if (info == NULL)
		return -EINVAL;

	info->max_nb_queue_pairs = ML_TVM_QP_PER_DEVICE;
	info->driver_id = tvm_mldev_driver_id;
	info->driver_name = dev->device->driver->name;
	info->device = dev->device;

	return 0;
}

int
tvm_ml_model_create(struct rte_mldev *dev, struct rte_ml_model *model,
		    uint8_t *model_id)
{
	struct tvm_ml_model_metadata *model_metadata;
	struct tvm_ml_model_metadata metadata;
	struct tvm_ml_config *ml_config;
	struct tvm_ml_model *ml_model;
	struct tvm_ml_dev *ml_dev;

	const struct rte_memzone *mz;
	char str[PATH_MAX] = {0};
	uint64_t mz_size;
	uint8_t *buffer;
	uint8_t idx;

	size_t model_info_size;
	size_t model_data_size;

	RTE_ASSERT(model != NULL);
	RTE_ASSERT(model_id != NULL);

	buffer = model->model_buffer;
	memcpy(&metadata, buffer, sizeof(struct tvm_ml_model_metadata));
	if (tvm_ml_metadata_check(&metadata) != 0)
		return -1;

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;

	/* Assign model ID */
	for (idx = 0; idx < ml_config->max_models_created; idx++) {
		if (ml_config->ml_models[idx] == NULL)
			break;
	}

	if (idx >= ml_config->max_models_created) {
		MLDEV_LOG_ERR("No slots available to load new model");
		return -1;
	}

	/* Get MZ size */
	model_info_size = sizeof(struct rte_ml_model_info) +
			  sizeof(struct rte_ml_input_info) +
			  sizeof(struct rte_ml_output_info);
	model_info_size = RTE_ALIGN_CEIL(model_info_size, ML_TVM_ALIGN_SIZE);

	model_data_size = model->model_size;
	model_data_size = RTE_ALIGN_CEIL(model_data_size, ML_TVM_ALIGN_SIZE);
	mz_size =
		RTE_ALIGN_CEIL(sizeof(struct tvm_ml_model), ML_TVM_ALIGN_SIZE) +
		model_info_size + 2 * model_data_size;

	/* Allocate memzone for model object and model data */
	snprintf(str, PATH_MAX, "%s_%d", ML_MODEL_MEMZONE_NAME, idx);
	mz = rte_memzone_reserve_aligned(str, mz_size, 0, 0, ML_TVM_ALIGN_SIZE);
	if (!mz) {
		MLDEV_LOG_ERR("rte_memzone_reserve failed : %s", str);
		goto err_exit;
	}

	ml_model = mz->addr;
	ml_model->ml_config = ml_config;
	ml_model->model_id = idx;
	ml_model->model_info = RTE_PTR_ADD(
		mz->addr,
		RTE_ALIGN_CEIL(sizeof(struct tvm_ml_model), ML_TVM_ALIGN_SIZE));
	if (model->model_name) {
		rte_strlcpy(ml_model->name, model->model_name,
			    sizeof(ml_model->name));
		MLDEV_LOG_DEBUG("ml_model->name = %s", ml_model->name);
	}

	model_metadata = &ml_model->model_metadata;
	memcpy(model_metadata, &metadata, sizeof(struct tvm_ml_model_metadata));

	tvm_ml_model_info_set(ml_model);

	/* Initialize model lock and state */
	ml_model->state = TVM_ML_MODEL_STATE_CREATED;
	ml_config->ml_models[idx] = ml_model;

	*model_id = idx;
	return 0;

err_exit:
	snprintf(str, PATH_MAX, "%s_%d", ML_MODEL_MEMZONE_NAME, idx);
	mz = rte_memzone_lookup(str);
	if (mz)
		rte_memzone_free(mz);

	return -1;
}

int
tvm_ml_model_destroy(struct rte_mldev *dev, uint8_t model_id)
{
	struct tvm_ml_config *ml_config;
	struct tvm_ml_dev *ml_dev;
	struct tvm_ml_model *ml_model;
	char str[PATH_MAX] = {0};

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;
	ml_model = ml_config->ml_models[model_id];

	if (ml_model->state != TVM_ML_MODEL_STATE_CREATED) {
		MLDEV_LOG_ERR("Cannot destroy. Model in use.");
		return -EBUSY;
	}

	ml_config->ml_models[model_id] = NULL;

	snprintf(str, PATH_MAX, "%s_%d", ML_MODEL_MEMZONE_NAME, model_id);
	return rte_memzone_free(rte_memzone_lookup(str));
}

int
tvm_ml_model_load(struct rte_mldev *dev, uint8_t model_id)
{
	struct tvm_ml_config *ml_config;
	struct tvm_ml_model *ml_model;
	struct tvm_ml_dev *ml_dev;
	int ret = 0;

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;
	ml_model = ml_config->ml_models[model_id];

	if (ml_model->state == TVM_ML_MODEL_STATE_CREATED) {
		ml_model->state = TVM_ML_MODEL_STATE_LOADED;
		ret = 0;
	} else if (ml_model->state == TVM_ML_MODEL_STATE_UNKNOWN) {
		ret = -1;
	}

	return ret;
}

int
tvm_ml_model_unload(struct rte_mldev *dev, uint8_t model_id)
{
	struct tvm_ml_config *ml_config;
	struct tvm_ml_model *ml_model;
	struct tvm_ml_dev *ml_dev;
	int ret = 0;

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;
	ml_model = ml_config->ml_models[model_id];

	if (ml_model->state == TVM_ML_MODEL_STATE_LOADED) {
		ml_model->state = TVM_ML_MODEL_STATE_CREATED;
		ret = 0;
	} else if (ml_model->state == TVM_ML_MODEL_STATE_UNKNOWN) {
		ret = -1;
	}

	return ret;
}

static int
tvm_ml_model_info_get(struct rte_mldev *dev, uint8_t model_id,
		      struct rte_ml_model_info *info)
{
	struct rte_ml_model_info *model_info;
	struct tvm_ml_config *ml_config;
	struct tvm_ml_model *ml_model;
	struct tvm_ml_dev *ml_dev;

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;
	ml_model = ml_config->ml_models[model_id];

	model_info = (void *)(ml_model->model_info);
	memcpy(info->name, model_info->name, sizeof(info->name));
	memcpy(info->version, model_info->version, sizeof(info->version));
	info->index = model_info->index;
	info->num_inputs = model_info->num_inputs;
	info->total_input_size = model_info->total_input_size;
	info->num_outputs = model_info->num_outputs;
	info->total_output_size = model_info->total_output_size;

	if (info->input_info != NULL)
		memcpy(info->input_info, model_info->input_info,
		       model_info->num_inputs *
			       sizeof(struct rte_ml_input_info));

	if (info->output_info != NULL)
		memcpy(info->output_info, model_info->output_info,
		       model_info->num_outputs *
			       sizeof(struct rte_ml_output_info));

	return 0;
}

int
tvm_ml_inference_sync(struct rte_mldev *dev, struct rte_ml_op *op)
{
	struct tvm_ml_config *ml_config;
	struct tvm_ml_model *ml_model;
	struct tvm_ml_dev *ml_dev;
	int ret = 0;

	ml_dev = dev->data->dev_private;
	ml_config = &ml_dev->ml_config;
	ml_model = ml_config->ml_models[op->model_id];

	if (ml_model->state != TVM_ML_MODEL_STATE_LOADED)
		return -EINVAL;

	op->result.success = true;
	op->result.error_code = 0;

	return ret;
}

struct rte_mldev_ops tvm_ml_ops = {
	/* Device control ops */
	.dev_configure = tvm_ml_dev_configure,
	.dev_close = tvm_ml_dev_close,
	.dev_start = tvm_ml_dev_start,
	.dev_stop = tvm_ml_dev_stop,
	.dev_info_get = tvm_ml_dev_info_get,

	/* ML model handling ops */
	.ml_model_create = tvm_ml_model_create,
	.ml_model_destroy = tvm_ml_model_destroy,
	.ml_model_load = tvm_ml_model_load,
	.ml_model_unload = tvm_ml_model_unload,
	.ml_model_info_get = tvm_ml_model_info_get,
};
