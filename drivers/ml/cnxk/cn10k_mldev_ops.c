/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <mldev_pmd.h>

#include "cn10k_mldev.h"
#include "cn10k_mldev_ops.h"
#include "cnxk_mldev.h"

#include "roc_api.h"

int
cn10k_ml_dev_config(struct rte_mldev *dev,
		    __rte_unused struct rte_mldev_config *conf)
{
	__rte_unused struct cnxk_ml_dev *cnxk_dev = dev->data->dev_private;
	__rte_unused struct roc_ml *roc_ml = &cnxk_dev->ml;

	return 0;
}

int
cn10k_ml_dev_close(struct rte_mldev *dev)
{
	__rte_unused struct cnxk_ml_dev *cnxk_dev = dev->data->dev_private;
	__rte_unused struct roc_ml *roc_ml = &cnxk_dev->ml;

	return 0;
}

struct rte_mldev_ops cn10k_ml_ops = {
	/* Device control ops */
	.dev_configure = cn10k_ml_dev_config,
	.dev_close = cn10k_ml_dev_close,
};
