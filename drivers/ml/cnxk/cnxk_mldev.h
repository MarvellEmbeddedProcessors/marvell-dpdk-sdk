/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell
 */
#ifndef _CNXK_MLDEV_H_
#define _CNXK_MLDEV_H_

#include "roc_ml.h"

#define ML_FIRMWARE_STRLEN 512

/**
 * Memory resources
 */
struct cnxk_ml_mem {
	/** Memory for BAR0 */
	struct rte_mem_resource res0;

	/** Memory for BAR4 */
	struct rte_mem_resource res4;
};

/**
 * Device private data
 */
struct cnxk_ml_dev {
	/** Ml device ROC */
	struct roc_ml ml;

	/** ML device memory resources */
	struct cnxk_ml_mem mem;

	/** ML firmware path */
	char firmware[ML_FIRMWARE_STRLEN];
};

int cnxk_mldev_parse_devargs(struct rte_devargs *devargs,
			     struct cnxk_ml_dev *cnxk_dev);

#endif
