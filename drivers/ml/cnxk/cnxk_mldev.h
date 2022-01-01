/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell
 */
#ifndef _CNXK_MLDEV_H_
#define _CNXK_MLDEV_H_

#include "roc_ml.h"

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
};

#endif
