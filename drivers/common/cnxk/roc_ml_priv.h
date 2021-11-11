/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _ROC_ML_PRIV_H_
#define _ROC_ML_PRIV_H_

#include "roc_api.h"

struct ml {
	struct plt_pci_device *pci_dev;
	struct dev dev;
	uint8_t *ml_reg_addr;
} __plt_cache_aligned;

static inline struct ml *
roc_ml_to_ml_priv(struct roc_ml *roc_ml)
{
	return (struct ml *)&roc_ml->reserved[0];
}

#endif /* _ROC_ML_PRIV_H_ */
