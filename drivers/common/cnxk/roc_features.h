/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _ROC_FEATURES_H_
#define _ROC_FEATURES_H_

static inline bool
roc_feature_sso_has_stash(void)
{
	return roc_model_is_cn10kb() ? true : false;
}

#endif
