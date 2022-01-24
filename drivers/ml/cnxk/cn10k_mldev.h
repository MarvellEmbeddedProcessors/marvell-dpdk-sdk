/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _CN10K_MLDEV_H_
#define _CN10K_MLDEV_H_

/* Marvell OCTEON CN10K ML PMD device name */
#define MLDEV_NAME_CN10K_PMD ml_cn10k

/* Poll mode job control */
#define ML_CN10K_POLL_JOB_START	 0
#define ML_CN10K_POLL_JOB_FINISH 1

/* Device macros */
#define ML_CN10K_ALIGN_SIZE 128
#define ML_CN10K_MAX_MODELS 16

#endif /* _CN10K_MLDEV_H_ */
