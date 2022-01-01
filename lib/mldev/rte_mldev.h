/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell
 */

#ifndef _RTE_MLDEV_H
#define _RTE_MLDEV_H

/**
 * @file rte_mldev.h
 *
 * Machine Learning inference API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_log.h>

/* Logging Macros */

#define MLDEV_LOG_ERR(...)                                                     \
	RTE_LOG(ERR, MLDEV,                                                    \
		RTE_FMT("%s() line %u: " RTE_FMT_HEAD(__VA_ARGS__, ) "\n",     \
			__func__, __LINE__, RTE_FMT_TAIL(__VA_ARGS__, )))

#define MLDEV_LOG_INFO(...)                                                    \
	RTE_LOG(INFO, MLDEV,                                                   \
		RTE_FMT(RTE_FMT_HEAD(__VA_ARGS__, ) "\n",                      \
			RTE_FMT_TAIL(__VA_ARGS__, )))

#define MLDEV_LOG_DEBUG(...)                                                   \
	RTE_LOG(DEBUG, MLDEV,                                                  \
		RTE_FMT("%s() line %u: " RTE_FMT_HEAD(__VA_ARGS__, ) "\n",     \
			__func__, __LINE__, RTE_FMT_TAIL(__VA_ARGS__, )))

#define MLDEV_PMD_TRACE(...)                                                   \
	RTE_LOG(DEBUG, MLDEV,                                                  \
		RTE_FMT("[%s] %s: " RTE_FMT_HEAD(__VA_ARGS__, ) "\n", dev,     \
			__func__, RTE_FMT_TAIL(__VA_ARGS__, )))

#define RTE_MLDEV_DETACHED (0)
#define RTE_MLDEV_ATTACHED (1)

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* RTE_MLDEV_H */
