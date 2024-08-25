/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef __CN20K_EVENTDEV_H__
#define __CN20K_EVENTDEV_H__

#define CN20K_SSO_DEFAULT_STASH_OFFSET -1
#define CN20K_SSO_DEFAULT_STASH_LENGTH 2

struct cn20k_sso_hws {
	uint64_t base;
	uint32_t gw_wdata;
	uint64_t gw_rdata;
	uint8_t swtag_req;
	uint8_t hws_id;
	/* Add Work Fastpath data */
	int64_t *fc_mem __rte_cache_aligned;
	int64_t *fc_cache_space;
	uintptr_t aw_lmt;
	uintptr_t grp_base;
	int32_t xaq_lmt;
} __rte_cache_aligned;

#endif /* __CN20K_EVENTDEV_H__ */
