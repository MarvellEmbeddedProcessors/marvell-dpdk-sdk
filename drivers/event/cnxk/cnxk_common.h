/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#ifndef __CNXK_COMMON_H__
#define __CNXK_COMMON_H__

#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

static uint32_t
cnxk_sso_hws_prf_wdata(struct cnxk_sso_evdev *dev)
{
	uint32_t wdata = 1;

	if (dev->deq_tmo_ns)
		wdata |= BIT(16);

	switch (dev->gw_mode) {
	case CNXK_GW_MODE_NONE:
	default:
		break;
	case CNXK_GW_MODE_PREF:
		wdata |= BIT(19);
		break;
	case CNXK_GW_MODE_PREF_WFE:
		wdata |= BIT(20) | BIT(19);
		break;
	}

	return wdata;
}

#endif /* __CNXK_COMMON_H__ */
