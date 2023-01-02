/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _OTX_EP_IRQ_H_
#define _OTX_EP_IRQ_H_

int otx_ep_register_irq(struct otx_ep_device *otx_ep,
			rte_intr_callback_fn cb, void *data, unsigned int vec);
int otx_ep_unregister_irq(struct otx_ep_device *otx_ep,
			  rte_intr_callback_fn cb, void *data);
#endif
