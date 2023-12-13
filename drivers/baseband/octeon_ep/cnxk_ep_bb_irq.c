/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <rte_interrupts.h>
#include <eal_interrupts.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>

#include "cnxk_ep_bb_common.h"

#define MAX_INTR_VEC_ID RTE_MAX_RXTX_INTR_VEC_ID
#define MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
			      sizeof(int) * (MAX_INTR_VEC_ID))
static int
cnxk_ep_bb_irq_get_info(struct rte_intr_handle *intr_handle)
{
	struct vfio_irq_info irq = { .argsz = sizeof(irq) };
	int rc;

	irq.index = VFIO_PCI_MSIX_IRQ_INDEX;

	rc = ioctl(intr_handle->dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
	if (rc < 0) {
		cnxk_ep_bb_err("Failed to get IRQ info rc=%d errno=%d", rc, errno);
		return rc;
	}

	cnxk_ep_bb_dbg("Flags=0x%x index=0x%x count=0x%x max_intr_vec_id=0x%x",
			irq.flags, irq.index, irq.count, MAX_INTR_VEC_ID);

	if (irq.count > MAX_INTR_VEC_ID) {
		cnxk_ep_bb_err("HW max=%d > MAX_INTR_VEC_ID: %d",
				intr_handle->max_intr, MAX_INTR_VEC_ID);
		intr_handle->max_intr = MAX_INTR_VEC_ID;
	} else {
		intr_handle->max_intr = irq.count;
	}
	cnxk_ep_bb_info("Flags=0x%x index=0x%x count=0x%x max_intr_vec_id=0x%x intr_handle->max_intr+0x%x",
			irq.flags, irq.index, irq.count, MAX_INTR_VEC_ID, intr_handle->max_intr);

	return 0;
}

static int
cnxk_ep_bb_irq_init(struct rte_intr_handle *intr_handle)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int32_t *fd_ptr;
	int len, rc;
	uint32_t i;

	if (intr_handle->max_intr > MAX_INTR_VEC_ID) {
		cnxk_ep_bb_err("Max_intr=%d greater than MAX_INTR_VEC_ID=%d",
				intr_handle->max_intr, MAX_INTR_VEC_ID);
		return -ERANGE;
	}

	len = sizeof(struct vfio_irq_set) +
		sizeof(int32_t) * intr_handle->max_intr;

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->start = 0;
	irq_set->count = intr_handle->max_intr;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;

	fd_ptr = (int32_t *)&irq_set->data[0];
	for (i = 0; i < irq_set->count; i++)
		fd_ptr[i] = -1;

	rc = ioctl(intr_handle->dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (rc)
		cnxk_ep_bb_err("Failed to set irqs vector rc=%d", rc);

	return rc;
}

static int
cnxk_ep_bb_irq_config(struct rte_intr_handle *intr_handle, unsigned int vec)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int32_t *fd_ptr;
	int len, rc;

	if (vec > intr_handle->max_intr) {
		cnxk_ep_bb_err("vector=%d greater than max_intr=%d", vec,
				intr_handle->max_intr);
		return -EINVAL;
	}

	len = sizeof(struct vfio_irq_set) + sizeof(int32_t);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;

	irq_set->start = vec;
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;

	/* Use vec fd to set interrupt vectors */
	fd_ptr = (int32_t *)&irq_set->data[0];
	fd_ptr[0] = intr_handle->efds[vec];

	rc = ioctl(intr_handle->dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (rc)
		cnxk_ep_bb_err("Failed to set_irqs vector=0x%x rc=%d", vec, rc);

	return rc;
}

int
cnxk_ep_bb_register_irq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
			rte_intr_callback_fn cb, void *data, unsigned int vec)
{
	struct rte_pci_device *pci_dev      = cnxk_ep_bb_vf->pdev;
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	struct rte_intr_handle tmp_handle;
	int rc = -1;

	/* If no max_intr read from VFIO */
	if (intr_handle->max_intr == 0) {
		cnxk_ep_bb_irq_get_info(intr_handle);
		cnxk_ep_bb_irq_init(intr_handle);
	}

	if (vec > intr_handle->max_intr) {
		cnxk_ep_bb_err("Vector=%d greater than max_intr=%d", vec,
				intr_handle->max_intr);
		return -EINVAL;
	}

	tmp_handle = *intr_handle;
	/* Create new eventfd for interrupt vector */
	tmp_handle.fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (tmp_handle.fd == -1)
		return -ENODEV;

	/* Register vector interrupt callback */
	rc = rte_intr_callback_register(&tmp_handle, cb, data);
	if (rc) {
		cnxk_ep_bb_err("Failed to register vector:0x%x irq callback.", vec);
		return rc;
	}

	intr_handle->efds[vec] = tmp_handle.fd;
	intr_handle->nb_efd = (vec > intr_handle->nb_efd) ?
			vec : intr_handle->nb_efd;
	if ((intr_handle->nb_efd + 1) > intr_handle->max_intr)
		intr_handle->max_intr = intr_handle->nb_efd + 1;
	cnxk_ep_bb_info("Enable vector:0x%x for vfio (efds: %d, max:%d) type: %x dev_fd: %x",
			vec, intr_handle->nb_efd, intr_handle->max_intr, intr_handle->type,
			intr_handle->dev_fd);

	/* Enable MSIX vectors to VFIO */
	return cnxk_ep_bb_irq_config(intr_handle, vec);
}

int
cnxk_ep_bb_unregister_irq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
			rte_intr_callback_fn cb, void *data)
{
	struct rte_pci_device *pci_dev = cnxk_ep_bb_vf->pdev;
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	int rc = -1;

	rc = rte_intr_callback_unregister(intr_handle, cb, data);
	if (rc) {
		cnxk_ep_bb_err("Failed to unregister irq callback.\n");
		return rc;
	}
	return 0;
}
