/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Marvell.
 */

#include <mldev_pmd.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_mldev.h>
#include <rte_pci.h>

#include "cn10k_mldev.h"
#include "cn10k_mldev_ops.h"
#include "cnxk_mldev.h"

#include "roc_api.h"

uint8_t cn10k_mldev_driver_id;

static int
cn10k_ml_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		   struct rte_pci_device *pci_dev)
{
	char name[RTE_MLDEV_NAME_LEN];
	struct cnxk_ml_dev *ml_dev;
	struct rte_mldev *mldev;
	int rc;

	struct rte_mldev_pmd_init_params init_params = {
		.name = "",
		.socket_id = rte_socket_id(),
		.private_data_size = sizeof(struct cnxk_ml_dev),
		.max_nb_queue_pairs = RTE_MLDEV_PMD_DEFAULT_MAX_NB_QUEUE_PAIRS};

	rc = roc_plt_init();
	if (rc < 0) {
		plt_err("Failed to initialize platform model");
		return rc;
	}

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	mldev = rte_mldev_pmd_create(name, &pci_dev->device, &init_params);
	if (mldev == NULL) {
		rc = -ENODEV;
		goto exit;
	}

	/* Get private data space allocated */
	ml_dev = mldev->data->dev_private;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ml_dev->roc.pci_dev = pci_dev;

		rc = cnxk_mldev_parse_devargs(mldev->device->devargs, ml_dev);
		if (rc) {
			plt_err("Failed to parse devargs rc=%d", rc);
			goto pmd_destroy;
		}

		rc = roc_ml_dev_init(&ml_dev->roc);
		if (rc) {
			plt_err("Failed to initialize roc ml rc = %d", rc);
			goto pmd_destroy;
		}
	}

	mldev->dev_ops = &cn10k_ml_ops;
	mldev->driver_id = cn10k_mldev_driver_id;

	rte_mldev_pmd_probing_finish(mldev);

	return 0;

pmd_destroy:
	rte_mldev_pmd_destroy(mldev);

exit:
	plt_err("Could not create device (vendor_id: 0x%x device_id: 0x%x)",
		pci_dev->id.vendor_id, pci_dev->id.device_id);
	return rc;
}

static int
cn10k_ml_pci_remove(struct rte_pci_device *pci_dev)
{
	char name[RTE_MLDEV_NAME_LEN];
	struct cnxk_ml_dev *ml_dev;
	struct rte_mldev *mldev;
	int rc;

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	mldev = rte_mldev_pmd_get_named_dev(name);
	if (mldev == NULL)
		return -ENODEV;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ml_dev = mldev->data->dev_private;
		rc = roc_ml_dev_fini(&ml_dev->roc);
		if (rc)
			return rc;
	}

	return rte_mldev_pmd_destroy(mldev);
}

static struct rte_pci_id pci_id_ml_table[] = {
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_CN10K_ML_PF)},
	/* sentinel */
	{},
};

static struct rte_pci_driver cn10k_mldev_pmd = {
	.id_table = pci_id_ml_table,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_NEED_IOVA_AS_VA,
	.probe = cn10k_ml_pci_probe,
	.remove = cn10k_ml_pci_remove,
};

static struct mldev_driver cn10k_mldev_drv;

RTE_PMD_REGISTER_PCI(MLDEV_NAME_CN10K_PMD, cn10k_mldev_pmd);
RTE_PMD_REGISTER_PCI_TABLE(MLDEV_NAME_CN10K_PMD, pci_id_ml_table);
RTE_PMD_REGISTER_KMOD_DEP(MLDEV_NAME_CN10K_PMD, "vfio-pci");
RTE_PMD_REGISTER_ML_DRIVER(cn10k_mldev_drv, cn10k_mldev_pmd.driver,
			   cn10k_mldev_driver_id);
