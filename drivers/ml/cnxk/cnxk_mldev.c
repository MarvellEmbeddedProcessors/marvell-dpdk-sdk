/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <rte_devargs.h>
#include <rte_kvargs.h>

#include "cnxk_mldev.h"

#define CNXK_ML_FIRMWARE      "ml_firmware"
#define CNXK_ML_FIRMWARE_PATH "/lib/firmware/mlip-fw.bin"

static int
parse_mldev_firmware(const char *key __rte_unused, const char *value,
		     void *extra_args)
{
	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*(char **)extra_args = strdup(value);

	if (!*(char **)extra_args)
		return -ENOMEM;

	return 0;
}

int
cnxk_mldev_parse_devargs(struct rte_devargs *devargs,
			 struct cnxk_ml_dev *ml_dev)
{
	struct rte_kvargs *kvlist;
	char *firmware = NULL;
	int rc;

	if (devargs == NULL)
		goto null_devargs;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		goto exit;

	rc = rte_kvargs_process(kvlist, CNXK_ML_FIRMWARE, &parse_mldev_firmware,
				&firmware);
	if (rc < 0) {
		rte_kvargs_free(kvlist);
		goto exit;
	}
	rte_kvargs_free(kvlist);

null_devargs:
	if (firmware == NULL) {
		rte_strscpy(ml_dev->ml_fw.filepath, CNXK_ML_FIRMWARE_PATH,
			    sizeof(ml_dev->ml_fw.filepath));
	} else {
		if (rte_strscpy(ml_dev->ml_fw.filepath, firmware,
				sizeof(ml_dev->ml_fw.filepath)) < 0) {
			plt_err("%s : firmware path too long", firmware);
			free(firmware);
		}
	}
	plt_ml_dbg("ML firmware = %s", ml_dev->ml_fw.filepath);

	return 0;

exit:
	return -EINVAL;
}

RTE_PMD_REGISTER_PARAM_STRING(ml_cnxk, CNXK_ML_FIRMWARE "=<path>");
