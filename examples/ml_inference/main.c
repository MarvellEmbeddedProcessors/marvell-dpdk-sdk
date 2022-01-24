/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#include <getopt.h>
#include <stdio.h>

#include <rte_eal.h>
#include <rte_mldev.h>

static void
print_usage(const char *prog_name)
{
	printf("***Usage: %s [EAL params]\n", prog_name);
	printf("\n");
}

static int
parse_args(int argc, char **argv)
{
	int opt, option_index;

	static struct option lgopts[] = {{"help", 0, 0, 'h'}, {NULL, 0, 0, 0}};

	while ((opt = getopt_long(argc, argv, "h", lgopts, &option_index)) !=
	       EOF)
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			printf("ERROR: Unknown option: -%c\n", opt);
			return -1;
		}

	return 0;
}

int
main(int argc, char **argv)
{
	struct rte_mldev_config ml_config;
	uint8_t dev_count;
	uint8_t dev_id;
	int ret;

	/* Init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return 1;
	argc -= ret;
	argv += ret;

	/* Parse application arguments (after the EAL args) */
	ret = parse_args(argc, argv);
	if (ret < 0) {
		print_usage(argv[0]);
		return 1;
	}

	/* Get total number of ML devices initialized */
	dev_count = rte_mldev_count();
	if (dev_count <= 0) {
		printf("No ML devices found. exit.\n");
		return -ENODEV;
	}

	/* Configure ML devices, use only dev_id = 0 */
	dev_id = 0;
	ml_config.socket_id = rte_mldev_socket_id(dev_id);
	if (rte_mldev_configure(dev_id, &ml_config) != 0) {
		printf("Device configuration failed, dev_id = %d\n", dev_id);
		goto close_dev;
	}

	/* Start device */
	rte_mldev_start(dev_id);

	/* Stop device */
	rte_mldev_stop(dev_id);

close_dev:
	/* Close ML device */
	rte_mldev_close(dev_id);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
