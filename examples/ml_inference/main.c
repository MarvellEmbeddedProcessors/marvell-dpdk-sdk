/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#include <getopt.h>
#include <stdio.h>

#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_mldev.h>

/* ML constants */
#define ML_MAX_MODELS 32
#define ML_ALIGN_SIZE 128

/* ML global variables */
static uint16_t g_models_counter;
static bool g_interleave;

/* ML args structure */
typedef struct {
	char models[ML_MAX_MODELS][PATH_MAX];
} ml_opts_t;

/* ML model variables structure */
typedef struct {
	uint8_t model_id;
} ml_model_vars_t;

static ml_opts_t ml_opts;
static ml_model_vars_t ml_models[ML_MAX_MODELS];

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

	static struct option lgopts[] = {
		{"model", required_argument, NULL, 'm'},
		{"interleave", no_argument, NULL, 'I'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}};

	/* Set defaults */
	g_interleave = false;

	while ((opt = getopt_long(argc, argv, "m:Ih", lgopts, &option_index)) !=
	       EOF)
		switch (opt) {
		case 'm':
			if (g_models_counter >= ML_MAX_MODELS) {
				fprintf(stderr,
					"Models Limit Exceeded, MAX %d\n",
					ML_MAX_MODELS);
				return -1;
			}
			strncpy(ml_opts.models[g_models_counter++], optarg,
				PATH_MAX - 1);
			break;
		case 'I':
			g_interleave = true;
			break;
		case '?':
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
	struct rte_mldev_model ml_model;
	const struct rte_memzone *mz;
	char str[PATH_MAX] = {0};
	uint8_t dev_count;
	uint8_t dev_id;
	uint16_t idx;
	uint16_t i;
	FILE *fp;
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
	ret = 0;
	ml_config.socket_id = rte_mldev_socket_id(dev_id);
	if (rte_mldev_configure(dev_id, &ml_config) != 0) {
		printf("Device configuration failed, dev_id = %d\n", dev_id);
		ret = -1;
		goto exit_cleanup;
	}

	/* Start device */
	if (rte_mldev_start(dev_id) != 0) {
		fprintf(stderr, "Device start failed, dev_id = %d\n", dev_id);
		ret = -1;
		goto error_close;
	};

	/* Create models */
	for (idx = 0; idx < g_models_counter; idx++) {
		fp = fopen(ml_opts.models[idx], "r+");
		if (fp == NULL) {
			fprintf(stderr, "Failed to open file : %s\n",
				ml_opts.models[idx]);
			goto error_destroy;
		}
		fseek(fp, 0, SEEK_END);
		ml_model.model_size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		snprintf(str, PATH_MAX, "model_%d", idx);
		ml_model.model_name = str;

		mz = rte_memzone_reserve_aligned(
			ml_model.model_name, ml_model.model_size,
			rte_mldev_socket_id(dev_id), 0, ML_ALIGN_SIZE);
		if (mz == NULL) {
			fprintf(stderr, "Failed to create memzone: %s\n",
				ml_model.model_name);
			goto error_destroy;
		}
		ml_model.model_buffer = mz->addr;

		fread(ml_model.model_buffer, 1, ml_model.model_size, fp);
		fclose(fp);

		if (rte_mldev_model_create(dev_id, &ml_model,
					   &ml_models[idx].model_id) != 0) {
			fprintf(stderr, "Error creating model : %s\n",
				ml_model.model_name);
			goto error_destroy;
		}
	}

	if (g_interleave) {
		for (idx = 0; idx < g_models_counter; idx++) {
			if (rte_mldev_model_load(
				    dev_id, ml_models[idx].model_id) != 0) {
				fprintf(stderr, "Error loading model : %s\n",
					ml_model.model_name);
				goto error_unload;
			}
		}

error_unload:
		for (i = 0; i < idx; i++) {
			if (rte_mldev_model_unload(
				    dev_id, ml_models[i].model_id) != 0) {
				fprintf(stderr, "Error unloading model : %s\n",
					ml_model.model_name);
				goto error_destroy;
			}
		}
	} else {
		for (idx = 0; idx < g_models_counter; idx++) {
			if (rte_mldev_model_load(
				    dev_id, ml_models[idx].model_id) != 0) {
				fprintf(stderr, "Error loading model : %s\n",
					ml_model.model_name);
				goto error_destroy;
			}

			if (rte_mldev_model_unload(
				    dev_id, ml_models[idx].model_id) != 0) {
				fprintf(stderr, "Error unloading model : %s\n",
					ml_model.model_name);
				goto error_destroy;
			}
		}
	}

error_destroy:
	for (i = 0; i < idx; i++)
		rte_mldev_model_destroy(dev_id, ml_models[i].model_id);

	/* Stop device */
	rte_mldev_stop(dev_id);

error_close:
	/* Close ML device */
	rte_mldev_close(dev_id);

exit_cleanup:
	/* clean up the EAL */
	rte_eal_cleanup();

	return ret;
}
