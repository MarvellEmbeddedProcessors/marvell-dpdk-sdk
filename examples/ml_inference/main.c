/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#include <getopt.h>
#include <stdio.h>

#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_ml.h>
#include <rte_mldev.h>

/* ML constants */
#define ML_MAX_MODELS 32
#define ML_ALIGN_SIZE 128
#define ML_QUEUE_SIZE 64

/* ML global variables */
static uint16_t g_models_counter;

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
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}};

	while ((opt = getopt_long(argc, argv, "m:h", lgopts, &option_index)) !=
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
	struct rte_mldev_qp_conf qp_conf;
	struct rte_mldev_info dev_info;
	struct rte_ml_model ml_model;
	const struct rte_memzone *mz;
	char str[PATH_MAX] = {0};
	uint8_t dev_count;
	uint8_t dev_id;
	uint16_t idx;
	int ret = 0;
	int err = 0;
	FILE *fp;

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
		fprintf(stderr, "No ML devices found. exit.\n");
		return -ENODEV;
	}

	/* Get device info */
	dev_id = 0;
	ret = rte_mldev_info_get(dev_id, &dev_info);
	if (ret != 0) {
		fprintf(stderr, "Failed to get device info, dev_id = %d\n",
			dev_id);
		goto exit_cleanup;
	}

	/* Configure ML devices, use only dev_id = 0 */
	ml_config.socket_id = rte_mldev_socket_id(dev_id);
	ml_config.nb_queue_pairs = dev_info.max_nb_queue_pairs;
	ret = rte_mldev_configure(dev_id, &ml_config);
	if (ret != 0) {
		fprintf(stderr, "Device configuration failed, dev_id = %d\n",
			dev_id);
		goto exit_cleanup;
	}

	/* setup queue pairs */
	qp_conf.nb_desc = ML_QUEUE_SIZE;
	if (rte_mldev_queue_pair_setup(dev_id, 0, &qp_conf,
				       rte_mldev_socket_id(dev_id)) != 0) {
		fprintf(stderr, "Queue-pair setup failed, dev_id = %d\n",
			dev_id);
		ret = -1;
		goto error_close;
	}

	/* Start device */
	ret = rte_mldev_start(dev_id);
	if (ret != 0) {
		fprintf(stderr, "Device start failed, dev_id = %d\n", dev_id);
		goto error_close;
	};

	/* Create models */
	for (idx = 0; idx < g_models_counter; idx++) {
		fp = fopen(ml_opts.models[idx], "r+");
		if (fp == NULL) {
			fprintf(stderr, "Failed to open file : %s\n",
				ml_opts.models[idx]);
			goto error_stop;
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
			fclose(fp);
			goto error_stop;
		}
		ml_model.model_buffer = mz->addr;
		fread(ml_model.model_buffer, 1, ml_model.model_size, fp);
		fclose(fp);

		ret = rte_ml_model_create(dev_id, &ml_model,
					  &ml_models[idx].model_id);
		if (ret != 0) {
			fprintf(stderr, "Error creating model : %s\n",
				ml_model.model_name);
			goto error_stop;
		}

		ret = rte_ml_model_load(dev_id, ml_models[idx].model_id);
		if (ret != 0) {
			fprintf(stderr, "Error loading model : %s\n",
				ml_model.model_name);
			goto error_model_destroy;
		}

		ret = rte_ml_model_unload(dev_id, ml_models[idx].model_id);
		if (ret != 0) {
			fprintf(stderr, "Error unloading model : %s\n",
				ml_model.model_name);
			goto error_model_destroy;
		}

error_model_destroy:
		err = rte_ml_model_destroy(dev_id, ml_models[idx].model_id);
		if (err != 0 && ret == 0)
			ret = err;

		if (ret != 0)
			goto error_stop;
	}

error_stop:
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
