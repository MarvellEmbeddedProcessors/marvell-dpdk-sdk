/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _CN10K_MLDEV_H_
#define _CN10K_MLDEV_H_

/* Marvell OCTEON CN10K ML PMD device name */
#define MLDEV_NAME_CN10K_PMD ml_cn10k

/* Poll mode job control */
#define ML_CN10K_POLL_JOB_START	 0
#define ML_CN10K_POLL_JOB_FINISH 1

/* Device macros */
#define ML_CN10K_ALIGN_SIZE 128
#define ML_CN10K_MAX_MODELS 16

/* Page size in bytes. */
#define ML_CN10K_OCM_PAGESIZE 0x4000

/* Number of OCM tiles. */
#define ML_CN10K_OCM_NUMTILES 0x8

/* OCM in bytes, per tile. */
#define ML_CN10K_OCM_TILESIZE 0x100000

/* OCM pages, per tile. */
#define ML_CN10K_OCM_NUMPAGES (ML_CN10K_OCM_TILESIZE / ML_CN10K_OCM_PAGESIZE)

/* Maximum OCM mask words, per tile, 8 bit words. */
#define ML_CN10K_OCM_MASKWORDS (ML_CN10K_OCM_NUMPAGES / 8)

/* Number of Queue-Pairs per device */
#define ML_CN10K_QP_PER_DEVICE 1

/* ML OCM and Tile information structure */
struct cn10k_ml_ocm_tile_info {
	/* Mask of used / allotted pages on tile's OCM */
	uint8_t ocm_mask[ML_CN10K_OCM_MASKWORDS];

	/* Last pages in the tile's OCM used for weights and bias
	 * default = -1
	 */
	int last_wb_page;

	/* Number pages used for scratch memory on the tile's OCM */
	uint16_t scratch_pages;
};

#endif /* _CN10K_MLDEV_H_ */
