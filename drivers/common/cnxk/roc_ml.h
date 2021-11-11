/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _ROC_ML_H_
#define _ROC_ML_H_

#include "roc_api.h"

#define ROC_ML_MEM_SZ	  (6 * 1024)
#define ROC_ML_TIMEOUT_MS 10000

/* ML_CFG */
#define ROC_ML_CFG_JD_SIZE	  GENMASK_ULL(1, 0)
#define ROC_ML_CFG_MLIP_ENA	  BIT_ULL(2)
#define ROC_ML_CFG_BUSY		  BIT_ULL(3)
#define ROC_ML_CFG_WRAP_CLK_FORCE BIT_ULL(4)
#define ROC_ML_CFG_MLIP_CLK_FORCE BIT_ULL(5)
#define ROC_ML_CFG_ENA		  BIT_ULL(6)

/* ML_MLR_BASE */
#define ROC_ML_MLR_BASE_BASE GENMASK_ULL(51, 0)

/* ML_AXI_BRIDGE */
#define ROC_ML_AXI_BRIDGE_CTRL_AXI_RESP_CTRL	BIT_ULL(0)
#define ROC_ML_AXI_BRIDGE_CTRL_BRIDGE_CTRL_MODE BIT_ULL(1)
#define ROC_ML_AXI_BRIDGE_CTRL_FORCE_AXI_ID	GENMASK_ULL(11, 2)
#define ROC_ML_AXI_BRIDGE_CTRL_CSR_WR_BLK	BIT_ULL(13)
#define ROC_ML_AXI_BRIDGE_CTRL_NCB_WR_BLK	BIT_ULL(14)
#define ROC_ML_AXI_BRIDGE_CTRL_CSR_RD_BLK	BIT_ULL(15)
#define ROC_ML_AXI_BRIDGE_CTRL_NCB_RD_BLK	BIT_ULL(16)
#define ROC_ML_AXI_BRIDGE_CTRL_FENCE		BIT_ULL(17)
#define ROC_ML_AXI_BRIDGE_CTRL_BUSY		BIT_ULL(18)
#define ROC_ML_AXI_BRIDGE_CTRL_FORCE_WRESP_OK	BIT_ULL(19)
#define ROC_ML_AXI_BRIDGE_CTRL_FORCE_RRESP_OK	BIT_ULL(20)

/* ML_JOB_MGR_CTRL */
#define ROC_ML_JOB_MGR_CTRL_STALL_ON_ERR     BIT_ULL(0)
#define ROC_ML_JOB_MGR_CTRL_PF_OVERRIDE	     BIT_ULL(1)
#define ROC_ML_JOB_MGR_CTRL_PF_FUNC_OVERRIDE GENMASK_ULL(19, 4)
#define ROC_ML_JOB_MGR_CTRL_BUSY	     BIT_ULL(20)
#define ROC_ML_JOB_MGR_CTRL_STALL_ON_IDLE    BIT_ULL(21)

/* ML_JCMDQ_STATUS */
#define ROC_ML_JCMDQ_STATUS_AVAIL_COUNT GENMASK_ULL(4, 0)

/* ML_ANBX_BACKP_DISABLE */
#define ROC_ML_ANBX_BACKP_DISABLE_EXTMSTR_B_BACKP_DISABLE BIT_ULL(0)
#define ROC_ML_ANBX_BACKP_DISABLE_EXTMSTR_R_BACKP_DISABLE BIT_ULL(1)

/* ML_ANBX_NCBI_P_OVR */
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_MSH_DST_OVR_VLD	 BIT_ULL(0)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_MSH_DST_OVR	 GENMASK_ULL(11, 1)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_NS_OVR_VLD	 BIT_ULL(12)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_NS_OVR		 BIT_ULL(13)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_PADDR_OVR_VLD	 BIT_ULL(14)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_PADDR_OVR		 BIT_ULL(15)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_RO_OVR_VLD	 BIT_ULL(16)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_RO_OVR		 BIT_ULL(17)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_MPADID_VAL_OVR_VLD BIT_ULL(18)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_MPADID_VAL_OVR	 BIT_ULL(19)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_MPAMDID_OVR_VLD	 BIT_ULL(20)
#define ML_ANBX_NCBI_P_OVR_ANB_NCBI_P_MPAMDID_OVR	 BIT_ULL(21)

/* ML_ANBX_NCBI_NP_OVR */
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_MSH_DST_OVR_VLD	   BIT_ULL(0)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_MSH_DST_OVR	   GENMASK_ULL(11, 1)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_NS_OVR_VLD	   BIT_ULL(12)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_NS_OVR		   BIT_ULL(13)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_PADDR_OVR_VLD	   BIT_ULL(14)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_PADDR_OVR	   BIT_ULL(15)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_RO_OVR_VLD	   BIT_ULL(16)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_RO_OVR		   BIT_ULL(17)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_MPADID_VAL_OVR_VLD BIT_ULL(18)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_MPADID_VAL_OVR	   BIT_ULL(19)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_MPAMDID_OVR_VLD	   BIT_ULL(20)
#define ML_ANBX_NCBI_NP_OVR_ANB_NCBI_NP_MPAMDID_OVR	   BIT_ULL(21)

/* ML_SW_RST_CTRL */
#define ROC_ML_SW_RST_CTRL_ACC_RST  BIT_ULL(0)
#define ROC_ML_SW_RST_CTRL_CMPC_RST BIT_ULL(1)

struct roc_ml {
	struct plt_pci_device *pci_dev;
	uint8_t reserved[ROC_ML_MEM_SZ] __plt_cache_aligned;
} __plt_cache_aligned;

/* Register read and write */
uint64_t __roc_api roc_ml_reg_read64(struct roc_ml *roc_ml, uint64_t offset);
void __roc_api roc_ml_reg_write64(struct roc_ml *roc_ml, uint64_t val,
				  uint64_t offset);
uint32_t __roc_api roc_ml_reg_read32(struct roc_ml *roc_ml, uint64_t offset);
void __roc_api roc_ml_reg_write32(struct roc_ml *roc_ml, uint32_t val,
				  uint64_t offset);

/* Address translation */
void *__roc_api roc_ml_addr_ap2mlip(struct roc_ml *roc_ml, void *addr);
void *__roc_api roc_ml_addr_mlip2ap(struct roc_ml *roc_ml, void *addr);

/* Scratch and JCMDQ job functions */
void __roc_api roc_ml_scratch_enqueue(struct roc_ml *roc_ml, void *jd);
bool __roc_api roc_ml_scratch_is_valid_bit_set(struct roc_ml *roc_ml);
bool __roc_api roc_ml_scratch_is_done_bit_set(struct roc_ml *roc_ml);
uint16_t __roc_api roc_ml_jcmdq_avail_count_get(struct roc_ml *roc_ml);
void __roc_api roc_ml_jcmdq_enqueue(struct roc_ml *roc_ml, void *jd);

/* Device management */
void __roc_api roc_ml_clk_force_on(struct roc_ml *roc_ml);
void __roc_api roc_ml_clk_force_off(struct roc_ml *roc_ml);
void __roc_api roc_ml_dma_stall_on(struct roc_ml *roc_ml);
void __roc_api roc_ml_dma_stall_off(struct roc_ml *roc_ml);
bool __roc_api roc_ml_mlip_is_enabled(struct roc_ml *roc_ml);
int __roc_api roc_ml_mlip_reset(struct roc_ml *roc_ml);

/* Device / Block, Init / Finish functions */
int __roc_api roc_ml_dev_init(struct roc_ml *roc_ml);
int __roc_api roc_ml_dev_fini(struct roc_ml *roc_ml);
int __roc_api roc_ml_blk_init(struct roc_bphy *roc_bphy, struct roc_ml *roc_ml);
int __roc_api roc_ml_blk_fini(struct roc_bphy *roc_bphy, struct roc_ml *roc_ml);

#endif /*_ROC_ML_H_*/
