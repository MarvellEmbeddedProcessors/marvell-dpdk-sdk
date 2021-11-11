/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef __ML_HW_H__
#define __ML_HW_H__

/* Constants */
#define ML_ANBX_NR 0x3

/* Base Offsets */
#define ML_MLAB_BLK_OFFSET 0x20000000
#define ML_AXI_START_ADDR  0x800000000

/* MLW Register offsets / ML_PF_BAR0 */
#define ML_CFG			 0x10000
#define ML_MLR_BASE		 0x10008
#define ML_AXI_BRIDGE_CTRL(a)	 (0x10020 | (uint64_t)(a) << 3)
#define ML_JOB_MGR_CTRL		 0x10060
#define ML_JCMDQ_IN(a)		 (0x11000 | (uint64_t)(a) << 3) /* CN10KA */
#define ML_JCMDQ_STATUS		 0x11010			/* CN10KA */
#define ML_SCRATCH(a)		 (0x14000 | (uint64_t)(a) << 3)
#define ML_ANBX_BACKP_DISABLE(a) (0x18000 | (uint64_t)(a) << 12) /* CN10KA */
#define ML_ANBX_NCBI_P_OVR(a)	 (0x18010 | (uint64_t)(a) << 12) /* CN10KA */
#define ML_ANBX_NCBI_NP_OVR(a)	 (0x18020 | (uint64_t)(a) << 12) /* CN10KA */

/* MLW config-gen registers */
#define ML_SW_RST_CTRL		      0x12084000
#define ML_A35_0_RST_VECTOR_BASE_W(a) (0x12084014 + (a) * (0x04))
#define ML_A35_1_RST_VECTOR_BASE_W(a) (0x1208401c + (a) * (0x04))

/* Scratch Register offsets */
#define ML_SCRATCH_WORK_PTR	      (ML_SCRATCH(0))
#define ML_SCRATCH_AP_FW_COMM	      (ML_SCRATCH(1))
#define ML_SCRATCH_DBG_BUFFER_HEAD_C0 (ML_SCRATCH(2))
#define ML_SCRATCH_DBG_BUFFER_TAIL_C0 (ML_SCRATCH(3))
#define ML_SCRATCH_DBG_BUFFER_HEAD_C1 (ML_SCRATCH(4))
#define ML_SCRATCH_DBG_BUFFER_TAIL_C1 (ML_SCRATCH(5))
#define ML_SCRATCH_EXCEPTION_SP_C0    (ML_SCRATCH(6))
#define ML_SCRATCH_EXCEPTION_SP_C1    (ML_SCRATCH(7))

/* Software defined scratch register structures */
union ml_scratch_work_ptr {
	uint64_t u;
	struct ml_scratch_work_ptr_s {
		uint64_t work_cmd_ptr;
	} s;
};

union ml_scratch_ap_fw_comm {
	uint64_t u;
	struct ml_scratch_ap_fw_comm_s {
		uint64_t work_cmd : 16;
		uint64_t valid : 1;
		uint64_t done : 1;
		uint64_t rsvd_63_18 : 46;
	} s;
};

#endif /* __ML_HW_H__ */
