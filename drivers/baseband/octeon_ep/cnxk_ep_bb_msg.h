/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _CNXK_EP_BB_MSG_H_
#define _CNXK_EP_BB_MSG_H_

#define	OCTEON_EP_MAX_SG_ENTRIES	8
#define	OCTEON_EP_MAX_BURST_SIZE	64

/* Queue number to op_type mapping on cnxk; host can use any assignment
 * Queue #	Operation type
 *	0	RTE_BBDEV_OP_TURBO_DEC
 *	1	RTE_BBDEV_OP_TURBO_ENC
 *	2	RTE_BBDEV_OP_LDPC_DEC
 *	3	RTE_BBDEV_OP_LDPC_ENC
 */
#define Q_TO_OP_TYPE(q)		((q) + RTE_BBDEV_OP_TURBO_DEC)

/** Different command types supported by the device */
enum oct_bbdev_cmd_type {
	OTX_BBDEV_CMD_INFO_GET = 0x8000,/**< info_get */
	OTX_BBDEV_CMD_SETUP_QUES,	/**< device config */
	OTX_BBDEV_CMD_QUE_SETUP,	/**< queue setup */
	OTX_BBDEV_CMD_QUE_RELEASE,	/**< queue release */
	OTX_BBDEV_CMD_DEV_START,	/**< device start */
	OTX_BBDEV_CMD_DEV_STOP,		/**< device stop */
};

union oct_bbdev_msg_type {
	enum rte_bbdev_op_type	op_type;
	enum oct_bbdev_cmd_type	cmd_type;
};

struct oct_bbdev_seg_data {
	rte_iova_t	data;		/* IOVA of segment mbuf buf_head */
	uint32_t	length;		/* Segment data_len */
};
struct oct_bbdev_op_sg_list {
	uint16_t			num_segs;	/* Number of segments */
	struct oct_bbdev_seg_data	seg_data[OCTEON_EP_MAX_SG_ENTRIES]; /* Translated addr */
};

struct oct_bbdev_op_turbo_enc {
	struct rte_bbdev_enc_op		op;		/* Operation payload input by library */
	rte_iova_t			out_buf;	/* Output buffer address */
	struct oct_bbdev_op_sg_list	in_sg_list;	/* Input scatter-gather list */
};

struct oct_bbdev_op_ldpc_enc {
	struct rte_bbdev_enc_op		op;		/* Operation payload input by library */
	rte_iova_t			out_buf;	/* Output buffer address */
	struct oct_bbdev_op_sg_list	in_sg_list;	/* Input scatter-gather list */
};

struct oct_bbdev_op_turbo_dec {
	struct rte_bbdev_dec_op		op;		/* Operation payload input by library */
	rte_iova_t			hard_out_buf;	/* Oard output buffer address */
	rte_iova_t			soft_out_buf;	/* Soft output buffer address */
	struct oct_bbdev_op_sg_list	in_sg_list;	/* Input scatter-gather list */
};

struct oct_bbdev_op_ldpc_dec {
	struct rte_bbdev_dec_op		op;		/* Operation payload input by library */
	rte_iova_t			hard_out_buf;	/* Hard output address */
	rte_iova_t			soft_out_buf;	/* Soft output address */
	rte_iova_t			harq_cmb_in_buf;/* Hard combined input address */
	rte_iova_t			harq_cmb_out_buf;/* Hard combined output address */
	struct oct_bbdev_op_sg_list	in_sg_list;	/* Input scatter-gather list */
};

/* TX SDP message format for command/operation */
struct oct_bbdev_op_msg {
	/* Fake ethernet header to aid NIX parsing */
	uint8_t		rsvd[11];
	uint8_t		q_no;
	uint16_t	tpid;
	uint16_t	msg_type;	/**< cmd/op (union oct_bbdev_msg_type) */
	uint16_t	etype;
	void		*op_ptr;	/* rte_bbdev input op ptr save location */

	/* Followed by bbdev command/operation payload */
	union {
#ifdef TODO_LATER
		struct oct_bbdev_info_get	info_get;	/**< info_get */
		struct oct_bbdev_setup_queues	setup_queues;	/**< device config */
		struct oct_bbdev_queue_setup	queue_setup;	/**< queue setup */
		struct oct_bbdev_start		start;		/**< device start */
		struct oct_bbdev_stop		stop;		/**< device stop */
		struct oct_bbdev_queue_release	queue_release;	/**< queue release */
#endif
		struct oct_bbdev_op_turbo_enc	turbo_enc;	/**< turbo enc */
		struct oct_bbdev_op_turbo_dec	turbo_dec;	/**< turbo dec */
		struct oct_bbdev_op_ldpc_enc	ldpc_enc;	/**< ldpc enc */
		struct oct_bbdev_op_ldpc_dec	ldpc_dec;	/**< ldpc dec */
	} u;
};

#define MBUF_TO_OCT_MSG(mbuf)		rte_pktmbuf_mtod(mbuf, struct oct_bbdev_op_msg *)

#endif  /* _CNXK_EP_BB_MSG_H_ */
