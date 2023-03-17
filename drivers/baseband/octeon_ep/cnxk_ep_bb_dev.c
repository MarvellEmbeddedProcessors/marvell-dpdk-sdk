/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <string.h>

#include <rte_malloc.h>
#include <rte_kvargs.h>
#include <rte_devargs.h>
#include <rte_bbdev.h>
#include <rte_bbdev_pmd.h>
#include <rte_hexdump.h>
#include <rte_log.h>

#include "cnxk_ep_bb_common.h"
#include "cnxk_ep_bb_vf.h"
#include "cnxk_ep_bb_msg.h"

RTE_LOG_REGISTER_DEFAULT(bbdev_octeon_ep_logtype, NOTICE);

/* Helper macro for logging */
#define rte_bbdev_log(level, fmt, ...) \
	rte_log(RTE_LOG_ ## level, bbdev_octeon_ep_logtype, fmt "\n", \
		##__VA_ARGS__)

#define rte_bbdev_log_debug(fmt, ...) \
	rte_bbdev_log(DEBUG, RTE_STR(__LINE__) ":%s() " fmt, __func__, \
		##__VA_ARGS__)

#define bbdev_log_info(fmt, ...) \
	rte_bbdev_log(INFO, RTE_STR(__LINE__) ":%s() " fmt, __func__, \
		##__VA_ARGS__)

/*  Initialisation params structure that can be used by octeon bbdev driver */
struct octeon_ep_params {
	int socket_id;  /*< device socket */
};

#ifdef TODO_ARG_PARSE
/* Possible params */
#define OCTEON_EP_SOCKET_ID_ARG      "socket_id"

static const char * const octeon_ep_valid_params[] = {
	OCTEON_EP_SOCKET_ID_ARG,
	NULL
};

/* Parse 16bit integer from string argument */
static inline int
parse_u16_arg(const char *key, const char *value, void *extra_args)
{
	uint16_t *u16 = extra_args;
	unsigned int long result;

	if ((value == NULL) || (extra_args == NULL))
		return -EINVAL;
	errno = 0;
	result = strtoul(value, NULL, 0);
	if ((result >= (1 << 16)) || (errno != 0)) {
		rte_bbdev_log(ERR, "Invalid value %" PRId64 " for %s", result, key);
		return -ERANGE;
	}
	*u16 = (uint16_t)result;
	return 0;
}

/* Parse parameters used to create device */
static int
parse_octeon_ep_params(struct octeon_ep_params *params, const char *input_args)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	if (params == NULL)
		return -EINVAL;
	if (input_args) {
		kvlist = rte_kvargs_parse(input_args, octeon_ep_valid_params);
		if (kvlist == NULL)
			return -EFAULT;

		ret = rte_kvargs_process(kvlist, octeon_ep_valid_params[0],
					&parse_u16_arg, &params->socket_id);
		if (ret < 0)
			goto exit;
		if (params->socket_id >= RTE_MAX_NUMA_NODES) {
			rte_bbdev_log(ERR, "Invalid socket, must be < %u",
					RTE_MAX_NUMA_NODES);
			goto exit;
		}
	}

exit:
	rte_kvargs_free(kvlist);
	return ret;
}
#endif

/* Get device info */
static void
info_get(struct rte_bbdev *bbdev, struct rte_bbdev_driver_info *dev_info)
{
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = CNXK_BB_DEV(bbdev);

	/* TODO_NOW: get similar capabilities for octeon bbdev */
	static const struct rte_bbdev_op_cap bbdev_capabilities[] = {
/* TODO_CAPA: #ifdef RTE_BBDEV_SDK_AVX2 */
		{
			.type = RTE_BBDEV_OP_TURBO_DEC,
			.cap.turbo_dec = {
				.capability_flags =
					RTE_BBDEV_TURBO_SUBBLOCK_DEINTERLEAVE |
					RTE_BBDEV_TURBO_POS_LLR_1_BIT_IN |
					RTE_BBDEV_TURBO_NEG_LLR_1_BIT_IN |
					RTE_BBDEV_TURBO_CRC_TYPE_24B |
					RTE_BBDEV_TURBO_DEC_TB_CRC_24B_KEEP |
					RTE_BBDEV_TURBO_EARLY_TERMINATION,
				.max_llr_modulus = 16,
				.num_buffers_src =
						RTE_BBDEV_TURBO_MAX_CODE_BLOCKS,
				.num_buffers_hard_out =
						RTE_BBDEV_TURBO_MAX_CODE_BLOCKS,
				.num_buffers_soft_out = 0,
			}
		},
		{
			.type   = RTE_BBDEV_OP_TURBO_ENC,
			.cap.turbo_enc = {
				.capability_flags =
						RTE_BBDEV_TURBO_CRC_24B_ATTACH |
						RTE_BBDEV_TURBO_CRC_24A_ATTACH |
						RTE_BBDEV_TURBO_RATE_MATCH |
						RTE_BBDEV_TURBO_RV_INDEX_BYPASS,
				.num_buffers_src =
						RTE_BBDEV_TURBO_MAX_CODE_BLOCKS,
				.num_buffers_dst =
						RTE_BBDEV_TURBO_MAX_CODE_BLOCKS,
			}
		},
/* TODO:CAPA #ifdef RTE_BBDEV_SDK_AVX512 */
		{
			.type   = RTE_BBDEV_OP_LDPC_ENC,
			.cap.ldpc_enc = {
				.capability_flags =
						RTE_BBDEV_LDPC_RATE_MATCH |
						RTE_BBDEV_LDPC_CRC_16_ATTACH |
						RTE_BBDEV_LDPC_CRC_24A_ATTACH |
						RTE_BBDEV_LDPC_CRC_24B_ATTACH,
				.num_buffers_src =
						RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
				.num_buffers_dst =
						RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			}
		},
		{
		.type   = RTE_BBDEV_OP_LDPC_DEC,
		.cap.ldpc_dec = {
			.capability_flags =
					RTE_BBDEV_LDPC_CRC_TYPE_16_CHECK |
					RTE_BBDEV_LDPC_CRC_TYPE_24B_CHECK |
					RTE_BBDEV_LDPC_CRC_TYPE_24A_CHECK |
					RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP |
					RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE |
					RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE |
					RTE_BBDEV_LDPC_ITERATION_STOP_ENABLE,
			.llr_size = 8,
			.llr_decimals = 4,
			.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_hard_out =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_soft_out = 0,
		}
		},
		RTE_BBDEV_END_OF_CAPABILITIES_LIST()
	};

#ifdef RTE_BBDEV_SDK_AVX2
	static const enum rte_cpu_flag_t cpu_flag = RTE_CPUFLAG_SSE4_2;
	dev_info->cpu_flag_reqs = &cpu_flag;
#else
	dev_info->cpu_flag_reqs = NULL;
#endif
	/* Get EP info such as rx/tx_offloads, max_pktlen */
	cnxk_ep_bb_dev_info_get(cnxk_ep_bb_vf);

	memset(&dev_info->default_queue_conf, 0, sizeof(struct rte_bbdev_queue_conf));
	dev_info->default_queue_conf.socket = bbdev->data->socket_id;

	/* Use EP queue sizes */
	dev_info->queue_size_lim = RTE_MIN(cnxk_ep_bb_vf->conf->num_iqdef_descs,
					cnxk_ep_bb_vf->conf->num_oqdef_descs);
	dev_info->default_queue_conf.queue_size = dev_info->queue_size_lim;

	dev_info->driver_name = RTE_STR(DRIVER_NAME);
	dev_info->max_num_queues = RTE_MIN(cnxk_ep_bb_vf->max_rx_queues,
					cnxk_ep_bb_vf->max_tx_queues);
	dev_info->hardware_accelerated = true;
	dev_info->max_dl_queue_priority = 0;
	dev_info->max_ul_queue_priority = 0;
	dev_info->capabilities = bbdev_capabilities;
	dev_info->min_alignment = 64;
	dev_info->harq_buffer_size = 0;
	dev_info->data_endianness = RTE_LITTLE_ENDIAN;

	/* TODO_LATER: send this dev_info to EP, get updates & match EP rev # */

	rte_bbdev_log_debug("got device info from %u", bbdev->data->dev_id);
}

/* Configure device */
/* ignoring socket_id because it is already present in bbdev->private_data;
 * app is passing the same value
 */
static int
setup_queues(struct rte_bbdev *bbdev, uint16_t num_queues, int socket_id __rte_unused)
{
	/* TODO_LATER: send this to EP */
	return cnxk_ep_bb_dev_configure(CNXK_BB_DEV(bbdev), num_queues);
}

/* Release queue */
static int
q_release(struct rte_bbdev *bbdev, uint16_t q_no)
{
	int ret;

	/* TODO_LATER: send this to EP */
	ret = cnxk_ep_bb_queue_release(CNXK_BB_DEV(bbdev), q_no);
	bbdev->data->queues[q_no].queue_private = NULL;
	rte_bbdev_log_debug("released device queue %u:%u",
			bbdev->data->dev_id, q_no);
	return ret;
}

/* Setup a queue */
static int
q_setup(struct rte_bbdev *bbdev, uint16_t q_no,
		const struct rte_bbdev_queue_conf *queue_conf)
{
	int ret;
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = CNXK_BB_DEV(bbdev);

	/* TODO_LATER: send this to EP */
	ret = cnxk_ep_bb_queue_setup(cnxk_ep_bb_vf, q_no, queue_conf);
	bbdev->data->queues[q_no].queue_private = cnxk_ep_bb_vf->droq[q_no];
	rte_bbdev_log_debug("setup device queue %u:%u",
			bbdev->data->dev_id, q_no);
	return ret;
}

/* Start device */
static int
dev_start(struct rte_bbdev *bbdev)
{
	/* TODO_LATER: send this to EP */
	return cnxk_ep_bb_dev_start(CNXK_BB_DEV(bbdev));
}

/* Stop device */
static void
dev_stop(struct rte_bbdev *bbdev)
{
	/* TODO_LATER: send this to EP */
	cnxk_ep_bb_dev_stop(CNXK_BB_DEV(bbdev));
}

static const struct rte_bbdev_ops pmd_ops = {
	.info_get = info_get,
	.setup_queues = setup_queues,
	.queue_setup = q_setup,
	.start = dev_start,
	.stop = dev_stop,
	.queue_release = q_release
};

#define	MBUF_IOVA_CHK(m)	((m) ? rte_pktmbuf_iova(m) : 0)

#define	MBUF_SEG_IOVA(m, s)	do {	\
	(s)->data = rte_pktmbuf_iova(m);\
	(s)->length = (m)->data_len;	\
} while (0)

static int
fill_iova_chain(struct rte_bbdev_op_data *input, struct oct_bbdev_op_sg_list *sg_list)
{
	struct rte_mbuf *mbuf = input->data;
	struct oct_bbdev_seg_data *seg = sg_list->seg_data;

	/* Check if segments exceed max limit */
	if (unlikely(mbuf->nb_segs > OCTEON_EP_MAX_SG_ENTRIES))
		return -1;
	/* Set segment count, total length */
	sg_list->num_segs = mbuf->nb_segs;
	/* Translate each segment */
	do {
		MBUF_SEG_IOVA(mbuf, seg);
		++seg;
		mbuf = mbuf->next;
	} while (mbuf);

	return 0;
}

static void
add_to_mbufq(struct rte_mbuf **mbufs, int num, struct mbufq_s *mbufq)
{
	struct rte_mbuf *first, *last;
	int i;

	first = last = mbufs[0];
	for (i = 1; i < num; ++i) {
		last->next = mbufs[i];
		last = mbufs[i];
	}
	last->next = NULL;
	if (mbufq->tail)
		mbufq->tail->next = first;
	else
		mbufq->head = first;
	mbufq->tail = last;
}

/* Enqueue limited single burst of command/operation messages */
static uint16_t
enqueue_burst(struct rte_bbdev_queue_data *q_data, void *ops[], uint16_t nb_ops)
{
	int i = 0, nb_enq, err, q_no = Q_TO_Q_NUM(q_data);
	struct rte_mbuf *mbufs[OCTEON_EP_MAX_BURST_SIZE];
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = Q_TO_BB_DEV(q_data);
	struct oct_bbdev_op_msg *msg;

	/* Allocate message buffers */
	if (unlikely(rte_pktmbuf_alloc_bulk(cnxk_ep_bb_vf->msg_pool, mbufs, nb_ops)))
		return 0;

	/* Prepare op_type specific message for each op */
	switch (q_data->conf.op_type) {
	case RTE_BBDEV_OP_TURBO_DEC: {
		struct oct_bbdev_op_turbo_dec *req;
		struct rte_bbdev_dec_op *op;
		for (i = 0; i < nb_ops; ++i) {
			/* Populate turbo_dec message */
			msg = MBUF_TO_OCT_MSG(mbufs[i]);
			mbufs[i]->data_len = sizeof(struct oct_bbdev_op_msg);
			msg->vf_id = cnxk_ep_bb_vf->vf_num;
			msg->q_no = q_no;
			msg->tpid = rte_cpu_to_be_16(0x8100);
			msg->msg_type = RTE_BBDEV_OP_TURBO_DEC;
			req = &msg->u.turbo_dec;
			op = ops[i];
			err = fill_iova_chain(&op->turbo_dec.input, &req->in_sg_list);
			/* Stop further enqueue if sg_list overflow */
			if (unlikely(err))
				goto exit;
			req->op = *op;
			msg->op_ptr = op;
			req->hard_out_buf = rte_pktmbuf_iova(op->turbo_dec.hard_output.data);
			req->soft_out_buf = MBUF_IOVA_CHK(op->turbo_dec.soft_output.data);
		}
		break;
	}
	case RTE_BBDEV_OP_TURBO_ENC: {
		struct oct_bbdev_op_turbo_enc *req;
		struct rte_bbdev_enc_op *op;
		for (i = 0; i < nb_ops; ++i) {
			/* Populate turbo_enc message */
			msg = MBUF_TO_OCT_MSG(mbufs[i]);
			mbufs[i]->data_len = sizeof(struct oct_bbdev_op_msg);
			msg->vf_id = cnxk_ep_bb_vf->vf_num;
			msg->q_no = q_no;
			msg->tpid = rte_cpu_to_be_16(0x8100);
			msg->msg_type = RTE_BBDEV_OP_TURBO_ENC;
			req = &msg->u.turbo_enc;
			op = ops[i];
			err = fill_iova_chain(&op->turbo_enc.input, &req->in_sg_list);
			/* Stop further enqueue if sg_list overflow */
			if (unlikely(err))
				goto exit;
			req->op = *op;
			msg->op_ptr = op;
			req->out_buf = rte_pktmbuf_iova(op->turbo_enc.output.data);
		}
		break;
	}
	case RTE_BBDEV_OP_LDPC_DEC: {
		struct oct_bbdev_op_ldpc_dec *req;
		struct rte_bbdev_dec_op *op;
		for (i = 0; i < nb_ops; ++i) {
			/* Populate ldpc_dec message */
			msg = MBUF_TO_OCT_MSG(mbufs[i]);
			mbufs[i]->data_len = sizeof(struct oct_bbdev_op_msg);
			msg->vf_id = cnxk_ep_bb_vf->vf_num;
			msg->q_no = q_no;
			msg->tpid = rte_cpu_to_be_16(0x8100);
			msg->msg_type = RTE_BBDEV_OP_LDPC_DEC;
			req = &msg->u.ldpc_dec;
			op = ops[i];
			err = fill_iova_chain(&op->ldpc_dec.input, &req->in_sg_list);
			/* Stop further enqueue if sg_list overflow */
			if (unlikely(err))
				goto exit;
			req->op = *op;
			msg->op_ptr = op;
			req->hard_out_buf = rte_pktmbuf_iova(op->ldpc_dec.hard_output.data);
			req->soft_out_buf = MBUF_IOVA_CHK(op->ldpc_dec.soft_output.data);
			req->harq_cmb_in_buf = MBUF_IOVA_CHK(op->ldpc_dec.harq_combined_input.data);
			req->harq_cmb_out_buf =
				MBUF_IOVA_CHK(op->ldpc_dec.harq_combined_output.data);
		}
		break;
	}
	case RTE_BBDEV_OP_LDPC_ENC: {
		struct oct_bbdev_op_ldpc_enc *req;
		struct rte_bbdev_enc_op *op;
		for (i = 0; i < nb_ops; ++i) {
			/* Populate ldpc_enc message */
			msg = MBUF_TO_OCT_MSG(mbufs[i]);
			mbufs[i]->data_len = sizeof(struct oct_bbdev_op_msg);
			msg->vf_id = cnxk_ep_bb_vf->vf_num;
			msg->q_no = q_no;
			msg->tpid = rte_cpu_to_be_16(0x8100);
			msg->msg_type = RTE_BBDEV_OP_LDPC_ENC;
			req = &msg->u.ldpc_enc;
			op = ops[i];
			err = fill_iova_chain(&op->ldpc_enc.input, &req->in_sg_list);
			/* Stop further enqueue if sg_list overflow */
			if (unlikely(err))
				goto exit;
			req->op = *op;
			msg->op_ptr = op;
			req->out_buf = rte_pktmbuf_iova(op->ldpc_enc.output.data);
		}
		break;
	}
	default:
		rte_bbdev_log(ERR, "Invalid queue op_type %d",
				q_data->conf.op_type);
		goto exit;
	}
exit:
	/* Enqueue to TX queue; skipping 0 check on i as it results in nop */
	nb_enq = cnxk_ep_bb_enqueue_ops(q_data->queue_private, mbufs, i);
	/* Add processed ops to wait list; include those that could not be queued */
	if (likely(nb_enq))
		add_to_mbufq(mbufs, nb_enq, &cnxk_ep_bb_vf->mbuf_queues[q_no].wait_ops);
	/* Free unused mbufs */
	if (unlikely(nb_enq < nb_ops))
		rte_pktmbuf_free_bulk(&mbufs[nb_enq], nb_ops - nb_enq);
	return nb_enq;
}

/* enqueue_dec_ops and enqueue_enc_ops differ only in type of
 * ops argument.  Using same routine enqueue_ops() by defining
 * ops type to be (void **).  Within enqueue_ops(), actual op_type is
 * determined using q_data->conf.op_type
 */
static uint16_t
enqueue_ops(struct rte_bbdev_queue_data *q_data, void **ops, uint16_t nb_ops)
{
	uint16_t nb_enq = 0, in_cnt, cnt, left = nb_ops;

	while (left != 0) {
		/* Send one burst of min(left, OCTEON_EP_MAX_BURST_SIZE) */
		in_cnt = RTE_MIN(left, OCTEON_EP_MAX_BURST_SIZE);
		cnt = enqueue_burst(q_data, &ops[nb_enq], in_cnt);
		nb_enq += cnt;
		/* Stop if all were not processed */
		if (cnt < in_cnt)
			break;
		/* Send next burst until done */
		left -= cnt;
	}

	/* TODO: optional q_data->queue_stats.acc_offload_cycles stats */
	q_data->queue_stats.enqueue_err_count += nb_ops - nb_enq;
	q_data->queue_stats.enqueued_count += nb_enq;
	if (nb_enq)
		rte_bbdev_log_debug("TX: %d/%d ops type %d q %d lcore %d total %" PRId64,
				nb_enq, nb_ops, q_data->conf.op_type, Q_TO_Q_NUM(q_data),
				rte_lcore_id(), q_data->queue_stats.enqueued_count);
	return nb_enq;
}

/* Enqueue encode operations */
static uint16_t
enqueue_enc_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	return enqueue_ops(q_data, (void **)ops, nb_ops);
}

/* Enqueue decode operations */
static uint16_t
enqueue_dec_ops(struct rte_bbdev_queue_data *q_data,
		 struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	return enqueue_ops(q_data, (void **)ops, nb_ops);
}

/* Locate matching req cmd/op in waiting list and get skip count
 * Returns number of cmd/ops skipped for match, 0 if cmd/op not found
 * TODO_LATER: differentiate between cmd & op messages on queue 0
 */
#define	FIND_OP()	({						\
	struct rte_mbuf *mbuf;						\
	int cnt = 0;							\
	/* mbuf at wait queue head is already checked */		\
	for (mbuf = wait_head->next; mbuf; mbuf = mbuf->next) {		\
		/* Update skip count */					\
		++cnt;							\
		req = MBUF_TO_OCT_MSG(mbuf);				\
		if (req->op_ptr == resp->op_ptr)			\
			break;						\
	}								\
	/* Indicate if we did not get req cmd/op */			\
	if (!mbuf)							\
		cnt = 0;						\
	cnt;								\
})

/* Copy response into original request */
#define	COPY_RESP()	do {		\
	switch (q_data->conf.op_type) {	\
	case RTE_BBDEV_OP_TURBO_DEC: {	\
		struct rte_bbdev_dec_op *op1 = req->op_ptr, *op2 = &resp->u.turbo_dec.op;	\
		memcpy(op1, op2, sizeof(struct rte_bbdev_dec_op));	\
		op1->turbo_dec.hard_output.data->data_len =		\
			op1->turbo_dec.hard_output.data->pkt_len =	\
			op2->turbo_dec.hard_output.length;		\
		break;			\
	}				\
	case RTE_BBDEV_OP_LDPC_DEC: {	\
		struct rte_bbdev_dec_op *op1 = req->op_ptr, *op2 = &resp->u.ldpc_dec.op;	\
		memcpy(op1, op2, sizeof(struct rte_bbdev_dec_op));	\
		op1->ldpc_dec.hard_output.data->data_len =		\
			op1->ldpc_dec.hard_output.data->pkt_len =	\
			op2->ldpc_dec.hard_output.length;		\
		break;			\
	}				\
	case RTE_BBDEV_OP_TURBO_ENC: {	\
		struct rte_bbdev_enc_op *op1 = req->op_ptr, *op2 = &resp->u.turbo_enc.op;	\
		memcpy(op1, op2, sizeof(struct rte_bbdev_enc_op));	\
		op1->turbo_enc.output.data->data_len = op1->turbo_enc.output.data->pkt_len =	\
			op2->turbo_enc.output.length;			\
		break;			\
	}				\
	case RTE_BBDEV_OP_LDPC_ENC: {	\
		struct rte_bbdev_enc_op *op1 = req->op_ptr, *op2 = &resp->u.ldpc_enc.op;	\
		memcpy(op1, op2, sizeof(struct rte_bbdev_enc_op));	\
		op1->ldpc_enc.output.data->data_len = op1->ldpc_enc.output.data->pkt_len =	\
			op2->ldpc_enc.output.length;			\
		break;			\
	}				\
	default:			\
		break;			\
	}				\
} while (0)

/* Move wait list head to output */
#define	MOVE_OP()	do {		\
	*ops++ = req->op_ptr;		\
	next = wait_head->next;		\
	wait_head->next = NULL;		\
	rte_pktmbuf_free(wait_head);	\
	wait_head = next;		\
} while (0)

/* Set error status for cmd/op with no response */
#define	SET_ERR_STATUS()	do {			\
	switch (req->msg_type) {			\
	case RTE_BBDEV_OP_TURBO_DEC:			\
	case RTE_BBDEV_OP_LDPC_DEC:			\
		((struct rte_bbdev_dec_op *)req->op_ptr)->status =	\
			1 << RTE_BBDEV_DRV_ERROR;	\
		break;					\
	case RTE_BBDEV_OP_TURBO_ENC:			\
	case RTE_BBDEV_OP_LDPC_ENC:			\
		((struct rte_bbdev_enc_op *)req->op_ptr)->status =	\
			1 << RTE_BBDEV_DRV_ERROR;	\
		break;					\
	}						\
} while (0)

/* Move given number of command/operation messages from wait list to output queue
 *	qhead		Wait list queue head
 *	ops		Output ops array
 *	cnt		Number of command/operation messages to move
 *	left		Space left in ops array
 */
#define	MOVE_FAILED_OPS()	do {	\
	/* Num of failed cmd/ops to move */		\
	int num = RTE_MIN(skip, left);	\
	do {				\
		req = MBUF_TO_OCT_MSG(wait_head);	\
		SET_ERR_STATUS();	\
		MOVE_OP();		\
	} while (--num);		\
	if (likely(skip < left)) {	\
		COPY_RESP();		\
		MOVE_OP();		\
	}				\
} while (0)

#define MSG_TO_OPAQUE(msg)	({	\
	void *opaque;			\
	switch (rte_be_to_cpu_16((msg)->msg_type)) {			\
	case RTE_BBDEV_OP_TURBO_DEC:	\
		opaque = (msg)->u.turbo_dec.op.opaque_data;	\
		break;			\
	case RTE_BBDEV_OP_LDPC_DEC:	\
		opaque = (msg)->u.ldpc_dec.op.opaque_data;	\
		break;			\
	case RTE_BBDEV_OP_TURBO_ENC:	\
		opaque = (msg)->u.turbo_dec.op.opaque_data;	\
		break;			\
	case RTE_BBDEV_OP_LDPC_ENC:	\
		opaque = (msg)->u.ldpc_dec.op.opaque_data;	\
		break;			\
	default:			\
		opaque = NULL;		\
		break;			\
	}				\
	opaque;				\
})

#define PRT_INFO()							\
	rte_bbdev_log(ERR, "expected req: q=%d msg_type=%d opq=0x%p,"	\
		"got resp: q=%d msg_type=%d opq=0x%p",			\
		req->q_no, rte_be_to_cpu_16(req->msg_type),		\
		MSG_TO_OPAQUE(req), resp->q_no,				\
		rte_be_to_cpu_16(resp->msg_type), MSG_TO_OPAQUE(resp))

/* Scenarios				  left	    err_cnt	mb_done
 *   response matched wait queue head	  -= 1	    no-chg	no-chg
 *   response did not match any request   no-chg    +1		no-chg
 *   response matched after n cmd/op &
 *     move all to output		  -= (n+1)  +n		no-chg
 *     moved only k failed cmd/op	  -= k      +k		false
 */
#define RX_ONE(rx_mbuf)	do {			\
	struct oct_bbdev_op_msg *req, *resp;	\
	int skip;				\
						\
	/* Check if response is for first cmd/op */	\
	resp = MBUF_TO_OCT_MSG(rx_mbuf);		\
	req = MBUF_TO_OCT_MSG(wait_head);		\
	if (likely(req->op_ptr == resp->op_ptr)) {	\
		/* Update status & move to output */	\
		COPY_RESP();			\
		MOVE_OP();			\
		rte_pktmbuf_free(rx_mbuf);	\
		--left;				\
		break;				\
	}					\
	/* Search for matching request cmd/op */\
	skip = FIND_OP();			\
	/* If not found, then drop this unexpected response */			\
	if (unlikely(skip == 0)) {		\
		PRT_INFO();			\
		rte_pktmbuf_free(rx_mbuf);	\
		++err_cnt;			\
		break;				\
	}					\
	/* Move all till matching request from waiting list to output */	\
	MOVE_FAILED_OPS();			\
	/* If successful cmd/op was added to output, free response mbuf */	\
	if (likely(skip < left)) {		\
		left -= skip + 1;		\
		err_cnt += skip;		\
		rte_pktmbuf_free(rx_mbuf);	\
	} else {				\
		err_cnt += left;		\
		left = 0;			\
		mb_done = 0;			\
	}					\
	break;					\
} while (0)

/* Dequeue limited single burst of command/operation responses */
static uint16_t
dequeue_burst(struct rte_bbdev_queue_data *q_data, void *ops[], uint16_t nb_ops)
{
	int i, err_cnt = 0, mb_done, left = nb_ops, nb_deq, q_no = Q_TO_Q_NUM(q_data);
	struct rte_mbuf *saved, *next, *mbufs[OCTEON_EP_MAX_BURST_SIZE];
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = Q_TO_BB_DEV(q_data);
	struct mbufq_s *sv_mbufs = &cnxk_ep_bb_vf->mbuf_queues[q_no].sv_mbufs;
	struct mbufq_s *wait_ops = &cnxk_ep_bb_vf->mbuf_queues[q_no].wait_ops;
	struct rte_mbuf *wait_head = wait_ops->head;

	/* Process saved mbufs */
	if (unlikely(sv_mbufs->head)) {
		mb_done = 1;
		saved = sv_mbufs->head;
		do {
			next = saved->next;
			RX_ONE(saved);
			if (unlikely(!mb_done))
				break;
			saved = next;
		} while (saved && left > 0);
		sv_mbufs->head = saved;
		if (likely(saved == NULL))
			sv_mbufs->tail = NULL;
	}

	/* Burst dequeue responses into provided ops array */
	nb_deq = cnxk_ep_bb_dequeue_ops(q_data->queue_private, mbufs, left);
	/* Process each response */
	mb_done = 1;
	for (i = 0; (i < nb_deq) && (left > 0); ++i) {
		RX_ONE(mbufs[i]);
		if (unlikely(!mb_done))
			break;
	}
	/* Update wait queue */
	wait_ops->head = wait_head;
	if (unlikely(wait_head == NULL))
		wait_ops->tail = NULL;

	/* Update stats */
	q_data->queue_stats.dequeued_count += nb_ops - left;
	q_data->queue_stats.dequeue_err_count += err_cnt;
	/* Save mbufs which could not be processed for next time */
	if (unlikely(i < nb_deq))
		add_to_mbufq(&mbufs[i], nb_deq - i, sv_mbufs);

	return nb_ops - left;
}

/* dequeue_dec_ops and dequeue_enc_ops differ only in type of
 * ops argument.  Using same routine enqueue_ops() by defining
 * ops type to be (void **).  Within enqueue_ops(), actual op_type is
 * determined using q_data->conf.op_type
 */
static uint16_t
dequeue_ops(struct rte_bbdev_queue_data *q_data, void **ops, uint16_t nb_ops)
{
	uint16_t nb_deq = 0, in_cnt, cnt, left = nb_ops;

	while (left != 0) {
		/* Receive one burst of min(left, OCTEON_EP_MAX_BURST_SIZE) */
		in_cnt = RTE_MIN(left, OCTEON_EP_MAX_BURST_SIZE);
		cnt = dequeue_burst(q_data, &ops[nb_deq], in_cnt);
		nb_deq += cnt;
		/* Stop if all were not received */
		if (cnt < in_cnt)
			break;
		/* Receive next burst until done */
		left -= cnt;
	}
	/* stats is already updated in dequeue_burst */
	/* TODO: optional q_data->queue_stats.acc_offload_cycles stats */
	if (nb_deq)
		rte_bbdev_log_debug("RX: %d ops type %d q %d lcore %d total %" PRId64,
				nb_deq, q_data->conf.op_type, Q_TO_Q_NUM(q_data),
				rte_lcore_id(), q_data->queue_stats.dequeued_count);
	return nb_deq;
}

/* Dequeue encode responses */
static uint16_t
dequeue_enc_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	return dequeue_ops(q_data, (void **)ops, nb_ops);
}

/* Dequeue decode responses */
static uint16_t
dequeue_dec_ops(struct rte_bbdev_queue_data *q_data,
		 struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	return dequeue_ops(q_data, (void **)ops, nb_ops);
}

/* Create device */
static int
octeon_ep_bbdev_create(struct rte_pci_device *pci_dev,
		struct octeon_ep_params *init_params,
		struct rte_bbdev **bbdev_out)
{
	struct rte_bbdev *bbdev;
	const char *name = CNXK_BB_DEV_NAME(pci_dev);

	bbdev = rte_bbdev_allocate(name);
	if (bbdev == NULL)
		return -ENODEV;

	bbdev->data->dev_private = rte_zmalloc_socket(name,
			sizeof(struct cnxk_ep_bb_device), RTE_CACHE_LINE_SIZE,
			init_params->socket_id);
	if (bbdev->data->dev_private == NULL) {
		rte_bbdev_release(bbdev);
		return -ENOMEM;
	}

	bbdev->dev_ops = &pmd_ops;
	bbdev->device = &pci_dev->device;
	bbdev->data->socket_id = init_params->socket_id;
	bbdev->intr_handle = NULL;

	/* register rx/tx burst functions for data path */
	bbdev->dequeue_enc_ops = dequeue_enc_ops;
	bbdev->dequeue_dec_ops = dequeue_dec_ops;
	bbdev->enqueue_enc_ops = enqueue_enc_ops;
	bbdev->enqueue_dec_ops = enqueue_dec_ops;
	bbdev->dequeue_ldpc_enc_ops = dequeue_enc_ops;
	bbdev->dequeue_ldpc_dec_ops = dequeue_dec_ops;
	bbdev->enqueue_ldpc_enc_ops = enqueue_enc_ops;
	bbdev->enqueue_ldpc_dec_ops = enqueue_dec_ops;
	*bbdev_out = bbdev;

	return 0;
}

static int
octeon_ep_bbdev_exit(struct rte_bbdev *bbdev)
{
	rte_free(bbdev->data->dev_private);
	return rte_bbdev_release(bbdev);
}

/* Initialise device */
static int
octeon_ep_bbdev_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		      struct rte_pci_device *pci_dev)
{
	int ret;
	struct octeon_ep_params init_params = {
		rte_socket_id(),
	};
	const char *name;
	struct rte_bbdev *bbdev;

	if (pci_dev == NULL)
		return -EINVAL;
	name = CNXK_BB_DEV_NAME(pci_dev);
	if (name == NULL)
		return -EINVAL;
#ifdef TODO_ARG_PARSE
	/* pci_dev->device.devargs is NULL
	 * parse_octeon_ep_params() - found none
	 */
	bbdev_log_info("here, devargs=%p", pci_dev->device.devargs);
	parse_octeon_ep_params(&init_params, pci_dev->device.devargs->args);
#endif
	ret = octeon_ep_bbdev_create(pci_dev, &init_params, &bbdev);
	if (ret)
		return ret;

	ret = cnxk_ep_bb_sdp_init(bbdev);
	if (ret) {
		octeon_ep_bbdev_exit(bbdev);
		return ret;
	}
	rte_bbdev_log_debug("Initialized %s on NUMA node %d pkt_mode=loop",
		name, init_params.socket_id);
	return 0;
}

/* Uninitialise device */
static int
octeon_ep_bbdev_pci_remove(struct rte_pci_device *pci_dev)
{
	struct rte_bbdev *bbdev;
	const char *name;

	if (pci_dev == NULL)
		return -EINVAL;

	name = CNXK_BB_DEV_NAME(pci_dev);
	if (name == NULL)
		return -EINVAL;

	bbdev = rte_bbdev_get_named_dev(name);
	if (bbdev == NULL)
		return -EINVAL;

	cnxk_ep_bb_dev_exit(CNXK_BB_DEV(bbdev));

	return octeon_ep_bbdev_exit(bbdev);
}

/* Set of PCI devices this driver supports */
static const struct rte_pci_id pci_id_octeon_ep_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_CNF10KA_EP_BBDEV_VF) },
	{ .vendor_id = 0, /* sentinel */ }
};

static struct rte_pci_driver bbdev_octeon_ep_pmd = {
	.id_table	= pci_id_octeon_ep_map,
	.drv_flags	= RTE_PCI_DRV_NEED_MAPPING,
	.probe		= octeon_ep_bbdev_pci_probe,
	.remove		= octeon_ep_bbdev_pci_remove
};

RTE_PMD_REGISTER_PCI(bbdev_octeon_ep, bbdev_octeon_ep_pmd);
RTE_PMD_REGISTER_PCI_TABLE(bbdev_octeon_ep, pci_id_octeon_ep_map);
RTE_PMD_REGISTER_KMOD_DEP(bbdev_octeon_ep, "vfio-pci");
RTE_LOG_REGISTER_DEFAULT(octeon_ep_bbdev_logtype, NOTICE);
