/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "rte_malloc.h"

#include "cnxk_ep_bb_common.h"
#include "cnxk_ep_bb_vf.h"
#include "cnxk_ep_bb_rxtx.h"

/* SDP_LENGTH_S specifies packet length and is of 8-byte size */
#define INFO_SIZE 8
#define DROQ_REFILL_THRESHOLD 16
#define OTX2_SDP_REQUEST_ISM	(0x1ULL << 63)

/* These arrays indexed by cnxk_ep_bb_device->sdp_packet_mode */
static uint8_t front_size[2] = {OTX2_EP_FSZ_NIC, OTX2_EP_FSZ_LOOP};
static uint8_t rh_size[2] = {CNXK_EP_BB_RH_SIZE_NIC, CNXK_EP_BB_RH_SIZE_LOOP};
static uint8_t droq_info_size[2] = {CNXK_EP_BB_DROQ_INFO_SIZE_NIC,
				    CNXK_EP_BB_DROQ_INFO_SIZE_LOOP};

const struct rte_memzone *
cnxk_ep_bb_dmazone_reserve(uint16_t dev_id, const char *ring_name, uint16_t queue_id,
				size_t size, unsigned int align, int socket_id)
{
	char z_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	int rc;

	rc = snprintf(z_name, RTE_MEMZONE_NAMESIZE, "bbdev_%d_q%d_%s",
			dev_id, queue_id, ring_name);
	if (rc >= RTE_MEMZONE_NAMESIZE) {
		cnxk_ep_bb_err("memzone name too long\n");
		return NULL;
	}
	mz = rte_memzone_lookup(z_name);
	if (mz) {
		if ((socket_id != SOCKET_ID_ANY && socket_id != mz->socket_id) ||
				size > mz->len ||
				((uintptr_t)mz->addr & (align - 1)) != 0) {
			cnxk_ep_bb_err("existing memzone %s has different attributes\n",
				mz->name);
			return NULL;
		}
		return mz;
	}
	return rte_memzone_reserve_aligned(z_name, size, socket_id,
					RTE_MEMZONE_IOVA_CONTIG, align);
}

void
cnxk_ep_bb_dmazone_free(const struct rte_memzone *mz)
{
	const struct rte_memzone *mz_tmp;
	int ret = 0;

	if (mz == NULL) {
		cnxk_ep_bb_err("Memzone: NULL\n");
		return;
	}

	mz_tmp = rte_memzone_lookup(mz->name);
	if (mz_tmp == NULL) {
		cnxk_ep_bb_err("Memzone %s Not Found\n", mz->name);
		return;
	}

	ret = rte_memzone_free(mz);
	if (ret)
		cnxk_ep_bb_err("Memzone free failed : ret = %d\n", ret);
}

/* Free IQ resources */
int
cnxk_ep_bb_delete_iqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t iq_no)
{
	struct cnxk_ep_bb_instr_queue *iq;

	iq = cnxk_ep_bb_vf->instr_queue[iq_no];
	if (iq == NULL) {
		cnxk_ep_bb_err("Invalid IQ[%d]\n", iq_no);
		return -EINVAL;
	}

	rte_free(iq->req_list);
	iq->req_list = NULL;

	if (iq->iq_mz) {
		cnxk_ep_bb_dmazone_free(iq->iq_mz);
		iq->iq_mz = NULL;
	}

	rte_free(cnxk_ep_bb_vf->instr_queue[iq_no]);
	cnxk_ep_bb_vf->instr_queue[iq_no] = NULL;

	cnxk_ep_bb_vf->nb_tx_queues--;

	cnxk_ep_bb_info("IQ[%d] is deleted", iq_no);

	return 0;
}

/* IQ initialization */
static int
cnxk_ep_bb_init_instr_queue(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, int iq_no, int num_descs,
		     unsigned int socket_id)
{
	const struct cnxk_ep_bb_config *conf;
	struct cnxk_ep_bb_instr_queue *iq;
	uint32_t q_size;
	int ret;

	conf = cnxk_ep_bb_vf->conf;
	iq = cnxk_ep_bb_vf->instr_queue[iq_no];
	q_size = conf->iq.instr_type * num_descs;

	/* IQ memory creation for Instruction submission to OCTEON TX2 */
	iq->iq_mz = cnxk_ep_bb_dmazone_reserve(cnxk_ep_bb_vf->bbdev->data->dev_id, "instr_queue",
					iq_no, q_size, CNXK_EP_BB_PCI_RING_ALIGN, socket_id);
	if (iq->iq_mz == NULL) {
		cnxk_ep_bb_err("IQ[%d] memzone alloc failed\n", iq_no);
		goto iq_init_fail;
	}
	iq->base_addr_dma = iq->iq_mz->iova;
	iq->base_addr = (uint8_t *)iq->iq_mz->addr;

	if (num_descs & (num_descs - 1)) {
		cnxk_ep_bb_err("IQ[%d] descs not in power of 2\n", iq_no);
		goto iq_init_fail;
	}

	iq->nb_desc = num_descs;

	/* Create a IQ request list to hold requests that have been
	 * posted to OCTEON TX2. This list will be used for freeing the IQ
	 * data buffer(s) later once the OCTEON TX2 fetched the requests.
	 */
	iq->req_list = rte_zmalloc_socket("request_list",
			(iq->nb_desc * CNXK_EP_BB_IQREQ_LIST_SIZE),
			RTE_CACHE_LINE_SIZE,
			rte_socket_id());
	if (iq->req_list == NULL) {
		cnxk_ep_bb_err("IQ[%d] req_list alloc failed\n", iq_no);
		goto iq_init_fail;
	}

	cnxk_ep_bb_info("IQ[%d]: base: %p basedma: %" PRIx64 " count: %d",
		     iq_no, iq->base_addr, (unsigned long)iq->base_addr_dma,
		     iq->nb_desc);

	iq->cnxk_ep_bb_dev = cnxk_ep_bb_vf;
	iq->q_no = iq_no;
	iq->fill_cnt = 0;
	iq->host_write_index = 0;
	iq->otx_read_index = 0;
	iq->flush_index = 0;
	iq->instr_pending = 0;

	cnxk_ep_bb_vf->io_qmask.iq |= (1ull << iq_no);

	/* Set 32B/64B mode for each input queue */
	if (conf->iq.instr_type == 64)
		cnxk_ep_bb_vf->io_qmask.iq64B |= (1ull << iq_no);

	iq->iqcmd_64B = (conf->iq.instr_type == 64);

	/* Set up IQ registers */
	ret = cnxk_ep_bb_vf->fn_list.setup_iq_regs(cnxk_ep_bb_vf, iq_no);
	if (ret)
		return ret;

	return 0;

iq_init_fail:
	return -ENOMEM;
}

int
cnxk_ep_bb_setup_iqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t iq_no, int num_descs,
		 unsigned int socket_id)
{
	struct cnxk_ep_bb_instr_queue *iq;

	iq = (struct cnxk_ep_bb_instr_queue *)rte_zmalloc("cnxk_ep_bb_IQ", sizeof(*iq),
						RTE_CACHE_LINE_SIZE);
	if (iq == NULL)
		return -ENOMEM;

	cnxk_ep_bb_vf->instr_queue[iq_no] = iq;

	cnxk_ep_bb_vf->nb_tx_queues++;
	if (cnxk_ep_bb_init_instr_queue(cnxk_ep_bb_vf, iq_no, num_descs, socket_id)) {
		cnxk_ep_bb_err("IQ init is failed\n");
		goto delete_IQ;
	}
	cnxk_ep_bb_info("IQ[%d] is created", iq_no);
	return 0;

delete_IQ:
	cnxk_ep_bb_delete_iqs(cnxk_ep_bb_vf, iq_no);
	return -ENOMEM;
}

static void
cnxk_ep_bb_droq_reset_indices(struct cnxk_ep_bb_droq *droq)
{
	droq->read_idx  = 0;
	droq->write_idx = 0;
	droq->refill_idx = 0;
	droq->refill_count = 0;
	droq->last_pkt_count = 0;
	droq->pkts_pending = 0;
}

static void
cnxk_ep_bb_droq_destroy_ring_buffers(struct cnxk_ep_bb_droq *droq)
{
	uint32_t idx;

	for (idx = 0; idx < droq->nb_desc; idx++) {
		if (droq->recv_buf_list[idx]) {
			rte_pktmbuf_free(droq->recv_buf_list[idx]);
			droq->recv_buf_list[idx] = NULL;
		}
	}

	cnxk_ep_bb_droq_reset_indices(droq);
}

/* Free OQs resources */
int
cnxk_ep_bb_delete_oqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t oq_no)
{
	struct cnxk_ep_bb_droq *droq;

	droq = cnxk_ep_bb_vf->droq[oq_no];
	if (droq == NULL) {
		cnxk_ep_bb_err("Invalid droq[%d]\n", oq_no);
		return -EINVAL;
	}

	cnxk_ep_bb_droq_destroy_ring_buffers(droq);
	rte_free(droq->recv_buf_list);
	droq->recv_buf_list = NULL;

	if (droq->desc_ring_mz) {
		cnxk_ep_bb_dmazone_free(droq->desc_ring_mz);
		droq->desc_ring_mz = NULL;
	}

	memset(droq, 0, CNXK_EP_BB_DROQ_SIZE);

	rte_free(cnxk_ep_bb_vf->droq[oq_no]);
	cnxk_ep_bb_vf->droq[oq_no] = NULL;

	cnxk_ep_bb_vf->nb_rx_queues--;

	cnxk_ep_bb_info("OQ[%d] is deleted", oq_no);
	return 0;
}

static int
cnxk_ep_bb_droq_setup_ring_buffers(struct cnxk_ep_bb_droq *droq)
{
	struct cnxk_ep_bb_droq_desc *desc_ring = droq->desc_ring;
	struct cnxk_ep_bb_droq_info *info;
	struct rte_mbuf *buf;
	uint32_t idx;

	for (idx = 0; idx < droq->nb_desc; idx++) {
		buf = rte_pktmbuf_alloc(droq->mpool);
		if (buf == NULL) {
			cnxk_ep_bb_err("OQ buffer alloc failed\n");
			droq->stats.rx_alloc_failure++;
			return -ENOMEM;
		}

		droq->recv_buf_list[idx] = buf;
		info = rte_pktmbuf_mtod(buf, struct cnxk_ep_bb_droq_info *);
		memset(info, 0, sizeof(*info));
		desc_ring[idx].buffer_ptr = rte_mbuf_data_iova_default(buf);
	}

	cnxk_ep_bb_droq_reset_indices(droq);

	return 0;
}

/* OQ initialization */
static int
cnxk_ep_bb_init_droq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no,
	      uint32_t num_descs, uint32_t desc_size,
	      struct rte_mempool *mpool, unsigned int socket_id)
{
	const struct cnxk_ep_bb_config *conf = cnxk_ep_bb_vf->conf;
	uint32_t c_refill_threshold;
	struct cnxk_ep_bb_droq *droq;
	uint32_t desc_ring_size;
	int ret;

	cnxk_ep_bb_info("OQ[%d] Init start", q_no);

	droq = cnxk_ep_bb_vf->droq[q_no];
	droq->cnxk_ep_bb_dev = cnxk_ep_bb_vf;
	droq->q_no = q_no;
	droq->mpool = mpool;

	droq->nb_desc      = num_descs;
	droq->buffer_size  = desc_size;
	c_refill_threshold = RTE_MAX(conf->oq.refill_threshold,
				     droq->nb_desc / 2);

	/* OQ desc_ring set up */
	desc_ring_size = droq->nb_desc * CNXK_EP_BB_DROQ_DESC_SIZE;
	droq->desc_ring_mz = cnxk_ep_bb_dmazone_reserve(cnxk_ep_bb_vf->bbdev->data->dev_id, "droq",
					q_no, desc_ring_size, CNXK_EP_BB_PCI_RING_ALIGN, socket_id);

	if (droq->desc_ring_mz == NULL) {
		cnxk_ep_bb_err("OQ:%d desc_ring allocation failed\n", q_no);
		goto init_droq_fail;
	}
	droq->desc_ring_dma = droq->desc_ring_mz->iova;
	droq->desc_ring = (struct cnxk_ep_bb_droq_desc *)droq->desc_ring_mz->addr;

	cnxk_ep_bb_dbg("OQ[%d]: desc_ring: virt: 0x%p, dma: %" PRIx64,
		    q_no, droq->desc_ring, (unsigned long)droq->desc_ring_dma);
	cnxk_ep_bb_dbg("OQ[%d]: num_desc: %d", q_no, droq->nb_desc);

	/* OQ buf_list set up */
	droq->recv_buf_list = rte_zmalloc_socket("recv_buf_list",
				(droq->nb_desc * sizeof(struct rte_mbuf *)),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (droq->recv_buf_list == NULL) {
		cnxk_ep_bb_err("OQ recv_buf_list alloc failed\n");
		goto init_droq_fail;
	}

	if (cnxk_ep_bb_droq_setup_ring_buffers(droq))
		goto init_droq_fail;

	droq->refill_threshold = c_refill_threshold;

	/* Set up OQ registers */
	ret = cnxk_ep_bb_vf->fn_list.setup_oq_regs(cnxk_ep_bb_vf, q_no);
	if (ret)
		return ret;

	cnxk_ep_bb_vf->io_qmask.oq |= (1ull << q_no);

	return 0;

init_droq_fail:
	return -ENOMEM;
}

/* OQ configuration and setup */
int
cnxk_ep_bb_setup_oqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, int oq_no, int num_descs,
		 int desc_size, struct rte_mempool *mpool,
		 unsigned int socket_id)
{
	struct cnxk_ep_bb_droq *droq;

	/* Allocate new droq. */
	droq = (struct cnxk_ep_bb_droq *)rte_zmalloc("cnxk_ep_bb_OQ",
				sizeof(*droq), RTE_CACHE_LINE_SIZE);
	if (droq == NULL) {
		cnxk_ep_bb_err("Droq[%d] Creation Failed\n", oq_no);
		return -ENOMEM;
	}
	cnxk_ep_bb_vf->droq[oq_no] = droq;

	cnxk_ep_bb_vf->nb_rx_queues++;
	if (cnxk_ep_bb_init_droq(cnxk_ep_bb_vf, oq_no, num_descs, desc_size, mpool,
			     socket_id)) {
		cnxk_ep_bb_err("Droq[%d] Initialization failed\n", oq_no);
		goto delete_OQ;
	}
	cnxk_ep_bb_info("OQ[%d] is created", oq_no);
	return 0;

delete_OQ:
	cnxk_ep_bb_delete_oqs(cnxk_ep_bb_vf, oq_no);
	return -ENOMEM;
}

static inline void
cnxk_ep_bb_iqreq_delete(struct cnxk_ep_bb_instr_queue *iq, uint32_t idx)
{
	uint32_t reqtype;
	void *buf;
	struct cnxk_ep_bb_buf_free_info *finfo;

	buf     = iq->req_list[idx].buf;
	reqtype = iq->req_list[idx].reqtype;

	switch (reqtype) {
	case CNXK_EP_BB_REQTYPE_NORESP_NET:
		/* These mbufs will be freed after response arrives
		 * rte_pktmbuf_free((struct rte_mbuf *)buf);
		 * cnxk_ep_bb_dbg("IQ buffer freed at idx[%d]\n", idx);
		 */
		break;

	case CNXK_EP_BB_REQTYPE_NORESP_GATHER:
		finfo = (struct  cnxk_ep_bb_buf_free_info *)buf;
		/* This will take care of multiple segments also */
		cnxk_ep_bb_err("error: bbdev cmd/op IQ should not free scatter buffer\n");
		rte_pktmbuf_free(finfo->mbuf);
		rte_free(finfo->g.sg);
		rte_free(finfo);
		break;

	case CNXK_EP_BB_REQTYPE_NONE:
	default:
		cnxk_ep_bb_info("This iqreq mode is not supported:%d\n", reqtype);
	}

	/* Reset the request list at this index */
	iq->req_list[idx].buf = NULL;
	iq->req_list[idx].reqtype = 0;
}

static inline void
cnxk_ep_bb_iqreq_add(struct cnxk_ep_bb_instr_queue *iq, void *buf,
		uint32_t reqtype, int index)
{
	iq->req_list[index].buf = buf;
	iq->req_list[index].reqtype = reqtype;
}

static uint32_t
otx_vf_update_read_index(struct cnxk_ep_bb_instr_queue *iq)
{
	uint32_t val;

	/*
	 * Batch subtractions from the HW counter to reduce PCIe traffic
	 * This adds an extra local variable, but almost halves the
	 * number of PCIe writes.
	 */
	val = *iq->inst_cnt_ism;
	iq->inst_cnt += val - iq->inst_cnt_ism_prev;
	iq->inst_cnt_ism_prev = val;

	if (val > (uint32_t)(1 << 31)) {
		/*
		 * Only subtract the packet count in the HW counter
		 * when count above halfway to saturation.
		 */
		rte_write32(val, iq->inst_cnt_reg);
		*iq->inst_cnt_ism = 0;
		iq->inst_cnt_ism_prev = 0;
	}
	rte_write64(OTX2_SDP_REQUEST_ISM, iq->inst_cnt_reg);

	/* Modulo of the new index with the IQ size will give us
	 * the new index.
	 */
	return iq->inst_cnt & (iq->nb_desc - 1);
}

static void
cnxk_ep_bb_flush_iq(struct cnxk_ep_bb_instr_queue *iq)
{
	uint32_t instr_processed = 0;

	iq->otx_read_index = otx_vf_update_read_index(iq);
	while (iq->flush_index != iq->otx_read_index) {
		/* Free the IQ data buffer to the pool */
		cnxk_ep_bb_iqreq_delete(iq, iq->flush_index);
		iq->flush_index =
			cnxk_ep_bb_incr_index(iq->flush_index, 1, iq->nb_desc);

		instr_processed++;
	}

	iq->stats.instr_processed = instr_processed;
	iq->instr_pending -= instr_processed;
}

static inline void
cnxk_ep_bb_ring_doorbell(struct cnxk_ep_bb_device *cnxk_ep_bb_vf __rte_unused,
		struct cnxk_ep_bb_instr_queue *iq)
{
	rte_wmb();
	rte_write64(iq->fill_cnt, iq->doorbell_reg);
	iq->fill_cnt = 0;
}

static inline int
post_iqcmd(struct cnxk_ep_bb_instr_queue *iq, uint8_t *iqcmd)
{
	uint8_t *iqptr, cmdsize;

	/* This ensures that the read index does not wrap around to
	 * the same position if queue gets full before OCTEON TX2 could
	 * fetch any instr.
	 */
	if (iq->instr_pending > (iq->nb_desc - 1))
		return CNXK_EP_BB_IQ_SEND_FAILED;

	/* Copy cmd into iq */
	cmdsize = 64;
	iqptr   = iq->base_addr + (iq->host_write_index << 6);

	rte_memcpy(iqptr, iqcmd, cmdsize);

	/* Increment the host write index */
	iq->host_write_index =
		cnxk_ep_bb_incr_index(iq->host_write_index, 1, iq->nb_desc);

	iq->fill_cnt++;

	/* Flush the command into memory. We need to be sure the data
	 * is in memory before indicating that the instruction is
	 * pending.
	 */
	iq->instr_pending++;
	/* CNXK_EP_BB_IQ_SEND_SUCCESS */
	return 0;
}


static int
cnxk_ep_bb_send_data(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, struct cnxk_ep_bb_instr_queue *iq,
		 void *cmd, int dbell)
{
	uint32_t ret;

	/* Submit IQ command */
	ret = post_iqcmd(iq, cmd);

	if (ret == CNXK_EP_BB_IQ_SEND_SUCCESS) {
		if (dbell)
			cnxk_ep_bb_ring_doorbell(cnxk_ep_bb_vf, iq);
		iq->stats.instr_posted++;

	} else {
		iq->stats.instr_dropped++;
		if (iq->fill_cnt)
			cnxk_ep_bb_ring_doorbell(cnxk_ep_bb_vf, iq);
	}
	return ret;
}

static inline void
set_sg_size(struct cnxk_ep_bb_sg_entry *sg_entry, uint16_t size, uint32_t pos)
{
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	sg_entry->u.size[pos] = size;
#elif RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	sg_entry->u.size[3 - pos] = size;
#endif
}

#ifdef TODO_ADD_FOR_OTX
/* Enqueue requests/packets to OTX_EP IQ queue.
 * returns number of requests enqueued successfully
 */
uint16_t
otx_bb_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	struct cnxk_ep_bb_instr_64B iqcmd;
	struct cnxk_ep_bb_instr_queue *iq;
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf;
	struct rte_mbuf *m;

	uint32_t iqreq_type, sgbuf_sz;
	int dbell, index, count = 0;
	unsigned int pkt_len, i;
	int gather, gsz;
	void *iqreq_buf;
	uint64_t dptr;

	iq = (struct cnxk_ep_bb_instr_queue *)tx_queue;
	cnxk_ep_bb_vf = iq->cnxk_ep_bb_dev;

	iqcmd.ih.u64 = 0;
	iqcmd.pki_ih3.u64 = 0;
	iqcmd.irh.u64 = 0;

	/* ih invars */
	iqcmd.ih.s.fsz = CNXK_EP_BB_FSZ;
	iqcmd.ih.s.pkind = cnxk_ep_bb_vf->pkind; /* The SDK decided PKIND value */

	/* pki ih3 invars */
	iqcmd.pki_ih3.s.w = 1;
	iqcmd.pki_ih3.s.utt = 1;
	iqcmd.pki_ih3.s.tagtype = ORDERED_TAG;
	/* sl will be sizeof(pki_ih3) */
	iqcmd.pki_ih3.s.sl = CNXK_EP_BB_FSZ + OTX_CUST_DATA_LEN;

	/* irh invars */
	iqcmd.irh.s.opcode = CNXK_EP_BB_NW_PKT_OP;

	for (i = 0; i < nb_pkts; i++) {
		m = pkts[i];
		if (m->nb_segs == 1) {
			/* dptr */
			dptr = rte_mbuf_data_iova(m);
			pkt_len = rte_pktmbuf_data_len(m);
			iqreq_buf = m;
			iqreq_type = CNXK_EP_BB_REQTYPE_NORESP_NET;
			gather = 0;
			gsz = 0;
		} else {
			struct cnxk_ep_bb_buf_free_info *finfo;
			int j, frags, num_sg;

			if (!(cnxk_ep_bb_vf->tx_offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS))
				goto xmit_fail;

			finfo = (struct cnxk_ep_bb_buf_free_info *)rte_malloc(NULL,
							sizeof(*finfo), 0);
			if (finfo == NULL) {
				cnxk_ep_bb_err("free buffer alloc failed\n");
				goto xmit_fail;
			}
			num_sg = (m->nb_segs + 3) / 4;
			sgbuf_sz = sizeof(struct cnxk_ep_bb_sg_entry) * num_sg;
			finfo->g.sg =
				rte_zmalloc(NULL, sgbuf_sz, CNXK_EP_BB_SG_ALIGN);
			if (finfo->g.sg == NULL) {
				rte_free(finfo);
				cnxk_ep_bb_err("sg entry alloc failed\n");
				goto xmit_fail;
			}
			gather = 1;
			gsz = m->nb_segs;
			finfo->g.num_sg = num_sg;
			finfo->g.sg[0].ptr[0] = rte_mbuf_data_iova(m);
			set_sg_size(&finfo->g.sg[0], m->data_len, 0);
			pkt_len = m->data_len;
			finfo->mbuf = m;

			frags = m->nb_segs - 1;
			j = 1;
			m = m->next;
			while (frags--) {
				finfo->g.sg[(j >> 2)].ptr[(j & 3)] =
						rte_mbuf_data_iova(m);
				set_sg_size(&finfo->g.sg[(j >> 2)],
						m->data_len, (j & 3));
				pkt_len += m->data_len;
				j++;
				m = m->next;
			}
			dptr = rte_mem_virt2iova(finfo->g.sg);
			iqreq_buf = finfo;
			iqreq_type = CNXK_EP_BB_REQTYPE_NORESP_GATHER;
			if (pkt_len > CNXK_EP_BB_MAX_PKT_SZ) {
				rte_free(finfo->g.sg);
				rte_free(finfo);
				cnxk_ep_bb_err("failed\n");
				goto xmit_fail;
			}
		}
		/* ih vars */
		iqcmd.ih.s.tlen = pkt_len + iqcmd.ih.s.fsz;
		iqcmd.ih.s.gather = gather;
		iqcmd.ih.s.gsz = gsz;

		iqcmd.dptr = dptr;
		cnxk_ep_bb_swap_8B_data(&iqcmd.irh.u64, 1);

#ifdef CNXK_EP_BB_IO_DEBUG
		cnxk_ep_bb_dbg("After swapping\n");
		cnxk_ep_bb_dbg("Word0 [dptr]: 0x%016lx\n",
			   (unsigned long)iqcmd.dptr);
		cnxk_ep_bb_dbg("Word1 [ihtx]: 0x%016lx\n", (unsigned long)iqcmd.ih);
		cnxk_ep_bb_dbg("Word2 [pki_ih3]: 0x%016lx\n",
			   (unsigned long)iqcmd.pki_ih3);
		cnxk_ep_bb_dbg("Word3 [rptr]: 0x%016lx\n",
			   (unsigned long)iqcmd.rptr);
		cnxk_ep_bb_dbg("Word4 [irh]: 0x%016lx\n", (unsigned long)iqcmd.irh);
		cnxk_ep_bb_dbg("Word5 [exhdr[0]]: 0x%016lx\n",
				(unsigned long)iqcmd.exhdr[0]);
		rte_pktmbuf_dump(stdout, m, rte_pktmbuf_pkt_len(m));
#endif
		dbell = (i == (unsigned int)(nb_pkts - 1)) ? 1 : 0;
		index = iq->host_write_index;
		if (cnxk_ep_bb_send_data(cnxk_ep_bb_vf, iq, &iqcmd, dbell))
			goto xmit_fail;
		cnxk_ep_bb_iqreq_add(iq, iqreq_buf, iqreq_type, index);
		iq->stats.tx_pkts++;
		iq->stats.tx_bytes += pkt_len;
		count++;
	}

xmit_fail:
	if (iq->instr_pending >= CNXK_EP_BB_MAX_INSTR)
		cnxk_ep_bb_flush_iq(iq);

	/* Return no# of instructions posted successfully. */
	return count;
}
#endif

/* Enqueue requests/packets to OTX_EP IQ queue.
 * returns number of requests enqueued successfully
 */
uint16_t
cnxk_ep_bb_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	struct cnxk_ep_bb_instr_64B iqcmd2;
	struct cnxk_ep_bb_instr_queue *iq;
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf;
	uint64_t dptr;
	int count = 0;
	unsigned int i;
	struct rte_mbuf *m;
	unsigned int pkt_len;
	void *iqreq_buf;
	uint32_t iqreq_type, sgbuf_sz;
	int gather, gsz;
	int dbell;
	int index;

	iq = (struct cnxk_ep_bb_instr_queue *)tx_queue;
	cnxk_ep_bb_vf = iq->cnxk_ep_bb_dev;

	iqcmd2.ih.u64 = 0;
	iqcmd2.irh.u64 = 0;

	/* ih invars */
	iqcmd2.ih.s.fsz = front_size[cnxk_ep_bb_vf->sdp_packet_mode];
	iqcmd2.ih.s.pkind = cnxk_ep_bb_vf->pkind; /* The SDK decided PKIND value */
	/* irh invars, ignored in LOOP mode */
	iqcmd2.irh.s.opcode = CNXK_EP_BB_NW_PKT_OP;

	for (i = 0; i < nb_pkts; i++) {
		m = pkts[i];
		if (m->nb_segs == 1) {
			/* dptr */
			dptr = rte_mbuf_data_iova(m);
			pkt_len = rte_pktmbuf_data_len(m);
			iqreq_buf = m;
			iqreq_type = CNXK_EP_BB_REQTYPE_NORESP_NET;
			gather = 0;
			gsz = 0;
		} else {
			struct cnxk_ep_bb_buf_free_info *finfo;
			int j, frags, num_sg;
			if (!(cnxk_ep_bb_vf->tx_offloads & EPDEV_TX_OFFLOAD_MULTI_SEGS))
				goto xmit_fail;
			finfo = (struct cnxk_ep_bb_buf_free_info *)
					rte_malloc(NULL, sizeof(*finfo), 0);
			if (finfo == NULL) {
				cnxk_ep_bb_err("free buffer alloc failed\n");
				goto xmit_fail;
			}
			num_sg = (m->nb_segs + 3) / 4;
			sgbuf_sz = sizeof(struct cnxk_ep_bb_sg_entry) * num_sg;
			finfo->g.sg =
				rte_zmalloc(NULL, sgbuf_sz, CNXK_EP_BB_SG_ALIGN);
			if (finfo->g.sg == NULL) {
				rte_free(finfo);
				cnxk_ep_bb_err("sg entry alloc failed\n");
				goto xmit_fail;
			}
			gather = 1;
			gsz = m->nb_segs;
			finfo->g.num_sg = num_sg;
			finfo->g.sg[0].ptr[0] = rte_mbuf_data_iova(m);
			set_sg_size(&finfo->g.sg[0], m->data_len, 0);
			pkt_len = m->data_len;
			finfo->mbuf = m;

			frags = m->nb_segs - 1;
			j = 1;
			m = m->next;
			while (frags--) {
				finfo->g.sg[(j >> 2)].ptr[(j & 3)] =
						rte_mbuf_data_iova(m);
				set_sg_size(&finfo->g.sg[(j >> 2)],
						m->data_len, (j & 3));
				pkt_len += m->data_len;
				j++;
				m = m->next;
			}
			dptr = rte_mem_virt2iova(finfo->g.sg);
			iqreq_buf = finfo;
			iqreq_type = CNXK_EP_BB_REQTYPE_NORESP_GATHER;
			if (pkt_len > CNXK_EP_BB_MAX_PKT_SZ) {
				rte_free(finfo->g.sg);
				rte_free(finfo);
				cnxk_ep_bb_err("failed\n");
				goto xmit_fail;
			}
		}
		/* ih vars */
		iqcmd2.ih.s.tlen = pkt_len + iqcmd2.ih.s.fsz;
		iqcmd2.ih.s.gather = gather;
		iqcmd2.ih.s.gsz = gsz;
		iqcmd2.dptr = dptr;
		cnxk_ep_bb_swap_8B_data(&iqcmd2.irh.u64, 1);

#ifdef CNXK_EP_BB_IO_DEBUG
		cnxk_ep_bb_dbg("After swapping\n");
		cnxk_ep_bb_dbg("Word0 [dptr]: 0x%016lx\n",
			   (unsigned long)iqcmd.dptr);
		cnxk_ep_bb_dbg("Word1 [ihtx]: 0x%016lx\n", (unsigned long)iqcmd.ih);
		cnxk_ep_bb_dbg("Word2 [pki_ih3]: 0x%016lx\n",
			   (unsigned long)iqcmd.pki_ih3);
		cnxk_ep_bb_dbg("Word3 [rptr]: 0x%016lx\n",
			   (unsigned long)iqcmd.rptr);
		cnxk_ep_bb_dbg("Word4 [irh]: 0x%016lx\n", (unsigned long)iqcmd.irh);
		cnxk_ep_bb_dbg("Word5 [exhdr[0]]: 0x%016lx\n",
			   (unsigned long)iqcmd.exhdr[0]);
#endif
		index = iq->host_write_index;
		dbell = (i == (unsigned int)(nb_pkts - 1)) ? 1 : 0;
		if (cnxk_ep_bb_send_data(cnxk_ep_bb_vf, iq, &iqcmd2, dbell))
			goto xmit_fail;
		cnxk_ep_bb_iqreq_add(iq, iqreq_buf, iqreq_type, index);
		iq->stats.tx_pkts++;
		iq->stats.tx_bytes += pkt_len;
		count++;
	}

xmit_fail:
	if (iq->instr_pending >= CNXK_EP_BB_MAX_INSTR)
		cnxk_ep_bb_flush_iq(iq);

	/* Return no# of instructions posted successfully. */
	return count;
}

static uint32_t
cnxk_ep_bb_droq_refill(struct cnxk_ep_bb_droq *droq)
{
	struct cnxk_ep_bb_droq_desc *desc_ring;
	struct cnxk_ep_bb_droq_info *info;
	struct rte_mbuf *buf = NULL;
	uint32_t desc_refilled = 0;

	desc_ring = droq->desc_ring;

	while (droq->refill_count && (desc_refilled < droq->nb_desc)) {
		/* If a valid buffer exists (happens if there is no dispatch),
		 * reuse the buffer, else allocate.
		 */
		if (droq->recv_buf_list[droq->refill_idx] != NULL)
			break;

		buf = rte_pktmbuf_alloc(droq->mpool);
		/* If a buffer could not be allocated, no point in
		 * continuing
		 */
		if (buf == NULL) {
			droq->stats.rx_alloc_failure++;
			break;
		}
		info = rte_pktmbuf_mtod(buf, struct cnxk_ep_bb_droq_info *);
		memset(info, 0, sizeof(*info));

		droq->recv_buf_list[droq->refill_idx] = buf;
		desc_ring[droq->refill_idx].buffer_ptr =
					rte_mbuf_data_iova_default(buf);


		droq->refill_idx = cnxk_ep_bb_incr_index(droq->refill_idx, 1,
				droq->nb_desc);

		desc_refilled++;
		droq->refill_count--;
	}

	return desc_refilled;
}

static struct rte_mbuf *
cnxk_ep_bb_droq_read_packet(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
			struct cnxk_ep_bb_droq *droq, int next_fetch)
{
	volatile struct cnxk_ep_bb_droq_info *info;
	struct rte_mbuf *droq_pkt2 = NULL;
	struct rte_mbuf *droq_pkt = NULL;
	struct cnxk_ep_bb_droq_info *info2;
	uint64_t total_pkt_len;
	uint32_t pkt_len = 0;
	int next_idx;
	int info_size;

	info_size = droq_info_size[cnxk_ep_bb_vf->sdp_packet_mode];
	droq_pkt  = droq->recv_buf_list[droq->read_idx];
	droq_pkt2  = droq->recv_buf_list[droq->read_idx];
	info = rte_pktmbuf_mtod(droq_pkt, struct cnxk_ep_bb_droq_info *);
	/* make sure info is available */
	rte_rmb();
	if (unlikely(!info->length)) {
		int retry = CNXK_EP_BB_MAX_DELAYED_PKT_RETRIES;
		/* cnxk_ep_bb_dbg("OCTEON DROQ[%d]: read_idx: %d; Data not ready "
		 * "yet, Retry; pending=%" PRId64, droq->q_no, droq->read_idx,
		 * droq->pkts_pending);
		 */
		droq->stats.pkts_delayed_data++;
		while (retry && !info->length) {
			retry--;
			rte_delay_us_block(50);
		}
		if (!retry && !info->length) {
			cnxk_ep_bb_err("OCTEON DROQ[%d]: read_idx: %d; Retry failed !!\n",
				   droq->q_no, droq->read_idx);
			assert(0);
		}
	}
	if (next_fetch) {
		next_idx = cnxk_ep_bb_incr_index(droq->read_idx, 1, droq->nb_desc);
		droq_pkt2  = droq->recv_buf_list[next_idx];
		info2 = rte_pktmbuf_mtod(droq_pkt2, struct cnxk_ep_bb_droq_info *);
		rte_prefetch_non_temporal((const void *)info2);
	}

	info->length = rte_bswap64(info->length);
	/* Deduce the actual data size */
	total_pkt_len = info->length + INFO_SIZE;
	if (total_pkt_len <= droq->buffer_size) {
		info->length -=  rh_size[cnxk_ep_bb_vf->sdp_packet_mode];
		droq_pkt  = droq->recv_buf_list[droq->read_idx];
		if (likely(droq_pkt != NULL)) {
			droq_pkt->data_off += info_size;
			/* cnxk_ep_bb_dbg("OQ: pkt_len[%" PRId64 "], buffer_size %d\n",
			 * (long)info->length, droq->buffer_size);
			 */
			pkt_len = (uint32_t)info->length;
			droq_pkt->pkt_len  = pkt_len;
			droq_pkt->data_len  = pkt_len;
			droq_pkt->port = cnxk_ep_bb_vf->port_id;
			droq->recv_buf_list[droq->read_idx] = NULL;
			droq->read_idx = cnxk_ep_bb_incr_index(droq->read_idx, 1,
							   droq->nb_desc);
			droq->refill_count++;
		}
	} else {
		struct rte_mbuf *first_buf = NULL;
		struct rte_mbuf *last_buf = NULL;

		/* initiating a csr read helps to flush pending dma */
		droq->sent_reg_val = rte_read32(droq->pkts_sent_reg);
		rte_rmb();
		while (pkt_len < total_pkt_len) {
			int cpy_len = 0;

			cpy_len = ((pkt_len + droq->buffer_size) >
					total_pkt_len)
					? ((uint32_t)total_pkt_len -
						pkt_len)
					: droq->buffer_size;

			droq_pkt = droq->recv_buf_list[droq->read_idx];
			droq->recv_buf_list[droq->read_idx] = NULL;

			if (likely(droq_pkt != NULL)) {
				/* Note the first seg */
				if (!pkt_len)
					first_buf = droq_pkt;

				droq_pkt->port = cnxk_ep_bb_vf->port_id;
				if (!pkt_len) {
					droq_pkt->data_off +=
						info_size;
					droq_pkt->pkt_len =
						cpy_len - info_size;
					droq_pkt->data_len =
						cpy_len - info_size;
				} else {
					droq_pkt->pkt_len = cpy_len;
					droq_pkt->data_len = cpy_len;
				}

				if (pkt_len) {
					first_buf->nb_segs++;
					first_buf->pkt_len += droq_pkt->pkt_len;
				}

				if (last_buf)
					last_buf->next = droq_pkt;

				last_buf = droq_pkt;
			} else {
				cnxk_ep_bb_err("no recvbuf in jumbo processing\n");
				assert(0);
			}

			pkt_len += cpy_len;
			droq->read_idx = cnxk_ep_bb_incr_index(droq->read_idx, 1,
							   droq->nb_desc);
			droq->refill_count++;
		}
		droq_pkt = first_buf;
	}
	if (droq_pkt->pkt_len > cnxk_ep_bb_vf->max_rx_pktlen) {
		rte_pktmbuf_free(droq_pkt);
		goto oq_read_fail;
	}
	if (droq_pkt->nb_segs > 1 &&
	    !(cnxk_ep_bb_vf->rx_offloads & EPDEV_RX_OFFLOAD_SCATTER)) {
		rte_pktmbuf_free(droq_pkt);
		goto oq_read_fail;
	}
	return droq_pkt;
oq_read_fail:
	return NULL;
}

static inline uint32_t
cnxk_ep_bb_check_droq_pkts(struct cnxk_ep_bb_droq *droq)
{
	uint32_t new_pkts;
	uint32_t val;

	/*
	 * Batch subtractions from the HW counter to reduce PCIe traffic
	 * This adds an extra local variable, but almost halves the
	 * number of PCIe writes.
	 */
	val = *droq->pkts_sent_ism;
	new_pkts = val - droq->pkts_sent_ism_prev;
	droq->pkts_sent_ism_prev = val;

	if (val > (uint32_t)(1 << 31)) {
		/*
		 * Only subtract the packet count in the HW counter
		 * when count above halfway to saturation.
		 */
		rte_write32(val, droq->pkts_sent_reg);
		*droq->pkts_sent_ism = 0;
		droq->pkts_sent_ism_prev = 0;
	}
	rte_write64(OTX2_SDP_REQUEST_ISM, droq->pkts_sent_reg);

	droq->pkts_pending += new_pkts;
	return new_pkts;
}

/* Check for response arrival from OCTEON TX2
 * returns number of requests completed
 */
uint16_t
cnxk_ep_bb_recv_pkts(void *rx_queue,
		  struct rte_mbuf **rx_pkts,
		  uint16_t budget)
{
	struct cnxk_ep_bb_droq *droq = rx_queue;
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf;
	struct rte_mbuf *oq_pkt;

	uint32_t pkts = 0;
	uint32_t valid_pkts = 0;
	uint32_t new_pkts = 0;
	int next_fetch;

	cnxk_ep_bb_vf = droq->cnxk_ep_bb_dev;

	if (droq->pkts_pending > budget) {
		new_pkts = budget;
	} else {
		new_pkts = droq->pkts_pending;
		new_pkts += cnxk_ep_bb_check_droq_pkts(droq);
		if (new_pkts > budget)
			new_pkts = budget;
	}

	if (!new_pkts)
		goto update_credit; /* No pkts at this moment */

	for (pkts = 0; pkts < new_pkts; pkts++) {
		/* Push the received pkt to application */
		next_fetch = (pkts == new_pkts - 1) ? 0 : 1;
		oq_pkt = cnxk_ep_bb_droq_read_packet(cnxk_ep_bb_vf, droq, next_fetch);
		if (!oq_pkt) {
			RTE_LOG_DP(ERR, PMD,
				   "DROQ read pkt failed pending %" PRIu64
				    "last_pkt_count %" PRIu64 "new_pkts %d.\n",
				   droq->pkts_pending, droq->last_pkt_count,
				   new_pkts);
			droq->stats.rx_err++;
			continue;
		} else {
			rx_pkts[valid_pkts] = oq_pkt;
			valid_pkts++;
			/* Stats */
			droq->stats.pkts_received++;
			droq->stats.bytes_received += oq_pkt->pkt_len;
		}
	}
	droq->pkts_pending -= pkts;

	/* Refill DROQ buffers */
update_credit:
	if (droq->refill_count >= DROQ_REFILL_THRESHOLD) {
		int desc_refilled = cnxk_ep_bb_droq_refill(droq);

		/* Flush the droq descriptor data to memory to be sure
		 * that when we update the credits the data in memory is
		 * accurate.
		 */
		rte_wmb();
		rte_write32(desc_refilled, droq->pkts_credit_reg);
	} else {
		/*
		 * SDP output goes into DROP state when output doorbell count
		 * goes below drop count. When door bell count is written with
		 * a value greater than drop count SDP output should come out
		 * of DROP state. Due to a race condition this is not happening.
		 * Writing doorbell register with 0 again may make SDP output
		 * come out of this state.
		 */

		rte_write32(0, droq->pkts_credit_reg);
	}
	return valid_pkts;
}

int
cnxk_ep_bb_dequeue_ops(void *rx_queue, struct rte_mbuf **ops,
				uint16_t budget)
{
	struct cnxk_ep_bb_droq *droq = (struct cnxk_ep_bb_droq *)rx_queue;

	return droq->cnxk_ep_bb_dev->rx_pkt_burst(rx_queue, ops, budget);
}

int
cnxk_ep_bb_enqueue_ops(void *rx_queue, struct rte_mbuf **ops,
				uint16_t nb_ops)
{
	struct cnxk_ep_bb_droq *droq = (struct cnxk_ep_bb_droq *)rx_queue;
	struct cnxk_ep_bb_instr_queue *iq =
		droq->cnxk_ep_bb_dev->instr_queue[droq->q_no];

	return droq->cnxk_ep_bb_dev->tx_pkt_burst(iq, ops, nb_ops);
}
