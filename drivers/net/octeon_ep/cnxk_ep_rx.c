/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#include "cnxk_ep_rx.h"

#ifdef RTE_ARCH_X86
static __rte_always_inline uint32_t
hadd(__m128i x)
{
	__m128i hi64 = _mm_shuffle_epi32(x, _MM_SHUFFLE(1, 0, 3, 2));
	__m128i sum64 = _mm_add_epi32(hi64, x);
	__m128i hi32 = _mm_shufflelo_epi16(sum64, _MM_SHUFFLE(1, 0, 3, 2));
	__m128i sum32 = _mm_add_epi32(sum64, hi32);
	return _mm_cvtsi128_si32(sum32);
}

static __rte_always_inline void
cnxk_ep_process_pkts_vec_sse(struct rte_mbuf **rx_pkts, struct otx_ep_droq *droq, uint16_t new_pkts)
{
	struct rte_mbuf **recv_buf_list = droq->recv_buf_list;
	uint32_t bytes_rsvd = 0, read_idx = droq->read_idx;
	uint32_t idx0, idx1, idx2, idx3;
	struct rte_mbuf *m0, *m1, *m2, *m3;
	uint16_t nb_desc = droq->nb_desc;
	uint16_t pkts = 0;

	idx0 = read_idx;
	while (pkts < new_pkts) {
		const __m128i bswap_mask = _mm_set_epi8(0xFF, 0xFF, 12, 13, 0xFF, 0xFF, 8, 9, 0xFF,
							0xFF, 4, 5, 0xFF, 0xFF, 0, 1);
		const __m128i cpy_mask = _mm_set_epi8(0xFF, 0xFF, 9, 8, 0xFF, 0xFF, 9, 8, 0xFF,
						      0xFF, 1, 0, 0xFF, 0xFF, 1, 0);
		__m128i s01, s23;

		idx1 = otx_ep_incr_index(idx0, 1, nb_desc);
		idx2 = otx_ep_incr_index(idx1, 1, nb_desc);
		idx3 = otx_ep_incr_index(idx2, 1, nb_desc);

		m0 = recv_buf_list[idx0];
		m1 = recv_buf_list[idx1];
		m2 = recv_buf_list[idx2];
		m3 = recv_buf_list[idx3];

		s01 = _mm_set_epi32(rte_pktmbuf_mtod(m3, struct otx_ep_droq_info *)->length >> 48,
				    rte_pktmbuf_mtod(m1, struct otx_ep_droq_info *)->length >> 48,
				    rte_pktmbuf_mtod(m2, struct otx_ep_droq_info *)->length >> 48,
				    rte_pktmbuf_mtod(m0, struct otx_ep_droq_info *)->length >> 48);
		s01 = _mm_shuffle_epi8(s01, bswap_mask);
		bytes_rsvd += hadd(s01);
		s23 = _mm_shuffle_epi32(s01, _MM_SHUFFLE(3, 3, 1, 1));
		s01 = _mm_shuffle_epi8(s01, cpy_mask);
		s23 = _mm_shuffle_epi8(s23, cpy_mask);

		*(uint64_t *)&m0->pkt_len = _mm_extract_epi64(s01, 0);
		*(uint64_t *)&m1->pkt_len = _mm_extract_epi64(s01, 1);
		*(uint64_t *)&m2->pkt_len = _mm_extract_epi64(s23, 0);
		*(uint64_t *)&m3->pkt_len = _mm_extract_epi64(s23, 1);

		*(uint64_t *)&m0->rearm_data = droq->rearm_data;
		*(uint64_t *)&m1->rearm_data = droq->rearm_data;
		*(uint64_t *)&m2->rearm_data = droq->rearm_data;
		*(uint64_t *)&m3->rearm_data = droq->rearm_data;

		rx_pkts[pkts++] = m0;
		rx_pkts[pkts++] = m1;
		rx_pkts[pkts++] = m2;
		rx_pkts[pkts++] = m3;
		idx0 = otx_ep_incr_index(idx3, 1, nb_desc);
	}
	droq->read_idx = idx0;

	droq->refill_count += new_pkts;
	droq->pkts_pending -= new_pkts;
	/* Stats */
	droq->stats.pkts_received += new_pkts;
	droq->stats.bytes_received += bytes_rsvd;
}

#endif

static __rte_always_inline void
cnxk_ep_process_pkts_scalar_mseg(struct rte_mbuf **rx_pkts, struct otx_ep_droq *droq,
				 uint16_t new_pkts)
{
	struct rte_mbuf **recv_buf_list = droq->recv_buf_list;
	uint32_t total_pkt_len, bytes_rsvd = 0;
	uint16_t port_id = droq->otx_ep_dev->port_id;
	uint16_t nb_desc = droq->nb_desc;
	uint16_t pkts;

	for (pkts = 0; pkts < new_pkts; pkts++) {
		struct otx_ep_droq_info *info;
		struct rte_mbuf *first_buf = NULL;
		struct rte_mbuf *last_buf = NULL;
		struct rte_mbuf *mbuf;
		uint32_t pkt_len = 0;

		mbuf = recv_buf_list[droq->read_idx];
		info = rte_pktmbuf_mtod(mbuf, struct otx_ep_droq_info *);

		total_pkt_len = rte_bswap16(info->length >> 48) + OTX_EP_INFO_SIZE;

		while (pkt_len < total_pkt_len) {
			int cpy_len;

			cpy_len = ((pkt_len + droq->buffer_size) > total_pkt_len)
					? ((uint32_t)total_pkt_len - pkt_len) : droq->buffer_size;

			mbuf = droq->recv_buf_list[droq->read_idx];

			if (!pkt_len) {
				/* Note the first seg */
				first_buf = mbuf;
				mbuf->data_off += OTX_EP_INFO_SIZE;
				mbuf->pkt_len = cpy_len - OTX_EP_INFO_SIZE;
				mbuf->data_len = cpy_len - OTX_EP_INFO_SIZE;
			} else {
				mbuf->pkt_len = cpy_len;
				mbuf->data_len = cpy_len;
				first_buf->nb_segs++;
				first_buf->pkt_len += mbuf->pkt_len;
			}

			if (last_buf)
				last_buf->next = mbuf;

			last_buf = mbuf;

			pkt_len += cpy_len;
			droq->read_idx = otx_ep_incr_index(droq->read_idx, 1, nb_desc);
			droq->refill_count++;
		}
		mbuf = first_buf;
		mbuf->port = port_id;
		rx_pkts[pkts] = mbuf;
		bytes_rsvd += pkt_len;
	}

	droq->refill_count += new_pkts;
	droq->pkts_pending -= pkts;
	/* Stats */
	droq->stats.pkts_received += pkts;
	droq->stats.bytes_received += bytes_rsvd;
}

uint16_t __rte_noinline __rte_hot
cnxk_ep_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct otx_ep_droq *droq = (struct otx_ep_droq *)rx_queue;
	uint16_t new_pkts;

	new_pkts = cnxk_ep_rx_pkts_to_process(droq, nb_pkts);
	cnxk_ep_process_pkts_scalar(rx_pkts, droq, new_pkts);

	/* Refill RX buffers */
	if (droq->refill_count >= DROQ_REFILL_THRESHOLD)
		cnxk_ep_rx_refill(droq);

	return new_pkts;
}

#ifdef RTE_ARCH_X86
uint16_t __rte_noinline __rte_hot
cnxk_ep_recv_pkts_sse(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct otx_ep_droq *droq = (struct otx_ep_droq *)rx_queue;
	uint16_t new_pkts, vpkts;

	new_pkts = cnxk_ep_rx_pkts_to_process(droq, nb_pkts);
	vpkts = RTE_ALIGN_FLOOR(new_pkts, CNXK_EP_OQ_DESC_PER_LOOP_SSE);
	cnxk_ep_process_pkts_vec_sse(rx_pkts, droq, vpkts);
	cnxk_ep_process_pkts_scalar(&rx_pkts[vpkts], droq, new_pkts - vpkts);

	/* Refill RX buffers */
	if (droq->refill_count >= DROQ_REFILL_THRESHOLD)
		cnxk_ep_rx_refill(droq);

	return new_pkts;
}
#endif

uint16_t __rte_noinline __rte_hot
cn9k_ep_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct otx_ep_droq *droq = (struct otx_ep_droq *)rx_queue;
	uint16_t new_pkts;

	new_pkts = cnxk_ep_rx_pkts_to_process(droq, nb_pkts);
	cnxk_ep_process_pkts_scalar(rx_pkts, droq, new_pkts);

	/* Refill RX buffers */
	if (droq->refill_count >= DROQ_REFILL_THRESHOLD) {
		cnxk_ep_rx_refill(droq);
	} else {
		/* SDP output goes into DROP state when output doorbell count
		 * goes below drop count. When door bell count is written with
		 * a value greater than drop count SDP output should come out
		 * of DROP state. Due to a race condition this is not happening.
		 * Writing doorbell register with 0 again may make SDP output
		 * come out of this state.
		 */

		rte_write32(0, droq->pkts_credit_reg);
	}

	return new_pkts;
}

#ifdef RTE_ARCH_X86
uint16_t __rte_noinline __rte_hot
cn9k_ep_recv_pkts_sse(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct otx_ep_droq *droq = (struct otx_ep_droq *)rx_queue;
	uint16_t new_pkts, vpkts;

	new_pkts = cnxk_ep_rx_pkts_to_process(droq, nb_pkts);
	vpkts = RTE_ALIGN_FLOOR(new_pkts, CNXK_EP_OQ_DESC_PER_LOOP_SSE);
	cnxk_ep_process_pkts_vec_sse(rx_pkts, droq, vpkts);
	cnxk_ep_process_pkts_scalar(&rx_pkts[vpkts], droq, new_pkts - vpkts);

	/* Refill RX buffers */
	if (droq->refill_count >= DROQ_REFILL_THRESHOLD) {
		cnxk_ep_rx_refill(droq);
	} else {
		/* SDP output goes into DROP state when output doorbell count
		 * goes below drop count. When door bell count is written with
		 * a value greater than drop count SDP output should come out
		 * of DROP state. Due to a race condition this is not happening.
		 * Writing doorbell register with 0 again may make SDP output
		 * come out of this state.
		 */

		rte_write32(0, droq->pkts_credit_reg);
	}

	return new_pkts;
}

#endif

uint16_t __rte_noinline __rte_hot
cnxk_ep_recv_pkts_mseg(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct otx_ep_droq *droq = (struct otx_ep_droq *)rx_queue;
	uint16_t new_pkts;

	new_pkts = cnxk_ep_rx_pkts_to_process(droq, nb_pkts);
	cnxk_ep_process_pkts_scalar_mseg(rx_pkts, droq, new_pkts);

	/* Refill RX buffers */
	if (droq->refill_count >= DROQ_REFILL_THRESHOLD)
		cnxk_ep_rx_refill(droq);

	return new_pkts;
}

uint16_t __rte_noinline __rte_hot
cn9k_ep_recv_pkts_mseg(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct otx_ep_droq *droq = (struct otx_ep_droq *)rx_queue;
	uint16_t new_pkts;

	new_pkts = cnxk_ep_rx_pkts_to_process(droq, nb_pkts);
	cnxk_ep_process_pkts_scalar_mseg(rx_pkts, droq, new_pkts);

	/* Refill RX buffers */
	if (droq->refill_count >= DROQ_REFILL_THRESHOLD) {
		cnxk_ep_rx_refill(droq);
	} else {
		/* SDP output goes into DROP state when output doorbell count
		 * goes below drop count. When door bell count is written with
		 * a value greater than drop count SDP output should come out
		 * of DROP state. Due to a race condition this is not happening.
		 * Writing doorbell register with 0 again may make SDP output
		 * come out of this state.
		 */

		rte_write32(0, droq->pkts_credit_reg);
	}

	return new_pkts;
}
