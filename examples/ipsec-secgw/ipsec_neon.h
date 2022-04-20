/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _IPSEC_NEON_H_
#define _IPSEC_NEON_H_

#include "ipsec.h"

#define FWDSTEP		4
#define MAX_TX_BURST	(MAX_PKT_BURST / 2)
#define BAD_PORT	((uint16_t)-1)

extern xmm_t val_eth[RTE_MAX_ETHPORTS];

/*
 * Group consecutive packets with the same destination port into one burst.
 * To avoid extra latency this is done together with some other packet
 * processing, but after we made a final decision about packet's destination.
 * To do this we maintain:
 * pnum - array of number of consecutive packets with the same dest port for
 * each packet in the input burst.
 * lp - pointer to the last updated element in the pnum.
 * dlp - dest port value lp corresponds to.
 */

#define	GRPSZ	(1 << FWDSTEP)
#define	GRPMSK	(GRPSZ - 1)

#define GROUP_PORT_STEP(dlp, dcp, lp, pn, idx)	do { \
	if (likely((dlp) == (dcp)[(idx)])) {         \
		(lp)[0]++;                           \
	} else {                                     \
		(dlp) = (dcp)[idx];                  \
		(lp) = (pn) + (idx);                 \
		(lp)[0] = 1;                         \
	}                                            \
} while (0)

static const struct {
	uint64_t pnum; /* prebuild 4 values for pnum[]. */
	int32_t  idx;  /* index for new last updated elemnet. */
	uint16_t lpv;  /* add value to the last updated element. */
} gptbl[GRPSZ] = {
	{
		/* 0: a != b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 1: a == b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010002),
		.idx = 4,
		.lpv = 1,
	},
	{
		/* 2: a != b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 3: a == b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020003),
		.idx = 4,
		.lpv = 2,
	},
	{
		/* 4: a != b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 5: a == b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010002),
		.idx = 4,
		.lpv = 1,
	},
	{
		/* 6: a != b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 7: a == b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030004),
		.idx = 4,
		.lpv = 3,
	},
	{
		/* 8: a != b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010001),
		.idx = 3,
		.lpv = 0,
	},
	{
		/* 9: a == b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010002),
		.idx = 3,
		.lpv = 1,
	},
	{
		/* 0xa: a != b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020001),
		.idx = 3,
		.lpv = 0,
	},
	{
		/* 0xb: a == b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020003),
		.idx = 3,
		.lpv = 2,
	},
	{
		/* 0xc: a != b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010001),
		.idx = 2,
		.lpv = 0,
	},
	{
		/* 0xd: a == b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010002),
		.idx = 2,
		.lpv = 1,
	},
	{
		/* 0xe: a != b, b == c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300040001),
		.idx = 1,
		.lpv = 0,
	},
	{
		/* 0xf: a == b, b == c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300040005),
		.idx = 0,
		.lpv = 4,
	},
};


/*
 * Update source and destination MAC addresses in the ethernet header.
 */
static inline void
processx4_step3(struct rte_mbuf *pkts[FWDSTEP], uint16_t dst_port[FWDSTEP],
		uint64_t tx_offloads, bool ip_cksum, uint8_t *l_pkt)
{
	uint32x4_t te[FWDSTEP];
	uint32x4_t ve[FWDSTEP];
	uint32_t *p[FWDSTEP];
	struct rte_mbuf *pkt;
	uint8_t i;

	for (i = 0; i < FWDSTEP; i++) {
		pkt = pkts[i];

		/* Check if it is a large packet */
		if (pkt->pkt_len - RTE_ETHER_HDR_LEN > mtu_size)
			*l_pkt |= 1;

		p[i] = rte_pktmbuf_mtod(pkt, uint32_t *);
		ve[i] = vreinterpretq_u32_s32(val_eth[dst_port[i]]);
		te[i] = vld1q_u32(p[i]);

		/* Update last 4 bytes */
		ve[i] = vsetq_lane_u32(vgetq_lane_u32(te[i], 3), ve[i], 3);
		vst1q_u32(p[i], ve[i]);

		if (ip_cksum) {
			struct rte_ipv4_hdr *ip;

			pkt->ol_flags |= tx_offloads;

			ip = (struct rte_ipv4_hdr *)
				(p[i] + RTE_ETHER_HDR_LEN + 1);
			ip->hdr_checksum = 0;

			/* calculate IPv4 cksum in SW */
			if ((pkt->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0)
				ip->hdr_checksum = rte_ipv4_cksum(ip);
		}

	}
}

/*
 * Group consecutive packets with the same destination port in bursts of 4.
 * Suppose we have array of destination ports:
 * dst_port[] = {a, b, c, d,, e, ... }
 * dp1 should contain: <a, b, c, d>, dp2: <b, c, d, e>.
 * We doing 4 comparisons at once and the result is 4 bit mask.
 * This mask is used as an index into prebuild array of pnum values.
 */
static inline uint16_t *
port_groupx4(uint16_t pn[FWDSTEP + 1], uint16_t *lp, uint16x8_t dp1,
	     uint16x8_t dp2)
{
	union {
		uint16_t u16[FWDSTEP + 1];
		uint64_t u64;
	} *pnum = (void *)pn;

	uint16x8_t mask = {1, 2, 4, 8, 0, 0, 0, 0};
	int32_t v;

	dp1 = vceqq_u16(dp1, dp2);
	dp1 = vandq_u16(dp1, mask);
	v = vaddvq_u16(dp1);

	/* update last port counter. */
	lp[0] += gptbl[v].lpv;
	rte_compiler_barrier();

	/* if dest port value has changed. */
	if (v != GRPMSK) {
		pnum->u64 = gptbl[v].pnum;
		pnum->u16[FWDSTEP] = 1;
		lp = pnum->u16 + gptbl[v].idx;
	}

	return lp;
}

/**
 * Process single packet:
 * Update source and destination MAC addresses in the ethernet header.
 */
static inline void
process_packet(struct rte_mbuf *pkt, uint16_t *dst_port, uint64_t tx_offloads,
	       bool ip_cksum, uint8_t *l_pkt)
{
	struct rte_ether_hdr *eth_hdr;
	uint32x4_t te, ve;

	/* Check if it is a large packet */
	if (pkt->pkt_len - RTE_ETHER_HDR_LEN > mtu_size)
		*l_pkt |= 1;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

	te = vld1q_u32((uint32_t *)eth_hdr);
	ve = vreinterpretq_u32_s32(val_eth[dst_port[0]]);

	ve = vcopyq_laneq_u32(ve, 3, te, 3);
	vst1q_u32((uint32_t *)eth_hdr, ve);

	if (ip_cksum) {
		struct rte_ipv4_hdr *ip;

		pkt->ol_flags |= tx_offloads;

		ip = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		ip->hdr_checksum = 0;

		/* calculate IPv4 cksum in SW */
		if ((pkt->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0)
			ip->hdr_checksum = rte_ipv4_cksum(ip);
	}
}

static inline void
send_packets(struct rte_mbuf *m[], uint16_t port, uint32_t num, bool is_ipv4)
{
	uint8_t proto;
	uint32_t i;

	proto = is_ipv4 ? IPPROTO_IP : IPPROTO_IPV6;
	for (i = 0; i < num; i++)
		send_single_packet(m[i], port, proto);
}

static inline void
send_packetsx4(struct rte_mbuf *m[], uint16_t port, uint32_t num)
{
	unsigned int lcoreid = rte_lcore_id();
	struct lcore_conf *qconf;
	uint32_t len, j, n;

	qconf = &lcore_conf[lcoreid];

	len = qconf->tx_mbufs[port].len;

	/*
	 * If TX buffer for that queue is empty, and we have enough packets,
	 * then send them straightway.
	 */
	if (num >= MAX_TX_BURST && len == 0) {
		n = rte_eth_tx_burst(port, qconf->tx_queue_id[port], m, num);
		core_stats_update_tx(n);
		if (unlikely(n < num)) {
			do {
				rte_pktmbuf_free(m[n]);
			} while (++n < num);
		}
		return;
	}

	/*
	 * Put packets into TX buffer for that queue.
	 */

	n = len + num;
	n = (n > MAX_PKT_BURST) ? MAX_PKT_BURST - len : num;

	j = 0;
	switch (n % FWDSTEP) {
	while (j < n) {
		case 0:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
			/* fallthrough */
		case 3:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
			/* fallthrough */
		case 2:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
			/* fallthrough */
		case 1:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
		}
	}

	len += n;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {

		send_burst(qconf, MAX_PKT_BURST, port);

		/* copy rest of the packets into the TX buffer. */
		len = num - n;
		if (len == 0)
			goto exit;

		j = 0;
		switch (len % FWDSTEP) {
		while (j < len) {
			case 0:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
				/* fallthrough */
			case 3:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
				/* fallthrough */
			case 2:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
				/* fallthrough */
			case 1:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
		}
		}
	}

exit:
	qconf->tx_mbufs[port].len = len;
}

/**
 * Send packets burst to the ports in dst_port array
 */
static __rte_always_inline void
send_multi_pkts(struct rte_mbuf **pkts, uint16_t dst_port[MAX_PKT_BURST],
		int nb_rx, uint64_t tx_offloads, bool ip_cksum, bool is_ipv4)
{
	unsigned int lcoreid = rte_lcore_id();
	uint16_t pnum[MAX_PKT_BURST + 1];
	uint8_t l_pkt = 0;
	uint16_t dlp, *lp;
	int i = 0, k;

	/*
	 * Finish packet processing and group consecutive
	 * packets with the same destination port.
	 */
	k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);

	if (k != 0) {
		uint16x8_t dp1, dp2;

		lp = pnum;
		lp[0] = 1;

		processx4_step3(pkts, dst_port, tx_offloads, ip_cksum, &l_pkt);

		/* dp1: <d[0], d[1], d[2], d[3], ... > */
		dp1 = vld1q_u16(dst_port);

		for (i = FWDSTEP; i != k; i += FWDSTEP) {
			processx4_step3(&pkts[i], &dst_port[i], tx_offloads,
					ip_cksum, &l_pkt);

			/*
			 * dp2:
			 * <d[j-3], d[j-2], d[j-1], d[j], ... >
			 */
			dp2 = vld1q_u16(&dst_port[i - FWDSTEP + 1]);
			lp  = port_groupx4(&pnum[i - FWDSTEP], lp, dp1, dp2);

			/*
			 * dp1:
			 * <d[j], d[j+1], d[j+2], d[j+3], ... >
			 */
			dp1 = vextq_u16(dp2, dp1, FWDSTEP - 1);
		}

		/*
		 * dp2: <d[j-3], d[j-2], d[j-1], d[j-1], ... >
		 */
		dp2 = vextq_u16(dp1, dp1, 1);
		dp2 = vsetq_lane_u16(vgetq_lane_u16(dp2, 2), dp2, 3);
		lp  = port_groupx4(&pnum[i - FWDSTEP], lp, dp1, dp2);

		/*
		 * remove values added by the last repeated
		 * dst port.
		 */
		lp[0]--;
		dlp = dst_port[i - 1];
	} else {
		/* set dlp and lp to the never used values. */
		dlp = BAD_PORT - 1;
		lp = pnum + MAX_PKT_BURST;
	}

	/* Process up to last 3 packets one by one. */
	switch (nb_rx % FWDSTEP) {
	case 3:
		process_packet(pkts[i], dst_port + i, tx_offloads, ip_cksum,
			       &l_pkt);
		GROUP_PORT_STEP(dlp, dst_port, lp, pnum, i);
		i++;
		/* fallthrough */
	case 2:
		process_packet(pkts[i], dst_port + i, tx_offloads, ip_cksum,
			       &l_pkt);
		GROUP_PORT_STEP(dlp, dst_port, lp, pnum, i);
		i++;
		/* fallthrough */
	case 1:
		process_packet(pkts[i], dst_port + i, tx_offloads, ip_cksum,
			       &l_pkt);
		GROUP_PORT_STEP(dlp, dst_port, lp, pnum, i);
	}

	/*
	 * Send packets out, through destination port.
	 * Consecutive packets with the same destination port
	 * are already grouped together.
	 * If destination port for the packet equals BAD_PORT,
	 * then free the packet without sending it out.
	 */
	for (i = 0; i < nb_rx; i += k) {

		uint16_t pn;

		pn = dst_port[i];
		k = pnum[i];

		if (likely(pn != BAD_PORT)) {
			if (l_pkt)
				/* Large packet is present, need to send
				 * individual packets with fragment
				 */
				send_packets(pkts + i, pn, k, is_ipv4);
			else
				send_packetsx4(pkts + i, pn, k);

		} else {
			free_pkts(&pkts[i], k);
			if (is_ipv4)
				core_statistics[lcoreid].lpm4.miss++;
			else
				core_statistics[lcoreid].lpm6.miss++;
		}
	}
}

#endif /* _IPSEC_NEON_H_ */
