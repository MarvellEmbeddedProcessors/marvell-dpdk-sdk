/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include "extbuf_event.h"

#define SRC_IP_ADDR	     ((198U << 24) | (18 << 16) | (0 << 8) | 1)
#define DST_IP_ADDR	     ((198U << 24) | (18 << 16) | (0 << 8) | 2)
#define SRC_UDP_PORT	     9
#define DST_UDP_PORT	     9
#define MAX_NUM_LCORE	     24
#define SEG_LEN		     64
#define USR_BUF_LEN	     (SEG_LEN * 2)
#define BUF_ALIGN	     128
#define MAX_PKT_BURST	     32
#define MEMPOOL_CACHE_SIZE   256
#define PRINT_DELAY_MS	     1000
#define MAGIC_PATTERN	     0xf00dfeed
#define MTU		     8192
#define MAX_TX_BURST_RETRIES 64
#define NUM_FLOWS	     100

#define ERROR(...)                                                             \
	do {                                                                   \
		keep_running = false;                                          \
		rte_mb();                                                      \
		rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, __VA_ARGS__);          \
	} while (0)

#define NOTICE(...) rte_log(RTE_LOG_NOTICE, RTE_LOGTYPE_USER1, __VA_ARGS__)
#define EXIT(...)   rte_exit(EXIT_FAILURE, __VA_ARGS__)

static bool keep_running = true;

struct app_arg {
	bool tx_mode;
	bool perf_mode;
	bool use_tx_compl;
	bool event_tx_compl;
	unsigned int n_queue;
	unsigned int n_desc;
	unsigned int max_pkts;
};

struct queue_info {
	unsigned int lcore;
	uint64_t pkts;
	uint64_t last_count;
	uint64_t dropped;
} __rte_cache_aligned;

struct packet_header {
	struct rte_ether_hdr ether;
	struct rte_ipv4_hdr ipv4;
	struct rte_udp_hdr udp;
} __rte_packed;

struct port_info {
	struct queue_info qinfo[MAX_NUM_LCORE];
	unsigned int portid;
	unsigned int n_queue;
	struct rte_mempool *pool;
	struct rte_mempool *pinned_pool;
	uint64_t last_count;
	uint64_t max_pps;
} __rte_cache_aligned;

struct thread_info {
	struct port_info *pinfo;
	unsigned int qid;
	bool *keep_runnig;
	struct app_arg *arg;
	unsigned int lcore;
	bool launched;
} __rte_cache_aligned;

struct rte_mempool *shinfo_pool;
struct rte_mbuf_ext_shared_info *s[MAX_PKT_BURST];

static void
print_event_stats(struct global_event_resources *rsrc, bool show_pps)
{
	uint64_t pps = 0;
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	pps = ((rsrc->tx_pkts - rsrc->lst_count) * 1000) / PRINT_DELAY_MS;
	if (show_pps) {
		if (pps > rsrc->lst_pps)
			NOTICE("Max PPS for tx completion= %ld\n", pps);
		else
			NOTICE("Max PPS for tx completion= %ld\n", rsrc->lst_pps);
		return;
	}
	NOTICE("%s%s", clr, topLeft);
	NOTICE("PPS = %ld\n", pps);
	rsrc->lst_count = rsrc->tx_pkts;
	rsrc->lst_pps = pps;
}

static void
print_stats(struct port_info *pinfo, unsigned int n_port, struct app_arg *arg,
	    bool show_pps)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	uint64_t pps, pkts, dropped;
	unsigned int p, q;

	NOTICE("%s%s", clr, topLeft);
	NOTICE("\n======================================");
	NOTICE("\nStatistics -- (Perf = %d, Nqueues = %u)", arg->perf_mode,
	       arg->n_queue);
	NOTICE("\n======================================");
	for (p = 0; p < n_port; p++) {
		struct port_info *ptr = &pinfo[p];

		pkts = 0;
		dropped = 0;
		NOTICE("\nPort %u", p);
		NOTICE("\n--------------------------------------");
		for (q = 0; q < arg->n_queue; q++) {
			pkts += ptr->qinfo[q].pkts;
			dropped += ptr->qinfo[q].dropped;
			pps = (ptr->qinfo[q].pkts - ptr->qinfo[q].last_count);
			pps = (pps * 1000) / PRINT_DELAY_MS;
			if (show_pps)
				NOTICE("\nQueue %02u PPS         %16"PRIu64, q,
				       pps);
			ptr->qinfo[q].last_count = ptr->qinfo[q].pkts;
		}

		pps = ((pkts - ptr->last_count) * 1000) / PRINT_DELAY_MS;
		ptr->last_count = pkts;
		if (pps > ptr->max_pps)
			ptr->max_pps = pps;

		if (show_pps) {
			NOTICE("\nCombined PPS         %16"PRIu64, pps);
			NOTICE("\n--------------------------------------");
		}
		NOTICE("\nMaximum PPS          %16"PRIu64
		       "\nTotal %s Pkts        %16"PRIu64
		       "\nTotal Dropped Pkts   %16"PRIu64,
		       ptr->max_pps, arg->tx_mode ? "TX" : "RX", pkts, dropped);
	}
	NOTICE("\n======================================\n");
	fflush(stdout);
}

static void
setup_packet(struct packet_header *hdr, uint32_t pkt_len, unsigned int portid,
	     unsigned int flow)
{
	uint16_t len;

	memset(hdr, 0, sizeof(struct packet_header));

	len = (uint16_t)(pkt_len -
			 sizeof(struct rte_ether_hdr) -
			 sizeof(struct rte_ipv4_hdr));
	hdr->udp.dgram_len = rte_cpu_to_be_16(len);
	hdr->udp.src_port = rte_cpu_to_be_16(SRC_UDP_PORT + flow);
	hdr->udp.dst_port = rte_cpu_to_be_16(DST_UDP_PORT);

	len = (uint16_t)(len + sizeof(struct rte_ipv4_hdr));
	hdr->ipv4.version_ihl = RTE_IPV4_VHL_DEF;
	hdr->ipv4.time_to_live = 64;
	hdr->ipv4.next_proto_id = IPPROTO_UDP;
	hdr->ipv4.dst_addr = rte_cpu_to_be_32(DST_IP_ADDR);
	hdr->ipv4.src_addr = rte_cpu_to_be_32(SRC_IP_ADDR);
	hdr->ipv4.total_length = rte_cpu_to_be_16(len);
	hdr->ipv4.hdr_checksum = rte_ipv4_cksum(&hdr->ipv4);

	rte_eth_macaddr_get(portid, &hdr->ether.src_addr);
	hdr->ether.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
}

static void
initialize(struct port_info *pinfo, struct app_arg *arg)
{
	struct rte_eth_dev_info dev_info;
	unsigned int nb_mbufs, q, portid;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_conf port_lconf;
	struct rte_eth_fc_conf fc_conf;
	uint16_t nb_txd, nb_rxd;
	char name[16];
	int ret;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_NONE,
		},
		.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP,
			},
		},
	};

	portid = pinfo->portid;
	pinfo->n_queue = arg->n_queue;

	/* Create the mbuf pool. */
	nb_mbufs = ((unsigned int)arg->n_desc + MAX_PKT_BURST +
		   MEMPOOL_CACHE_SIZE) * MAX_NUM_LCORE;
	snprintf(name, sizeof(name), "mbuf_pool_%u", portid);
	pinfo->pool =
		rte_pktmbuf_pool_create(name, nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
					MTU, rte_socket_id());
	if (pinfo->pool == NULL)
		EXIT("Cannot init mbuf pool\n");

	snprintf(name, sizeof(name), "mbuf_pinned_pool_%u", portid);
	pinfo->pinned_pool =
		rte_pktmbuf_pool_create(name, nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
				MTU, rte_socket_id());
	if (pinfo->pinned_pool == NULL)
		EXIT("Cannot init mbuf pinned_pool\n");

	snprintf(name, sizeof(name), "mbuf_shinfo_pool_%u", portid);
	shinfo_pool =
		rte_mempool_create(name, nb_mbufs, sizeof(struct rte_mbuf_ext_shared_info),
				   MEMPOOL_CACHE_SIZE, 0, NULL, NULL, NULL, NULL,
				   SOCKET_ID_ANY, 0);
	if (shinfo_pool == NULL)
		EXIT("Cannot init mbuf shinfo_pool\n");

	NOTICE("Initializing port %u... ", portid);

	ret = rte_eth_dev_info_get(portid, &dev_info);
	if (ret != 0)
		EXIT("Error during getting device (port %u) info: %s\n", portid,
		     strerror(-ret));

	port_lconf = port_conf;
	/* Enable Multi Seg */
	if (!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS))
		EXIT("Device doesn't support multi seg\n");
	port_lconf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	/* Disable Fast Free */
	port_lconf.txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the number of queues */
	ret = rte_eth_dev_configure(portid, arg->tx_mode ? 0 : pinfo->n_queue,
				    arg->tx_mode ? pinfo->n_queue : 0,
				    &port_lconf);
	if (ret < 0)
		EXIT("Cannot configure device: err=%d, port=%u\n", ret, portid);

	/* Turn off flow control */
	ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
	if (!ret) {
		fc_conf.mode = RTE_ETH_FC_NONE;
		ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
	}
	if (ret < 0)
		EXIT("Failed to turn off flow control\n");

	nb_txd = arg->tx_mode ? arg->n_desc : 0;
	nb_rxd = arg->tx_mode ? 0 : arg->n_desc;
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (ret < 0)
		EXIT("Cannot adjust number of descs: err=%d, port=%u\n", ret,
		     portid);

	if (arg->tx_mode) {
		/* Initialize TX queue */
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = port_lconf.txmode.offloads;
		for (q = 0; q < pinfo->n_queue; q++) {
			ret = rte_eth_tx_queue_setup(
				portid, q, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
			if (ret < 0)
				EXIT("Tx queue setup err=%d, port=%u\n", ret,
				     portid);
		}
	} else {
		/* Initialize RX queue */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_lconf.rxmode.offloads;
		for (q = 0; q < pinfo->n_queue; q++) {
			ret = rte_eth_rx_queue_setup(
				portid, q, nb_rxd,
				rte_eth_dev_socket_id(portid),
				&rxq_conf, pinfo->pool);
			if (ret < 0)
				EXIT("Rx queue setup err=%d, port=%u\n", ret,
				     portid);
		}
	}

	/* Set MTU */
	ret = rte_eth_dev_set_mtu(portid, MTU);
	if (ret < 0)
		EXIT("Failed to set MTU\n");

	/* Start device */
	rte_eth_promiscuous_enable(portid);
	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		EXIT("rte_eth_dev_start:err=%d, port=%u\n", ret, portid);

	NOTICE("done:\n");
	fflush(stdout);
}

static void
finalize(struct port_info *pinfo)
{
	unsigned int portid;
	int ret;

	portid = pinfo->portid;

	/* Close port */
	NOTICE("Closing port %d...\n", portid);
	ret = rte_eth_dev_stop(portid);
	if (ret != 0)
		EXIT("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
	rte_eth_dev_close(portid);

	/* Free mempool */
	rte_mempool_free(pinfo->pool);

	if (pinfo->pinned_pool)
		rte_mempool_free(pinfo->pinned_pool);
	if (shinfo_pool)
		rte_mempool_free(shinfo_pool);
}

static void
dummy_free_cb(void *addr, void *opaque)
{
	RTE_SET_USED(addr);
	RTE_SET_USED(opaque);
}

static void
free_cb_compl(void *addr, void *opaque)
{
	struct rte_mbuf *m = (struct rte_mbuf *)addr;
	rte_pktmbuf_free(m);
	rte_mempool_put(shinfo_pool, opaque);
}

static void
init_shinfo(struct rte_mbuf_ext_shared_info *s)
{
	s->free_cb = dummy_free_cb;
	s->fcb_opaque = NULL;
	rte_mbuf_ext_refcnt_set(s, 1);
}

static void
init_shinfo_compl(struct rte_mbuf_ext_shared_info *s)
{
	s->free_cb = free_cb_compl;
	s->fcb_opaque = s;
	rte_mbuf_ext_refcnt_set(s, 1);
}

static int
launch_lcore_rx(void *args)
{
	struct rte_mbuf *m, *pkts_burst[MAX_PKT_BURST];
	unsigned int lcore, j, portid, recd, qid;
	struct thread_info *tinfo = args;
	struct queue_info *qinfo;
	struct port_info *pinfo;
	uint64_t *addr;

	rte_mb();
	lcore = rte_lcore_id();
	pinfo = tinfo->pinfo;
	portid = pinfo->portid;
	qid = tinfo->qid;
	qinfo = &pinfo->qinfo[qid];
	NOTICE("Entering RX main loop on lcore %u portid=%u qid=%u\n", lcore,
	       portid, qid);
	fflush(stdout);

	while (keep_running) {
		recd = rte_eth_rx_burst(portid, qid, pkts_burst, MAX_PKT_BURST);
		qinfo->pkts += recd;

		if (tinfo->arg->perf_mode) {
			rte_pktmbuf_free_bulk(pkts_burst, recd);
		} else {
			for (j = 0; j < recd; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				addr = (uint64_t *)((uint64_t)m->buf_addr +
						    m->data_off);
				if (*(addr + 8) != MAGIC_PATTERN ||
				    *(addr + 16) != MAGIC_PATTERN ||
				    *(addr + 24) != MAGIC_PATTERN ||
				    *(addr + 32) != MAGIC_PATTERN) {
					ERROR("Invalid data received\n");
				}
				rte_pktmbuf_free(m);
			}
		}
		if (tinfo->arg->max_pkts &&
		    qinfo->pkts >= tinfo->arg->max_pkts)
			ERROR("Max Packets Reached\n");
	}

	return 0;
}

static int
launch_lcore_tx(void *args)
{
	unsigned int lcore, portid, extra_bytes = 0, qid;
	struct rte_mbuf_ext_shared_info s2, s3, s4, s5;
	struct rte_mbuf *m1, *m2, *m3, *m4, *m5;
	struct thread_info *tinfo = args;
	struct queue_info *qinfo;
	struct port_info *pinfo;
	uint32_t usrbuf_len;
	int sent, flow = 0;
	uint64_t usr_addr;
	void *usrbuf;

	rte_mb();
	lcore = rte_lcore_id();
	pinfo = tinfo->pinfo;
	portid = pinfo->portid;
	qid = tinfo->qid;
	qinfo = &pinfo->qinfo[qid];
	NOTICE("Entering TX main loop on lcore %u portid=%u qid=%u\n", lcore,
	       portid, qid);
	fflush(stdout);

	/* Allocate the user memory */
	usrbuf_len = RTE_ALIGN_CEIL(USR_BUF_LEN, BUF_ALIGN);
	usrbuf = rte_zmalloc(NULL, usrbuf_len * NUM_FLOWS, BUF_ALIGN);
	if (!usrbuf) {
		ERROR("Failed to allocate usrbuf\n");
		return 0;
	}

	/* Allocate mbufs to which external buffers will be attached to */
	m4 = rte_pktmbuf_alloc(pinfo->pool);
	m5 = rte_pktmbuf_alloc(pinfo->pool);
	if (m4 == NULL || m5 == NULL) {
		ERROR("Failed to allocate mbuf\n");
		goto free_usrbuf;
	}

	while (keep_running) {
		struct rte_mbuf *m[3];
		uint64_t addr;

		flow = (flow + 1) % NUM_FLOWS;
		usr_addr = (uint64_t)usrbuf + usrbuf_len * flow;

		/* Create 5 segmented packet.
		 *
		 * Seg 1, 2, and 3 are allocated everytime in the loop.
		 * Seg 4 and 5 are allocated once.
		 *
		 * Seg 1 - Normal MBuf.
		 * Seg 2 - External Mbuf at offset 0 of user buffer.
		 * Seg 3 - External MBuf at offset 64 of Seg 1.
		 * Seg 4 - External Mbuf at offset 64 of user buffer.
		 * Seg 5 - External Mbuf at offset 0 of Seg 1. Data offset
		 *         is set at 128.
		 *
		 * All segments except Seg 5 are 64B in length. Seg 5 has
		 * min 8B length. It increments by 1 each loop and rolls
		 * back to 8B once the packet length hits the MTU.
		 */

		/* Allocate Seg 1, 2 and 3 */
		if (rte_pktmbuf_alloc_bulk(pinfo->pool, m, 3)) {
			ERROR("Failed to allocate mbufs\n");
			break;
		}
		m1 = m[0];
		m2 = m[1];
		m3 = m[2];

		/* Setup Seg 1 */
		m1->data_len = SEG_LEN;
		m1->data_off = 0;

		/* Setup Seg 2 */
		usr_addr = (uint64_t)usrbuf;
		*(uint64_t *)usr_addr = MAGIC_PATTERN;
		init_shinfo(&s2);
		rte_pktmbuf_attach_extbuf(m2, (void *)usr_addr, usr_addr,
					  SEG_LEN, &s2);
		m2->data_len = SEG_LEN;
		m2->data_off = 0;

		/* Setup Seg 3 */
		addr = (uint64_t)m1->buf_addr + 64;
		*(uint64_t *)(addr) = MAGIC_PATTERN;
		init_shinfo(&s3);
		rte_pktmbuf_attach_extbuf(m3, (void *)addr, addr, SEG_LEN, &s3);
		m3->data_len = SEG_LEN;
		m3->data_off = 0;

		/* Setup Seg 4 */
		usr_addr = (uint64_t)usrbuf + 64;
		*(uint64_t *)usr_addr = MAGIC_PATTERN;
		init_shinfo(&s4);
		rte_pktmbuf_attach_extbuf(m4, (void *)usr_addr, usr_addr,
					  SEG_LEN, &s4);
		m4->data_len = SEG_LEN;
		m4->data_off = 0;

		/* Setup Seg 5 */
		addr = (uint64_t)m1->buf_addr;
		*(uint64_t *)(addr + 128) = MAGIC_PATTERN;
		init_shinfo(&s5);
		rte_pktmbuf_attach_extbuf(m5, (void *)addr, addr, MTU - 128,
					  &s5);
		m5->data_len = 8;
		m5->data_off = 128;

		/* Setup Packet length and contents */
		m1->pkt_len = SEG_LEN * 4 + 8 + extra_bytes;
		if (m1->pkt_len > MTU) {
			extra_bytes = 0;
			m1->pkt_len = SEG_LEN * 4 + 8;
		}
		m5->data_len += extra_bytes;
		extra_bytes++;
		setup_packet((struct packet_header *)m1->buf_addr, m1->pkt_len,
			     portid, flow);

		/* Update refcnt of m4 and m5 so that it  doesn't get freed
		   during transmit
		 */
		rte_mbuf_refcnt_update(m4, 1);
		rte_mbuf_refcnt_update(m5, 1);

		/* Create the segment chain */
		m1->next = m2;
		m2->next = m3;
		m3->next = m4;
		m4->next = m5;
		m5->next = NULL;
		m1->nb_segs = 5;

		sent = rte_eth_tx_burst(portid, qid, (struct rte_mbuf **)&m1,
					1);
		if (unlikely(sent != 1)) {
			int retry = 0;

			while (sent != 1 && retry < MAX_TX_BURST_RETRIES) {
				rte_delay_us(10);
				sent = rte_eth_tx_burst(portid, qid,
							(struct rte_mbuf **)&m1,
							1);
				retry++;
			}

			if (sent != 1) {
				rte_mbuf_refcnt_update(m4, -1);
				rte_mbuf_refcnt_update(m5, -1);
				rte_pktmbuf_free_seg(m1);
				rte_pktmbuf_free_seg(m2);
				rte_pktmbuf_free_seg(m3);
				qinfo->dropped++;
			}
		}
		qinfo->pkts += sent;

		/* Detach the external buffers from m4 and m5 so
		 * that those can be re-used again in next iteration
		 */
		rte_pktmbuf_detach_extbuf(m4);
		rte_pktmbuf_detach_extbuf(m5);

		if (tinfo->arg->max_pkts &&
		    qinfo->pkts >= tinfo->arg->max_pkts) {
			ERROR("Max packets reached\n");
			break;
		}
	}

	/* Free all mbufs */
	rte_pktmbuf_free_seg(m4);
	rte_pktmbuf_free_seg(m5);

free_usrbuf:
	/* Free user buffer */
	rte_free(usrbuf);
	return 0;
}

static int
launch_lcore_tx_perf_compl(void *args)
{
	unsigned int lcore, j, portid, qid;
	struct rte_mbuf *m[MAX_PKT_BURST];
	struct rte_mbuf *pinned_m[MAX_PKT_BURST];
	struct thread_info *tinfo = args;
	struct queue_info *qinfo;
	struct port_info *pinfo;
	int sent = 0;

	rte_mb();
	lcore = rte_lcore_id();
	pinfo = tinfo->pinfo;
	portid = pinfo->portid;
	qid = tinfo->qid;
	qinfo = &pinfo->qinfo[qid];
	NOTICE("Entering TX Perf Completion main loop on lcore %u portid=%u qid=%u\n",
	       lcore, portid, qid);
	fflush(stdout);
	NOTICE("\nWARNING: Please use tx_compl_ena=1 as devargs to support");
	NOTICE("\n         transmit completion else completion is invoked");
	NOTICE("\n         before packet is actually transmitted\n");
	fflush(stdout);

	while (keep_running) {
		if (rte_pktmbuf_alloc_bulk(pinfo->pool, m, MAX_PKT_BURST)) {
			ERROR("Failed to allocate mbuf\n");
			break;
		}

		if (rte_pktmbuf_alloc_bulk(pinfo->pinned_pool, pinned_m, MAX_PKT_BURST)) {
			ERROR("Failed to allocate pinned_mbuf\n");
			break;
		}

		if (rte_mempool_get_bulk(shinfo_pool, (void **)s, MAX_PKT_BURST) != 0)
			ERROR("Failed to allocate shinfo\n");

		/* Attach the user memory to the segments */
		for (j = 0; j < MAX_PKT_BURST; j++) {
			init_shinfo_compl(s[j]);
			rte_pktmbuf_attach_extbuf(
				m[j], pinned_m[j], (uint64_t)pinned_m[j],
				sizeof(struct rte_mbuf), s[j]);
			m[j]->data_len = sizeof(struct rte_mbuf);
			m[j]->data_off = 0;
			m[j]->next = NULL;
			m[j]->pkt_len = sizeof(struct rte_mbuf);
		}

		sent = rte_eth_tx_burst(portid, qid, m, MAX_PKT_BURST);
		if (unlikely(sent != MAX_PKT_BURST)) {
			int retry = 0;

			while (sent < MAX_PKT_BURST &&
			       retry < MAX_TX_BURST_RETRIES) {
				sent += rte_eth_tx_burst(portid, qid, m + sent,
							 MAX_PKT_BURST - sent);
				retry++;
			}
			if (sent != MAX_PKT_BURST) {
				rte_pktmbuf_free_bulk(m + sent,
						      MAX_PKT_BURST - sent);
				qinfo->dropped += MAX_PKT_BURST - sent;
			}
		}
		qinfo->pkts += sent;

		if (tinfo->arg->max_pkts &&
		    qinfo->pkts >= tinfo->arg->max_pkts)
			ERROR("Max packets reached\n");
	}

	/* Free user buffer */
	return 0;
}

static int
launch_lcore_tx_perf(void *args)
{
	struct rte_mbuf_ext_shared_info s[MAX_PKT_BURST];
	unsigned int lcore, j, portid, qid;
	struct rte_mbuf *m[MAX_PKT_BURST];
	struct thread_info *tinfo = args;
	struct queue_info *qinfo;
	struct port_info *pinfo;
	uint16_t usrbuf_len;
	int sent, flow = 0;
	uint64_t usr_addr;
	void *usrbuf;

	rte_mb();
	lcore = rte_lcore_id();
	pinfo = tinfo->pinfo;
	portid = pinfo->portid;
	qid = tinfo->qid;
	qinfo = &pinfo->qinfo[qid];
	NOTICE("Entering TX Perf main loop on lcore %u portid=%u qid=%u\n",
	       lcore, portid, qid);
	fflush(stdout);

	/* Allocate the user memory */
	usrbuf_len = RTE_ALIGN_CEIL(USR_BUF_LEN, BUF_ALIGN);
	usrbuf = rte_zmalloc(NULL, usrbuf_len * NUM_FLOWS, BUF_ALIGN);
	if (!usrbuf) {
		ERROR("Failed to allocate usrbuf\n");
		return 0;
	}
	usr_addr = (uint64_t)usrbuf;

	for (j = 0; j < NUM_FLOWS; j++)
		setup_packet(
			(struct packet_header *)(usr_addr + j * usrbuf_len),
			SEG_LEN, portid, j);

	while (keep_running) {
		if (rte_pktmbuf_alloc_bulk(pinfo->pool, m, MAX_PKT_BURST)) {
			ERROR("Failed to allocate mbuf\n");
			break;
		}

		/* Attach the user memory to the segments */
		for (j = 0; j < MAX_PKT_BURST; j++) {
			flow = (flow + 1) % NUM_FLOWS;
			init_shinfo(&s[j]);
			rte_pktmbuf_attach_extbuf(
				m[j], (void *)(usr_addr + flow * usrbuf_len),
				usr_addr + flow * usrbuf_len, SEG_LEN, &s[j]);
			m[j]->data_len = SEG_LEN;
			m[j]->data_off = 0;
			m[j]->next = NULL;
			m[j]->pkt_len = SEG_LEN;
		}

		sent = rte_eth_tx_burst(portid, qid, m, MAX_PKT_BURST);
		if (unlikely(sent != MAX_PKT_BURST)) {
			int retry = 0;;

			while (sent < MAX_PKT_BURST &&
			       retry < MAX_TX_BURST_RETRIES) {
				sent += rte_eth_tx_burst(portid, qid, m + sent,
							 MAX_PKT_BURST - sent);
				retry++;
			}
			if (sent != MAX_PKT_BURST) {
				rte_pktmbuf_free_bulk(m + sent,
						      MAX_PKT_BURST - sent);
				qinfo->dropped += MAX_PKT_BURST - sent;
			}
		}
		qinfo->pkts += sent;

		if (tinfo->arg->max_pkts &&
		    qinfo->pkts >= tinfo->arg->max_pkts)
			ERROR("Max packets reached\n");
	}

	/* Free user buffer */
	rte_free(usrbuf);
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		ERROR("\n\nSignal %d received, preparing to exit..\n", signum);
}

static int
parse_args(int argc, char **argv, struct app_arg *arg)
{
	arg->tx_mode = true;
	arg->perf_mode = false;
	arg->use_tx_compl = false;
	arg->event_tx_compl = false;
	arg->n_queue = 1;
	arg->n_desc = 1024;
	arg->max_pkts = 0;

	/* Parse Arguments */
	while (argc > 1) {
		if (strncmp(argv[1], "--rx", 4) == 0) {
			arg->tx_mode = false;
		} else if (strncmp(argv[1], "--perf", 6) == 0) {
			arg->perf_mode = true;
			if (strncmp(argv[3], "--use-tx-completion", 19) == 0)
				arg->use_tx_compl = true;
			argv = argv + 2;
			argc = argc - 2;
		} else if (strncmp(argv[1], "--event-tx-compl", 16) == 0) {
			arg->event_tx_compl = true;
		} else if (strncmp(argv[1], "--nqueue", 8) == 0) {
			if (argc < 3)
				return -1;
			arg->n_queue = strtoul(argv[2], 0, 0);
			argv++;
			argc--;
		} else if (strncmp(argv[1], "--ndesc", 7) == 0) {
			if (argc < 3)
				return -1;
			arg->n_desc = strtoul(argv[2], 0, 0);
			argv++;
			argc--;
		} else if (strncmp(argv[1], "--max-pkts", 10) == 0) {
			if (argc < 3)
				return -1;
			arg->max_pkts = strtoul(argv[2], 0, 0);
			argv++;
			argc--;
		} else {
			return -1;
		}
		argv++;
		argc--;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct global_event_resources *rsrc = NULL;
	struct port_info pinfo[RTE_MAX_ETHPORTS];
	struct thread_info tinfo[RTE_MAX_LCORE];
	struct queue_info qinfo[RTE_MAX_LCORE];
	unsigned int n_port, n_lcore, p, q, c;
	struct app_arg arg;
	int ret;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		EXIT("Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	memset(&tinfo, 0, sizeof(tinfo));
	memset(&qinfo, 0, sizeof(qinfo));
	memset(&pinfo, 0, sizeof(pinfo));
	memset(&arg, 0, sizeof(arg));

	if (parse_args(argc, argv, &arg))
		EXIT("Argument parsing failed\n");

	n_port = rte_eth_dev_count_avail();
	if (n_port == 0)
		EXIT("No Ethernet ports - bye\n");

	/* Check lcores */
	n_lcore = 0;
	RTE_LCORE_FOREACH_WORKER(c) {
		if (!rte_lcore_is_enabled(c))
			continue;
		tinfo[n_lcore].arg = &arg;
		tinfo[n_lcore].lcore = c;
		n_lcore++;
	}
	if (n_lcore < n_port * arg.n_queue)
		EXIT("Need at least %u lcores\n", n_port * arg.n_queue);

	/* Initialize the ports */
	n_port = 0;
	RTE_ETH_FOREACH_DEV(p) {
		pinfo[n_port].portid = p;
		initialize(&pinfo[n_port], &arg);
		n_port++;
	}

	if (arg.event_tx_compl) {
		rsrc = initialize_event(n_port);
		rsrc->keep_running = (uint8_t *)&keep_running;
		lcore_function_t *f;
		f = event_loop_single;
		rte_eal_mp_remote_launch(f, rsrc, SKIP_MAIN);
	}
	/* Launch rx/tx threads per queue */
	for (p = 0; p < n_port && !arg.event_tx_compl; p++) {
		for (q = 0; q < arg.n_queue; q++) {
			lcore_function_t *f;
			if (arg.tx_mode) {
				if (arg.perf_mode)
					f = arg.use_tx_compl ?
						launch_lcore_tx_perf_compl :
						launch_lcore_tx_perf;
				else
					f = launch_lcore_tx;
			} else {
				f = launch_lcore_rx;
			}

			c = p * arg.n_queue + q;
			tinfo[c].pinfo = &pinfo[p];
			tinfo[c].qid = q;
			ret = rte_eal_remote_launch(f, &tinfo[c],
						    tinfo[c].lcore);
			if (ret) {
				ERROR("Failed to launch thread\n");
				goto cleanup;
			}
			tinfo[c].launched = true;
		}
	}

	/* Periodically print the stats */
	while (keep_running) {
		rte_delay_ms(PRINT_DELAY_MS);
		rte_mb();
		if (arg.event_tx_compl) {
			print_event_stats(rsrc, false);
		} else {
			print_stats(pinfo, n_port, &arg, true);
		}
	}

cleanup:
	/* Wait for threads to exit out */
	for (p = 0; p < n_port && !arg.event_tx_compl; p++) {
		for (q = 0; q < arg.n_queue; q++) {
			c = p * arg.n_queue + q;
			if (!tinfo[c].launched)
				continue;
			if (rte_eal_wait_lcore(tinfo[c].lcore) < 0)
				EXIT("Failed waiting for completion\n");
		}
	}

	/* Finalize the ports */
	for (p = 0; p < n_port; p++)
		finalize(&pinfo[p]);

	if (arg.event_tx_compl) {
		print_event_stats(rsrc, true);
		finalize_event(rsrc);
	}

	/* Print final stats */
	rte_mb();
	rte_eal_cleanup();
	if (!arg.event_tx_compl)
		print_stats(pinfo, n_port, &arg, false);

	return ret;
}
