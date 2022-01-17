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

#define SEG_LEN			 64
#define USR_BUF_LEN		 (SEG_LEN * 2)
#define BUF_ALIGN		 128
#define MAX_PKT_BURST		 32
#define BURST_TX_DRAIN_US	 100
#define MEMPOOL_CACHE_SIZE	 256
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define PRINT_DELAY_MS		 1000
#define MAGIC_PATTERN		 0xf00dfeed

#define ERR_EXIT(...)                                                          \
	{                                                                      \
		force_quit = true;                                             \
		rte_exit(EXIT_FAILURE, __VA_ARGS__);                           \
	}

static volatile bool force_quit;

struct thread_info {
	unsigned int lcore;
	unsigned int portid;
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
	uint64_t max_tx;
	struct rte_eth_dev_tx_buffer *tx_buf;
	struct rte_mempool *pool;
} __rte_cache_aligned;

static void
print_stats(struct thread_info *tinfo, unsigned int nb_ports)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	unsigned int i;

	printf("%s%s", clr, topLeft);
	printf("\n====================================================");
	printf("\nPort statistics -- Enabled Ports = %u", nb_ports);
	printf("\n====================================================");
	for (i = 0; i < nb_ports; i++) {
		printf("\nStatistics for port %u Lcore %u ----------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets recd: %24"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   tinfo[i].portid,
			   tinfo[i].lcore,
			   tinfo[i].tx,
			   tinfo[i].rx,
			   tinfo[i].dropped);
	}
	printf("\n====================================================\n");
	fflush(stdout);
}

static void
initialize(struct thread_info *tinfo)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_conf port_lconf;
	unsigned int nb_mbufs, portid;
	uint16_t nb_txd, nb_rxd;
	char name[16];
	int ret;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
	};

	/* Create the mbuf pool. */
	nb_mbufs = RTE_MAX((unsigned int)RTE_TEST_TX_DESC_DEFAULT +
			    MAX_PKT_BURST + MEMPOOL_CACHE_SIZE, 8192U);
	snprintf(name, 16, "mbuf_pool_%u", tinfo->portid);
	tinfo->pool =
		rte_pktmbuf_pool_create(name, nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE,
					rte_socket_id());
	if (tinfo->pool == NULL)
		ERR_EXIT("Cannot init mbuf pool\n");

	portid = tinfo->portid;
	printf("Initializing port %u... ", portid);

	ret = rte_eth_dev_info_get(portid, &dev_info);
	if (ret != 0)
		ERR_EXIT("Error during getting device (port %u) info: %s\n",
			 portid, strerror(-ret));

	port_lconf = port_conf;
	/* Enable Multi Seg */
	if (!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS))
		ERR_EXIT("Device doesn't support multi seg\n");
	port_lconf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	/* Disable Fast Free */
	port_lconf.txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the number of queues */
	ret = rte_eth_dev_configure(portid, 1, 1, &port_lconf);
	if (ret < 0)
		ERR_EXIT("Cannot configure device: err=%d, port=%u\n", ret,
			 portid);

	nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (ret < 0)
		ERR_EXIT("Cannot adjust number of descs: err=%d, port=%u\n",
			 ret, portid);

	/* Initialize RX queue */
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_lconf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
				     rte_eth_dev_socket_id(portid),
				     &rxq_conf,
				     tinfo->pool);
	if (ret < 0)
		ERR_EXIT("Rx queue setup err=%d, port=%u\n", ret, portid);

	/* Initialize TX queue */
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_lconf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				     rte_eth_dev_socket_id(portid), &txq_conf);
	if (ret < 0)
		ERR_EXIT("Tx queue setup err=%d, port=%u\n", ret, portid);

	/* Initialize TX buffers */
	snprintf(name, 16, "tx_buffer_%u", tinfo->portid);
	tinfo->tx_buf =
		rte_zmalloc_socket(name, RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST),
				   0, rte_eth_dev_socket_id(portid));
	if (tinfo->tx_buf == NULL)
		ERR_EXIT("Cannot allocate buffer for tx on port %u\n", portid);
	rte_eth_tx_buffer_init(tinfo->tx_buf, MAX_PKT_BURST);

	/* Set the custom error callback which ensures that the mbufs with
	 * external buffers attached are never freed.
	 */
	ret = rte_eth_tx_buffer_set_err_callback(
			tinfo->tx_buf, rte_eth_tx_buffer_count_callback,
			&tinfo->dropped);
	if (ret < 0)
		ERR_EXIT("Cannot set error callback for tx buffer on port %u\n",
			 portid);

	/* Start device */
	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		ERR_EXIT("rte_eth_dev_start:err=%d, port=%u\n",
			 ret, portid);

	printf("done:\n");
	fflush(stdout);
}

static void
finalize(struct thread_info *tinfo)
{
	unsigned int portid = 0;
	int ret, sent;

	portid = tinfo->portid;

	/* Close port */
	printf("Closing port %d...", portid);
	sent = rte_eth_tx_buffer_flush(portid, 0, tinfo->tx_buf);
	if (sent)
		tinfo->tx += sent;
	ret = rte_eth_dev_stop(portid);
	if (ret != 0)
		printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
	rte_eth_dev_close(portid);

	/* Free mempool */
	rte_mempool_free(tinfo->pool);
}

static void dummy_free_cb(void *addr, void *opaque)
{
	RTE_SET_USED(addr);
	RTE_SET_USED(opaque);
}

static void init_shinfo(struct rte_mbuf_ext_shared_info *s)
{
	s->free_cb = dummy_free_cb;
	s->fcb_opaque = NULL;
	rte_mbuf_ext_refcnt_set(s, 1);
}

static int
launch_one_lcore_rx(void *args)
{
	struct rte_mbuf *m, *pkts_burst[MAX_PKT_BURST];
	unsigned int lcore, j, portid, recd;
	struct thread_info *tinfo = args;
	uint64_t *addr;

	rte_mb();
	lcore = rte_lcore_id();
	portid = tinfo->portid;
	printf("Entering main loop on lcore %u portid=%u\n", lcore, portid);
	fflush(stdout);

	while (!force_quit) {
		recd = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
		tinfo->rx += recd;

		for (j = 0; j < recd; j++) {
			m = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			addr = (uint64_t *)((uint64_t)m->buf_addr +
					    m->data_off);
			if (*addr != MAGIC_PATTERN ||
			    *(addr + 8) != MAGIC_PATTERN ||
			    *(addr + 16) != MAGIC_PATTERN ||
			    *(addr + 24) != MAGIC_PATTERN ||
			    *(addr + 32) != MAGIC_PATTERN)
				ERR_EXIT("Invalid data received");
			rte_pktmbuf_free(m);
		}
	}

	return 0;
}

static int
launch_one_lcore_tx(void *args)
{
	uint64_t prev_tsc, diff_tsc, cur_tsc, drain_tsc;
	struct rte_mbuf_ext_shared_info s2, s4, s5;
	struct rte_mbuf *m1, *m2, *m3, *m4, *m5;
	struct thread_info *tinfo = args;
	unsigned int lcore, j, portid;
	uint16_t usrbuf_len;
	uint64_t usr_addr;
	char name[16];
	void *usrbuf;
	int sent;

	rte_mb();
	lcore = rte_lcore_id();
	portid = tinfo->portid;
	printf("Entering main loop on lcore %u portid=%u\n", lcore, portid);
	fflush(stdout);

	/* Allocate the user memory */
	usrbuf_len = RTE_ALIGN_CEIL(USR_BUF_LEN +
				    sizeof(struct rte_mbuf_ext_shared_info),
				    BUF_ALIGN);
	snprintf(name, 16, "usr_buf_%u", tinfo->portid);
	usrbuf = rte_zmalloc(name, usrbuf_len, BUF_ALIGN);
	if (!usrbuf)
		ERR_EXIT("Failed to allocate usrbuf");

	/* Create packet with following type of segments.
	 * Seg 1 - Normal MBuf allocated every time inside loop. This can
	 *         also be a packet mbuf that is received on the fly.
	 * Seg 2 - External Mbuf at offset 0 of user buffer
	 * Seg 3 - Normal MBuf allocated only once.
	 * Seg 4 - External MBuf at offset 64 of user buffer
	 * Seg 5 - External mbuf pointing at offset 64 of segment 1
	 *
	 * All segments are 64B in length.
	 */
	m2 = rte_pktmbuf_alloc(tinfo->pool);
	m3 = rte_pktmbuf_alloc(tinfo->pool);
	m4 = rte_pktmbuf_alloc(tinfo->pool);
	m5 = rte_pktmbuf_alloc(tinfo->pool);
	if (m2 == NULL || m3 == NULL || m4 == NULL || m5 == NULL)
		ERR_EXIT("Failed to allocate mbuf");

	/* Attach user buffer to seg 2 */
	usr_addr = (uint64_t)usrbuf;
	*(uint64_t *)usr_addr = MAGIC_PATTERN;
	init_shinfo(&s2);
	rte_pktmbuf_attach_extbuf(m2, (void *)usr_addr, usr_addr, SEG_LEN, &s2);
	m2->data_len = SEG_LEN;
	m2->data_off = 0;

	/* Update data length of seg 3 */
	m3->data_len = SEG_LEN;
	m3->data_off = 0;
	*(uint64_t *)(m3->buf_addr) = MAGIC_PATTERN;

	/* Attach user buffer at offset 64 to seg 4 */
	usr_addr += 64;
	*(uint64_t *)usr_addr = MAGIC_PATTERN;
	init_shinfo(&s4);
	rte_pktmbuf_attach_extbuf(m4, (void *)usr_addr, usr_addr, SEG_LEN, &s4);
	m4->data_len = SEG_LEN;
	m4->data_off = 0;

	/* Initialise shinfo used in seg 5 */
	init_shinfo(&s5);

	/* Initialise timestamps*/
	drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	prev_tsc = 0;

	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			if (lcore != rte_get_main_lcore()) {
				sent = rte_eth_tx_buffer_flush(portid, 0,
						tinfo->tx_buf);
				tinfo->tx += sent;
			}
			prev_tsc = cur_tsc;
		}

		for (j = 0; j < MAX_PKT_BURST; j++) {
			uint64_t addr;

			/* Allocate segment 1 every time */
			m1 = rte_pktmbuf_alloc(tinfo->pool);
			if (m1 == NULL)
				ERR_EXIT("Failed to allocate mbuf");

			m1->data_len = SEG_LEN;
			m1->data_off = 0;
			*(uint64_t *)(m1->buf_addr) = MAGIC_PATTERN;

			/* Attach seg 1 memory at offset 64 in segment 5 */
			addr = (uint64_t)m1->buf_addr + 64;
			*(uint64_t *)(addr) = MAGIC_PATTERN;
			rte_pktmbuf_attach_extbuf(m5, (void *)addr, addr,
						  SEG_LEN, &s5);
			m5->data_len = SEG_LEN;
			m5->data_off = 0;

			/* Update refcnt of m2, m3, m4 and m5 so that it
			 * doesn't get freed during transmit
			 */
			rte_mbuf_refcnt_update(m2, 1);
			rte_mbuf_refcnt_update(m3, 1);
			rte_mbuf_refcnt_update(m4, 1);
			rte_mbuf_refcnt_update(m5, 1);

			/* Create the segment chain */
			m1->next = m2;
			m2->next = m3;
			m3->next = m4;
			m4->next = m5;
			m5->next = NULL;
			m1->nb_segs = 5;
			m1->pkt_len = SEG_LEN * m1->nb_segs;
			sent = rte_eth_tx_buffer(portid, 0, tinfo->tx_buf, m1);
			tinfo->tx += sent;

			/* Detach the external buffer from m5 so that m5 can be
			 * re-used again in next iteration
			 */
			rte_pktmbuf_detach_extbuf(m5);

			if (tinfo->max_tx && tinfo->tx >= tinfo->max_tx) {
				force_quit = true;
				rte_mb();
				break;
			}
		}
	}

	/* Free all mbufs */
	rte_pktmbuf_free(m2);
	rte_pktmbuf_free(m3);
	rte_pktmbuf_free(m4);
	rte_pktmbuf_free(m5);

	/* Free user buffer */
	rte_free(usrbuf);
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit..\n", signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	unsigned int nb_ports, idx, lcore, portid;
	struct thread_info tinfo[RTE_MAX_ETHPORTS];
	uint64_t max_tx = 0;
	bool tx_mode = true;
	uint64_t total;
	int ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		ERR_EXIT("Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* Parse Arguments */
	if (argc > 1) {
		if (strncmp(argv[1], "--rx", 4) == 0) {
			tx_mode = false;
		} else if (strncmp(argv[1], "--max-tx", 8) == 0) {
			if (argc < 3)
				ERR_EXIT("No packet count\n");
			max_tx = strtoul(argv[2], 0, 0);
		}
	}

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		ERR_EXIT("No Ethernet ports - bye\n");

	memset(&tinfo, 0, sizeof(tinfo));
	idx = 0;
	RTE_ETH_FOREACH_DEV(portid) {
		tinfo[idx].portid = portid;
		tinfo[idx].max_tx = max_tx;
		idx++;
	}

	idx = 0;
	RTE_LCORE_FOREACH_WORKER(lcore) {
		if (!rte_lcore_is_enabled(lcore))
			continue;
		tinfo[idx++].lcore = lcore;
		if (idx >= nb_ports)
			break;
	}

	for (idx = 0; idx < nb_ports; idx++) {
		initialize(&tinfo[idx]);
		if (tx_mode)
			ret = rte_eal_remote_launch(launch_one_lcore_tx,
						    &tinfo[idx],
						    tinfo[idx].lcore);
		else
			ret = rte_eal_remote_launch(launch_one_lcore_rx,
						    &tinfo[idx],
						    tinfo[idx].lcore);
		if (ret)
			ERR_EXIT("Failed to launch thread\n");
	}

	while (!force_quit) {
		rte_delay_ms(PRINT_DELAY_MS);
		rte_mb();
		print_stats(tinfo, nb_ports);
	}

	ret = 0;
	for (idx = 0; idx < nb_ports; idx++) {
		if (rte_eal_wait_lcore(tinfo[idx].lcore) < 0)
			ERR_EXIT("Failed Waiting for thread completion\n");
		finalize(&tinfo[idx]);
	}
	rte_mb();
	rte_eal_cleanup();
	print_stats(tinfo, nb_ports);
	for (total = 0, idx = 0; idx < nb_ports; idx++) {
		total += tinfo[idx].tx;
		total += tinfo[idx].rx;
	}
	printf("%s TOTAL PACKETS = %"PRIu64"\n", tx_mode ? "Tx" : "Rx", total);
	return ret;
}
