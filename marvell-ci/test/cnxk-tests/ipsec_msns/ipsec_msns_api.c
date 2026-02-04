/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hexdump.h>
#include <rte_bitmap.h>
#include <rte_ipsec.h>
#include <rte_malloc.h>
#include <rte_pmd_cnxk.h>
#include <rte_security.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>

#include "ipsec_msns.h"
#include "ipsec_msns_api.h"
#include "flow.h"
#include "parser.h"

#define NB_ETHPORTS_USED	 1
#define MEMPOOL_CACHE_SIZE	 32
#define MEMPOOL_PRV_AREA_SIZE	 128
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define RTE_PORT_ALL		 (~(uint16_t)0x0)

#define RX_PTHRESH 8  /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8  /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0  /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define NB_MBUF 10240U

static int create_custom_flow(uint16_t port_id, enum rte_pmd_cnxk_sec_action_alg alg,
			      uint16_t profile_id);
static void destroy_custom_flow(uint16_t port_id);
enum test_mode {
	IPSEC_MSNS,
	/* Verify the RTE PMD APIs */
	IPSEC_RTE_PMD_CNXK_API_TEST,
	/* Custom profile API test */
	CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST,
};

static struct rte_mempool *mbufpool[RTE_MAX_ETHPORTS];
static struct rte_mempool *vector_pool[RTE_MAX_ETHPORTS];
static struct rte_mempool *sess_pool;
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
static bool is_plat_cn20k;
static const char *config_file;

#define VECTOR_SIZE_DEFAULT   64
#define VECTOR_TMO_NS_DEFAULT 1E6
static uint16_t vector_en;
static uint16_t vector_sz = VECTOR_SIZE_DEFAULT;
static uint16_t custom_profile_id;

static struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_NONE,
			.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SECURITY,
		},
	.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
			.offloads = RTE_ETH_TX_OFFLOAD_SECURITY | RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
		},
	.lpbk_mode = 0,
};

static struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
			.pthresh = RX_PTHRESH,
			.hthresh = RX_HTHRESH,
			.wthresh = RX_WTHRESH,
		},
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
			.pthresh = TX_PTHRESH,
			.hthresh = TX_HTHRESH,
			.wthresh = TX_WTHRESH,
		},
	.tx_free_thresh = 32, /* Use PMD default values */
	.tx_rs_thresh = 32,   /* Use PMD default values */
};

struct lcore_cfg {
	uint8_t socketid;
	uint16_t nb_ports;
	uint16_t portid;
	int eventdev_id;
	int event_port_id;
	int eventq_id;
	uint16_t queueid;

	/* Stats */
	uint64_t rx_pkts;
	uint64_t rx_ipsec_pkts;
	uint64_t tx_pkts;
};

static struct lcore_cfg lcore_cfg[RTE_MAX_LCORE];

static struct rte_flow *default_flow[RTE_MAX_ETHPORTS][RTE_PMD_CNXK_SEC_ACTION_ALG4 + 1];
static struct rte_flow *default_flow_no_msns[RTE_MAX_ETHPORTS];
static struct rte_flow *custom_flow[RTE_MAX_ETHPORTS];

/* Example usage, max entries 4K */
#define MAX_SA_SIZE (4 * 1024)

struct sa_index_map {
	struct rte_bitmap *map;
	uint32_t size;
};

static struct sa_index_map bmap[RTE_MAX_ETHPORTS][2];

static uint32_t ethdev_port_mask = RTE_PORT_ALL;
static volatile bool force_quit;
static uint32_t nb_bufs;
static enum test_mode testmode;
static bool loopback;
static bool event_en;
static int eventdev_id;
static int rx_adapter_id;
static int tx_adapter_id;
static int nb_event_queues;
static int nb_event_ports;
static uint32_t num_sas = 1;
static bool inl_inb_oop;
static struct ipsec_session_data *sess_conf = &conf_aes_128_gcm;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static const char *
ipsec_test_mode_to_string(enum test_mode testmode)
{
	switch (testmode) {
	case IPSEC_MSNS:
		return "IPSEC_MSNS";
	case IPSEC_RTE_PMD_CNXK_API_TEST:
		return "IPSEC_RTE_PMD_CNXK_API_TEST";
	case CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST:
		return "CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST";

	}
	return NULL;
}

/* Check the link status of all ports in up to 3s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30  /* 3s (30 * 100ms) in total */
	uint8_t count, all_ports_up, print_flag = 0;
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];
	struct rte_eth_link link;
	uint16_t portid;
	int ret;

	printf("Checking link statuses...\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & RTE_BIT64(portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n", portid,
					       rte_strerror(-ret));
				continue;
			}

			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status, sizeof(link_status), &link);
				printf("Port %d %s\n", portid, link_status);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
			print_flag = 1;
	}
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

static void
copy_buf_to_pkt_segs(void *buf, unsigned int len, struct rte_mbuf *pkt, unsigned int offset)
{
	unsigned int copy_len;
	struct rte_mbuf *seg;
	void *seg_buf;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t)copy_len);
		len -= copy_len;
		buf = ((char *)buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, void *);
	}
	rte_memcpy(seg_buf, buf, (size_t)len);
}

static inline void
copy_buf_to_pkt(void *buf, unsigned int len, struct rte_mbuf *pkt, unsigned int offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf, (size_t)len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static inline int
init_traffic(struct rte_mempool *mp, struct rte_mbuf **pkts_burst,
	     struct ipsec_test_packet *vectors)
{
	struct rte_mbuf *pkt;

	pkt = rte_pktmbuf_alloc(mp);
	if (pkt == NULL)
		return -1;

	pkt->data_len = vectors->len;
	pkt->pkt_len = vectors->len;
	copy_buf_to_pkt(vectors->data, vectors->len, pkt, 0);
	pkts_burst[0] = pkt;
	return 0;
}

static void
init_lcore(void)
{
	uint16_t ev_port_id = 0;
	unsigned int lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_cfg[lcore_id].socketid = rte_lcore_to_socket_id(lcore_id);
		if (rte_lcore_is_enabled(lcore_id) != 0) {
			if (event_en) {
				/* Assign event port id */
				lcore_cfg[lcore_id].eventdev_id = 0;
				lcore_cfg[lcore_id].event_port_id = -1;
				if (ev_port_id >= nb_event_ports)
					continue;
				lcore_cfg[lcore_id].event_port_id = ev_port_id++;
			} else {
				lcore_cfg[lcore_id].portid = 0;
			}
		}
	}
}

static int
init_sess_mempool(void)
{
	struct rte_security_ctx *sec_ctx;
	uint16_t nb_sess = RTE_MAX(num_sas * 2, 2048ul);
	uint32_t sess_sz;
	int socketid = 0;
	char s[64];

	sec_ctx = rte_eth_dev_get_sec_ctx(0);
	if (sec_ctx == NULL)
		return -ENOENT;

	sess_sz = rte_security_session_get_size(sec_ctx);
	if (sess_pool == NULL) {
		snprintf(s, sizeof(s), "sess_pool_%d", socketid);
		sess_pool = rte_mempool_create(s, nb_sess, sess_sz, MEMPOOL_CACHE_SIZE, 0,
					       NULL, NULL, NULL, NULL, socketid, 0);
		if (sess_pool == NULL) {
			printf("Cannot init sess pool on socket %d\n", socketid);
			return -1;
		}
		printf("Allocated sess pool on socket %d\n", socketid);
	}
	return 0;
}

static int
init_pktmbuf_pool(uint32_t portid, unsigned int nb_mbuf)
{
	int socketid = 0;
	char s[64];

	if (mbufpool[portid] == NULL) {
		snprintf(s, sizeof(s), "mbuf_pool_%d", portid);
		mbufpool[portid] = rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE,
							   MEMPOOL_PRV_AREA_SIZE,
							   RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
		if (mbufpool[portid] == NULL) {
			printf("Cannot init mbuf pool on socket %d\n", socketid);
			return -1;
		}
		printf("Allocated mbuf pool for port %d\n", portid);
	}
	return 0;
}

static int
ut_eventdev_stop(void)
{
	int rc = 0;

	rte_event_dev_stop(eventdev_id);
	rc = rte_event_eth_rx_adapter_stop(rx_adapter_id);
	rc |= rte_event_eth_tx_adapter_stop(tx_adapter_id);
	return rc;
}

static int
ut_eventdev_start(void)
{
	int rc = 0;

	rc |= rte_event_eth_rx_adapter_start(rx_adapter_id);
	rc |= rte_event_eth_tx_adapter_start(tx_adapter_id);
	rc = rte_event_dev_start(eventdev_id);
	return rc;
}

static int
ut_eventdev_setup(void)
{
	struct rte_event_eth_rx_adapter_queue_conf queue_conf;
	struct rte_event_dev_info evdev_default_conf = {0};
	struct rte_event_dev_config eventdev_conf = {0};
	struct rte_event_queue_conf eventq_conf = {0};
	struct rte_event_port_conf ev_port_conf = {0};
	const int all_queues = -1;
	uint8_t ev_queue_id = 0;
	int portid, ev_port_id;
	uint32_t caps = 0;
	int ret;

	/* Setup eventdev */
	eventdev_id = 0;
	rx_adapter_id = 0;
	tx_adapter_id = 0;

	/* Get default conf of eventdev */
	ret = rte_event_dev_info_get(eventdev_id, &evdev_default_conf);
	if (ret < 0) {
		printf("Error in getting event device info[devID:%d]\n",
		       eventdev_id);
		return ret;
	}
	nb_event_ports = rte_lcore_count();
	nb_event_queues = evdev_default_conf.max_event_queues;

	/* Get Tx adapter capabilities */
	ret = rte_event_eth_tx_adapter_caps_get(eventdev_id, tx_adapter_id, &caps);
	if (ret < 0) {
		printf("Failed to get event device %d eth tx adapter"
		       " capabilities\n",
		       eventdev_id);
		return ret;
	}

	eventdev_conf.nb_events_limit =
		evdev_default_conf.max_num_events;
	eventdev_conf.nb_event_queue_flows =
		evdev_default_conf.max_event_queue_flows;
	eventdev_conf.nb_event_port_dequeue_depth =
		evdev_default_conf.max_event_port_dequeue_depth;
	eventdev_conf.nb_event_port_enqueue_depth =
		evdev_default_conf.max_event_port_enqueue_depth;

	eventdev_conf.nb_event_queues = nb_event_queues;
	eventdev_conf.nb_event_ports = nb_event_ports;

	/* Configure event device */

	ret = rte_event_dev_configure(eventdev_id, &eventdev_conf);
	if (ret < 0) {
		printf("Error in configuring event device\n");
		return ret;
	}

	/* Configure event queue */
	eventq_conf.schedule_type = RTE_SCHED_TYPE_PARALLEL;
	eventq_conf.nb_atomic_flows = 1024;
	eventq_conf.nb_atomic_order_sequences = 1024;

	/* Setup the queue */
	for (ev_queue_id = 0; ev_queue_id < nb_event_queues; ev_queue_id++) {
		ret = rte_event_queue_setup(eventdev_id, ev_queue_id, &eventq_conf);
		if (ret < 0) {
			printf("Failed to setup event queue %d, rc=%d\n", ev_queue_id, ret);
			return ret;
		}
	}

	/* Configure event port */
	for (ev_port_id = 0; ev_port_id < nb_event_ports; ev_port_id++) {
		ret = rte_event_port_setup(eventdev_id, ev_port_id, NULL);
		if (ret < 0) {
			printf("Failed to setup event port %d\n", ret);
			return ret;
		}

		/* Make event queue - event port link */
		ret = rte_event_port_link(eventdev_id, ev_port_id, NULL, NULL, 1);
		if (ret < 0) {
			printf("Failed to link event port %d\n", ret);
			return ret;
		}
	}

	/* Setup port conf */
	ev_port_conf.new_event_threshold = 1200;
	ev_port_conf.dequeue_depth =
		evdev_default_conf.max_event_port_dequeue_depth;
	ev_port_conf.enqueue_depth =
		evdev_default_conf.max_event_port_enqueue_depth;

	/* Create Rx adapter */
	ret = rte_event_eth_rx_adapter_create(rx_adapter_id, eventdev_id,
					      &ev_port_conf);
	if (ret < 0) {
		printf("Failed to create rx adapter %d\n", ret);
		return ret;
	}

	/* Create tx adapter */
	ret = rte_event_eth_tx_adapter_create(tx_adapter_id, eventdev_id,
					      &ev_port_conf);
	if (ret < 0) {
		printf("Failed to create tx adapter %d\n", ret);
		return ret;
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		/* Setup queue conf */
		memset(&queue_conf, 0, sizeof(queue_conf));
		queue_conf.ev.queue_id = portid % nb_event_queues;
		queue_conf.ev.sched_type = RTE_SCHED_TYPE_PARALLEL;
		queue_conf.ev.event_type = RTE_EVENT_TYPE_ETHDEV;

		if (vector_en) {
			/* Event vector enable */
			queue_conf.vector_sz = vector_sz;
			queue_conf.vector_timeout_ns = VECTOR_TMO_NS_DEFAULT;
			queue_conf.vector_mp = vector_pool[portid];
			queue_conf.rx_queue_flags |= RTE_EVENT_ETH_RX_ADAPTER_QUEUE_EVENT_VECTOR;
		}

		/* Add queue to the adapter */
		ret = rte_event_eth_rx_adapter_queue_add(rx_adapter_id, portid,
							 all_queues, &queue_conf);
		if (ret < 0) {
			printf("Failed to add eth queue to rx adapter %d\n", ret);
			return ret;
		}

		/* Add queue to the adapter */
		ret = rte_event_eth_tx_adapter_queue_add(tx_adapter_id, portid,
							 all_queues);
		if (ret < 0) {
			printf("Failed to add eth queue to tx adapter %d\n", ret);
			return ret;
		}

	}
	/* Start rx adapter */
	ret = rte_event_eth_rx_adapter_start(rx_adapter_id);
	if (ret < 0) {
		printf("Failed to start rx adapter %d\n", ret);
		return ret;
	}

	/* Start tx adapter */
	ret = rte_event_eth_tx_adapter_start(tx_adapter_id);
	if (ret < 0) {
		printf("Failed to start tx adapter %d\n", ret);
		return ret;
	}

	/* Start eventdev */
	ret = rte_event_dev_start(eventdev_id);
	if (ret < 0) {
		printf("Failed to start event device %d\n", ret);
		return ret;
	}

	/* Stop event dev before traffic */
	ut_eventdev_stop();

	return 0;
}

static void
ut_eventdev_teardown(void)
{
	int ret;
	int portid;

	/* Stop rx adapter */
	ret = rte_event_eth_rx_adapter_stop(rx_adapter_id);
	if (ret < 0)
		printf("Failed to stop rx adapter %d\n", ret);

	/* Stop tx adapter */
	ret = rte_event_eth_tx_adapter_stop(tx_adapter_id);
	if (ret < 0)
		printf("Failed to stop tx adapter %d\n", ret);

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_event_eth_rx_adapter_queue_del(rx_adapter_id, portid, -1);
		if (ret < 0)
			printf("Failed to remove rx adapter queues %d\n", ret);
		ret = rte_event_eth_tx_adapter_queue_del(tx_adapter_id, portid, -1);
		if (ret < 0)
			printf("Failed to remove tx adapter queues %d\n", ret);
	}

	/* Release rx adapter */
	ret = rte_event_eth_rx_adapter_free(rx_adapter_id);
	if (ret < 0)
		printf("Failed to free rx adapter %d\n", ret);

	/* Release tx adapter */
	ret = rte_event_eth_tx_adapter_free(tx_adapter_id);
	if (ret < 0)
		printf("Failed to free tx adapter %d\n", ret);

	/* Stop and release event devices */
	rte_event_dev_stop(eventdev_id);
	ret = rte_event_dev_close(eventdev_id);
	if (ret < 0)
		printf("Failed to close event dev %d, %d\n", eventdev_id, ret);
}

static void
print_usage(const char *name)
{
	printf("Invalid arguments\n");
	fprintf(stderr, "Usage: %s [arguments]\n"
		"\t[--testmode <N>]\n"
		"\t\t\t0: IPSEC_MSNS\n"
		"\t\t\t1: IPSEC_RTE_PMD_CNXK_API_TEST\n"
		"\t\t\t2: CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST\n"
		"\t[--portmask]	          Port mask to enable\n"
		"\t[--nb-mbufs <count >]  MBUFs per packet pool\n"
		"\t[--num-sas <count>]    Number of SA's to create\n"
		"\t[--inl-inb-oop]        Enable inline inbound OOP\n"
		"\t[--vector-en]          Enable vector mode with eventdev. Default is disabled\n"
		"\t[--vector-sz <size>]   Set vector size. Default is 32.\n"
		"\t[--algo <aes_128_gcm|aes_256_gcm>] Cipher algorithm to use\n"
		"\t[--lpbk]               Enable loopback mode\n"
		"\t[--config <file>]      Configuration file for flow rules\n",
		name);
}

static int
parse_args(int argc, char **argv)
{
	char *name = argv[0];

	argc--;
	argv++;
	while (argc) {
		if (!strcmp(argv[0], "--testmode") && (argc > 1)) {
			testmode = strtoul(argv[1], NULL, 0);
			if (testmode == IPSEC_RTE_PMD_CNXK_API_TEST ||
			    testmode == CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST)
				event_en = true;

			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--portmask") && (argc > 1)) {
			ethdev_port_mask = strtoul(argv[1], NULL, 0);
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--nb-mbufs") && (argc > 1)) {
			nb_bufs = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--num-sas") && (argc > 1)) {
			num_sas = atoi(argv[1]);
			if (num_sas > MAX_SA_SIZE) {
				printf("Number of SAs given is greater than MAX SAs\n");
				return -1;
			}
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--inl-inb-oop")) {
			inl_inb_oop = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--algo")) {
			const char *alg = argv[1];

			argc -= 2;
			argv += 2;
			if (!strcmp(alg, "aes-128-gcm")) {
				sess_conf = &conf_aes_128_gcm;
				continue;
			} else if (!strcmp(alg, "aes-256-gcm")) {
				sess_conf = &conf_aes_256_gcm;
				continue;
			} else {
				printf("Invalid algo %s\n", alg);
			}
		}

		if (!strcmp(argv[0], "--vector-en")) {
			vector_en = true;
			argc--;
			argv++;
			continue;
		}
		if (!strcmp(argv[0], "--vector-sz") && (argc > 1)) {
			vector_sz = strtoul(argv[1], NULL, 0);
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--lpbk")) {
			loopback = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--config") && (argc > 1)) {
			config_file = argv[1];
			continue;
		}

		/* Unknown args */
		print_usage(name);
		return -1;
	}

	return 0;
}

static int
port_init(uint16_t portid, uint32_t nb_mbufs, uint16_t nb_rx_queue, uint16_t nb_tx_queue,
	  uint16_t nb_rxd, uint16_t nb_txd)
{
	uint16_t queueid, lcore_id;
	struct lcore_cfg *lconf;
	int socketid = 0, ret;

	ret = init_pktmbuf_pool(portid, nb_mbufs);
	if (ret) {
		printf("Failed to setup pktmbuf pool for port=%d, ret=%d", portid, ret);
		return ret;
	}

	if (vector_en && vector_pool[portid] == NULL) {
		unsigned int nb_vec;
		char s[64];

		nb_vec = (nb_mbufs + vector_sz - 1) / vector_sz;
		nb_vec = RTE_MAX(512U, nb_vec);
		nb_vec += rte_lcore_count() * 32;
		snprintf(s, sizeof(s), "vector_pool_%d", portid);
		vector_pool[portid] = rte_event_vector_pool_create(s, nb_vec, 32, vector_sz,
								   socketid);
		if (vector_pool[portid] == NULL) {
			printf("Failed to create vector pool for port %d\n", portid);
			return -ENOMEM;
		}
		printf("Allocated vector pool for port %d\n", portid);
	}

	/* Enable loopback mode for non perf test */
	port_conf.lpbk_mode = (testmode == IPSEC_MSNS ||
			       testmode == IPSEC_RTE_PMD_CNXK_API_TEST ||
			       testmode == CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST) ?
			       1 : 0;

	if (loopback)
		port_conf.lpbk_mode = 1;

	if (testmode == CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	/* port configure */
	ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf);
	if (ret < 0) {
		printf("Cannot configure device: err=%d, port=%d\n", ret, portid);
		return ret;
	}
	ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	if (ret < 0) {
		printf("Cannot get mac address: err=%d, port=%d\n", ret, portid);
		return ret;
	}
	printf("Port %u ", portid);
	print_ethaddr("Address:", &ports_eth_addr[portid]);
	printf("\n");

	queueid = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (lcore_id == rte_get_main_lcore())
			continue;

		if (queueid == nb_tx_queue)
			break;

		/* init TX queue */
		printf("Setup txq=%u,%d,%d\n", lcore_id, queueid, socketid);

		ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid, &tx_conf);
		if (ret < 0) {
			printf("rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);
			return ret;
		}

		printf("Setup rxq=%u,%d,%d\n", lcore_id, queueid, socketid);
		ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid, &rx_conf,
					     mbufpool[portid]);
		if (ret < 0) {
			printf("rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, portid);
			return ret;
		}

		lconf = &lcore_cfg[lcore_id];
		lconf->queueid = queueid;

		queueid++;
	}

	return 0;
}

static int
cnxk_sa_index_init(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t size)
{
	uint32_t bmap_sz;
	uint32_t i;
	void *mem;

	if (bmap[port_id][dir].map == NULL) {
		bmap_sz = rte_bitmap_get_memory_footprint(size);
		mem = rte_zmalloc("ut_sa_index_bmap", bmap_sz, RTE_CACHE_LINE_SIZE);
		if (mem == NULL)
			return -1;
		bmap[port_id][dir].map = rte_bitmap_init(size, mem, bmap_sz);
		if (bmap[port_id][dir].map == NULL)
			return -1;
		for (i = 0; i < size; i++)
			rte_bitmap_set(bmap[port_id][dir].map, i);
		bmap[port_id][dir].size = size;
	}
	return 0;
}

static int
ut_setup(int argc, char **argv)
{
	uint32_t nb_lcores;
	uint32_t nb_mbufs;
	uint16_t nb_ports;
	uint16_t nb_rxd;
	uint16_t nb_txd;
	uint16_t portid;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		printf("Invalid EAL arguments\n");
		return -1;
	}
	argc -= ret;
	argv += ret;

	ret = parse_args(argc, argv);
	if (ret < 0)
		return ret;

	if (config_file && parse_cfg_file(config_file)) {
		printf("Failed to parse config file %s\n", config_file);
		return -1;
	}

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < NB_ETHPORTS_USED || ethdev_port_mask == 0) {
		printf("At least %u port(s) used for test\n", NB_ETHPORTS_USED);
		return -1;
	}

	ret = init_sess_mempool();
	if (ret) {
		printf("Unable to initialize session mempool: ret = %d\n", ret);
		return -1;
	}

	nb_lcores = rte_lcore_count();

	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	nb_txd = RTE_TEST_TX_DESC_DEFAULT;

	nb_mbufs = nb_bufs ? nb_bufs : RTE_MAX(nb_ports * (nb_rxd + nb_txd +
							   nb_lcores * MEMPOOL_CACHE_SIZE),
					       NB_MBUF);

	/* Setup all available ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;

		if (testmode == CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST)
			ret = port_init(portid, nb_mbufs, nb_lcores - 1, nb_lcores - 1,
					nb_rxd, nb_txd);
		else
			ret = port_init(portid, nb_mbufs, 1, 1, nb_rxd, nb_txd);

		/* Init sa_index map with 4K size*/
		ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, MAX_SA_SIZE);
		if (ret) {
			printf("egress sa index init failed: err=%d, port=%d\n", ret, portid);
			return ret;
		}

		ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, MAX_SA_SIZE);
		if (ret) {
			printf("ingress sa index init failed: err=%d, port=%d\n", ret, portid);
			return ret;
		}
	}
	if (ret)
		return -1;

	if (event_en) {
		/* Setup event device */
		ret = ut_eventdev_setup();
		if (ret < 0) {
			printf("Failed to setup eventdev, err=%d\n", ret);
			return ret;
		}
	}

	init_lcore();

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;

		if (testmode == CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST) {
			struct rte_pmd_cnxk_profile_cfg_params profile_cfg = {0};
			uint16_t profile_id = 0;

			/* Configure opcode prot field */
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_OPCODE]
				.offset = 40;
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_OPCODE]
				.sizem1 = 1; /* 2 nibbles */
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_OPCODE]
				.logmult = 0;
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_OPCODE]
				.valid = 1;

			/* Configure sa_index prot field */
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_SA_INDEX]
				.offset = 50;
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_SA_INDEX]
				.sizem1 = 1; /* 2 nibbles */
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_SA_INDEX]
				.logmult = 0;
			profile_cfg.prot_field_cfg[RTE_PMD_CNXK_RX_PROT_SA_INDEX]
				.valid = 1;

			/* Set SA size (power-of-2) and max SA count */
			profile_cfg.max_sa = 10;
			profile_cfg.sa_size = rte_align32pow2(
				sizeof(struct rte_pmd_cnxk_ipsec_inb_sa));

			/* Configure default inline config to match IPv4 and use LD layer */
			profile_cfg.def_cfg.lid = 2;           /* LD layer, lptr=14 */
			profile_cfg.def_cfg.ltype_mask = 0xF;
			profile_cfg.def_cfg.ltype_match = 6;
			profile_cfg.def_cfg.match_oipv4 = 1;
			profile_cfg.def_cfg.match_oipv6 = 1;
			profile_cfg.def_cfg.oiplen_ena = 1;

			profile_cfg.gen_cfg.ctx_val = 1;
			profile_cfg.gen_cfg.egrp = 0;

			/* Setup custom profile */
			ret = rte_pmd_cnxk_nix_inl_custom_profile_setup(portid, &profile_cfg,
								       &profile_id);
			if (ret < 0) {
				printf("rte_pmd_cnxk_nix_inl_custom_profile_setup: err=%d, port=%d\n",
				       ret, portid);
				return ret;
			}
			custom_profile_id = profile_id;
			printf("Custom profile created with profile_id=%u on port=%d\n",
			       profile_id, portid);
		}

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			printf("rte_eth_dev_start: err=%d, port=%d\n", ret, portid);
			return ret;
		}
		/* always enable promiscuous */
		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0) {
			printf("rte_eth_promiscuous_enable: err=%s, port=%d\n", rte_strerror(-ret),
			       portid);
			return ret;
		}
	}

	check_all_ports_link_status(ethdev_port_mask);
	flow_init();
	return 0;
}

static void
ut_teardown(void)
{
	int portid;
	int ret;

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%s, port=%u\n", rte_strerror(-ret), portid);
	}

	/* Event device cleanup */
	if (event_en)
		ut_eventdev_teardown();

	/* Release custom profile if it was created */
	if (testmode == CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST) {
		RTE_ETH_FOREACH_DEV(portid) {
			if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
				continue;
			ret = rte_pmd_cnxk_nix_inl_custom_profile_release(portid,
									 custom_profile_id);
			if (ret != 0)
				printf("rte_pmd_cnxk_nix_inl_custom_profile_release: "
				       "err=%d, port=%u\n", ret, portid);
		}
	}

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_eth_dev_reset(portid);
		if (ret != 0)
			printf("rte_eth_dev_reset: err=%s, port=%u\n", rte_strerror(-ret), portid);

	}
}

static void
ipsec_inb_sa_init(struct rte_pmd_cnxk_ipsec_inb_sa *sa)
{
	size_t offset;

	memset(sa, 0, sizeof(struct rte_pmd_cnxk_ipsec_inb_sa));

	sa->w0.s.pkt_output = CPT_IE_OT_SA_PKT_OUTPUT_NO_FRAG;
	sa->w0.s.pkt_format = CPT_IE_OT_SA_PKT_FMT_META;
	sa->w0.s.pkind = CPT_IE_OT_CPT_PKIND;
	sa->w0.s.et_ovrwr = 1;
	sa->w2.s.l3hdr_on_err = 1;

	offset = offsetof(struct rte_pmd_cnxk_ipsec_inb_sa, ctx);
	sa->w0.s.hw_ctx_off = offset / 8;
	sa->w0.s.ctx_push_size = sa->w0.s.hw_ctx_off + 1;
	sa->w0.s.ctx_size = 2;
	sa->w0.s.ctx_hdr_size = 1;
	sa->w0.s.aop_valid = 1;
}

static void
custom_prof_inb_sa_init(struct rte_pmd_cnxk_ipsec_inb_sa *sa)
{
	size_t offset;

	memset(sa, 0, sizeof(struct rte_pmd_cnxk_ipsec_inb_sa));

	/* Reassembly-specific parameters */
	sa->w0.s.pkt_output = CPT_IE_OT_SA_PKT_OUTPUT_HW_BASED_DEFRAG;
	sa->w0.s.pkt_format = CPT_IE_OT_SA_PKT_FMT_META;
	sa->w0.s.pkind = CPT_IE_OT_CPT_PKIND;
	sa->w2.s.l3hdr_on_err = 1;
	sa->w2.s.valid = 1;
	sa->w2.s.dir = CPT_IE_SA_DIR_INBOUND;

	offset = offsetof(struct rte_pmd_cnxk_ipsec_inb_sa, ctx);
	sa->w0.s.hw_ctx_off = offset / 8;
	sa->w0.s.ctx_push_size = sa->w0.s.hw_ctx_off + 1;
	sa->w0.s.ctx_size = 2;
	sa->w0.s.ctx_hdr_size = 1;
	sa->w0.s.aop_valid = 1;
}

static void
create_default_ipsec_flow(uint16_t port_id)
{
	struct rte_flow_action action[2];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	int ret;

	/* Add the default rte_flow to enable SECURITY for all ESP packets */

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ESP;
	pattern[0].spec = NULL;
	pattern[0].mask = NULL;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	action[0].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[0].conf = NULL;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;
	action[1].conf = NULL;

	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret)
		return;

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL)
		return;

	default_flow_no_msns[port_id] = flow;
	printf("Created default flow enabling SECURITY for all ESP traffic on port %d\n",
		port_id);
}

static int
create_custom_flow(uint16_t port_id, enum rte_pmd_cnxk_sec_action_alg alg, uint16_t profile_id)
{
	struct rte_pmd_cnxk_sec_action sec = {0};
	struct rte_flow_action action[3];
	struct rte_flow_item pattern[3];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	struct rte_flow_action_count count = {0};
	int ret;

	/* Match all IPv4 packets */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[0].spec = NULL;
	pattern[0].mask = NULL;
	pattern[0].last = NULL;

	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	/* Action: Count action to track flow hits */
	count.id = 0;
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[0].conf = &count;

	/* Action: Security action with custom profile */
	sec.alg = alg;
	sec.profile_id = profile_id;
	sec.use_custom_profile = true;
	sec.sa_xor = 0;
	sec.sa_hi = 0;
	sec.sa_lo = 0;
	sec.sa_index = 0;

	action[1].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[1].conf = &sec;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;
	action[2].conf = NULL;

	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret) {
		printf("Custom flow validation failed: %s\n",
		       err.message ? err.message : "unknown error");
		return ret;
	}

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL) {
		printf("Custom flow rule create failed: %s\n",
		       err.message ? err.message : "unknown error");
		return -1;
	}

	custom_flow[port_id] = flow;
	printf("Custom flow created for port %u with profile_id %u\n", port_id, profile_id);
	return 0;
}

static void
destroy_custom_flow(uint16_t port_id)
{
	struct rte_flow_error err;
	int ret;

	if (!custom_flow[port_id])
		return;

	ret = rte_flow_destroy(port_id, custom_flow[port_id], &err);
	if (ret) {
		printf("Custom flow rule destroy failed for port=%u, rc=%d\n",
		       port_id, ret);
		return;
	}
	custom_flow[port_id] = NULL;
	printf("Custom flow destroyed for port %u\n", port_id);
}

static void
destroy_default_ipsec_flow(uint16_t portid)
{
	struct rte_flow_error err;
	int ret;

	if (!default_flow_no_msns[portid])
		return;
	ret = rte_flow_destroy(portid, default_flow_no_msns[portid], &err);
	if (ret) {
		printf("\nDefault flow rule destroy failed\n");
		return;
	}
	default_flow_no_msns[portid] = NULL;
}

#define SA_COOKIE 0xAFAFAFAF
static void
pmd_cnxk_api_inb_session_fill(struct rte_pmd_cnxk_ipsec_inb_sa *sa)
{
	uint8_t *salt_key = sa->w8.s.salt;
	uint32_t *tmp_salt;
	uint64_t *tmp_key;
	int i;

	ipsec_inb_sa_init(sa);

	sa->w0.s.count_glb_octets = 1;
	sa->w0.s.count_glb_pkts = 1;
	sa->w2.s.dir = CPT_IE_SA_DIR_INBOUND;
	sa->w2.s.ipsec_protocol = CPT_IE_SA_PROTOCOL_ESP;
	sa->w2.s.ipsec_mode = CPT_IE_SA_MODE_TUNNEL;
	sa->w2.s.enc_type = CPT_IE_OT_SA_ENC_AES_GCM;
	sa->w2.s.auth_type = CPT_IE_OT_SA_AUTH_NULL;

	memcpy(salt_key, &sess_conf->ipsec_xform.salt, 4);
	tmp_salt = (uint32_t *)salt_key;
	*tmp_salt = rte_be_to_cpu_32(*tmp_salt);
	sa->w2.s.spi = 1;

	memcpy(sa->cipher_key, sess_conf->key.data, 16);
	tmp_key = (uint64_t *)sa->cipher_key;
	for (i = 0; i < (int)(CPT_CTX_MAX_CKEY_LEN / sizeof(uint64_t)); i++)
		tmp_key[i] = rte_be_to_cpu_64(tmp_key[i]);

	sa->w2.s.aes_key_len = CPT_IE_SA_AES_KEY_LEN_128;
	sa->w1.s.cookie = SA_COOKIE;
}

static int
pmd_cnxk_api_custom_inb_sa_verify(void)
{
	uint16_t lcore_id = rte_lcore_id();
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	unsigned int portid, nb_rx = 0, j;
	unsigned int nb_sent = 0, nb_tx;
	struct rte_mbuf *tx_pkts = NULL;
	struct rte_mbuf *pkt;
	struct rte_event ev;
	uint32_t *data;
	int rc;

	nb_tx = 1;
	portid = info->portid;
	rc = init_traffic(mbufpool[portid], &tx_pkts, &pkt_ipv4_gcm128_spi1_cipher);
	if (rc != 0)
		return -1;

	create_default_ipsec_flow(portid);
	/* Start event dev */
	ut_eventdev_start();

	nb_sent = rte_eth_tx_burst(portid, 0, &tx_pkts, nb_tx);
	if (nb_sent != nb_tx) {
		printf("\nFailed to tx %u pkts", nb_tx);
		rc = -1;
		goto exit;
	}

	printf("Sent %u pkts\n", nb_sent);
	rte_delay_ms(100);

	/* Retry few times before giving up */
	j = 0;
	while (j++ < 10) {
		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0) {
			rte_pause();
			continue;
		}
		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
			break;
		default:
			printf("Invalid event type %u", ev.event_type);
			rc = -1;
			goto exit;
		}
		pkt = ev.mbuf;
		break;
	}

	printf("Recv %u pkts\n", nb_rx);
	/* Check for minimum number of Rx packets expected */
	if (nb_rx != nb_tx) {
		printf("\nReceived less Rx pkts(%u) pkts\n", nb_rx);
		rc = -1;
		goto exit;
	}
	/* Get meta buffer pointer from WQE, mbuf + 128 is the WQE pointer */
	data = (uint32_t *)(*(uint64_t *)RTE_PTR_ADD(pkt, 128 + 72));
	data += is_plat_cn20k ? 0 : 1;
	if (data[0] != SA_COOKIE) {
		printf("SA cookie is not matched in the meta packet\n");
		rte_hexdump(stdout, NULL, data, pkt->pkt_len);
		rc = -1;
	}
	rte_pktmbuf_free(pkt);
exit:
	destroy_default_ipsec_flow(portid);
	return rc;
}

#define NB_INST		65
#define CPT_RES_ALIGN	sizeof(union rte_pmd_cnxk_cpt_res_s)
static int
pmd_cnxk_api_inl_dev_inst_submit(void *cptr)
{
	struct ipsec_test_packet *pkt = &pkt_ipv4_gcm128_spi1_cipher;
	struct rte_pmd_cnxk_cpt_q_stats stats, prev_stats;
	union rte_pmd_cnxk_cpt_res_s res, *hw_res;
	union roc_ot_ipsec_inb_param1 param1;
	struct cpt_inst_s *inst_mem, *inst;
	void *data_ptrs[NB_INST];
	uint64_t timeout, pkts;
	void *qptr, *dptr;
	int rc = 0, i;

	const union rte_pmd_cnxk_cpt_res_s res_init = {
		.cn10k.compcode = CPT_COMP_NOT_DONE,
	};

	inst_mem = rte_malloc(NULL, NB_INST * sizeof(struct cpt_inst_s), 0);
	if (inst_mem == NULL) {
		printf("Could not allocate instruction memory\n");
		return -ENOMEM;
	}
	rte_pmd_cnxk_cpt_q_stats_get(0, RTE_PMD_CNXK_CPT_Q_STATS_INL_DEV, &prev_stats, 0);
	for (i = 0; i < NB_INST; i++) {
		inst = RTE_PTR_ADD(inst_mem, i * sizeof(struct cpt_inst_s));

		memset(inst, 0, sizeof(struct cpt_inst_s));
		data_ptrs[i] = rte_zmalloc(NULL, MAX_PKT_LEN + CPT_RES_ALIGN, 0);
		if (data_ptrs[i] == NULL) {
			printf("Could not allocate memory for dptr\n");
			rc = -ENOMEM;
			goto exit;
		}
		hw_res = RTE_PTR_ALIGN_CEIL(data_ptrs[i], CPT_RES_ALIGN);

		inst->w3.s.qord = 1;

		dptr = RTE_PTR_ADD(hw_res, sizeof(union rte_pmd_cnxk_cpt_res_s));
		memcpy(dptr, pkt->data, pkt->len);
		inst->dptr = (uint64_t)((uintptr_t)dptr + RTE_ETHER_HDR_LEN);

		inst->w7.s.egrp = is_plat_cn20k ? CPT_DFLT_ENG_GRP_SE : CPT_DFLT_ENG_GRP_SE_IE;
		inst->w7.s.ctx_val = 1;
		inst->w7.s.cptr = (uint64_t)(uintptr_t)cptr;

		inst->w4.s.opcode_major = CPT_IE_OT_MAJOR_OP_PROCESS_INBOUND_IPSEC | (1 << 6);
		param1.u16 = 0;

		/* Disable IP checksum verification by default */
		param1.s.ip_csum_disable = 1;

		/* Disable L4 checksum verification by default */
		param1.s.l4_csum_disable = 1;

		param1.s.esp_trailer_disable = 1;

		inst->w4.s.param1 = param1.u16;
		inst->w4.s.dlen = pkt->len - RTE_ETHER_HDR_LEN;

		inst->res_addr = (uint64_t)hw_res;
		__atomic_store_n(&hw_res->u64[0], res_init.u64[0], __ATOMIC_RELAXED);
	}

	timeout = rte_rdtsc() + rte_get_tsc_hz() * 60;

	qptr = rte_pmd_cnxk_inl_dev_qptr_get();
	if (rte_pmd_cnxk_inl_dev_submit(qptr, inst_mem, NB_INST) != NB_INST) {
		printf("Couldn't submit CPT instructions to inline device\n");
		rc = -1;
		goto exit;
	}
	do {
		hw_res = RTE_PTR_ALIGN_CEIL(data_ptrs[NB_INST - 1], CPT_RES_ALIGN);
		res.u64[0] = __atomic_load_n(&hw_res->u64[0], __ATOMIC_RELAXED);
	} while ((res.cn10k.compcode == CPT_COMP_NOT_DONE) && (rte_rdtsc() < timeout));

	if (res.cn10k.compcode != CPT_COMP_GOOD  && res.cn10k.compcode != CPT_COMP_WARN) {
		printf("res.compcode: %d\n", res.cn10k.compcode);
		rc = -1;
	} else {
		rte_pmd_cnxk_cpt_q_stats_get(0, RTE_PMD_CNXK_CPT_Q_STATS_INL_DEV, &stats, 0);
		pkts = stats.dec_pkts - prev_stats.dec_pkts;
		if (pkts != NB_INST) {
			printf("Inbound packet count: %u is not matched with queue counter: %lu\n",
			       NB_INST, pkts);
			rc = -1;
		}
	}
exit:
	i--;
	for (; i >= 0; i--)
		rte_free(data_ptrs[i]);
	rte_free(inst_mem);

	return rc;
}

#define CUSTOM_SA_SZ  512
static int
rte_pmd_cnxk_api_test(void)
{
	union rte_pmd_cnxk_ipsec_hw_sa *sa, sa_dptr;
	uint16_t lcore_id = rte_lcore_id();
	unsigned int portid;
	int rc = 0;

	portid = lcore_cfg[lcore_id].portid;
	sa = rte_pmd_cnxk_hw_session_base_get(portid, true);
	/* Get the SA for spi 1 */
	sa = RTE_PTR_ADD(sa, CUSTOM_SA_SZ);
	memset(sa, 0, CUSTOM_SA_SZ);

	pmd_cnxk_api_inb_session_fill(&sa_dptr.inb);

	/* Copy word0 from sa_dptr to populate ctx_push_sz ctx_size fields */
	memcpy(sa, &sa_dptr.inb, 8);
	sa_dptr.inb.w2.s.valid = 1;

	rc = rte_pmd_cnxk_hw_sa_write(portid, sa, &sa_dptr, CUSTOM_SA_SZ, true);
	if (rc) {
		printf("Couldn't create the SA\n");
		return rc;
	}
	/* Verify the inline device instruction submit API */
	rc = pmd_cnxk_api_inl_dev_inst_submit(sa);
	if (rc)
		goto exit;

	/* Verify the custom_inb_sa, driver wouldn't do the post processing
	 * of inline IPsec inbound packet.
	 */
	rc = pmd_cnxk_api_custom_inb_sa_verify();

exit:
	/* Destroy the SA */
	ipsec_inb_sa_init(&sa_dptr.inb);
	if (rte_pmd_cnxk_hw_sa_write(portid, sa, &sa_dptr, CUSTOM_SA_SZ, true))
		printf("Couldn't destroy the SA\n");

	return rc;
}

static int
rte_pmd_cnxk_custom_profile_test(void)
{
	union rte_pmd_cnxk_ipsec_hw_sa *sa_base, *sa_ptr, sa_dptr;
	uint16_t lcore_id = rte_lcore_id();
	unsigned int portid;
	uint32_t sa_size = rte_align32pow2(sizeof(struct rte_pmd_cnxk_ipsec_inb_sa));
	uint32_t sa_index = 8; /* Write to 8th SA slot */
	struct rte_mbuf *tx_pkts[3] = {NULL};
	struct reass_test_packet *fragments[3] = {
		&pkt_fragment_0,
		&pkt_fragment_1,
		&pkt_fragment_2
	};
	int rc = 0;
	int i;
	uint16_t nb_sent;
	struct lcore_cfg *info;
	struct rte_mbuf *pkt;
	struct rte_event ev;
	uint32_t *data;
	uint16_t nb_rx = 0;
	int retry = 0;
	const int max_retries = 100;
	uint8_t reas_sts;
	uint16_t rlen;
	uint32_t cookie;
	uint8_t *cpth;
	uint64_t *wqe, *parse_hdr, w0, w3;
	uint8_t compcode, uc_compcode;

	portid = lcore_cfg[lcore_id].portid;
	info = &lcore_cfg[lcore_id];

	/* Get SA base for the custom profile from inline device */
	sa_base = rte_pmd_cnxk_inl_inb_prof_sa_base_get(portid, custom_profile_id);
	if (!sa_base) {
		printf("Failed to get SA base for profile_id=%u on port=%d\n",
		       custom_profile_id, portid);
		return -EINVAL;
	}

	/* Calculate address of 8th SA */
	sa_ptr = (union rte_pmd_cnxk_ipsec_hw_sa *)((uint8_t *)sa_base + (sa_index * sa_size));

	/* Initialize reassembly SA */
	memset(&sa_dptr, 0, sizeof(struct rte_pmd_cnxk_ipsec_inb_sa));
	custom_prof_inb_sa_init(&sa_dptr.inb);

	/* Set SA index/cookie to 8 */
	sa_dptr.inb.w1.s.cookie = sa_index;

	/* Write SA to hardware at 8th slot */
	rc = rte_pmd_cnxk_hw_sa_write(portid, sa_ptr, &sa_dptr, 256, true);
	if (rc) {
		printf("Couldn't write reassembly SA to hardware at index %u\n", sa_index);
		return rc;
	}

	printf("Custom profile test: SA written successfully at index %u for profile_id=%u\n",
	       sa_index, custom_profile_id);

	/* Initialize traffic buffers for three fragment packets */
	for (i = 0; i < 3; i++) {
		/* Cast to ipsec_test_packet since both have same structure (len, data) */
		rc = init_traffic(mbufpool[portid], &tx_pkts[i],
				 (struct ipsec_test_packet *)fragments[i]);
		if (rc) {
			printf("Failed to initialize traffic buffer %d\n", i);
			goto free_pkts;
		}
	}
	printf("Initialized 3 fragment packet buffers\n");

	/* Create custom flow with ALG4 and custom_profile_id */
	rc = create_custom_flow(portid, RTE_PMD_CNXK_SEC_ACTION_ALG4, custom_profile_id);
	if (rc) {
		printf("Failed to create custom flow for port %u\n", portid);
		goto free_pkts;
	}

	/* Start event dev */
	rc = ut_eventdev_start();
	if (rc) {
		printf("Failed to start event device, rc=%d\n", rc);
		goto free_pkts_cleanup;
	}

	rte_delay_ms(100);

	/* Transmit the three fragment packets */
	nb_sent = rte_eth_tx_burst(portid, 0, tx_pkts, 3);
	if (nb_sent != 3) {
		printf("Failed to transmit all packets: sent %u out of 3\n", nb_sent);
		/* Free any packets that weren't sent */
		for (uint16_t i = nb_sent; i < 3; i++) {
			if (tx_pkts[i])
				rte_pktmbuf_free(tx_pkts[i]);
		}
		rc = -1;
		goto cleanup;
	}
	rte_delay_ms(10000);
	/* Receive packet in event mode and verify cookie */
	/* Receive packet - retry until we get it or timeout */
	while (retry < max_retries) {
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0) {
			rte_pause();
			retry++;
			continue;
		}
		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
			break;
		default:
			printf("Invalid event type %u", ev.event_type);
			rc = -1;
			goto cleanup;
		}
		/* Get packet from event */
		pkt = ev.mbuf;

		/* Get meta buffer pointer from WQE, mbuf + 128 is the WQE pointer */
		data = (uint32_t *)(*(uint64_t *)RTE_PTR_ADD(pkt, 128 + 72));
		data += is_plat_cn20k ? 0 : 1;

		wqe = (uint64_t *)RTE_PTR_ADD(pkt, 128);
		compcode = (uint8_t)(wqe[10] & 0xFF);
		uc_compcode = (uint8_t)((wqe[10] >> 8) & 0xFF);
		printf("  CPT comp:  0x%02x, uc_comp: 0x%02x\n", compcode, uc_compcode);

		cpth = rte_pktmbuf_mtod(pkt, uint8_t *);  /* buf_addr + data_off */
		parse_hdr = (uint64_t *)cpth;
		w0 = parse_hdr[0];
		w3 = parse_hdr[3];

		reas_sts = (uint8_t)((w0 >> 49) & 0xF);       /* w0[52:49] = reas_sts */
		rlen = (uint16_t)((w3 >> 48) & 0xFFFF);      /* w3[63:48] = rlen */
		cookie = (uint32_t)(w0 & 0xFFFFFFFF);        /* w0[31:0] = cookie (sa_idx) */

		printf("CPT_PARSE_HDR @ %p (data_off=%u): cookie=%u, reas_sts=%u, rlen=%u\n",
		       (void *)cpth, pkt->data_off, cookie, reas_sts, rlen);

		rc = 0;

		/* Verify cookie matches sa_index (8) */
		if (cookie != sa_index) {
			printf("Cookie mismatch! Expected 0x%x, got 0x%x\n",
			       sa_index, cookie);
			rc = -1;
		}

		/* Verify reas_sts is 0 (success) */
		if (reas_sts != 0) {
			printf("Reassembly status error! reas_sts=%u (expected 0)\n",
			       reas_sts);
			rc = -1;
		}

		/* Verify rlen is non-zero (reassembled length) */
		if (rlen == 0) {
			printf("Reassembled length is zero!\n");
			rc = -1;
		}

		if (rc != 0)
			rte_hexdump(stdout, "Meta data", data, 32);

		/* Free received packet */
		rte_pktmbuf_free(pkt);

		break;
	}

	if (nb_rx == 0) {
		printf("FAILED: No packet received after %d retries\n", max_retries);
		rc = -1;
	} else if (rc == 0) {
		printf("PASSED: Packet received with correct cookie\n");
	} else {
		printf("FAILED: Cookie mismatch\n");
	}

	goto cleanup;

free_pkts_cleanup:
	/* Destroy custom flow before freeing packets */
	destroy_custom_flow(portid);

free_pkts:
	for (i = 0; i < 3; i++) {
		if (tx_pkts[i])
			rte_pktmbuf_free(tx_pkts[i]);
	}
	return rc;

cleanup:
	/* Destroy custom flow */
	destroy_custom_flow(portid);

	return rc;
}

static int
cnxk_sa_index_alloc(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t size)
{
	bool update_idx;
	int index, bit;
	uint32_t count;
	uint32_t i, j;

	if (bmap[port_id][dir].map == NULL)
		return -1;

	if (size > bmap[port_id][dir].size)
		return -1;

	__rte_bitmap_scan_init(bmap[port_id][dir].map);
	i = 0;
retry:
	update_idx = 1;
	count = 0;
	index = -1;
	for (; i < bmap[port_id][dir].size; i++) {
		bit = rte_bitmap_get(bmap[port_id][dir].map, i);
		if (bit) {
			if (update_idx) {
				if ((i + size) > bmap[port_id][dir].size)
					return -1;
				index = i;
				update_idx = 0;
			}
			count++;
			if (count >= size) {
				for (j = index; j < (index + size); j++)
					rte_bitmap_clear(bmap[port_id][dir].map, j);
				return index;
			}
		} else {
			i++;
			goto retry;
		}
	}
	return -1;
}

static int
cnxk_sa_index_free(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t sa_index,
		   uint32_t size)
{
	uint32_t i;
	int bit;

	if (bmap[port_id][dir].map == NULL)
		return -1;

	if ((sa_index + size) > bmap[port_id][dir].size)
		return -1;

	for (i = sa_index; i < sa_index + size; i++) {
		bit = rte_bitmap_get(bmap[port_id][dir].map, i);
		if (!bit)
			rte_bitmap_set(bmap[port_id][dir].map, i);
	}
	return 0;
}

static int
compare_pkt_data(struct rte_mbuf *m, uint8_t *ref, unsigned int tot_len)
{
	unsigned int nb_segs = m->nb_segs;
	struct rte_mbuf *save = m;
	unsigned int matched = 0;
	unsigned int len;

	while (m && nb_segs != 0) {
		len = tot_len;
		if (len > m->data_len)
			len = m->data_len;
		if (len != 0) {
			if (memcmp(rte_pktmbuf_mtod(m, char *), ref + matched, len)) {
				printf("\n====Test case failed: Data Mismatch");
				rte_hexdump(stdout, "Data", rte_pktmbuf_mtod(m, char *), len);
				rte_hexdump(stdout, "Reference", ref + matched, len);
				return -1;
			}
		}
		tot_len -= len;
		matched += len;
		m = m->next;
		nb_segs--;
	}

	if (tot_len) {
		printf("\n====Test case failed: Data Missing %u", tot_len);
		printf("\n====nb_segs %u, tot_len %u", nb_segs, tot_len);
		rte_pktmbuf_dump(stderr, save, -1);
		return -1;
	}
	return 0;
}

/* Create Inline IPsec session */
static int
create_inline_ipsec_session(struct ipsec_session_data *sa, uint16_t portid,
			    struct rte_security_session **ses,
			    enum rte_security_ipsec_sa_direction dir,
			    enum rte_security_ipsec_tunnel_type tun_type)
{
	uint32_t src_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 2));
	uint32_t dst_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 1));
	uint16_t src_v6[8] = {0x2607, 0xf8b0, 0x400c, 0x0c03, 0x0000, 0x0000, 0x0000, 0x001a};
	uint16_t dst_v6[8] = {0x2001, 0x0470, 0xe5bf, 0xdead, 0x4957, 0x2174, 0xe82c, 0x4887};
	struct rte_security_session_conf sess_conf = {
		.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
		.ipsec = sa->ipsec_xform,
		.crypto_xform = &sa->xform.aead,
		.userdata = NULL,
	};
	const struct rte_security_capability *sec_cap;
	struct rte_security_ctx *sec_ctx;

	sess_conf.ipsec.direction = dir;
	sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return -1;
	}

	sec_cap = rte_security_capabilities_get(sec_ctx);
	if (sec_cap == NULL) {
		printf("No capabilities registered\n");
		return -1;
	}

	/* iterate until ESP tunnel*/
	while (sec_cap->action != RTE_SECURITY_ACTION_TYPE_NONE) {
		if (sec_cap->action == sess_conf.action_type &&
		    sec_cap->protocol == RTE_SECURITY_PROTOCOL_IPSEC &&
		    sec_cap->ipsec.mode == sess_conf.ipsec.mode && sec_cap->ipsec.direction == dir)
			break;
		sec_cap++;
	}

	if (sec_cap->action == RTE_SECURITY_ACTION_TYPE_NONE) {
		printf("No suitable security capability found\n");
		return -1;
	}

	sess_conf.crypto_xform->aead.key.data = sa->key.data;

	/* Save SA as userdata for the security session. When
	 * the packet is received, this userdata will be
	 * retrieved using the metadata from the packet.
	 *
	 * The PMD is expected to set similar metadata for other
	 * operations, like rte_eth_event, which are tied to
	 * security session. In such cases, the userdata could
	 * be obtained to uniquely identify the security
	 * parameters denoted.
	 */

	sess_conf.userdata = (void *)sa;
	sess_conf.ipsec.tunnel.type = tun_type;
	if (tun_type == RTE_SECURITY_IPSEC_TUNNEL_IPV4) {
		memcpy(&sess_conf.ipsec.tunnel.ipv4.src_ip, &src_v4, sizeof(src_v4));
		memcpy(&sess_conf.ipsec.tunnel.ipv4.dst_ip, &dst_v4, sizeof(dst_v4));
	} else {
		memcpy(&sess_conf.ipsec.tunnel.ipv6.src_addr, &src_v6, sizeof(src_v6));
		memcpy(&sess_conf.ipsec.tunnel.ipv6.dst_addr, &dst_v6, sizeof(dst_v6));
	}

	*ses = rte_security_session_create(sec_ctx, &sess_conf, sess_pool);
	if (*ses == NULL) {
		printf("SEC Session init failed\n");
		return -1;
	}

	return 0;
}

static int
create_default_flow(uint16_t port_id, enum rte_pmd_cnxk_sec_action_alg alg, uint32_t spi,
		    uint16_t sa_lo, uint16_t sa_hi, uint32_t sa_index)
{
	struct rte_pmd_cnxk_sec_action sec = {0};
	struct rte_flow_action_mark mark = {0};
	struct rte_flow_item_esp mesp = {0};
	struct rte_flow_item_esp esp = {0};
	struct rte_flow_action action[3];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	int act_count = 0;
	int ret;

	/* Add the default rte_flow to enable SECURITY for all ESP packets */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ESP;
	pattern[0].spec = &esp;
	pattern[0].mask = &mesp;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	if (inl_inb_oop)
		sec.is_non_inp = 1;

	action[act_count].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[act_count].conf = &sec;
	act_count++;

	esp.hdr.spi = RTE_BE32(spi);
	mesp.hdr.spi = RTE_BE32(0xffffffff);
	switch (alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG0;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG1;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG2;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG3;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG4:
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG4;
		sec.sa_xor = 0;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		sec.sa_index = sa_index;
		esp.hdr.spi = RTE_BE32(0x100);
		mesp.hdr.spi = RTE_BE32(0xffffffff);
		mark.id = 0x200;
		action[act_count].type = RTE_FLOW_ACTION_TYPE_MARK;
		action[act_count].conf = &mark;
		act_count++;
		break;
	}

	action[act_count].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_count].conf = NULL;
	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret)
		return ret;

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL) {
		printf("\nDefault flow rule create failed\n");
		return -1;
	}

	default_flow[port_id][alg] = flow;
	return 0;
}

static void
destroy_default_flow(uint16_t port_id)
{
	struct rte_flow_error err;
	uint8_t alg;
	int ret;

	for (alg = RTE_PMD_CNXK_SEC_ACTION_ALG0; alg <= RTE_PMD_CNXK_SEC_ACTION_ALG4; alg++) {
		if (!default_flow[port_id][alg])
			continue;
		ret = rte_flow_destroy(port_id, default_flow[port_id][alg], &err);
		if (ret) {
			printf("\nDefault flow rule destroy failed for port=%d alg=%d, rc=%d\n",
			       port_id, alg, ret);
			return;
		}
		default_flow[port_id][alg] = NULL;
	}
}

static int
ut_ipsec_encap_decap(struct test_ipsec_vector *vector, enum rte_security_ipsec_tunnel_type tun_type,
		     uint8_t alg)
{
	struct rte_security_session *out_ses = NULL, *in_ses = NULL;
	uint32_t in_sa_index = 0, out_sa_index = 0, spi = 0;
	struct rte_security_session_conf conf = {0};
	struct rte_security_ctx *sec_ctx = NULL;
	uint32_t index_count = 0, sa_index = 0;
	uint16_t lcore_id = rte_lcore_id();
	struct ipsec_session_data sa_data;
	unsigned int portid, nb_rx = 0, j;
	unsigned int nb_sent = 0, nb_tx;
	struct rte_mbuf *tx_pkts = NULL;
	struct rte_mbuf *rx_pkts = NULL;
	uint16_t sa_hi = 0, sa_lo = 0;
	uint64_t userdata;
	int ret = 0;

	nb_tx = 1;
	portid = lcore_cfg[lcore_id].portid;
	ret = init_traffic(mbufpool[portid], &tx_pkts, vector->frags);
	if (ret != 0) {
		ret = -1;
		goto out;
	}

	switch (alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		/* Allocate 1 index and use it */
		index_count = 1;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index;
		spi = (0x1 << 28 | in_sa_index);
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		/* Allocate 2 index and use higher index */
		index_count = 2;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 1;
		spi = (sa_index << 28) | 0x0000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		/* Allocate 3 index and use higher index */
		index_count = 3;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 2;
		spi = (sa_index << 25) | 0x00000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		/* Allocate 3 index and use higher index */
		index_count = 3;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 2;
		spi = (sa_index << 25) | 0x00000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG4:
		/* Allocate 4 index and use higher index */
		index_count = 4;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 3;
		spi = 0x100;
		sa_hi = 0;
		sa_lo = 0;
		break;
	default:
		ret = -1;
		goto out;
	}

	sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = out_sa_index;
	/* Create Inline IPsec outbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &out_ses,
					  RTE_SECURITY_IPSEC_SA_DIR_EGRESS, tun_type);
	if (ret)
		goto out;
	printf("Created Outbound session with sa_index = 0x%x\n", sa_data.ipsec_xform.spi);

	/* Update the real spi value */
	sa_data.ipsec_xform.spi = spi;
	sa_data.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	memcpy(&conf.ipsec, &sa_data.ipsec_xform, sizeof(struct rte_security_ipsec_xform));
	conf.crypto_xform = &sa_data.xform.aead;
	ret = rte_security_session_update(sec_ctx, out_ses, &conf);
	if (ret) {
		printf("Security session update failed outbound\n");
		goto out;
	}
	printf("Updated Outbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	rte_security_set_pkt_metadata(sec_ctx, out_ses, tx_pkts, NULL);
	tx_pkts->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
	tx_pkts->l2_len = RTE_ETHER_HDR_LEN;

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = sa_index;
	/* Create Inline IPsec inbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &in_ses,
					  RTE_SECURITY_IPSEC_SA_DIR_INGRESS, tun_type);
	if (ret)
		goto out;
	printf("Created Inbound session with sa_index = 0x%x\n", sa_data.ipsec_xform.spi);

	sa_data.ipsec_xform.spi = spi;
	sa_data.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	memcpy(&conf.ipsec, &sa_data.ipsec_xform, sizeof(struct rte_security_ipsec_xform));
	conf.crypto_xform = &sa_data.xform.aead;
	conf.userdata = (void *)(uint64_t)(alg);
	ret = rte_security_session_update(sec_ctx, in_ses, &conf);
	if (ret) {
		printf("Security session update failed inbound\n");
		goto out;
	}
	printf("Updated Inbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	ret = create_default_flow(portid, alg, spi, sa_lo, sa_hi, sa_index);
	if (ret) {
		printf("Flow creation failed\n");
		goto out;
	}

	nb_sent = rte_eth_tx_burst(portid, 0, &tx_pkts, nb_tx);
	if (nb_sent != nb_tx) {
		ret = -1;
		printf("\nFailed to tx %u pkts", nb_tx);
		goto out;
	}

	printf("Sent %u pkts\n", nb_sent);
	rte_delay_ms(100);

	/* Retry few times before giving up */
	nb_rx = 0;
	j = 0;
	do {
		nb_rx += rte_eth_rx_burst(portid, 0, &rx_pkts, nb_tx - nb_rx);
		j++;
		if (nb_rx >= nb_tx)
			break;
		rte_delay_ms(100);
	} while (j < 10);

	printf("Recv %u pkts\n", nb_rx);
	/* Check for minimum number of Rx packets expected */
	if (nb_rx != nb_tx) {
		printf("\nReceived less Rx pkts(%u) pkts\n", nb_rx);
		ret = -1;
		goto out;
	}

	if (rx_pkts->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED ||
	    !(rx_pkts->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD)) {
		printf("\nSecurity offload failed\n");
		ret = -1;
		goto out;
	}

	/* Check for userdata match */
	userdata = *rte_security_dynfield(rx_pkts);
	if (userdata != alg) {
		printf("\nDecrypted packet userdata mismatch %lx != %x\n",
		       userdata, alg);
		ret = -1;
		goto out;
	}

	if (vector->full_pkt->len != rx_pkts->pkt_len) {
		printf("\nDecrypted packet length mismatch\n");
		ret = -1;
		goto out;
	}
	ret = compare_pkt_data(rx_pkts, vector->full_pkt->data, vector->full_pkt->len);
out:
	destroy_default_flow(portid);

	cnxk_sa_index_free(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, out_sa_index, index_count);
	cnxk_sa_index_free(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, in_sa_index, index_count);

	/* Clear session data. */
	if (out_ses)
		rte_security_session_destroy(sec_ctx, out_ses);
	if (in_ses)
		rte_security_session_destroy(sec_ctx, in_ses);

	rte_pktmbuf_free(tx_pkts);
	rte_pktmbuf_free(rx_pkts);
	return ret;
}

static int
ut_ipsec_ipv4_burst_encap_decap(void)
{
	struct test_ipsec_vector ipv4_nofrag_case = {
		.sa_data = sess_conf,
		.full_pkt = &pkt_ipv4_plain,
		.frags = &pkt_ipv4_plain,
	};
	int rc;

	/* Start event dev */
	ut_eventdev_start();

	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG0);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG0: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG1);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG1: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG2);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG2: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG3);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG3: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG4);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG4: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	return 0;
}

int
main(int argc, char **argv)
{
	const char *pattern = "cn20k";
	int rc = 0;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	rc = ut_setup(argc, argv);
	if (rc == -ENOTSUP) {
		printf("Custom inline profile not supported on this platform, skipping test\n");
		return 0;
	}
	if (rc) {
		printf("TEST FAILED: ut_setup\n");
		return rc;
	}

	is_plat_cn20k = strstr(rte_pmd_cnxk_model_str_get(), pattern) ? true : false;

	printf("\n");
	switch (testmode) {
	case IPSEC_MSNS:
		rc = ut_ipsec_ipv4_burst_encap_decap();
		if (rc)
			printf("TEST FAILED: ut_ipsec_ipv4_burst_encap_decap\n");
		break;
	case IPSEC_RTE_PMD_CNXK_API_TEST:
		printf("Model: %s Test Mode: %s\n", rte_pmd_cnxk_model_str_get(),
		       ipsec_test_mode_to_string(testmode));
		rc = rte_pmd_cnxk_api_test();
		printf("Test %s: %s\n", ipsec_test_mode_to_string(testmode), rc ? "FAILED" : "PASS");
		break;
	case CUSTOM_PROFILE_RTE_PMD_CNXK_API_TEST:
		printf("Model: %s Test Mode: %s\n", rte_pmd_cnxk_model_str_get(),
		       ipsec_test_mode_to_string(testmode));
		rc = rte_pmd_cnxk_custom_profile_test();
		printf("Test %s: %s\n", ipsec_test_mode_to_string(testmode), rc ? "FAILED" : "PASS");
		break;
	}
	ut_teardown();
	return rc;
}
