/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <inttypes.h>
#include <rte_atomic.h>
#include <rte_bitmap.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hexdump.h>
#include <rte_ipsec.h>
#include <rte_malloc.h>
#include <rte_pmd_cnxk.h>
#include <rte_security.h>

#include "ipsec_msns.h"

#define NB_ETHPORTS_USED	 1
#define MEMPOOL_CACHE_SIZE	 32
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define RTE_PORT_ALL		 (~(uint16_t)0x0)

#define RX_PTHRESH 8  /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8  /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0  /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define NB_MBUF 10240

static struct rte_mempool *mbufpool;
static struct rte_mempool *sess_pool;
static struct rte_mempool *sess_priv_pool;
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_NONE,
			.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SECURITY,
		},
	.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
			.offloads = RTE_ETH_TX_OFFLOAD_SECURITY | RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
		},
	.lpbk_mode = 1, /* enable loopback */
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
	uint16_t port;
};

static struct lcore_cfg lcore_cfg;

static struct rte_flow *default_flow[RTE_MAX_ETHPORTS];

struct sa_index_map {
	struct rte_bitmap *map;
	uint32_t size;
};

static struct sa_index_map bmap[RTE_MAX_ETHPORTS][2];

/* Example usage, max entries 4K */
#define MAX_SA_SIZE (4 * 1024)

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

static void
cnxk_sa_index_fini(int port_id, enum rte_security_ipsec_sa_direction dir)
{
	rte_free(bmap[port_id][dir].map);
	bmap[port_id][dir].map = NULL;
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
		printf("\n====Test casecase failed: Data Missing %u", tot_len);
		printf("\n====nb_segs %u, tot_len %u", nb_segs, tot_len);
		rte_pktmbuf_dump(stderr, save, -1);
		return -1;
	}
	return 0;
}

/* Create Inline IPsec session */
static int
create_inline_ipsec_session(struct ipsec_session_data *sa, uint16_t portid,
			    struct rte_ipsec_session *ips, enum rte_security_ipsec_sa_direction dir,
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

	ips->security.ses = rte_security_session_create(
		sec_ctx, &sess_conf, sess_pool, sess_priv_pool);
	if (ips->security.ses == NULL) {
		printf("SEC Session init failed\n");
		return -1;
	}

	ips->security.ol_flags = sec_cap->ol_flags;
	ips->security.ctx = sec_ctx;

	return 0;
}

/* Check the link status of all ports in up to 3s, and print them finally */
static void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
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
		for (portid = 0; portid < port_num; portid++) {
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
	unsigned int lcore_id;
	uint16_t portid;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_cfg.socketid = rte_lcore_to_socket_id(lcore_id);
		if (rte_lcore_is_enabled(lcore_id) != 0) {
			RTE_ETH_FOREACH_DEV(portid) {
				if (lcore_cfg.socketid == rte_eth_dev_socket_id(portid)) {
					lcore_cfg.port = portid;
					break;
				}
			}
			return;
		}
	}
}

static int
init_mempools(unsigned int nb_mbuf)
{
	struct rte_security_ctx *sec_ctx;
	uint16_t nb_sess = 512;
	unsigned int lcore_id;
	uint32_t sess_sz;
	int socketid;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		socketid = rte_lcore_to_socket_id(lcore_id);
		if (mbufpool == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			mbufpool = rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
							   RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (mbufpool == NULL)
				printf("Cannot init mbuf pool on socket %d\n", socketid);
			printf("Allocated mbuf pool on socket %d\n", socketid);
		}

		sec_ctx = rte_eth_dev_get_sec_ctx(lcore_cfg.port);
		if (sec_ctx == NULL)
			continue;

		sess_sz = rte_security_session_get_size(sec_ctx);
		if (sess_pool == NULL) {
			snprintf(s, sizeof(s), "sess_pool_%d", socketid);
			sess_pool = rte_mempool_create(s, nb_sess, sess_sz, MEMPOOL_CACHE_SIZE, 0,
						       NULL, NULL, NULL, NULL, socketid, 0);
			if (sess_pool == NULL) {
				printf("Cannot init sess pool on socket %d\n", socketid);
				rte_mempool_free(mbufpool);
				return -1;
			}
			printf("Allocated sess pool on socket %d\n", socketid);
		}
		if (sess_priv_pool == NULL) {
			snprintf(s, sizeof(s), "sess_priv_pool_%d", socketid);
			sess_priv_pool = rte_mempool_create(
				s, nb_sess, sess_sz, MEMPOOL_CACHE_SIZE, 0,
				NULL, NULL, NULL, NULL, socketid, 0);
			if (sess_priv_pool == NULL) {
				printf("Cannot init sess_priv pool on socket %d\n",
				       socketid);
				rte_mempool_free(mbufpool);
				return -1;
			}
			printf("Allocated sess_priv pool on socket %d\n",
			       socketid);
		}
	}
	return 0;
}

static int
create_default_flow(uint16_t port_id, enum rte_pmd_cnxk_sec_action_alg alg, uint16_t sa_lo,
		    uint16_t sa_hi, uint32_t sa_index)
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

	action[act_count].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[act_count].conf = &sec;
	act_count++;

	switch (alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		/* SPI = 0x10000001, sa_index = 0 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG0;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		/* SPI = 0x10000001, sa_index = 1 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG1;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		/* SPI = 0x04000001, sa_index = 2 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG2;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		/* SPI = 0x04000001, sa_index = 2 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG3;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG4:
		/* SPI = 0x100, sa_index = 3 */
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

	default_flow[port_id] = flow;
	return 0;
}

static void
destroy_default_flow(uint16_t port_id)
{
	struct rte_flow_error err;
	int ret;

	if (!default_flow[port_id])
		return;
	ret = rte_flow_destroy(port_id, default_flow[port_id], &err);
	if (ret) {
		printf("\nDefault flow rule destroy failed\n");
		return;
	}
	default_flow[port_id] = NULL;
}

static int
ut_setup_inline_ipsec(void)
{
	uint16_t portid = lcore_cfg.port;
	int ret;

	/* Start device */
	ret = rte_eth_dev_start(portid);
	if (ret < 0) {
		printf("rte_eth_dev_start: err=%d, port=%d\n", ret, portid);
		return ret;
	}
	/* always enable promiscuous */
	ret = rte_eth_promiscuous_enable(portid);
	if (ret != 0) {
		printf("rte_eth_promiscuous_enable: err=%s, port=%d\n", rte_strerror(-ret), portid);
		return ret;
	}
	check_all_ports_link_status(1, RTE_PORT_ALL);

	return 0;
}

static void
ut_teardown_inline_ipsec(void)
{
	int socketid = lcore_cfg.socketid;
	uint16_t portid = lcore_cfg.port;
	int ret;

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		if (socketid != rte_eth_dev_socket_id(portid))
			continue;

		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%s, port=%u\n", rte_strerror(-ret), portid);
	}
}

static int
ut_setup(int argc, char **argv)
{
	uint16_t nb_rx_queue = 1, nb_tx_queue = 1;
	int socketid, ret;
	uint16_t nb_ports;
	uint16_t nb_rxd;
	uint16_t nb_txd;
	uint16_t portid;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		printf("Invalid EAL arguments\n");
		return -1;
	}
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < NB_ETHPORTS_USED) {
		printf("At least %u port(s) used for test\n", NB_ETHPORTS_USED);
		return -1;
	}

	init_lcore();

	ret = init_mempools(NB_MBUF);
	if (ret) {
		printf("Unable to initialize mempools: ret = %d\n", ret);
		return -1;
	}

	portid = lcore_cfg.port;
	socketid = lcore_cfg.socketid;

	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	nb_txd = RTE_TEST_TX_DESC_DEFAULT;

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

	/* tx queue setup */
	ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, socketid, &tx_conf);
	if (ret < 0) {
		printf("rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);
		return ret;
	}
	/* rx queue steup */
	ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, socketid, &rx_conf, mbufpool);
	if (ret < 0) {
		printf("rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, portid);
		return ret;
	}

	return 0;
}

static void
ut_teardown(void)
{
	uint16_t socketid = lcore_cfg.socketid;
	uint16_t portid = lcore_cfg.port;
	int ret;

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		if (socketid != rte_eth_dev_socket_id(portid))
			continue;

		ret = rte_eth_dev_reset(portid);
		if (ret != 0)
			printf("rte_eth_dev_reset: err=%s, port=%u\n", rte_strerror(-ret), portid);
	}
}

static int
ut_ipsec_encap_decap(struct test_ipsec_vector *vector, enum rte_security_ipsec_tunnel_type tun_type,
		     uint8_t alg)
{
	uint32_t in_sa_index = 0, out_sa_index = 0, spi = 0;
	struct rte_security_session_conf conf = {0};
	uint32_t index_count = 0, sa_index = 0;
	struct rte_ipsec_session out_ips = {0};
	struct rte_ipsec_session in_ips = {0};
	struct ipsec_session_data sa_data;
	unsigned int portid, nb_rx = 0, j;
	unsigned int nb_sent = 0, nb_tx;
	struct rte_mbuf *tx_pkts = NULL;
	struct rte_mbuf *rx_pkts = NULL;
	uint16_t sa_hi = 0, sa_lo = 0;
	int ret = 0;

	nb_tx = 1;
	portid = lcore_cfg.port;
	ret = init_traffic(mbufpool, &tx_pkts, vector->frags);
	if (ret != 0) {
		ret = -1;
		goto out;
	}

	/* Init sa_index map with 4K size*/
	ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, MAX_SA_SIZE);
	if (ret) {
		ret = -1;
		goto out;
	}

	ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, MAX_SA_SIZE);
	if (ret) {
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

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = out_sa_index;
	/* Create Inline IPsec outbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &out_ips,
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
	ret = rte_security_session_update(out_ips.security.ctx, out_ips.security.ses, &conf);
	if (ret) {
		printf("Security session update failed outbound\n");
		goto out;
	}
	printf("Updated Outbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	if (out_ips.security.ol_flags & RTE_SECURITY_TX_OLOAD_NEED_MDATA)
		rte_security_set_pkt_metadata(out_ips.security.ctx, out_ips.security.ses, tx_pkts,
					      NULL);
	tx_pkts->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
	tx_pkts->l2_len = RTE_ETHER_HDR_LEN;

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = sa_index;
	/* Create Inline IPsec inbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &in_ips,
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
	ret = rte_security_session_update(in_ips.security.ctx, in_ips.security.ses, &conf);
	if (ret) {
		printf("Security session update failed inbound\n");
		goto out;
	}
	printf("Updated Inbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	ret = create_default_flow(portid, alg, sa_lo, sa_hi, sa_index);
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

	cnxk_sa_index_fini(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS);
	cnxk_sa_index_fini(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS);

	/* Clear session data. */
	if (out_ips.security.ses)
		rte_security_session_destroy(out_ips.security.ctx, out_ips.security.ses);
	if (in_ips.security.ses)
		rte_security_session_destroy(in_ips.security.ctx, in_ips.security.ses);

	rte_pktmbuf_free(tx_pkts);
	rte_pktmbuf_free(rx_pkts);
	return ret;
}

static int
ut_ipsec_ipv4_burst_encap_decap(void)
{
	struct test_ipsec_vector ipv4_nofrag_case = {
		.sa_data = &conf_aes_128_gcm,
		.full_pkt = &pkt_ipv4_plain,
		.frags = &pkt_ipv4_plain,
	};
	int rc;

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
	int rc;

	rc = ut_setup(argc, argv);
	if (rc) {
		printf("TEST FAILED: ut_setup\n");
		return rc;
	}
	rc = ut_setup_inline_ipsec();
	if (rc) {
		printf("TEST FAILED: ut_setup_inline_ipsec\n");
		return rc;
	}
	rc = ut_ipsec_ipv4_burst_encap_decap();
	if (rc) {
		printf("TEST FAILED: ut_ipsec_ipv4_burst_encap_decap\n");
		return rc;
	}
	ut_teardown_inline_ipsec();
	ut_teardown();
	return 0;
}
