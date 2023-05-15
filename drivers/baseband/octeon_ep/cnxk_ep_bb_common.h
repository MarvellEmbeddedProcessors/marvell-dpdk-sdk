/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _CNXK_EP_BB_COMMON_H_
#define _CNXK_EP_BB_COMMON_H_

#include <rte_interrupts.h>
#include <rte_bbdev.h>
#include <rte_bus_pci.h>

#include "cnxk_ep_bb_msg.h"

#define DRIVER_NAME octeon_ep_bb_vf

#define CNXK_EP_BB_NW_PKT_OP		0x1220
#define CNXK_EP_BB_NW_CMD_OP		0x1221

#define CNXK_EP_BB_MAX_RINGS_PER_VF	(8)
#define CNXK_EP_BB_CFG_IO_QUEUES	CNXK_EP_BB_MAX_RINGS_PER_VF
#define CNXK_EP_BB_64BYTE_INSTR		(64)

#define EPDEV_RX_OFFLOAD_SCATTER	RTE_BIT64(0)
#define EPDEV_TX_OFFLOAD_MULTI_SEGS	RTE_BIT64(0)

/* this is a static value set by SLI PF driver in octeon
 * No handshake is available
 * Change this if changing the value in SLI PF driver
 */
/* TODO: Common for all platorms - copied from otx_ep_vf.h */
#define SDP_GBL_WMARK 0x100

/* TODO: some of these config parameters are not used */
/*
 * Backpressure for SDP is configured on Octeon, and the minimum queue sizes
 * must be much larger than the backpressure watermark configured in the Octeon
 * SDP driver.  IQ and OQ backpressure configurations are separate.
 */
#define CNXK_EP_BB_MIN_IQ_DESCRIPTORS	(2048)
#define CNXK_EP_BB_MIN_OQ_DESCRIPTORS	(2048)
#define CNXK_EP_BB_MAX_IQ_DESCRIPTORS	(8192)
#define CNXK_EP_BB_MAX_OQ_DESCRIPTORS	(8192)
#define CNXK_EP_BB_OQ_BUF_SIZE		(2048)
#define CNXK_EP_BB_MIN_RX_BUF_SIZE	(64)

#define CNXK_EP_BB_OQ_INFOPTR_MODE	(0)
#define CNXK_EP_BB_OQ_REFIL_THRESHOLD	(16)

/* IQ instruction req types */
#define CNXK_EP_BB_REQTYPE_NONE             (0)
#define CNXK_EP_BB_REQTYPE_NORESP_INSTR     (1)
#define CNXK_EP_BB_REQTYPE_NORESP_NET_DIRECT       (2)
#define CNXK_EP_BB_REQTYPE_NORESP_NET       CNXK_EP_BB_REQTYPE_NORESP_NET_DIRECT
#define CNXK_EP_BB_REQTYPE_NORESP_GATHER    (3)
#define CNXK_EP_BB_NORESP_OHSM_SEND     (4)
#define CNXK_EP_BB_NORESP_LAST          (4)
#define CNXK_EP_BB_PCI_RING_ALIGN   65536
#define SDP_PKIND 40
#define SDP_OTX2_PKIND_FS24 57	/* Front size 24, NIC mode */
/* Use LBK PKIND */
#define SDP_OTX2_PKIND_FS0  0	/* Front size 0, LOOP packet mode */

/*
 * Values for SDP packet mode
 * NIC: Has 24 byte header Host-> Octeon, 8 byte header Octeon->Host,
 *      application must handle these
 * LOOP: No headers, standard DPDK apps work on both ends.
 * The mode is selected by a parameter provided to the HOST DPDK driver
 */
#define SDP_PACKET_MODE_NIC	0x0
#define SDP_PACKET_MODE_LOOP	0x1

#define      ORDERED_TAG 0
#define      ATOMIC_TAG  1
#define      NULL_TAG  2
#define      NULL_NULL_TAG  3

#define CNXK_EP_BB_BUSY_LOOP_COUNT      (10000)
#define CNXK_EP_BB_MAX_IOQS_PER_VF 8
#define OTX_CUST_DATA_LEN 0

#define cnxk_ep_bb_info(fmt, args...)				\
	rte_log(RTE_LOG_INFO, octeon_ep_bbdev_logtype,		\
		"%s():%u " fmt "\n",				\
		__func__, __LINE__, ##args)

#define cnxk_ep_bb_err(fmt, args...)				\
	rte_log(RTE_LOG_ERR, octeon_ep_bbdev_logtype,		\
		"%s():%u " fmt "\n",				\
		__func__, __LINE__, ##args)

#define cnxk_ep_bb_dbg(fmt, args...)				\
	rte_log(RTE_LOG_DEBUG, octeon_ep_bbdev_logtype,		\
		"%s():%u " fmt "\n",				\
		__func__, __LINE__, ##args)

/* IO Access */
#define oct_ep_read64(addr) rte_read64_relaxed((void *)(addr))
#define oct_ep_write64(val, addr) rte_write64_relaxed((val), (void *)(addr))


/* Input Request Header format */
union cnxk_ep_bb_instr_irh {
	uint64_t u64;
	struct {
		/* Request ID  */
		uint64_t rid:16;

		/* PCIe port to use for response */
		uint64_t pcie_port:3;

		/* Scatter indicator  1=scatter */
		uint64_t scatter:1;

		/* Size of Expected result OR no. of entries in scatter list */
		uint64_t rlenssz:14;

		/* Desired destination port for result */
		uint64_t dport:6;

		/* Opcode Specific parameters */
		uint64_t param:8;

		/* Opcode for the return packet  */
		uint64_t opcode:16;
	} s;
};

#define cnxk_ep_bb_write64(value, base_addr, reg_off) \
	{\
	typeof(value) val = (value); \
	typeof(reg_off) off = (reg_off); \
	cnxk_ep_bb_dbg("octeon_write_csr64: reg: 0x%08lx val: 0x%016llx\n", \
		   (unsigned long)off, (unsigned long long)val); \
	rte_write64(val, ((base_addr) + off)); \
	}

/* Instruction Header - for OCTEON-TX models */
typedef union cnxk_ep_bb_instr_ih {
	uint64_t u64;
	struct {
	  /** Data Len */
		uint64_t tlen:16;

	  /** Reserved */
		uint64_t rsvd:20;

	  /** PKIND for OTX_EP */
		uint64_t pkind:6;

	  /** Front Data size */
		uint64_t fsz:6;

	  /** No. of entries in gather list */
		uint64_t gsz:14;

	  /** Gather indicator 1=gather*/
		uint64_t gather:1;

	  /** Reserved3 */
		uint64_t reserved3:1;
	} s;
} cnxk_ep_bb_instr_ih_t;

/* OTX_EP IQ request list */
struct cnxk_ep_bb_instr_list {
	void *buf;
	uint32_t reqtype;
};
#define CNXK_EP_BB_IQREQ_LIST_SIZE	(sizeof(struct cnxk_ep_bb_instr_list))

/* Input Queue statistics. Each input queue has four stats fields. */
struct cnxk_ep_bb_iq_stats {
	uint64_t instr_posted; /* Instructions posted to this queue. */
	uint64_t instr_processed; /* Instructions processed in this queue. */
	uint64_t instr_dropped; /* Instructions that could not be processed */
	uint64_t tx_pkts;
	uint64_t tx_bytes;
};

/* Structure to define the configuration attributes for each Input queue. */
struct cnxk_ep_bb_iq_config {
	/* Max number of IQs available */
	uint16_t max_iqs;

	/* Command size - 32 or 64 bytes */
	uint16_t instr_type;

	/* Pending list size, usually set to the sum of the size of all IQs */
	uint32_t pending_list_size;
};

/** The instruction (input) queue.
 *  The input queue is used to post raw (instruction) mode data or packet data
 *  to OCTEON TX2 device from the host. Each IQ of a OTX_EP EP VF device has one
 *  such structure to represent it.
 */
struct cnxk_ep_bb_instr_queue {
	struct cnxk_ep_bb_device *cnxk_ep_bb_dev;

	uint32_t q_no;
	uint32_t pkt_in_done;

	/* Flag for 64 byte commands. */
	uint32_t iqcmd_64B:1;
	uint32_t rsvd:17;
	uint32_t status:8;

	/* Number of  descriptors in this ring. */
	uint32_t nb_desc;

	/* Input ring index, where the driver should write the next packet */
	uint32_t host_write_index;

	/* Input ring index, where the OCTEON TX2 should read the next packet */
	uint32_t otx_read_index;

	uint32_t reset_instr_cnt;

	/** This index aids in finding the window in the queue where OCTEON TX2
	 *  has read the commands.
	 */
	uint32_t flush_index;
	/* Free-running/wrapping instruction counter for IQ. */
	uint32_t inst_cnt;

	/* This keeps track of the instructions pending in this queue. */
	uint64_t instr_pending;

	/* Pointer to the Virtual Base addr of the input ring. */
	uint8_t *base_addr;

	/* This IQ request list */
	struct cnxk_ep_bb_instr_list *req_list;

	/* OTX_EP doorbell register for the ring. */
	void *doorbell_reg;

	/* OTX_EP instruction count register for this ring. */
	void *inst_cnt_reg;

	/* Number of instructions pending to be posted to OCTEON TX2. */
	uint32_t fill_cnt;

	/* Statistics for this input queue. */
	struct cnxk_ep_bb_iq_stats stats;

	/* DMA mapped base address of the input descriptor ring. */
	uint64_t base_addr_dma;

	/* Memory zone */
	const struct rte_memzone *iq_mz;

	/* Location in memory updated by SDP ISM */
	uint32_t *inst_cnt_ism;
	/* track inst count locally to consolidate HW counter updates */
	uint32_t inst_cnt_ism_prev;
};

/** Descriptor format.
 *  The descriptor ring is made of descriptors which have 2 64-bit values:
 *  -# Physical (bus) address of the data buffer.
 *  -# Physical (bus) address of a cnxk_ep_bb_droq_info structure.
 *  The device DMA's incoming packets and its information at the address
 *  given by these descriptor fields.
 */
struct cnxk_ep_bb_droq_desc {
	/* The buffer pointer */
	uint64_t buffer_ptr;

	/* The Info pointer */
	uint64_t info_ptr;
};
#define CNXK_EP_BB_DROQ_DESC_SIZE	(sizeof(struct cnxk_ep_bb_droq_desc))

/* Receive Header, only present in NIC mode. */
union cnxk_ep_bb_rh {
	uint64_t rh64;
};

#define CNXK_EP_BB_RH_SIZE (sizeof(union cnxk_ep_bb_rh))
#define CNXK_EP_BB_RH_SIZE_NIC (sizeof(union cnxk_ep_bb_rh))
#define CNXK_EP_BB_RH_SIZE_LOOP 0  /* Nothing in LOOP mode */

/** Information about packet DMA'ed by OCTEON TX2.
 *  The format of the information available at Info Pointer after OCTEON TX2
 *  has posted a packet. Not all descriptors have valid information. Only
 *  the Info field of the first descriptor for a packet has information
 *  about the packet.
 */
struct cnxk_ep_bb_droq_info {
	/* The Length of the packet. */
	uint64_t length;

	/* The Output Receive Header, only present in NIC mode */
	union cnxk_ep_bb_rh rh;
};
#define CNXK_EP_BB_DROQ_INFO_SIZE_NIC	(sizeof(struct cnxk_ep_bb_droq_info))
#define CNXK_EP_BB_DROQ_INFO_SIZE_LOOP	(sizeof(struct cnxk_ep_bb_droq_info) + \
						CNXK_EP_BB_RH_SIZE_LOOP - \
						CNXK_EP_BB_RH_SIZE_NIC)

/* DROQ statistics. Each output queue has four stats fields. */
struct cnxk_ep_bb_droq_stats {
	/* Number of packets received in this queue. */
	uint64_t pkts_received;

	/* Bytes received by this queue. */
	uint64_t bytes_received;

	/* Num of failures of rte_pktmbuf_alloc() */
	uint64_t rx_alloc_failure;

	/* Rx error */
	uint64_t rx_err;

	/* packets with data got ready after interrupt arrived */
	uint64_t pkts_delayed_data;

	/* packets dropped due to zero length */
	uint64_t dropped_zlp;
};

/* Structure to define the configuration attributes for each Output queue. */
struct cnxk_ep_bb_oq_config {
	/* Max number of OQs available */
	uint16_t max_oqs;

	/* If set, the Output queue uses info-pointer mode. (Default: 1 ) */
	uint16_t info_ptr;

	/** The number of buffers that were consumed during packet processing by
	 *  the driver on this Output queue before the driver attempts to
	 *  replenish the descriptor ring with new buffers.
	 */
	uint32_t refill_threshold;
};

/* The Descriptor Ring Output Queue(DROQ) structure. */
struct cnxk_ep_bb_droq {
	struct cnxk_ep_bb_device *cnxk_ep_bb_dev;
	/* The 8B aligned descriptor ring starts at this address. */
	struct cnxk_ep_bb_droq_desc *desc_ring;

	uint32_t q_no;
	uint64_t last_pkt_count;

	struct rte_mempool *mpool;

	/* Driver should read the next packet at this index */
	uint32_t read_idx;

	/* OCTEON TX2 will write the next packet at this index */
	uint32_t write_idx;

	/* At this index, the driver will refill the descriptor's buffer */
	uint32_t refill_idx;

	/* Packets pending to be processed */
	uint64_t pkts_pending;

	/* Number of descriptors in this ring. */
	uint32_t nb_desc;

	/* The number of descriptors pending to refill. */
	uint32_t refill_count;

	uint32_t refill_threshold;

	/* The 8B aligned info ptrs begin from this address. */
	struct cnxk_ep_bb_droq_info *info_list;

	/* receive buffer list contains mbuf ptr list */
	struct rte_mbuf **recv_buf_list;

	/* The size of each buffer pointed by the buffer pointer. */
	uint32_t buffer_size;

	/** Pointer to the mapped packet credit register.
	 *  Host writes number of info/buffer ptrs available to this register
	 */
	void *pkts_credit_reg;

	/** Pointer to the mapped packet sent register. OCTEON TX2 writes the
	 *  number of packets DMA'ed to host memory in this register.
	 */
	void *pkts_sent_reg;

	/** Fix for DMA incompletion during pkt reads.
	 *  This variable is used to initiate a sent_reg_read
	 *  that completes pending dma
	 *  this variable is used as lvalue so compiler cannot optimize
	 *  the reads
	 */
	uint32_t sent_reg_val;

	/* Statistics for this DROQ. */
	struct cnxk_ep_bb_droq_stats stats;

	/* DMA mapped address of the DROQ descriptor ring. */
	size_t desc_ring_dma;

	/* Info_ptr list is allocated at this virtual address. */
	size_t info_base_addr;

	/* DMA mapped address of the info list */
	size_t info_list_dma;

	/* Allocated size of info list. */
	uint32_t info_alloc_size;

	/* Memory zone **/
	const struct rte_memzone *desc_ring_mz;

	const struct rte_memzone *info_mz;

	/* Pointer to host memory copy of output packet count, set by ISM */
	uint32_t *pkts_sent_ism;
	uint32_t pkts_sent_ism_prev;
};
#define CNXK_EP_BB_DROQ_SIZE		(sizeof(struct cnxk_ep_bb_droq))

/* IQ/OQ mask */
struct cnxk_ep_bb_io_enable {
	uint64_t iq;
	uint64_t oq;
	uint64_t iq64B;
};

/* Structure to define the configuration. */
struct cnxk_ep_bb_config {
	/* Input Queue attributes. */
	struct cnxk_ep_bb_iq_config iq;

	/* Output Queue attributes. */
	struct cnxk_ep_bb_oq_config oq;

	/* Num of desc for IQ rings */
	uint32_t num_iqdef_descs;

	/* Num of desc for OQ rings */
	uint32_t num_oqdef_descs;

	/* OQ buffer size */
	uint32_t oqdef_buf_size;
};

/* SRIOV information */
struct cnxk_ep_bb_sriov_info {
	/* Number of rings assigned to VF */
	uint32_t rings_per_vf;

	/* Number of VF devices enabled */
	uint32_t num_vfs;
};

/* Required functions for each VF device */
struct cnxk_ep_bb_fn_list {
	int (*setup_iq_regs)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no);

	int (*setup_oq_regs)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no);

	int (*setup_device_regs)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);

	int (*enable_io_queues)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);
	void (*disable_io_queues)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);

	int (*enable_iq)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no);
	void (*disable_iq)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no);

	int (*enable_oq)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no);
	void (*disable_oq)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t q_no);
	int (*enable_rxq_intr)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t q_no);
	int (*disable_rxq_intr)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t q_no);
	int (*register_interrupt)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
		rte_intr_callback_fn cb, void *data, unsigned int vec);
	int (*unregister_interrupt)(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
		rte_intr_callback_fn cb, void *data);
};

#define CNXK_BB_DEV_NAME(p)	((p)->device.name)
#define CNXK_BB_DEV(bbdev)	((struct cnxk_ep_bb_device *)(bbdev->data->dev_private))
#define Q_TO_BB_DEV(q)		(((struct cnxk_ep_bb_droq *)(q)->queue_private)->cnxk_ep_bb_dev)
#define Q_TO_Q_NUM(q)		(((struct cnxk_ep_bb_droq *)(q)->queue_private)->q_no)

typedef uint16_t (*cnxk_ep_bb_rx_burst_t)(void *rxq, struct rte_mbuf **rx_pkts,
				uint16_t budget);
typedef uint16_t (*cnxk_ep_bb_tx_burst_t)(void *txq, struct rte_mbuf **tx_pkts,
				uint16_t nb_pkts);

struct mbufq_s {
	struct rte_mbuf *head, *tail;
};

struct mbuf_queues_s {
	struct mbufq_s wait_ops, sv_mbufs;
};

#define	CNXK_EP_BB_Q0_IDLE		0
#define	CNXK_EP_BB_Q0_CONFIGURED	1
#define	CNXK_EP_BB_Q0_ACTIVE_DEFAULT	2
#define	CNXK_EP_BB_Q0_ACTIVE		3

/* CNXK EP BBDev VF device data structure */
struct cnxk_ep_bb_device {
	/* PCI device pointer */
	struct rte_pci_device *pdev;

	uint16_t chip_id;
	uint16_t pf_num;
	uint16_t vf_num;

	uint32_t pkind;

	struct rte_bbdev	*bbdev;
	struct rte_mempool	*msg_pool;
	cnxk_ep_bb_rx_burst_t	rx_pkt_burst;
	cnxk_ep_bb_tx_burst_t	tx_pkt_burst;
	struct mbuf_queues_s	mbuf_queues[CNXK_EP_BB_MAX_IOQS_PER_VF];
	uint32_t		max_rx_pktlen;
	struct oct_bbdev_info	bbdev_info;
	uint32_t		status;

	int port_id;

	/* Memory mapped h/w address */
	uint8_t *hw_addr;

	struct cnxk_ep_bb_fn_list fn_list;

	uint32_t max_tx_queues;

	uint32_t max_rx_queues;

	/* Num IQs */
	uint32_t nb_tx_queues;

	/* The input instruction queues */
	struct cnxk_ep_bb_instr_queue *instr_queue[CNXK_EP_BB_MAX_IOQS_PER_VF];

	/* Num OQs */
	uint32_t nb_rx_queues;

	/* The DROQ output queues  */
	struct cnxk_ep_bb_droq *droq[CNXK_EP_BB_MAX_IOQS_PER_VF];

	/* IOQ mask */
	struct cnxk_ep_bb_io_enable io_qmask;

	/* SR-IOV info */
	struct cnxk_ep_bb_sriov_info sriov_info;

	/* Device configuration */
	const struct cnxk_ep_bb_config *conf;

	uint64_t rx_offloads;

	uint64_t tx_offloads;

	/* Packet mode (LOOP vs NIC), set by parameter */
	uint8_t sdp_packet_mode;

	/* DMA buffer for SDP ISM messages */
	const struct rte_memzone *ism_buffer_mz;
};

void cnxk_ep_bb_dmazone_free(const struct rte_memzone *mz);
const struct rte_memzone *cnxk_ep_bb_dmazone_reserve(uint16_t dev_id, const char *ring_name,
				uint16_t queue_id, size_t size, unsigned int align, int socket_id);
int cnxk_ep_bb_setup_iqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t iq_no,
		     int num_descs, unsigned int socket_id);
int cnxk_ep_bb_delete_iqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t iq_no);

int cnxk_ep_bb_setup_oqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, int oq_no, int num_descs,
		     int desc_size, struct rte_mempool *mpool,
		     unsigned int socket_id);
int cnxk_ep_bb_delete_oqs(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint32_t oq_no);
int cnxk_ep_bb_register_irq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
			rte_intr_callback_fn cb, void *data, unsigned int vec);
int cnxk_ep_bb_unregister_irq(struct cnxk_ep_bb_device *cnxk_ep_bb_vf,
			rte_intr_callback_fn cb, void *data);
int cnxk_ep_bb_dev_info_get(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);
int cnxk_ep_bb_dev_configure(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t nb_queues);
int cnxk_ep_bb_queue_setup(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t q_no,
		       const struct rte_bbdev_queue_conf *queue_conf);
int cnxk_ep_bb_queue_release(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t q_no);
int cnxk_ep_bb_dev_start(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);
void cnxk_ep_bb_dev_stop_q0_skip(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);
int cnxk_ep_bb_dev_start_q0_chk(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);
int cnxk_ep_bb_dev_stop(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);
void restore_q0_config_start(struct rte_bbdev *bbdev);
void *chk_q0_config_start(struct rte_bbdev *bbdev);
int cnxk_ep_bb_sdp_init(struct rte_bbdev *bbdev);
int cnxk_ep_bb_dev_exit(struct cnxk_ep_bb_device *cnxk_ep_bb_vf);
int cnxk_ep_bb_dequeue_ops(void *rx_queue, struct rte_mbuf **ops, uint16_t budget);
int cnxk_ep_bb_enqueue_ops(void *rx_queue, struct rte_mbuf **ops, uint16_t nb_ops);

struct cnxk_ep_bb_sg_entry {
	/** The first 64 bit gives the size of data in each dptr. */
	union {
		uint16_t size[4];
		uint64_t size64;
	} u;

	/** The 4 dptr pointers for this entry. */
	uint64_t ptr[4];
};

#define CNXK_EP_BB_SG_ENTRY_SIZE	(sizeof(struct cnxk_ep_bb_sg_entry))

/** Structure of a node in list of gather components maintained by
 *  driver for each network device.
 */
struct cnxk_ep_bb_gather {
	/** number of gather entries. */
	int num_sg;

	/** Gather component that can accommodate max sized fragment list
	 *  received from the IP layer.
	 */
	struct cnxk_ep_bb_sg_entry *sg;
};

struct cnxk_ep_bb_buf_free_info {
	struct rte_mbuf *mbuf;
	struct cnxk_ep_bb_gather g;
};

#define CNXK_EP_BB_MAX_PKT_SZ 65498U
#define CNXK_EP_BB_MAX_MAC_ADDRS 1
#define CNXK_EP_BB_SG_ALIGN 8
#define CNXK_EP_BB_CLEAR_ISIZE_BSIZE 0x7FFFFFULL
#define CNXK_EP_BB_CLEAR_OUT_INT_LVLS 0x3FFFFFFFFFFFFFULL
#define CNXK_EP_BB_CLEAR_IN_INT_LVLS 0xFFFFFFFF
#define CNXK_EP_BB_CLEAR_SDP_IN_INT_LVLS 0x3FFFFFFFFFFFFFUL
#define CNXK_EP_BB_DROQ_BUFSZ_MASK 0xFFFF
#define CNXK_EP_BB_CLEAR_SLIST_DBELL 0xFFFFFFFF
#define CNXK_EP_BB_CLEAR_SDP_OUT_PKT_CNT 0xFFFFFFFFF

#define CNXK_EP_BB_ETH_OVERHEAD \
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + 8)
#define CNXK_EP_BB_FRAME_SIZE_MAX       9000

/* PCI IDs */
#define PCI_VENDOR_ID_CAVIUM			0x177D

extern int octeon_ep_bbdev_logtype;
#endif  /* _CNXK_EP_BB_COMMON_H_ */
