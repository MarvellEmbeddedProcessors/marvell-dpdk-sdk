/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#ifndef _OTX_EP_COMMON_H_
#define _OTX_EP_COMMON_H_


#define OTX_EP_NW_PKT_OP               0x1220
#define OTX_EP_NW_CMD_OP               0x1221

#define OTX_EP_MAX_RINGS_PER_VF        (8)
#define OTX_EP_CFG_IO_QUEUES        OTX_EP_MAX_RINGS_PER_VF
#define OTX_EP_64BYTE_INSTR         (64)
/*
 * Backpressure for SDP is configured on Octeon, and the minimum queue sizes
 * must be much larger than the backpressure watermark configured in the Octeon
 * SDP driver.  IQ and OQ backpressure configurations are separate.
 */
#define OTX_EP_MIN_IQ_DESCRIPTORS   (2048)
#define OTX_EP_MIN_OQ_DESCRIPTORS   (2048)
#define OTX_EP_MAX_IQ_DESCRIPTORS   (8192)
#define OTX_EP_MAX_OQ_DESCRIPTORS   (8192)
#define OTX_EP_OQ_BUF_SIZE          (2048)
#define OTX_EP_MIN_RX_BUF_SIZE      (64)

#define OTX_EP_OQ_INFOPTR_MODE      (0)
#define OTX_EP_OQ_REFIL_THRESHOLD   (16)

/* IQ instruction req types */
#define OTX_EP_REQTYPE_NONE             (0)
#define OTX_EP_REQTYPE_NORESP_INSTR     (1)
#define OTX_EP_REQTYPE_NORESP_NET_DIRECT       (2)
#define OTX_EP_REQTYPE_NORESP_NET       OTX_EP_REQTYPE_NORESP_NET_DIRECT
#define OTX_EP_REQTYPE_NORESP_GATHER    (3)
#define OTX_EP_NORESP_OHSM_SEND     (4)
#define OTX_EP_NORESP_LAST          (4)
#define OTX_EP_PCI_RING_ALIGN   65536
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
#define SDP_PACKET_MODE_PARAM	"sdp_packet_mode"
#define SDP_PACKET_MODE_NIC	0x0
#define SDP_PACKET_MODE_LOOP	0x1

#define      ORDERED_TAG 0
#define      ATOMIC_TAG  1
#define      NULL_TAG  2
#define      NULL_NULL_TAG  3

#define OTX_EP_BUSY_LOOP_COUNT      (10000)
#define OTX_EP_MAX_IOQS_PER_VF 8
#define OTX_CUST_DATA_LEN 0

#define otx_ep_info(fmt, args...)				\
	rte_log(RTE_LOG_INFO, otx_net_ep_logtype,		\
		"%s():%u " fmt "\n",				\
		__func__, __LINE__, ##args)

#define otx_ep_err(fmt, args...)				\
	rte_log(RTE_LOG_ERR, otx_net_ep_logtype,		\
		"%s():%u " fmt "\n",				\
		__func__, __LINE__, ##args)

#define otx_ep_dbg(fmt, args...)				\
	rte_log(RTE_LOG_DEBUG, otx_net_ep_logtype,		\
		"%s():%u " fmt "\n",				\
		__func__, __LINE__, ##args)

/* IO Access */
#define oct_ep_read64(addr) rte_read64_relaxed((void *)(addr))
#define oct_ep_write64(val, addr) rte_write64_relaxed((val), (void *)(addr))

/* Input Request Header format */
union otx_ep_instr_irh {
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

#define otx_ep_write64(value, base_addr, reg_off) \
	{\
	typeof(value) val = (value); \
	typeof(reg_off) off = (reg_off); \
	otx_ep_dbg("octeon_write_csr64: reg: 0x%08lx val: 0x%016llx\n", \
		   (unsigned long)off, (unsigned long long)val); \
	rte_write64(val, ((base_addr) + off)); \
	}

/* Instruction Header - for OCTEON-TX models */
typedef union otx_ep_instr_ih {
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
} otx_ep_instr_ih_t;

/* OTX_EP IQ request list */
struct otx_ep_instr_list {
	void *buf;
	uint32_t reqtype;
};
#define OTX_EP_IQREQ_LIST_SIZE	(sizeof(struct otx_ep_instr_list))

/* Input Queue statistics. Each input queue has four stats fields. */
struct otx_ep_iq_stats {
	uint64_t instr_posted; /* Instructions posted to this queue. */
	uint64_t instr_processed; /* Instructions processed in this queue. */
	uint64_t instr_dropped; /* Instructions that could not be processed */
	uint64_t tx_pkts;
	uint64_t tx_bytes;
};

/* Structure to define the configuration attributes for each Input queue. */
struct otx_ep_iq_config {
	/* Max number of IQs available */
	uint16_t max_iqs;

	/* Command size - 32 or 64 bytes */
	uint16_t instr_type;

	/* Pending list size, usually set to the sum of the size of all IQs */
	uint32_t pending_list_size;
};

/** The instruction (input) queue.
 *  The input queue is used to post raw (instruction) mode data or packet data
 *  to OCTEON 9 device from the host. Each IQ of a OTX_EP EP VF device has one
 *  such structure to represent it.
 */
struct otx_ep_instr_queue {
	struct otx_ep_device *otx_ep_dev;

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

	/* Input ring index, where the OCTEON 9 should read the next packet */
	uint32_t otx_read_index;

	uint32_t reset_instr_cnt;

	/** This index aids in finding the window in the queue where OCTEON 9
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
	struct otx_ep_instr_list *req_list;

	/* OTX_EP doorbell register for the ring. */
	void *doorbell_reg;

	/* OTX_EP instruction count register for this ring. */
	void *inst_cnt_reg;

	/* Number of instructions pending to be posted to OCTEON 9. */
	uint32_t fill_cnt;

	/* Statistics for this input queue. */
	struct otx_ep_iq_stats stats;

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
 *  -# Physical (bus) address of a otx_ep_droq_info structure.
 *  The device DMA's incoming packets and its information at the address
 *  given by these descriptor fields.
 */
struct otx_ep_droq_desc {
	/* The buffer pointer */
	uint64_t buffer_ptr;

	/* The Info pointer */
	uint64_t info_ptr;
};
#define OTX_EP_DROQ_DESC_SIZE	(sizeof(struct otx_ep_droq_desc))

/* Receive Header, only present in NIC mode. */
union otx_ep_rh {
	uint64_t rh64;
};

#define OTX_EP_RH_SIZE (sizeof(union otx_ep_rh))
#define OTX_EP_RH_SIZE_NIC (sizeof(union otx_ep_rh))
#define OTX_EP_RH_SIZE_LOOP 0  /* Nothing in LOOP mode */

/** Information about packet DMA'ed by OCTEON 9.
 *  The format of the information available at Info Pointer after OCTEON 9
 *  has posted a packet. Not all descriptors have valid information. Only
 *  the Info field of the first descriptor for a packet has information
 *  about the packet.
 */
struct otx_ep_droq_info {
	/* The Length of the packet. */
	uint64_t length;

	/* The Output Receive Header, only present in NIC mode */
	union otx_ep_rh rh;
};
#define OTX_EP_DROQ_INFO_SIZE_NIC	(sizeof(struct otx_ep_droq_info))
#define OTX_EP_DROQ_INFO_SIZE_LOOP	(sizeof(struct otx_ep_droq_info) + \
						OTX_EP_RH_SIZE_LOOP - \
						OTX_EP_RH_SIZE_NIC)

/* DROQ statistics. Each output queue has four stats fields. */
struct otx_ep_droq_stats {
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
struct otx_ep_oq_config {
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
struct otx_ep_droq {
	struct otx_ep_device *otx_ep_dev;
	/* The 8B aligned descriptor ring starts at this address. */
	struct otx_ep_droq_desc *desc_ring;

	uint32_t q_no;
	uint64_t last_pkt_count;

	struct rte_mempool *mpool;

	/* Driver should read the next packet at this index */
	uint32_t read_idx;

	/* OCTEON 9 will write the next packet at this index */
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
	struct otx_ep_droq_info *info_list;

	/* receive buffer list contains mbuf ptr list */
	struct rte_mbuf **recv_buf_list;

	/* The size of each buffer pointed by the buffer pointer. */
	uint32_t buffer_size;

	/** Pointer to the mapped packet credit register.
	 *  Host writes number of info/buffer ptrs available to this register
	 */
	void *pkts_credit_reg;

	/** Pointer to the mapped packet sent register. OCTEON 9 writes the
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
	struct otx_ep_droq_stats stats;

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
#define OTX_EP_DROQ_SIZE		(sizeof(struct otx_ep_droq))

/* IQ/OQ mask */
struct otx_ep_io_enable {
	uint64_t iq;
	uint64_t oq;
	uint64_t iq64B;
};

/* Structure to define the configuration. */
struct otx_ep_config {
	/* Input Queue attributes. */
	struct otx_ep_iq_config iq;

	/* Output Queue attributes. */
	struct otx_ep_oq_config oq;

	/* Num of desc for IQ rings */
	uint32_t num_iqdef_descs;

	/* Num of desc for OQ rings */
	uint32_t num_oqdef_descs;

	/* OQ buffer size */
	uint32_t oqdef_buf_size;
};

#define MBOX_MAX_DATA_SIZE  6
#define MBOX_MORE_FRAG_FLAG 1
#define MBOX_MAX_DATA_BUF_SIZE 256
typedef enum {
	OTX_VF_MBOX_CMD_SET_MTU,
	OTX_VF_MBOX_CMD_SET_MAC_ADDR,
	OTX_VF_MBOX_CMD_GET_MAC_ADDR,
	OTX_VF_MBOX_CMD_START_QUEUE,
	OTX_VF_MBOX_CMD_STOP_QUEUE,
	OTX_VF_MBOX_CMD_GET_LINK,
	OTX_VF_MBOX_CMD_BULK_SEND,
	OTX_VF_MBOX_CMD_BULK_GET,
	OTX_VF_MBOX_CMD_LAST,
} otx_vf_mbox_opcode_t;

typedef enum {
	OTX_VF_MBOX_TYPE_CMD,
	OTX_VF_MBOX_TYPE_RSP_ACK,
	OTX_VF_MBOX_TYPE_RSP_NACK,
} otx_vf_mbox_word_type_t;

union otx_vf_mbox_word {
	uint64_t u64;
	struct {
		uint64_t version:3;
		uint64_t rsvd1:2;
		uint64_t opcode:5;
		uint64_t rsvd2:3;
		uint64_t id:1;
		uint64_t type:2;
		uint64_t data:48;
	} s;
	struct {
		uint64_t version:3;
		uint64_t rsvd1:2;
		uint64_t opcode:5;
		uint64_t rsvd2:2;
		uint64_t frag:1;
		uint64_t id:1;
		uint64_t type:2;
		uint8_t data[6];
	} s_data;
	struct {
		uint64_t version:3;
		uint64_t rsvd1:2;
		uint64_t opcode:5;
		uint64_t rsvd2:3;
		uint64_t id:1;
		uint64_t type:2;
		uint8_t mac_addr[6];
	} s_set_mac;
	struct {
		uint64_t version:3;
		uint64_t rsvd1:2;
		uint64_t opcode:5;
		uint64_t rsvd2:3;
		uint64_t id:1;
		uint64_t type:2;
		uint64_t mtu:48;
	} s_set_mtu;
	struct {
		uint64_t version:3;
		uint64_t rsvd1:2;
		uint64_t opcode:5;
		uint64_t rsvd2:3;
		uint64_t id:1;
		uint64_t type:2;
		uint64_t link_status:1;
		uint64_t link_speed:8;
		uint64_t duplex:1;
		uint64_t autoneg:1;
		uint64_t rsvd:37;
	} s_get_link;
} __rte_packed;

typedef enum {
	OTX_VF_LINK_STATUS_DOWN,
	OTX_VF_LINK_STATUS_UP,
} otx_vf_link_status_t;

typedef enum {
	OTX_VF_LINK_SPEED_NONE,
	OTX_VF_LINK_SPEED_100,
	OTX_VF_LINK_SPEED_1000,
	OTX_VF_LINK_SPEED_2500,
	OTX_VF_LINK_SPEED_5000,
	OTX_VF_LINK_SPEED_10000,
	OTX_VF_LINK_SPEED_20000,
	OTX_VF_LINK_SPEED_25000,
	OTX_VF_LINK_SPEED_40000,
	OTX_VF_LINK_SPEED_50000,
	OTX_VF_LINK_SPEED_100000,
	OTX_VF_LINK_SPEED_LAST,
} otx_vf_link_speed_t;

typedef enum {
	OTX_VF_LINK_HALF_DUPLEX,
	OTX_VF_LINK_FULL_DUPLEX,
} otx_vf_link_duplex_t;

typedef enum {
	OTX_VF_LINK_AUTONEG,
	OTX_VF_LINK_FIXED,
} otx_vf_link_autoneg_t;

struct otx_vf_mbox_link {
	uint64_t link_status:1;
	uint64_t link_speed:8;
	uint64_t duplex:1;
	uint64_t autoneg:1;
	uint64_t rsvd:37;
} __rte_packed;

#define OTX_VF_MBOX_TIMEOUT_MS 10
#define OTX_VF_MBOX_MAX_RETRIES 2
#define OTX_VF_MBOX_VERSION 0

/* SRIOV information */
struct otx_ep_sriov_info {
	/* Number of rings assigned to VF */
	uint32_t rings_per_vf;

	/* Number of VF devices enabled */
	uint32_t num_vfs;
};

/* Required functions for each VF device */
struct otx_ep_fn_list {
	int (*setup_iq_regs)(struct otx_ep_device *otx_ep, uint32_t q_no);

	int (*setup_oq_regs)(struct otx_ep_device *otx_ep, uint32_t q_no);

	int (*setup_device_regs)(struct otx_ep_device *otx_ep);

	int (*enable_io_queues)(struct otx_ep_device *otx_ep);
	void (*disable_io_queues)(struct otx_ep_device *otx_ep);

	int (*enable_iq)(struct otx_ep_device *otx_ep, uint32_t q_no);
	void (*disable_iq)(struct otx_ep_device *otx_ep, uint32_t q_no);

	int (*enable_oq)(struct otx_ep_device *otx_ep, uint32_t q_no);
	void (*disable_oq)(struct otx_ep_device *otx_ep, uint32_t q_no);
	int (*enable_rxq_intr)(struct otx_ep_device *otx_epvf, uint16_t q_no);
	int (*disable_rxq_intr)(struct otx_ep_device *otx_epvf, uint16_t q_no);
	int (*send_mbox_cmd)(struct otx_ep_device *otx_epvf, union
		otx_vf_mbox_word cmd, union otx_vf_mbox_word *rsp);
	int (*send_mbox_cmd_nolock)(struct otx_ep_device *otx_epvf, union
		otx_vf_mbox_word cmd, union otx_vf_mbox_word *rsp);
	void (*enable_mbox_interrupt)(struct otx_ep_device *otx_epvf);
	void (*disable_mbox_interrupt)(struct otx_ep_device *otx_epvf);
	int (*register_pf_vf_mbox_interrupt)(struct otx_ep_device *otx_epvf);
	int (*unregister_pf_vf_mbox_interrupt)(struct otx_ep_device *otx_epvf);
	int (*register_interrupt)(struct otx_ep_device *otx_ep,
		rte_intr_callback_fn cb, void *data, unsigned int vec);
	int (*unregister_interrupt)(struct otx_ep_device *otx_ep,
		rte_intr_callback_fn cb, void *data);

};

/* OTX_EP EP VF device data structure */
struct otx_ep_device {
	/* PCI device pointer */
	struct rte_pci_device *pdev;

	uint16_t chip_id;
	uint16_t pf_num;
	uint16_t vf_num;

	uint32_t pkind;

	struct rte_eth_dev *eth_dev;

	int port_id;

	/* Memory mapped h/w address */
	uint8_t *hw_addr;

	struct otx_ep_fn_list fn_list;

	uint32_t max_tx_queues;

	uint32_t max_rx_queues;

	/* Num IQs */
	uint32_t nb_tx_queues;

	/* The input instruction queues */
	struct otx_ep_instr_queue *instr_queue[OTX_EP_MAX_IOQS_PER_VF];

	/* Num OQs */
	uint32_t nb_rx_queues;

	/* The DROQ output queues  */
	struct otx_ep_droq *droq[OTX_EP_MAX_IOQS_PER_VF];

	/* IOQ mask */
	struct otx_ep_io_enable io_qmask;

	/* SR-IOV info */
	struct otx_ep_sriov_info sriov_info;

	/* Device configuration */
	const struct otx_ep_config *conf;

	rte_spinlock_t mbox_lock;

	int mbox_cmd_id;

	uint8_t mbox_data_buf[MBOX_MAX_DATA_BUF_SIZE];

	int32_t mbox_data_index;

	int32_t mbox_rcv_message_len;

	uint64_t rx_offloads;

	uint64_t tx_offloads;

	/* Packet mode (LOOP vs NIC), set by parameter */
	uint8_t sdp_packet_mode;

	/* DMA buffer for SDP ISM messages */
	const struct rte_memzone *ism_buffer_mz;
};

int otx_ep_setup_iqs(struct otx_ep_device *otx_ep, uint32_t iq_no,
		     int num_descs, unsigned int socket_id);
int otx_ep_delete_iqs(struct otx_ep_device *otx_ep, uint32_t iq_no);

int otx_ep_setup_oqs(struct otx_ep_device *otx_ep, int oq_no, int num_descs,
		     int desc_size, struct rte_mempool *mpool,
		     unsigned int socket_id);
int otx_ep_delete_oqs(struct otx_ep_device *otx_ep, uint32_t oq_no);
int otx_ep_register_irq(struct otx_ep_device *otx_ep,
			rte_intr_callback_fn cb, void *data, unsigned int vec);
int otx_ep_unregister_irq(struct otx_ep_device *otx_ep,
			rte_intr_callback_fn cb, void *data);
int otx_ep_send_vf_pf_config_data(struct rte_eth_dev *eth_dev,
					otx_vf_mbox_opcode_t opcode,
					uint8_t *data, int32_t size);
int otx_ep_get_pf_vf_data(struct rte_eth_dev *eth_dev,
					otx_vf_mbox_opcode_t opcode,
					uint8_t *data, int32_t *size);


struct otx_ep_sg_entry {
	/** The first 64 bit gives the size of data in each dptr. */
	union {
		uint16_t size[4];
		uint64_t size64;
	} u;

	/** The 4 dptr pointers for this entry. */
	uint64_t ptr[4];
};

#define OTX_EP_SG_ENTRY_SIZE	(sizeof(struct otx_ep_sg_entry))

/** Structure of a node in list of gather components maintained by
 *  driver for each network device.
 */
struct otx_ep_gather {
	/** number of gather entries. */
	int num_sg;

	/** Gather component that can accommodate max sized fragment list
	 *  received from the IP layer.
	 */
	struct otx_ep_sg_entry *sg;
};

struct otx_ep_buf_free_info {
	struct rte_mbuf *mbuf;
	struct otx_ep_gather g;
};

#define OTX_EP_MAX_PKT_SZ 65498U
#define OTX_EP_MAX_MAC_ADDRS 1
#define OTX_EP_SG_ALIGN 8
#define OTX_EP_CLEAR_ISIZE_BSIZE 0x7FFFFFULL
#define OTX_EP_CLEAR_OUT_INT_LVLS 0x3FFFFFFFFFFFFFULL
#define OTX_EP_CLEAR_IN_INT_LVLS 0xFFFFFFFF
#define OTX_EP_CLEAR_SDP_IN_INT_LVLS 0x3FFFFFFFFFFFFFUL
#define OTX_EP_DROQ_BUFSZ_MASK 0xFFFF
#define OTX_EP_CLEAR_SLIST_DBELL 0xFFFFFFFF
#define OTX_EP_CLEAR_SDP_OUT_PKT_CNT 0xFFFFFFFFF

#define OTX_EP_ETH_OVERHEAD \
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + 8)
#define OTX_EP_FRAME_SIZE_MAX       9000

/* PCI IDs */
#define PCI_VENDOR_ID_CAVIUM			0x177D

extern int otx_net_ep_logtype;
#endif  /* _OTX_EP_COMMON_H_ */
