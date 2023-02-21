/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "cnxk_ep_bb_common.h"
#include "cnxk_ep_bb_vf.h"
#include "cnxk_ep_bb_rxtx.h"

#ifdef TODO_STATS
static int cnxk_ep_bb_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = CNXK_BB_DEV(dev);
	uint32_t i;

	for (i = 0; i < cnxk_ep_bb_vf->nb_tx_queues; i++)
		memset(&cnxk_ep_bb_vf->instr_queue[i]->stats, 0,
		       sizeof(struct cnxk_ep_bb_iq_stats));

	for (i = 0; i < cnxk_ep_bb_vf->nb_rx_queues; i++)
		memset(&cnxk_ep_bb_vf->droq[i]->stats, 0,
		       sizeof(struct cnxk_ep_bb_droq_stats));

	return 0;
}

static int cnxk_ep_bb_dev_stats_get(struct rte_eth_dev *eth_dev,
				struct rte_eth_stats *stats)
{
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = CNXK_BB_DEV(eth_dev);
	struct cnxk_ep_bb_iq_stats *ostats;
	struct cnxk_ep_bb_droq_stats *istats;
	uint32_t i;

	memset(stats, 0, sizeof(struct rte_eth_stats));

	for (i = 0; i < cnxk_ep_bb_vf->nb_tx_queues; i++) {
		ostats = &cnxk_ep_bb_vf->instr_queue[i]->stats;
		stats->q_opackets[i] = ostats->tx_pkts;
		stats->q_obytes[i] = ostats->tx_bytes;
		stats->opackets += ostats->tx_pkts;
		stats->obytes += ostats->tx_bytes;
		stats->oerrors += ostats->instr_dropped;
	}
	for (i = 0; i < cnxk_ep_bb_vf->nb_rx_queues; i++) {
		istats = &cnxk_ep_bb_vf->droq[i]->stats;
		stats->q_ipackets[i] = istats->pkts_received;
		stats->q_ibytes[i] = istats->bytes_received;
		stats->q_errors[i] = istats->rx_err;
		stats->ipackets += istats->pkts_received;
		stats->ibytes += istats->bytes_received;
		stats->imissed += istats->rx_alloc_failure;
		stats->ierrors += istats->rx_err;
		stats->rx_nombuf += istats->rx_alloc_failure;
	}
	return 0;
}
#endif

int
cnxk_ep_bb_dev_info_get(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	cnxk_ep_bb_vf->max_rx_pktlen = CNXK_EP_BB_MAX_PKT_SZ;
	cnxk_ep_bb_vf->rx_offloads |= EPDEV_RX_OFFLOAD_SCATTER;
	cnxk_ep_bb_vf->tx_offloads |= EPDEV_TX_OFFLOAD_MULTI_SEGS;
	return 0;
}

int
cnxk_ep_bb_dev_start(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	unsigned int q;
	int ret;

	/* Enable IQ/OQ for this device */
	ret = cnxk_ep_bb_vf->fn_list.enable_io_queues(cnxk_ep_bb_vf);
	if (ret) {
		cnxk_ep_bb_err("IOQ enable failed\n");
		return ret;
	}

	for (q = 0; q < cnxk_ep_bb_vf->nb_rx_queues; q++) {
		rte_write32(cnxk_ep_bb_vf->droq[q]->nb_desc,
			    cnxk_ep_bb_vf->droq[q]->pkts_credit_reg);
		rte_wmb();
		cnxk_ep_bb_info("OQ[%d] dbells [%d]", q,
		rte_read32(cnxk_ep_bb_vf->droq[q]->pkts_credit_reg));
	}
	cnxk_ep_bb_info("dev started");
	return 0;
}

/* Stop device and disable input/output functions */
int
cnxk_ep_bb_dev_stop(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	cnxk_ep_bb_vf->fn_list.disable_io_queues(cnxk_ep_bb_vf);
	return 0;
}

/*
 * We only need 2 uint32_t locations per IOQ, but separate these so
 * each IOQ has the variables on its own cache line.
 */
#define CNXK_EP_BB_ISM_BUFFER_SIZE	(CNXK_EP_BB_MAX_IOQS_PER_VF * RTE_CACHE_LINE_SIZE)
static int
cnxk_ep_bb_ism_setup(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	cnxk_ep_bb_vf->ism_buffer_mz = cnxk_ep_bb_dmazone_reserve(
							cnxk_ep_bb_vf->bbdev->data->dev_id,
							"ism", 0, CNXK_EP_BB_ISM_BUFFER_SIZE,
							CNXK_EP_BB_PCI_RING_ALIGN, 0);
	if (cnxk_ep_bb_vf->ism_buffer_mz == NULL) {
		cnxk_ep_bb_err("Failed to allocate ISM buffer\n");
		return(-1);
	}
	/* Same DMA buffer is shared by OQ and IQ, clear it at start */
	memset(cnxk_ep_bb_vf->ism_buffer_mz->addr, 0, CNXK_EP_BB_ISM_BUFFER_SIZE);
	cnxk_ep_bb_dbg("ISM: virt: 0x%p, dma: %p",
		    (void *)cnxk_ep_bb_vf->ism_buffer_mz->addr,
		   (void *)cnxk_ep_bb_vf->ism_buffer_mz->iova);

	return 0;
}
static int
cnxk_ep_bb_chip_specific_setup(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	struct rte_pci_device *pdev = cnxk_ep_bb_vf->pdev;
	uint32_t dev_id = pdev->id.device_id;
	int ret = 0;

	switch (dev_id) {
	case PCI_DEVID_CNF10KA_EP_BBDEV_VF:
		cnxk_ep_bb_vf->chip_id = dev_id;
		ret = cnxk_ep_bb_vf_setup_device(cnxk_ep_bb_vf);
		cnxk_ep_bb_vf->fn_list.disable_io_queues(cnxk_ep_bb_vf);
		if (cnxk_ep_bb_ism_setup(cnxk_ep_bb_vf))
			ret = -EINVAL;
		break;
	default:
		cnxk_ep_bb_err("Unsupported device\n");
		ret = -EINVAL;
	}

	if (!ret)
		cnxk_ep_bb_info("OTX_EP dev_id[%X]", dev_id);

	return ret;
}

static void
cnxk_ep_bb_interrupt_handler(void *param)
{
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = (struct cnxk_ep_bb_device *)param;
	uint64_t reg_val;
	if (cnxk_ep_bb_vf) {
		/* Clear Mbox interrupts */
		reg_val = rte_read64((uint8_t *)cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_BB_R_MBOX_PF_VF_INT(0));
		rte_write64(reg_val, (uint8_t *)cnxk_ep_bb_vf->hw_addr +
				CNXK_EP_BB_R_MBOX_PF_VF_INT(0));
		cnxk_ep_bb_info("cnxk_ep_bb_dev_interrupt_handler: pf %d vf %d port %d\n",
			cnxk_ep_bb_vf->pf_num, cnxk_ep_bb_vf->vf_num, cnxk_ep_bb_vf->port_id);
	} else {
		cnxk_ep_bb_err("cnxk_ep_bb_dev_interrupt_handler is called with dev NULL\n");
	}
}

/* OTX_EP VF device initialization */
static int
cnxk_ep_bb_dev_init(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	uint32_t ethdev_queues;
	int ret = 0;
	uint32_t vec = 0;

	ret = cnxk_ep_bb_chip_specific_setup(cnxk_ep_bb_vf);
	if (ret) {
		cnxk_ep_bb_err("Chip specific setup failed\n");
		goto setup_fail;
	}

	cnxk_ep_bb_vf->fn_list.setup_device_regs(cnxk_ep_bb_vf);

	cnxk_ep_bb_vf->rx_pkt_burst = &cnxk_ep_bb_recv_pkts;
	if (cnxk_ep_bb_vf->chip_id == PCI_DEVID_CNF10KA_EP_BBDEV_VF)
		cnxk_ep_bb_vf->tx_pkt_burst = &cnxk_ep_bb_xmit_pkts;
	else {
		cnxk_ep_bb_err("Invalid chip_id\n");
		ret = -EINVAL;
		goto setup_fail;
	}
	ethdev_queues = (uint32_t)(cnxk_ep_bb_vf->sriov_info.rings_per_vf);
	cnxk_ep_bb_vf->max_rx_queues = ethdev_queues;
	cnxk_ep_bb_vf->max_tx_queues = ethdev_queues;
	cnxk_ep_bb_vf->fn_list.register_interrupt(cnxk_ep_bb_vf, cnxk_ep_bb_interrupt_handler,
						(void *)cnxk_ep_bb_vf, vec);
	cnxk_ep_bb_info("OTX_EP Device is Ready");
setup_fail:
	return ret;
}

int
cnxk_ep_bb_dev_configure(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t nb_queues)
{
	if (nb_queues > cnxk_ep_bb_vf->max_rx_queues) {
		cnxk_ep_bb_err("invalid num queues\n");
		return -EINVAL;
	}
	cnxk_ep_bb_info("CNX_BBDEV configured with %d of %d available queue pairs",
			nb_queues, cnxk_ep_bb_vf->max_rx_queues);
	return 0;
}

/**
 * Allocate and initialize given RX & TX queue.  Populate the receive
 * queue with buffers from bbdev message mempool.
 *
 * @param cnxk_ep_bb_vf
 *   Pointer to structure cnxk_ep_bb_device
 * @param q_no
 *   Queue number
 * @param queue_conf
 *   Pointer to the structure rte_bbdev_queue_conf
 *
 * @return
 *    - On success, return 0
 *    - On failure, return -1
 */
int
cnxk_ep_bb_queue_setup(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t q_no,
		       const struct rte_bbdev_queue_conf *queue_conf)
{
	struct rte_pktmbuf_pool_private *mbp_priv;
	uint16_t buf_size;
	int ret;

	/* TODO: assuming that max_rx_queues == max_tx_queues */
	if (q_no >= cnxk_ep_bb_vf->max_rx_queues) {
		cnxk_ep_bb_err("Invalid rx queue number %u\n", q_no);
		return -EINVAL;
	}

	if (queue_conf->queue_size & (queue_conf->queue_size - 1)) {
		cnxk_ep_bb_err("Invalid rx desc number(%u) This must be a power of 2\n",
			   queue_conf->queue_size);
		return -EINVAL;
	}
	if (queue_conf->queue_size < (SDP_GBL_WMARK * 8)) {
		cnxk_ep_bb_err("Invalid rx desc number(%u) should at least be 8*wmark(%u)\n",
			   queue_conf->queue_size, (SDP_GBL_WMARK * 8));
		return -EINVAL;
	}

	cnxk_ep_bb_dbg("setting up rx queue %u", q_no);
	mbp_priv = rte_mempool_get_priv(cnxk_ep_bb_vf->msg_pool);
	buf_size = mbp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM;
	ret = cnxk_ep_bb_setup_oqs(cnxk_ep_bb_vf, q_no, queue_conf->queue_size, buf_size,
				cnxk_ep_bb_vf->msg_pool, queue_conf->socket);
	if (ret) {
		cnxk_ep_bb_err("droq allocation failed\n");
		return ret;
	}

	cnxk_ep_bb_dbg("setting up tx queue %d", q_no);
	ret = cnxk_ep_bb_setup_iqs(cnxk_ep_bb_vf, q_no, queue_conf->queue_size,
				queue_conf->socket);
	if (ret) {
		cnxk_ep_bb_err("IQ(TxQ) creation failed.\n");
		cnxk_ep_bb_delete_oqs(cnxk_ep_bb_vf, q_no);
		return ret;
	}
	return 0;
}

/**
 * Release given RX & TX queue.
 *
 * @param cnxk_ep_bb_vf
 *   Pointer to cnxk_bb device structure.
 * @param q_no
 *   RX & TX queue index.
 *
 * @return
 *    - On success, return 0
 *    - On failure, return non-zero error code
 */
int
cnxk_ep_bb_queue_release(struct cnxk_ep_bb_device *cnxk_ep_bb_vf, uint16_t q_no)
{
	int ret = 0, ret1;

	ret1 = cnxk_ep_bb_delete_oqs(cnxk_ep_bb_vf, q_no);
	if (ret1) {
		cnxk_ep_bb_err("Failed to delete OQ:%d\n", q_no);
		ret = ret1;
	}
	ret1 = cnxk_ep_bb_delete_iqs(cnxk_ep_bb_vf, q_no);
	if (ret1) {
		cnxk_ep_bb_err("Failed to delete IQ:%d\n", q_no);
		ret = ret1;
	}
	return ret;
}

int
cnxk_ep_bb_dev_exit(struct cnxk_ep_bb_device *cnxk_ep_bb_vf)
{
	int ret = 0, ret1;
	uint32_t q;

	cnxk_ep_bb_vf->fn_list.unregister_interrupt(cnxk_ep_bb_vf, cnxk_ep_bb_interrupt_handler,
						(void *)cnxk_ep_bb_vf);
	cnxk_ep_bb_vf->fn_list.disable_io_queues(cnxk_ep_bb_vf);

	for (q = 0; q < cnxk_ep_bb_vf->nb_rx_queues; q++) {
		ret1 = cnxk_ep_bb_queue_release(cnxk_ep_bb_vf, q);
		if (unlikely(ret1))
			ret = ret1;
	}
	cnxk_ep_bb_info("Num OQs/IQs:%d freed\n", cnxk_ep_bb_vf->nb_rx_queues);

	cnxk_ep_bb_dmazone_free(cnxk_ep_bb_vf->ism_buffer_mz);
	return ret;
}

int
cnxk_ep_bb_sdp_init(struct rte_bbdev *bbdev)
{
	struct rte_pci_device *pdev = RTE_DEV_TO_PCI(bbdev->device);
	struct cnxk_ep_bb_device *cnxk_ep_bb_vf = CNXK_BB_DEV(bbdev);
	int ret;

	/* Single process support */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	cnxk_ep_bb_vf->bbdev = bbdev;
	cnxk_ep_bb_vf->sdp_packet_mode = SDP_PACKET_MODE_LOOP;
	cnxk_ep_bb_vf->port_id = bbdev->data->dev_id;
	cnxk_ep_bb_vf->hw_addr = pdev->mem_resource[0].addr;
	cnxk_ep_bb_vf->pdev = pdev;

	if (cnxk_ep_bb_dev_init(cnxk_ep_bb_vf))
		return -ENOMEM;
	if (cnxk_ep_bb_vf->chip_id == PCI_DEVID_CNF10KA_EP_BBDEV_VF) {
		if (cnxk_ep_bb_vf->sdp_packet_mode == SDP_PACKET_MODE_NIC) {
			cnxk_ep_bb_vf->pkind = SDP_OTX2_PKIND_FS24;
			cnxk_ep_bb_info("Using pkind %d for NIC packet mode",
				  cnxk_ep_bb_vf->pkind);
		} else {
			cnxk_ep_bb_vf->pkind = SDP_OTX2_PKIND_FS0;
			cnxk_ep_bb_info("Using pkind %d for LOOP packet mode",
				  cnxk_ep_bb_vf->pkind);
		}
	}
#ifdef TODO_OTHER_DEVIDS_NOT_TESTED
	else if (cnxk_ep_bb_vf->chip_id == PCI_DEVID_OCTEONTX_EP_VF) {
		cnxk_ep_bb_vf->pkind = SDP_PKIND;
		cnxk_ep_bb_info("Using pkind %d.\n", cnxk_ep_bb_vf->pkind);
	}
#endif
	else {
		cnxk_ep_bb_err("Invalid chip id\n");
		ret = -EINVAL;
		goto exit;
	}

	/* Create mempool for RX/TX messages with EP */
	/* TODO_LATER: use common mempool for multiple bbdevs */
	/* TODO_NOW: calculate optimal elt_size; set to 512 */
	cnxk_ep_bb_vf->msg_pool = rte_pktmbuf_pool_create(RTE_STR(DRIVER_NAME)RTE_STR(_msg_pool),
						4*cnxk_ep_bb_vf->conf->num_oqdef_descs +
						4*cnxk_ep_bb_vf->conf->num_iqdef_descs,
						128, 0, 512, bbdev->data->socket_id);
	if (!cnxk_ep_bb_vf->msg_pool) {
		cnxk_ep_bb_err("msg_mpool create failed\n");
		ret = -ENOMEM;
		goto exit;
	}
	return 0;

exit:	cnxk_ep_bb_dev_exit(cnxk_ep_bb_vf);
	return ret;
}
