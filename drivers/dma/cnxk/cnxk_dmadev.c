/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 Marvell International Ltd.
 */

#include <string.h>
#include <unistd.h>

#include <rte_bus.h>
#include <rte_bus_pci.h>
#include <rte_common.h>
#include <rte_dmadev.h>
#include <rte_dmadev_pmd.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_pci.h>

#include <cnxk_dmadev.h>

static int cnxk_stats_reset(struct rte_dma_dev *dev, uint16_t vchan);

static int
cnxk_dmadev_info_get(const struct rte_dma_dev *dev, struct rte_dma_info *dev_info, uint32_t size)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;
	RTE_SET_USED(size);

	dev_info->max_vchans = MAX_VCHANS_PER_QUEUE;
	dev_info->nb_vchans = dpivf->num_vchans;
	dev_info->dev_capa = RTE_DMA_CAPA_MEM_TO_MEM | RTE_DMA_CAPA_MEM_TO_DEV |
			     RTE_DMA_CAPA_DEV_TO_MEM | RTE_DMA_CAPA_DEV_TO_DEV |
			     RTE_DMA_CAPA_OPS_COPY | RTE_DMA_CAPA_OPS_COPY_SG;
	dev_info->max_desc = DPI_MAX_DESC;
	dev_info->min_desc = DPI_MIN_DESC;
	dev_info->max_sges = DPI_MAX_POINTER;

	return 0;
}

static int
cnxk_dmadev_vchan_free(struct cnxk_dpi_vf_s *dpivf, uint16_t vchan)
{
	struct cnxk_dpi_conf *dpi_conf;
	uint16_t num_vchans;
	uint16_t max_desc;
	int i, j;

	if (vchan == RTE_DMA_ALL_VCHAN) {
		num_vchans = dpivf->num_vchans;
		i = 0;
	} else {
		if (vchan >= MAX_VCHANS_PER_QUEUE)
			return -EINVAL;

		num_vchans = vchan + 1;
		i = vchan;
	}

	for (; i < num_vchans; i++) {
		dpi_conf = &dpivf->conf[i];
		max_desc = dpi_conf->c_desc.max_cnt;
		if (dpi_conf->c_desc.compl_ptr) {
			for (j = 0; j < max_desc; j++)
				rte_free(dpi_conf->c_desc.compl_ptr[j]);
		}

		rte_free(dpi_conf->c_desc.compl_ptr);
		dpi_conf->c_desc.compl_ptr = NULL;
	}

	return 0;
}

static int
cnxk_dmadev_configure(struct rte_dma_dev *dev, const struct rte_dma_conf *conf, uint32_t conf_sz)
{
	struct cnxk_dpi_vf_s *dpivf = NULL;
	int rc = 0;

	RTE_SET_USED(conf_sz);

	dpivf = dev->fp_obj->dev_private;

	/* Accept only number of vchans as config from application. */
	if (!(dpivf->flag & CNXK_DPI_DEV_START)) {
		/* After config function, vchan setup function has to be called.
		 * Free up vchan memory if any, before configuring num_vchans.
		 */
		cnxk_dmadev_vchan_free(dpivf, RTE_DMA_ALL_VCHAN);
		dpivf->num_vchans = conf->nb_vchans;
	}

	if (dpivf->flag & CNXK_DPI_DEV_CONFIG)
		return rc;

	rc = roc_dpi_configure(&dpivf->rdpi);
	if (rc < 0) {
		plt_err("DMA configure failed err = %d", rc);
		goto done;
	}

	dpivf->flag |= CNXK_DPI_DEV_CONFIG;

done:
	return rc;
}

static int
cnxk_dmadev_vchan_setup(struct rte_dma_dev *dev, uint16_t vchan,
			const struct rte_dma_vchan_conf *conf, uint32_t conf_sz)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	union dpi_instr_hdr_s *header = &dpi_conf->hdr;
	uint16_t max_desc;
	uint32_t size;
	int i;

	RTE_SET_USED(conf_sz);

	if (dpivf->flag & CNXK_DPI_DEV_START)
		return 0;

	header->cn9k.pt = DPI_HDR_PT_ZBW_CA;

	switch (conf->direction) {
	case RTE_DMA_DIR_DEV_TO_MEM:
		header->cn9k.xtype = DPI_XTYPE_INBOUND;
		header->cn9k.lport = conf->src_port.pcie.coreid;
		header->cn9k.fport = 0;
		header->cn9k.pvfe = conf->src_port.pcie.vfen;
		if (header->cn9k.pvfe) {
			header->cn9k.func = conf->src_port.pcie.pfid << 12;
			header->cn9k.func |= conf->src_port.pcie.vfid;
		}
		break;
	case RTE_DMA_DIR_MEM_TO_DEV:
		header->cn9k.xtype = DPI_XTYPE_OUTBOUND;
		header->cn9k.lport = 0;
		header->cn9k.fport = conf->dst_port.pcie.coreid;
		header->cn9k.pvfe = conf->dst_port.pcie.vfen;
		if (header->cn9k.pvfe) {
			header->cn9k.func = conf->dst_port.pcie.pfid << 12;
			header->cn9k.func |= conf->dst_port.pcie.vfid;
		}
		break;
	case RTE_DMA_DIR_MEM_TO_MEM:
		header->cn9k.xtype = DPI_XTYPE_INTERNAL_ONLY;
		header->cn9k.lport = 0;
		header->cn9k.fport = 0;
		header->cn9k.pvfe = 0;
		break;
	case RTE_DMA_DIR_DEV_TO_DEV:
		header->cn9k.xtype = DPI_XTYPE_EXTERNAL_ONLY;
		header->cn9k.lport = conf->src_port.pcie.coreid;
		header->cn9k.fport = conf->dst_port.pcie.coreid;
		header->cn9k.pvfe = 0;
	};

	/* Free up descriptor memory before allocating. */
	cnxk_dmadev_vchan_free(dpivf, vchan);

	max_desc = conf->nb_desc;
	if (!rte_is_power_of_2(max_desc))
		max_desc = rte_align32pow2(max_desc);

	if (max_desc > DPI_MAX_DESC)
		max_desc = DPI_MAX_DESC;

	size = (max_desc * sizeof(struct cnxk_dpi_compl_s *));
	dpi_conf->c_desc.compl_ptr = rte_zmalloc(NULL, size, 0);

	if (dpi_conf->c_desc.compl_ptr == NULL) {
		plt_err("Failed to allocate for comp_data");
		return -ENOMEM;
	}

	for (i = 0; i < max_desc; i++) {
		dpi_conf->c_desc.compl_ptr[i] =
			rte_zmalloc(NULL, sizeof(struct cnxk_dpi_compl_s), 0);
		if (!dpi_conf->c_desc.compl_ptr[i]) {
			plt_err("Failed to allocate for descriptor memory");
			return -ENOMEM;
		}

		dpi_conf->c_desc.compl_ptr[i]->cdata = DPI_REQ_CDATA;
	}

	dpi_conf->c_desc.max_cnt = (max_desc - 1);

	return 0;
}

static int
cn10k_dmadev_vchan_setup(struct rte_dma_dev *dev, uint16_t vchan,
			 const struct rte_dma_vchan_conf *conf, uint32_t conf_sz)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	union dpi_instr_hdr_s *header = &dpi_conf->hdr;
	uint16_t max_desc;
	uint32_t size;
	int i;

	RTE_SET_USED(conf_sz);

	if (dpivf->flag & CNXK_DPI_DEV_START)
		return 0;

	header->cn10k.pt = DPI_HDR_PT_ZBW_CA;

	switch (conf->direction) {
	case RTE_DMA_DIR_DEV_TO_MEM:
		header->cn10k.xtype = DPI_XTYPE_INBOUND;
		header->cn10k.lport = conf->src_port.pcie.coreid;
		header->cn10k.fport = 0;
		header->cn10k.pvfe = conf->src_port.pcie.vfen;
		if (header->cn10k.pvfe) {
			header->cn10k.func = conf->src_port.pcie.pfid << 12;
			header->cn10k.func |= conf->src_port.pcie.vfid;
		}
		break;
	case RTE_DMA_DIR_MEM_TO_DEV:
		header->cn10k.xtype = DPI_XTYPE_OUTBOUND;
		header->cn10k.lport = 0;
		header->cn10k.fport = conf->dst_port.pcie.coreid;
		header->cn10k.pvfe = conf->dst_port.pcie.vfen;
		if (header->cn10k.pvfe) {
			header->cn10k.func = conf->dst_port.pcie.pfid << 12;
			header->cn10k.func |= conf->dst_port.pcie.vfid;
		}
		break;
	case RTE_DMA_DIR_MEM_TO_MEM:
		header->cn10k.xtype = DPI_XTYPE_INTERNAL_ONLY;
		header->cn10k.lport = 0;
		header->cn10k.fport = 0;
		header->cn10k.pvfe = 0;
		break;
	case RTE_DMA_DIR_DEV_TO_DEV:
		header->cn10k.xtype = DPI_XTYPE_EXTERNAL_ONLY;
		header->cn10k.lport = conf->src_port.pcie.coreid;
		header->cn10k.fport = conf->dst_port.pcie.coreid;
		header->cn10k.pvfe = 0;
	};

	/* Free up descriptor memory before allocating. */
	cnxk_dmadev_vchan_free(dpivf, vchan);

	max_desc = conf->nb_desc;
	if (!rte_is_power_of_2(max_desc))
		max_desc = rte_align32pow2(max_desc);

	if (max_desc > DPI_MAX_DESC)
		max_desc = DPI_MAX_DESC;

	size = (max_desc * sizeof(struct cnxk_dpi_compl_s *));
	dpi_conf->c_desc.compl_ptr = rte_zmalloc(NULL, size, 0);

	if (dpi_conf->c_desc.compl_ptr == NULL) {
		plt_err("Failed to allocate for comp_data");
		return -ENOMEM;
	}

	for (i = 0; i < max_desc; i++) {
		dpi_conf->c_desc.compl_ptr[i] =
			rte_zmalloc(NULL, sizeof(struct cnxk_dpi_compl_s), 0);
		if (!dpi_conf->c_desc.compl_ptr[i]) {
			plt_err("Failed to allocate for descriptor memory");
			return -ENOMEM;
		}
		dpi_conf->c_desc.compl_ptr[i]->cdata = DPI_REQ_CDATA;
	}

	dpi_conf->c_desc.max_cnt = (max_desc - 1);

	return 0;
}

static int
cnxk_dmadev_start(struct rte_dma_dev *dev)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;
	struct cnxk_dpi_conf *dpi_conf;
	int i, j;

	if (dpivf->flag & CNXK_DPI_DEV_START)
		return 0;

	for (i = 0; i < dpivf->num_vchans; i++) {
		dpi_conf = &dpivf->conf[i];
		dpi_conf->c_desc.head = 0;
		dpi_conf->c_desc.tail = 0;
		dpi_conf->pnum_words = 0;
		dpi_conf->pending = 0;
		dpi_conf->desc_idx = 0;
		for (j = 0; j < dpi_conf->c_desc.max_cnt; j++) {
			if (dpi_conf->c_desc.compl_ptr[j])
				dpi_conf->c_desc.compl_ptr[j]->cdata = DPI_REQ_CDATA;
		}

		cnxk_stats_reset(dev, i);
	}

	roc_dpi_enable(&dpivf->rdpi);

	dpivf->flag |= CNXK_DPI_DEV_START;

	return 0;
}

static int
cnxk_dmadev_stop(struct rte_dma_dev *dev)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;

	roc_dpi_disable(&dpivf->rdpi);
	dpivf->flag &= ~CNXK_DPI_DEV_START;

	return 0;
}

static int
cnxk_dmadev_close(struct rte_dma_dev *dev)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;

	roc_dpi_disable(&dpivf->rdpi);
	cnxk_dmadev_vchan_free(dpivf, RTE_DMA_ALL_VCHAN);
	roc_dpi_dev_fini(&dpivf->rdpi);

	/* Clear all flags as we close the device. */
	dpivf->flag = 0;

	return 0;
}

static inline int
__dpi_queue_write(struct roc_dpi *dpi, uint64_t *cmds, int cmd_count)
{
	uint64_t *ptr = dpi->chunk_base;

	if ((cmd_count < DPI_MIN_CMD_SIZE) || (cmd_count > DPI_MAX_CMD_SIZE) || cmds == NULL)
		return -EINVAL;

	/*
	 * Normally there is plenty of room in the current buffer for the
	 * command
	 */
	if (dpi->chunk_head + cmd_count < dpi->pool_size_m1) {
		ptr += dpi->chunk_head;
		dpi->chunk_head += cmd_count;
		while (cmd_count--)
			*ptr++ = *cmds++;
	} else {
		int count;
		uint64_t *new_buff = dpi->chunk_next;

		dpi->chunk_next = (void *)roc_npa_aura_op_alloc(dpi->aura_handle, 0);
		if (!dpi->chunk_next) {
			plt_dp_dbg("Failed to alloc next buffer from NPA");

			/* NPA failed to allocate a buffer. Restoring chunk_next
			 * to its original address.
			 */
			dpi->chunk_next = new_buff;
			return -ENOSPC;
		}

		/*
		 * Figure out how many cmd words will fit in this buffer.
		 * One location will be needed for the next buffer pointer.
		 */
		count = dpi->pool_size_m1 - dpi->chunk_head;
		ptr += dpi->chunk_head;
		cmd_count -= count;
		while (count--)
			*ptr++ = *cmds++;

		/*
		 * chunk next ptr is 2 DWORDS
		 * second DWORD is reserved.
		 */
		*ptr++ = (uint64_t)new_buff;
		*ptr = 0;

		/*
		 * The current buffer is full and has a link to the next
		 * buffers. Time to write the rest of the commands into the new
		 * buffer.
		 */
		dpi->chunk_base = new_buff;
		dpi->chunk_head = cmd_count;
		ptr = new_buff;
		while (cmd_count--)
			*ptr++ = *cmds++;

		/* queue index may be greater than pool size */
		if (dpi->chunk_head >= dpi->pool_size_m1) {
			new_buff = dpi->chunk_next;
			dpi->chunk_next = (void *)roc_npa_aura_op_alloc(dpi->aura_handle, 0);
			if (!dpi->chunk_next) {
				plt_dp_dbg("Failed to alloc next buffer from NPA");

				/* NPA failed to allocate a buffer. Restoring chunk_next
				 * to its original address.
				 */
				dpi->chunk_next = new_buff;
				return -ENOSPC;
			}

			/* Write next buffer address */
			*ptr = (uint64_t)new_buff;
			dpi->chunk_base = new_buff;
			dpi->chunk_head = 0;
		}
	}

	return 0;
}

static int
cnxk_dmadev_copy(void *dev_private, uint16_t vchan, rte_iova_t src, rte_iova_t dst, uint32_t length,
		 uint64_t flags)
{
	struct cnxk_dpi_vf_s *dpivf = dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	union dpi_instr_hdr_s *header = &dpi_conf->hdr;
	struct cnxk_dpi_compl_s *comp_ptr;
	uint64_t cmd[DPI_MAX_CMD_SIZE];
	rte_iova_t fptr, lptr;
	int num_words = 0;
	int rc;

	comp_ptr = dpi_conf->c_desc.compl_ptr[dpi_conf->c_desc.tail];
	header->cn9k.ptr = (uint64_t)comp_ptr;
	STRM_INC(dpi_conf->c_desc, tail);

	if (unlikely(dpi_conf->c_desc.tail == dpi_conf->c_desc.head)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return -ENOSPC;
	}

	header->cn9k.nfst = 1;
	header->cn9k.nlst = 1;

	/*
	 * For inbound case, src pointers are last pointers.
	 * For all other cases, src pointers are first pointers.
	 */
	if (header->cn9k.xtype == DPI_XTYPE_INBOUND) {
		fptr = dst;
		lptr = src;
	} else {
		fptr = src;
		lptr = dst;
	}

	cmd[0] = header->u[0];
	cmd[1] = header->u[1];
	cmd[2] = header->u[2];
	/* word3 is always 0 */
	num_words += 4;
	cmd[num_words++] = length;
	cmd[num_words++] = fptr;
	cmd[num_words++] = length;
	cmd[num_words++] = lptr;

	rc = __dpi_queue_write(&dpivf->rdpi, cmd, num_words);
	if (unlikely(rc)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return rc;
	}

	rte_wmb();
	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		plt_write64(num_words, dpivf->rdpi.rbase + DPI_VDMA_DBELL);
		dpi_conf->stats.submitted++;
	} else {
		dpi_conf->pnum_words += num_words;
		dpi_conf->pending++;
	}

	return (dpi_conf->desc_idx++);
}

static int
cnxk_dmadev_copy_sg(void *dev_private, uint16_t vchan, const struct rte_dma_sge *src,
		    const struct rte_dma_sge *dst, uint16_t nb_src, uint16_t nb_dst, uint64_t flags)
{
	struct cnxk_dpi_vf_s *dpivf = dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	union dpi_instr_hdr_s *header = &dpi_conf->hdr;
	const struct rte_dma_sge *fptr, *lptr;
	struct cnxk_dpi_compl_s *comp_ptr;
	uint64_t cmd[DPI_MAX_CMD_SIZE];
	int num_words = 0;
	int i, rc;

	comp_ptr = dpi_conf->c_desc.compl_ptr[dpi_conf->c_desc.tail];
	header->cn9k.ptr = (uint64_t)comp_ptr;
	STRM_INC(dpi_conf->c_desc, tail);

	if (unlikely(dpi_conf->c_desc.tail == dpi_conf->c_desc.head)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return -ENOSPC;
	}

	/*
	 * For inbound case, src pointers are last pointers.
	 * For all other cases, src pointers are first pointers.
	 */
	if (header->cn9k.xtype == DPI_XTYPE_INBOUND) {
		header->cn9k.nfst = nb_dst & DPI_MAX_POINTER;
		header->cn9k.nlst = nb_src & DPI_MAX_POINTER;
		fptr = &dst[0];
		lptr = &src[0];
	} else {
		header->cn9k.nfst = nb_src & DPI_MAX_POINTER;
		header->cn9k.nlst = nb_dst & DPI_MAX_POINTER;
		fptr = &src[0];
		lptr = &dst[0];
	}

	cmd[0] = header->u[0];
	cmd[1] = header->u[1];
	cmd[2] = header->u[2];
	num_words += 4;
	for (i = 0; i < header->cn9k.nfst; i++) {
		cmd[num_words++] = (uint64_t)fptr->length;
		cmd[num_words++] = fptr->addr;
		fptr++;
	}

	for (i = 0; i < header->cn9k.nlst; i++) {
		cmd[num_words++] = (uint64_t)lptr->length;
		cmd[num_words++] = lptr->addr;
		lptr++;
	}

	rc = __dpi_queue_write(&dpivf->rdpi, cmd, num_words);
	if (unlikely(rc)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return rc;
	}

	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		rte_wmb();
		plt_write64(num_words, dpivf->rdpi.rbase + DPI_VDMA_DBELL);
		dpi_conf->stats.submitted += nb_src;
	} else {
		dpi_conf->pnum_words += num_words;
		dpi_conf->pending++;
	}

	return (dpi_conf->desc_idx++);
}

static int
cn10k_dmadev_copy(void *dev_private, uint16_t vchan, rte_iova_t src, rte_iova_t dst,
		  uint32_t length, uint64_t flags)
{
	struct cnxk_dpi_vf_s *dpivf = dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	union dpi_instr_hdr_s *header = &dpi_conf->hdr;
	struct cnxk_dpi_compl_s *comp_ptr;
	uint64_t cmd[DPI_MAX_CMD_SIZE];
	rte_iova_t fptr, lptr;
	int num_words = 0;
	int rc;

	comp_ptr = dpi_conf->c_desc.compl_ptr[dpi_conf->c_desc.tail];
	header->cn10k.ptr = (uint64_t)comp_ptr;
	STRM_INC(dpi_conf->c_desc, tail);

	if (unlikely(dpi_conf->c_desc.tail == dpi_conf->c_desc.head)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return -ENOSPC;
	}

	header->cn10k.nfst = 1;
	header->cn10k.nlst = 1;

	fptr = src;
	lptr = dst;

	cmd[0] = header->u[0];
	cmd[1] = header->u[1];
	cmd[2] = header->u[2];
	/* word3 is always 0 */
	num_words += 4;
	cmd[num_words++] = length;
	cmd[num_words++] = fptr;
	cmd[num_words++] = length;
	cmd[num_words++] = lptr;

	rc = __dpi_queue_write(&dpivf->rdpi, cmd, num_words);
	if (unlikely(rc)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return rc;
	}

	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		rte_wmb();
		plt_write64(num_words, dpivf->rdpi.rbase + DPI_VDMA_DBELL);
		dpi_conf->stats.submitted++;
	} else {
		dpi_conf->pnum_words += num_words;
		dpi_conf->pending++;
	}

	return dpi_conf->desc_idx++;
}

static int
cn10k_dmadev_copy_sg(void *dev_private, uint16_t vchan, const struct rte_dma_sge *src,
		     const struct rte_dma_sge *dst, uint16_t nb_src, uint16_t nb_dst,
		     uint64_t flags)
{
	struct cnxk_dpi_vf_s *dpivf = dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	union dpi_instr_hdr_s *header = &dpi_conf->hdr;
	const struct rte_dma_sge *fptr, *lptr;
	struct cnxk_dpi_compl_s *comp_ptr;
	uint64_t cmd[DPI_MAX_CMD_SIZE];
	int num_words = 0;
	int i, rc;

	comp_ptr = dpi_conf->c_desc.compl_ptr[dpi_conf->c_desc.tail];
	header->cn10k.ptr = (uint64_t)comp_ptr;
	STRM_INC(dpi_conf->c_desc, tail);

	if (unlikely(dpi_conf->c_desc.tail == dpi_conf->c_desc.head)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return -ENOSPC;
	}

	header->cn10k.nfst = nb_src & DPI_MAX_POINTER;
	header->cn10k.nlst = nb_dst & DPI_MAX_POINTER;
	fptr = &src[0];
	lptr = &dst[0];

	cmd[0] = header->u[0];
	cmd[1] = header->u[1];
	cmd[2] = header->u[2];
	num_words += 4;

	for (i = 0; i < header->cn10k.nfst; i++) {
		cmd[num_words++] = (uint64_t)fptr->length;
		cmd[num_words++] = fptr->addr;
		fptr++;
	}

	for (i = 0; i < header->cn10k.nlst; i++) {
		cmd[num_words++] = (uint64_t)lptr->length;
		cmd[num_words++] = lptr->addr;
		lptr++;
	}

	rc = __dpi_queue_write(&dpivf->rdpi, cmd, num_words);
	if (unlikely(rc)) {
		STRM_DEC(dpi_conf->c_desc, tail);
		return rc;
	}

	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		rte_wmb();
		plt_write64(num_words, dpivf->rdpi.rbase + DPI_VDMA_DBELL);
		dpi_conf->stats.submitted += nb_src;
	} else {
		dpi_conf->pnum_words += num_words;
		dpi_conf->pending++;
	}

	return (dpi_conf->desc_idx++);
}

static uint16_t
cnxk_dmadev_completed(void *dev_private, uint16_t vchan, const uint16_t nb_cpls, uint16_t *last_idx,
		      bool *has_error)
{
	struct cnxk_dpi_vf_s *dpivf = dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	struct cnxk_dpi_cdesc_data_s *c_desc = &dpi_conf->c_desc;
	struct cnxk_dpi_compl_s *comp_ptr;
	int cnt;

	for (cnt = 0; cnt < nb_cpls; cnt++) {
		comp_ptr = c_desc->compl_ptr[c_desc->head];

		if (comp_ptr->cdata) {
			if (comp_ptr->cdata == DPI_REQ_CDATA)
				break;
			*has_error = 1;
			dpi_conf->stats.errors++;
			STRM_INC(*c_desc, head);
			break;
		}

		comp_ptr->cdata = DPI_REQ_CDATA;
		STRM_INC(*c_desc, head);
	}

	dpi_conf->stats.completed += cnt;
	*last_idx = dpi_conf->stats.completed - 1;

	return cnt;
}

static uint16_t
cnxk_dmadev_completed_status(void *dev_private, uint16_t vchan, const uint16_t nb_cpls,
			     uint16_t *last_idx, enum rte_dma_status_code *status)
{
	struct cnxk_dpi_vf_s *dpivf = dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	struct cnxk_dpi_cdesc_data_s *c_desc = &dpi_conf->c_desc;
	struct cnxk_dpi_compl_s *comp_ptr;
	int cnt;

	for (cnt = 0; cnt < nb_cpls; cnt++) {
		comp_ptr = c_desc->compl_ptr[c_desc->head];
		status[cnt] = comp_ptr->cdata;
		if (status[cnt]) {
			if (status[cnt] == DPI_REQ_CDATA)
				break;

			dpi_conf->stats.errors++;
		}
		comp_ptr->cdata = DPI_REQ_CDATA;
		STRM_INC(*c_desc, head);
	}

	dpi_conf->stats.completed += cnt;
	*last_idx = dpi_conf->stats.completed - 1;

	return cnt;
}

static uint16_t
cnxk_damdev_burst_capacity(const void *dev_private, uint16_t vchan)
{
	const struct cnxk_dpi_vf_s *dpivf = (const struct cnxk_dpi_vf_s *)dev_private;
	const struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	uint16_t burst_cap;

	burst_cap = dpi_conf->c_desc.max_cnt -
		    ((dpi_conf->stats.submitted - dpi_conf->stats.completed) + dpi_conf->pending) +
		    1;

	return burst_cap;
}

static int
cnxk_dmadev_submit(void *dev_private, uint16_t vchan)
{
	struct cnxk_dpi_vf_s *dpivf = dev_private;
	struct cnxk_dpi_conf *dpi_conf = &dpivf->conf[vchan];
	uint32_t num_words = dpi_conf->pnum_words;

	if (!dpi_conf->pnum_words)
		return 0;

	rte_wmb();
	plt_write64(num_words, dpivf->rdpi.rbase + DPI_VDMA_DBELL);

	dpi_conf->stats.submitted += dpi_conf->pending;
	dpi_conf->pnum_words = 0;
	dpi_conf->pending = 0;

	return 0;
}

static int
cnxk_stats_get(const struct rte_dma_dev *dev, uint16_t vchan, struct rte_dma_stats *rte_stats,
	       uint32_t size)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;
	struct cnxk_dpi_conf *dpi_conf;
	int i;

	if (size < sizeof(rte_stats))
		return -EINVAL;
	if (rte_stats == NULL)
		return -EINVAL;

	/* Stats of all vchans requested. */
	if (vchan == RTE_DMA_ALL_VCHAN) {
		for (i = 0; i < dpivf->num_vchans; i++) {
			dpi_conf = &dpivf->conf[i];
			rte_stats->submitted += dpi_conf->stats.submitted;
			rte_stats->completed += dpi_conf->stats.completed;
			rte_stats->errors += dpi_conf->stats.errors;
		}

		goto done;
	}

	if (vchan >= MAX_VCHANS_PER_QUEUE)
		return -EINVAL;

	dpi_conf = &dpivf->conf[vchan];
	*rte_stats = dpi_conf->stats;

done:
	return 0;
}

static int
cnxk_stats_reset(struct rte_dma_dev *dev, uint16_t vchan)
{
	struct cnxk_dpi_vf_s *dpivf = dev->fp_obj->dev_private;
	struct cnxk_dpi_conf *dpi_conf;
	int i;

	/* clear stats of all vchans. */
	if (vchan == RTE_DMA_ALL_VCHAN) {
		for (i = 0; i < dpivf->num_vchans; i++) {
			dpi_conf = &dpivf->conf[i];
			dpi_conf->stats = (struct rte_dma_stats){0};
		}

		return 0;
	}

	if (vchan >= MAX_VCHANS_PER_QUEUE)
		return -EINVAL;

	dpi_conf = &dpivf->conf[vchan];
	dpi_conf->stats = (struct rte_dma_stats){0};

	return 0;
}

static const struct rte_dma_dev_ops cn10k_dmadev_ops = {
	.dev_close = cnxk_dmadev_close,
	.dev_configure = cnxk_dmadev_configure,
	.dev_info_get = cnxk_dmadev_info_get,
	.dev_start = cnxk_dmadev_start,
	.dev_stop = cnxk_dmadev_stop,
	.stats_get = cnxk_stats_get,
	.stats_reset = cnxk_stats_reset,
	.vchan_setup = cn10k_dmadev_vchan_setup,
};

static const struct rte_dma_dev_ops cnxk_dmadev_ops = {
	.dev_close = cnxk_dmadev_close,
	.dev_configure = cnxk_dmadev_configure,
	.dev_info_get = cnxk_dmadev_info_get,
	.dev_start = cnxk_dmadev_start,
	.dev_stop = cnxk_dmadev_stop,
	.stats_get = cnxk_stats_get,
	.stats_reset = cnxk_stats_reset,
	.vchan_setup = cnxk_dmadev_vchan_setup,
};

static int
cnxk_dmadev_probe(struct rte_pci_driver *pci_drv __rte_unused, struct rte_pci_device *pci_dev)
{
	struct cnxk_dpi_vf_s *dpivf = NULL;
	char name[RTE_DEV_NAME_MAX_LEN];
	struct rte_dma_dev *dmadev;
	struct roc_dpi *rdpi = NULL;
	int rc;

	if (!pci_dev->mem_resource[0].addr)
		return -ENODEV;

	rc = roc_plt_init();
	if (rc) {
		plt_err("Failed to initialize platform model, rc=%d", rc);
		return rc;
	}
	memset(name, 0, sizeof(name));
	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	dmadev = rte_dma_pmd_allocate(name, pci_dev->device.numa_node, sizeof(*dpivf));
	if (dmadev == NULL) {
		plt_err("dma device allocation failed for %s", name);
		return -ENOMEM;
	}

	dpivf = dmadev->data->dev_private;

	dmadev->device = &pci_dev->device;
	dmadev->fp_obj->dev_private = dpivf;
	dmadev->dev_ops = &cnxk_dmadev_ops;

	dmadev->fp_obj->copy = cnxk_dmadev_copy;
	dmadev->fp_obj->copy_sg = cnxk_dmadev_copy_sg;
	dmadev->fp_obj->submit = cnxk_dmadev_submit;
	dmadev->fp_obj->completed = cnxk_dmadev_completed;
	dmadev->fp_obj->completed_status = cnxk_dmadev_completed_status;
	dmadev->fp_obj->burst_capacity = cnxk_damdev_burst_capacity;

	if (pci_dev->id.subsystem_device_id == PCI_SUBSYSTEM_DEVID_CN10KA ||
	    pci_dev->id.subsystem_device_id == PCI_SUBSYSTEM_DEVID_CN10KAS ||
	    pci_dev->id.subsystem_device_id == PCI_SUBSYSTEM_DEVID_CNF10KA ||
	    pci_dev->id.subsystem_device_id == PCI_SUBSYSTEM_DEVID_CNF10KB ||
	    pci_dev->id.subsystem_device_id == PCI_SUBSYSTEM_DEVID_CN10KB) {
		dmadev->dev_ops = &cn10k_dmadev_ops;
		dmadev->fp_obj->copy = cn10k_dmadev_copy;
		dmadev->fp_obj->copy_sg = cn10k_dmadev_copy_sg;
	}

	rdpi = &dpivf->rdpi;

	rdpi->pci_dev = pci_dev;
	rc = roc_dpi_dev_init(rdpi);
	if (rc < 0)
		goto err_out_free;

	dmadev->state = RTE_DMA_DEV_READY;

	return 0;

err_out_free:
	if (dmadev)
		rte_dma_pmd_release(name);

	return rc;
}

static int
cnxk_dmadev_remove(struct rte_pci_device *pci_dev)
{
	char name[RTE_DEV_NAME_MAX_LEN];

	memset(name, 0, sizeof(name));
	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	return rte_dma_pmd_release(name);
}

static const struct rte_pci_id cnxk_dma_pci_map[] = {
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_CNXK_DPI_VF)},
	{
		.vendor_id = 0,
	},
};

static struct rte_pci_driver cnxk_dmadev = {
	.id_table = cnxk_dma_pci_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_NEED_IOVA_AS_VA,
	.probe = cnxk_dmadev_probe,
	.remove = cnxk_dmadev_remove,
};

RTE_PMD_REGISTER_PCI(cnxk_dmadev_pci_driver, cnxk_dmadev);
RTE_PMD_REGISTER_PCI_TABLE(cnxk_dmadev_pci_driver, cnxk_dma_pci_map);
RTE_PMD_REGISTER_KMOD_DEP(cnxk_dmadev_pci_driver, "vfio-pci");
