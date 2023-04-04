/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

static int
nix_fc_rxchan_bpid_get(struct roc_nix *roc_nix, struct roc_nix_fc_cfg *fc_cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);

	if (nix->chan_cnt != 0)
		fc_cfg->rxchan_cfg.enable = true;
	else
		fc_cfg->rxchan_cfg.enable = false;

	fc_cfg->type = ROC_NIX_FC_RXCHAN_CFG;

	return 0;
}

static int
nix_fc_rxchan_bpid_set(struct roc_nix *roc_nix, bool enable)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct dev *dev = &nix->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	struct nix_bp_cfg_req *req;
	struct nix_bp_cfg_rsp *rsp;
	int rc = -ENOSPC, i;

	if (enable) {
		req = mbox_alloc_msg_nix_bp_enable(mbox);
		if (req == NULL)
			goto exit;

		req->chan_base = 0;
		if (roc_nix_is_lbk(roc_nix) || roc_nix_is_sdp(roc_nix))
			req->chan_cnt = NIX_LBK_MAX_CHAN;
		else
			req->chan_cnt = NIX_CGX_MAX_CHAN;

		req->bpid_per_chan = true;

		rc = mbox_process_msg(mbox, (void *)&rsp);
		if (rc || (req->chan_cnt != rsp->chan_cnt)) {
			rc = -EIO;
			goto exit;
		}

		nix->chan_cnt = rsp->chan_cnt;
		for (i = 0; i < rsp->chan_cnt; i++)
			nix->bpid[i] = rsp->chan_bpid[i] & 0x1FF;
	} else {
		req = mbox_alloc_msg_nix_bp_disable(mbox);
		if (req == NULL)
			goto exit;
		req->chan_base = 0;
		req->chan_cnt = nix->chan_cnt;

		rc = mbox_process(mbox);
		if (rc)
			goto exit;

		memset(nix->bpid, 0, sizeof(uint16_t) * NIX_MAX_CHAN);
		nix->chan_cnt = 0;
	}

	if (roc_model_is_cn9k())
		goto exit;

	/* Enable backpressure on CPT if inline inb is enabled */
	if (enable && roc_nix_inl_inb_is_enabled(roc_nix) &&
	    !roc_errata_cpt_hang_on_x2p_bp()) {
		req = mbox_alloc_msg_nix_cpt_bp_enable(mbox);
		if (req == NULL)
			goto exit;
		req->chan_base = 0;
		if (roc_nix_is_lbk(roc_nix) || roc_nix_is_sdp(roc_nix))
			req->chan_cnt = NIX_LBK_MAX_CHAN;
		else
			req->chan_cnt = NIX_CGX_MAX_CHAN;
		req->bpid_per_chan = 0;

		rc = mbox_process_msg(mbox, (void *)&rsp);
		if (rc)
			goto exit;
		nix->cpt_lbpid = rsp->chan_bpid[0] & 0x1FF;
	} else {
		req = mbox_alloc_msg_nix_cpt_bp_disable(mbox);
		if (req == NULL)
			goto exit;
		req->chan_base = 0;
		if (roc_nix_is_lbk(roc_nix) || roc_nix_is_sdp(roc_nix))
			req->chan_cnt = NIX_LBK_MAX_CHAN;
		else
			req->chan_cnt = NIX_CGX_MAX_CHAN;
		req->bpid_per_chan = 0;

		rc = mbox_process_msg(mbox, (void *)&rsp);
		if (rc)
			goto exit;
		nix->cpt_lbpid = 0;
	}

	/* CPT to NIX BP on all channels */
	if (!roc_feature_nix_has_rxchan_multi_bpid() || !nix->cpt_nixbpid)
		goto exit;

	mbox_put(mbox);
	for (i = 0; i < nix->rx_chan_cnt; i++) {
		rc = roc_nix_chan_bpid_set(roc_nix, i, nix->cpt_nixbpid, enable, false);
		if (rc)
			break;
	}
	return rc;
exit:
	mbox_put(mbox);
	return rc;
}

static int
nix_fc_cq_config_get(struct roc_nix *roc_nix, struct roc_nix_fc_cfg *fc_cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct dev *dev = &nix->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	struct nix_aq_enq_rsp *rsp;
	int rc;

	if (roc_model_is_cn9k()) {
		struct nix_aq_enq_req *aq;

		aq = mbox_alloc_msg_nix_aq_enq(mbox);
		if (!aq) {
			rc = -ENOSPC;
			goto exit;
		}

		aq->qidx = fc_cfg->cq_cfg.rq;
		aq->ctype = NIX_AQ_CTYPE_CQ;
		aq->op = NIX_AQ_INSTOP_READ;
	} else {
		struct nix_cn10k_aq_enq_req *aq;

		aq = mbox_alloc_msg_nix_cn10k_aq_enq(mbox);
		if (!aq) {
			rc = -ENOSPC;
			goto exit;
		}

		aq->qidx = fc_cfg->cq_cfg.rq;
		aq->ctype = NIX_AQ_CTYPE_CQ;
		aq->op = NIX_AQ_INSTOP_READ;
	}

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		goto exit;

	fc_cfg->cq_cfg.cq_drop = rsp->cq.bp;
	fc_cfg->cq_cfg.enable = rsp->cq.bp_ena;
	fc_cfg->type = ROC_NIX_FC_CQ_CFG;

exit:
	mbox_put(mbox);
	return rc;
}

static int
nix_fc_rq_config_get(struct roc_nix *roc_nix, struct roc_nix_fc_cfg *fc_cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct dev *dev = &nix->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	struct nix_aq_enq_rsp *rsp;
	struct npa_aq_enq_req *npa_req;
	struct npa_aq_enq_rsp *npa_rsp;
	int rc;

	if (roc_model_is_cn9k()) {
		struct nix_aq_enq_req *aq;

		aq = mbox_alloc_msg_nix_aq_enq(mbox);
		if (!aq) {
			rc = -ENOSPC;
			goto exit;
		}

		aq->qidx = fc_cfg->rq_cfg.rq;
		aq->ctype = NIX_AQ_CTYPE_RQ;
		aq->op = NIX_AQ_INSTOP_READ;
	} else {
		struct nix_cn10k_aq_enq_req *aq;

		aq = mbox_alloc_msg_nix_cn10k_aq_enq(mbox);
		if (!aq) {
			rc = -ENOSPC;
			goto exit;
		}

		aq->qidx = fc_cfg->rq_cfg.rq;
		aq->ctype = NIX_AQ_CTYPE_RQ;
		aq->op = NIX_AQ_INSTOP_READ;
	}

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		goto exit;

	npa_req = mbox_alloc_msg_npa_aq_enq(mbox);
	if (!npa_req) {
		rc = -ENOSPC;
		goto exit;
	}

	npa_req->aura_id = rsp->rq.lpb_aura;
	npa_req->ctype = NPA_AQ_CTYPE_AURA;
	npa_req->op = NPA_AQ_INSTOP_READ;

	rc = mbox_process_msg(mbox, (void *)&npa_rsp);
	if (rc)
		goto exit;

	fc_cfg->cq_cfg.cq_drop = npa_rsp->aura.bp;
	fc_cfg->cq_cfg.enable = npa_rsp->aura.bp_ena;
	fc_cfg->type = ROC_NIX_FC_RQ_CFG;

exit:
	mbox_put(mbox);
	return rc;
}

static int
nix_fc_cq_config_set(struct roc_nix *roc_nix, struct roc_nix_fc_cfg *fc_cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct dev *dev = &nix->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	int rc;

	if (roc_model_is_cn9k()) {
		struct nix_aq_enq_req *aq;

		aq = mbox_alloc_msg_nix_aq_enq(mbox);
		if (!aq) {
			rc = -ENOSPC;
			goto exit;
		}

		aq->qidx = fc_cfg->cq_cfg.rq;
		aq->ctype = NIX_AQ_CTYPE_CQ;
		aq->op = NIX_AQ_INSTOP_WRITE;

		if (fc_cfg->cq_cfg.enable) {
			aq->cq.bpid = nix->bpid[fc_cfg->cq_cfg.tc];
			aq->cq_mask.bpid = ~(aq->cq_mask.bpid);
			aq->cq.bp = fc_cfg->cq_cfg.cq_drop;
			aq->cq_mask.bp = ~(aq->cq_mask.bp);
		}

		aq->cq.bp_ena = !!(fc_cfg->cq_cfg.enable);
		aq->cq_mask.bp_ena = ~(aq->cq_mask.bp_ena);
	} else {
		struct nix_cn10k_aq_enq_req *aq;

		aq = mbox_alloc_msg_nix_cn10k_aq_enq(mbox);
		if (!aq) {
			rc = -ENOSPC;
			goto exit;
		}

		aq->qidx = fc_cfg->cq_cfg.rq;
		aq->ctype = NIX_AQ_CTYPE_CQ;
		aq->op = NIX_AQ_INSTOP_WRITE;

		if (fc_cfg->cq_cfg.enable) {
			aq->cq.bpid = nix->bpid[fc_cfg->cq_cfg.tc];
			aq->cq_mask.bpid = ~(aq->cq_mask.bpid);
			aq->cq.bp = fc_cfg->cq_cfg.cq_drop;
			aq->cq_mask.bp = ~(aq->cq_mask.bp);
		}

		aq->cq.bp_ena = !!(fc_cfg->cq_cfg.enable);
		aq->cq_mask.bp_ena = ~(aq->cq_mask.bp_ena);
	}

	rc = mbox_process(mbox);
exit:
	mbox_put(mbox);
	return rc;
}

static int
nix_fc_rq_config_set(struct roc_nix *roc_nix, struct roc_nix_fc_cfg *fc_cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct roc_nix_fc_cfg tmp;
	struct roc_nix_rq *rq;
	int sso_ena = 0, rc;

	rq = nix->rqs[fc_cfg->rq_cfg.rq];
	/* Check whether RQ is connected to SSO or not */
	sso_ena = roc_nix_rq_is_sso_enable(roc_nix, fc_cfg->rq_cfg.rq);
	if (sso_ena < 0)
		return -EINVAL;

	if (sso_ena) {
		roc_nix_fc_npa_bp_cfg(roc_nix, fc_cfg->rq_cfg.pool,
				      fc_cfg->rq_cfg.enable, true,
				      fc_cfg->rq_cfg.tc);

		if (roc_nix->local_meta_aura_ena && roc_nix->meta_aura_handle)
			roc_nix_fc_npa_bp_cfg(roc_nix, roc_nix->meta_aura_handle,
					      fc_cfg->rq_cfg.enable, true, fc_cfg->rq_cfg.tc);
	}

	/* Copy RQ config to CQ config as they are occupying same area */
	memset(&tmp, 0, sizeof(tmp));
	tmp.type = ROC_NIX_FC_CQ_CFG;
	tmp.cq_cfg.rq = fc_cfg->rq_cfg.rq;
	tmp.cq_cfg.tc = fc_cfg->rq_cfg.tc;
	tmp.cq_cfg.cq_drop = fc_cfg->rq_cfg.cq_drop;
	tmp.cq_cfg.enable = fc_cfg->rq_cfg.enable;

	rc = nix_fc_cq_config_set(roc_nix, &tmp);
	if (rc)
		return rc;

	rq->tc = fc_cfg->rq_cfg.enable ? fc_cfg->rq_cfg.tc : ROC_NIX_PFC_CLASS_INVALID;
	plt_nix_dbg("RQ %u: TC %u %s", fc_cfg->rq_cfg.rq, fc_cfg->rq_cfg.tc,
		    fc_cfg->rq_cfg.enable ? "enabled" : "disabled");
	return 0;
}

int
roc_nix_fc_config_get(struct roc_nix *roc_nix, struct roc_nix_fc_cfg *fc_cfg)
{
	if (!roc_nix_is_pf(roc_nix) && !roc_nix_is_lbk(roc_nix) &&
	    !roc_nix_is_sdp(roc_nix))
		return 0;

	if (fc_cfg->type == ROC_NIX_FC_CQ_CFG)
		return nix_fc_cq_config_get(roc_nix, fc_cfg);
	else if (fc_cfg->type == ROC_NIX_FC_RQ_CFG)
		return nix_fc_rq_config_get(roc_nix, fc_cfg);
	else if (fc_cfg->type == ROC_NIX_FC_RXCHAN_CFG)
		return nix_fc_rxchan_bpid_get(roc_nix, fc_cfg);
	else if (fc_cfg->type == ROC_NIX_FC_TM_CFG)
		return nix_tm_bp_config_get(roc_nix, &fc_cfg->tm_cfg.enable);

	return -EINVAL;
}

int
roc_nix_fc_config_set(struct roc_nix *roc_nix, struct roc_nix_fc_cfg *fc_cfg)
{
	if (fc_cfg->type == ROC_NIX_FC_CQ_CFG)
		return nix_fc_cq_config_set(roc_nix, fc_cfg);
	else if (fc_cfg->type == ROC_NIX_FC_RQ_CFG)
		return nix_fc_rq_config_set(roc_nix, fc_cfg);
	else if (fc_cfg->type == ROC_NIX_FC_RXCHAN_CFG)
		return nix_fc_rxchan_bpid_set(roc_nix,
					      fc_cfg->rxchan_cfg.enable);
	else if (fc_cfg->type == ROC_NIX_FC_TM_CFG)
		return nix_tm_bp_config_set(roc_nix, fc_cfg->tm_cfg.sq,
					    fc_cfg->tm_cfg.tc,
					    fc_cfg->tm_cfg.enable);

	return -EINVAL;
}

enum roc_nix_fc_mode
roc_nix_fc_mode_get(struct roc_nix *roc_nix)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	enum roc_nix_fc_mode mode;

	if (nix->tx_pause && nix->rx_pause)
		mode = ROC_NIX_FC_FULL;
	else if (nix->rx_pause)
		mode = ROC_NIX_FC_RX;
	else if (nix->tx_pause)
		mode = ROC_NIX_FC_TX;
	else
		mode = ROC_NIX_FC_NONE;
	return mode;
}

int
roc_nix_fc_mode_set(struct roc_nix *roc_nix, enum roc_nix_fc_mode mode)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct dev *dev = &nix->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	struct cgx_pause_frm_cfg *req;
	uint8_t tx_pause, rx_pause;
	int rc = -ENOSPC;

	rx_pause = (mode == ROC_NIX_FC_FULL) || (mode == ROC_NIX_FC_RX);
	tx_pause = (mode == ROC_NIX_FC_FULL) || (mode == ROC_NIX_FC_TX);

	/* Nothing much to do for LBK links */
	if (roc_nix_is_lbk(roc_nix)) {
		nix->rx_pause = rx_pause;
		nix->tx_pause = tx_pause;
		rc = 0;
		goto exit;
	}

	/* Set new config */
	req = mbox_alloc_msg_cgx_cfg_pause_frm(mbox);
	if (req == NULL)
		goto exit;
	req->set = 1;
	req->rx_pause = rx_pause;
	req->tx_pause = tx_pause;

	rc = mbox_process(mbox);
	if (rc)
		goto exit;

	nix->rx_pause = rx_pause;
	nix->tx_pause = tx_pause;
exit:
	mbox_put(mbox);
	return rc;
}

void
roc_nix_fc_npa_bp_cfg(struct roc_nix *roc_nix, uint64_t pool_id, uint8_t ena,
		      uint8_t force, uint8_t tc)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct npa_lf *lf = idev_npa_obj_get();
	struct npa_aq_enq_req *req;
	struct npa_aq_enq_rsp *rsp;
	struct mbox *mbox;
	uint32_t limit;
	uint64_t shift;
	int rc;

	if (roc_nix_is_sdp(roc_nix))
		return;

	if (!lf)
		return;
	mbox = mbox_get(lf->mbox);

	req = mbox_alloc_msg_npa_aq_enq(mbox);
	if (req == NULL)
		goto exit;

	req->aura_id = roc_npa_aura_handle_to_aura(pool_id);
	req->ctype = NPA_AQ_CTYPE_AURA;
	req->op = NPA_AQ_INSTOP_READ;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		goto exit;

	limit = rsp->aura.limit;
	shift = rsp->aura.shift;

	/* BP is already enabled. */
	if (rsp->aura.bp_ena && ena) {
		uint16_t bpid;
		bool nix1;

		nix1 = !!(rsp->aura.bp_ena & 0x2);
		if (nix1)
			bpid = rsp->aura.nix1_bpid;
		else
			bpid = rsp->aura.nix0_bpid;

		/* If BP ids don't match disable BP. */
		if (((nix1 != nix->is_nix1) || (bpid != nix->bpid[tc])) &&
		    !force) {
			req = mbox_alloc_msg_npa_aq_enq(mbox);
			if (req == NULL)
				goto exit;

			plt_info("Disabling BP/FC on aura 0x%" PRIx64
				 " as it shared across ports or tc",
				 pool_id);
			req->aura_id = roc_npa_aura_handle_to_aura(pool_id);
			req->ctype = NPA_AQ_CTYPE_AURA;
			req->op = NPA_AQ_INSTOP_WRITE;

			req->aura.bp_ena = 0;
			req->aura_mask.bp_ena = ~(req->aura_mask.bp_ena);

			mbox_process(mbox);
		}

		if ((nix1 != nix->is_nix1) || (bpid != nix->bpid[tc]))
			plt_info("Ignoring aura 0x%" PRIx64 "->%u bpid mapping",
				 pool_id, nix->bpid[tc]);
		goto exit;
	}

	/* BP was previously enabled but now disabled skip. */
	if (rsp->aura.bp && ena)
		goto exit;

	req = mbox_alloc_msg_npa_aq_enq(mbox);
	if (req == NULL)
		goto exit;

	req->aura_id = roc_npa_aura_handle_to_aura(pool_id);
	req->ctype = NPA_AQ_CTYPE_AURA;
	req->op = NPA_AQ_INSTOP_WRITE;

	if (ena) {
		if (nix->is_nix1) {
			req->aura.nix1_bpid = nix->bpid[tc];
			req->aura_mask.nix1_bpid = ~(req->aura_mask.nix1_bpid);
		} else {
			req->aura.nix0_bpid = nix->bpid[tc];
			req->aura_mask.nix0_bpid = ~(req->aura_mask.nix0_bpid);
		}
		req->aura.bp = NIX_RQ_AURA_THRESH(limit >> shift);
		req->aura_mask.bp = ~(req->aura_mask.bp);
	} else {
		req->aura.bp = 0;
		req->aura_mask.bp = ~(req->aura_mask.bp);
	}

	req->aura.bp_ena = (!!ena << nix->is_nix1);
	req->aura_mask.bp_ena = ~(req->aura_mask.bp_ena);

	mbox_process(mbox);
exit:
	mbox_put(mbox);
	return;
}

int
roc_nix_pfc_mode_set(struct roc_nix *roc_nix, struct roc_nix_pfc_cfg *pfc_cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct dev *dev = &nix->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	uint8_t tx_pause, rx_pause;
	struct cgx_pfc_cfg *req;
	struct cgx_pfc_rsp *rsp;
	int rc = -ENOSPC;

	if (roc_nix_is_lbk(roc_nix)) {
		rc =  NIX_ERR_OP_NOTSUP;
		goto exit;
	}

	rx_pause = (pfc_cfg->mode == ROC_NIX_FC_FULL) ||
		   (pfc_cfg->mode == ROC_NIX_FC_RX);
	tx_pause = (pfc_cfg->mode == ROC_NIX_FC_FULL) ||
		   (pfc_cfg->mode == ROC_NIX_FC_TX);

	req = mbox_alloc_msg_cgx_prio_flow_ctrl_cfg(mbox);
	if (req == NULL)
		goto exit;

	req->pfc_en = pfc_cfg->tc;
	req->rx_pause = rx_pause;
	req->tx_pause = tx_pause;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		goto exit;

	nix->pfc_rx_pause = rsp->rx_pause;
	nix->pfc_tx_pause = rsp->tx_pause;
	if (rsp->tx_pause)
		nix->cev |= BIT(pfc_cfg->tc);
	else
		nix->cev &= ~BIT(pfc_cfg->tc);

exit:
	mbox_put(mbox);
	return rc;
}

int
roc_nix_pfc_mode_get(struct roc_nix *roc_nix, struct roc_nix_pfc_cfg *pfc_cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);

	if (roc_nix_is_lbk(roc_nix))
		return NIX_ERR_OP_NOTSUP;

	pfc_cfg->tc = nix->cev;

	if (nix->pfc_rx_pause && nix->pfc_tx_pause)
		pfc_cfg->mode = ROC_NIX_FC_FULL;
	else if (nix->pfc_rx_pause)
		pfc_cfg->mode = ROC_NIX_FC_RX;
	else if (nix->pfc_tx_pause)
		pfc_cfg->mode = ROC_NIX_FC_TX;
	else
		pfc_cfg->mode = ROC_NIX_FC_NONE;

	return 0;
}

uint16_t
roc_nix_chan_count_get(struct roc_nix *roc_nix)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);

	return nix->chan_cnt;
}

/* Allocate BPID for requested type
 * Returns number of BPIDs allocated
 *	0 if no BPIDs available
 *	-ve value on error
 */
int
roc_nix_bpids_alloc(struct roc_nix *roc_nix, uint8_t type, uint8_t bp_cnt, uint16_t *bpids)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct mbox *mbox = mbox_get(nix->dev.mbox);
	struct nix_alloc_bpid_req *req;
	struct nix_bpids *rsp;
	int rc = -EINVAL;

	/* Use this api for unreserved interface types */
	if ((type < ROC_NIX_INTF_TYPE_RSVD) || (bp_cnt > ROC_NIX_MAX_BPID_CNT) || !bpids)
		goto exit;

	rc = -ENOSPC;
	req = mbox_alloc_msg_nix_alloc_bpids(mbox);
	if (req == NULL)
		goto exit;
	req->type = type;
	req->bpid_cnt = bp_cnt;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		goto exit;

	for (rc = 0; rc < rsp->bpid_cnt; rc++)
		bpids[rc] = rsp->bpids[rc];
exit:
	mbox_put(mbox);
	return rc;
}

int
roc_nix_bpids_free(struct roc_nix *roc_nix, uint8_t bp_cnt, uint16_t *bpids)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct mbox *mbox = mbox_get(nix->dev.mbox);
	struct nix_bpids *req;
	int rc = -EINVAL;

	/* Use this api for unreserved interface types */
	if ((bp_cnt > ROC_NIX_MAX_BPID_CNT) || !bpids)
		goto exit;

	rc = -ENOSPC;
	req = mbox_alloc_msg_nix_free_bpids(mbox);
	if (req == NULL)
		goto exit;
	for (rc = 0; rc < bp_cnt; rc++)
		req->bpids[rc] = bpids[rc];
	req->bpid_cnt = rc;

	rc = mbox_process(mbox);
exit:
	mbox_put(mbox);
	return rc;
}

int
roc_nix_rx_chan_cfg_get(struct roc_nix *roc_nix, uint16_t chan, bool is_cpt, uint64_t *cfg)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct mbox *mbox = mbox_get(nix->dev.mbox);
	struct nix_rx_chan_cfg *req;
	struct nix_rx_chan_cfg *rsp;
	int rc = -EINVAL;

	req = mbox_alloc_msg_nix_rx_chan_cfg(mbox);
	if (req == NULL)
		goto exit;
	if (is_cpt)
		req->type = ROC_NIX_INTF_TYPE_CPT;
	req->chan = chan;
	req->read = 1;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		goto exit;
	*cfg = rsp->val;
exit:
	mbox_put(mbox);
	return rc;
}

int
roc_nix_rx_chan_cfg_set(struct roc_nix *roc_nix, uint16_t chan, bool is_cpt, uint64_t val)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct mbox *mbox = mbox_get(nix->dev.mbox);
	struct nix_rx_chan_cfg *req;
	int rc = -EINVAL;

	req = mbox_alloc_msg_nix_rx_chan_cfg(mbox);
	if (req == NULL)
		goto exit;
	if (is_cpt)
		req->type = ROC_NIX_INTF_TYPE_CPT;
	req->chan = chan;
	req->val = val;
	req->read = 0;

	rc = mbox_process(mbox);
	if (rc)
		goto exit;
exit:
	mbox_put(mbox);
	return rc;
}

#define NIX_BPID1_ENA 15
#define NIX_BPID2_ENA 14
#define NIX_BPID3_ENA 13

#define NIX_BPID1_OFF 20
#define NIX_BPID2_OFF 32
#define NIX_BPID3_OFF 44

int
roc_nix_chan_bpid_set(struct roc_nix *roc_nix, uint16_t chan, uint64_t bpid, int ena, bool cpt_chan)
{
	uint64_t cfg;
	int rc;

	if (!roc_feature_nix_has_rxchan_multi_bpid())
		return -ENOTSUP;

	rc = roc_nix_rx_chan_cfg_get(roc_nix, chan, cpt_chan, &cfg);
	if (rc)
		return rc;

	if (ena) {
		if ((((cfg >> NIX_BPID1_OFF) & GENMASK_ULL(8, 0)) == bpid) ||
		    (((cfg >> NIX_BPID2_OFF) & GENMASK_ULL(8, 0)) == bpid) ||
		    (((cfg >> NIX_BPID3_OFF) & GENMASK_ULL(8, 0)) == bpid))
			return 0;

		if (!(cfg & BIT_ULL(NIX_BPID1_ENA))) {
			cfg &= ~GENMASK_ULL(NIX_BPID1_OFF + 8, NIX_BPID1_OFF);
			cfg |= (((uint64_t)bpid << NIX_BPID1_OFF) | BIT_ULL(NIX_BPID1_ENA));
		} else if (!(cfg & BIT_ULL(NIX_BPID2_ENA))) {
			cfg &= ~GENMASK_ULL(NIX_BPID2_OFF + 8, NIX_BPID2_OFF);
			cfg |= (((uint64_t)bpid << NIX_BPID2_OFF) | BIT_ULL(NIX_BPID2_ENA));
		} else if (!(cfg & BIT_ULL(NIX_BPID3_ENA))) {
			cfg &= ~GENMASK_ULL(NIX_BPID3_OFF + 8, NIX_BPID3_OFF);
			cfg |= (((uint64_t)bpid << NIX_BPID3_OFF) | BIT_ULL(NIX_BPID3_ENA));
		} else {
			plt_nix_dbg("Exceed maximum BPIDs");
			return -ENOSPC;
		}
	} else {
		if (((cfg >> NIX_BPID1_OFF) & GENMASK_ULL(8, 0)) == bpid) {
			cfg &= ~(GENMASK_ULL(NIX_BPID1_OFF + 8, NIX_BPID1_OFF) |
				 BIT_ULL(NIX_BPID1_ENA));
		} else if (((cfg >> NIX_BPID2_OFF) & GENMASK_ULL(8, 0)) == bpid) {
			cfg &= ~(GENMASK_ULL(NIX_BPID2_OFF + 8, NIX_BPID2_OFF) |
				 BIT_ULL(NIX_BPID2_ENA));
		} else if (((cfg >> NIX_BPID3_OFF) & GENMASK_ULL(8, 0)) == bpid) {
			cfg &= ~(GENMASK_ULL(NIX_BPID3_OFF + 8, NIX_BPID3_OFF) |
				 BIT_ULL(NIX_BPID3_ENA));
		} else {
			plt_nix_dbg("BPID not found");
			return -EINVAL;
		}
	}
	return roc_nix_rx_chan_cfg_set(roc_nix, chan, cpt_chan, cfg);
}
