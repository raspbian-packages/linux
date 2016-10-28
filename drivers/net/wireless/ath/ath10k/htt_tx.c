/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/etherdevice.h>
#include "htt.h"
#include "mac.h"
#include "hif.h"
#include "txrx.h"
#include "debug.h"

static u8 ath10k_htt_tx_txq_calc_size(size_t count)
{
	int exp;
	int factor;

	exp = 0;
	factor = count >> 7;

	while (factor >= 64 && exp < 4) {
		factor >>= 3;
		exp++;
	}

	if (exp == 4)
		return 0xff;

	if (count > 0)
		factor = max(1, factor);

	return SM(exp, HTT_TX_Q_STATE_ENTRY_EXP) |
	       SM(factor, HTT_TX_Q_STATE_ENTRY_FACTOR);
}

static void __ath10k_htt_tx_txq_recalc(struct ieee80211_hw *hw,
				       struct ieee80211_txq *txq)
{
	struct ath10k *ar = hw->priv;
	struct ath10k_sta *arsta;
	struct ath10k_vif *arvif = (void *)txq->vif->drv_priv;
	unsigned long frame_cnt;
	unsigned long byte_cnt;
	int idx;
	u32 bit;
	u16 peer_id;
	u8 tid;
	u8 count;

	lockdep_assert_held(&ar->htt.tx_lock);

	if (!ar->htt.tx_q_state.enabled)
		return;

	if (ar->htt.tx_q_state.mode != HTT_TX_MODE_SWITCH_PUSH_PULL)
		return;

	if (txq->sta) {
		arsta = (void *)txq->sta->drv_priv;
		peer_id = arsta->peer_id;
	} else {
		peer_id = arvif->peer_id;
	}

	tid = txq->tid;
	bit = BIT(peer_id % 32);
	idx = peer_id / 32;

	ieee80211_txq_get_depth(txq, &frame_cnt, &byte_cnt);
	count = ath10k_htt_tx_txq_calc_size(byte_cnt);

	if (unlikely(peer_id >= ar->htt.tx_q_state.num_peers) ||
	    unlikely(tid >= ar->htt.tx_q_state.num_tids)) {
		ath10k_warn(ar, "refusing to update txq for peer_id %hu tid %hhu due to out of bounds\n",
			    peer_id, tid);
		return;
	}

	ar->htt.tx_q_state.vaddr->count[tid][peer_id] = count;
	ar->htt.tx_q_state.vaddr->map[tid][idx] &= ~bit;
	ar->htt.tx_q_state.vaddr->map[tid][idx] |= count ? bit : 0;

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx txq state update peer_id %hu tid %hhu count %hhu\n",
		   peer_id, tid, count);
}

static void __ath10k_htt_tx_txq_sync(struct ath10k *ar)
{
	u32 seq;
	size_t size;

	lockdep_assert_held(&ar->htt.tx_lock);

	if (!ar->htt.tx_q_state.enabled)
		return;

	if (ar->htt.tx_q_state.mode != HTT_TX_MODE_SWITCH_PUSH_PULL)
		return;

	seq = le32_to_cpu(ar->htt.tx_q_state.vaddr->seq);
	seq++;
	ar->htt.tx_q_state.vaddr->seq = cpu_to_le32(seq);

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx txq state update commit seq %u\n",
		   seq);

	size = sizeof(*ar->htt.tx_q_state.vaddr);
	dma_sync_single_for_device(ar->dev,
				   ar->htt.tx_q_state.paddr,
				   size,
				   DMA_TO_DEVICE);
}

void ath10k_htt_tx_txq_recalc(struct ieee80211_hw *hw,
			      struct ieee80211_txq *txq)
{
	struct ath10k *ar = hw->priv;

	spin_lock_bh(&ar->htt.tx_lock);
	__ath10k_htt_tx_txq_recalc(hw, txq);
	spin_unlock_bh(&ar->htt.tx_lock);
}

void ath10k_htt_tx_txq_sync(struct ath10k *ar)
{
	spin_lock_bh(&ar->htt.tx_lock);
	__ath10k_htt_tx_txq_sync(ar);
	spin_unlock_bh(&ar->htt.tx_lock);
}

void ath10k_htt_tx_txq_update(struct ieee80211_hw *hw,
			      struct ieee80211_txq *txq)
{
	struct ath10k *ar = hw->priv;

	spin_lock_bh(&ar->htt.tx_lock);
	__ath10k_htt_tx_txq_recalc(hw, txq);
	__ath10k_htt_tx_txq_sync(ar);
	spin_unlock_bh(&ar->htt.tx_lock);
}

void ath10k_htt_tx_dec_pending(struct ath10k_htt *htt)
{
	lockdep_assert_held(&htt->tx_lock);

	htt->num_pending_tx--;
	if (htt->num_pending_tx == htt->max_num_pending_tx - 1)
		ath10k_mac_tx_unlock(htt->ar, ATH10K_TX_PAUSE_Q_FULL);
}

int ath10k_htt_tx_inc_pending(struct ath10k_htt *htt)
{
	lockdep_assert_held(&htt->tx_lock);

	if (htt->num_pending_tx >= htt->max_num_pending_tx)
		return -EBUSY;

	htt->num_pending_tx++;
	if (htt->num_pending_tx == htt->max_num_pending_tx)
		ath10k_mac_tx_lock(htt->ar, ATH10K_TX_PAUSE_Q_FULL);

	return 0;
}

int ath10k_htt_tx_mgmt_inc_pending(struct ath10k_htt *htt, bool is_mgmt,
				   bool is_presp)
{
	struct ath10k *ar = htt->ar;

	lockdep_assert_held(&htt->tx_lock);

	if (!is_mgmt || !ar->hw_params.max_probe_resp_desc_thres)
		return 0;

	if (is_presp &&
	    ar->hw_params.max_probe_resp_desc_thres < htt->num_pending_mgmt_tx)
		return -EBUSY;

	htt->num_pending_mgmt_tx++;

	return 0;
}

void ath10k_htt_tx_mgmt_dec_pending(struct ath10k_htt *htt)
{
	lockdep_assert_held(&htt->tx_lock);

	if (!htt->ar->hw_params.max_probe_resp_desc_thres)
		return;

	htt->num_pending_mgmt_tx--;
}

int ath10k_htt_tx_alloc_msdu_id(struct ath10k_htt *htt, struct sk_buff *skb)
{
	struct ath10k *ar = htt->ar;
	int ret;

	lockdep_assert_held(&htt->tx_lock);

	ret = idr_alloc(&htt->pending_tx, skb, 0,
			htt->max_num_pending_tx, GFP_ATOMIC);

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx alloc msdu_id %d\n", ret);

	return ret;
}

void ath10k_htt_tx_free_msdu_id(struct ath10k_htt *htt, u16 msdu_id)
{
	struct ath10k *ar = htt->ar;

	lockdep_assert_held(&htt->tx_lock);

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx free msdu_id %hu\n", msdu_id);

	idr_remove(&htt->pending_tx, msdu_id);
}

static void ath10k_htt_tx_free_cont_frag_desc(struct ath10k_htt *htt)
{
	size_t size;

	if (!htt->frag_desc.vaddr)
		return;

	size = htt->max_num_pending_tx * sizeof(struct htt_msdu_ext_desc);

	dma_free_coherent(htt->ar->dev,
			  size,
			  htt->frag_desc.vaddr,
			  htt->frag_desc.paddr);
}

static int ath10k_htt_tx_alloc_cont_frag_desc(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	size_t size;

	if (!ar->hw_params.continuous_frag_desc)
		return 0;

	size = htt->max_num_pending_tx * sizeof(struct htt_msdu_ext_desc);
	htt->frag_desc.vaddr = dma_alloc_coherent(ar->dev, size,
						  &htt->frag_desc.paddr,
						  GFP_KERNEL);
	if (!htt->frag_desc.vaddr) {
		ath10k_err(ar, "failed to alloc fragment desc memory\n");
		return -ENOMEM;
	}

	return 0;
}

static void ath10k_htt_tx_free_txq(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	size_t size;

	if (!test_bit(ATH10K_FW_FEATURE_PEER_FLOW_CONTROL,
		      ar->running_fw->fw_file.fw_features))
		return;

	size = sizeof(*htt->tx_q_state.vaddr);

	dma_unmap_single(ar->dev, htt->tx_q_state.paddr, size, DMA_TO_DEVICE);
	kfree(htt->tx_q_state.vaddr);
}

static int ath10k_htt_tx_alloc_txq(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	size_t size;
	int ret;

	if (!test_bit(ATH10K_FW_FEATURE_PEER_FLOW_CONTROL,
		      ar->running_fw->fw_file.fw_features))
		return 0;

	htt->tx_q_state.num_peers = HTT_TX_Q_STATE_NUM_PEERS;
	htt->tx_q_state.num_tids = HTT_TX_Q_STATE_NUM_TIDS;
	htt->tx_q_state.type = HTT_Q_DEPTH_TYPE_BYTES;

	size = sizeof(*htt->tx_q_state.vaddr);
	htt->tx_q_state.vaddr = kzalloc(size, GFP_KERNEL);
	if (!htt->tx_q_state.vaddr)
		return -ENOMEM;

	htt->tx_q_state.paddr = dma_map_single(ar->dev, htt->tx_q_state.vaddr,
					       size, DMA_TO_DEVICE);
	ret = dma_mapping_error(ar->dev, htt->tx_q_state.paddr);
	if (ret) {
		ath10k_warn(ar, "failed to dma map tx_q_state: %d\n", ret);
		kfree(htt->tx_q_state.vaddr);
		return -EIO;
	}

	return 0;
}

int ath10k_htt_tx_alloc(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	int ret, size;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "htt tx max num pending tx %d\n",
		   htt->max_num_pending_tx);

	spin_lock_init(&htt->tx_lock);
	idr_init(&htt->pending_tx);

	size = htt->max_num_pending_tx * sizeof(struct ath10k_htt_txbuf);
	htt->txbuf.vaddr = dma_alloc_coherent(ar->dev, size,
						  &htt->txbuf.paddr,
						  GFP_KERNEL);
	if (!htt->txbuf.vaddr) {
		ath10k_err(ar, "failed to alloc tx buffer\n");
		ret = -ENOMEM;
		goto free_idr_pending_tx;
	}

	ret = ath10k_htt_tx_alloc_cont_frag_desc(htt);
	if (ret) {
		ath10k_err(ar, "failed to alloc cont frag desc: %d\n", ret);
		goto free_txbuf;
	}

	ret = ath10k_htt_tx_alloc_txq(htt);
	if (ret) {
		ath10k_err(ar, "failed to alloc txq: %d\n", ret);
		goto free_frag_desc;
	}

	size = roundup_pow_of_two(htt->max_num_pending_tx);
	ret = kfifo_alloc(&htt->txdone_fifo, size, GFP_KERNEL);
	if (ret) {
		ath10k_err(ar, "failed to alloc txdone fifo: %d\n", ret);
		goto free_txq;
	}

	return 0;

free_txq:
	ath10k_htt_tx_free_txq(htt);

free_frag_desc:
	ath10k_htt_tx_free_cont_frag_desc(htt);

free_txbuf:
	size = htt->max_num_pending_tx *
			  sizeof(struct ath10k_htt_txbuf);
	dma_free_coherent(htt->ar->dev, size, htt->txbuf.vaddr,
			  htt->txbuf.paddr);

free_idr_pending_tx:
	idr_destroy(&htt->pending_tx);

	return ret;
}

static int ath10k_htt_tx_clean_up_pending(int msdu_id, void *skb, void *ctx)
{
	struct ath10k *ar = ctx;
	struct ath10k_htt *htt = &ar->htt;
	struct htt_tx_done tx_done = {0};

	ath10k_dbg(ar, ATH10K_DBG_HTT, "force cleanup msdu_id %hu\n", msdu_id);

	tx_done.msdu_id = msdu_id;
	tx_done.status = HTT_TX_COMPL_STATE_DISCARD;

	ath10k_txrx_tx_unref(htt, &tx_done);

	return 0;
}

void ath10k_htt_tx_free(struct ath10k_htt *htt)
{
	int size;

	tasklet_kill(&htt->txrx_compl_task);

	idr_for_each(&htt->pending_tx, ath10k_htt_tx_clean_up_pending, htt->ar);
	idr_destroy(&htt->pending_tx);

	if (htt->txbuf.vaddr) {
		size = htt->max_num_pending_tx *
				  sizeof(struct ath10k_htt_txbuf);
		dma_free_coherent(htt->ar->dev, size, htt->txbuf.vaddr,
				  htt->txbuf.paddr);
	}

	ath10k_htt_tx_free_txq(htt);
	ath10k_htt_tx_free_cont_frag_desc(htt);
	WARN_ON(!kfifo_is_empty(&htt->txdone_fifo));
	kfifo_free(&htt->txdone_fifo);
}

void ath10k_htt_htc_tx_complete(struct ath10k *ar, struct sk_buff *skb)
{
	dev_kfree_skb_any(skb);
}

void ath10k_htt_hif_tx_complete(struct ath10k *ar, struct sk_buff *skb)
{
	dev_kfree_skb_any(skb);
}
EXPORT_SYMBOL(ath10k_htt_hif_tx_complete);

int ath10k_htt_h2t_ver_req_msg(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	int len = 0;
	int ret;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->ver_req);

	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, len);
	cmd = (struct htt_cmd *)skb->data;
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_VERSION_REQ;

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_h2t_stats_req(struct ath10k_htt *htt, u8 mask, u64 cookie)
{
	struct ath10k *ar = htt->ar;
	struct htt_stats_req *req;
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	int len = 0, ret;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->stats_req);

	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, len);
	cmd = (struct htt_cmd *)skb->data;
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_STATS_REQ;

	req = &cmd->stats_req;

	memset(req, 0, sizeof(*req));

	/* currently we support only max 8 bit masks so no need to worry
	 * about endian support */
	req->upload_types[0] = mask;
	req->reset_types[0] = mask;
	req->stat_type = HTT_STATS_REQ_CFG_STAT_TYPE_INVALID;
	req->cookie_lsb = cpu_to_le32(cookie & 0xffffffff);
	req->cookie_msb = cpu_to_le32((cookie & 0xffffffff00000000ULL) >> 32);

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		ath10k_warn(ar, "failed to send htt type stats request: %d",
			    ret);
		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_send_frag_desc_bank_cfg(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	struct htt_frag_desc_bank_cfg *cfg;
	int ret, size;
	u8 info;

	if (!ar->hw_params.continuous_frag_desc)
		return 0;

	if (!htt->frag_desc.paddr) {
		ath10k_warn(ar, "invalid frag desc memory\n");
		return -EINVAL;
	}

	size = sizeof(cmd->hdr) + sizeof(cmd->frag_desc_bank_cfg);
	skb = ath10k_htc_alloc_skb(ar, size);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, size);
	cmd = (struct htt_cmd *)skb->data;
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_FRAG_DESC_BANK_CFG;

	info = 0;
	info |= SM(htt->tx_q_state.type,
		   HTT_FRAG_DESC_BANK_CFG_INFO_Q_STATE_DEPTH_TYPE);

	if (test_bit(ATH10K_FW_FEATURE_PEER_FLOW_CONTROL,
		     ar->running_fw->fw_file.fw_features))
		info |= HTT_FRAG_DESC_BANK_CFG_INFO_Q_STATE_VALID;

	cfg = &cmd->frag_desc_bank_cfg;
	cfg->info = info;
	cfg->num_banks = 1;
	cfg->desc_size = sizeof(struct htt_msdu_ext_desc);
	cfg->bank_base_addrs[0] = __cpu_to_le32(htt->frag_desc.paddr);
	cfg->bank_id[0].bank_min_id = 0;
	cfg->bank_id[0].bank_max_id = __cpu_to_le16(htt->max_num_pending_tx -
						    1);

	cfg->q_state.paddr = cpu_to_le32(htt->tx_q_state.paddr);
	cfg->q_state.num_peers = cpu_to_le16(htt->tx_q_state.num_peers);
	cfg->q_state.num_tids = cpu_to_le16(htt->tx_q_state.num_tids);
	cfg->q_state.record_size = HTT_TX_Q_STATE_ENTRY_SIZE;
	cfg->q_state.record_multiplier = HTT_TX_Q_STATE_ENTRY_MULTIPLIER;

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt frag desc bank cmd\n");

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		ath10k_warn(ar, "failed to send frag desc bank cfg request: %d\n",
			    ret);
		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_send_rx_ring_cfg_ll(struct ath10k_htt *htt)
{
	struct ath10k *ar = htt->ar;
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	struct htt_rx_ring_setup_ring *ring;
	const int num_rx_ring = 1;
	u16 flags;
	u32 fw_idx;
	int len;
	int ret;

	/*
	 * the HW expects the buffer to be an integral number of 4-byte
	 * "words"
	 */
	BUILD_BUG_ON(!IS_ALIGNED(HTT_RX_BUF_SIZE, 4));
	BUILD_BUG_ON((HTT_RX_BUF_SIZE & HTT_MAX_CACHE_LINE_SIZE_MASK) != 0);

	len = sizeof(cmd->hdr) + sizeof(cmd->rx_setup.hdr)
	    + (sizeof(*ring) * num_rx_ring);
	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, len);

	cmd = (struct htt_cmd *)skb->data;
	ring = &cmd->rx_setup.rings[0];

	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_RX_RING_CFG;
	cmd->rx_setup.hdr.num_rings = 1;

	/* FIXME: do we need all of this? */
	flags = 0;
	flags |= HTT_RX_RING_FLAGS_MAC80211_HDR;
	flags |= HTT_RX_RING_FLAGS_MSDU_PAYLOAD;
	flags |= HTT_RX_RING_FLAGS_PPDU_START;
	flags |= HTT_RX_RING_FLAGS_PPDU_END;
	flags |= HTT_RX_RING_FLAGS_MPDU_START;
	flags |= HTT_RX_RING_FLAGS_MPDU_END;
	flags |= HTT_RX_RING_FLAGS_MSDU_START;
	flags |= HTT_RX_RING_FLAGS_MSDU_END;
	flags |= HTT_RX_RING_FLAGS_RX_ATTENTION;
	flags |= HTT_RX_RING_FLAGS_FRAG_INFO;
	flags |= HTT_RX_RING_FLAGS_UNICAST_RX;
	flags |= HTT_RX_RING_FLAGS_MULTICAST_RX;
	flags |= HTT_RX_RING_FLAGS_CTRL_RX;
	flags |= HTT_RX_RING_FLAGS_MGMT_RX;
	flags |= HTT_RX_RING_FLAGS_NULL_RX;
	flags |= HTT_RX_RING_FLAGS_PHY_DATA_RX;

	fw_idx = __le32_to_cpu(*htt->rx_ring.alloc_idx.vaddr);

	ring->fw_idx_shadow_reg_paddr =
		__cpu_to_le32(htt->rx_ring.alloc_idx.paddr);
	ring->rx_ring_base_paddr = __cpu_to_le32(htt->rx_ring.base_paddr);
	ring->rx_ring_len = __cpu_to_le16(htt->rx_ring.size);
	ring->rx_ring_bufsize = __cpu_to_le16(HTT_RX_BUF_SIZE);
	ring->flags = __cpu_to_le16(flags);
	ring->fw_idx_init_val = __cpu_to_le16(fw_idx);

#define desc_offset(x) (offsetof(struct htt_rx_desc, x) / 4)

	ring->mac80211_hdr_offset = __cpu_to_le16(desc_offset(rx_hdr_status));
	ring->msdu_payload_offset = __cpu_to_le16(desc_offset(msdu_payload));
	ring->ppdu_start_offset = __cpu_to_le16(desc_offset(ppdu_start));
	ring->ppdu_end_offset = __cpu_to_le16(desc_offset(ppdu_end));
	ring->mpdu_start_offset = __cpu_to_le16(desc_offset(mpdu_start));
	ring->mpdu_end_offset = __cpu_to_le16(desc_offset(mpdu_end));
	ring->msdu_start_offset = __cpu_to_le16(desc_offset(msdu_start));
	ring->msdu_end_offset = __cpu_to_le16(desc_offset(msdu_end));
	ring->rx_attention_offset = __cpu_to_le16(desc_offset(attention));
	ring->frag_info_offset = __cpu_to_le16(desc_offset(frag_info));

#undef desc_offset

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_h2t_aggr_cfg_msg(struct ath10k_htt *htt,
				u8 max_subfrms_ampdu,
				u8 max_subfrms_amsdu)
{
	struct ath10k *ar = htt->ar;
	struct htt_aggr_conf *aggr_conf;
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	int len;
	int ret;

	/* Firmware defaults are: amsdu = 3 and ampdu = 64 */

	if (max_subfrms_ampdu == 0 || max_subfrms_ampdu > 64)
		return -EINVAL;

	if (max_subfrms_amsdu == 0 || max_subfrms_amsdu > 31)
		return -EINVAL;

	len = sizeof(cmd->hdr);
	len += sizeof(cmd->aggr_conf);

	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, len);
	cmd = (struct htt_cmd *)skb->data;
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_AGGR_CFG;

	aggr_conf = &cmd->aggr_conf;
	aggr_conf->max_num_ampdu_subframes = max_subfrms_ampdu;
	aggr_conf->max_num_amsdu_subframes = max_subfrms_amsdu;

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt h2t aggr cfg msg amsdu %d ampdu %d",
		   aggr_conf->max_num_amsdu_subframes,
		   aggr_conf->max_num_ampdu_subframes);

	ret = ath10k_htc_send(&htt->ar->htc, htt->eid, skb);
	if (ret) {
		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_tx_fetch_resp(struct ath10k *ar,
			     __le32 token,
			     __le16 fetch_seq_num,
			     struct htt_tx_fetch_record *records,
			     size_t num_records)
{
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	const u16 resp_id = 0;
	int len = 0;
	int ret;

	/* Response IDs are echo-ed back only for host driver convienence
	 * purposes. They aren't used for anything in the driver yet so use 0.
	 */

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->tx_fetch_resp);
	len += sizeof(cmd->tx_fetch_resp.records[0]) * num_records;

	skb = ath10k_htc_alloc_skb(ar, len);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, len);
	cmd = (struct htt_cmd *)skb->data;
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_TX_FETCH_RESP;
	cmd->tx_fetch_resp.resp_id = cpu_to_le16(resp_id);
	cmd->tx_fetch_resp.fetch_seq_num = fetch_seq_num;
	cmd->tx_fetch_resp.num_records = cpu_to_le16(num_records);
	cmd->tx_fetch_resp.token = token;

	memcpy(cmd->tx_fetch_resp.records, records,
	       sizeof(records[0]) * num_records);

	ret = ath10k_htc_send(&ar->htc, ar->htt.eid, skb);
	if (ret) {
		ath10k_warn(ar, "failed to submit htc command: %d\n", ret);
		goto err_free_skb;
	}

	return 0;

err_free_skb:
	dev_kfree_skb_any(skb);

	return ret;
}

static u8 ath10k_htt_tx_get_vdev_id(struct ath10k *ar, struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ath10k_skb_cb *cb = ATH10K_SKB_CB(skb);
	struct ath10k_vif *arvif;

	if (info->flags & IEEE80211_TX_CTL_TX_OFFCHAN) {
		return ar->scan.vdev_id;
	} else if (cb->vif) {
		arvif = (void *)cb->vif->drv_priv;
		return arvif->vdev_id;
	} else if (ar->monitor_started) {
		return ar->monitor_vdev_id;
	} else {
		return 0;
	}
}

static u8 ath10k_htt_tx_get_tid(struct sk_buff *skb, bool is_eth)
{
	struct ieee80211_hdr *hdr = (void *)skb->data;
	struct ath10k_skb_cb *cb = ATH10K_SKB_CB(skb);

	if (!is_eth && ieee80211_is_mgmt(hdr->frame_control))
		return HTT_DATA_TX_EXT_TID_MGMT;
	else if (cb->flags & ATH10K_SKB_F_QOS)
		return skb->priority % IEEE80211_QOS_CTL_TID_MASK;
	else
		return HTT_DATA_TX_EXT_TID_NON_QOS_MCAST_BCAST;
}

int ath10k_htt_mgmt_tx(struct ath10k_htt *htt, struct sk_buff *msdu)
{
	struct ath10k *ar = htt->ar;
	struct device *dev = ar->dev;
	struct sk_buff *txdesc = NULL;
	struct htt_cmd *cmd;
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(msdu);
	u8 vdev_id = ath10k_htt_tx_get_vdev_id(ar, msdu);
	int len = 0;
	int msdu_id = -1;
	int res;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)msdu->data;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->mgmt_tx);

	spin_lock_bh(&htt->tx_lock);
	res = ath10k_htt_tx_alloc_msdu_id(htt, msdu);
	spin_unlock_bh(&htt->tx_lock);
	if (res < 0)
		goto err;

	msdu_id = res;

	if ((ieee80211_is_action(hdr->frame_control) ||
	     ieee80211_is_deauth(hdr->frame_control) ||
	     ieee80211_is_disassoc(hdr->frame_control)) &&
	     ieee80211_has_protected(hdr->frame_control)) {
		skb_put(msdu, IEEE80211_CCMP_MIC_LEN);
	}

	txdesc = ath10k_htc_alloc_skb(ar, len);
	if (!txdesc) {
		res = -ENOMEM;
		goto err_free_msdu_id;
	}

	skb_cb->paddr = dma_map_single(dev, msdu->data, msdu->len,
				       DMA_TO_DEVICE);
	res = dma_mapping_error(dev, skb_cb->paddr);
	if (res) {
		res = -EIO;
		goto err_free_txdesc;
	}

	skb_put(txdesc, len);
	cmd = (struct htt_cmd *)txdesc->data;
	memset(cmd, 0, len);

	cmd->hdr.msg_type         = HTT_H2T_MSG_TYPE_MGMT_TX;
	cmd->mgmt_tx.msdu_paddr = __cpu_to_le32(ATH10K_SKB_CB(msdu)->paddr);
	cmd->mgmt_tx.len        = __cpu_to_le32(msdu->len);
	cmd->mgmt_tx.desc_id    = __cpu_to_le32(msdu_id);
	cmd->mgmt_tx.vdev_id    = __cpu_to_le32(vdev_id);
	memcpy(cmd->mgmt_tx.hdr, msdu->data,
	       min_t(int, msdu->len, HTT_MGMT_FRM_HDR_DOWNLOAD_LEN));

	res = ath10k_htc_send(&htt->ar->htc, htt->eid, txdesc);
	if (res)
		goto err_unmap_msdu;

	return 0;

err_unmap_msdu:
	dma_unmap_single(dev, skb_cb->paddr, msdu->len, DMA_TO_DEVICE);
err_free_txdesc:
	dev_kfree_skb_any(txdesc);
err_free_msdu_id:
	spin_lock_bh(&htt->tx_lock);
	ath10k_htt_tx_free_msdu_id(htt, msdu_id);
	spin_unlock_bh(&htt->tx_lock);
err:
	return res;
}

int ath10k_htt_tx(struct ath10k_htt *htt, enum ath10k_hw_txrx_mode txmode,
		  struct sk_buff *msdu)
{
	struct ath10k *ar = htt->ar;
	struct device *dev = ar->dev;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)msdu->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(msdu);
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(msdu);
	struct ath10k_hif_sg_item sg_items[2];
	struct ath10k_htt_txbuf *txbuf;
	struct htt_data_tx_desc_frag *frags;
	bool is_eth = (txmode == ATH10K_HW_TXRX_ETHERNET);
	u8 vdev_id = ath10k_htt_tx_get_vdev_id(ar, msdu);
	u8 tid = ath10k_htt_tx_get_tid(msdu, is_eth);
	int prefetch_len;
	int res;
	u8 flags0 = 0;
	u16 msdu_id, flags1 = 0;
	u16 freq = 0;
	u32 frags_paddr = 0;
	u32 txbuf_paddr;
	struct htt_msdu_ext_desc *ext_desc = NULL;

	spin_lock_bh(&htt->tx_lock);
	res = ath10k_htt_tx_alloc_msdu_id(htt, msdu);
	spin_unlock_bh(&htt->tx_lock);
	if (res < 0)
		goto err;

	msdu_id = res;

	prefetch_len = min(htt->prefetch_len, msdu->len);
	prefetch_len = roundup(prefetch_len, 4);

	txbuf = &htt->txbuf.vaddr[msdu_id];
	txbuf_paddr = htt->txbuf.paddr +
		      (sizeof(struct ath10k_htt_txbuf) * msdu_id);

	if ((ieee80211_is_action(hdr->frame_control) ||
	     ieee80211_is_deauth(hdr->frame_control) ||
	     ieee80211_is_disassoc(hdr->frame_control)) &&
	     ieee80211_has_protected(hdr->frame_control)) {
		skb_put(msdu, IEEE80211_CCMP_MIC_LEN);
	} else if (!(skb_cb->flags & ATH10K_SKB_F_NO_HWCRYPT) &&
		   txmode == ATH10K_HW_TXRX_RAW &&
		   ieee80211_has_protected(hdr->frame_control)) {
		skb_put(msdu, IEEE80211_CCMP_MIC_LEN);
	}

	skb_cb->paddr = dma_map_single(dev, msdu->data, msdu->len,
				       DMA_TO_DEVICE);
	res = dma_mapping_error(dev, skb_cb->paddr);
	if (res) {
		res = -EIO;
		goto err_free_msdu_id;
	}

	if (unlikely(info->flags & IEEE80211_TX_CTL_TX_OFFCHAN))
		freq = ar->scan.roc_freq;

	switch (txmode) {
	case ATH10K_HW_TXRX_RAW:
	case ATH10K_HW_TXRX_NATIVE_WIFI:
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_MAC_HDR_PRESENT;
		/* pass through */
	case ATH10K_HW_TXRX_ETHERNET:
		if (ar->hw_params.continuous_frag_desc) {
			memset(&htt->frag_desc.vaddr[msdu_id], 0,
			       sizeof(struct htt_msdu_ext_desc));
			frags = (struct htt_data_tx_desc_frag *)
				&htt->frag_desc.vaddr[msdu_id].frags;
			ext_desc = &htt->frag_desc.vaddr[msdu_id];
			frags[0].tword_addr.paddr_lo =
				__cpu_to_le32(skb_cb->paddr);
			frags[0].tword_addr.paddr_hi = 0;
			frags[0].tword_addr.len_16 = __cpu_to_le16(msdu->len);

			frags_paddr =  htt->frag_desc.paddr +
				(sizeof(struct htt_msdu_ext_desc) * msdu_id);
		} else {
			frags = txbuf->frags;
			frags[0].dword_addr.paddr =
				__cpu_to_le32(skb_cb->paddr);
			frags[0].dword_addr.len = __cpu_to_le32(msdu->len);
			frags[1].dword_addr.paddr = 0;
			frags[1].dword_addr.len = 0;

			frags_paddr = txbuf_paddr;
		}
		flags0 |= SM(txmode, HTT_DATA_TX_DESC_FLAGS0_PKT_TYPE);
		break;
	case ATH10K_HW_TXRX_MGMT:
		flags0 |= SM(ATH10K_HW_TXRX_MGMT,
			     HTT_DATA_TX_DESC_FLAGS0_PKT_TYPE);
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_MAC_HDR_PRESENT;

		frags_paddr = skb_cb->paddr;
		break;
	}

	/* Normally all commands go through HTC which manages tx credits for
	 * each endpoint and notifies when tx is completed.
	 *
	 * HTT endpoint is creditless so there's no need to care about HTC
	 * flags. In that case it is trivial to fill the HTC header here.
	 *
	 * MSDU transmission is considered completed upon HTT event. This
	 * implies no relevant resources can be freed until after the event is
	 * received. That's why HTC tx completion handler itself is ignored by
	 * setting NULL to transfer_context for all sg items.
	 *
	 * There is simply no point in pushing HTT TX_FRM through HTC tx path
	 * as it's a waste of resources. By bypassing HTC it is possible to
	 * avoid extra memory allocations, compress data structures and thus
	 * improve performance. */

	txbuf->htc_hdr.eid = htt->eid;
	txbuf->htc_hdr.len = __cpu_to_le16(sizeof(txbuf->cmd_hdr) +
					   sizeof(txbuf->cmd_tx) +
					   prefetch_len);
	txbuf->htc_hdr.flags = 0;

	if (skb_cb->flags & ATH10K_SKB_F_NO_HWCRYPT)
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_NO_ENCRYPT;

	flags1 |= SM((u16)vdev_id, HTT_DATA_TX_DESC_FLAGS1_VDEV_ID);
	flags1 |= SM((u16)tid, HTT_DATA_TX_DESC_FLAGS1_EXT_TID);
	if (msdu->ip_summed == CHECKSUM_PARTIAL &&
	    !test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
		flags1 |= HTT_DATA_TX_DESC_FLAGS1_CKSUM_L3_OFFLOAD;
		flags1 |= HTT_DATA_TX_DESC_FLAGS1_CKSUM_L4_OFFLOAD;
		if (ar->hw_params.continuous_frag_desc)
			ext_desc->flags |= HTT_MSDU_CHECKSUM_ENABLE;
	}

	/* Prevent firmware from sending up tx inspection requests. There's
	 * nothing ath10k can do with frames requested for inspection so force
	 * it to simply rely a regular tx completion with discard status.
	 */
	flags1 |= HTT_DATA_TX_DESC_FLAGS1_POSTPONED;

	txbuf->cmd_hdr.msg_type = HTT_H2T_MSG_TYPE_TX_FRM;
	txbuf->cmd_tx.flags0 = flags0;
	txbuf->cmd_tx.flags1 = __cpu_to_le16(flags1);
	txbuf->cmd_tx.len = __cpu_to_le16(msdu->len);
	txbuf->cmd_tx.id = __cpu_to_le16(msdu_id);
	txbuf->cmd_tx.frags_paddr = __cpu_to_le32(frags_paddr);
	if (ath10k_mac_tx_frm_has_freq(ar)) {
		txbuf->cmd_tx.offchan_tx.peerid =
				__cpu_to_le16(HTT_INVALID_PEERID);
		txbuf->cmd_tx.offchan_tx.freq =
				__cpu_to_le16(freq);
	} else {
		txbuf->cmd_tx.peerid =
				__cpu_to_le32(HTT_INVALID_PEERID);
	}

	trace_ath10k_htt_tx(ar, msdu_id, msdu->len, vdev_id, tid);
	ath10k_dbg(ar, ATH10K_DBG_HTT,
		   "htt tx flags0 %hhu flags1 %hu len %d id %hu frags_paddr %08x, msdu_paddr %08x vdev %hhu tid %hhu freq %hu\n",
		   flags0, flags1, msdu->len, msdu_id, frags_paddr,
		   (u32)skb_cb->paddr, vdev_id, tid, freq);
	ath10k_dbg_dump(ar, ATH10K_DBG_HTT_DUMP, NULL, "htt tx msdu: ",
			msdu->data, msdu->len);
	trace_ath10k_tx_hdr(ar, msdu->data, msdu->len);
	trace_ath10k_tx_payload(ar, msdu->data, msdu->len);

	sg_items[0].transfer_id = 0;
	sg_items[0].transfer_context = NULL;
	sg_items[0].vaddr = &txbuf->htc_hdr;
	sg_items[0].paddr = txbuf_paddr +
			    sizeof(txbuf->frags);
	sg_items[0].len = sizeof(txbuf->htc_hdr) +
			  sizeof(txbuf->cmd_hdr) +
			  sizeof(txbuf->cmd_tx);

	sg_items[1].transfer_id = 0;
	sg_items[1].transfer_context = NULL;
	sg_items[1].vaddr = msdu->data;
	sg_items[1].paddr = skb_cb->paddr;
	sg_items[1].len = prefetch_len;

	res = ath10k_hif_tx_sg(htt->ar,
			       htt->ar->htc.endpoint[htt->eid].ul_pipe_id,
			       sg_items, ARRAY_SIZE(sg_items));
	if (res)
		goto err_unmap_msdu;

	return 0;

err_unmap_msdu:
	dma_unmap_single(dev, skb_cb->paddr, msdu->len, DMA_TO_DEVICE);
err_free_msdu_id:
	ath10k_htt_tx_free_msdu_id(htt, msdu_id);
err:
	return res;
}
