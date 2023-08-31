// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2019-2020  Realtek Corporation
 */

#include "coex.h"
#include "debug.h"
#include "fw.h"
#include "mac.h"
#include "phy.h"
#include "ps.h"
#include "reg.h"
#include "sar.h"
#include "util.h"

static u16 get_max_amsdu_len(struct rtw89_dev *rtwdev,
			     const struct rtw89_ra_report *report)
{
	u32 bit_rate = report->bit_rate;

	/* lower than ofdm, do not aggregate */
	if (bit_rate < 550)
		return 1;

	/* avoid AMSDU for legacy rate */
	if (report->might_fallback_legacy)
		return 1;

	/* lower than 20M vht 2ss mcs8, make it small */
	if (bit_rate < 1800)
		return 1200;

	/* lower than 40M vht 2ss mcs9, make it medium */
	if (bit_rate < 4000)
		return 2600;

	/* not yet 80M vht 2ss mcs8/9, make it twice regular packet size */
	if (bit_rate < 7000)
		return 3500;

	return rtwdev->chip->max_amsdu_limit;
}

static u64 get_mcs_ra_mask(u16 mcs_map, u8 highest_mcs, u8 gap)
{
	u64 ra_mask = 0;
	u8 mcs_cap;
	int i, nss;

	for (i = 0, nss = 12; i < 4; i++, mcs_map >>= 2, nss += 12) {
		mcs_cap = mcs_map & 0x3;
		switch (mcs_cap) {
		case 2:
			ra_mask |= GENMASK_ULL(highest_mcs, 0) << nss;
			break;
		case 1:
			ra_mask |= GENMASK_ULL(highest_mcs - gap, 0) << nss;
			break;
		case 0:
			ra_mask |= GENMASK_ULL(highest_mcs - gap * 2, 0) << nss;
			break;
		default:
			break;
		}
	}

	return ra_mask;
}

static u64 get_he_ra_mask(struct ieee80211_sta *sta)
{
	struct ieee80211_sta_he_cap cap = sta->deflink.he_cap;
	u16 mcs_map;

	switch (sta->deflink.bandwidth) {
	case IEEE80211_STA_RX_BW_160:
		if (cap.he_cap_elem.phy_cap_info[0] &
		    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G)
			mcs_map = le16_to_cpu(cap.he_mcs_nss_supp.rx_mcs_80p80);
		else
			mcs_map = le16_to_cpu(cap.he_mcs_nss_supp.rx_mcs_160);
		break;
	default:
		mcs_map = le16_to_cpu(cap.he_mcs_nss_supp.rx_mcs_80);
	}

	/* MCS11, MCS9, MCS7 */
	return get_mcs_ra_mask(mcs_map, 11, 2);
}

#define RA_FLOOR_TABLE_SIZE	7
#define RA_FLOOR_UP_GAP		3
static u64 rtw89_phy_ra_mask_rssi(struct rtw89_dev *rtwdev, u8 rssi,
				  u8 ratr_state)
{
	u8 rssi_lv_t[RA_FLOOR_TABLE_SIZE] = {30, 44, 48, 52, 56, 60, 100};
	u8 rssi_lv = 0;
	u8 i;

	rssi >>= 1;
	for (i = 0; i < RA_FLOOR_TABLE_SIZE; i++) {
		if (i >= ratr_state)
			rssi_lv_t[i] += RA_FLOOR_UP_GAP;
		if (rssi < rssi_lv_t[i]) {
			rssi_lv = i;
			break;
		}
	}
	if (rssi_lv == 0)
		return 0xffffffffffffffffULL;
	else if (rssi_lv == 1)
		return 0xfffffffffffffff0ULL;
	else if (rssi_lv == 2)
		return 0xffffffffffffefe0ULL;
	else if (rssi_lv == 3)
		return 0xffffffffffffcfc0ULL;
	else if (rssi_lv == 4)
		return 0xffffffffffff8f80ULL;
	else if (rssi_lv >= 5)
		return 0xffffffffffff0f00ULL;

	return 0xffffffffffffffffULL;
}

static u64 rtw89_phy_ra_mask_recover(u64 ra_mask, u64 ra_mask_bak)
{
	if ((ra_mask & ~(RA_MASK_CCK_RATES | RA_MASK_OFDM_RATES)) == 0)
		ra_mask |= (ra_mask_bak & ~(RA_MASK_CCK_RATES | RA_MASK_OFDM_RATES));

	if (ra_mask == 0)
		ra_mask |= (ra_mask_bak & (RA_MASK_CCK_RATES | RA_MASK_OFDM_RATES));

	return ra_mask;
}

static u64 rtw89_phy_ra_mask_cfg(struct rtw89_dev *rtwdev, struct rtw89_sta *rtwsta)
{
	struct ieee80211_sta *sta = rtwsta_to_sta(rtwsta);
	const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_SUB_ENTITY_0);
	struct cfg80211_bitrate_mask *mask = &rtwsta->mask;
	enum nl80211_band band;
	u64 cfg_mask;

	if (!rtwsta->use_cfg_mask)
		return -1;

	switch (chan->band_type) {
	case RTW89_BAND_2G:
		band = NL80211_BAND_2GHZ;
		cfg_mask = u64_encode_bits(mask->control[NL80211_BAND_2GHZ].legacy,
					   RA_MASK_CCK_RATES | RA_MASK_OFDM_RATES);
		break;
	case RTW89_BAND_5G:
		band = NL80211_BAND_5GHZ;
		cfg_mask = u64_encode_bits(mask->control[NL80211_BAND_5GHZ].legacy,
					   RA_MASK_OFDM_RATES);
		break;
	case RTW89_BAND_6G:
		band = NL80211_BAND_6GHZ;
		cfg_mask = u64_encode_bits(mask->control[NL80211_BAND_6GHZ].legacy,
					   RA_MASK_OFDM_RATES);
		break;
	default:
		rtw89_warn(rtwdev, "unhandled band type %d\n", chan->band_type);
		return -1;
	}

	if (sta->deflink.he_cap.has_he) {
		cfg_mask |= u64_encode_bits(mask->control[band].he_mcs[0],
					    RA_MASK_HE_1SS_RATES);
		cfg_mask |= u64_encode_bits(mask->control[band].he_mcs[1],
					    RA_MASK_HE_2SS_RATES);
	} else if (sta->deflink.vht_cap.vht_supported) {
		cfg_mask |= u64_encode_bits(mask->control[band].vht_mcs[0],
					    RA_MASK_VHT_1SS_RATES);
		cfg_mask |= u64_encode_bits(mask->control[band].vht_mcs[1],
					    RA_MASK_VHT_2SS_RATES);
	} else if (sta->deflink.ht_cap.ht_supported) {
		cfg_mask |= u64_encode_bits(mask->control[band].ht_mcs[0],
					    RA_MASK_HT_1SS_RATES);
		cfg_mask |= u64_encode_bits(mask->control[band].ht_mcs[1],
					    RA_MASK_HT_2SS_RATES);
	}

	return cfg_mask;
}

static const u64
rtw89_ra_mask_ht_rates[4] = {RA_MASK_HT_1SS_RATES, RA_MASK_HT_2SS_RATES,
			     RA_MASK_HT_3SS_RATES, RA_MASK_HT_4SS_RATES};
static const u64
rtw89_ra_mask_vht_rates[4] = {RA_MASK_VHT_1SS_RATES, RA_MASK_VHT_2SS_RATES,
			      RA_MASK_VHT_3SS_RATES, RA_MASK_VHT_4SS_RATES};
static const u64
rtw89_ra_mask_he_rates[4] = {RA_MASK_HE_1SS_RATES, RA_MASK_HE_2SS_RATES,
			     RA_MASK_HE_3SS_RATES, RA_MASK_HE_4SS_RATES};

static void rtw89_phy_ra_gi_ltf(struct rtw89_dev *rtwdev,
				struct rtw89_sta *rtwsta,
				bool *fix_giltf_en, u8 *fix_giltf)
{
	const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_SUB_ENTITY_0);
	struct cfg80211_bitrate_mask *mask = &rtwsta->mask;
	u8 band = chan->band_type;
	enum nl80211_band nl_band = rtw89_hw_to_nl80211_band(band);
	u8 he_gi = mask->control[nl_band].he_gi;
	u8 he_ltf = mask->control[nl_band].he_ltf;

	if (!rtwsta->use_cfg_mask)
		return;

	if (he_ltf == 2 && he_gi == 2) {
		*fix_giltf = RTW89_GILTF_LGI_4XHE32;
	} else if (he_ltf == 2 && he_gi == 0) {
		*fix_giltf = RTW89_GILTF_SGI_4XHE08;
	} else if (he_ltf == 1 && he_gi == 1) {
		*fix_giltf = RTW89_GILTF_2XHE16;
	} else if (he_ltf == 1 && he_gi == 0) {
		*fix_giltf = RTW89_GILTF_2XHE08;
	} else if (he_ltf == 0 && he_gi == 1) {
		*fix_giltf = RTW89_GILTF_1XHE16;
	} else if (he_ltf == 0 && he_gi == 0) {
		*fix_giltf = RTW89_GILTF_1XHE08;
	} else {
		*fix_giltf_en = false;
		return;
	}

	*fix_giltf_en = true;
}

static void rtw89_phy_ra_sta_update(struct rtw89_dev *rtwdev,
				    struct ieee80211_sta *sta, bool csi)
{
	struct rtw89_sta *rtwsta = (struct rtw89_sta *)sta->drv_priv;
	struct rtw89_vif *rtwvif = rtwsta->rtwvif;
	struct rtw89_phy_rate_pattern *rate_pattern = &rtwvif->rate_pattern;
	struct rtw89_ra_info *ra = &rtwsta->ra;
	const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_SUB_ENTITY_0);
	struct ieee80211_vif *vif = rtwvif_to_vif(rtwsta->rtwvif);
	const u64 *high_rate_masks = rtw89_ra_mask_ht_rates;
	u8 rssi = ewma_rssi_read(&rtwsta->avg_rssi);
	u64 ra_mask = 0;
	u64 ra_mask_bak;
	u8 mode = 0;
	u8 csi_mode = RTW89_RA_RPT_MODE_LEGACY;
	u8 bw_mode = 0;
	u8 stbc_en = 0;
	u8 ldpc_en = 0;
	u8 fix_giltf = 0;
	u8 i;
	bool sgi = false;
	bool fix_giltf_en = false;

	memset(ra, 0, sizeof(*ra));
	/* Set the ra mask from sta's capability */
	if (sta->deflink.he_cap.has_he) {
		mode |= RTW89_RA_MODE_HE;
		csi_mode = RTW89_RA_RPT_MODE_HE;
		ra_mask |= get_he_ra_mask(sta);
		high_rate_masks = rtw89_ra_mask_he_rates;
		if (sta->deflink.he_cap.he_cap_elem.phy_cap_info[2] &
		    IEEE80211_HE_PHY_CAP2_STBC_RX_UNDER_80MHZ)
			stbc_en = 1;
		if (sta->deflink.he_cap.he_cap_elem.phy_cap_info[1] &
		    IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD)
			ldpc_en = 1;
		rtw89_phy_ra_gi_ltf(rtwdev, rtwsta, &fix_giltf_en, &fix_giltf);
	} else if (sta->deflink.vht_cap.vht_supported) {
		u16 mcs_map = le16_to_cpu(sta->deflink.vht_cap.vht_mcs.rx_mcs_map);

		mode |= RTW89_RA_MODE_VHT;
		csi_mode = RTW89_RA_RPT_MODE_VHT;
		/* MCS9, MCS8, MCS7 */
		ra_mask |= get_mcs_ra_mask(mcs_map, 9, 1);
		high_rate_masks = rtw89_ra_mask_vht_rates;
		if (sta->deflink.vht_cap.cap & IEEE80211_VHT_CAP_RXSTBC_MASK)
			stbc_en = 1;
		if (sta->deflink.vht_cap.cap & IEEE80211_VHT_CAP_RXLDPC)
			ldpc_en = 1;
	} else if (sta->deflink.ht_cap.ht_supported) {
		mode |= RTW89_RA_MODE_HT;
		csi_mode = RTW89_RA_RPT_MODE_HT;
		ra_mask |= ((u64)sta->deflink.ht_cap.mcs.rx_mask[3] << 48) |
			   ((u64)sta->deflink.ht_cap.mcs.rx_mask[2] << 36) |
			   (sta->deflink.ht_cap.mcs.rx_mask[1] << 24) |
			   (sta->deflink.ht_cap.mcs.rx_mask[0] << 12);
		high_rate_masks = rtw89_ra_mask_ht_rates;
		if (sta->deflink.ht_cap.cap & IEEE80211_HT_CAP_RX_STBC)
			stbc_en = 1;
		if (sta->deflink.ht_cap.cap & IEEE80211_HT_CAP_LDPC_CODING)
			ldpc_en = 1;
	}

	switch (chan->band_type) {
	case RTW89_BAND_2G:
		ra_mask |= sta->deflink.supp_rates[NL80211_BAND_2GHZ];
		if (sta->deflink.supp_rates[NL80211_BAND_2GHZ] & 0xf)
			mode |= RTW89_RA_MODE_CCK;
		if (sta->deflink.supp_rates[NL80211_BAND_2GHZ] & 0xff0)
			mode |= RTW89_RA_MODE_OFDM;
		break;
	case RTW89_BAND_5G:
		ra_mask |= (u64)sta->deflink.supp_rates[NL80211_BAND_5GHZ] << 4;
		mode |= RTW89_RA_MODE_OFDM;
		break;
	case RTW89_BAND_6G:
		ra_mask |= (u64)sta->deflink.supp_rates[NL80211_BAND_6GHZ] << 4;
		mode |= RTW89_RA_MODE_OFDM;
		break;
	default:
		rtw89_err(rtwdev, "Unknown band type\n");
		break;
	}

	ra_mask_bak = ra_mask;

	if (mode >= RTW89_RA_MODE_HT) {
		u64 mask = 0;
		for (i = 0; i < rtwdev->hal.tx_nss; i++)
			mask |= high_rate_masks[i];
		if (mode & RTW89_RA_MODE_OFDM)
			mask |= RA_MASK_SUBOFDM_RATES;
		if (mode & RTW89_RA_MODE_CCK)
			mask |= RA_MASK_SUBCCK_RATES;
		ra_mask &= mask;
	} else if (mode & RTW89_RA_MODE_OFDM) {
		ra_mask &= (RA_MASK_OFDM_RATES | RA_MASK_SUBCCK_RATES);
	}

	if (mode != RTW89_RA_MODE_CCK)
		ra_mask &= rtw89_phy_ra_mask_rssi(rtwdev, rssi, 0);

	ra_mask = rtw89_phy_ra_mask_recover(ra_mask, ra_mask_bak);
	ra_mask &= rtw89_phy_ra_mask_cfg(rtwdev, rtwsta);

	switch (sta->deflink.bandwidth) {
	case IEEE80211_STA_RX_BW_160:
		bw_mode = RTW89_CHANNEL_WIDTH_160;
		sgi = sta->deflink.vht_cap.vht_supported &&
		      (sta->deflink.vht_cap.cap & IEEE80211_VHT_CAP_SHORT_GI_160);
		break;
	case IEEE80211_STA_RX_BW_80:
		bw_mode = RTW89_CHANNEL_WIDTH_80;
		sgi = sta->deflink.vht_cap.vht_supported &&
		      (sta->deflink.vht_cap.cap & IEEE80211_VHT_CAP_SHORT_GI_80);
		break;
	case IEEE80211_STA_RX_BW_40:
		bw_mode = RTW89_CHANNEL_WIDTH_40;
		sgi = sta->deflink.ht_cap.ht_supported &&
		      (sta->deflink.ht_cap.cap & IEEE80211_HT_CAP_SGI_40);
		break;
	default:
		bw_mode = RTW89_CHANNEL_WIDTH_20;
		sgi = sta->deflink.ht_cap.ht_supported &&
		      (sta->deflink.ht_cap.cap & IEEE80211_HT_CAP_SGI_20);
		break;
	}

	if (sta->deflink.he_cap.he_cap_elem.phy_cap_info[3] &
	    IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_RX_16_QAM)
		ra->dcm_cap = 1;

	if (rate_pattern->enable && !vif->p2p) {
		ra_mask = rtw89_phy_ra_mask_cfg(rtwdev, rtwsta);
		ra_mask &= rate_pattern->ra_mask;
		mode = rate_pattern->ra_mode;
	}

	ra->bw_cap = bw_mode;
	ra->er_cap = rtwsta->er_cap;
	ra->mode_ctrl = mode;
	ra->macid = rtwsta->mac_id;
	ra->stbc_cap = stbc_en;
	ra->ldpc_cap = ldpc_en;
	ra->ss_num = min(sta->deflink.rx_nss, rtwdev->hal.tx_nss) - 1;
	ra->en_sgi = sgi;
	ra->ra_mask = ra_mask;
	ra->fix_giltf_en = fix_giltf_en;
	ra->fix_giltf = fix_giltf;

	if (!csi)
		return;

	ra->fixed_csi_rate_en = false;
	ra->ra_csi_rate_en = true;
	ra->cr_tbl_sel = false;
	ra->band_num = rtwvif->phy_idx;
	ra->csi_bw = bw_mode;
	ra->csi_gi_ltf = RTW89_GILTF_LGI_4XHE32;
	ra->csi_mcs_ss_idx = 5;
	ra->csi_mode = csi_mode;
}

void rtw89_phy_ra_updata_sta(struct rtw89_dev *rtwdev, struct ieee80211_sta *sta,
			     u32 changed)
{
	struct rtw89_sta *rtwsta = (struct rtw89_sta *)sta->drv_priv;
	struct rtw89_ra_info *ra = &rtwsta->ra;

	rtw89_phy_ra_sta_update(rtwdev, sta, false);

	if (changed & IEEE80211_RC_SUPP_RATES_CHANGED)
		ra->upd_mask = 1;
	if (changed & (IEEE80211_RC_BW_CHANGED | IEEE80211_RC_NSS_CHANGED))
		ra->upd_bw_nss_mask = 1;

	rtw89_debug(rtwdev, RTW89_DBG_RA,
		    "ra updat: macid = %d, bw = %d, nss = %d, gi = %d %d",
		    ra->macid,
		    ra->bw_cap,
		    ra->ss_num,
		    ra->en_sgi,
		    ra->giltf);

	rtw89_fw_h2c_ra(rtwdev, ra, false);
}

static bool __check_rate_pattern(struct rtw89_phy_rate_pattern *next,
				 u16 rate_base, u64 ra_mask, u8 ra_mode,
				 u32 rate_ctrl, u32 ctrl_skip, bool force)
{
	u8 n, c;

	if (rate_ctrl == ctrl_skip)
		return true;

	n = hweight32(rate_ctrl);
	if (n == 0)
		return true;

	if (force && n != 1)
		return false;

	if (next->enable)
		return false;

	c = __fls(rate_ctrl);
	next->rate = rate_base + c;
	next->ra_mode = ra_mode;
	next->ra_mask = ra_mask;
	next->enable = true;

	return true;
}

void rtw89_phy_rate_pattern_vif(struct rtw89_dev *rtwdev,
				struct ieee80211_vif *vif,
				const struct cfg80211_bitrate_mask *mask)
{
	struct ieee80211_supported_band *sband;
	struct rtw89_vif *rtwvif = (struct rtw89_vif *)vif->drv_priv;
	struct rtw89_phy_rate_pattern next_pattern = {0};
	const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_SUB_ENTITY_0);
	static const u16 hw_rate_he[] = {RTW89_HW_RATE_HE_NSS1_MCS0,
					 RTW89_HW_RATE_HE_NSS2_MCS0,
					 RTW89_HW_RATE_HE_NSS3_MCS0,
					 RTW89_HW_RATE_HE_NSS4_MCS0};
	static const u16 hw_rate_vht[] = {RTW89_HW_RATE_VHT_NSS1_MCS0,
					  RTW89_HW_RATE_VHT_NSS2_MCS0,
					  RTW89_HW_RATE_VHT_NSS3_MCS0,
					  RTW89_HW_RATE_VHT_NSS4_MCS0};
	static const u16 hw_rate_ht[] = {RTW89_HW_RATE_MCS0,
					 RTW89_HW_RATE_MCS8,
					 RTW89_HW_RATE_MCS16,
					 RTW89_HW_RATE_MCS24};
	u8 band = chan->band_type;
	enum nl80211_band nl_band = rtw89_hw_to_nl80211_band(band);
	u8 tx_nss = rtwdev->hal.tx_nss;
	u8 i;

	for (i = 0; i < tx_nss; i++)
		if (!__check_rate_pattern(&next_pattern, hw_rate_he[i],
					  RA_MASK_HE_RATES, RTW89_RA_MODE_HE,
					  mask->control[nl_band].he_mcs[i],
					  0, true))
			goto out;

	for (i = 0; i < tx_nss; i++)
		if (!__check_rate_pattern(&next_pattern, hw_rate_vht[i],
					  RA_MASK_VHT_RATES, RTW89_RA_MODE_VHT,
					  mask->control[nl_band].vht_mcs[i],
					  0, true))
			goto out;

	for (i = 0; i < tx_nss; i++)
		if (!__check_rate_pattern(&next_pattern, hw_rate_ht[i],
					  RA_MASK_HT_RATES, RTW89_RA_MODE_HT,
					  mask->control[nl_band].ht_mcs[i],
					  0, true))
			goto out;

	/* lagacy cannot be empty for nl80211_parse_tx_bitrate_mask, and
	 * require at least one basic rate for ieee80211_set_bitrate_mask,
	 * so the decision just depends on if all bitrates are set or not.
	 */
	sband = rtwdev->hw->wiphy->bands[nl_band];
	if (band == RTW89_BAND_2G) {
		if (!__check_rate_pattern(&next_pattern, RTW89_HW_RATE_CCK1,
					  RA_MASK_CCK_RATES | RA_MASK_OFDM_RATES,
					  RTW89_RA_MODE_CCK | RTW89_RA_MODE_OFDM,
					  mask->control[nl_band].legacy,
					  BIT(sband->n_bitrates) - 1, false))
			goto out;
	} else {
		if (!__check_rate_pattern(&next_pattern, RTW89_HW_RATE_OFDM6,
					  RA_MASK_OFDM_RATES, RTW89_RA_MODE_OFDM,
					  mask->control[nl_band].legacy,
					  BIT(sband->n_bitrates) - 1, false))
			goto out;
	}

	if (!next_pattern.enable)
		goto out;

	rtwvif->rate_pattern = next_pattern;
	rtw89_debug(rtwdev, RTW89_DBG_RA,
		    "configure pattern: rate 0x%x, mask 0x%llx, mode 0x%x\n",
		    next_pattern.rate,
		    next_pattern.ra_mask,
		    next_pattern.ra_mode);
	return;

out:
	rtwvif->rate_pattern.enable = false;
	rtw89_debug(rtwdev, RTW89_DBG_RA, "unset rate pattern\n");
}

static void rtw89_phy_ra_updata_sta_iter(void *data, struct ieee80211_sta *sta)
{
	struct rtw89_dev *rtwdev = (struct rtw89_dev *)data;

	rtw89_phy_ra_updata_sta(rtwdev, sta, IEEE80211_RC_SUPP_RATES_CHANGED);
}

void rtw89_phy_ra_update(struct rtw89_dev *rtwdev)
{
	ieee80211_iterate_stations_atomic(rtwdev->hw,
					  rtw89_phy_ra_updata_sta_iter,
					  rtwdev);
}

void rtw89_phy_ra_assoc(struct rtw89_dev *rtwdev, struct ieee80211_sta *sta)
{
	struct rtw89_sta *rtwsta = (struct rtw89_sta *)sta->drv_priv;
	struct rtw89_ra_info *ra = &rtwsta->ra;
	u8 rssi = ewma_rssi_read(&rtwsta->avg_rssi) >> RSSI_FACTOR;
	bool csi = rtw89_sta_has_beamformer_cap(sta);

	rtw89_phy_ra_sta_update(rtwdev, sta, csi);

	if (rssi > 40)
		ra->init_rate_lv = 1;
	else if (rssi > 20)
		ra->init_rate_lv = 2;
	else if (rssi > 1)
		ra->init_rate_lv = 3;
	else
		ra->init_rate_lv = 0;
	ra->upd_all = 1;
	rtw89_debug(rtwdev, RTW89_DBG_RA,
		    "ra assoc: macid = %d, mode = %d, bw = %d, nss = %d, lv = %d",
		    ra->macid,
		    ra->mode_ctrl,
		    ra->bw_cap,
		    ra->ss_num,
		    ra->init_rate_lv);
	rtw89_debug(rtwdev, RTW89_DBG_RA,
		    "ra assoc: dcm = %d, er = %d, ldpc = %d, stbc = %d, gi = %d %d",
		    ra->dcm_cap,
		    ra->er_cap,
		    ra->ldpc_cap,
		    ra->stbc_cap,
		    ra->en_sgi,
		    ra->giltf);

	rtw89_fw_h2c_ra(rtwdev, ra, csi);
}

u8 rtw89_phy_get_txsc(struct rtw89_dev *rtwdev,
		      const struct rtw89_chan *chan,
		      enum rtw89_bandwidth dbw)
{
	enum rtw89_bandwidth cbw = chan->band_width;
	u8 pri_ch = chan->primary_channel;
	u8 central_ch = chan->channel;
	u8 txsc_idx = 0;
	u8 tmp = 0;

	if (cbw == dbw || cbw == RTW89_CHANNEL_WIDTH_20)
		return txsc_idx;

	switch (cbw) {
	case RTW89_CHANNEL_WIDTH_40:
		txsc_idx = pri_ch > central_ch ? 1 : 2;
		break;
	case RTW89_CHANNEL_WIDTH_80:
		if (dbw == RTW89_CHANNEL_WIDTH_20) {
			if (pri_ch > central_ch)
				txsc_idx = (pri_ch - central_ch) >> 1;
			else
				txsc_idx = ((central_ch - pri_ch) >> 1) + 1;
		} else {
			txsc_idx = pri_ch > central_ch ? 9 : 10;
		}
		break;
	case RTW89_CHANNEL_WIDTH_160:
		if (pri_ch > central_ch)
			tmp = (pri_ch - central_ch) >> 1;
		else
			tmp = ((central_ch - pri_ch) >> 1) + 1;

		if (dbw == RTW89_CHANNEL_WIDTH_20) {
			txsc_idx = tmp;
		} else if (dbw == RTW89_CHANNEL_WIDTH_40) {
			if (tmp == 1 || tmp == 3)
				txsc_idx = 9;
			else if (tmp == 5 || tmp == 7)
				txsc_idx = 11;
			else if (tmp == 2 || tmp == 4)
				txsc_idx = 10;
			else if (tmp == 6 || tmp == 8)
				txsc_idx = 12;
			else
				return 0xff;
		} else {
			txsc_idx = pri_ch > central_ch ? 13 : 14;
		}
		break;
	case RTW89_CHANNEL_WIDTH_80_80:
		if (dbw == RTW89_CHANNEL_WIDTH_20) {
			if (pri_ch > central_ch)
				txsc_idx = (10 - (pri_ch - central_ch)) >> 1;
			else
				txsc_idx = ((central_ch - pri_ch) >> 1) + 5;
		} else if (dbw == RTW89_CHANNEL_WIDTH_40) {
			txsc_idx = pri_ch > central_ch ? 10 : 12;
		} else {
			txsc_idx = 14;
		}
		break;
	default:
		break;
	}

	return txsc_idx;
}
EXPORT_SYMBOL(rtw89_phy_get_txsc);

static bool rtw89_phy_check_swsi_busy(struct rtw89_dev *rtwdev)
{
	return !!rtw89_phy_read32_mask(rtwdev, R_SWSI_V1, B_SWSI_W_BUSY_V1) ||
	       !!rtw89_phy_read32_mask(rtwdev, R_SWSI_V1, B_SWSI_R_BUSY_V1);
}

u32 rtw89_phy_read_rf(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path,
		      u32 addr, u32 mask)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const u32 *base_addr = chip->rf_base_addr;
	u32 val, direct_addr;

	if (rf_path >= rtwdev->chip->rf_path_num) {
		rtw89_err(rtwdev, "unsupported rf path (%d)\n", rf_path);
		return INV_RF_DATA;
	}

	addr &= 0xff;
	direct_addr = base_addr[rf_path] + (addr << 2);
	mask &= RFREG_MASK;

	val = rtw89_phy_read32_mask(rtwdev, direct_addr, mask);

	return val;
}
EXPORT_SYMBOL(rtw89_phy_read_rf);

static u32 rtw89_phy_read_rf_a(struct rtw89_dev *rtwdev,
			       enum rtw89_rf_path rf_path, u32 addr, u32 mask)
{
	bool busy;
	bool done;
	u32 val;
	int ret;

	ret = read_poll_timeout_atomic(rtw89_phy_check_swsi_busy, busy, !busy,
				       1, 30, false, rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "read rf busy swsi\n");
		return INV_RF_DATA;
	}

	mask &= RFREG_MASK;

	val = FIELD_PREP(B_SWSI_READ_ADDR_PATH_V1, rf_path) |
	      FIELD_PREP(B_SWSI_READ_ADDR_ADDR_V1, addr);
	rtw89_phy_write32_mask(rtwdev, R_SWSI_READ_ADDR_V1, B_SWSI_READ_ADDR_V1, val);
	udelay(2);

	ret = read_poll_timeout_atomic(rtw89_phy_read32_mask, done, done, 1,
				       30, false, rtwdev, R_SWSI_V1,
				       B_SWSI_R_DATA_DONE_V1);
	if (ret) {
		rtw89_err(rtwdev, "read swsi busy\n");
		return INV_RF_DATA;
	}

	return rtw89_phy_read32_mask(rtwdev, R_SWSI_V1, mask);
}

u32 rtw89_phy_read_rf_v1(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path,
			 u32 addr, u32 mask)
{
	bool ad_sel = FIELD_GET(RTW89_RF_ADDR_ADSEL_MASK, addr);

	if (rf_path >= rtwdev->chip->rf_path_num) {
		rtw89_err(rtwdev, "unsupported rf path (%d)\n", rf_path);
		return INV_RF_DATA;
	}

	if (ad_sel)
		return rtw89_phy_read_rf(rtwdev, rf_path, addr, mask);
	else
		return rtw89_phy_read_rf_a(rtwdev, rf_path, addr, mask);
}
EXPORT_SYMBOL(rtw89_phy_read_rf_v1);

bool rtw89_phy_write_rf(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path,
			u32 addr, u32 mask, u32 data)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const u32 *base_addr = chip->rf_base_addr;
	u32 direct_addr;

	if (rf_path >= rtwdev->chip->rf_path_num) {
		rtw89_err(rtwdev, "unsupported rf path (%d)\n", rf_path);
		return false;
	}

	addr &= 0xff;
	direct_addr = base_addr[rf_path] + (addr << 2);
	mask &= RFREG_MASK;

	rtw89_phy_write32_mask(rtwdev, direct_addr, mask, data);

	/* delay to ensure writing properly */
	udelay(1);

	return true;
}
EXPORT_SYMBOL(rtw89_phy_write_rf);

static bool rtw89_phy_write_rf_a(struct rtw89_dev *rtwdev,
				 enum rtw89_rf_path rf_path, u32 addr, u32 mask,
				 u32 data)
{
	u8 bit_shift;
	u32 val;
	bool busy, b_msk_en = false;
	int ret;

	ret = read_poll_timeout_atomic(rtw89_phy_check_swsi_busy, busy, !busy,
				       1, 30, false, rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "write rf busy swsi\n");
		return false;
	}

	data &= RFREG_MASK;
	mask &= RFREG_MASK;

	if (mask != RFREG_MASK) {
		b_msk_en = true;
		rtw89_phy_write32_mask(rtwdev, R_SWSI_BIT_MASK_V1, RFREG_MASK,
				       mask);
		bit_shift = __ffs(mask);
		data = (data << bit_shift) & RFREG_MASK;
	}

	val = FIELD_PREP(B_SWSI_DATA_BIT_MASK_EN_V1, b_msk_en) |
	      FIELD_PREP(B_SWSI_DATA_PATH_V1, rf_path) |
	      FIELD_PREP(B_SWSI_DATA_ADDR_V1, addr) |
	      FIELD_PREP(B_SWSI_DATA_VAL_V1, data);

	rtw89_phy_write32_mask(rtwdev, R_SWSI_DATA_V1, MASKDWORD, val);

	return true;
}

bool rtw89_phy_write_rf_v1(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path,
			   u32 addr, u32 mask, u32 data)
{
	bool ad_sel = FIELD_GET(RTW89_RF_ADDR_ADSEL_MASK, addr);

	if (rf_path >= rtwdev->chip->rf_path_num) {
		rtw89_err(rtwdev, "unsupported rf path (%d)\n", rf_path);
		return false;
	}

	if (ad_sel)
		return rtw89_phy_write_rf(rtwdev, rf_path, addr, mask, data);
	else
		return rtw89_phy_write_rf_a(rtwdev, rf_path, addr, mask, data);
}
EXPORT_SYMBOL(rtw89_phy_write_rf_v1);

static bool rtw89_chip_rf_v1(struct rtw89_dev *rtwdev)
{
	return rtwdev->chip->ops->write_rf == rtw89_phy_write_rf_v1;
}

static void rtw89_phy_bb_reset(struct rtw89_dev *rtwdev,
			       enum rtw89_phy_idx phy_idx)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;

	chip->ops->bb_reset(rtwdev, phy_idx);
}

static void rtw89_phy_config_bb_reg(struct rtw89_dev *rtwdev,
				    const struct rtw89_reg2_def *reg,
				    enum rtw89_rf_path rf_path,
				    void *extra_data)
{
	if (reg->addr == 0xfe)
		mdelay(50);
	else if (reg->addr == 0xfd)
		mdelay(5);
	else if (reg->addr == 0xfc)
		mdelay(1);
	else if (reg->addr == 0xfb)
		udelay(50);
	else if (reg->addr == 0xfa)
		udelay(5);
	else if (reg->addr == 0xf9)
		udelay(1);
	else
		rtw89_phy_write32(rtwdev, reg->addr, reg->data);
}

union rtw89_phy_bb_gain_arg {
	u32 addr;
	struct {
		union {
			u8 type;
			struct {
				u8 rxsc_start:4;
				u8 bw:4;
			};
		};
		u8 path;
		u8 gain_band;
		u8 cfg_type;
	};
} __packed;

static void
rtw89_phy_cfg_bb_gain_error(struct rtw89_dev *rtwdev,
			    union rtw89_phy_bb_gain_arg arg, u32 data)
{
	struct rtw89_phy_bb_gain_info *gain = &rtwdev->bb_gain;
	u8 type = arg.type;
	u8 path = arg.path;
	u8 gband = arg.gain_band;
	int i;

	switch (type) {
	case 0:
		for (i = 0; i < 4; i++, data >>= 8)
			gain->lna_gain[gband][path][i] = data & 0xff;
		break;
	case 1:
		for (i = 4; i < 7; i++, data >>= 8)
			gain->lna_gain[gband][path][i] = data & 0xff;
		break;
	case 2:
		for (i = 0; i < 2; i++, data >>= 8)
			gain->tia_gain[gband][path][i] = data & 0xff;
		break;
	default:
		rtw89_warn(rtwdev,
			   "bb gain error {0x%x:0x%x} with unknown type: %d\n",
			   arg.addr, data, type);
		break;
	}
}

enum rtw89_phy_bb_rxsc_start_idx {
	RTW89_BB_RXSC_START_IDX_FULL = 0,
	RTW89_BB_RXSC_START_IDX_20 = 1,
	RTW89_BB_RXSC_START_IDX_20_1 = 5,
	RTW89_BB_RXSC_START_IDX_40 = 9,
	RTW89_BB_RXSC_START_IDX_80 = 13,
};

static void
rtw89_phy_cfg_bb_rpl_ofst(struct rtw89_dev *rtwdev,
			  union rtw89_phy_bb_gain_arg arg, u32 data)
{
	struct rtw89_phy_bb_gain_info *gain = &rtwdev->bb_gain;
	u8 rxsc_start = arg.rxsc_start;
	u8 bw = arg.bw;
	u8 path = arg.path;
	u8 gband = arg.gain_band;
	u8 rxsc;
	s8 ofst;
	int i;

	switch (bw) {
	case RTW89_CHANNEL_WIDTH_20:
		gain->rpl_ofst_20[gband][path] = (s8)data;
		break;
	case RTW89_CHANNEL_WIDTH_40:
		if (rxsc_start == RTW89_BB_RXSC_START_IDX_FULL) {
			gain->rpl_ofst_40[gband][path][0] = (s8)data;
		} else if (rxsc_start == RTW89_BB_RXSC_START_IDX_20) {
			for (i = 0; i < 2; i++, data >>= 8) {
				rxsc = RTW89_BB_RXSC_START_IDX_20 + i;
				ofst = (s8)(data & 0xff);
				gain->rpl_ofst_40[gband][path][rxsc] = ofst;
			}
		}
		break;
	case RTW89_CHANNEL_WIDTH_80:
		if (rxsc_start == RTW89_BB_RXSC_START_IDX_FULL) {
			gain->rpl_ofst_80[gband][path][0] = (s8)data;
		} else if (rxsc_start == RTW89_BB_RXSC_START_IDX_20) {
			for (i = 0; i < 4; i++, data >>= 8) {
				rxsc = RTW89_BB_RXSC_START_IDX_20 + i;
				ofst = (s8)(data & 0xff);
				gain->rpl_ofst_80[gband][path][rxsc] = ofst;
			}
		} else if (rxsc_start == RTW89_BB_RXSC_START_IDX_40) {
			for (i = 0; i < 2; i++, data >>= 8) {
				rxsc = RTW89_BB_RXSC_START_IDX_40 + i;
				ofst = (s8)(data & 0xff);
				gain->rpl_ofst_80[gband][path][rxsc] = ofst;
			}
		}
		break;
	case RTW89_CHANNEL_WIDTH_160:
		if (rxsc_start == RTW89_BB_RXSC_START_IDX_FULL) {
			gain->rpl_ofst_160[gband][path][0] = (s8)data;
		} else if (rxsc_start == RTW89_BB_RXSC_START_IDX_20) {
			for (i = 0; i < 4; i++, data >>= 8) {
				rxsc = RTW89_BB_RXSC_START_IDX_20 + i;
				ofst = (s8)(data & 0xff);
				gain->rpl_ofst_160[gband][path][rxsc] = ofst;
			}
		} else if (rxsc_start == RTW89_BB_RXSC_START_IDX_20_1) {
			for (i = 0; i < 4; i++, data >>= 8) {
				rxsc = RTW89_BB_RXSC_START_IDX_20_1 + i;
				ofst = (s8)(data & 0xff);
				gain->rpl_ofst_160[gband][path][rxsc] = ofst;
			}
		} else if (rxsc_start == RTW89_BB_RXSC_START_IDX_40) {
			for (i = 0; i < 4; i++, data >>= 8) {
				rxsc = RTW89_BB_RXSC_START_IDX_40 + i;
				ofst = (s8)(data & 0xff);
				gain->rpl_ofst_160[gband][path][rxsc] = ofst;
			}
		} else if (rxsc_start == RTW89_BB_RXSC_START_IDX_80) {
			for (i = 0; i < 2; i++, data >>= 8) {
				rxsc = RTW89_BB_RXSC_START_IDX_80 + i;
				ofst = (s8)(data & 0xff);
				gain->rpl_ofst_160[gband][path][rxsc] = ofst;
			}
		}
		break;
	default:
		rtw89_warn(rtwdev,
			   "bb rpl ofst {0x%x:0x%x} with unknown bw: %d\n",
			   arg.addr, data, bw);
		break;
	}
}

static void
rtw89_phy_cfg_bb_gain_bypass(struct rtw89_dev *rtwdev,
			     union rtw89_phy_bb_gain_arg arg, u32 data)
{
	struct rtw89_phy_bb_gain_info *gain = &rtwdev->bb_gain;
	u8 type = arg.type;
	u8 path = arg.path;
	u8 gband = arg.gain_band;
	int i;

	switch (type) {
	case 0:
		for (i = 0; i < 4; i++, data >>= 8)
			gain->lna_gain_bypass[gband][path][i] = data & 0xff;
		break;
	case 1:
		for (i = 4; i < 7; i++, data >>= 8)
			gain->lna_gain_bypass[gband][path][i] = data & 0xff;
		break;
	default:
		rtw89_warn(rtwdev,
			   "bb gain bypass {0x%x:0x%x} with unknown type: %d\n",
			   arg.addr, data, type);
		break;
	}
}

static void
rtw89_phy_cfg_bb_gain_op1db(struct rtw89_dev *rtwdev,
			    union rtw89_phy_bb_gain_arg arg, u32 data)
{
	struct rtw89_phy_bb_gain_info *gain = &rtwdev->bb_gain;
	u8 type = arg.type;
	u8 path = arg.path;
	u8 gband = arg.gain_band;
	int i;

	switch (type) {
	case 0:
		for (i = 0; i < 4; i++, data >>= 8)
			gain->lna_op1db[gband][path][i] = data & 0xff;
		break;
	case 1:
		for (i = 4; i < 7; i++, data >>= 8)
			gain->lna_op1db[gband][path][i] = data & 0xff;
		break;
	case 2:
		for (i = 0; i < 4; i++, data >>= 8)
			gain->tia_lna_op1db[gband][path][i] = data & 0xff;
		break;
	case 3:
		for (i = 4; i < 8; i++, data >>= 8)
			gain->tia_lna_op1db[gband][path][i] = data & 0xff;
		break;
	default:
		rtw89_warn(rtwdev,
			   "bb gain op1db {0x%x:0x%x} with unknown type: %d\n",
			   arg.addr, data, type);
		break;
	}
}

static void rtw89_phy_config_bb_gain(struct rtw89_dev *rtwdev,
				     const struct rtw89_reg2_def *reg,
				     enum rtw89_rf_path rf_path,
				     void *extra_data)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	union rtw89_phy_bb_gain_arg arg = { .addr = reg->addr };
	struct rtw89_efuse *efuse = &rtwdev->efuse;

	if (arg.gain_band >= RTW89_BB_GAIN_BAND_NR)
		return;

	if (arg.path >= chip->rf_path_num)
		return;

	if (arg.addr >= 0xf9 && arg.addr <= 0xfe) {
		rtw89_warn(rtwdev, "bb gain table with flow ctrl\n");
		return;
	}

	switch (arg.cfg_type) {
	case 0:
		rtw89_phy_cfg_bb_gain_error(rtwdev, arg, reg->data);
		break;
	case 1:
		rtw89_phy_cfg_bb_rpl_ofst(rtwdev, arg, reg->data);
		break;
	case 2:
		rtw89_phy_cfg_bb_gain_bypass(rtwdev, arg, reg->data);
		break;
	case 3:
		rtw89_phy_cfg_bb_gain_op1db(rtwdev, arg, reg->data);
		break;
	case 4:
		/* This cfg_type is only used by rfe_type >= 50 with eFEM */
		if (efuse->rfe_type < 50)
			break;
		fallthrough;
	default:
		rtw89_warn(rtwdev,
			   "bb gain {0x%x:0x%x} with unknown cfg type: %d\n",
			   arg.addr, reg->data, arg.cfg_type);
		break;
	}
}

static void
rtw89_phy_cofig_rf_reg_store(struct rtw89_dev *rtwdev,
			     const struct rtw89_reg2_def *reg,
			     enum rtw89_rf_path rf_path,
			     struct rtw89_fw_h2c_rf_reg_info *info)
{
	u16 idx = info->curr_idx % RTW89_H2C_RF_PAGE_SIZE;
	u8 page = info->curr_idx / RTW89_H2C_RF_PAGE_SIZE;

	if (page >= RTW89_H2C_RF_PAGE_NUM) {
		rtw89_warn(rtwdev, "RF parameters exceed size. path=%d, idx=%d",
			   rf_path, info->curr_idx);
		return;
	}

	info->rtw89_phy_config_rf_h2c[page][idx] =
		cpu_to_le32((reg->addr << 20) | reg->data);
	info->curr_idx++;
}

static int rtw89_phy_config_rf_reg_fw(struct rtw89_dev *rtwdev,
				      struct rtw89_fw_h2c_rf_reg_info *info)
{
	u16 remain = info->curr_idx;
	u16 len = 0;
	u8 i;
	int ret = 0;

	if (remain > RTW89_H2C_RF_PAGE_NUM * RTW89_H2C_RF_PAGE_SIZE) {
		rtw89_warn(rtwdev,
			   "rf reg h2c total len %d larger than %d\n",
			   remain, RTW89_H2C_RF_PAGE_NUM * RTW89_H2C_RF_PAGE_SIZE);
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < RTW89_H2C_RF_PAGE_NUM && remain; i++, remain -= len) {
		len = remain > RTW89_H2C_RF_PAGE_SIZE ? RTW89_H2C_RF_PAGE_SIZE : remain;
		ret = rtw89_fw_h2c_rf_reg(rtwdev, info, len * 4, i);
		if (ret)
			goto out;
	}
out:
	info->curr_idx = 0;

	return ret;
}

static void rtw89_phy_config_rf_reg_noio(struct rtw89_dev *rtwdev,
					 const struct rtw89_reg2_def *reg,
					 enum rtw89_rf_path rf_path,
					 void *extra_data)
{
	u32 addr = reg->addr;

	if (addr == 0xfe || addr == 0xfd || addr == 0xfc || addr == 0xfb ||
	    addr == 0xfa || addr == 0xf9)
		return;

	if (rtw89_chip_rf_v1(rtwdev) && addr < 0x100)
		return;

	rtw89_phy_cofig_rf_reg_store(rtwdev, reg, rf_path,
				     (struct rtw89_fw_h2c_rf_reg_info *)extra_data);
}

static void rtw89_phy_config_rf_reg(struct rtw89_dev *rtwdev,
				    const struct rtw89_reg2_def *reg,
				    enum rtw89_rf_path rf_path,
				    void *extra_data)
{
	if (reg->addr == 0xfe) {
		mdelay(50);
	} else if (reg->addr == 0xfd) {
		mdelay(5);
	} else if (reg->addr == 0xfc) {
		mdelay(1);
	} else if (reg->addr == 0xfb) {
		udelay(50);
	} else if (reg->addr == 0xfa) {
		udelay(5);
	} else if (reg->addr == 0xf9) {
		udelay(1);
	} else {
		rtw89_write_rf(rtwdev, rf_path, reg->addr, 0xfffff, reg->data);
		rtw89_phy_cofig_rf_reg_store(rtwdev, reg, rf_path,
					     (struct rtw89_fw_h2c_rf_reg_info *)extra_data);
	}
}

void rtw89_phy_config_rf_reg_v1(struct rtw89_dev *rtwdev,
				const struct rtw89_reg2_def *reg,
				enum rtw89_rf_path rf_path,
				void *extra_data)
{
	rtw89_write_rf(rtwdev, rf_path, reg->addr, RFREG_MASK, reg->data);

	if (reg->addr < 0x100)
		return;

	rtw89_phy_cofig_rf_reg_store(rtwdev, reg, rf_path,
				     (struct rtw89_fw_h2c_rf_reg_info *)extra_data);
}
EXPORT_SYMBOL(rtw89_phy_config_rf_reg_v1);

static int rtw89_phy_sel_headline(struct rtw89_dev *rtwdev,
				  const struct rtw89_phy_table *table,
				  u32 *headline_size, u32 *headline_idx,
				  u8 rfe, u8 cv)
{
	const struct rtw89_reg2_def *reg;
	u32 headline;
	u32 compare, target;
	u8 rfe_para, cv_para;
	u8 cv_max = 0;
	bool case_matched = false;
	u32 i;

	for (i = 0; i < table->n_regs; i++) {
		reg = &table->regs[i];
		headline = get_phy_headline(reg->addr);
		if (headline != PHY_HEADLINE_VALID)
			break;
	}
	*headline_size = i;
	if (*headline_size == 0)
		return 0;

	/* case 1: RFE match, CV match */
	compare = get_phy_compare(rfe, cv);
	for (i = 0; i < *headline_size; i++) {
		reg = &table->regs[i];
		target = get_phy_target(reg->addr);
		if (target == compare) {
			*headline_idx = i;
			return 0;
		}
	}

	/* case 2: RFE match, CV don't care */
	compare = get_phy_compare(rfe, PHY_COND_DONT_CARE);
	for (i = 0; i < *headline_size; i++) {
		reg = &table->regs[i];
		target = get_phy_target(reg->addr);
		if (target == compare) {
			*headline_idx = i;
			return 0;
		}
	}

	/* case 3: RFE match, CV max in table */
	for (i = 0; i < *headline_size; i++) {
		reg = &table->regs[i];
		rfe_para = get_phy_cond_rfe(reg->addr);
		cv_para = get_phy_cond_cv(reg->addr);
		if (rfe_para == rfe) {
			if (cv_para >= cv_max) {
				cv_max = cv_para;
				*headline_idx = i;
				case_matched = true;
			}
		}
	}

	if (case_matched)
		return 0;

	/* case 4: RFE don't care, CV max in table */
	for (i = 0; i < *headline_size; i++) {
		reg = &table->regs[i];
		rfe_para = get_phy_cond_rfe(reg->addr);
		cv_para = get_phy_cond_cv(reg->addr);
		if (rfe_para == PHY_COND_DONT_CARE) {
			if (cv_para >= cv_max) {
				cv_max = cv_para;
				*headline_idx = i;
				case_matched = true;
			}
		}
	}

	if (case_matched)
		return 0;

	return -EINVAL;
}

static void rtw89_phy_init_reg(struct rtw89_dev *rtwdev,
			       const struct rtw89_phy_table *table,
			       void (*config)(struct rtw89_dev *rtwdev,
					      const struct rtw89_reg2_def *reg,
					      enum rtw89_rf_path rf_path,
					      void *data),
			       void *extra_data)
{
	const struct rtw89_reg2_def *reg;
	enum rtw89_rf_path rf_path = table->rf_path;
	u8 rfe = rtwdev->efuse.rfe_type;
	u8 cv = rtwdev->hal.cv;
	u32 i;
	u32 headline_size = 0, headline_idx = 0;
	u32 target = 0, cfg_target;
	u8 cond;
	bool is_matched = true;
	bool target_found = false;
	int ret;

	ret = rtw89_phy_sel_headline(rtwdev, table, &headline_size,
				     &headline_idx, rfe, cv);
	if (ret) {
		rtw89_err(rtwdev, "invalid PHY package: %d/%d\n", rfe, cv);
		return;
	}

	cfg_target = get_phy_target(table->regs[headline_idx].addr);
	for (i = headline_size; i < table->n_regs; i++) {
		reg = &table->regs[i];
		cond = get_phy_cond(reg->addr);
		switch (cond) {
		case PHY_COND_BRANCH_IF:
		case PHY_COND_BRANCH_ELIF:
			target = get_phy_target(reg->addr);
			break;
		case PHY_COND_BRANCH_ELSE:
			is_matched = false;
			if (!target_found) {
				rtw89_warn(rtwdev, "failed to load CR %x/%x\n",
					   reg->addr, reg->data);
				return;
			}
			break;
		case PHY_COND_BRANCH_END:
			is_matched = true;
			target_found = false;
			break;
		case PHY_COND_CHECK:
			if (target_found) {
				is_matched = false;
				break;
			}

			if (target == cfg_target) {
				is_matched = true;
				target_found = true;
			} else {
				is_matched = false;
				target_found = false;
			}
			break;
		default:
			if (is_matched)
				config(rtwdev, reg, rf_path, extra_data);
			break;
		}
	}
}

void rtw89_phy_init_bb_reg(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const struct rtw89_phy_table *bb_table = chip->bb_table;
	const struct rtw89_phy_table *bb_gain_table = chip->bb_gain_table;

	rtw89_phy_init_reg(rtwdev, bb_table, rtw89_phy_config_bb_reg, NULL);
	rtw89_chip_init_txpwr_unit(rtwdev, RTW89_PHY_0);
	if (bb_gain_table)
		rtw89_phy_init_reg(rtwdev, bb_gain_table,
				   rtw89_phy_config_bb_gain, NULL);
	rtw89_phy_bb_reset(rtwdev, RTW89_PHY_0);
}

static u32 rtw89_phy_nctl_poll(struct rtw89_dev *rtwdev)
{
	rtw89_phy_write32(rtwdev, 0x8080, 0x4);
	udelay(1);
	return rtw89_phy_read32(rtwdev, 0x8080);
}

void rtw89_phy_init_rf_reg(struct rtw89_dev *rtwdev, bool noio)
{
	void (*config)(struct rtw89_dev *rtwdev, const struct rtw89_reg2_def *reg,
		       enum rtw89_rf_path rf_path, void *data);
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const struct rtw89_phy_table *rf_table;
	struct rtw89_fw_h2c_rf_reg_info *rf_reg_info;
	u8 path;

	rf_reg_info = kzalloc(sizeof(*rf_reg_info), GFP_KERNEL);
	if (!rf_reg_info)
		return;

	for (path = RF_PATH_A; path < chip->rf_path_num; path++) {
		rf_table = chip->rf_table[path];
		rf_reg_info->rf_path = rf_table->rf_path;
		if (noio)
			config = rtw89_phy_config_rf_reg_noio;
		else
			config = rf_table->config ? rf_table->config :
				 rtw89_phy_config_rf_reg;
		rtw89_phy_init_reg(rtwdev, rf_table, config, (void *)rf_reg_info);
		if (rtw89_phy_config_rf_reg_fw(rtwdev, rf_reg_info))
			rtw89_warn(rtwdev, "rf path %d reg h2c config failed\n",
				   rf_reg_info->rf_path);
	}
	kfree(rf_reg_info);
}

static void rtw89_phy_init_rf_nctl(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const struct rtw89_phy_table *nctl_table;
	u32 val;
	int ret;

	/* IQK/DPK clock & reset */
	rtw89_phy_write32_set(rtwdev, R_IOQ_IQK_DPK, 0x3);
	rtw89_phy_write32_set(rtwdev, R_GNT_BT_WGT_EN, 0x1);
	rtw89_phy_write32_set(rtwdev, R_P0_PATH_RST, 0x8000000);
	rtw89_phy_write32_set(rtwdev, R_P1_PATH_RST, 0x8000000);
	if (chip->chip_id == RTL8852B)
		rtw89_phy_write32_set(rtwdev, R_IOQ_IQK_DPK, 0x2);

	/* check 0x8080 */
	rtw89_phy_write32(rtwdev, R_NCTL_CFG, 0x8);

	ret = read_poll_timeout(rtw89_phy_nctl_poll, val, val == 0x4, 10,
				1000, false, rtwdev);
	if (ret)
		rtw89_err(rtwdev, "failed to poll nctl block\n");

	nctl_table = chip->nctl_table;
	rtw89_phy_init_reg(rtwdev, nctl_table, rtw89_phy_config_bb_reg, NULL);
}

static u32 rtw89_phy0_phy1_offset(struct rtw89_dev *rtwdev, u32 addr)
{
	u32 phy_page = addr >> 8;
	u32 ofst = 0;

	switch (phy_page) {
	case 0x6:
	case 0x7:
	case 0x8:
	case 0x9:
	case 0xa:
	case 0xb:
	case 0xc:
	case 0xd:
	case 0x19:
	case 0x1a:
	case 0x1b:
		ofst = 0x2000;
		break;
	default:
		/* warning case */
		ofst = 0;
		break;
	}

	if (phy_page >= 0x40 && phy_page <= 0x4f)
		ofst = 0x2000;

	return ofst;
}

void rtw89_phy_write32_idx(struct rtw89_dev *rtwdev, u32 addr, u32 mask,
			   u32 data, enum rtw89_phy_idx phy_idx)
{
	if (rtwdev->dbcc_en && phy_idx == RTW89_PHY_1)
		addr += rtw89_phy0_phy1_offset(rtwdev, addr);
	rtw89_phy_write32_mask(rtwdev, addr, mask, data);
}
EXPORT_SYMBOL(rtw89_phy_write32_idx);

u32 rtw89_phy_read32_idx(struct rtw89_dev *rtwdev, u32 addr, u32 mask,
			 enum rtw89_phy_idx phy_idx)
{
	if (rtwdev->dbcc_en && phy_idx == RTW89_PHY_1)
		addr += rtw89_phy0_phy1_offset(rtwdev, addr);
	return rtw89_phy_read32_mask(rtwdev, addr, mask);
}
EXPORT_SYMBOL(rtw89_phy_read32_idx);

void rtw89_phy_set_phy_regs(struct rtw89_dev *rtwdev, u32 addr, u32 mask,
			    u32 val)
{
	rtw89_phy_write32_idx(rtwdev, addr, mask, val, RTW89_PHY_0);

	if (!rtwdev->dbcc_en)
		return;

	rtw89_phy_write32_idx(rtwdev, addr, mask, val, RTW89_PHY_1);
}

void rtw89_phy_write_reg3_tbl(struct rtw89_dev *rtwdev,
			      const struct rtw89_phy_reg3_tbl *tbl)
{
	const struct rtw89_reg3_def *reg3;
	int i;

	for (i = 0; i < tbl->size; i++) {
		reg3 = &tbl->reg3[i];
		rtw89_phy_write32_mask(rtwdev, reg3->addr, reg3->mask, reg3->data);
	}
}
EXPORT_SYMBOL(rtw89_phy_write_reg3_tbl);

static const u8 rtw89_rs_idx_max[] = {
	[RTW89_RS_CCK] = RTW89_RATE_CCK_MAX,
	[RTW89_RS_OFDM] = RTW89_RATE_OFDM_MAX,
	[RTW89_RS_MCS] = RTW89_RATE_MCS_MAX,
	[RTW89_RS_HEDCM] = RTW89_RATE_HEDCM_MAX,
	[RTW89_RS_OFFSET] = RTW89_RATE_OFFSET_MAX,
};

static const u8 rtw89_rs_nss_max[] = {
	[RTW89_RS_CCK] = 1,
	[RTW89_RS_OFDM] = 1,
	[RTW89_RS_MCS] = RTW89_NSS_MAX,
	[RTW89_RS_HEDCM] = RTW89_NSS_HEDCM_MAX,
	[RTW89_RS_OFFSET] = 1,
};

static const u8 _byr_of_rs[] = {
	[RTW89_RS_CCK] = offsetof(struct rtw89_txpwr_byrate, cck),
	[RTW89_RS_OFDM] = offsetof(struct rtw89_txpwr_byrate, ofdm),
	[RTW89_RS_MCS] = offsetof(struct rtw89_txpwr_byrate, mcs),
	[RTW89_RS_HEDCM] = offsetof(struct rtw89_txpwr_byrate, hedcm),
	[RTW89_RS_OFFSET] = offsetof(struct rtw89_txpwr_byrate, offset),
};

#define _byr_seek(rs, raw) ((s8 *)(raw) + _byr_of_rs[rs])
#define _byr_idx(rs, nss, idx) ((nss) * rtw89_rs_idx_max[rs] + (idx))
#define _byr_chk(rs, nss, idx) \
	((nss) < rtw89_rs_nss_max[rs] && (idx) < rtw89_rs_idx_max[rs])

void rtw89_phy_load_txpwr_byrate(struct rtw89_dev *rtwdev,
				 const struct rtw89_txpwr_table *tbl)
{
	const struct rtw89_txpwr_byrate_cfg *cfg = tbl->data;
	const struct rtw89_txpwr_byrate_cfg *end = cfg + tbl->size;
	s8 *byr;
	u32 data;
	u8 i, idx;

	for (; cfg < end; cfg++) {
		byr = _byr_seek(cfg->rs, &rtwdev->byr[cfg->band]);
		data = cfg->data;

		for (i = 0; i < cfg->len; i++, data >>= 8) {
			idx = _byr_idx(cfg->rs, cfg->nss, (cfg->shf + i));
			byr[idx] = (s8)(data & 0xff);
		}
	}
}
EXPORT_SYMBOL(rtw89_phy_load_txpwr_byrate);

#define _phy_txpwr_rf_to_mac(rtwdev, txpwr_rf)				\
({									\
	const struct rtw89_chip_info *__c = (rtwdev)->chip;		\
	(txpwr_rf) >> (__c->txpwr_factor_rf - __c->txpwr_factor_mac);	\
})

static
s8 rtw89_phy_read_txpwr_byrate(struct rtw89_dev *rtwdev, u8 band,
			       const struct rtw89_rate_desc *rate_desc)
{
	s8 *byr;
	u8 idx;

	if (rate_desc->rs == RTW89_RS_CCK)
		band = RTW89_BAND_2G;

	if (!_byr_chk(rate_desc->rs, rate_desc->nss, rate_desc->idx)) {
		rtw89_debug(rtwdev, RTW89_DBG_TXPWR,
			    "[TXPWR] unknown byrate desc rs=%d nss=%d idx=%d\n",
			    rate_desc->rs, rate_desc->nss, rate_desc->idx);

		return 0;
	}

	byr = _byr_seek(rate_desc->rs, &rtwdev->byr[band]);
	idx = _byr_idx(rate_desc->rs, rate_desc->nss, rate_desc->idx);

	return _phy_txpwr_rf_to_mac(rtwdev, byr[idx]);
}

static u8 rtw89_channel_6g_to_idx(struct rtw89_dev *rtwdev, u8 channel_6g)
{
	switch (channel_6g) {
	case 1 ... 29:
		return (channel_6g - 1) / 2;
	case 33 ... 61:
		return (channel_6g - 3) / 2;
	case 65 ... 93:
		return (channel_6g - 5) / 2;
	case 97 ... 125:
		return (channel_6g - 7) / 2;
	case 129 ... 157:
		return (channel_6g - 9) / 2;
	case 161 ... 189:
		return (channel_6g - 11) / 2;
	case 193 ... 221:
		return (channel_6g - 13) / 2;
	case 225 ... 253:
		return (channel_6g - 15) / 2;
	default:
		rtw89_warn(rtwdev, "unknown 6g channel: %d\n", channel_6g);
		return 0;
	}
}

static u8 rtw89_channel_to_idx(struct rtw89_dev *rtwdev, u8 band, u8 channel)
{
	if (band == RTW89_BAND_6G)
		return rtw89_channel_6g_to_idx(rtwdev, channel);

	switch (channel) {
	case 1 ... 14:
		return channel - 1;
	case 36 ... 64:
		return (channel - 36) / 2;
	case 100 ... 144:
		return ((channel - 100) / 2) + 15;
	case 149 ... 177:
		return ((channel - 149) / 2) + 38;
	default:
		rtw89_warn(rtwdev, "unknown channel: %d\n", channel);
		return 0;
	}
}

s8 rtw89_phy_read_txpwr_limit(struct rtw89_dev *rtwdev, u8 band,
			      u8 bw, u8 ntx, u8 rs, u8 bf, u8 ch)
{
	const struct rtw89_rfe_parms *rfe_parms = rtwdev->rfe_parms;
	const struct rtw89_txpwr_rule_2ghz *rule_2ghz = &rfe_parms->rule_2ghz;
	const struct rtw89_txpwr_rule_5ghz *rule_5ghz = &rfe_parms->rule_5ghz;
	const struct rtw89_txpwr_rule_6ghz *rule_6ghz = &rfe_parms->rule_6ghz;
	u8 ch_idx = rtw89_channel_to_idx(rtwdev, band, ch);
	u8 regd = rtw89_regd_get(rtwdev, band);
	s8 lmt = 0, sar;

	switch (band) {
	case RTW89_BAND_2G:
		lmt = (*rule_2ghz->lmt)[bw][ntx][rs][bf][regd][ch_idx];
		if (lmt)
			break;

		lmt = (*rule_2ghz->lmt)[bw][ntx][rs][bf][RTW89_WW][ch_idx];
		break;
	case RTW89_BAND_5G:
		lmt = (*rule_5ghz->lmt)[bw][ntx][rs][bf][regd][ch_idx];
		if (lmt)
			break;

		lmt = (*rule_5ghz->lmt)[bw][ntx][rs][bf][RTW89_WW][ch_idx];
		break;
	case RTW89_BAND_6G:
		lmt = (*rule_6ghz->lmt)[bw][ntx][rs][bf][regd][ch_idx];
		if (lmt)
			break;

		lmt = (*rule_6ghz->lmt)[bw][ntx][rs][bf][RTW89_WW][ch_idx];
		break;
	default:
		rtw89_warn(rtwdev, "unknown band type: %d\n", band);
		return 0;
	}

	lmt = _phy_txpwr_rf_to_mac(rtwdev, lmt);
	sar = rtw89_query_sar(rtwdev);

	return min(lmt, sar);
}
EXPORT_SYMBOL(rtw89_phy_read_txpwr_limit);

#define __fill_txpwr_limit_nonbf_bf(ptr, band, bw, ntx, rs, ch)		\
	do {								\
		u8 __i;							\
		for (__i = 0; __i < RTW89_BF_NUM; __i++)		\
			ptr[__i] = rtw89_phy_read_txpwr_limit(rtwdev,	\
							      band,	\
							      bw, ntx,	\
							      rs, __i,	\
							      (ch));	\
	} while (0)

static void rtw89_phy_fill_txpwr_limit_20m(struct rtw89_dev *rtwdev,
					   struct rtw89_txpwr_limit *lmt,
					   u8 band, u8 ntx, u8 ch)
{
	__fill_txpwr_limit_nonbf_bf(lmt->cck_20m, band, RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_CCK, ch);
	__fill_txpwr_limit_nonbf_bf(lmt->cck_40m, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_CCK, ch);
	__fill_txpwr_limit_nonbf_bf(lmt->ofdm, band, RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_OFDM, ch);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[0], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch);
}

static void rtw89_phy_fill_txpwr_limit_40m(struct rtw89_dev *rtwdev,
					   struct rtw89_txpwr_limit *lmt,
					   u8 band, u8 ntx, u8 ch, u8 pri_ch)
{
	__fill_txpwr_limit_nonbf_bf(lmt->cck_20m, band, RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_CCK, ch - 2);
	__fill_txpwr_limit_nonbf_bf(lmt->cck_40m, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_CCK, ch);
	__fill_txpwr_limit_nonbf_bf(lmt->ofdm, band, RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_OFDM, pri_ch);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[0], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch - 2);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[1], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch + 2);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_40m[0], band,
				    RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch);
}

static void rtw89_phy_fill_txpwr_limit_80m(struct rtw89_dev *rtwdev,
					   struct rtw89_txpwr_limit *lmt,
					   u8 band, u8 ntx, u8 ch, u8 pri_ch)
{
	s8 val_0p5_n[RTW89_BF_NUM];
	s8 val_0p5_p[RTW89_BF_NUM];
	u8 i;

	__fill_txpwr_limit_nonbf_bf(lmt->ofdm, band, RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_OFDM, pri_ch);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[0], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch - 6);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[1], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch - 2);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[2], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch + 2);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[3], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch + 6);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_40m[0], band,
				    RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch - 4);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_40m[1], band,
				    RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch + 4);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_80m[0], band,
				    RTW89_CHANNEL_WIDTH_80,
				    ntx, RTW89_RS_MCS, ch);

	__fill_txpwr_limit_nonbf_bf(val_0p5_n, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch - 4);
	__fill_txpwr_limit_nonbf_bf(val_0p5_p, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch + 4);

	for (i = 0; i < RTW89_BF_NUM; i++)
		lmt->mcs_40m_0p5[i] = min_t(s8, val_0p5_n[i], val_0p5_p[i]);
}

static void rtw89_phy_fill_txpwr_limit_160m(struct rtw89_dev *rtwdev,
					    struct rtw89_txpwr_limit *lmt,
					    u8 band, u8 ntx, u8 ch, u8 pri_ch)
{
	s8 val_0p5_n[RTW89_BF_NUM];
	s8 val_0p5_p[RTW89_BF_NUM];
	s8 val_2p5_n[RTW89_BF_NUM];
	s8 val_2p5_p[RTW89_BF_NUM];
	u8 i;

	/* fill ofdm section */
	__fill_txpwr_limit_nonbf_bf(lmt->ofdm, band, RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_OFDM, pri_ch);

	/* fill mcs 20m section */
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[0], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch - 14);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[1], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch - 10);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[2], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch - 6);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[3], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch - 2);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[4], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch + 2);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[5], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch + 6);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[6], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch + 10);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_20m[7], band,
				    RTW89_CHANNEL_WIDTH_20,
				    ntx, RTW89_RS_MCS, ch + 14);

	/* fill mcs 40m section */
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_40m[0], band,
				    RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch - 12);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_40m[1], band,
				    RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch - 4);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_40m[2], band,
				    RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch + 4);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_40m[3], band,
				    RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch + 12);

	/* fill mcs 80m section */
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_80m[0], band,
				    RTW89_CHANNEL_WIDTH_80,
				    ntx, RTW89_RS_MCS, ch - 8);
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_80m[1], band,
				    RTW89_CHANNEL_WIDTH_80,
				    ntx, RTW89_RS_MCS, ch + 8);

	/* fill mcs 160m section */
	__fill_txpwr_limit_nonbf_bf(lmt->mcs_160m, band,
				    RTW89_CHANNEL_WIDTH_160,
				    ntx, RTW89_RS_MCS, ch);

	/* fill mcs 40m 0p5 section */
	__fill_txpwr_limit_nonbf_bf(val_0p5_n, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch - 4);
	__fill_txpwr_limit_nonbf_bf(val_0p5_p, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch + 4);

	for (i = 0; i < RTW89_BF_NUM; i++)
		lmt->mcs_40m_0p5[i] = min_t(s8, val_0p5_n[i], val_0p5_p[i]);

	/* fill mcs 40m 2p5 section */
	__fill_txpwr_limit_nonbf_bf(val_2p5_n, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch - 8);
	__fill_txpwr_limit_nonbf_bf(val_2p5_p, band, RTW89_CHANNEL_WIDTH_40,
				    ntx, RTW89_RS_MCS, ch + 8);

	for (i = 0; i < RTW89_BF_NUM; i++)
		lmt->mcs_40m_2p5[i] = min_t(s8, val_2p5_n[i], val_2p5_p[i]);
}

static
void rtw89_phy_fill_txpwr_limit(struct rtw89_dev *rtwdev,
				const struct rtw89_chan *chan,
				struct rtw89_txpwr_limit *lmt,
				u8 ntx)
{
	u8 band = chan->band_type;
	u8 pri_ch = chan->primary_channel;
	u8 ch = chan->channel;
	u8 bw = chan->band_width;

	memset(lmt, 0, sizeof(*lmt));

	switch (bw) {
	case RTW89_CHANNEL_WIDTH_20:
		rtw89_phy_fill_txpwr_limit_20m(rtwdev, lmt, band, ntx, ch);
		break;
	case RTW89_CHANNEL_WIDTH_40:
		rtw89_phy_fill_txpwr_limit_40m(rtwdev, lmt, band, ntx, ch,
					       pri_ch);
		break;
	case RTW89_CHANNEL_WIDTH_80:
		rtw89_phy_fill_txpwr_limit_80m(rtwdev, lmt, band, ntx, ch,
					       pri_ch);
		break;
	case RTW89_CHANNEL_WIDTH_160:
		rtw89_phy_fill_txpwr_limit_160m(rtwdev, lmt, band, ntx, ch,
						pri_ch);
		break;
	}
}

static s8 rtw89_phy_read_txpwr_limit_ru(struct rtw89_dev *rtwdev, u8 band,
					u8 ru, u8 ntx, u8 ch)
{
	const struct rtw89_rfe_parms *rfe_parms = rtwdev->rfe_parms;
	const struct rtw89_txpwr_rule_2ghz *rule_2ghz = &rfe_parms->rule_2ghz;
	const struct rtw89_txpwr_rule_5ghz *rule_5ghz = &rfe_parms->rule_5ghz;
	const struct rtw89_txpwr_rule_6ghz *rule_6ghz = &rfe_parms->rule_6ghz;
	u8 ch_idx = rtw89_channel_to_idx(rtwdev, band, ch);
	u8 regd = rtw89_regd_get(rtwdev, band);
	s8 lmt_ru = 0, sar;

	switch (band) {
	case RTW89_BAND_2G:
		lmt_ru = (*rule_2ghz->lmt_ru)[ru][ntx][regd][ch_idx];
		if (lmt_ru)
			break;

		lmt_ru = (*rule_2ghz->lmt_ru)[ru][ntx][RTW89_WW][ch_idx];
		break;
	case RTW89_BAND_5G:
		lmt_ru = (*rule_5ghz->lmt_ru)[ru][ntx][regd][ch_idx];
		if (lmt_ru)
			break;

		lmt_ru = (*rule_5ghz->lmt_ru)[ru][ntx][RTW89_WW][ch_idx];
		break;
	case RTW89_BAND_6G:
		lmt_ru = (*rule_6ghz->lmt_ru)[ru][ntx][regd][ch_idx];
		if (lmt_ru)
			break;

		lmt_ru = (*rule_6ghz->lmt_ru)[ru][ntx][RTW89_WW][ch_idx];
		break;
	default:
		rtw89_warn(rtwdev, "unknown band type: %d\n", band);
		return 0;
	}

	lmt_ru = _phy_txpwr_rf_to_mac(rtwdev, lmt_ru);
	sar = rtw89_query_sar(rtwdev);

	return min(lmt_ru, sar);
}

static void
rtw89_phy_fill_txpwr_limit_ru_20m(struct rtw89_dev *rtwdev,
				  struct rtw89_txpwr_limit_ru *lmt_ru,
				  u8 band, u8 ntx, u8 ch)
{
	lmt_ru->ru26[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU26,
							ntx, ch);
	lmt_ru->ru52[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU52,
							ntx, ch);
	lmt_ru->ru106[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							 RTW89_RU106,
							 ntx, ch);
}

static void
rtw89_phy_fill_txpwr_limit_ru_40m(struct rtw89_dev *rtwdev,
				  struct rtw89_txpwr_limit_ru *lmt_ru,
				  u8 band, u8 ntx, u8 ch)
{
	lmt_ru->ru26[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU26,
							ntx, ch - 2);
	lmt_ru->ru26[1] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU26,
							ntx, ch + 2);
	lmt_ru->ru52[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU52,
							ntx, ch - 2);
	lmt_ru->ru52[1] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU52,
							ntx, ch + 2);
	lmt_ru->ru106[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							 RTW89_RU106,
							 ntx, ch - 2);
	lmt_ru->ru106[1] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							 RTW89_RU106,
							 ntx, ch + 2);
}

static void
rtw89_phy_fill_txpwr_limit_ru_80m(struct rtw89_dev *rtwdev,
				  struct rtw89_txpwr_limit_ru *lmt_ru,
				  u8 band, u8 ntx, u8 ch)
{
	lmt_ru->ru26[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU26,
							ntx, ch - 6);
	lmt_ru->ru26[1] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU26,
							ntx, ch - 2);
	lmt_ru->ru26[2] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU26,
							ntx, ch + 2);
	lmt_ru->ru26[3] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU26,
							ntx, ch + 6);
	lmt_ru->ru52[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU52,
							ntx, ch - 6);
	lmt_ru->ru52[1] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU52,
							ntx, ch - 2);
	lmt_ru->ru52[2] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU52,
							ntx, ch + 2);
	lmt_ru->ru52[3] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							RTW89_RU52,
							ntx, ch + 6);
	lmt_ru->ru106[0] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							 RTW89_RU106,
							 ntx, ch - 6);
	lmt_ru->ru106[1] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							 RTW89_RU106,
							 ntx, ch - 2);
	lmt_ru->ru106[2] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							 RTW89_RU106,
							 ntx, ch + 2);
	lmt_ru->ru106[3] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
							 RTW89_RU106,
							 ntx, ch + 6);
}

static void
rtw89_phy_fill_txpwr_limit_ru_160m(struct rtw89_dev *rtwdev,
				   struct rtw89_txpwr_limit_ru *lmt_ru,
				   u8 band, u8 ntx, u8 ch)
{
	static const int ofst[] = { -14, -10, -6, -2, 2, 6, 10, 14 };
	int i;

	static_assert(ARRAY_SIZE(ofst) == RTW89_RU_SEC_NUM);
	for (i = 0; i < RTW89_RU_SEC_NUM; i++) {
		lmt_ru->ru26[i] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
								RTW89_RU26,
								ntx,
								ch + ofst[i]);
		lmt_ru->ru52[i] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
								RTW89_RU52,
								ntx,
								ch + ofst[i]);
		lmt_ru->ru106[i] = rtw89_phy_read_txpwr_limit_ru(rtwdev, band,
								 RTW89_RU106,
								 ntx,
								 ch + ofst[i]);
	}
}

static
void rtw89_phy_fill_txpwr_limit_ru(struct rtw89_dev *rtwdev,
				   const struct rtw89_chan *chan,
				   struct rtw89_txpwr_limit_ru *lmt_ru,
				   u8 ntx)
{
	u8 band = chan->band_type;
	u8 ch = chan->channel;
	u8 bw = chan->band_width;

	memset(lmt_ru, 0, sizeof(*lmt_ru));

	switch (bw) {
	case RTW89_CHANNEL_WIDTH_20:
		rtw89_phy_fill_txpwr_limit_ru_20m(rtwdev, lmt_ru, band, ntx,
						  ch);
		break;
	case RTW89_CHANNEL_WIDTH_40:
		rtw89_phy_fill_txpwr_limit_ru_40m(rtwdev, lmt_ru, band, ntx,
						  ch);
		break;
	case RTW89_CHANNEL_WIDTH_80:
		rtw89_phy_fill_txpwr_limit_ru_80m(rtwdev, lmt_ru, band, ntx,
						  ch);
		break;
	case RTW89_CHANNEL_WIDTH_160:
		rtw89_phy_fill_txpwr_limit_ru_160m(rtwdev, lmt_ru, band, ntx,
						   ch);
		break;
	}
}

void rtw89_phy_set_txpwr_byrate(struct rtw89_dev *rtwdev,
				const struct rtw89_chan *chan,
				enum rtw89_phy_idx phy_idx)
{
	u8 max_nss_num = rtwdev->chip->rf_path_num;
	static const u8 rs[] = {
		RTW89_RS_CCK,
		RTW89_RS_OFDM,
		RTW89_RS_MCS,
		RTW89_RS_HEDCM,
	};
	struct rtw89_rate_desc cur;
	u8 band = chan->band_type;
	u8 ch = chan->channel;
	u32 addr, val;
	s8 v[4] = {};
	u8 i;

	rtw89_debug(rtwdev, RTW89_DBG_TXPWR,
		    "[TXPWR] set txpwr byrate with ch=%d\n", ch);

	BUILD_BUG_ON(rtw89_rs_idx_max[RTW89_RS_CCK] % 4);
	BUILD_BUG_ON(rtw89_rs_idx_max[RTW89_RS_OFDM] % 4);
	BUILD_BUG_ON(rtw89_rs_idx_max[RTW89_RS_MCS] % 4);
	BUILD_BUG_ON(rtw89_rs_idx_max[RTW89_RS_HEDCM] % 4);

	addr = R_AX_PWR_BY_RATE;
	for (cur.nss = 0; cur.nss < max_nss_num; cur.nss++) {
		for (i = 0; i < ARRAY_SIZE(rs); i++) {
			if (cur.nss >= rtw89_rs_nss_max[rs[i]])
				continue;

			cur.rs = rs[i];
			for (cur.idx = 0; cur.idx < rtw89_rs_idx_max[rs[i]];
			     cur.idx++) {
				v[cur.idx % 4] =
					rtw89_phy_read_txpwr_byrate(rtwdev,
								    band,
								    &cur);

				if ((cur.idx + 1) % 4)
					continue;

				val = FIELD_PREP(GENMASK(7, 0), v[0]) |
				      FIELD_PREP(GENMASK(15, 8), v[1]) |
				      FIELD_PREP(GENMASK(23, 16), v[2]) |
				      FIELD_PREP(GENMASK(31, 24), v[3]);

				rtw89_mac_txpwr_write32(rtwdev, phy_idx, addr,
							val);
				addr += 4;
			}
		}
	}
}
EXPORT_SYMBOL(rtw89_phy_set_txpwr_byrate);

void rtw89_phy_set_txpwr_offset(struct rtw89_dev *rtwdev,
				const struct rtw89_chan *chan,
				enum rtw89_phy_idx phy_idx)
{
	struct rtw89_rate_desc desc = {
		.nss = RTW89_NSS_1,
		.rs = RTW89_RS_OFFSET,
	};
	u8 band = chan->band_type;
	s8 v[RTW89_RATE_OFFSET_MAX] = {};
	u32 val;

	rtw89_debug(rtwdev, RTW89_DBG_TXPWR, "[TXPWR] set txpwr offset\n");

	for (desc.idx = 0; desc.idx < RTW89_RATE_OFFSET_MAX; desc.idx++)
		v[desc.idx] = rtw89_phy_read_txpwr_byrate(rtwdev, band, &desc);

	BUILD_BUG_ON(RTW89_RATE_OFFSET_MAX != 5);
	val = FIELD_PREP(GENMASK(3, 0), v[0]) |
	      FIELD_PREP(GENMASK(7, 4), v[1]) |
	      FIELD_PREP(GENMASK(11, 8), v[2]) |
	      FIELD_PREP(GENMASK(15, 12), v[3]) |
	      FIELD_PREP(GENMASK(19, 16), v[4]);

	rtw89_mac_txpwr_write32_mask(rtwdev, phy_idx, R_AX_PWR_RATE_OFST_CTRL,
				     GENMASK(19, 0), val);
}
EXPORT_SYMBOL(rtw89_phy_set_txpwr_offset);

void rtw89_phy_set_txpwr_limit(struct rtw89_dev *rtwdev,
			       const struct rtw89_chan *chan,
			       enum rtw89_phy_idx phy_idx)
{
	u8 max_ntx_num = rtwdev->chip->rf_path_num;
	struct rtw89_txpwr_limit lmt;
	u8 ch = chan->channel;
	u8 bw = chan->band_width;
	const s8 *ptr;
	u32 addr, val;
	u8 i, j;

	rtw89_debug(rtwdev, RTW89_DBG_TXPWR,
		    "[TXPWR] set txpwr limit with ch=%d bw=%d\n", ch, bw);

	BUILD_BUG_ON(sizeof(struct rtw89_txpwr_limit) !=
		     RTW89_TXPWR_LMT_PAGE_SIZE);

	addr = R_AX_PWR_LMT;
	for (i = 0; i < max_ntx_num; i++) {
		rtw89_phy_fill_txpwr_limit(rtwdev, chan, &lmt, i);

		ptr = (s8 *)&lmt;
		for (j = 0; j < RTW89_TXPWR_LMT_PAGE_SIZE;
		     j += 4, addr += 4, ptr += 4) {
			val = FIELD_PREP(GENMASK(7, 0), ptr[0]) |
			      FIELD_PREP(GENMASK(15, 8), ptr[1]) |
			      FIELD_PREP(GENMASK(23, 16), ptr[2]) |
			      FIELD_PREP(GENMASK(31, 24), ptr[3]);

			rtw89_mac_txpwr_write32(rtwdev, phy_idx, addr, val);
		}
	}
}
EXPORT_SYMBOL(rtw89_phy_set_txpwr_limit);

void rtw89_phy_set_txpwr_limit_ru(struct rtw89_dev *rtwdev,
				  const struct rtw89_chan *chan,
				  enum rtw89_phy_idx phy_idx)
{
	u8 max_ntx_num = rtwdev->chip->rf_path_num;
	struct rtw89_txpwr_limit_ru lmt_ru;
	u8 ch = chan->channel;
	u8 bw = chan->band_width;
	const s8 *ptr;
	u32 addr, val;
	u8 i, j;

	rtw89_debug(rtwdev, RTW89_DBG_TXPWR,
		    "[TXPWR] set txpwr limit ru with ch=%d bw=%d\n", ch, bw);

	BUILD_BUG_ON(sizeof(struct rtw89_txpwr_limit_ru) !=
		     RTW89_TXPWR_LMT_RU_PAGE_SIZE);

	addr = R_AX_PWR_RU_LMT;
	for (i = 0; i < max_ntx_num; i++) {
		rtw89_phy_fill_txpwr_limit_ru(rtwdev, chan, &lmt_ru, i);

		ptr = (s8 *)&lmt_ru;
		for (j = 0; j < RTW89_TXPWR_LMT_RU_PAGE_SIZE;
		     j += 4, addr += 4, ptr += 4) {
			val = FIELD_PREP(GENMASK(7, 0), ptr[0]) |
			      FIELD_PREP(GENMASK(15, 8), ptr[1]) |
			      FIELD_PREP(GENMASK(23, 16), ptr[2]) |
			      FIELD_PREP(GENMASK(31, 24), ptr[3]);

			rtw89_mac_txpwr_write32(rtwdev, phy_idx, addr, val);
		}
	}
}
EXPORT_SYMBOL(rtw89_phy_set_txpwr_limit_ru);

struct rtw89_phy_iter_ra_data {
	struct rtw89_dev *rtwdev;
	struct sk_buff *c2h;
};

static void rtw89_phy_c2h_ra_rpt_iter(void *data, struct ieee80211_sta *sta)
{
	struct rtw89_phy_iter_ra_data *ra_data = (struct rtw89_phy_iter_ra_data *)data;
	struct rtw89_dev *rtwdev = ra_data->rtwdev;
	struct rtw89_sta *rtwsta = (struct rtw89_sta *)sta->drv_priv;
	struct rtw89_ra_report *ra_report = &rtwsta->ra_report;
	struct sk_buff *c2h = ra_data->c2h;
	u8 mode, rate, bw, giltf, mac_id;
	u16 legacy_bitrate;
	bool valid;
	u8 mcs = 0;

	mac_id = RTW89_GET_PHY_C2H_RA_RPT_MACID(c2h->data);
	if (mac_id != rtwsta->mac_id)
		return;

	rate = RTW89_GET_PHY_C2H_RA_RPT_MCSNSS(c2h->data);
	bw = RTW89_GET_PHY_C2H_RA_RPT_BW(c2h->data);
	giltf = RTW89_GET_PHY_C2H_RA_RPT_GILTF(c2h->data);
	mode = RTW89_GET_PHY_C2H_RA_RPT_MD_SEL(c2h->data);

	if (mode == RTW89_RA_RPT_MODE_LEGACY) {
		valid = rtw89_ra_report_to_bitrate(rtwdev, rate, &legacy_bitrate);
		if (!valid)
			return;
	}

	memset(&ra_report->txrate, 0, sizeof(ra_report->txrate));

	switch (mode) {
	case RTW89_RA_RPT_MODE_LEGACY:
		ra_report->txrate.legacy = legacy_bitrate;
		break;
	case RTW89_RA_RPT_MODE_HT:
		ra_report->txrate.flags |= RATE_INFO_FLAGS_MCS;
		if (RTW89_CHK_FW_FEATURE(OLD_HT_RA_FORMAT, &rtwdev->fw))
			rate = RTW89_MK_HT_RATE(FIELD_GET(RTW89_RA_RATE_MASK_NSS, rate),
						FIELD_GET(RTW89_RA_RATE_MASK_MCS, rate));
		else
			rate = FIELD_GET(RTW89_RA_RATE_MASK_HT_MCS, rate);
		ra_report->txrate.mcs = rate;
		if (giltf)
			ra_report->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
		mcs = ra_report->txrate.mcs & 0x07;
		break;
	case RTW89_RA_RPT_MODE_VHT:
		ra_report->txrate.flags |= RATE_INFO_FLAGS_VHT_MCS;
		ra_report->txrate.mcs = FIELD_GET(RTW89_RA_RATE_MASK_MCS, rate);
		ra_report->txrate.nss = FIELD_GET(RTW89_RA_RATE_MASK_NSS, rate) + 1;
		if (giltf)
			ra_report->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
		mcs = ra_report->txrate.mcs;
		break;
	case RTW89_RA_RPT_MODE_HE:
		ra_report->txrate.flags |= RATE_INFO_FLAGS_HE_MCS;
		ra_report->txrate.mcs = FIELD_GET(RTW89_RA_RATE_MASK_MCS, rate);
		ra_report->txrate.nss = FIELD_GET(RTW89_RA_RATE_MASK_NSS, rate) + 1;
		if (giltf == RTW89_GILTF_2XHE08 || giltf == RTW89_GILTF_1XHE08)
			ra_report->txrate.he_gi = NL80211_RATE_INFO_HE_GI_0_8;
		else if (giltf == RTW89_GILTF_2XHE16 || giltf == RTW89_GILTF_1XHE16)
			ra_report->txrate.he_gi = NL80211_RATE_INFO_HE_GI_1_6;
		else
			ra_report->txrate.he_gi = NL80211_RATE_INFO_HE_GI_3_2;
		mcs = ra_report->txrate.mcs;
		break;
	}

	ra_report->txrate.bw = rtw89_hw_to_rate_info_bw(bw);
	ra_report->bit_rate = cfg80211_calculate_bitrate(&ra_report->txrate);
	ra_report->hw_rate = FIELD_PREP(RTW89_HW_RATE_MASK_MOD, mode) |
			     FIELD_PREP(RTW89_HW_RATE_MASK_VAL, rate);
	ra_report->might_fallback_legacy = mcs <= 2;
	sta->deflink.agg.max_rc_amsdu_len = get_max_amsdu_len(rtwdev, ra_report);
	rtwsta->max_agg_wait = sta->deflink.agg.max_rc_amsdu_len / 1500 - 1;
}

static void
rtw89_phy_c2h_ra_rpt(struct rtw89_dev *rtwdev, struct sk_buff *c2h, u32 len)
{
	struct rtw89_phy_iter_ra_data ra_data;

	ra_data.rtwdev = rtwdev;
	ra_data.c2h = c2h;
	ieee80211_iterate_stations_atomic(rtwdev->hw,
					  rtw89_phy_c2h_ra_rpt_iter,
					  &ra_data);
}

static
void (* const rtw89_phy_c2h_ra_handler[])(struct rtw89_dev *rtwdev,
					  struct sk_buff *c2h, u32 len) = {
	[RTW89_PHY_C2H_FUNC_STS_RPT] = rtw89_phy_c2h_ra_rpt,
	[RTW89_PHY_C2H_FUNC_MU_GPTBL_RPT] = NULL,
	[RTW89_PHY_C2H_FUNC_TXSTS] = NULL,
};

void rtw89_phy_c2h_handle(struct rtw89_dev *rtwdev, struct sk_buff *skb,
			  u32 len, u8 class, u8 func)
{
	void (*handler)(struct rtw89_dev *rtwdev,
			struct sk_buff *c2h, u32 len) = NULL;

	switch (class) {
	case RTW89_PHY_C2H_CLASS_RA:
		if (func < RTW89_PHY_C2H_FUNC_RA_MAX)
			handler = rtw89_phy_c2h_ra_handler[func];
		break;
	case RTW89_PHY_C2H_CLASS_DM:
		if (func == RTW89_PHY_C2H_DM_FUNC_LOWRT_RTY)
			return;
		fallthrough;
	default:
		rtw89_info(rtwdev, "c2h class %d not support\n", class);
		return;
	}
	if (!handler) {
		rtw89_info(rtwdev, "c2h class %d func %d not support\n", class,
			   func);
		return;
	}
	handler(rtwdev, skb, len);
}

static u8 rtw89_phy_cfo_get_xcap_reg(struct rtw89_dev *rtwdev, bool sc_xo)
{
	u32 reg_mask;

	if (sc_xo)
		reg_mask = B_AX_XTAL_SC_XO_MASK;
	else
		reg_mask = B_AX_XTAL_SC_XI_MASK;

	return (u8)rtw89_read32_mask(rtwdev, R_AX_XTAL_ON_CTRL0, reg_mask);
}

static void rtw89_phy_cfo_set_xcap_reg(struct rtw89_dev *rtwdev, bool sc_xo,
				       u8 val)
{
	u32 reg_mask;

	if (sc_xo)
		reg_mask = B_AX_XTAL_SC_XO_MASK;
	else
		reg_mask = B_AX_XTAL_SC_XI_MASK;

	rtw89_write32_mask(rtwdev, R_AX_XTAL_ON_CTRL0, reg_mask, val);
}

static void rtw89_phy_cfo_set_crystal_cap(struct rtw89_dev *rtwdev,
					  u8 crystal_cap, bool force)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	const struct rtw89_chip_info *chip = rtwdev->chip;
	u8 sc_xi_val, sc_xo_val;

	if (!force && cfo->crystal_cap == crystal_cap)
		return;
	crystal_cap = clamp_t(u8, crystal_cap, 0, 127);
	if (chip->chip_id == RTL8852A) {
		rtw89_phy_cfo_set_xcap_reg(rtwdev, true, crystal_cap);
		rtw89_phy_cfo_set_xcap_reg(rtwdev, false, crystal_cap);
		sc_xo_val = rtw89_phy_cfo_get_xcap_reg(rtwdev, true);
		sc_xi_val = rtw89_phy_cfo_get_xcap_reg(rtwdev, false);
	} else {
		rtw89_mac_write_xtal_si(rtwdev, XTAL_SI_XTAL_SC_XO,
					crystal_cap, XTAL_SC_XO_MASK);
		rtw89_mac_write_xtal_si(rtwdev, XTAL_SI_XTAL_SC_XI,
					crystal_cap, XTAL_SC_XI_MASK);
		rtw89_mac_read_xtal_si(rtwdev, XTAL_SI_XTAL_SC_XO, &sc_xo_val);
		rtw89_mac_read_xtal_si(rtwdev, XTAL_SI_XTAL_SC_XI, &sc_xi_val);
	}
	cfo->crystal_cap = sc_xi_val;
	cfo->x_cap_ofst = (s8)((int)cfo->crystal_cap - cfo->def_x_cap);

	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Set sc_xi=0x%x\n", sc_xi_val);
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Set sc_xo=0x%x\n", sc_xo_val);
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Get xcap_ofst=%d\n",
		    cfo->x_cap_ofst);
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Set xcap OK\n");
}

static void rtw89_phy_cfo_reset(struct rtw89_dev *rtwdev)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	u8 cap;

	cfo->def_x_cap = cfo->crystal_cap_default & B_AX_XTAL_SC_MASK;
	cfo->is_adjust = false;
	if (cfo->crystal_cap == cfo->def_x_cap)
		return;
	cap = cfo->crystal_cap;
	cap += (cap > cfo->def_x_cap ? -1 : 1);
	rtw89_phy_cfo_set_crystal_cap(rtwdev, cap, false);
	rtw89_debug(rtwdev, RTW89_DBG_CFO,
		    "(0x%x) approach to dflt_val=(0x%x)\n", cfo->crystal_cap,
		    cfo->def_x_cap);
}

static void rtw89_dcfo_comp(struct rtw89_dev *rtwdev, s32 curr_cfo)
{
	const struct rtw89_reg_def *dcfo_comp = rtwdev->chip->dcfo_comp;
	bool is_linked = rtwdev->total_sta_assoc > 0;
	s32 cfo_avg_312;
	s32 dcfo_comp_val;
	int sign;

	if (!is_linked) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "DCFO: is_linked=%d\n",
			    is_linked);
		return;
	}
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "DCFO: curr_cfo=%d\n", curr_cfo);
	if (curr_cfo == 0)
		return;
	dcfo_comp_val = rtw89_phy_read32_mask(rtwdev, R_DCFO, B_DCFO);
	sign = curr_cfo > 0 ? 1 : -1;
	cfo_avg_312 = curr_cfo / 625 + sign * dcfo_comp_val;
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "avg_cfo_312=%d step\n", cfo_avg_312);
	if (rtwdev->chip->chip_id == RTL8852A && rtwdev->hal.cv == CHIP_CBV)
		cfo_avg_312 = -cfo_avg_312;
	rtw89_phy_set_phy_regs(rtwdev, dcfo_comp->addr, dcfo_comp->mask,
			       cfo_avg_312);
}

static void rtw89_dcfo_comp_init(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;

	rtw89_phy_set_phy_regs(rtwdev, R_DCFO_OPT, B_DCFO_OPT_EN, 1);
	rtw89_phy_set_phy_regs(rtwdev, R_DCFO_WEIGHT, B_DCFO_WEIGHT_MSK, 8);

	if (chip->cfo_hw_comp)
		rtw89_write32_mask(rtwdev, R_AX_PWR_UL_CTRL2,
				   B_AX_PWR_UL_CFO_MASK, 0x6);
	else
		rtw89_write32_clr(rtwdev, R_AX_PWR_UL_CTRL2, B_AX_PWR_UL_CFO_MASK);
}

static void rtw89_phy_cfo_init(struct rtw89_dev *rtwdev)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	struct rtw89_efuse *efuse = &rtwdev->efuse;

	cfo->crystal_cap_default = efuse->xtal_cap & B_AX_XTAL_SC_MASK;
	cfo->crystal_cap = cfo->crystal_cap_default;
	cfo->def_x_cap = cfo->crystal_cap;
	cfo->x_cap_ub = min_t(int, cfo->def_x_cap + CFO_BOUND, 0x7f);
	cfo->x_cap_lb = max_t(int, cfo->def_x_cap - CFO_BOUND, 0x1);
	cfo->is_adjust = false;
	cfo->divergence_lock_en = false;
	cfo->x_cap_ofst = 0;
	cfo->lock_cnt = 0;
	cfo->rtw89_multi_cfo_mode = RTW89_TP_BASED_AVG_MODE;
	cfo->apply_compensation = false;
	cfo->residual_cfo_acc = 0;
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Default xcap=%0x\n",
		    cfo->crystal_cap_default);
	rtw89_phy_cfo_set_crystal_cap(rtwdev, cfo->crystal_cap_default, true);
	rtw89_phy_set_phy_regs(rtwdev, R_DCFO, B_DCFO, 1);
	rtw89_dcfo_comp_init(rtwdev);
	cfo->cfo_timer_ms = 2000;
	cfo->cfo_trig_by_timer_en = false;
	cfo->phy_cfo_trk_cnt = 0;
	cfo->phy_cfo_status = RTW89_PHY_DCFO_STATE_NORMAL;
	cfo->cfo_ul_ofdma_acc_mode = RTW89_CFO_UL_OFDMA_ACC_ENABLE;
}

static void rtw89_phy_cfo_crystal_cap_adjust(struct rtw89_dev *rtwdev,
					     s32 curr_cfo)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	s8 crystal_cap = cfo->crystal_cap;
	s32 cfo_abs = abs(curr_cfo);
	int sign;

	if (!cfo->is_adjust) {
		if (cfo_abs > CFO_TRK_ENABLE_TH)
			cfo->is_adjust = true;
	} else {
		if (cfo_abs < CFO_TRK_STOP_TH)
			cfo->is_adjust = false;
	}
	if (!cfo->is_adjust) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "Stop CFO tracking\n");
		return;
	}
	sign = curr_cfo > 0 ? 1 : -1;
	if (cfo_abs > CFO_TRK_STOP_TH_4)
		crystal_cap += 7 * sign;
	else if (cfo_abs > CFO_TRK_STOP_TH_3)
		crystal_cap += 5 * sign;
	else if (cfo_abs > CFO_TRK_STOP_TH_2)
		crystal_cap += 3 * sign;
	else if (cfo_abs > CFO_TRK_STOP_TH_1)
		crystal_cap += 1 * sign;
	else
		return;
	rtw89_phy_cfo_set_crystal_cap(rtwdev, (u8)crystal_cap, false);
	rtw89_debug(rtwdev, RTW89_DBG_CFO,
		    "X_cap{Curr,Default}={0x%x,0x%x}\n",
		    cfo->crystal_cap, cfo->def_x_cap);
}

static s32 rtw89_phy_average_cfo_calc(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	s32 cfo_khz_all = 0;
	s32 cfo_cnt_all = 0;
	s32 cfo_all_avg = 0;
	u8 i;

	if (rtwdev->total_sta_assoc != 1)
		return 0;
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "one_entry_only\n");
	for (i = 0; i < CFO_TRACK_MAX_USER; i++) {
		if (cfo->cfo_cnt[i] == 0)
			continue;
		cfo_khz_all += cfo->cfo_tail[i];
		cfo_cnt_all += cfo->cfo_cnt[i];
		cfo_all_avg = phy_div(cfo_khz_all, cfo_cnt_all);
		cfo->pre_cfo_avg[i] = cfo->cfo_avg[i];
		cfo->dcfo_avg = phy_div(cfo_khz_all << chip->dcfo_comp_sft,
					cfo_cnt_all);
	}
	rtw89_debug(rtwdev, RTW89_DBG_CFO,
		    "CFO track for macid = %d\n", i);
	rtw89_debug(rtwdev, RTW89_DBG_CFO,
		    "Total cfo=%dK, pkt_cnt=%d, avg_cfo=%dK\n",
		    cfo_khz_all, cfo_cnt_all, cfo_all_avg);
	return cfo_all_avg;
}

static s32 rtw89_phy_multi_sta_cfo_calc(struct rtw89_dev *rtwdev)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	struct rtw89_traffic_stats *stats = &rtwdev->stats;
	s32 target_cfo = 0;
	s32 cfo_khz_all = 0;
	s32 cfo_khz_all_tp_wgt = 0;
	s32 cfo_avg = 0;
	s32 max_cfo_lb = BIT(31);
	s32 min_cfo_ub = GENMASK(30, 0);
	u16 cfo_cnt_all = 0;
	u8 active_entry_cnt = 0;
	u8 sta_cnt = 0;
	u32 tp_all = 0;
	u8 i;
	u8 cfo_tol = 0;

	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Multi entry cfo_trk\n");
	if (cfo->rtw89_multi_cfo_mode == RTW89_PKT_BASED_AVG_MODE) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "Pkt based avg mode\n");
		for (i = 0; i < CFO_TRACK_MAX_USER; i++) {
			if (cfo->cfo_cnt[i] == 0)
				continue;
			cfo_khz_all += cfo->cfo_tail[i];
			cfo_cnt_all += cfo->cfo_cnt[i];
			cfo_avg = phy_div(cfo_khz_all, (s32)cfo_cnt_all);
			rtw89_debug(rtwdev, RTW89_DBG_CFO,
				    "Msta cfo=%d, pkt_cnt=%d, avg_cfo=%d\n",
				    cfo_khz_all, cfo_cnt_all, cfo_avg);
			target_cfo = cfo_avg;
		}
	} else if (cfo->rtw89_multi_cfo_mode == RTW89_ENTRY_BASED_AVG_MODE) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "Entry based avg mode\n");
		for (i = 0; i < CFO_TRACK_MAX_USER; i++) {
			if (cfo->cfo_cnt[i] == 0)
				continue;
			cfo->cfo_avg[i] = phy_div(cfo->cfo_tail[i],
						  (s32)cfo->cfo_cnt[i]);
			cfo_khz_all += cfo->cfo_avg[i];
			rtw89_debug(rtwdev, RTW89_DBG_CFO,
				    "Macid=%d, cfo_avg=%d\n", i,
				    cfo->cfo_avg[i]);
		}
		sta_cnt = rtwdev->total_sta_assoc;
		cfo_avg = phy_div(cfo_khz_all, (s32)sta_cnt);
		rtw89_debug(rtwdev, RTW89_DBG_CFO,
			    "Msta cfo_acc=%d, ent_cnt=%d, avg_cfo=%d\n",
			    cfo_khz_all, sta_cnt, cfo_avg);
		target_cfo = cfo_avg;
	} else if (cfo->rtw89_multi_cfo_mode == RTW89_TP_BASED_AVG_MODE) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "TP based avg mode\n");
		cfo_tol = cfo->sta_cfo_tolerance;
		for (i = 0; i < CFO_TRACK_MAX_USER; i++) {
			sta_cnt++;
			if (cfo->cfo_cnt[i] != 0) {
				cfo->cfo_avg[i] = phy_div(cfo->cfo_tail[i],
							  (s32)cfo->cfo_cnt[i]);
				active_entry_cnt++;
			} else {
				cfo->cfo_avg[i] = cfo->pre_cfo_avg[i];
			}
			max_cfo_lb = max(cfo->cfo_avg[i] - cfo_tol, max_cfo_lb);
			min_cfo_ub = min(cfo->cfo_avg[i] + cfo_tol, min_cfo_ub);
			cfo_khz_all += cfo->cfo_avg[i];
			/* need tp for each entry */
			rtw89_debug(rtwdev, RTW89_DBG_CFO,
				    "[%d] cfo_avg=%d, tp=tbd\n",
				    i, cfo->cfo_avg[i]);
			if (sta_cnt >= rtwdev->total_sta_assoc)
				break;
		}
		tp_all = stats->rx_throughput; /* need tp for each entry */
		cfo_avg =  phy_div(cfo_khz_all_tp_wgt, (s32)tp_all);

		rtw89_debug(rtwdev, RTW89_DBG_CFO, "Assoc sta cnt=%d\n",
			    sta_cnt);
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "Active sta cnt=%d\n",
			    active_entry_cnt);
		rtw89_debug(rtwdev, RTW89_DBG_CFO,
			    "Msta cfo with tp_wgt=%d, avg_cfo=%d\n",
			    cfo_khz_all_tp_wgt, cfo_avg);
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "cfo_lb=%d,cfo_ub=%d\n",
			    max_cfo_lb, min_cfo_ub);
		if (max_cfo_lb <= min_cfo_ub) {
			rtw89_debug(rtwdev, RTW89_DBG_CFO,
				    "cfo win_size=%d\n",
				    min_cfo_ub - max_cfo_lb);
			target_cfo = clamp(cfo_avg, max_cfo_lb, min_cfo_ub);
		} else {
			rtw89_debug(rtwdev, RTW89_DBG_CFO,
				    "No intersection of cfo tolerance windows\n");
			target_cfo = phy_div(cfo_khz_all, (s32)sta_cnt);
		}
		for (i = 0; i < CFO_TRACK_MAX_USER; i++)
			cfo->pre_cfo_avg[i] = cfo->cfo_avg[i];
	}
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Target cfo=%d\n", target_cfo);
	return target_cfo;
}

static void rtw89_phy_cfo_statistics_reset(struct rtw89_dev *rtwdev)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;

	memset(&cfo->cfo_tail, 0, sizeof(cfo->cfo_tail));
	memset(&cfo->cfo_cnt, 0, sizeof(cfo->cfo_cnt));
	cfo->packet_count = 0;
	cfo->packet_count_pre = 0;
	cfo->cfo_avg_pre = 0;
}

static void rtw89_phy_cfo_dm(struct rtw89_dev *rtwdev)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	s32 new_cfo = 0;
	bool x_cap_update = false;
	u8 pre_x_cap = cfo->crystal_cap;
	u8 dcfo_comp_sft = rtwdev->chip->dcfo_comp_sft;

	cfo->dcfo_avg = 0;
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "CFO:total_sta_assoc=%d\n",
		    rtwdev->total_sta_assoc);
	if (rtwdev->total_sta_assoc == 0) {
		rtw89_phy_cfo_reset(rtwdev);
		return;
	}
	if (cfo->packet_count == 0) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "Pkt cnt = 0\n");
		return;
	}
	if (cfo->packet_count == cfo->packet_count_pre) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "Pkt cnt doesn't change\n");
		return;
	}
	if (rtwdev->total_sta_assoc == 1)
		new_cfo = rtw89_phy_average_cfo_calc(rtwdev);
	else
		new_cfo = rtw89_phy_multi_sta_cfo_calc(rtwdev);
	if (new_cfo == 0) {
		rtw89_debug(rtwdev, RTW89_DBG_CFO, "curr_cfo=0\n");
		return;
	}
	if (cfo->divergence_lock_en) {
		cfo->lock_cnt++;
		if (cfo->lock_cnt > CFO_PERIOD_CNT) {
			cfo->divergence_lock_en = false;
			cfo->lock_cnt = 0;
		} else {
			rtw89_phy_cfo_reset(rtwdev);
		}
		return;
	}
	if (cfo->crystal_cap >= cfo->x_cap_ub ||
	    cfo->crystal_cap <= cfo->x_cap_lb) {
		cfo->divergence_lock_en = true;
		rtw89_phy_cfo_reset(rtwdev);
		return;
	}

	rtw89_phy_cfo_crystal_cap_adjust(rtwdev, new_cfo);
	cfo->cfo_avg_pre = new_cfo;
	cfo->dcfo_avg_pre = cfo->dcfo_avg;
	x_cap_update =  cfo->crystal_cap != pre_x_cap;
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Xcap_up=%d\n", x_cap_update);
	rtw89_debug(rtwdev, RTW89_DBG_CFO, "Xcap: D:%x C:%x->%x, ofst=%d\n",
		    cfo->def_x_cap, pre_x_cap, cfo->crystal_cap,
		    cfo->x_cap_ofst);
	if (x_cap_update) {
		if (cfo->dcfo_avg > 0)
			cfo->dcfo_avg -= CFO_SW_COMP_FINE_TUNE << dcfo_comp_sft;
		else
			cfo->dcfo_avg += CFO_SW_COMP_FINE_TUNE << dcfo_comp_sft;
	}
	rtw89_dcfo_comp(rtwdev, cfo->dcfo_avg);
	rtw89_phy_cfo_statistics_reset(rtwdev);
}

void rtw89_phy_cfo_track_work(struct work_struct *work)
{
	struct rtw89_dev *rtwdev = container_of(work, struct rtw89_dev,
						cfo_track_work.work);
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;

	mutex_lock(&rtwdev->mutex);
	if (!cfo->cfo_trig_by_timer_en)
		goto out;
	rtw89_leave_ps_mode(rtwdev);
	rtw89_phy_cfo_dm(rtwdev);
	ieee80211_queue_delayed_work(rtwdev->hw, &rtwdev->cfo_track_work,
				     msecs_to_jiffies(cfo->cfo_timer_ms));
out:
	mutex_unlock(&rtwdev->mutex);
}

static void rtw89_phy_cfo_start_work(struct rtw89_dev *rtwdev)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;

	ieee80211_queue_delayed_work(rtwdev->hw, &rtwdev->cfo_track_work,
				     msecs_to_jiffies(cfo->cfo_timer_ms));
}

void rtw89_phy_cfo_track(struct rtw89_dev *rtwdev)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	struct rtw89_traffic_stats *stats = &rtwdev->stats;
	bool is_ul_ofdma = false, ofdma_acc_en = false;

	if (stats->rx_tf_periodic > CFO_TF_CNT_TH)
		is_ul_ofdma = true;
	if (cfo->cfo_ul_ofdma_acc_mode == RTW89_CFO_UL_OFDMA_ACC_ENABLE &&
	    is_ul_ofdma)
		ofdma_acc_en = true;

	switch (cfo->phy_cfo_status) {
	case RTW89_PHY_DCFO_STATE_NORMAL:
		if (stats->tx_throughput >= CFO_TP_UPPER) {
			cfo->phy_cfo_status = RTW89_PHY_DCFO_STATE_ENHANCE;
			cfo->cfo_trig_by_timer_en = true;
			cfo->cfo_timer_ms = CFO_COMP_PERIOD;
			rtw89_phy_cfo_start_work(rtwdev);
		}
		break;
	case RTW89_PHY_DCFO_STATE_ENHANCE:
		if (stats->tx_throughput <= CFO_TP_LOWER)
			cfo->phy_cfo_status = RTW89_PHY_DCFO_STATE_NORMAL;
		else if (ofdma_acc_en &&
			 cfo->phy_cfo_trk_cnt >= CFO_PERIOD_CNT)
			cfo->phy_cfo_status = RTW89_PHY_DCFO_STATE_HOLD;
		else
			cfo->phy_cfo_trk_cnt++;

		if (cfo->phy_cfo_status == RTW89_PHY_DCFO_STATE_NORMAL) {
			cfo->phy_cfo_trk_cnt = 0;
			cfo->cfo_trig_by_timer_en = false;
		}
		break;
	case RTW89_PHY_DCFO_STATE_HOLD:
		if (stats->tx_throughput <= CFO_TP_LOWER) {
			cfo->phy_cfo_status = RTW89_PHY_DCFO_STATE_NORMAL;
			cfo->phy_cfo_trk_cnt = 0;
			cfo->cfo_trig_by_timer_en = false;
		} else {
			cfo->phy_cfo_trk_cnt++;
		}
		break;
	default:
		cfo->phy_cfo_status = RTW89_PHY_DCFO_STATE_NORMAL;
		cfo->phy_cfo_trk_cnt = 0;
		break;
	}
	rtw89_debug(rtwdev, RTW89_DBG_CFO,
		    "[CFO]WatchDog tp=%d,state=%d,timer_en=%d,trk_cnt=%d,thermal=%ld\n",
		    stats->tx_throughput, cfo->phy_cfo_status,
		    cfo->cfo_trig_by_timer_en, cfo->phy_cfo_trk_cnt,
		    ewma_thermal_read(&rtwdev->phystat.avg_thermal[0]));
	if (cfo->cfo_trig_by_timer_en)
		return;
	rtw89_phy_cfo_dm(rtwdev);
}

void rtw89_phy_cfo_parse(struct rtw89_dev *rtwdev, s16 cfo_val,
			 struct rtw89_rx_phy_ppdu *phy_ppdu)
{
	struct rtw89_cfo_tracking_info *cfo = &rtwdev->cfo_tracking;
	u8 macid = phy_ppdu->mac_id;

	if (macid >= CFO_TRACK_MAX_USER) {
		rtw89_warn(rtwdev, "mac_id %d is out of range\n", macid);
		return;
	}

	cfo->cfo_tail[macid] += cfo_val;
	cfo->cfo_cnt[macid]++;
	cfo->packet_count++;
}

void rtw89_phy_ul_tb_assoc(struct rtw89_dev *rtwdev, struct rtw89_vif *rtwvif)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_SUB_ENTITY_0);
	struct rtw89_phy_ul_tb_info *ul_tb_info = &rtwdev->ul_tb_info;

	if (!chip->support_ul_tb_ctrl)
		return;

	rtwvif->def_tri_idx =
		rtw89_phy_read32_mask(rtwdev, R_DCFO_OPT, B_TXSHAPE_TRIANGULAR_CFG);

	if (chip->chip_id == RTL8852B && rtwdev->hal.cv > CHIP_CBV)
		rtwvif->dyn_tb_bedge_en = false;
	else if (chan->band_type >= RTW89_BAND_5G &&
		 chan->band_width >= RTW89_CHANNEL_WIDTH_40)
		rtwvif->dyn_tb_bedge_en = true;
	else
		rtwvif->dyn_tb_bedge_en = false;

	rtw89_debug(rtwdev, RTW89_DBG_UL_TB,
		    "[ULTB] def_if_bandedge=%d, def_tri_idx=%d\n",
		    ul_tb_info->def_if_bandedge, rtwvif->def_tri_idx);
	rtw89_debug(rtwdev, RTW89_DBG_UL_TB,
		    "[ULTB] dyn_tb_begde_en=%d, dyn_tb_tri_en=%d\n",
		    rtwvif->dyn_tb_bedge_en, ul_tb_info->dyn_tb_tri_en);
}

struct rtw89_phy_ul_tb_check_data {
	bool valid;
	bool high_tf_client;
	bool low_tf_client;
	bool dyn_tb_bedge_en;
	u8 def_tri_idx;
};

static
void rtw89_phy_ul_tb_ctrl_check(struct rtw89_dev *rtwdev,
				struct rtw89_vif *rtwvif,
				struct rtw89_phy_ul_tb_check_data *ul_tb_data)
{
	struct rtw89_traffic_stats *stats = &rtwdev->stats;
	struct ieee80211_vif *vif = rtwvif_to_vif(rtwvif);

	if (rtwvif->wifi_role != RTW89_WIFI_ROLE_STATION)
		return;

	if (!vif->cfg.assoc)
		return;

	if (stats->rx_tf_periodic > UL_TB_TF_CNT_L2H_TH)
		ul_tb_data->high_tf_client = true;
	else if (stats->rx_tf_periodic < UL_TB_TF_CNT_H2L_TH)
		ul_tb_data->low_tf_client = true;

	ul_tb_data->valid = true;
	ul_tb_data->def_tri_idx = rtwvif->def_tri_idx;
	ul_tb_data->dyn_tb_bedge_en = rtwvif->dyn_tb_bedge_en;
}

void rtw89_phy_ul_tb_ctrl_track(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	struct rtw89_phy_ul_tb_info *ul_tb_info = &rtwdev->ul_tb_info;
	struct rtw89_phy_ul_tb_check_data ul_tb_data = {};
	struct rtw89_vif *rtwvif;

	if (!chip->support_ul_tb_ctrl)
		return;

	if (rtwdev->total_sta_assoc != 1)
		return;

	rtw89_for_each_rtwvif(rtwdev, rtwvif)
		rtw89_phy_ul_tb_ctrl_check(rtwdev, rtwvif, &ul_tb_data);

	if (!ul_tb_data.valid)
		return;

	if (ul_tb_data.dyn_tb_bedge_en) {
		if (ul_tb_data.high_tf_client) {
			rtw89_phy_write32_mask(rtwdev, R_BANDEDGE, B_BANDEDGE_EN, 0);
			rtw89_debug(rtwdev, RTW89_DBG_UL_TB,
				    "[ULTB] Turn off if_bandedge\n");
		} else if (ul_tb_data.low_tf_client) {
			rtw89_phy_write32_mask(rtwdev, R_BANDEDGE, B_BANDEDGE_EN,
					       ul_tb_info->def_if_bandedge);
			rtw89_debug(rtwdev, RTW89_DBG_UL_TB,
				    "[ULTB] Set to default if_bandedge = %d\n",
				    ul_tb_info->def_if_bandedge);
		}
	}

	if (ul_tb_info->dyn_tb_tri_en) {
		if (ul_tb_data.high_tf_client) {
			rtw89_phy_write32_mask(rtwdev, R_DCFO_OPT,
					       B_TXSHAPE_TRIANGULAR_CFG, 0);
			rtw89_debug(rtwdev, RTW89_DBG_UL_TB,
				    "[ULTB] Turn off Tx triangle\n");
		} else if (ul_tb_data.low_tf_client) {
			rtw89_phy_write32_mask(rtwdev, R_DCFO_OPT,
					       B_TXSHAPE_TRIANGULAR_CFG,
					       ul_tb_data.def_tri_idx);
			rtw89_debug(rtwdev, RTW89_DBG_UL_TB,
				    "[ULTB] Set to default tx_shap_idx = %d\n",
				    ul_tb_data.def_tri_idx);
		}
	}
}

static void rtw89_phy_ul_tb_info_init(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	struct rtw89_phy_ul_tb_info *ul_tb_info = &rtwdev->ul_tb_info;

	if (!chip->support_ul_tb_ctrl)
		return;

	ul_tb_info->dyn_tb_tri_en = true;
	ul_tb_info->def_if_bandedge =
		rtw89_phy_read32_mask(rtwdev, R_BANDEDGE, B_BANDEDGE_EN);
}

static void rtw89_phy_stat_thermal_update(struct rtw89_dev *rtwdev)
{
	struct rtw89_phy_stat *phystat = &rtwdev->phystat;
	int i;
	u8 th;

	for (i = 0; i < rtwdev->chip->rf_path_num; i++) {
		th = rtw89_chip_get_thermal(rtwdev, i);
		if (th)
			ewma_thermal_add(&phystat->avg_thermal[i], th);

		rtw89_debug(rtwdev, RTW89_DBG_RFK_TRACK,
			    "path(%d) thermal cur=%u avg=%ld", i, th,
			    ewma_thermal_read(&phystat->avg_thermal[i]));
	}
}

struct rtw89_phy_iter_rssi_data {
	struct rtw89_dev *rtwdev;
	struct rtw89_phy_ch_info *ch_info;
	bool rssi_changed;
};

static void rtw89_phy_stat_rssi_update_iter(void *data,
					    struct ieee80211_sta *sta)
{
	struct rtw89_sta *rtwsta = (struct rtw89_sta *)sta->drv_priv;
	struct rtw89_phy_iter_rssi_data *rssi_data =
					(struct rtw89_phy_iter_rssi_data *)data;
	struct rtw89_phy_ch_info *ch_info = rssi_data->ch_info;
	unsigned long rssi_curr;

	rssi_curr = ewma_rssi_read(&rtwsta->avg_rssi);

	if (rssi_curr < ch_info->rssi_min) {
		ch_info->rssi_min = rssi_curr;
		ch_info->rssi_min_macid = rtwsta->mac_id;
	}

	if (rtwsta->prev_rssi == 0) {
		rtwsta->prev_rssi = rssi_curr;
	} else if (abs((int)rtwsta->prev_rssi - (int)rssi_curr) > (3 << RSSI_FACTOR)) {
		rtwsta->prev_rssi = rssi_curr;
		rssi_data->rssi_changed = true;
	}
}

static void rtw89_phy_stat_rssi_update(struct rtw89_dev *rtwdev)
{
	struct rtw89_phy_iter_rssi_data rssi_data = {0};

	rssi_data.rtwdev = rtwdev;
	rssi_data.ch_info = &rtwdev->ch_info;
	rssi_data.ch_info->rssi_min = U8_MAX;
	ieee80211_iterate_stations_atomic(rtwdev->hw,
					  rtw89_phy_stat_rssi_update_iter,
					  &rssi_data);
	if (rssi_data.rssi_changed)
		rtw89_btc_ntfy_wl_sta(rtwdev);
}

static void rtw89_phy_stat_init(struct rtw89_dev *rtwdev)
{
	struct rtw89_phy_stat *phystat = &rtwdev->phystat;
	int i;

	for (i = 0; i < rtwdev->chip->rf_path_num; i++)
		ewma_thermal_init(&phystat->avg_thermal[i]);

	rtw89_phy_stat_thermal_update(rtwdev);

	memset(&phystat->cur_pkt_stat, 0, sizeof(phystat->cur_pkt_stat));
	memset(&phystat->last_pkt_stat, 0, sizeof(phystat->last_pkt_stat));
}

void rtw89_phy_stat_track(struct rtw89_dev *rtwdev)
{
	struct rtw89_phy_stat *phystat = &rtwdev->phystat;

	rtw89_phy_stat_thermal_update(rtwdev);
	rtw89_phy_stat_rssi_update(rtwdev);

	phystat->last_pkt_stat = phystat->cur_pkt_stat;
	memset(&phystat->cur_pkt_stat, 0, sizeof(phystat->cur_pkt_stat));
}

static u16 rtw89_phy_ccx_us_to_idx(struct rtw89_dev *rtwdev, u32 time_us)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;

	return time_us >> (ilog2(CCX_US_BASE_RATIO) + env->ccx_unit_idx);
}

static u32 rtw89_phy_ccx_idx_to_us(struct rtw89_dev *rtwdev, u16 idx)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;

	return idx << (ilog2(CCX_US_BASE_RATIO) + env->ccx_unit_idx);
}

static void rtw89_phy_ccx_top_setting_init(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;

	env->ccx_manual_ctrl = false;
	env->ccx_ongoing = false;
	env->ccx_rac_lv = RTW89_RAC_RELEASE;
	env->ccx_rpt_stamp = 0;
	env->ccx_period = 0;
	env->ccx_unit_idx = RTW89_CCX_32_US;
	env->ccx_trigger_time = 0;
	env->ccx_edcca_opt_bw_idx = RTW89_CCX_EDCCA_BW20_0;

	rtw89_phy_set_phy_regs(rtwdev, R_CCX, B_CCX_EN_MSK, 1);
	rtw89_phy_set_phy_regs(rtwdev, R_CCX, B_CCX_TRIG_OPT_MSK, 1);
	rtw89_phy_set_phy_regs(rtwdev, R_CCX, B_MEASUREMENT_TRIG_MSK, 1);
	rtw89_phy_set_phy_regs(rtwdev, R_CCX, B_CCX_EDCCA_OPT_MSK,
			       RTW89_CCX_EDCCA_BW20_0);
}

static u16 rtw89_phy_ccx_get_report(struct rtw89_dev *rtwdev, u16 report,
				    u16 score)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	u32 numer = 0;
	u16 ret = 0;

	numer = report * score + (env->ccx_period >> 1);
	if (env->ccx_period)
		ret = numer / env->ccx_period;

	return ret >= score ? score - 1 : ret;
}

static void rtw89_phy_ccx_ms_to_period_unit(struct rtw89_dev *rtwdev,
					    u16 time_ms, u32 *period,
					    u32 *unit_idx)
{
	u32 idx;
	u8 quotient;

	if (time_ms >= CCX_MAX_PERIOD)
		time_ms = CCX_MAX_PERIOD;

	quotient = CCX_MAX_PERIOD_UNIT * time_ms / CCX_MAX_PERIOD;

	if (quotient < 4)
		idx = RTW89_CCX_4_US;
	else if (quotient < 8)
		idx = RTW89_CCX_8_US;
	else if (quotient < 16)
		idx = RTW89_CCX_16_US;
	else
		idx = RTW89_CCX_32_US;

	*unit_idx = idx;
	*period = (time_ms * MS_TO_4US_RATIO) >> idx;

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "[Trigger Time] period:%d, unit_idx:%d\n",
		    *period, *unit_idx);
}

static void rtw89_phy_ccx_racing_release(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "lv:(%d)->(0)\n", env->ccx_rac_lv);

	env->ccx_ongoing = false;
	env->ccx_rac_lv = RTW89_RAC_RELEASE;
	env->ifs_clm_app = RTW89_IFS_CLM_BACKGROUND;
}

static bool rtw89_phy_ifs_clm_th_update_check(struct rtw89_dev *rtwdev,
					      struct rtw89_ccx_para_info *para)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	bool is_update = env->ifs_clm_app != para->ifs_clm_app;
	u8 i = 0;
	u16 *ifs_th_l = env->ifs_clm_th_l;
	u16 *ifs_th_h = env->ifs_clm_th_h;
	u32 ifs_th0_us = 0, ifs_th_times = 0;
	u32 ifs_th_h_us[RTW89_IFS_CLM_NUM] = {0};

	if (!is_update)
		goto ifs_update_finished;

	switch (para->ifs_clm_app) {
	case RTW89_IFS_CLM_INIT:
	case RTW89_IFS_CLM_BACKGROUND:
	case RTW89_IFS_CLM_ACS:
	case RTW89_IFS_CLM_DBG:
	case RTW89_IFS_CLM_DIG:
	case RTW89_IFS_CLM_TDMA_DIG:
		ifs_th0_us = IFS_CLM_TH0_UPPER;
		ifs_th_times = IFS_CLM_TH_MUL;
		break;
	case RTW89_IFS_CLM_DBG_MANUAL:
		ifs_th0_us = para->ifs_clm_manual_th0;
		ifs_th_times = para->ifs_clm_manual_th_times;
		break;
	default:
		break;
	}

	/* Set sampling threshold for 4 different regions, unit in idx_cnt.
	 * low[i] = high[i-1] + 1
	 * high[i] = high[i-1] * ifs_th_times
	 */
	ifs_th_l[IFS_CLM_TH_START_IDX] = 0;
	ifs_th_h_us[IFS_CLM_TH_START_IDX] = ifs_th0_us;
	ifs_th_h[IFS_CLM_TH_START_IDX] = rtw89_phy_ccx_us_to_idx(rtwdev,
								 ifs_th0_us);
	for (i = 1; i < RTW89_IFS_CLM_NUM; i++) {
		ifs_th_l[i] = ifs_th_h[i - 1] + 1;
		ifs_th_h_us[i] = ifs_th_h_us[i - 1] * ifs_th_times;
		ifs_th_h[i] = rtw89_phy_ccx_us_to_idx(rtwdev, ifs_th_h_us[i]);
	}

ifs_update_finished:
	if (!is_update)
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "No need to update IFS_TH\n");

	return is_update;
}

static void rtw89_phy_ifs_clm_set_th_reg(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	u8 i = 0;

	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T1, B_IFS_T1_TH_LOW_MSK,
			       env->ifs_clm_th_l[0]);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T2, B_IFS_T2_TH_LOW_MSK,
			       env->ifs_clm_th_l[1]);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T3, B_IFS_T3_TH_LOW_MSK,
			       env->ifs_clm_th_l[2]);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T4, B_IFS_T4_TH_LOW_MSK,
			       env->ifs_clm_th_l[3]);

	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T1, B_IFS_T1_TH_HIGH_MSK,
			       env->ifs_clm_th_h[0]);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T2, B_IFS_T2_TH_HIGH_MSK,
			       env->ifs_clm_th_h[1]);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T3, B_IFS_T3_TH_HIGH_MSK,
			       env->ifs_clm_th_h[2]);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T4, B_IFS_T4_TH_HIGH_MSK,
			       env->ifs_clm_th_h[3]);

	for (i = 0; i < RTW89_IFS_CLM_NUM; i++)
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "Update IFS_T%d_th{low, high} : {%d, %d}\n",
			    i + 1, env->ifs_clm_th_l[i], env->ifs_clm_th_h[i]);
}

static void rtw89_phy_ifs_clm_setting_init(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	struct rtw89_ccx_para_info para = {0};

	env->ifs_clm_app = RTW89_IFS_CLM_BACKGROUND;
	env->ifs_clm_mntr_time = 0;

	para.ifs_clm_app = RTW89_IFS_CLM_INIT;
	if (rtw89_phy_ifs_clm_th_update_check(rtwdev, &para))
		rtw89_phy_ifs_clm_set_th_reg(rtwdev);

	rtw89_phy_set_phy_regs(rtwdev, R_IFS_COUNTER, B_IFS_COLLECT_EN,
			       true);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T1, B_IFS_T1_EN_MSK, true);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T2, B_IFS_T2_EN_MSK, true);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T3, B_IFS_T3_EN_MSK, true);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_T4, B_IFS_T4_EN_MSK, true);
}

static int rtw89_phy_ccx_racing_ctrl(struct rtw89_dev *rtwdev,
				     enum rtw89_env_racing_lv level)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	int ret = 0;

	if (level >= RTW89_RAC_MAX_NUM) {
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "[WARNING] Wrong LV=%d\n", level);
		return -EINVAL;
	}

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "ccx_ongoing=%d, level:(%d)->(%d)\n", env->ccx_ongoing,
		    env->ccx_rac_lv, level);

	if (env->ccx_ongoing) {
		if (level <= env->ccx_rac_lv)
			ret = -EINVAL;
		else
			env->ccx_ongoing = false;
	}

	if (ret == 0)
		env->ccx_rac_lv = level;

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK, "ccx racing success=%d\n",
		    !ret);

	return ret;
}

static void rtw89_phy_ccx_trigger(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;

	rtw89_phy_set_phy_regs(rtwdev, R_IFS_COUNTER, B_IFS_COUNTER_CLR_MSK, 0);
	rtw89_phy_set_phy_regs(rtwdev, R_CCX, B_MEASUREMENT_TRIG_MSK, 0);
	rtw89_phy_set_phy_regs(rtwdev, R_IFS_COUNTER, B_IFS_COUNTER_CLR_MSK, 1);
	rtw89_phy_set_phy_regs(rtwdev, R_CCX, B_MEASUREMENT_TRIG_MSK, 1);

	env->ccx_rpt_stamp++;
	env->ccx_ongoing = true;
}

static void rtw89_phy_ifs_clm_get_utility(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	u8 i = 0;
	u32 res = 0;

	env->ifs_clm_tx_ratio =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_tx, PERCENT);
	env->ifs_clm_edcca_excl_cca_ratio =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_edcca_excl_cca,
					 PERCENT);
	env->ifs_clm_cck_fa_ratio =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_cckfa, PERCENT);
	env->ifs_clm_ofdm_fa_ratio =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_ofdmfa, PERCENT);
	env->ifs_clm_cck_cca_excl_fa_ratio =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_cckcca_excl_fa,
					 PERCENT);
	env->ifs_clm_ofdm_cca_excl_fa_ratio =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_ofdmcca_excl_fa,
					 PERCENT);
	env->ifs_clm_cck_fa_permil =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_cckfa, PERMIL);
	env->ifs_clm_ofdm_fa_permil =
		rtw89_phy_ccx_get_report(rtwdev, env->ifs_clm_ofdmfa, PERMIL);

	for (i = 0; i < RTW89_IFS_CLM_NUM; i++) {
		if (env->ifs_clm_his[i] > ENV_MNTR_IFSCLM_HIS_MAX) {
			env->ifs_clm_ifs_avg[i] = ENV_MNTR_FAIL_DWORD;
		} else {
			env->ifs_clm_ifs_avg[i] =
				rtw89_phy_ccx_idx_to_us(rtwdev,
							env->ifs_clm_avg[i]);
		}

		res = rtw89_phy_ccx_idx_to_us(rtwdev, env->ifs_clm_cca[i]);
		res += env->ifs_clm_his[i] >> 1;
		if (env->ifs_clm_his[i])
			res /= env->ifs_clm_his[i];
		else
			res = 0;
		env->ifs_clm_cca_avg[i] = res;
	}

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "IFS-CLM ratio {Tx, EDCCA_exclu_cca} = {%d, %d}\n",
		    env->ifs_clm_tx_ratio, env->ifs_clm_edcca_excl_cca_ratio);
	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "IFS-CLM FA ratio {CCK, OFDM} = {%d, %d}\n",
		    env->ifs_clm_cck_fa_ratio, env->ifs_clm_ofdm_fa_ratio);
	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "IFS-CLM FA permil {CCK, OFDM} = {%d, %d}\n",
		    env->ifs_clm_cck_fa_permil, env->ifs_clm_ofdm_fa_permil);
	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "IFS-CLM CCA_exclu_FA ratio {CCK, OFDM} = {%d, %d}\n",
		    env->ifs_clm_cck_cca_excl_fa_ratio,
		    env->ifs_clm_ofdm_cca_excl_fa_ratio);
	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "Time:[his, ifs_avg(us), cca_avg(us)]\n");
	for (i = 0; i < RTW89_IFS_CLM_NUM; i++)
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK, "T%d:[%d, %d, %d]\n",
			    i + 1, env->ifs_clm_his[i], env->ifs_clm_ifs_avg[i],
			    env->ifs_clm_cca_avg[i]);
}

static bool rtw89_phy_ifs_clm_get_result(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	u8 i = 0;

	if (rtw89_phy_read32_mask(rtwdev, R_IFSCNT, B_IFSCNT_DONE_MSK) == 0) {
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "Get IFS_CLM report Fail\n");
		return false;
	}

	env->ifs_clm_tx =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CLM_TX_CNT,
				      B_IFS_CLM_TX_CNT_MSK);
	env->ifs_clm_edcca_excl_cca =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CLM_TX_CNT,
				      B_IFS_CLM_EDCCA_EXCLUDE_CCA_FA_MSK);
	env->ifs_clm_cckcca_excl_fa =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CLM_CCA,
				      B_IFS_CLM_CCKCCA_EXCLUDE_FA_MSK);
	env->ifs_clm_ofdmcca_excl_fa =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CLM_CCA,
				      B_IFS_CLM_OFDMCCA_EXCLUDE_FA_MSK);
	env->ifs_clm_cckfa =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CLM_FA,
				      B_IFS_CLM_CCK_FA_MSK);
	env->ifs_clm_ofdmfa =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CLM_FA,
				      B_IFS_CLM_OFDM_FA_MSK);

	env->ifs_clm_his[0] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_HIS, B_IFS_T1_HIS_MSK);
	env->ifs_clm_his[1] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_HIS, B_IFS_T2_HIS_MSK);
	env->ifs_clm_his[2] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_HIS, B_IFS_T3_HIS_MSK);
	env->ifs_clm_his[3] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_HIS, B_IFS_T4_HIS_MSK);

	env->ifs_clm_avg[0] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_AVG_L, B_IFS_T1_AVG_MSK);
	env->ifs_clm_avg[1] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_AVG_L, B_IFS_T2_AVG_MSK);
	env->ifs_clm_avg[2] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_AVG_H, B_IFS_T3_AVG_MSK);
	env->ifs_clm_avg[3] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_AVG_H, B_IFS_T4_AVG_MSK);

	env->ifs_clm_cca[0] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CCA_L, B_IFS_T1_CCA_MSK);
	env->ifs_clm_cca[1] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CCA_L, B_IFS_T2_CCA_MSK);
	env->ifs_clm_cca[2] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CCA_H, B_IFS_T3_CCA_MSK);
	env->ifs_clm_cca[3] =
		rtw89_phy_read32_mask(rtwdev, R_IFS_CCA_H, B_IFS_T4_CCA_MSK);

	env->ifs_clm_total_ifs =
		rtw89_phy_read32_mask(rtwdev, R_IFSCNT, B_IFSCNT_TOTAL_CNT_MSK);

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK, "IFS-CLM total_ifs = %d\n",
		    env->ifs_clm_total_ifs);
	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "{Tx, EDCCA_exclu_cca} = {%d, %d}\n",
		    env->ifs_clm_tx, env->ifs_clm_edcca_excl_cca);
	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "IFS-CLM FA{CCK, OFDM} = {%d, %d}\n",
		    env->ifs_clm_cckfa, env->ifs_clm_ofdmfa);
	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "IFS-CLM CCA_exclu_FA{CCK, OFDM} = {%d, %d}\n",
		    env->ifs_clm_cckcca_excl_fa, env->ifs_clm_ofdmcca_excl_fa);

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK, "Time:[his, avg, cca]\n");
	for (i = 0; i < RTW89_IFS_CLM_NUM; i++)
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "T%d:[%d, %d, %d]\n", i + 1, env->ifs_clm_his[i],
			    env->ifs_clm_avg[i], env->ifs_clm_cca[i]);

	rtw89_phy_ifs_clm_get_utility(rtwdev);

	return true;
}

static int rtw89_phy_ifs_clm_set(struct rtw89_dev *rtwdev,
				 struct rtw89_ccx_para_info *para)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	u32 period = 0;
	u32 unit_idx = 0;

	if (para->mntr_time == 0) {
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "[WARN] MNTR_TIME is 0\n");
		return -EINVAL;
	}

	if (rtw89_phy_ccx_racing_ctrl(rtwdev, para->rac_lv))
		return -EINVAL;

	if (para->mntr_time != env->ifs_clm_mntr_time) {
		rtw89_phy_ccx_ms_to_period_unit(rtwdev, para->mntr_time,
						&period, &unit_idx);
		rtw89_phy_set_phy_regs(rtwdev, R_IFS_COUNTER,
				       B_IFS_CLM_PERIOD_MSK, period);
		rtw89_phy_set_phy_regs(rtwdev, R_IFS_COUNTER,
				       B_IFS_CLM_COUNTER_UNIT_MSK, unit_idx);

		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "Update IFS-CLM time ((%d)) -> ((%d))\n",
			    env->ifs_clm_mntr_time, para->mntr_time);

		env->ifs_clm_mntr_time = para->mntr_time;
		env->ccx_period = (u16)period;
		env->ccx_unit_idx = (u8)unit_idx;
	}

	if (rtw89_phy_ifs_clm_th_update_check(rtwdev, para)) {
		env->ifs_clm_app = para->ifs_clm_app;
		rtw89_phy_ifs_clm_set_th_reg(rtwdev);
	}

	return 0;
}

void rtw89_phy_env_monitor_track(struct rtw89_dev *rtwdev)
{
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	struct rtw89_ccx_para_info para = {0};
	u8 chk_result = RTW89_PHY_ENV_MON_CCX_FAIL;

	env->ccx_watchdog_result = RTW89_PHY_ENV_MON_CCX_FAIL;
	if (env->ccx_manual_ctrl) {
		rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
			    "CCX in manual ctrl\n");
		return;
	}

	/* only ifs_clm for now */
	if (rtw89_phy_ifs_clm_get_result(rtwdev))
		env->ccx_watchdog_result |= RTW89_PHY_ENV_MON_IFS_CLM;

	rtw89_phy_ccx_racing_release(rtwdev);
	para.mntr_time = 1900;
	para.rac_lv = RTW89_RAC_LV_1;
	para.ifs_clm_app = RTW89_IFS_CLM_BACKGROUND;

	if (rtw89_phy_ifs_clm_set(rtwdev, &para) == 0)
		chk_result |= RTW89_PHY_ENV_MON_IFS_CLM;
	if (chk_result)
		rtw89_phy_ccx_trigger(rtwdev);

	rtw89_debug(rtwdev, RTW89_DBG_PHY_TRACK,
		    "get_result=0x%x, chk_result:0x%x\n",
		    env->ccx_watchdog_result, chk_result);
}

static bool rtw89_physts_ie_page_valid(enum rtw89_phy_status_bitmap *ie_page)
{
	if (*ie_page >= RTW89_PHYSTS_BITMAP_NUM ||
	    *ie_page == RTW89_RSVD_9)
		return false;
	else if (*ie_page > RTW89_RSVD_9)
		*ie_page -= 1;

	return true;
}

static u32 rtw89_phy_get_ie_bitmap_addr(enum rtw89_phy_status_bitmap ie_page)
{
	static const u8 ie_page_shift = 2;

	return R_PHY_STS_BITMAP_ADDR_START + (ie_page << ie_page_shift);
}

static u32 rtw89_physts_get_ie_bitmap(struct rtw89_dev *rtwdev,
				      enum rtw89_phy_status_bitmap ie_page)
{
	u32 addr;

	if (!rtw89_physts_ie_page_valid(&ie_page))
		return 0;

	addr = rtw89_phy_get_ie_bitmap_addr(ie_page);

	return rtw89_phy_read32(rtwdev, addr);
}

static void rtw89_physts_set_ie_bitmap(struct rtw89_dev *rtwdev,
				       enum rtw89_phy_status_bitmap ie_page,
				       u32 val)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	u32 addr;

	if (!rtw89_physts_ie_page_valid(&ie_page))
		return;

	if (chip->chip_id == RTL8852A)
		val &= B_PHY_STS_BITMAP_MSK_52A;

	addr = rtw89_phy_get_ie_bitmap_addr(ie_page);
	rtw89_phy_write32(rtwdev, addr, val);
}

static void rtw89_physts_enable_ie_bitmap(struct rtw89_dev *rtwdev,
					  enum rtw89_phy_status_bitmap bitmap,
					  enum rtw89_phy_status_ie_type ie,
					  bool enable)
{
	u32 val = rtw89_physts_get_ie_bitmap(rtwdev, bitmap);

	if (enable)
		val |= BIT(ie);
	else
		val &= ~BIT(ie);

	rtw89_physts_set_ie_bitmap(rtwdev, bitmap, val);
}

static void rtw89_physts_enable_fail_report(struct rtw89_dev *rtwdev,
					    bool enable,
					    enum rtw89_phy_idx phy_idx)
{
	if (enable) {
		rtw89_phy_write32_clr(rtwdev, R_PLCP_HISTOGRAM,
				      B_STS_DIS_TRIG_BY_FAIL);
		rtw89_phy_write32_clr(rtwdev, R_PLCP_HISTOGRAM,
				      B_STS_DIS_TRIG_BY_BRK);
	} else {
		rtw89_phy_write32_set(rtwdev, R_PLCP_HISTOGRAM,
				      B_STS_DIS_TRIG_BY_FAIL);
		rtw89_phy_write32_set(rtwdev, R_PLCP_HISTOGRAM,
				      B_STS_DIS_TRIG_BY_BRK);
	}
}

static void rtw89_physts_parsing_init(struct rtw89_dev *rtwdev)
{
	u8 i;

	rtw89_physts_enable_fail_report(rtwdev, false, RTW89_PHY_0);

	for (i = 0; i < RTW89_PHYSTS_BITMAP_NUM; i++) {
		if (i >= RTW89_CCK_PKT)
			rtw89_physts_enable_ie_bitmap(rtwdev, i,
						      RTW89_PHYSTS_IE09_FTR_0,
						      true);
		if ((i >= RTW89_CCK_BRK && i <= RTW89_VHT_MU) ||
		    (i >= RTW89_RSVD_9 && i <= RTW89_CCK_PKT))
			continue;
		rtw89_physts_enable_ie_bitmap(rtwdev, i,
					      RTW89_PHYSTS_IE24_OFDM_TD_PATH_A,
					      true);
	}
	rtw89_physts_enable_ie_bitmap(rtwdev, RTW89_VHT_PKT,
				      RTW89_PHYSTS_IE13_DL_MU_DEF, true);
	rtw89_physts_enable_ie_bitmap(rtwdev, RTW89_HE_PKT,
				      RTW89_PHYSTS_IE13_DL_MU_DEF, true);

	/* force IE01 for channel index, only channel field is valid */
	rtw89_physts_enable_ie_bitmap(rtwdev, RTW89_CCK_PKT,
				      RTW89_PHYSTS_IE01_CMN_OFDM, true);
}

static void rtw89_phy_dig_read_gain_table(struct rtw89_dev *rtwdev, int type)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	struct rtw89_dig_info *dig = &rtwdev->dig;
	const struct rtw89_phy_dig_gain_cfg *cfg;
	const char *msg;
	u8 i;
	s8 gain_base;
	s8 *gain_arr;
	u32 tmp;

	switch (type) {
	case RTW89_DIG_GAIN_LNA_G:
		gain_arr = dig->lna_gain_g;
		gain_base = LNA0_GAIN;
		cfg = chip->dig_table->cfg_lna_g;
		msg = "lna_gain_g";
		break;
	case RTW89_DIG_GAIN_TIA_G:
		gain_arr = dig->tia_gain_g;
		gain_base = TIA0_GAIN_G;
		cfg = chip->dig_table->cfg_tia_g;
		msg = "tia_gain_g";
		break;
	case RTW89_DIG_GAIN_LNA_A:
		gain_arr = dig->lna_gain_a;
		gain_base = LNA0_GAIN;
		cfg = chip->dig_table->cfg_lna_a;
		msg = "lna_gain_a";
		break;
	case RTW89_DIG_GAIN_TIA_A:
		gain_arr = dig->tia_gain_a;
		gain_base = TIA0_GAIN_A;
		cfg = chip->dig_table->cfg_tia_a;
		msg = "tia_gain_a";
		break;
	default:
		return;
	}

	for (i = 0; i < cfg->size; i++) {
		tmp = rtw89_phy_read32_mask(rtwdev, cfg->table[i].addr,
					    cfg->table[i].mask);
		tmp >>= DIG_GAIN_SHIFT;
		gain_arr[i] = sign_extend32(tmp, U4_MAX_BIT) + gain_base;
		gain_base += DIG_GAIN;

		rtw89_debug(rtwdev, RTW89_DBG_DIG, "%s[%d]=%d\n",
			    msg, i, gain_arr[i]);
	}
}

static void rtw89_phy_dig_update_gain_para(struct rtw89_dev *rtwdev)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;
	u32 tmp;
	u8 i;

	if (!rtwdev->hal.support_igi)
		return;

	tmp = rtw89_phy_read32_mask(rtwdev, R_PATH0_IB_PKPW,
				    B_PATH0_IB_PKPW_MSK);
	dig->ib_pkpwr = sign_extend32(tmp >> DIG_GAIN_SHIFT, U8_MAX_BIT);
	dig->ib_pbk = rtw89_phy_read32_mask(rtwdev, R_PATH0_IB_PBK,
					    B_PATH0_IB_PBK_MSK);
	rtw89_debug(rtwdev, RTW89_DBG_DIG, "ib_pkpwr=%d, ib_pbk=%d\n",
		    dig->ib_pkpwr, dig->ib_pbk);

	for (i = RTW89_DIG_GAIN_LNA_G; i < RTW89_DIG_GAIN_MAX; i++)
		rtw89_phy_dig_read_gain_table(rtwdev, i);
}

static const u8 rssi_nolink = 22;
static const u8 igi_rssi_th[IGI_RSSI_TH_NUM] = {68, 84, 90, 98, 104};
static const u16 fa_th_2g[FA_TH_NUM] = {22, 44, 66, 88};
static const u16 fa_th_5g[FA_TH_NUM] = {4, 8, 12, 16};
static const u16 fa_th_nolink[FA_TH_NUM] = {196, 352, 440, 528};

static void rtw89_phy_dig_update_rssi_info(struct rtw89_dev *rtwdev)
{
	struct rtw89_phy_ch_info *ch_info = &rtwdev->ch_info;
	struct rtw89_dig_info *dig = &rtwdev->dig;
	bool is_linked = rtwdev->total_sta_assoc > 0;

	if (is_linked) {
		dig->igi_rssi = ch_info->rssi_min >> 1;
	} else {
		rtw89_debug(rtwdev, RTW89_DBG_DIG, "RSSI update : NO Link\n");
		dig->igi_rssi = rssi_nolink;
	}
}

static void rtw89_phy_dig_update_para(struct rtw89_dev *rtwdev)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;
	const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_SUB_ENTITY_0);
	bool is_linked = rtwdev->total_sta_assoc > 0;
	const u16 *fa_th_src = NULL;

	switch (chan->band_type) {
	case RTW89_BAND_2G:
		dig->lna_gain = dig->lna_gain_g;
		dig->tia_gain = dig->tia_gain_g;
		fa_th_src = is_linked ? fa_th_2g : fa_th_nolink;
		dig->force_gaincode_idx_en = false;
		dig->dyn_pd_th_en = true;
		break;
	case RTW89_BAND_5G:
	default:
		dig->lna_gain = dig->lna_gain_a;
		dig->tia_gain = dig->tia_gain_a;
		fa_th_src = is_linked ? fa_th_5g : fa_th_nolink;
		dig->force_gaincode_idx_en = true;
		dig->dyn_pd_th_en = true;
		break;
	}
	memcpy(dig->fa_th, fa_th_src, sizeof(dig->fa_th));
	memcpy(dig->igi_rssi_th, igi_rssi_th, sizeof(dig->igi_rssi_th));
}

static const u8 pd_low_th_offset = 20, dynamic_igi_min = 0x20;
static const u8 igi_max_performance_mode = 0x5a;
static const u8 dynamic_pd_threshold_max;

static void rtw89_phy_dig_para_reset(struct rtw89_dev *rtwdev)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;

	dig->cur_gaincode.lna_idx = LNA_IDX_MAX;
	dig->cur_gaincode.tia_idx = TIA_IDX_MAX;
	dig->cur_gaincode.rxb_idx = RXB_IDX_MAX;
	dig->force_gaincode.lna_idx = LNA_IDX_MAX;
	dig->force_gaincode.tia_idx = TIA_IDX_MAX;
	dig->force_gaincode.rxb_idx = RXB_IDX_MAX;

	dig->dyn_igi_max = igi_max_performance_mode;
	dig->dyn_igi_min = dynamic_igi_min;
	dig->dyn_pd_th_max = dynamic_pd_threshold_max;
	dig->pd_low_th_ofst = pd_low_th_offset;
	dig->is_linked_pre = false;
}

static void rtw89_phy_dig_init(struct rtw89_dev *rtwdev)
{
	rtw89_phy_dig_update_gain_para(rtwdev);
	rtw89_phy_dig_reset(rtwdev);
}

static u8 rtw89_phy_dig_lna_idx_by_rssi(struct rtw89_dev *rtwdev, u8 rssi)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;
	u8 lna_idx;

	if (rssi < dig->igi_rssi_th[0])
		lna_idx = RTW89_DIG_GAIN_LNA_IDX6;
	else if (rssi < dig->igi_rssi_th[1])
		lna_idx = RTW89_DIG_GAIN_LNA_IDX5;
	else if (rssi < dig->igi_rssi_th[2])
		lna_idx = RTW89_DIG_GAIN_LNA_IDX4;
	else if (rssi < dig->igi_rssi_th[3])
		lna_idx = RTW89_DIG_GAIN_LNA_IDX3;
	else if (rssi < dig->igi_rssi_th[4])
		lna_idx = RTW89_DIG_GAIN_LNA_IDX2;
	else
		lna_idx = RTW89_DIG_GAIN_LNA_IDX1;

	return lna_idx;
}

static u8 rtw89_phy_dig_tia_idx_by_rssi(struct rtw89_dev *rtwdev, u8 rssi)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;
	u8 tia_idx;

	if (rssi < dig->igi_rssi_th[0])
		tia_idx = RTW89_DIG_GAIN_TIA_IDX1;
	else
		tia_idx = RTW89_DIG_GAIN_TIA_IDX0;

	return tia_idx;
}

#define IB_PBK_BASE 110
#define WB_RSSI_BASE 10
static u8 rtw89_phy_dig_rxb_idx_by_rssi(struct rtw89_dev *rtwdev, u8 rssi,
					struct rtw89_agc_gaincode_set *set)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;
	s8 lna_gain = dig->lna_gain[set->lna_idx];
	s8 tia_gain = dig->tia_gain[set->tia_idx];
	s32 wb_rssi = rssi + lna_gain + tia_gain;
	s32 rxb_idx_tmp = IB_PBK_BASE + WB_RSSI_BASE;
	u8 rxb_idx;

	rxb_idx_tmp += dig->ib_pkpwr - dig->ib_pbk - wb_rssi;
	rxb_idx = clamp_t(s32, rxb_idx_tmp, RXB_IDX_MIN, RXB_IDX_MAX);

	rtw89_debug(rtwdev, RTW89_DBG_DIG, "wb_rssi=%03d, rxb_idx_tmp=%03d\n",
		    wb_rssi, rxb_idx_tmp);

	return rxb_idx;
}

static void rtw89_phy_dig_gaincode_by_rssi(struct rtw89_dev *rtwdev, u8 rssi,
					   struct rtw89_agc_gaincode_set *set)
{
	set->lna_idx = rtw89_phy_dig_lna_idx_by_rssi(rtwdev, rssi);
	set->tia_idx = rtw89_phy_dig_tia_idx_by_rssi(rtwdev, rssi);
	set->rxb_idx = rtw89_phy_dig_rxb_idx_by_rssi(rtwdev, rssi, set);

	rtw89_debug(rtwdev, RTW89_DBG_DIG,
		    "final_rssi=%03d, (lna,tia,rab)=(%d,%d,%02d)\n",
		    rssi, set->lna_idx, set->tia_idx, set->rxb_idx);
}

#define IGI_OFFSET_MAX 25
#define IGI_OFFSET_MUL 2
static void rtw89_phy_dig_igi_offset_by_env(struct rtw89_dev *rtwdev)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;
	struct rtw89_env_monitor_info *env = &rtwdev->env_monitor;
	enum rtw89_dig_noisy_level noisy_lv;
	u8 igi_offset = dig->fa_rssi_ofst;
	u16 fa_ratio = 0;

	fa_ratio = env->ifs_clm_cck_fa_permil + env->ifs_clm_ofdm_fa_permil;

	if (fa_ratio < dig->fa_th[0])
		noisy_lv = RTW89_DIG_NOISY_LEVEL0;
	else if (fa_ratio < dig->fa_th[1])
		noisy_lv = RTW89_DIG_NOISY_LEVEL1;
	else if (fa_ratio < dig->fa_th[2])
		noisy_lv = RTW89_DIG_NOISY_LEVEL2;
	else if (fa_ratio < dig->fa_th[3])
		noisy_lv = RTW89_DIG_NOISY_LEVEL3;
	else
		noisy_lv = RTW89_DIG_NOISY_LEVEL_MAX;

	if (noisy_lv == RTW89_DIG_NOISY_LEVEL0 && igi_offset < 2)
		igi_offset = 0;
	else
		igi_offset += noisy_lv * IGI_OFFSET_MUL;

	igi_offset = min_t(u8, igi_offset, IGI_OFFSET_MAX);
	dig->fa_rssi_ofst = igi_offset;

	rtw89_debug(rtwdev, RTW89_DBG_DIG,
		    "fa_th: [+6 (%d) +4 (%d) +2 (%d) 0 (%d) -2 ]\n",
		    dig->fa_th[3], dig->fa_th[2], dig->fa_th[1], dig->fa_th[0]);

	rtw89_debug(rtwdev, RTW89_DBG_DIG,
		    "fa(CCK,OFDM,ALL)=(%d,%d,%d)%%, noisy_lv=%d, ofst=%d\n",
		    env->ifs_clm_cck_fa_permil, env->ifs_clm_ofdm_fa_permil,
		    env->ifs_clm_cck_fa_permil + env->ifs_clm_ofdm_fa_permil,
		    noisy_lv, igi_offset);
}

static void rtw89_phy_dig_set_lna_idx(struct rtw89_dev *rtwdev, u8 lna_idx)
{
	const struct rtw89_dig_regs *dig_regs = rtwdev->chip->dig_regs;

	rtw89_phy_write32_mask(rtwdev, dig_regs->p0_lna_init.addr,
			       dig_regs->p0_lna_init.mask, lna_idx);
	rtw89_phy_write32_mask(rtwdev, dig_regs->p1_lna_init.addr,
			       dig_regs->p1_lna_init.mask, lna_idx);
}

static void rtw89_phy_dig_set_tia_idx(struct rtw89_dev *rtwdev, u8 tia_idx)
{
	const struct rtw89_dig_regs *dig_regs = rtwdev->chip->dig_regs;

	rtw89_phy_write32_mask(rtwdev, dig_regs->p0_tia_init.addr,
			       dig_regs->p0_tia_init.mask, tia_idx);
	rtw89_phy_write32_mask(rtwdev, dig_regs->p1_tia_init.addr,
			       dig_regs->p1_tia_init.mask, tia_idx);
}

static void rtw89_phy_dig_set_rxb_idx(struct rtw89_dev *rtwdev, u8 rxb_idx)
{
	const struct rtw89_dig_regs *dig_regs = rtwdev->chip->dig_regs;

	rtw89_phy_write32_mask(rtwdev, dig_regs->p0_rxb_init.addr,
			       dig_regs->p0_rxb_init.mask, rxb_idx);
	rtw89_phy_write32_mask(rtwdev, dig_regs->p1_rxb_init.addr,
			       dig_regs->p1_rxb_init.mask, rxb_idx);
}

static void rtw89_phy_dig_set_igi_cr(struct rtw89_dev *rtwdev,
				     const struct rtw89_agc_gaincode_set set)
{
	rtw89_phy_dig_set_lna_idx(rtwdev, set.lna_idx);
	rtw89_phy_dig_set_tia_idx(rtwdev, set.tia_idx);
	rtw89_phy_dig_set_rxb_idx(rtwdev, set.rxb_idx);

	rtw89_debug(rtwdev, RTW89_DBG_DIG, "Set (lna,tia,rxb)=((%d,%d,%02d))\n",
		    set.lna_idx, set.tia_idx, set.rxb_idx);
}

static void rtw89_phy_dig_sdagc_follow_pagc_config(struct rtw89_dev *rtwdev,
						   bool enable)
{
	const struct rtw89_dig_regs *dig_regs = rtwdev->chip->dig_regs;

	rtw89_phy_write32_mask(rtwdev, dig_regs->p0_p20_pagcugc_en.addr,
			       dig_regs->p0_p20_pagcugc_en.mask, enable);
	rtw89_phy_write32_mask(rtwdev, dig_regs->p0_s20_pagcugc_en.addr,
			       dig_regs->p0_s20_pagcugc_en.mask, enable);
	rtw89_phy_write32_mask(rtwdev, dig_regs->p1_p20_pagcugc_en.addr,
			       dig_regs->p1_p20_pagcugc_en.mask, enable);
	rtw89_phy_write32_mask(rtwdev, dig_regs->p1_s20_pagcugc_en.addr,
			       dig_regs->p1_s20_pagcugc_en.mask, enable);

	rtw89_debug(rtwdev, RTW89_DBG_DIG, "sdagc_follow_pagc=%d\n", enable);
}

static void rtw89_phy_dig_config_igi(struct rtw89_dev *rtwdev)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;

	if (!rtwdev->hal.support_igi)
		return;

	if (dig->force_gaincode_idx_en) {
		rtw89_phy_dig_set_igi_cr(rtwdev, dig->force_gaincode);
		rtw89_debug(rtwdev, RTW89_DBG_DIG,
			    "Force gaincode index enabled.\n");
	} else {
		rtw89_phy_dig_gaincode_by_rssi(rtwdev, dig->igi_fa_rssi,
					       &dig->cur_gaincode);
		rtw89_phy_dig_set_igi_cr(rtwdev, dig->cur_gaincode);
	}
}

static void rtw89_phy_dig_dyn_pd_th(struct rtw89_dev *rtwdev, u8 rssi,
				    bool enable)
{
	const struct rtw89_chan *chan = rtw89_chan_get(rtwdev, RTW89_SUB_ENTITY_0);
	const struct rtw89_dig_regs *dig_regs = rtwdev->chip->dig_regs;
	enum rtw89_bandwidth cbw = chan->band_width;
	struct rtw89_dig_info *dig = &rtwdev->dig;
	u8 final_rssi = 0, under_region = dig->pd_low_th_ofst;
	u8 ofdm_cca_th;
	s8 cck_cca_th;
	u32 pd_val = 0;

	under_region += PD_TH_SB_FLTR_CMP_VAL;

	switch (cbw) {
	case RTW89_CHANNEL_WIDTH_40:
		under_region += PD_TH_BW40_CMP_VAL;
		break;
	case RTW89_CHANNEL_WIDTH_80:
		under_region += PD_TH_BW80_CMP_VAL;
		break;
	case RTW89_CHANNEL_WIDTH_160:
		under_region += PD_TH_BW160_CMP_VAL;
		break;
	case RTW89_CHANNEL_WIDTH_20:
		fallthrough;
	default:
		under_region += PD_TH_BW20_CMP_VAL;
		break;
	}

	dig->dyn_pd_th_max = dig->igi_rssi;

	final_rssi = min_t(u8, rssi, dig->igi_rssi);
	ofdm_cca_th = clamp_t(u8, final_rssi, PD_TH_MIN_RSSI + under_region,
			      PD_TH_MAX_RSSI + under_region);

	if (enable) {
		pd_val = (ofdm_cca_th - under_region - PD_TH_MIN_RSSI) >> 1;
		rtw89_debug(rtwdev, RTW89_DBG_DIG,
			    "igi=%d, ofdm_ccaTH=%d, backoff=%d, PD_low=%d\n",
			    final_rssi, ofdm_cca_th, under_region, pd_val);
	} else {
		rtw89_debug(rtwdev, RTW89_DBG_DIG,
			    "Dynamic PD th disabled, Set PD_low_bd=0\n");
	}

	rtw89_phy_write32_mask(rtwdev, dig_regs->seg0_pd_reg,
			       dig_regs->pd_lower_bound_mask, pd_val);
	rtw89_phy_write32_mask(rtwdev, dig_regs->seg0_pd_reg,
			       dig_regs->pd_spatial_reuse_en, enable);

	if (!rtwdev->hal.support_cckpd)
		return;

	cck_cca_th = max_t(s8, final_rssi - under_region, CCKPD_TH_MIN_RSSI);
	pd_val = (u32)(cck_cca_th - IGI_RSSI_MAX);

	rtw89_debug(rtwdev, RTW89_DBG_DIG,
		    "igi=%d, cck_ccaTH=%d, backoff=%d, cck_PD_low=((%d))dB\n",
		    final_rssi, cck_cca_th, under_region, pd_val);

	rtw89_phy_write32_mask(rtwdev, R_BMODE_PDTH_EN_V1,
			       B_BMODE_PDTH_LIMIT_EN_MSK_V1, enable);
	rtw89_phy_write32_mask(rtwdev, R_BMODE_PDTH_V1,
			       B_BMODE_PDTH_LOWER_BOUND_MSK_V1, pd_val);
}

void rtw89_phy_dig_reset(struct rtw89_dev *rtwdev)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;

	dig->bypass_dig = false;
	rtw89_phy_dig_para_reset(rtwdev);
	rtw89_phy_dig_set_igi_cr(rtwdev, dig->force_gaincode);
	rtw89_phy_dig_dyn_pd_th(rtwdev, rssi_nolink, false);
	rtw89_phy_dig_sdagc_follow_pagc_config(rtwdev, false);
	rtw89_phy_dig_update_para(rtwdev);
}

#define IGI_RSSI_MIN 10
void rtw89_phy_dig(struct rtw89_dev *rtwdev)
{
	struct rtw89_dig_info *dig = &rtwdev->dig;
	bool is_linked = rtwdev->total_sta_assoc > 0;

	if (unlikely(dig->bypass_dig)) {
		dig->bypass_dig = false;
		return;
	}

	if (!dig->is_linked_pre && is_linked) {
		rtw89_debug(rtwdev, RTW89_DBG_DIG, "First connected\n");
		rtw89_phy_dig_update_para(rtwdev);
	} else if (dig->is_linked_pre && !is_linked) {
		rtw89_debug(rtwdev, RTW89_DBG_DIG, "First disconnected\n");
		rtw89_phy_dig_update_para(rtwdev);
	}
	dig->is_linked_pre = is_linked;

	rtw89_phy_dig_igi_offset_by_env(rtwdev);
	rtw89_phy_dig_update_rssi_info(rtwdev);

	dig->dyn_igi_min = (dig->igi_rssi > IGI_RSSI_MIN) ?
			    dig->igi_rssi - IGI_RSSI_MIN : 0;
	dig->dyn_igi_max = dig->dyn_igi_min + IGI_OFFSET_MAX;
	dig->igi_fa_rssi = dig->dyn_igi_min + dig->fa_rssi_ofst;

	dig->igi_fa_rssi = clamp(dig->igi_fa_rssi, dig->dyn_igi_min,
				 dig->dyn_igi_max);

	rtw89_debug(rtwdev, RTW89_DBG_DIG,
		    "rssi=%03d, dyn(max,min)=(%d,%d), final_rssi=%d\n",
		    dig->igi_rssi, dig->dyn_igi_max, dig->dyn_igi_min,
		    dig->igi_fa_rssi);

	rtw89_phy_dig_config_igi(rtwdev);

	rtw89_phy_dig_dyn_pd_th(rtwdev, dig->igi_fa_rssi, dig->dyn_pd_th_en);

	if (dig->dyn_pd_th_en && dig->igi_fa_rssi > dig->dyn_pd_th_max)
		rtw89_phy_dig_sdagc_follow_pagc_config(rtwdev, true);
	else
		rtw89_phy_dig_sdagc_follow_pagc_config(rtwdev, false);
}

static void rtw89_phy_tx_path_div_sta_iter(void *data, struct ieee80211_sta *sta)
{
	struct rtw89_sta *rtwsta = (struct rtw89_sta *)sta->drv_priv;
	struct rtw89_dev *rtwdev = rtwsta->rtwdev;
	struct rtw89_vif *rtwvif = rtwsta->rtwvif;
	struct rtw89_hal *hal = &rtwdev->hal;
	bool *done = data;
	u8 rssi_a, rssi_b;
	u32 candidate;

	if (rtwvif->wifi_role != RTW89_WIFI_ROLE_STATION || sta->tdls)
		return;

	if (*done)
		return;

	*done = true;

	rssi_a = ewma_rssi_read(&rtwsta->rssi[RF_PATH_A]);
	rssi_b = ewma_rssi_read(&rtwsta->rssi[RF_PATH_B]);

	if (rssi_a > rssi_b + RTW89_TX_DIV_RSSI_RAW_TH)
		candidate = RF_A;
	else if (rssi_b > rssi_a + RTW89_TX_DIV_RSSI_RAW_TH)
		candidate = RF_B;
	else
		return;

	if (hal->antenna_tx == candidate)
		return;

	hal->antenna_tx = candidate;
	rtw89_fw_h2c_txpath_cmac_tbl(rtwdev, rtwsta);

	if (hal->antenna_tx == RF_A) {
		rtw89_phy_write32_mask(rtwdev, R_P0_RFMODE, B_P0_RFMODE_MUX, 0x12);
		rtw89_phy_write32_mask(rtwdev, R_P1_RFMODE, B_P1_RFMODE_MUX, 0x11);
	} else if (hal->antenna_tx == RF_B) {
		rtw89_phy_write32_mask(rtwdev, R_P0_RFMODE, B_P0_RFMODE_MUX, 0x11);
		rtw89_phy_write32_mask(rtwdev, R_P1_RFMODE, B_P1_RFMODE_MUX, 0x12);
	}
}

void rtw89_phy_tx_path_div_track(struct rtw89_dev *rtwdev)
{
	struct rtw89_hal *hal = &rtwdev->hal;
	bool done = false;

	if (!hal->tx_path_diversity)
		return;

	ieee80211_iterate_stations_atomic(rtwdev->hw,
					  rtw89_phy_tx_path_div_sta_iter,
					  &done);
}

static void rtw89_phy_env_monitor_init(struct rtw89_dev *rtwdev)
{
	rtw89_phy_ccx_top_setting_init(rtwdev);
	rtw89_phy_ifs_clm_setting_init(rtwdev);
}

void rtw89_phy_dm_init(struct rtw89_dev *rtwdev)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;

	rtw89_phy_stat_init(rtwdev);

	rtw89_chip_bb_sethw(rtwdev);

	rtw89_phy_env_monitor_init(rtwdev);
	rtw89_physts_parsing_init(rtwdev);
	rtw89_phy_dig_init(rtwdev);
	rtw89_phy_cfo_init(rtwdev);
	rtw89_phy_ul_tb_info_init(rtwdev);

	rtw89_phy_init_rf_nctl(rtwdev);
	rtw89_chip_rfk_init(rtwdev);
	rtw89_load_txpwr_table(rtwdev, chip->byr_table);
	rtw89_chip_set_txpwr_ctrl(rtwdev);
	rtw89_chip_power_trim(rtwdev);
	rtw89_chip_cfg_txrx_path(rtwdev);
}

void rtw89_phy_set_bss_color(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	enum rtw89_phy_idx phy_idx = RTW89_PHY_0;
	u8 bss_color;

	if (!vif->bss_conf.he_support || !vif->cfg.assoc)
		return;

	bss_color = vif->bss_conf.he_bss_color.color;

	rtw89_phy_write32_idx(rtwdev, chip->bss_clr_map_reg, B_BSS_CLR_MAP_VLD0, 0x1,
			      phy_idx);
	rtw89_phy_write32_idx(rtwdev, chip->bss_clr_map_reg, B_BSS_CLR_MAP_TGT,
			      bss_color, phy_idx);
	rtw89_phy_write32_idx(rtwdev, chip->bss_clr_map_reg, B_BSS_CLR_MAP_STAID,
			      vif->cfg.aid, phy_idx);
}

static void
_rfk_write_rf(struct rtw89_dev *rtwdev, const struct rtw89_reg5_def *def)
{
	rtw89_write_rf(rtwdev, def->path, def->addr, def->mask, def->data);
}

static void
_rfk_write32_mask(struct rtw89_dev *rtwdev, const struct rtw89_reg5_def *def)
{
	rtw89_phy_write32_mask(rtwdev, def->addr, def->mask, def->data);
}

static void
_rfk_write32_set(struct rtw89_dev *rtwdev, const struct rtw89_reg5_def *def)
{
	rtw89_phy_write32_set(rtwdev, def->addr, def->mask);
}

static void
_rfk_write32_clr(struct rtw89_dev *rtwdev, const struct rtw89_reg5_def *def)
{
	rtw89_phy_write32_clr(rtwdev, def->addr, def->mask);
}

static void
_rfk_delay(struct rtw89_dev *rtwdev, const struct rtw89_reg5_def *def)
{
	udelay(def->data);
}

static void
(*_rfk_handler[])(struct rtw89_dev *rtwdev, const struct rtw89_reg5_def *def) = {
	[RTW89_RFK_F_WRF] = _rfk_write_rf,
	[RTW89_RFK_F_WM] = _rfk_write32_mask,
	[RTW89_RFK_F_WS] = _rfk_write32_set,
	[RTW89_RFK_F_WC] = _rfk_write32_clr,
	[RTW89_RFK_F_DELAY] = _rfk_delay,
};

static_assert(ARRAY_SIZE(_rfk_handler) == RTW89_RFK_F_NUM);

void
rtw89_rfk_parser(struct rtw89_dev *rtwdev, const struct rtw89_rfk_tbl *tbl)
{
	const struct rtw89_reg5_def *p = tbl->defs;
	const struct rtw89_reg5_def *end = tbl->defs + tbl->size;

	for (; p < end; p++)
		_rfk_handler[p->flag](rtwdev, p);
}
EXPORT_SYMBOL(rtw89_rfk_parser);

#define RTW89_TSSI_FAST_MODE_NUM 4

static const struct rtw89_reg_def rtw89_tssi_fastmode_regs_flat[RTW89_TSSI_FAST_MODE_NUM] = {
	{0xD934, 0xff0000},
	{0xD934, 0xff000000},
	{0xD938, 0xff},
	{0xD934, 0xff00},
};

static const struct rtw89_reg_def rtw89_tssi_fastmode_regs_level[RTW89_TSSI_FAST_MODE_NUM] = {
	{0xD930, 0xff0000},
	{0xD930, 0xff000000},
	{0xD934, 0xff},
	{0xD930, 0xff00},
};

static
void rtw89_phy_tssi_ctrl_set_fast_mode_cfg(struct rtw89_dev *rtwdev,
					   enum rtw89_mac_idx mac_idx,
					   enum rtw89_tssi_bandedge_cfg bandedge_cfg,
					   u32 val)
{
	const struct rtw89_reg_def *regs;
	u32 reg;
	int i;

	if (bandedge_cfg == RTW89_TSSI_BANDEDGE_FLAT)
		regs = rtw89_tssi_fastmode_regs_flat;
	else
		regs = rtw89_tssi_fastmode_regs_level;

	for (i = 0; i < RTW89_TSSI_FAST_MODE_NUM; i++) {
		reg = rtw89_mac_reg_by_idx(regs[i].addr, mac_idx);
		rtw89_write32_mask(rtwdev, reg, regs[i].mask, val);
	}
}

static const struct rtw89_reg_def rtw89_tssi_bandedge_regs_flat[RTW89_TSSI_SBW_NUM] = {
	{0xD91C, 0xff000000},
	{0xD920, 0xff},
	{0xD920, 0xff00},
	{0xD920, 0xff0000},
	{0xD920, 0xff000000},
	{0xD924, 0xff},
	{0xD924, 0xff00},
	{0xD914, 0xff000000},
	{0xD918, 0xff},
	{0xD918, 0xff00},
	{0xD918, 0xff0000},
	{0xD918, 0xff000000},
	{0xD91C, 0xff},
	{0xD91C, 0xff00},
	{0xD91C, 0xff0000},
};

static const struct rtw89_reg_def rtw89_tssi_bandedge_regs_level[RTW89_TSSI_SBW_NUM] = {
	{0xD910, 0xff},
	{0xD910, 0xff00},
	{0xD910, 0xff0000},
	{0xD910, 0xff000000},
	{0xD914, 0xff},
	{0xD914, 0xff00},
	{0xD914, 0xff0000},
	{0xD908, 0xff},
	{0xD908, 0xff00},
	{0xD908, 0xff0000},
	{0xD908, 0xff000000},
	{0xD90C, 0xff},
	{0xD90C, 0xff00},
	{0xD90C, 0xff0000},
	{0xD90C, 0xff000000},
};

void rtw89_phy_tssi_ctrl_set_bandedge_cfg(struct rtw89_dev *rtwdev,
					  enum rtw89_mac_idx mac_idx,
					  enum rtw89_tssi_bandedge_cfg bandedge_cfg)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	const struct rtw89_reg_def *regs;
	const u32 *data;
	u32 reg;
	int i;

	if (bandedge_cfg >= RTW89_TSSI_CFG_NUM)
		return;

	if (bandedge_cfg == RTW89_TSSI_BANDEDGE_FLAT)
		regs = rtw89_tssi_bandedge_regs_flat;
	else
		regs = rtw89_tssi_bandedge_regs_level;

	data = chip->tssi_dbw_table->data[bandedge_cfg];

	for (i = 0; i < RTW89_TSSI_SBW_NUM; i++) {
		reg = rtw89_mac_reg_by_idx(regs[i].addr, mac_idx);
		rtw89_write32_mask(rtwdev, reg, regs[i].mask, data[i]);
	}

	reg = rtw89_mac_reg_by_idx(R_AX_BANDEDGE_CFG, mac_idx);
	rtw89_write32_mask(rtwdev, reg, B_AX_BANDEDGE_CFG_IDX_MASK, bandedge_cfg);

	rtw89_phy_tssi_ctrl_set_fast_mode_cfg(rtwdev, mac_idx, bandedge_cfg,
					      data[RTW89_TSSI_SBW20]);
}
EXPORT_SYMBOL(rtw89_phy_tssi_ctrl_set_bandedge_cfg);

static
const u8 rtw89_ch_base_table[16] = {1, 0xff,
				    36, 100, 132, 149, 0xff,
				    1, 33, 65, 97, 129, 161, 193, 225, 0xff};
#define RTW89_CH_BASE_IDX_2G		0
#define RTW89_CH_BASE_IDX_5G_FIRST	2
#define RTW89_CH_BASE_IDX_5G_LAST	5
#define RTW89_CH_BASE_IDX_6G_FIRST	7
#define RTW89_CH_BASE_IDX_6G_LAST	14

#define RTW89_CH_BASE_IDX_MASK		GENMASK(7, 4)
#define RTW89_CH_OFFSET_MASK		GENMASK(3, 0)

u8 rtw89_encode_chan_idx(struct rtw89_dev *rtwdev, u8 central_ch, u8 band)
{
	u8 chan_idx;
	u8 last, first;
	u8 idx;

	switch (band) {
	case RTW89_BAND_2G:
		chan_idx = FIELD_PREP(RTW89_CH_BASE_IDX_MASK, RTW89_CH_BASE_IDX_2G) |
			   FIELD_PREP(RTW89_CH_OFFSET_MASK, central_ch);
		return chan_idx;
	case RTW89_BAND_5G:
		first = RTW89_CH_BASE_IDX_5G_FIRST;
		last = RTW89_CH_BASE_IDX_5G_LAST;
		break;
	case RTW89_BAND_6G:
		first = RTW89_CH_BASE_IDX_6G_FIRST;
		last = RTW89_CH_BASE_IDX_6G_LAST;
		break;
	default:
		rtw89_warn(rtwdev, "Unsupported band %d\n", band);
		return 0;
	}

	for (idx = last; idx >= first; idx--)
		if (central_ch >= rtw89_ch_base_table[idx])
			break;

	if (idx < first) {
		rtw89_warn(rtwdev, "Unknown band %d channel %d\n", band, central_ch);
		return 0;
	}

	chan_idx = FIELD_PREP(RTW89_CH_BASE_IDX_MASK, idx) |
		   FIELD_PREP(RTW89_CH_OFFSET_MASK,
			      (central_ch - rtw89_ch_base_table[idx]) >> 1);
	return chan_idx;
}
EXPORT_SYMBOL(rtw89_encode_chan_idx);

void rtw89_decode_chan_idx(struct rtw89_dev *rtwdev, u8 chan_idx,
			   u8 *ch, enum nl80211_band *band)
{
	u8 idx, offset;

	idx = FIELD_GET(RTW89_CH_BASE_IDX_MASK, chan_idx);
	offset = FIELD_GET(RTW89_CH_OFFSET_MASK, chan_idx);

	if (idx == RTW89_CH_BASE_IDX_2G) {
		*band = NL80211_BAND_2GHZ;
		*ch = offset;
		return;
	}

	*band = idx <= RTW89_CH_BASE_IDX_5G_LAST ? NL80211_BAND_5GHZ : NL80211_BAND_6GHZ;
	*ch = rtw89_ch_base_table[idx] + (offset << 1);
}
EXPORT_SYMBOL(rtw89_decode_chan_idx);

#define EDCCA_DEFAULT 249
void rtw89_phy_config_edcca(struct rtw89_dev *rtwdev, bool scan)
{
	u32 reg = rtwdev->chip->edcca_lvl_reg;
	struct rtw89_hal *hal = &rtwdev->hal;
	u32 val;

	if (scan) {
		hal->edcca_bak = rtw89_phy_read32(rtwdev, reg);
		val = hal->edcca_bak;
		u32p_replace_bits(&val, EDCCA_DEFAULT, B_SEG0R_EDCCA_LVL_A_MSK);
		u32p_replace_bits(&val, EDCCA_DEFAULT, B_SEG0R_EDCCA_LVL_P_MSK);
		u32p_replace_bits(&val, EDCCA_DEFAULT, B_SEG0R_PPDU_LVL_MSK);
		rtw89_phy_write32(rtwdev, reg, val);
	} else {
		rtw89_phy_write32(rtwdev, reg, hal->edcca_bak);
	}
}
