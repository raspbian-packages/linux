/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2019-2020  Realtek Corporation
 */

#ifndef __RTW89_SAR_H__
#define __RTW89_SAR_H__

#include "core.h"

#define RTW89_SAR_TXPWR_MAC_MAX S8_MAX
#define RTW89_SAR_TXPWR_MAC_MIN S8_MIN

struct rtw89_sar_handler {
	const char *descr_sar_source;
	u8 txpwr_factor_sar;
	int (*query_sar_config)(struct rtw89_dev *rtwdev, s32 *cfg);
};

extern const struct cfg80211_sar_capa rtw89_sar_capa;

s8 rtw89_query_sar(struct rtw89_dev *rtwdev);
void rtw89_print_sar(struct seq_file *m, struct rtw89_dev *rtwdev);
int rtw89_ops_set_sar_specs(struct ieee80211_hw *hw,
			    const struct cfg80211_sar_specs *sar);

#endif
