/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Implementation of mac80211 API.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#ifndef WFX_KEY_H
#define WFX_KEY_H

#include <net/mac80211.h>

struct wfx_dev;
struct wfx_vif;

int wfx_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
		struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		struct ieee80211_key_conf *key);
int wfx_upload_keys(struct wfx_vif *wvif);
void wfx_wep_key_work(struct work_struct *work);

#endif /* WFX_STA_H */
