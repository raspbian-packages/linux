/*
 * Copyright (c) 2015-2016 Quantenna Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/nl80211.h>

#include "qlink_util.h"

u16 qlink_iface_type_to_nl_mask(u16 qlink_type)
{
	u16 result = 0;

	switch (qlink_type) {
	case QLINK_IFTYPE_AP:
		result |= BIT(NL80211_IFTYPE_AP);
		break;
	case QLINK_IFTYPE_STATION:
		result |= BIT(NL80211_IFTYPE_STATION);
		break;
	case QLINK_IFTYPE_ADHOC:
		result |= BIT(NL80211_IFTYPE_ADHOC);
		break;
	case QLINK_IFTYPE_MONITOR:
		result |= BIT(NL80211_IFTYPE_MONITOR);
		break;
	case QLINK_IFTYPE_WDS:
		result |= BIT(NL80211_IFTYPE_WDS);
		break;
	case QLINK_IFTYPE_AP_VLAN:
		result |= BIT(NL80211_IFTYPE_AP_VLAN);
		break;
	}

	return result;
}

u8 qlink_chan_width_mask_to_nl(u16 qlink_mask)
{
	u8 result = 0;

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_5))
		result |= BIT(NL80211_CHAN_WIDTH_5);

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_10))
		result |= BIT(NL80211_CHAN_WIDTH_10);

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_20_NOHT))
		result |= BIT(NL80211_CHAN_WIDTH_20_NOHT);

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_20))
		result |= BIT(NL80211_CHAN_WIDTH_20);

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_40))
		result |= BIT(NL80211_CHAN_WIDTH_40);

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_80))
		result |= BIT(NL80211_CHAN_WIDTH_80);

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_80P80))
		result |= BIT(NL80211_CHAN_WIDTH_80P80);

	if (qlink_mask & BIT(QLINK_CHAN_WIDTH_160))
		result |= BIT(NL80211_CHAN_WIDTH_160);

	return result;
}

static enum nl80211_chan_width qlink_chanwidth_to_nl(u8 qlw)
{
	switch (qlw) {
	case QLINK_CHAN_WIDTH_20_NOHT:
		return NL80211_CHAN_WIDTH_20_NOHT;
	case QLINK_CHAN_WIDTH_20:
		return NL80211_CHAN_WIDTH_20;
	case QLINK_CHAN_WIDTH_40:
		return NL80211_CHAN_WIDTH_40;
	case QLINK_CHAN_WIDTH_80:
		return NL80211_CHAN_WIDTH_80;
	case QLINK_CHAN_WIDTH_80P80:
		return NL80211_CHAN_WIDTH_80P80;
	case QLINK_CHAN_WIDTH_160:
		return NL80211_CHAN_WIDTH_160;
	case QLINK_CHAN_WIDTH_5:
		return NL80211_CHAN_WIDTH_5;
	case QLINK_CHAN_WIDTH_10:
		return NL80211_CHAN_WIDTH_10;
	default:
		return -1;
	}
}

void qlink_chandef_q2cfg(struct wiphy *wiphy,
			 const struct qlink_chandef *qch,
			 struct cfg80211_chan_def *chdef)
{
	chdef->center_freq1 = le16_to_cpu(qch->center_freq1);
	chdef->center_freq2 = le16_to_cpu(qch->center_freq2);
	chdef->width = qlink_chanwidth_to_nl(qch->width);

	switch (chdef->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
	case NL80211_CHAN_WIDTH_20:
	case NL80211_CHAN_WIDTH_5:
	case NL80211_CHAN_WIDTH_10:
		chdef->chan = ieee80211_get_channel(wiphy, chdef->center_freq1);
		break;
	case NL80211_CHAN_WIDTH_40:
	case NL80211_CHAN_WIDTH_80:
	case NL80211_CHAN_WIDTH_80P80:
	case NL80211_CHAN_WIDTH_160:
		chdef->chan = ieee80211_get_channel(wiphy,
						    chdef->center_freq1 - 10);
		break;
	default:
		chdef->chan = NULL;
		break;
	}
}

static u8 qlink_chanwidth_nl_to_qlink(enum nl80211_chan_width nlwidth)
{
	switch (nlwidth) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		return QLINK_CHAN_WIDTH_20_NOHT;
	case NL80211_CHAN_WIDTH_20:
		return QLINK_CHAN_WIDTH_20;
	case NL80211_CHAN_WIDTH_40:
		return QLINK_CHAN_WIDTH_40;
	case NL80211_CHAN_WIDTH_80:
		return QLINK_CHAN_WIDTH_80;
	case NL80211_CHAN_WIDTH_80P80:
		return QLINK_CHAN_WIDTH_80P80;
	case NL80211_CHAN_WIDTH_160:
		return QLINK_CHAN_WIDTH_160;
	case NL80211_CHAN_WIDTH_5:
		return QLINK_CHAN_WIDTH_5;
	case NL80211_CHAN_WIDTH_10:
		return QLINK_CHAN_WIDTH_10;
	default:
		return -1;
	}
}

void qlink_chandef_cfg2q(const struct cfg80211_chan_def *chdef,
			 struct qlink_chandef *qch)
{
	qch->center_freq1 = cpu_to_le16(chdef->center_freq1);
	qch->center_freq2 = cpu_to_le16(chdef->center_freq2);
	qch->width = qlink_chanwidth_nl_to_qlink(chdef->width);
}

enum qlink_hidden_ssid qlink_hidden_ssid_nl2q(enum nl80211_hidden_ssid nl_val)
{
	switch (nl_val) {
	case NL80211_HIDDEN_SSID_ZERO_LEN:
		return QLINK_HIDDEN_SSID_ZERO_LEN;
	case NL80211_HIDDEN_SSID_ZERO_CONTENTS:
		return QLINK_HIDDEN_SSID_ZERO_CONTENTS;
	case NL80211_HIDDEN_SSID_NOT_IN_USE:
	default:
		return QLINK_HIDDEN_SSID_NOT_IN_USE;
	}
}
