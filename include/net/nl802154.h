#ifndef __NL802154_H
#define __NL802154_H
/*
 * 802.15.4 netlink interface public header
 *
 * Copyright 2014 Alexander Aring <aar@pengutronix.de>
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
 *
 */

#include <linux/types.h>

#define NL802154_GENL_NAME "nl802154"

enum nl802154_commands {
/* don't change the order or add anything between, this is ABI! */
/* currently we don't shipping this file via uapi, ignore the above one */
	NL802154_CMD_UNSPEC,

	NL802154_CMD_GET_WPAN_PHY,		/* can dump */
	NL802154_CMD_SET_WPAN_PHY,
	NL802154_CMD_NEW_WPAN_PHY,
	NL802154_CMD_DEL_WPAN_PHY,

	NL802154_CMD_GET_INTERFACE,		/* can dump */
	NL802154_CMD_SET_INTERFACE,
	NL802154_CMD_NEW_INTERFACE,
	NL802154_CMD_DEL_INTERFACE,

	NL802154_CMD_SET_CHANNEL,

	NL802154_CMD_SET_PAN_ID,
	NL802154_CMD_SET_SHORT_ADDR,

	NL802154_CMD_SET_TX_POWER,
	NL802154_CMD_SET_CCA_MODE,
	NL802154_CMD_SET_CCA_ED_LEVEL,

	NL802154_CMD_SET_MAX_FRAME_RETRIES,

	NL802154_CMD_SET_BACKOFF_EXPONENT,
	NL802154_CMD_SET_MAX_CSMA_BACKOFFS,

	NL802154_CMD_SET_LBT_MODE,

	NL802154_CMD_SET_ACKREQ_DEFAULT,

	NL802154_CMD_SET_WPAN_PHY_NETNS,

	NL802154_CMD_SET_SEC_PARAMS,
	NL802154_CMD_GET_SEC_KEY,		/* can dump */
	NL802154_CMD_NEW_SEC_KEY,
	NL802154_CMD_DEL_SEC_KEY,
	NL802154_CMD_GET_SEC_DEV,		/* can dump */
	NL802154_CMD_NEW_SEC_DEV,
	NL802154_CMD_DEL_SEC_DEV,
	NL802154_CMD_GET_SEC_DEVKEY,		/* can dump */
	NL802154_CMD_NEW_SEC_DEVKEY,
	NL802154_CMD_DEL_SEC_DEVKEY,
	NL802154_CMD_GET_SEC_LEVEL,		/* can dump */
	NL802154_CMD_NEW_SEC_LEVEL,
	NL802154_CMD_DEL_SEC_LEVEL,

	/* add new commands above here */

	/* used to define NL802154_CMD_MAX below */
	__NL802154_CMD_AFTER_LAST,
	NL802154_CMD_MAX = __NL802154_CMD_AFTER_LAST - 1
};

enum nl802154_attrs {
/* don't change the order or add anything between, this is ABI! */
/* currently we don't shipping this file via uapi, ignore the above one */
	NL802154_ATTR_UNSPEC,

	NL802154_ATTR_WPAN_PHY,
	NL802154_ATTR_WPAN_PHY_NAME,

	NL802154_ATTR_IFINDEX,
	NL802154_ATTR_IFNAME,
	NL802154_ATTR_IFTYPE,

	NL802154_ATTR_WPAN_DEV,

	NL802154_ATTR_PAGE,
	NL802154_ATTR_CHANNEL,

	NL802154_ATTR_PAN_ID,
	NL802154_ATTR_SHORT_ADDR,

	NL802154_ATTR_TX_POWER,

	NL802154_ATTR_CCA_MODE,
	NL802154_ATTR_CCA_OPT,
	NL802154_ATTR_CCA_ED_LEVEL,

	NL802154_ATTR_MAX_FRAME_RETRIES,

	NL802154_ATTR_MAX_BE,
	NL802154_ATTR_MIN_BE,
	NL802154_ATTR_MAX_CSMA_BACKOFFS,

	NL802154_ATTR_LBT_MODE,

	NL802154_ATTR_GENERATION,

	NL802154_ATTR_CHANNELS_SUPPORTED,
	NL802154_ATTR_SUPPORTED_CHANNEL,

	NL802154_ATTR_EXTENDED_ADDR,

	NL802154_ATTR_WPAN_PHY_CAPS,

	NL802154_ATTR_SUPPORTED_COMMANDS,

	NL802154_ATTR_ACKREQ_DEFAULT,

	NL802154_ATTR_PAD,

	NL802154_ATTR_PID,
	NL802154_ATTR_NETNS_FD,

	/* add attributes here, update the policy in nl802154.c */

#ifdef CONFIG_IEEE802154_NL802154_EXPERIMENTAL
	NL802154_ATTR_SEC_ENABLED,
	NL802154_ATTR_SEC_OUT_LEVEL,
	NL802154_ATTR_SEC_OUT_KEY_ID,
	NL802154_ATTR_SEC_FRAME_COUNTER,

	NL802154_ATTR_SEC_LEVEL,
	NL802154_ATTR_SEC_DEVICE,
	NL802154_ATTR_SEC_DEVKEY,
	NL802154_ATTR_SEC_KEY,
#endif /* CONFIG_IEEE802154_NL802154_EXPERIMENTAL */

	__NL802154_ATTR_AFTER_LAST,
	NL802154_ATTR_MAX = __NL802154_ATTR_AFTER_LAST - 1
};

enum nl802154_iftype {
	NL802154_IFTYPE_UNSPEC = (~(__u32)0),

	NL802154_IFTYPE_NODE = 0,
	NL802154_IFTYPE_MONITOR,
	NL802154_IFTYPE_COORD,

	/* keep last */
	NUM_NL802154_IFTYPES,
	NL802154_IFTYPE_MAX = NUM_NL802154_IFTYPES - 1
};

/**
 * enum nl802154_wpan_phy_capability_attr - wpan phy capability attributes
 *
 * @__NL802154_CAP_ATTR_INVALID: attribute number 0 is reserved
 * @NL802154_CAP_ATTR_CHANNELS: a nested attribute for nl802154_channel_attr
 * @NL802154_CAP_ATTR_TX_POWERS: a nested attribute for
 *	nl802154_wpan_phy_tx_power
 * @NL802154_CAP_ATTR_MIN_CCA_ED_LEVEL: minimum value for cca_ed_level
 * @NL802154_CAP_ATTR_MAX_CCA_ED_LEVEL: maxmimum value for cca_ed_level
 * @NL802154_CAP_ATTR_CCA_MODES: nl802154_cca_modes flags
 * @NL802154_CAP_ATTR_CCA_OPTS: nl802154_cca_opts flags
 * @NL802154_CAP_ATTR_MIN_MINBE: minimum of minbe value
 * @NL802154_CAP_ATTR_MAX_MINBE: maximum of minbe value
 * @NL802154_CAP_ATTR_MIN_MAXBE: minimum of maxbe value
 * @NL802154_CAP_ATTR_MAX_MINBE: maximum of maxbe value
 * @NL802154_CAP_ATTR_MIN_CSMA_BACKOFFS: minimum of csma backoff value
 * @NL802154_CAP_ATTR_MAX_CSMA_BACKOFFS: maximum of csma backoffs value
 * @NL802154_CAP_ATTR_MIN_FRAME_RETRIES: minimum of frame retries value
 * @NL802154_CAP_ATTR_MAX_FRAME_RETRIES: maximum of frame retries value
 * @NL802154_CAP_ATTR_IFTYPES: nl802154_iftype flags
 * @NL802154_CAP_ATTR_LBT: nl802154_supported_bool_states flags
 * @NL802154_CAP_ATTR_MAX: highest cap attribute currently defined
 * @__NL802154_CAP_ATTR_AFTER_LAST: internal use
 */
enum nl802154_wpan_phy_capability_attr {
	__NL802154_CAP_ATTR_INVALID,

	NL802154_CAP_ATTR_IFTYPES,

	NL802154_CAP_ATTR_CHANNELS,
	NL802154_CAP_ATTR_TX_POWERS,

	NL802154_CAP_ATTR_CCA_ED_LEVELS,
	NL802154_CAP_ATTR_CCA_MODES,
	NL802154_CAP_ATTR_CCA_OPTS,

	NL802154_CAP_ATTR_MIN_MINBE,
	NL802154_CAP_ATTR_MAX_MINBE,

	NL802154_CAP_ATTR_MIN_MAXBE,
	NL802154_CAP_ATTR_MAX_MAXBE,

	NL802154_CAP_ATTR_MIN_CSMA_BACKOFFS,
	NL802154_CAP_ATTR_MAX_CSMA_BACKOFFS,

	NL802154_CAP_ATTR_MIN_FRAME_RETRIES,
	NL802154_CAP_ATTR_MAX_FRAME_RETRIES,

	NL802154_CAP_ATTR_LBT,

	/* keep last */
	__NL802154_CAP_ATTR_AFTER_LAST,
	NL802154_CAP_ATTR_MAX = __NL802154_CAP_ATTR_AFTER_LAST - 1
};

/**
 * enum nl802154_cca_modes - cca modes
 *
 * @__NL802154_CCA_INVALID: cca mode number 0 is reserved
 * @NL802154_CCA_ENERGY: Energy above threshold
 * @NL802154_CCA_CARRIER: Carrier sense only
 * @NL802154_CCA_ENERGY_CARRIER: Carrier sense with energy above threshold
 * @NL802154_CCA_ALOHA: CCA shall always report an idle medium
 * @NL802154_CCA_UWB_SHR: UWB preamble sense based on the SHR of a frame
 * @NL802154_CCA_UWB_MULTIPLEXED: UWB preamble sense based on the packet with
 *	the multiplexed preamble
 * @__NL802154_CCA_ATTR_AFTER_LAST: Internal
 * @NL802154_CCA_ATTR_MAX: Maximum CCA attribute number
 */
enum nl802154_cca_modes {
	__NL802154_CCA_INVALID,
	NL802154_CCA_ENERGY,
	NL802154_CCA_CARRIER,
	NL802154_CCA_ENERGY_CARRIER,
	NL802154_CCA_ALOHA,
	NL802154_CCA_UWB_SHR,
	NL802154_CCA_UWB_MULTIPLEXED,

	/* keep last */
	__NL802154_CCA_ATTR_AFTER_LAST,
	NL802154_CCA_ATTR_MAX = __NL802154_CCA_ATTR_AFTER_LAST - 1
};

/**
 * enum nl802154_cca_opts - additional options for cca modes
 *
 * @NL802154_CCA_OPT_ENERGY_CARRIER_OR: NL802154_CCA_ENERGY_CARRIER with OR
 * @NL802154_CCA_OPT_ENERGY_CARRIER_AND: NL802154_CCA_ENERGY_CARRIER with AND
 */
enum nl802154_cca_opts {
	NL802154_CCA_OPT_ENERGY_CARRIER_AND,
	NL802154_CCA_OPT_ENERGY_CARRIER_OR,

	/* keep last */
	__NL802154_CCA_OPT_ATTR_AFTER_LAST,
	NL802154_CCA_OPT_ATTR_MAX = __NL802154_CCA_OPT_ATTR_AFTER_LAST - 1
};

/**
 * enum nl802154_supported_bool_states - bool states for bool capability entry
 *
 * @NL802154_SUPPORTED_BOOL_FALSE: indicates to set false
 * @NL802154_SUPPORTED_BOOL_TRUE: indicates to set true
 * @__NL802154_SUPPORTED_BOOL_INVALD: reserved
 * @NL802154_SUPPORTED_BOOL_BOTH: indicates to set true and false
 * @__NL802154_SUPPORTED_BOOL_AFTER_LAST: Internal
 * @NL802154_SUPPORTED_BOOL_MAX: highest value for bool states
 */
enum nl802154_supported_bool_states {
	NL802154_SUPPORTED_BOOL_FALSE,
	NL802154_SUPPORTED_BOOL_TRUE,
	/* to handle them in a mask */
	__NL802154_SUPPORTED_BOOL_INVALD,
	NL802154_SUPPORTED_BOOL_BOTH,

	/* keep last */
	__NL802154_SUPPORTED_BOOL_AFTER_LAST,
	NL802154_SUPPORTED_BOOL_MAX = __NL802154_SUPPORTED_BOOL_AFTER_LAST - 1
};

#ifdef CONFIG_IEEE802154_NL802154_EXPERIMENTAL

enum nl802154_dev_addr_modes {
	NL802154_DEV_ADDR_NONE,
	__NL802154_DEV_ADDR_INVALID,
	NL802154_DEV_ADDR_SHORT,
	NL802154_DEV_ADDR_EXTENDED,

	/* keep last */
	__NL802154_DEV_ADDR_AFTER_LAST,
	NL802154_DEV_ADDR_MAX = __NL802154_DEV_ADDR_AFTER_LAST - 1
};

enum nl802154_dev_addr_attrs {
	NL802154_DEV_ADDR_ATTR_UNSPEC,

	NL802154_DEV_ADDR_ATTR_PAN_ID,
	NL802154_DEV_ADDR_ATTR_MODE,
	NL802154_DEV_ADDR_ATTR_SHORT,
	NL802154_DEV_ADDR_ATTR_EXTENDED,
	NL802154_DEV_ADDR_ATTR_PAD,

	/* keep last */
	__NL802154_DEV_ADDR_ATTR_AFTER_LAST,
	NL802154_DEV_ADDR_ATTR_MAX = __NL802154_DEV_ADDR_ATTR_AFTER_LAST - 1
};

enum nl802154_key_id_modes {
	NL802154_KEY_ID_MODE_IMPLICIT,
	NL802154_KEY_ID_MODE_INDEX,
	NL802154_KEY_ID_MODE_INDEX_SHORT,
	NL802154_KEY_ID_MODE_INDEX_EXTENDED,

	/* keep last */
	__NL802154_KEY_ID_MODE_AFTER_LAST,
	NL802154_KEY_ID_MODE_MAX = __NL802154_KEY_ID_MODE_AFTER_LAST - 1
};

enum nl802154_key_id_attrs {
	NL802154_KEY_ID_ATTR_UNSPEC,

	NL802154_KEY_ID_ATTR_MODE,
	NL802154_KEY_ID_ATTR_INDEX,
	NL802154_KEY_ID_ATTR_IMPLICIT,
	NL802154_KEY_ID_ATTR_SOURCE_SHORT,
	NL802154_KEY_ID_ATTR_SOURCE_EXTENDED,
	NL802154_KEY_ID_ATTR_PAD,

	/* keep last */
	__NL802154_KEY_ID_ATTR_AFTER_LAST,
	NL802154_KEY_ID_ATTR_MAX = __NL802154_KEY_ID_ATTR_AFTER_LAST - 1
};

enum nl802154_seclevels {
	NL802154_SECLEVEL_NONE,
	NL802154_SECLEVEL_MIC32,
	NL802154_SECLEVEL_MIC64,
	NL802154_SECLEVEL_MIC128,
	NL802154_SECLEVEL_ENC,
	NL802154_SECLEVEL_ENC_MIC32,
	NL802154_SECLEVEL_ENC_MIC64,
	NL802154_SECLEVEL_ENC_MIC128,

	/* keep last */
	__NL802154_SECLEVEL_AFTER_LAST,
	NL802154_SECLEVEL_MAX = __NL802154_SECLEVEL_AFTER_LAST - 1
};

enum nl802154_frames {
	NL802154_FRAME_BEACON,
	NL802154_FRAME_DATA,
	NL802154_FRAME_ACK,
	NL802154_FRAME_CMD,

	/* keep last */
	__NL802154_FRAME_AFTER_LAST,
	NL802154_FRAME_MAX = __NL802154_FRAME_AFTER_LAST - 1
};

enum nl802154_cmd_frames {
	__NL802154_CMD_FRAME_INVALID,
	NL802154_CMD_FRAME_ASSOC_REQUEST,
	NL802154_CMD_FRAME_ASSOC_RESPONSE,
	NL802154_CMD_FRAME_DISASSOC_NOTIFY,
	NL802154_CMD_FRAME_DATA_REQUEST,
	NL802154_CMD_FRAME_PAN_ID_CONFLICT_NOTIFY,
	NL802154_CMD_FRAME_ORPHAN_NOTIFY,
	NL802154_CMD_FRAME_BEACON_REQUEST,
	NL802154_CMD_FRAME_COORD_REALIGNMENT,
	NL802154_CMD_FRAME_GTS_REQUEST,

	/* keep last */
	__NL802154_CMD_FRAME_AFTER_LAST,
	NL802154_CMD_FRAME_MAX = __NL802154_CMD_FRAME_AFTER_LAST - 1
};

enum nl802154_seclevel_attrs {
	NL802154_SECLEVEL_ATTR_UNSPEC,

	NL802154_SECLEVEL_ATTR_LEVELS,
	NL802154_SECLEVEL_ATTR_FRAME,
	NL802154_SECLEVEL_ATTR_CMD_FRAME,
	NL802154_SECLEVEL_ATTR_DEV_OVERRIDE,

	/* keep last */
	__NL802154_SECLEVEL_ATTR_AFTER_LAST,
	NL802154_SECLEVEL_ATTR_MAX = __NL802154_SECLEVEL_ATTR_AFTER_LAST - 1
};

/* TODO what is this? couldn't find in mib */
enum {
	NL802154_DEVKEY_IGNORE,
	NL802154_DEVKEY_RESTRICT,
	NL802154_DEVKEY_RECORD,

	/* keep last */
	__NL802154_DEVKEY_AFTER_LAST,
	NL802154_DEVKEY_MAX = __NL802154_DEVKEY_AFTER_LAST - 1
};

enum nl802154_dev {
	NL802154_DEV_ATTR_UNSPEC,

	NL802154_DEV_ATTR_FRAME_COUNTER,
	NL802154_DEV_ATTR_PAN_ID,
	NL802154_DEV_ATTR_SHORT_ADDR,
	NL802154_DEV_ATTR_EXTENDED_ADDR,
	NL802154_DEV_ATTR_SECLEVEL_EXEMPT,
	NL802154_DEV_ATTR_KEY_MODE,
	NL802154_DEV_ATTR_PAD,

	/* keep last */
	__NL802154_DEV_ATTR_AFTER_LAST,
	NL802154_DEV_ATTR_MAX = __NL802154_DEV_ATTR_AFTER_LAST - 1
};

enum nl802154_devkey {
	NL802154_DEVKEY_ATTR_UNSPEC,

	NL802154_DEVKEY_ATTR_FRAME_COUNTER,
	NL802154_DEVKEY_ATTR_EXTENDED_ADDR,
	NL802154_DEVKEY_ATTR_ID,
	NL802154_DEVKEY_ATTR_PAD,

	/* keep last */
	__NL802154_DEVKEY_ATTR_AFTER_LAST,
	NL802154_DEVKEY_ATTR_MAX = __NL802154_DEVKEY_ATTR_AFTER_LAST - 1
};

enum nl802154_key {
	NL802154_KEY_ATTR_UNSPEC,

	NL802154_KEY_ATTR_ID,
	NL802154_KEY_ATTR_USAGE_FRAMES,
	NL802154_KEY_ATTR_USAGE_CMDS,
	NL802154_KEY_ATTR_BYTES,

	/* keep last */
	__NL802154_KEY_ATTR_AFTER_LAST,
	NL802154_KEY_ATTR_MAX = __NL802154_KEY_ATTR_AFTER_LAST - 1
};

#define NL802154_KEY_SIZE		16
#define NL802154_CMD_FRAME_NR_IDS	256

#endif /* CONFIG_IEEE802154_NL802154_EXPERIMENTAL */

#endif /* __NL802154_H */
