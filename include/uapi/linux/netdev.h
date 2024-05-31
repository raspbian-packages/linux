/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/netdev.yaml */
/* YNL-GEN uapi header */

#ifndef _UAPI_LINUX_NETDEV_H
#define _UAPI_LINUX_NETDEV_H

#define NETDEV_FAMILY_NAME	"netdev"
#define NETDEV_FAMILY_VERSION	1

/**
 * enum netdev_xdp_act
 * @NETDEV_XDP_ACT_BASIC: XDP features set supported by all drivers
 *   (XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX)
 * @NETDEV_XDP_ACT_REDIRECT: The netdev supports XDP_REDIRECT
 * @NETDEV_XDP_ACT_NDO_XMIT: This feature informs if netdev implements
 *   ndo_xdp_xmit callback.
 * @NETDEV_XDP_ACT_XSK_ZEROCOPY: This feature informs if netdev supports AF_XDP
 *   in zero copy mode.
 * @NETDEV_XDP_ACT_HW_OFFLOAD: This feature informs if netdev supports XDP hw
 *   offloading.
 * @NETDEV_XDP_ACT_RX_SG: This feature informs if netdev implements non-linear
 *   XDP buffer support in the driver napi callback.
 * @NETDEV_XDP_ACT_NDO_XMIT_SG: This feature informs if netdev implements
 *   non-linear XDP buffer support in ndo_xdp_xmit callback.
 */
enum netdev_xdp_act {
	NETDEV_XDP_ACT_BASIC = 1,
	NETDEV_XDP_ACT_REDIRECT = 2,
	NETDEV_XDP_ACT_NDO_XMIT = 4,
	NETDEV_XDP_ACT_XSK_ZEROCOPY = 8,
	NETDEV_XDP_ACT_HW_OFFLOAD = 16,
	NETDEV_XDP_ACT_RX_SG = 32,
	NETDEV_XDP_ACT_NDO_XMIT_SG = 64,

	/* private: */
	NETDEV_XDP_ACT_MASK = 127,
};

/**
 * enum netdev_xdp_rx_metadata
 * @NETDEV_XDP_RX_METADATA_TIMESTAMP: Device is capable of exposing receive HW
 *   timestamp via bpf_xdp_metadata_rx_timestamp().
 * @NETDEV_XDP_RX_METADATA_HASH: Device is capable of exposing receive packet
 *   hash via bpf_xdp_metadata_rx_hash().
 * @NETDEV_XDP_RX_METADATA_VLAN_TAG: Device is capable of exposing receive
 *   packet VLAN tag via bpf_xdp_metadata_rx_vlan_tag().
 */
enum netdev_xdp_rx_metadata {
	NETDEV_XDP_RX_METADATA_TIMESTAMP = 1,
	NETDEV_XDP_RX_METADATA_HASH = 2,
	NETDEV_XDP_RX_METADATA_VLAN_TAG = 4,
};

/**
 * enum netdev_xsk_flags
 * @NETDEV_XSK_FLAGS_TX_TIMESTAMP: HW timestamping egress packets is supported
 *   by the driver.
 * @NETDEV_XSK_FLAGS_TX_CHECKSUM: L3 checksum HW offload is supported by the
 *   driver.
 */
enum netdev_xsk_flags {
	NETDEV_XSK_FLAGS_TX_TIMESTAMP = 1,
	NETDEV_XSK_FLAGS_TX_CHECKSUM = 2,
};

enum netdev_queue_type {
	NETDEV_QUEUE_TYPE_RX,
	NETDEV_QUEUE_TYPE_TX,
};

enum {
	NETDEV_A_DEV_IFINDEX = 1,
	NETDEV_A_DEV_PAD,
	NETDEV_A_DEV_XDP_FEATURES,
	NETDEV_A_DEV_XDP_ZC_MAX_SEGS,
	NETDEV_A_DEV_XDP_RX_METADATA_FEATURES,
	NETDEV_A_DEV_XSK_FEATURES,

	__NETDEV_A_DEV_MAX,
	NETDEV_A_DEV_MAX = (__NETDEV_A_DEV_MAX - 1)
};

enum {
	NETDEV_A_PAGE_POOL_ID = 1,
	NETDEV_A_PAGE_POOL_IFINDEX,
	NETDEV_A_PAGE_POOL_NAPI_ID,
	NETDEV_A_PAGE_POOL_INFLIGHT,
	NETDEV_A_PAGE_POOL_INFLIGHT_MEM,
	NETDEV_A_PAGE_POOL_DETACH_TIME,

	__NETDEV_A_PAGE_POOL_MAX,
	NETDEV_A_PAGE_POOL_MAX = (__NETDEV_A_PAGE_POOL_MAX - 1)
};

enum {
	NETDEV_A_PAGE_POOL_STATS_INFO = 1,
	NETDEV_A_PAGE_POOL_STATS_ALLOC_FAST = 8,
	NETDEV_A_PAGE_POOL_STATS_ALLOC_SLOW,
	NETDEV_A_PAGE_POOL_STATS_ALLOC_SLOW_HIGH_ORDER,
	NETDEV_A_PAGE_POOL_STATS_ALLOC_EMPTY,
	NETDEV_A_PAGE_POOL_STATS_ALLOC_REFILL,
	NETDEV_A_PAGE_POOL_STATS_ALLOC_WAIVE,
	NETDEV_A_PAGE_POOL_STATS_RECYCLE_CACHED,
	NETDEV_A_PAGE_POOL_STATS_RECYCLE_CACHE_FULL,
	NETDEV_A_PAGE_POOL_STATS_RECYCLE_RING,
	NETDEV_A_PAGE_POOL_STATS_RECYCLE_RING_FULL,
	NETDEV_A_PAGE_POOL_STATS_RECYCLE_RELEASED_REFCNT,

	__NETDEV_A_PAGE_POOL_STATS_MAX,
	NETDEV_A_PAGE_POOL_STATS_MAX = (__NETDEV_A_PAGE_POOL_STATS_MAX - 1)
};

enum {
	NETDEV_A_NAPI_IFINDEX = 1,
	NETDEV_A_NAPI_ID,
	NETDEV_A_NAPI_IRQ,
	NETDEV_A_NAPI_PID,

	__NETDEV_A_NAPI_MAX,
	NETDEV_A_NAPI_MAX = (__NETDEV_A_NAPI_MAX - 1)
};

enum {
	NETDEV_A_QUEUE_ID = 1,
	NETDEV_A_QUEUE_IFINDEX,
	NETDEV_A_QUEUE_TYPE,
	NETDEV_A_QUEUE_NAPI_ID,

	__NETDEV_A_QUEUE_MAX,
	NETDEV_A_QUEUE_MAX = (__NETDEV_A_QUEUE_MAX - 1)
};

enum {
	NETDEV_CMD_DEV_GET = 1,
	NETDEV_CMD_DEV_ADD_NTF,
	NETDEV_CMD_DEV_DEL_NTF,
	NETDEV_CMD_DEV_CHANGE_NTF,
	NETDEV_CMD_PAGE_POOL_GET,
	NETDEV_CMD_PAGE_POOL_ADD_NTF,
	NETDEV_CMD_PAGE_POOL_DEL_NTF,
	NETDEV_CMD_PAGE_POOL_CHANGE_NTF,
	NETDEV_CMD_PAGE_POOL_STATS_GET,
	NETDEV_CMD_QUEUE_GET,
	NETDEV_CMD_NAPI_GET,

	__NETDEV_CMD_MAX,
	NETDEV_CMD_MAX = (__NETDEV_CMD_MAX - 1)
};

#define NETDEV_MCGRP_MGMT	"mgmt"
#define NETDEV_MCGRP_PAGE_POOL	"page-pool"

#endif /* _UAPI_LINUX_NETDEV_H */
