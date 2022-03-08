/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2019, Vladimir Oltean <olteanv@gmail.com>
 */

/* Included by drivers/net/dsa/sja1105/sja1105.h and net/dsa/tag_sja1105.c */

#ifndef _NET_DSA_SJA1105_H
#define _NET_DSA_SJA1105_H

#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/dsa/8021q.h>
#include <net/dsa.h>

#define ETH_P_SJA1105				ETH_P_DSA_8021Q
#define ETH_P_SJA1105_META			0x0008
#define ETH_P_SJA1110				0xdadc

#define SJA1105_DEFAULT_VLAN			(VLAN_N_VID - 1)

/* IEEE 802.3 Annex 57A: Slow Protocols PDUs (01:80:C2:xx:xx:xx) */
#define SJA1105_LINKLOCAL_FILTER_A		0x0180C2000000ull
#define SJA1105_LINKLOCAL_FILTER_A_MASK		0xFFFFFF000000ull
/* IEEE 1588 Annex F: Transport of PTP over Ethernet (01:1B:19:xx:xx:xx) */
#define SJA1105_LINKLOCAL_FILTER_B		0x011B19000000ull
#define SJA1105_LINKLOCAL_FILTER_B_MASK		0xFFFFFF000000ull

/* Source and Destination MAC of follow-up meta frames.
 * Whereas the choice of SMAC only affects the unique identification of the
 * switch as sender of meta frames, the DMAC must be an address that is present
 * in the DSA master port's multicast MAC filter.
 * 01-80-C2-00-00-0E is a good choice for this, as all profiles of IEEE 1588
 * over L2 use this address for some purpose already.
 */
#define SJA1105_META_SMAC			0x222222222222ull
#define SJA1105_META_DMAC			0x0180C200000Eull

#define SJA1105_HWTS_RX_EN			0

/* Global tagger data: each struct sja1105_port has a reference to
 * the structure defined in struct sja1105_private.
 */
struct sja1105_tagger_data {
	struct sk_buff *stampable_skb;
	/* Protects concurrent access to the meta state machine
	 * from taggers running on multiple ports on SMP systems
	 */
	spinlock_t meta_lock;
	unsigned long state;
	u8 ts_id;
	/* Used on SJA1110 where meta frames are generated only for
	 * 2-step TX timestamps
	 */
	struct sk_buff_head skb_txtstamp_queue;
};

struct sja1105_skb_cb {
	struct sk_buff *clone;
	u64 tstamp;
	/* Only valid for packets cloned for 2-step TX timestamping */
	u8 ts_id;
};

#define SJA1105_SKB_CB(skb) \
	((struct sja1105_skb_cb *)((skb)->cb))

struct sja1105_port {
	struct kthread_worker *xmit_worker;
	struct kthread_work xmit_work;
	struct sk_buff_head xmit_queue;
	struct sja1105_tagger_data *data;
	bool hwts_tx_en;
};

/* Timestamps are in units of 8 ns clock ticks (equivalent to
 * a fixed 125 MHz clock).
 */
#define SJA1105_TICK_NS			8

static inline s64 ns_to_sja1105_ticks(s64 ns)
{
	return ns / SJA1105_TICK_NS;
}

static inline s64 sja1105_ticks_to_ns(s64 ticks)
{
	return ticks * SJA1105_TICK_NS;
}

static inline bool dsa_port_is_sja1105(struct dsa_port *dp)
{
	return true;
}

#endif /* _NET_DSA_SJA1105_H */
