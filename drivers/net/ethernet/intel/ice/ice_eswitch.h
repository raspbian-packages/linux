/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2021, Intel Corporation. */

#ifndef _ICE_ESWITCH_H_
#define _ICE_ESWITCH_H_

#include <net/devlink.h>

#ifdef CONFIG_ICE_SWITCHDEV
void ice_eswitch_release(struct ice_pf *pf);
int ice_eswitch_configure(struct ice_pf *pf);
int ice_eswitch_rebuild(struct ice_pf *pf);

int ice_eswitch_mode_get(struct devlink *devlink, u16 *mode);
int
ice_eswitch_mode_set(struct devlink *devlink, u16 mode,
		     struct netlink_ext_ack *extack);
bool ice_is_eswitch_mode_switchdev(struct ice_pf *pf);

void ice_eswitch_update_repr(struct ice_vsi *vsi);

void ice_eswitch_stop_all_tx_queues(struct ice_pf *pf);
int
ice_eswitch_add_vf_mac_rule(struct ice_pf *pf, struct ice_vf *vf,
			    const u8 *mac);
void ice_eswitch_replay_vf_mac_rule(struct ice_vf *vf);
void ice_eswitch_del_vf_mac_rule(struct ice_vf *vf);

void ice_eswitch_set_target_vsi(struct sk_buff *skb,
				struct ice_tx_offload_params *off);
netdev_tx_t
ice_eswitch_port_start_xmit(struct sk_buff *skb, struct net_device *netdev);
#else /* CONFIG_ICE_SWITCHDEV */
static inline void ice_eswitch_release(struct ice_pf *pf) { }

static inline void ice_eswitch_stop_all_tx_queues(struct ice_pf *pf) { }
static inline void ice_eswitch_replay_vf_mac_rule(struct ice_vf *vf) { }
static inline void ice_eswitch_del_vf_mac_rule(struct ice_vf *vf) { }

static inline int
ice_eswitch_add_vf_mac_rule(struct ice_pf *pf, struct ice_vf *vf,
			    const u8 *mac)
{
	return -EOPNOTSUPP;
}

static inline void
ice_eswitch_set_target_vsi(struct sk_buff *skb,
			   struct ice_tx_offload_params *off) { }

static inline void ice_eswitch_update_repr(struct ice_vsi *vsi) { }

static inline int ice_eswitch_configure(struct ice_pf *pf)
{
	return 0;
}

static inline int ice_eswitch_rebuild(struct ice_pf *pf)
{
	return -EOPNOTSUPP;
}

static inline int ice_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	return DEVLINK_ESWITCH_MODE_LEGACY;
}

static inline int
ice_eswitch_mode_set(struct devlink *devlink, u16 mode,
		     struct netlink_ext_ack *extack)
{
	return -EOPNOTSUPP;
}

static inline bool ice_is_eswitch_mode_switchdev(struct ice_pf *pf)
{
	return false;
}

static inline netdev_tx_t
ice_eswitch_port_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	return NETDEV_TX_BUSY;
}
#endif /* CONFIG_ICE_SWITCHDEV */
#endif /* _ICE_ESWITCH_H_ */
