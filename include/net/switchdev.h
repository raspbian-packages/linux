/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * include/net/switchdev.h - Switch device API
 * Copyright (c) 2014-2015 Jiri Pirko <jiri@resnulli.us>
 * Copyright (c) 2014-2015 Scott Feldman <sfeldma@gmail.com>
 */
#ifndef _LINUX_SWITCHDEV_H_
#define _LINUX_SWITCHDEV_H_

#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/list.h>
#include <net/ip_fib.h>

#define SWITCHDEV_F_NO_RECURSE		BIT(0)
#define SWITCHDEV_F_SKIP_EOPNOTSUPP	BIT(1)
#define SWITCHDEV_F_DEFER		BIT(2)

struct switchdev_trans {
	bool ph_prepare;
};

static inline bool switchdev_trans_ph_prepare(struct switchdev_trans *trans)
{
	return trans && trans->ph_prepare;
}

static inline bool switchdev_trans_ph_commit(struct switchdev_trans *trans)
{
	return trans && !trans->ph_prepare;
}

enum switchdev_attr_id {
	SWITCHDEV_ATTR_ID_UNDEFINED,
	SWITCHDEV_ATTR_ID_PORT_STP_STATE,
	SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS,
	SWITCHDEV_ATTR_ID_PORT_PRE_BRIDGE_FLAGS,
	SWITCHDEV_ATTR_ID_PORT_MROUTER,
	SWITCHDEV_ATTR_ID_BRIDGE_AGEING_TIME,
	SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING,
	SWITCHDEV_ATTR_ID_BRIDGE_MC_DISABLED,
	SWITCHDEV_ATTR_ID_BRIDGE_MROUTER,
};

struct switchdev_attr {
	struct net_device *orig_dev;
	enum switchdev_attr_id id;
	u32 flags;
	void *complete_priv;
	void (*complete)(struct net_device *dev, int err, void *priv);
	union {
		u8 stp_state;				/* PORT_STP_STATE */
		unsigned long brport_flags;		/* PORT_{PRE}_BRIDGE_FLAGS */
		bool mrouter;				/* PORT_MROUTER */
		clock_t ageing_time;			/* BRIDGE_AGEING_TIME */
		bool vlan_filtering;			/* BRIDGE_VLAN_FILTERING */
		bool mc_disabled;			/* MC_DISABLED */
	} u;
};

enum switchdev_obj_id {
	SWITCHDEV_OBJ_ID_UNDEFINED,
	SWITCHDEV_OBJ_ID_PORT_VLAN,
	SWITCHDEV_OBJ_ID_PORT_MDB,
	SWITCHDEV_OBJ_ID_HOST_MDB,
};

struct switchdev_obj {
	struct net_device *orig_dev;
	enum switchdev_obj_id id;
	u32 flags;
	void *complete_priv;
	void (*complete)(struct net_device *dev, int err, void *priv);
};

/* SWITCHDEV_OBJ_ID_PORT_VLAN */
struct switchdev_obj_port_vlan {
	struct switchdev_obj obj;
	u16 flags;
	u16 vid_begin;
	u16 vid_end;
};

#define SWITCHDEV_OBJ_PORT_VLAN(OBJ) \
	container_of((OBJ), struct switchdev_obj_port_vlan, obj)

/* SWITCHDEV_OBJ_ID_PORT_MDB */
struct switchdev_obj_port_mdb {
	struct switchdev_obj obj;
	unsigned char addr[ETH_ALEN];
	u16 vid;
};

#define SWITCHDEV_OBJ_PORT_MDB(OBJ) \
	container_of((OBJ), struct switchdev_obj_port_mdb, obj)

typedef int switchdev_obj_dump_cb_t(struct switchdev_obj *obj);

enum switchdev_notifier_type {
	SWITCHDEV_FDB_ADD_TO_BRIDGE = 1,
	SWITCHDEV_FDB_DEL_TO_BRIDGE,
	SWITCHDEV_FDB_ADD_TO_DEVICE,
	SWITCHDEV_FDB_DEL_TO_DEVICE,
	SWITCHDEV_FDB_OFFLOADED,

	SWITCHDEV_PORT_OBJ_ADD, /* Blocking. */
	SWITCHDEV_PORT_OBJ_DEL, /* Blocking. */
	SWITCHDEV_PORT_ATTR_SET, /* May be blocking . */

	SWITCHDEV_VXLAN_FDB_ADD_TO_BRIDGE,
	SWITCHDEV_VXLAN_FDB_DEL_TO_BRIDGE,
	SWITCHDEV_VXLAN_FDB_ADD_TO_DEVICE,
	SWITCHDEV_VXLAN_FDB_DEL_TO_DEVICE,
	SWITCHDEV_VXLAN_FDB_OFFLOADED,
};

struct switchdev_notifier_info {
	struct net_device *dev;
	struct netlink_ext_ack *extack;
};

struct switchdev_notifier_fdb_info {
	struct switchdev_notifier_info info; /* must be first */
	const unsigned char *addr;
	u16 vid;
	u8 added_by_user:1,
	   offloaded:1;
};

struct switchdev_notifier_port_obj_info {
	struct switchdev_notifier_info info; /* must be first */
	const struct switchdev_obj *obj;
	struct switchdev_trans *trans;
	bool handled;
};

struct switchdev_notifier_port_attr_info {
	struct switchdev_notifier_info info; /* must be first */
	const struct switchdev_attr *attr;
	struct switchdev_trans *trans;
	bool handled;
};

static inline struct net_device *
switchdev_notifier_info_to_dev(const struct switchdev_notifier_info *info)
{
	return info->dev;
}

static inline struct netlink_ext_ack *
switchdev_notifier_info_to_extack(const struct switchdev_notifier_info *info)
{
	return info->extack;
}

#ifdef CONFIG_NET_SWITCHDEV

void switchdev_deferred_process(void);
int switchdev_port_attr_set(struct net_device *dev,
			    const struct switchdev_attr *attr);
int switchdev_port_obj_add(struct net_device *dev,
			   const struct switchdev_obj *obj,
			   struct netlink_ext_ack *extack);
int switchdev_port_obj_del(struct net_device *dev,
			   const struct switchdev_obj *obj);

int register_switchdev_notifier(struct notifier_block *nb);
int unregister_switchdev_notifier(struct notifier_block *nb);
int call_switchdev_notifiers(unsigned long val, struct net_device *dev,
			     struct switchdev_notifier_info *info,
			     struct netlink_ext_ack *extack);

int register_switchdev_blocking_notifier(struct notifier_block *nb);
int unregister_switchdev_blocking_notifier(struct notifier_block *nb);
int call_switchdev_blocking_notifiers(unsigned long val, struct net_device *dev,
				      struct switchdev_notifier_info *info,
				      struct netlink_ext_ack *extack);

void switchdev_port_fwd_mark_set(struct net_device *dev,
				 struct net_device *group_dev,
				 bool joining);

int switchdev_handle_port_obj_add(struct net_device *dev,
			struct switchdev_notifier_port_obj_info *port_obj_info,
			bool (*check_cb)(const struct net_device *dev),
			int (*add_cb)(struct net_device *dev,
				      const struct switchdev_obj *obj,
				      struct switchdev_trans *trans,
				      struct netlink_ext_ack *extack));
int switchdev_handle_port_obj_del(struct net_device *dev,
			struct switchdev_notifier_port_obj_info *port_obj_info,
			bool (*check_cb)(const struct net_device *dev),
			int (*del_cb)(struct net_device *dev,
				      const struct switchdev_obj *obj));

int switchdev_handle_port_attr_set(struct net_device *dev,
			struct switchdev_notifier_port_attr_info *port_attr_info,
			bool (*check_cb)(const struct net_device *dev),
			int (*set_cb)(struct net_device *dev,
				      const struct switchdev_attr *attr,
				      struct switchdev_trans *trans));
#else

static inline void switchdev_deferred_process(void)
{
}

static inline int switchdev_port_attr_set(struct net_device *dev,
					  const struct switchdev_attr *attr)
{
	return -EOPNOTSUPP;
}

static inline int switchdev_port_obj_add(struct net_device *dev,
					 const struct switchdev_obj *obj,
					 struct netlink_ext_ack *extack)
{
	return -EOPNOTSUPP;
}

static inline int switchdev_port_obj_del(struct net_device *dev,
					 const struct switchdev_obj *obj)
{
	return -EOPNOTSUPP;
}

static inline int register_switchdev_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int unregister_switchdev_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int call_switchdev_notifiers(unsigned long val,
					   struct net_device *dev,
					   struct switchdev_notifier_info *info,
					   struct netlink_ext_ack *extack)
{
	return NOTIFY_DONE;
}

static inline int
register_switchdev_blocking_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int
unregister_switchdev_blocking_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int
call_switchdev_blocking_notifiers(unsigned long val,
				  struct net_device *dev,
				  struct switchdev_notifier_info *info,
				  struct netlink_ext_ack *extack)
{
	return NOTIFY_DONE;
}

static inline int
switchdev_handle_port_obj_add(struct net_device *dev,
			struct switchdev_notifier_port_obj_info *port_obj_info,
			bool (*check_cb)(const struct net_device *dev),
			int (*add_cb)(struct net_device *dev,
				      const struct switchdev_obj *obj,
				      struct switchdev_trans *trans,
				      struct netlink_ext_ack *extack))
{
	return 0;
}

static inline int
switchdev_handle_port_obj_del(struct net_device *dev,
			struct switchdev_notifier_port_obj_info *port_obj_info,
			bool (*check_cb)(const struct net_device *dev),
			int (*del_cb)(struct net_device *dev,
				      const struct switchdev_obj *obj))
{
	return 0;
}

static inline int
switchdev_handle_port_attr_set(struct net_device *dev,
			struct switchdev_notifier_port_attr_info *port_attr_info,
			bool (*check_cb)(const struct net_device *dev),
			int (*set_cb)(struct net_device *dev,
				      const struct switchdev_attr *attr,
				      struct switchdev_trans *trans))
{
	return 0;
}
#endif

#endif /* _LINUX_SWITCHDEV_H_ */
