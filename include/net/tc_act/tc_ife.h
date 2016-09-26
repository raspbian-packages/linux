#ifndef __NET_TC_IFE_H
#define __NET_TC_IFE_H

#include <net/act_api.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/module.h>

#define IFE_METAHDRLEN 2
struct tcf_ife_info {
	struct tcf_common common;
	u8 eth_dst[ETH_ALEN];
	u8 eth_src[ETH_ALEN];
	u16 eth_type;
	u16 flags;
	/* list of metaids allowed */
	struct list_head metalist;
};
#define to_ife(a) \
	container_of(a->priv, struct tcf_ife_info, common)

struct tcf_meta_info {
	const struct tcf_meta_ops *ops;
	void *metaval;
	u16 metaid;
	struct list_head metalist;
};

struct tcf_meta_ops {
	u16 metaid; /*Maintainer provided ID */
	u16 metatype; /*netlink attribute type (look at net/netlink.h) */
	const char *name;
	const char *synopsis;
	struct list_head list;
	int	(*check_presence)(struct sk_buff *, struct tcf_meta_info *);
	int	(*encode)(struct sk_buff *, void *, struct tcf_meta_info *);
	int	(*decode)(struct sk_buff *, void *, u16 len);
	int	(*get)(struct sk_buff *skb, struct tcf_meta_info *mi);
	int	(*alloc)(struct tcf_meta_info *, void *, gfp_t);
	void	(*release)(struct tcf_meta_info *);
	int	(*validate)(void *val, int len);
	struct module	*owner;
};

#define MODULE_ALIAS_IFE_META(metan)   MODULE_ALIAS("ifemeta" __stringify_1(metan))

int ife_get_meta_u32(struct sk_buff *skb, struct tcf_meta_info *mi);
int ife_get_meta_u16(struct sk_buff *skb, struct tcf_meta_info *mi);
int ife_tlv_meta_encode(void *skbdata, u16 attrtype, u16 dlen,
			const void *dval);
int ife_alloc_meta_u32(struct tcf_meta_info *mi, void *metaval, gfp_t gfp);
int ife_alloc_meta_u16(struct tcf_meta_info *mi, void *metaval, gfp_t gfp);
int ife_check_meta_u32(u32 metaval, struct tcf_meta_info *mi);
int ife_encode_meta_u32(u32 metaval, void *skbdata, struct tcf_meta_info *mi);
int ife_validate_meta_u32(void *val, int len);
int ife_validate_meta_u16(void *val, int len);
void ife_release_meta_gen(struct tcf_meta_info *mi);
int register_ife_op(struct tcf_meta_ops *mops);
int unregister_ife_op(struct tcf_meta_ops *mops);

#endif /* __NET_TC_IFE_H */
