/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_H
#define RXE_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>
#include <crypto/hash.h>

#include "rxe_net.h"
#include "rxe_opcode.h"
#include "rxe_hdr.h"
#include "rxe_param.h"
#include "rxe_verbs.h"
#include "rxe_loc.h"

/*
 * Version 1 and Version 2 are identical on 64 bit machines, but on 32 bit
 * machines Version 2 has a different struct layout.
 */
#define RXE_UVERBS_ABI_VERSION		2

#define RXE_ROCE_V2_SPORT		(0xc000)

#define rxe_dbg(rxe, fmt, ...) ibdev_dbg(&(rxe)->ib_dev,		\
		"%s: " fmt, __func__, ##__VA_ARGS__)
#define rxe_dbg_uc(uc, fmt, ...) ibdev_dbg((uc)->ibuc.device,		\
		"uc#%d %s: " fmt, (uc)->elem.index, __func__, ##__VA_ARGS__)
#define rxe_dbg_pd(pd, fmt, ...) ibdev_dbg((pd)->ibpd.device,		\
		"pd#%d %s: " fmt, (pd)->elem.index, __func__, ##__VA_ARGS__)
#define rxe_dbg_ah(ah, fmt, ...) ibdev_dbg((ah)->ibah.device,		\
		"ah#%d %s: " fmt, (ah)->elem.index, __func__, ##__VA_ARGS__)
#define rxe_dbg_srq(srq, fmt, ...) ibdev_dbg((srq)->ibsrq.device,	\
		"srq#%d %s: " fmt, (srq)->elem.index, __func__, ##__VA_ARGS__)
#define rxe_dbg_qp(qp, fmt, ...) ibdev_dbg((qp)->ibqp.device,		\
		"qp#%d %s: " fmt, (qp)->elem.index, __func__, ##__VA_ARGS__)
#define rxe_dbg_cq(cq, fmt, ...) ibdev_dbg((cq)->ibcq.device,		\
		"cq#%d %s: " fmt, (cq)->elem.index, __func__, ##__VA_ARGS__)
#define rxe_dbg_mr(mr, fmt, ...) ibdev_dbg((mr)->ibmr.device,		\
		"mr#%d %s:  " fmt, (mr)->elem.index, __func__, ##__VA_ARGS__)
#define rxe_dbg_mw(mw, fmt, ...) ibdev_dbg((mw)->ibmw.device,		\
		"mw#%d %s:  " fmt, (mw)->elem.index, __func__, ##__VA_ARGS__)

void rxe_set_mtu(struct rxe_dev *rxe, unsigned int dev_mtu);

int rxe_add(struct rxe_dev *rxe, unsigned int mtu, const char *ibdev_name);

void rxe_rcv(struct sk_buff *skb);

/* The caller must do a matching ib_device_put(&dev->ib_dev) */
static inline struct rxe_dev *rxe_get_dev_from_net(struct net_device *ndev)
{
	struct ib_device *ibdev =
		ib_device_get_by_netdev(ndev, RDMA_DRIVER_RXE);

	if (!ibdev)
		return NULL;
	return container_of(ibdev, struct rxe_dev, ib_dev);
}

void rxe_port_up(struct rxe_dev *rxe);
void rxe_port_down(struct rxe_dev *rxe);
void rxe_set_port_state(struct rxe_dev *rxe);

#endif /* RXE_H */
