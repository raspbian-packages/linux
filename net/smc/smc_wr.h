/*
 * Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 * Work Requests exploiting Infiniband API
 *
 * Copyright IBM Corp. 2016
 *
 * Author(s):  Steffen Maier <maier@linux.vnet.ibm.com>
 */

#ifndef SMC_WR_H
#define SMC_WR_H

#include <linux/atomic.h>
#include <rdma/ib_verbs.h>
#include <asm/div64.h>

#include "smc.h"
#include "smc_core.h"

#define SMC_WR_MAX_CQE 32768	/* max. # of completion queue elements */
#define SMC_WR_BUF_CNT 16	/* # of ctrl buffers per link */

#define SMC_WR_TX_WAIT_FREE_SLOT_TIME	(10 * HZ)
#define SMC_WR_TX_WAIT_PENDING_TIME	(5 * HZ)

#define SMC_WR_TX_SIZE 44 /* actual size of wr_send data (<=SMC_WR_BUF_SIZE) */

#define SMC_WR_TX_PEND_PRIV_SIZE 32

struct smc_wr_tx_pend_priv {
	u8			priv[SMC_WR_TX_PEND_PRIV_SIZE];
};

typedef void (*smc_wr_tx_handler)(struct smc_wr_tx_pend_priv *,
				  struct smc_link *,
				  enum ib_wc_status);

typedef bool (*smc_wr_tx_filter)(struct smc_wr_tx_pend_priv *,
				 unsigned long);

typedef void (*smc_wr_tx_dismisser)(struct smc_wr_tx_pend_priv *);

struct smc_wr_rx_handler {
	struct hlist_node	list;	/* hash table collision resolution */
	void			(*handler)(struct ib_wc *, void *);
	u8			type;
};

/* Only used by RDMA write WRs.
 * All other WRs (CDC/LLC) use smc_wr_tx_send handling WR_ID implicitly
 */
static inline long smc_wr_tx_get_next_wr_id(struct smc_link *link)
{
	return atomic_long_inc_return(&link->wr_tx_id);
}

static inline void smc_wr_tx_set_wr_id(atomic_long_t *wr_tx_id, long val)
{
	atomic_long_set(wr_tx_id, val);
}

/* post a new receive work request to fill a completed old work request entry */
static inline int smc_wr_rx_post(struct smc_link *link)
{
	struct ib_recv_wr *bad_recv_wr = NULL;
	int rc;
	u64 wr_id, temp_wr_id;
	u32 index;

	wr_id = ++link->wr_rx_id; /* tasklet context, thus not atomic */
	temp_wr_id = wr_id;
	index = do_div(temp_wr_id, link->wr_rx_cnt);
	link->wr_rx_ibs[index].wr_id = wr_id;
	rc = ib_post_recv(link->roce_qp, &link->wr_rx_ibs[index], &bad_recv_wr);
	return rc;
}

int smc_wr_create_link(struct smc_link *lnk);
int smc_wr_alloc_link_mem(struct smc_link *lnk);
void smc_wr_free_link(struct smc_link *lnk);
void smc_wr_free_link_mem(struct smc_link *lnk);
void smc_wr_remember_qp_attr(struct smc_link *lnk);
void smc_wr_remove_dev(struct smc_ib_device *smcibdev);
void smc_wr_add_dev(struct smc_ib_device *smcibdev);

int smc_wr_tx_get_free_slot(struct smc_link *link, smc_wr_tx_handler handler,
			    struct smc_wr_buf **wr_buf,
			    struct smc_wr_tx_pend_priv **wr_pend_priv);
int smc_wr_tx_put_slot(struct smc_link *link,
		       struct smc_wr_tx_pend_priv *wr_pend_priv);
int smc_wr_tx_send(struct smc_link *link,
		   struct smc_wr_tx_pend_priv *wr_pend_priv);
void smc_wr_tx_cq_handler(struct ib_cq *ib_cq, void *cq_context);
bool smc_wr_tx_has_pending(struct smc_link *link, u8 wr_rx_hdr_type,
			   smc_wr_tx_filter filter, unsigned long data);
void smc_wr_tx_dismiss_slots(struct smc_link *lnk, u8 wr_rx_hdr_type,
			     smc_wr_tx_filter filter,
			     smc_wr_tx_dismisser dismisser,
			     unsigned long data);

int smc_wr_rx_register_handler(struct smc_wr_rx_handler *handler);
int smc_wr_rx_post_init(struct smc_link *link);
void smc_wr_rx_cq_handler(struct ib_cq *ib_cq, void *cq_context);

#endif /* SMC_WR_H */
