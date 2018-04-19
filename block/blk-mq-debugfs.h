/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INT_BLK_MQ_DEBUGFS_H
#define INT_BLK_MQ_DEBUGFS_H

#ifdef CONFIG_BLK_DEBUG_FS

#include <linux/seq_file.h>

struct blk_mq_debugfs_attr {
	const char *name;
	umode_t mode;
	int (*show)(void *, struct seq_file *);
	ssize_t (*write)(void *, const char __user *, size_t, loff_t *);
	/* Set either .show or .seq_ops. */
	const struct seq_operations *seq_ops;
};

int __blk_mq_debugfs_rq_show(struct seq_file *m, struct request *rq);
int blk_mq_debugfs_rq_show(struct seq_file *m, void *v);

int blk_mq_debugfs_register(struct request_queue *q);
void blk_mq_debugfs_unregister(struct request_queue *q);
int blk_mq_debugfs_register_hctx(struct request_queue *q,
				 struct blk_mq_hw_ctx *hctx);
void blk_mq_debugfs_unregister_hctx(struct blk_mq_hw_ctx *hctx);
int blk_mq_debugfs_register_hctxs(struct request_queue *q);
void blk_mq_debugfs_unregister_hctxs(struct request_queue *q);

int blk_mq_debugfs_register_sched(struct request_queue *q);
void blk_mq_debugfs_unregister_sched(struct request_queue *q);
int blk_mq_debugfs_register_sched_hctx(struct request_queue *q,
				       struct blk_mq_hw_ctx *hctx);
void blk_mq_debugfs_unregister_sched_hctx(struct blk_mq_hw_ctx *hctx);
#else
static inline int blk_mq_debugfs_register(struct request_queue *q)
{
	return 0;
}

static inline void blk_mq_debugfs_unregister(struct request_queue *q)
{
}

static inline int blk_mq_debugfs_register_hctx(struct request_queue *q,
					       struct blk_mq_hw_ctx *hctx)
{
	return 0;
}

static inline void blk_mq_debugfs_unregister_hctx(struct blk_mq_hw_ctx *hctx)
{
}

static inline int blk_mq_debugfs_register_hctxs(struct request_queue *q)
{
	return 0;
}

static inline void blk_mq_debugfs_unregister_hctxs(struct request_queue *q)
{
}

static inline int blk_mq_debugfs_register_sched(struct request_queue *q)
{
	return 0;
}

static inline void blk_mq_debugfs_unregister_sched(struct request_queue *q)
{
}

static inline int blk_mq_debugfs_register_sched_hctx(struct request_queue *q,
						     struct blk_mq_hw_ctx *hctx)
{
	return 0;
}

static inline void blk_mq_debugfs_unregister_sched_hctx(struct blk_mq_hw_ctx *hctx)
{
}
#endif

#endif
