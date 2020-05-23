// SPDX-License-Identifier: GPL-2.0+
/*
 * caam - Freescale FSL CAAM support for hw_random
 *
 * Copyright 2011 Freescale Semiconductor, Inc.
 * Copyright 2018-2019 NXP
 *
 * Based on caamalg.c crypto API driver.
 *
 * relationship between job descriptors to shared descriptors:
 *
 * ---------------                     --------------
 * | JobDesc #0  |-------------------->| ShareDesc  |
 * | *(buffer 0) |      |------------->| (generate) |
 * ---------------      |              | (move)     |
 *                      |              | (store)    |
 * ---------------      |              --------------
 * | JobDesc #1  |------|
 * | *(buffer 1) |
 * ---------------
 *
 * A job desc looks like this:
 *
 * ---------------------
 * | Header            |
 * | ShareDesc Pointer |
 * | SEQ_OUT_PTR       |
 * | (output buffer)   |
 * ---------------------
 *
 * The SharedDesc never changes, and each job descriptor points to one of two
 * buffers for each device, from which the data will be copied into the
 * requested destination
 */

#include <linux/hw_random.h>
#include <linux/completion.h>
#include <linux/atomic.h>

#include "compat.h"

#include "regs.h"
#include "intern.h"
#include "desc_constr.h"
#include "jr.h"
#include "error.h"

/*
 * Maximum buffer size: maximum number of random, cache-aligned bytes that
 * will be generated and moved to seq out ptr (extlen not allowed)
 */
#define RN_BUF_SIZE			(0xffff / L1_CACHE_BYTES * \
					 L1_CACHE_BYTES)

/* length of descriptors */
#define DESC_JOB_O_LEN			(CAAM_CMD_SZ * 2 + CAAM_PTR_SZ_MAX * 2)
#define DESC_RNG_LEN			(3 * CAAM_CMD_SZ)

/* Buffer, its dma address and lock */
struct buf_data {
	u8 buf[RN_BUF_SIZE] ____cacheline_aligned;
	dma_addr_t addr;
	struct completion filled;
	u32 hw_desc[DESC_JOB_O_LEN];
#define BUF_NOT_EMPTY 0
#define BUF_EMPTY 1
#define BUF_PENDING 2  /* Empty, but with job pending --don't submit another */
	atomic_t empty;
};

/* rng per-device context */
struct caam_rng_ctx {
	struct device *jrdev;
	dma_addr_t sh_desc_dma;
	u32 sh_desc[DESC_RNG_LEN];
	unsigned int cur_buf_idx;
	int current_buf;
	struct buf_data bufs[2];
};

static struct caam_rng_ctx *rng_ctx;

/*
 * Variable used to avoid double free of resources in case
 * algorithm registration was unsuccessful
 */
static bool init_done;

static inline void rng_unmap_buf(struct device *jrdev, struct buf_data *bd)
{
	if (bd->addr)
		dma_unmap_single(jrdev, bd->addr, RN_BUF_SIZE,
				 DMA_FROM_DEVICE);
}

static inline void rng_unmap_ctx(struct caam_rng_ctx *ctx)
{
	struct device *jrdev = ctx->jrdev;

	if (ctx->sh_desc_dma)
		dma_unmap_single(jrdev, ctx->sh_desc_dma,
				 desc_bytes(ctx->sh_desc), DMA_TO_DEVICE);
	rng_unmap_buf(jrdev, &ctx->bufs[0]);
	rng_unmap_buf(jrdev, &ctx->bufs[1]);
}

static void rng_done(struct device *jrdev, u32 *desc, u32 err, void *context)
{
	struct buf_data *bd;

	bd = container_of(desc, struct buf_data, hw_desc[0]);

	if (err)
		caam_jr_strstatus(jrdev, err);

	atomic_set(&bd->empty, BUF_NOT_EMPTY);
	complete(&bd->filled);

	/* Buffer refilled, invalidate cache */
	dma_sync_single_for_cpu(jrdev, bd->addr, RN_BUF_SIZE, DMA_FROM_DEVICE);

	print_hex_dump_debug("rng refreshed buf@: ", DUMP_PREFIX_ADDRESS, 16, 4,
			     bd->buf, RN_BUF_SIZE, 1);
}

static inline int submit_job(struct caam_rng_ctx *ctx, int to_current)
{
	struct buf_data *bd = &ctx->bufs[!(to_current ^ ctx->current_buf)];
	struct device *jrdev = ctx->jrdev;
	u32 *desc = bd->hw_desc;
	int err;

	dev_dbg(jrdev, "submitting job %d\n", !(to_current ^ ctx->current_buf));
	init_completion(&bd->filled);
	err = caam_jr_enqueue(jrdev, desc, rng_done, ctx);
	if (err)
		complete(&bd->filled); /* don't wait on failed job*/
	else
		atomic_inc(&bd->empty); /* note if pending */

	return err;
}

static int caam_read(struct hwrng *rng, void *data, size_t max, bool wait)
{
	struct caam_rng_ctx *ctx = rng_ctx;
	struct buf_data *bd = &ctx->bufs[ctx->current_buf];
	int next_buf_idx, copied_idx;
	int err;

	if (atomic_read(&bd->empty)) {
		/* try to submit job if there wasn't one */
		if (atomic_read(&bd->empty) == BUF_EMPTY) {
			err = submit_job(ctx, 1);
			/* if can't submit job, can't even wait */
			if (err)
				return 0;
		}
		/* no immediate data, so exit if not waiting */
		if (!wait)
			return 0;

		/* waiting for pending job */
		if (atomic_read(&bd->empty))
			wait_for_completion(&bd->filled);
	}

	next_buf_idx = ctx->cur_buf_idx + max;
	dev_dbg(ctx->jrdev, "%s: start reading at buffer %d, idx %d\n",
		 __func__, ctx->current_buf, ctx->cur_buf_idx);

	/* if enough data in current buffer */
	if (next_buf_idx < RN_BUF_SIZE) {
		memcpy(data, bd->buf + ctx->cur_buf_idx, max);
		ctx->cur_buf_idx = next_buf_idx;
		return max;
	}

	/* else, copy what's left... */
	copied_idx = RN_BUF_SIZE - ctx->cur_buf_idx;
	memcpy(data, bd->buf + ctx->cur_buf_idx, copied_idx);
	ctx->cur_buf_idx = 0;
	atomic_set(&bd->empty, BUF_EMPTY);

	/* ...refill... */
	submit_job(ctx, 1);

	/* and use next buffer */
	ctx->current_buf = !ctx->current_buf;
	dev_dbg(ctx->jrdev, "switched to buffer %d\n", ctx->current_buf);

	/* since there already is some data read, don't wait */
	return copied_idx + caam_read(rng, data + copied_idx,
				      max - copied_idx, false);
}

static inline int rng_create_sh_desc(struct caam_rng_ctx *ctx)
{
	struct device *jrdev = ctx->jrdev;
	u32 *desc = ctx->sh_desc;

	init_sh_desc(desc, HDR_SHARE_SERIAL);

	/* Generate random bytes */
	append_operation(desc, OP_ALG_ALGSEL_RNG | OP_TYPE_CLASS1_ALG);

	/* Store bytes */
	append_seq_fifo_store(desc, RN_BUF_SIZE, FIFOST_TYPE_RNGSTORE);

	ctx->sh_desc_dma = dma_map_single(jrdev, desc, desc_bytes(desc),
					  DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev, ctx->sh_desc_dma)) {
		dev_err(jrdev, "unable to map shared descriptor\n");
		return -ENOMEM;
	}

	print_hex_dump_debug("rng shdesc@: ", DUMP_PREFIX_ADDRESS, 16, 4,
			     desc, desc_bytes(desc), 1);

	return 0;
}

static inline int rng_create_job_desc(struct caam_rng_ctx *ctx, int buf_id)
{
	struct device *jrdev = ctx->jrdev;
	struct buf_data *bd = &ctx->bufs[buf_id];
	u32 *desc = bd->hw_desc;
	int sh_len = desc_len(ctx->sh_desc);

	init_job_desc_shared(desc, ctx->sh_desc_dma, sh_len, HDR_SHARE_DEFER |
			     HDR_REVERSE);

	bd->addr = dma_map_single(jrdev, bd->buf, RN_BUF_SIZE, DMA_FROM_DEVICE);
	if (dma_mapping_error(jrdev, bd->addr)) {
		dev_err(jrdev, "unable to map dst\n");
		return -ENOMEM;
	}

	append_seq_out_ptr_intlen(desc, bd->addr, RN_BUF_SIZE, 0);

	print_hex_dump_debug("rng job desc@: ", DUMP_PREFIX_ADDRESS, 16, 4,
			     desc, desc_bytes(desc), 1);

	return 0;
}

static void caam_cleanup(struct hwrng *rng)
{
	int i;
	struct buf_data *bd;

	for (i = 0; i < 2; i++) {
		bd = &rng_ctx->bufs[i];
		if (atomic_read(&bd->empty) == BUF_PENDING)
			wait_for_completion(&bd->filled);
	}

	rng_unmap_ctx(rng_ctx);
}

static int caam_init_buf(struct caam_rng_ctx *ctx, int buf_id)
{
	struct buf_data *bd = &ctx->bufs[buf_id];
	int err;

	err = rng_create_job_desc(ctx, buf_id);
	if (err)
		return err;

	atomic_set(&bd->empty, BUF_EMPTY);
	submit_job(ctx, buf_id == ctx->current_buf);
	wait_for_completion(&bd->filled);

	return 0;
}

static int caam_init_rng(struct caam_rng_ctx *ctx, struct device *jrdev)
{
	int err;

	ctx->jrdev = jrdev;

	err = rng_create_sh_desc(ctx);
	if (err)
		return err;

	ctx->current_buf = 0;
	ctx->cur_buf_idx = 0;

	err = caam_init_buf(ctx, 0);
	if (err)
		return err;

	return caam_init_buf(ctx, 1);
}

static struct hwrng caam_rng = {
	.name		= "rng-caam",
	.cleanup	= caam_cleanup,
	.read		= caam_read,
};

void caam_rng_exit(void)
{
	if (!init_done)
		return;

	caam_jr_free(rng_ctx->jrdev);
	hwrng_unregister(&caam_rng);
	kfree(rng_ctx);
}

int caam_rng_init(struct device *ctrldev)
{
	struct device *dev;
	u32 rng_inst;
	struct caam_drv_private *priv = dev_get_drvdata(ctrldev);
	int err;
	init_done = false;

	/* Check for an instantiated RNG before registration */
	if (priv->era < 10)
		rng_inst = (rd_reg32(&priv->ctrl->perfmon.cha_num_ls) &
			    CHA_ID_LS_RNG_MASK) >> CHA_ID_LS_RNG_SHIFT;
	else
		rng_inst = rd_reg32(&priv->ctrl->vreg.rng) & CHA_VER_NUM_MASK;

	if (!rng_inst)
		return 0;

	dev = caam_jr_alloc();
	if (IS_ERR(dev)) {
		pr_err("Job Ring Device allocation for transform failed\n");
		return PTR_ERR(dev);
	}
	rng_ctx = kmalloc(sizeof(*rng_ctx), GFP_DMA | GFP_KERNEL);
	if (!rng_ctx) {
		err = -ENOMEM;
		goto free_caam_alloc;
	}
	err = caam_init_rng(rng_ctx, dev);
	if (err)
		goto free_rng_ctx;

	dev_info(dev, "registering rng-caam\n");

	err = hwrng_register(&caam_rng);
	if (!err) {
		init_done = true;
		return err;
	}

free_rng_ctx:
	kfree(rng_ctx);
free_caam_alloc:
	caam_jr_free(dev);
	return err;
}
