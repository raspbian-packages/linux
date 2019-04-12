/*
 * DMA controller driver for CSR SiRFprimaII
 *
 * Copyright (c) 2011 Cambridge Silicon Radio Limited, a CSR plc group company.
 *
 * Licensed under GPLv2 or later.
 */

#include <linux/module.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/clk.h>
#include <linux/of_dma.h>
#include <linux/sirfsoc_dma.h>

#include "dmaengine.h"

#define SIRFSOC_DMA_VER_A7V1                    1
#define SIRFSOC_DMA_VER_A7V2                    2
#define SIRFSOC_DMA_VER_A6                      4

#define SIRFSOC_DMA_DESCRIPTORS                 16
#define SIRFSOC_DMA_CHANNELS                    16
#define SIRFSOC_DMA_TABLE_NUM                   256

#define SIRFSOC_DMA_CH_ADDR                     0x00
#define SIRFSOC_DMA_CH_XLEN                     0x04
#define SIRFSOC_DMA_CH_YLEN                     0x08
#define SIRFSOC_DMA_CH_CTRL                     0x0C

#define SIRFSOC_DMA_WIDTH_0                     0x100
#define SIRFSOC_DMA_CH_VALID                    0x140
#define SIRFSOC_DMA_CH_INT                      0x144
#define SIRFSOC_DMA_INT_EN                      0x148
#define SIRFSOC_DMA_INT_EN_CLR                  0x14C
#define SIRFSOC_DMA_CH_LOOP_CTRL                0x150
#define SIRFSOC_DMA_CH_LOOP_CTRL_CLR            0x154
#define SIRFSOC_DMA_WIDTH_ATLAS7                0x10
#define SIRFSOC_DMA_VALID_ATLAS7                0x14
#define SIRFSOC_DMA_INT_ATLAS7                  0x18
#define SIRFSOC_DMA_INT_EN_ATLAS7               0x1c
#define SIRFSOC_DMA_LOOP_CTRL_ATLAS7            0x20
#define SIRFSOC_DMA_CUR_DATA_ADDR               0x34
#define SIRFSOC_DMA_MUL_ATLAS7                  0x38
#define SIRFSOC_DMA_CH_LOOP_CTRL_ATLAS7         0x158
#define SIRFSOC_DMA_CH_LOOP_CTRL_CLR_ATLAS7     0x15C
#define SIRFSOC_DMA_IOBG_SCMD_EN		0x800
#define SIRFSOC_DMA_EARLY_RESP_SET		0x818
#define SIRFSOC_DMA_EARLY_RESP_CLR		0x81C

#define SIRFSOC_DMA_MODE_CTRL_BIT               4
#define SIRFSOC_DMA_DIR_CTRL_BIT                5
#define SIRFSOC_DMA_MODE_CTRL_BIT_ATLAS7        2
#define SIRFSOC_DMA_CHAIN_CTRL_BIT_ATLAS7       3
#define SIRFSOC_DMA_DIR_CTRL_BIT_ATLAS7         4
#define SIRFSOC_DMA_TAB_NUM_ATLAS7              7
#define SIRFSOC_DMA_CHAIN_INT_BIT_ATLAS7        5
#define SIRFSOC_DMA_CHAIN_FLAG_SHIFT_ATLAS7     25
#define SIRFSOC_DMA_CHAIN_ADDR_SHIFT            32

#define SIRFSOC_DMA_INT_FINI_INT_ATLAS7         BIT(0)
#define SIRFSOC_DMA_INT_CNT_INT_ATLAS7          BIT(1)
#define SIRFSOC_DMA_INT_PAU_INT_ATLAS7          BIT(2)
#define SIRFSOC_DMA_INT_LOOP_INT_ATLAS7         BIT(3)
#define SIRFSOC_DMA_INT_INV_INT_ATLAS7          BIT(4)
#define SIRFSOC_DMA_INT_END_INT_ATLAS7          BIT(5)
#define SIRFSOC_DMA_INT_ALL_ATLAS7              0x3F

/* xlen and dma_width register is in 4 bytes boundary */
#define SIRFSOC_DMA_WORD_LEN			4
#define SIRFSOC_DMA_XLEN_MAX_V1         0x800
#define SIRFSOC_DMA_XLEN_MAX_V2         0x1000

struct sirfsoc_dma_desc {
	struct dma_async_tx_descriptor	desc;
	struct list_head		node;

	/* SiRFprimaII 2D-DMA parameters */

	int             xlen;           /* DMA xlen */
	int             ylen;           /* DMA ylen */
	int             width;          /* DMA width */
	int             dir;
	bool            cyclic;         /* is loop DMA? */
	bool            chain;          /* is chain DMA? */
	u32             addr;		/* DMA buffer address */
	u64 chain_table[SIRFSOC_DMA_TABLE_NUM]; /* chain tbl */
};

struct sirfsoc_dma_chan {
	struct dma_chan			chan;
	struct list_head		free;
	struct list_head		prepared;
	struct list_head		queued;
	struct list_head		active;
	struct list_head		completed;
	unsigned long			happened_cyclic;
	unsigned long			completed_cyclic;

	/* Lock for this structure */
	spinlock_t			lock;

	int				mode;
};

struct sirfsoc_dma_regs {
	u32				ctrl[SIRFSOC_DMA_CHANNELS];
	u32				interrupt_en;
};

struct sirfsoc_dma {
	struct dma_device		dma;
	struct tasklet_struct		tasklet;
	struct sirfsoc_dma_chan		channels[SIRFSOC_DMA_CHANNELS];
	void __iomem			*base;
	int				irq;
	struct clk			*clk;
	int				type;
	void (*exec_desc)(struct sirfsoc_dma_desc *sdesc,
		int cid, int burst_mode, void __iomem *base);
	struct sirfsoc_dma_regs		regs_save;
};

struct sirfsoc_dmadata {
	void (*exec)(struct sirfsoc_dma_desc *sdesc,
		int cid, int burst_mode, void __iomem *base);
	int type;
};

enum sirfsoc_dma_chain_flag {
	SIRFSOC_DMA_CHAIN_NORMAL = 0x01,
	SIRFSOC_DMA_CHAIN_PAUSE = 0x02,
	SIRFSOC_DMA_CHAIN_LOOP = 0x03,
	SIRFSOC_DMA_CHAIN_END = 0x04
};

#define DRV_NAME	"sirfsoc_dma"

static int sirfsoc_dma_runtime_suspend(struct device *dev);

/* Convert struct dma_chan to struct sirfsoc_dma_chan */
static inline
struct sirfsoc_dma_chan *dma_chan_to_sirfsoc_dma_chan(struct dma_chan *c)
{
	return container_of(c, struct sirfsoc_dma_chan, chan);
}

/* Convert struct dma_chan to struct sirfsoc_dma */
static inline struct sirfsoc_dma *dma_chan_to_sirfsoc_dma(struct dma_chan *c)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(c);
	return container_of(schan, struct sirfsoc_dma, channels[c->chan_id]);
}

static void sirfsoc_dma_execute_hw_a7v2(struct sirfsoc_dma_desc *sdesc,
		int cid, int burst_mode, void __iomem *base)
{
	if (sdesc->chain) {
		/* DMA v2 HW chain mode */
		writel_relaxed((sdesc->dir << SIRFSOC_DMA_DIR_CTRL_BIT_ATLAS7) |
			       (sdesc->chain <<
				SIRFSOC_DMA_CHAIN_CTRL_BIT_ATLAS7) |
			       (0x8 << SIRFSOC_DMA_TAB_NUM_ATLAS7) | 0x3,
			       base + SIRFSOC_DMA_CH_CTRL);
	} else {
		/* DMA v2 legacy mode */
		writel_relaxed(sdesc->xlen, base + SIRFSOC_DMA_CH_XLEN);
		writel_relaxed(sdesc->ylen, base + SIRFSOC_DMA_CH_YLEN);
		writel_relaxed(sdesc->width, base + SIRFSOC_DMA_WIDTH_ATLAS7);
		writel_relaxed((sdesc->width*((sdesc->ylen+1)>>1)),
				base + SIRFSOC_DMA_MUL_ATLAS7);
		writel_relaxed((sdesc->dir << SIRFSOC_DMA_DIR_CTRL_BIT_ATLAS7) |
			       (sdesc->chain <<
				SIRFSOC_DMA_CHAIN_CTRL_BIT_ATLAS7) |
			       0x3, base + SIRFSOC_DMA_CH_CTRL);
	}
	writel_relaxed(sdesc->chain ? SIRFSOC_DMA_INT_END_INT_ATLAS7 :
		       (SIRFSOC_DMA_INT_FINI_INT_ATLAS7 |
			SIRFSOC_DMA_INT_LOOP_INT_ATLAS7),
		       base + SIRFSOC_DMA_INT_EN_ATLAS7);
	writel(sdesc->addr, base + SIRFSOC_DMA_CH_ADDR);
	if (sdesc->cyclic)
		writel(0x10001, base + SIRFSOC_DMA_LOOP_CTRL_ATLAS7);
}

static void sirfsoc_dma_execute_hw_a7v1(struct sirfsoc_dma_desc *sdesc,
		int cid, int burst_mode, void __iomem *base)
{
	writel_relaxed(1, base + SIRFSOC_DMA_IOBG_SCMD_EN);
	writel_relaxed((1 << cid), base + SIRFSOC_DMA_EARLY_RESP_SET);
	writel_relaxed(sdesc->width, base + SIRFSOC_DMA_WIDTH_0 + cid * 4);
	writel_relaxed(cid | (burst_mode << SIRFSOC_DMA_MODE_CTRL_BIT) |
		       (sdesc->dir << SIRFSOC_DMA_DIR_CTRL_BIT),
		       base + cid * 0x10 + SIRFSOC_DMA_CH_CTRL);
	writel_relaxed(sdesc->xlen, base + cid * 0x10 + SIRFSOC_DMA_CH_XLEN);
	writel_relaxed(sdesc->ylen, base + cid * 0x10 + SIRFSOC_DMA_CH_YLEN);
	writel_relaxed(readl_relaxed(base + SIRFSOC_DMA_INT_EN) |
		       (1 << cid), base + SIRFSOC_DMA_INT_EN);
	writel(sdesc->addr >> 2, base + cid * 0x10 + SIRFSOC_DMA_CH_ADDR);
	if (sdesc->cyclic) {
		writel((1 << cid) | 1 << (cid + 16) |
		       readl_relaxed(base + SIRFSOC_DMA_CH_LOOP_CTRL_ATLAS7),
		       base + SIRFSOC_DMA_CH_LOOP_CTRL_ATLAS7);
	}

}

static void sirfsoc_dma_execute_hw_a6(struct sirfsoc_dma_desc *sdesc,
		int cid, int burst_mode, void __iomem *base)
{
	writel_relaxed(sdesc->width, base + SIRFSOC_DMA_WIDTH_0 + cid * 4);
	writel_relaxed(cid | (burst_mode << SIRFSOC_DMA_MODE_CTRL_BIT) |
		       (sdesc->dir << SIRFSOC_DMA_DIR_CTRL_BIT),
		       base + cid * 0x10 + SIRFSOC_DMA_CH_CTRL);
	writel_relaxed(sdesc->xlen, base + cid * 0x10 + SIRFSOC_DMA_CH_XLEN);
	writel_relaxed(sdesc->ylen, base + cid * 0x10 + SIRFSOC_DMA_CH_YLEN);
	writel_relaxed(readl_relaxed(base + SIRFSOC_DMA_INT_EN) |
		       (1 << cid), base + SIRFSOC_DMA_INT_EN);
	writel(sdesc->addr >> 2, base + cid * 0x10 + SIRFSOC_DMA_CH_ADDR);
	if (sdesc->cyclic) {
		writel((1 << cid) | 1 << (cid + 16) |
		       readl_relaxed(base + SIRFSOC_DMA_CH_LOOP_CTRL),
		       base + SIRFSOC_DMA_CH_LOOP_CTRL);
	}

}

/* Execute all queued DMA descriptors */
static void sirfsoc_dma_execute(struct sirfsoc_dma_chan *schan)
{
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(&schan->chan);
	int cid = schan->chan.chan_id;
	struct sirfsoc_dma_desc *sdesc = NULL;
	void __iomem *base;

	/*
	 * lock has been held by functions calling this, so we don't hold
	 * lock again
	 */
	base = sdma->base;
	sdesc = list_first_entry(&schan->queued, struct sirfsoc_dma_desc,
				 node);
	/* Move the first queued descriptor to active list */
	list_move_tail(&sdesc->node, &schan->active);

	if (sdma->type == SIRFSOC_DMA_VER_A7V2)
		cid = 0;

	/* Start the DMA transfer */
	sdma->exec_desc(sdesc, cid, schan->mode, base);

	if (sdesc->cyclic)
		schan->happened_cyclic = schan->completed_cyclic = 0;
}

/* Interrupt handler */
static irqreturn_t sirfsoc_dma_irq(int irq, void *data)
{
	struct sirfsoc_dma *sdma = data;
	struct sirfsoc_dma_chan *schan;
	struct sirfsoc_dma_desc *sdesc = NULL;
	u32 is;
	bool chain;
	int ch;
	void __iomem *reg;

	switch (sdma->type) {
	case SIRFSOC_DMA_VER_A6:
	case SIRFSOC_DMA_VER_A7V1:
		is = readl(sdma->base + SIRFSOC_DMA_CH_INT);
		reg = sdma->base + SIRFSOC_DMA_CH_INT;
		while ((ch = fls(is) - 1) >= 0) {
			is &= ~(1 << ch);
			writel_relaxed(1 << ch, reg);
			schan = &sdma->channels[ch];
			spin_lock(&schan->lock);
			sdesc = list_first_entry(&schan->active,
						 struct sirfsoc_dma_desc, node);
			if (!sdesc->cyclic) {
				/* Execute queued descriptors */
				list_splice_tail_init(&schan->active,
						      &schan->completed);
				dma_cookie_complete(&sdesc->desc);
				if (!list_empty(&schan->queued))
					sirfsoc_dma_execute(schan);
			} else
				schan->happened_cyclic++;
			spin_unlock(&schan->lock);
		}
		break;

	case SIRFSOC_DMA_VER_A7V2:
		is = readl(sdma->base + SIRFSOC_DMA_INT_ATLAS7);

		reg = sdma->base + SIRFSOC_DMA_INT_ATLAS7;
		writel_relaxed(SIRFSOC_DMA_INT_ALL_ATLAS7, reg);
		schan = &sdma->channels[0];
		spin_lock(&schan->lock);
		sdesc = list_first_entry(&schan->active,
					 struct sirfsoc_dma_desc, node);
		if (!sdesc->cyclic) {
			chain = sdesc->chain;
			if ((chain && (is & SIRFSOC_DMA_INT_END_INT_ATLAS7)) ||
				(!chain &&
				(is & SIRFSOC_DMA_INT_FINI_INT_ATLAS7))) {
				/* Execute queued descriptors */
				list_splice_tail_init(&schan->active,
						      &schan->completed);
				dma_cookie_complete(&sdesc->desc);
				if (!list_empty(&schan->queued))
					sirfsoc_dma_execute(schan);
			}
		} else if (sdesc->cyclic && (is &
					SIRFSOC_DMA_INT_LOOP_INT_ATLAS7))
			schan->happened_cyclic++;

		spin_unlock(&schan->lock);
		break;

	default:
		break;
	}

	/* Schedule tasklet */
	tasklet_schedule(&sdma->tasklet);

	return IRQ_HANDLED;
}

/* process completed descriptors */
static void sirfsoc_dma_process_completed(struct sirfsoc_dma *sdma)
{
	dma_cookie_t last_cookie = 0;
	struct sirfsoc_dma_chan *schan;
	struct sirfsoc_dma_desc *sdesc;
	struct dma_async_tx_descriptor *desc;
	unsigned long flags;
	unsigned long happened_cyclic;
	LIST_HEAD(list);
	int i;

	for (i = 0; i < sdma->dma.chancnt; i++) {
		schan = &sdma->channels[i];

		/* Get all completed descriptors */
		spin_lock_irqsave(&schan->lock, flags);
		if (!list_empty(&schan->completed)) {
			list_splice_tail_init(&schan->completed, &list);
			spin_unlock_irqrestore(&schan->lock, flags);

			/* Execute callbacks and run dependencies */
			list_for_each_entry(sdesc, &list, node) {
				desc = &sdesc->desc;

				dmaengine_desc_get_callback_invoke(desc, NULL);
				last_cookie = desc->cookie;
				dma_run_dependencies(desc);
			}

			/* Free descriptors */
			spin_lock_irqsave(&schan->lock, flags);
			list_splice_tail_init(&list, &schan->free);
			schan->chan.completed_cookie = last_cookie;
			spin_unlock_irqrestore(&schan->lock, flags);
		} else {
			if (list_empty(&schan->active)) {
				spin_unlock_irqrestore(&schan->lock, flags);
				continue;
			}

			/* for cyclic channel, desc is always in active list */
			sdesc = list_first_entry(&schan->active,
				struct sirfsoc_dma_desc, node);

			/* cyclic DMA */
			happened_cyclic = schan->happened_cyclic;
			spin_unlock_irqrestore(&schan->lock, flags);

			desc = &sdesc->desc;
			while (happened_cyclic != schan->completed_cyclic) {
				dmaengine_desc_get_callback_invoke(desc, NULL);
				schan->completed_cyclic++;
			}
		}
	}
}

/* DMA Tasklet */
static void sirfsoc_dma_tasklet(unsigned long data)
{
	struct sirfsoc_dma *sdma = (void *)data;

	sirfsoc_dma_process_completed(sdma);
}

/* Submit descriptor to hardware */
static dma_cookie_t sirfsoc_dma_tx_submit(struct dma_async_tx_descriptor *txd)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(txd->chan);
	struct sirfsoc_dma_desc *sdesc;
	unsigned long flags;
	dma_cookie_t cookie;

	sdesc = container_of(txd, struct sirfsoc_dma_desc, desc);

	spin_lock_irqsave(&schan->lock, flags);

	/* Move descriptor to queue */
	list_move_tail(&sdesc->node, &schan->queued);

	cookie = dma_cookie_assign(txd);

	spin_unlock_irqrestore(&schan->lock, flags);

	return cookie;
}

static int sirfsoc_dma_slave_config(struct dma_chan *chan,
				    struct dma_slave_config *config)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	unsigned long flags;

	if ((config->src_addr_width != DMA_SLAVE_BUSWIDTH_4_BYTES) ||
		(config->dst_addr_width != DMA_SLAVE_BUSWIDTH_4_BYTES))
		return -EINVAL;

	spin_lock_irqsave(&schan->lock, flags);
	schan->mode = (config->src_maxburst == 4 ? 1 : 0);
	spin_unlock_irqrestore(&schan->lock, flags);

	return 0;
}

static int sirfsoc_dma_terminate_all(struct dma_chan *chan)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(&schan->chan);
	int cid = schan->chan.chan_id;
	unsigned long flags;

	spin_lock_irqsave(&schan->lock, flags);

	switch (sdma->type) {
	case SIRFSOC_DMA_VER_A7V1:
		writel_relaxed(1 << cid, sdma->base + SIRFSOC_DMA_INT_EN_CLR);
		writel_relaxed(1 << cid, sdma->base + SIRFSOC_DMA_CH_INT);
		writel_relaxed((1 << cid) | 1 << (cid + 16),
			       sdma->base +
			       SIRFSOC_DMA_CH_LOOP_CTRL_CLR_ATLAS7);
		writel_relaxed(1 << cid, sdma->base + SIRFSOC_DMA_CH_VALID);
		break;
	case SIRFSOC_DMA_VER_A7V2:
		writel_relaxed(0, sdma->base + SIRFSOC_DMA_INT_EN_ATLAS7);
		writel_relaxed(SIRFSOC_DMA_INT_ALL_ATLAS7,
			       sdma->base + SIRFSOC_DMA_INT_ATLAS7);
		writel_relaxed(0, sdma->base + SIRFSOC_DMA_LOOP_CTRL_ATLAS7);
		writel_relaxed(0, sdma->base + SIRFSOC_DMA_VALID_ATLAS7);
		break;
	case SIRFSOC_DMA_VER_A6:
		writel_relaxed(readl_relaxed(sdma->base + SIRFSOC_DMA_INT_EN) &
			       ~(1 << cid), sdma->base + SIRFSOC_DMA_INT_EN);
		writel_relaxed(readl_relaxed(sdma->base +
					     SIRFSOC_DMA_CH_LOOP_CTRL) &
			       ~((1 << cid) | 1 << (cid + 16)),
			       sdma->base + SIRFSOC_DMA_CH_LOOP_CTRL);
		writel_relaxed(1 << cid, sdma->base + SIRFSOC_DMA_CH_VALID);
		break;
	default:
		break;
	}

	list_splice_tail_init(&schan->active, &schan->free);
	list_splice_tail_init(&schan->queued, &schan->free);

	spin_unlock_irqrestore(&schan->lock, flags);

	return 0;
}

static int sirfsoc_dma_pause_chan(struct dma_chan *chan)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(&schan->chan);
	int cid = schan->chan.chan_id;
	unsigned long flags;

	spin_lock_irqsave(&schan->lock, flags);

	switch (sdma->type) {
	case SIRFSOC_DMA_VER_A7V1:
		writel_relaxed((1 << cid) | 1 << (cid + 16),
			       sdma->base +
			       SIRFSOC_DMA_CH_LOOP_CTRL_CLR_ATLAS7);
		break;
	case SIRFSOC_DMA_VER_A7V2:
		writel_relaxed(0, sdma->base + SIRFSOC_DMA_LOOP_CTRL_ATLAS7);
		break;
	case SIRFSOC_DMA_VER_A6:
		writel_relaxed(readl_relaxed(sdma->base +
					     SIRFSOC_DMA_CH_LOOP_CTRL) &
			       ~((1 << cid) | 1 << (cid + 16)),
			       sdma->base + SIRFSOC_DMA_CH_LOOP_CTRL);
		break;

	default:
		break;
	}

	spin_unlock_irqrestore(&schan->lock, flags);

	return 0;
}

static int sirfsoc_dma_resume_chan(struct dma_chan *chan)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(&schan->chan);
	int cid = schan->chan.chan_id;
	unsigned long flags;

	spin_lock_irqsave(&schan->lock, flags);
	switch (sdma->type) {
	case SIRFSOC_DMA_VER_A7V1:
		writel_relaxed((1 << cid) | 1 << (cid + 16),
			       sdma->base + SIRFSOC_DMA_CH_LOOP_CTRL_ATLAS7);
		break;
	case SIRFSOC_DMA_VER_A7V2:
		writel_relaxed(0x10001,
			       sdma->base + SIRFSOC_DMA_LOOP_CTRL_ATLAS7);
		break;
	case SIRFSOC_DMA_VER_A6:
		writel_relaxed(readl_relaxed(sdma->base +
					     SIRFSOC_DMA_CH_LOOP_CTRL) |
			       ((1 << cid) | 1 << (cid + 16)),
			       sdma->base + SIRFSOC_DMA_CH_LOOP_CTRL);
		break;

	default:
		break;
	}

	spin_unlock_irqrestore(&schan->lock, flags);

	return 0;
}

/* Alloc channel resources */
static int sirfsoc_dma_alloc_chan_resources(struct dma_chan *chan)
{
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(chan);
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	struct sirfsoc_dma_desc *sdesc;
	unsigned long flags;
	LIST_HEAD(descs);
	int i;

	pm_runtime_get_sync(sdma->dma.dev);

	/* Alloc descriptors for this channel */
	for (i = 0; i < SIRFSOC_DMA_DESCRIPTORS; i++) {
		sdesc = kzalloc(sizeof(*sdesc), GFP_KERNEL);
		if (!sdesc) {
			dev_notice(sdma->dma.dev, "Memory allocation error. "
				"Allocated only %u descriptors\n", i);
			break;
		}

		dma_async_tx_descriptor_init(&sdesc->desc, chan);
		sdesc->desc.flags = DMA_CTRL_ACK;
		sdesc->desc.tx_submit = sirfsoc_dma_tx_submit;

		list_add_tail(&sdesc->node, &descs);
	}

	/* Return error only if no descriptors were allocated */
	if (i == 0)
		return -ENOMEM;

	spin_lock_irqsave(&schan->lock, flags);

	list_splice_tail_init(&descs, &schan->free);
	spin_unlock_irqrestore(&schan->lock, flags);

	return i;
}

/* Free channel resources */
static void sirfsoc_dma_free_chan_resources(struct dma_chan *chan)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(chan);
	struct sirfsoc_dma_desc *sdesc, *tmp;
	unsigned long flags;
	LIST_HEAD(descs);

	spin_lock_irqsave(&schan->lock, flags);

	/* Channel must be idle */
	BUG_ON(!list_empty(&schan->prepared));
	BUG_ON(!list_empty(&schan->queued));
	BUG_ON(!list_empty(&schan->active));
	BUG_ON(!list_empty(&schan->completed));

	/* Move data */
	list_splice_tail_init(&schan->free, &descs);

	spin_unlock_irqrestore(&schan->lock, flags);

	/* Free descriptors */
	list_for_each_entry_safe(sdesc, tmp, &descs, node)
		kfree(sdesc);

	pm_runtime_put(sdma->dma.dev);
}

/* Send pending descriptor to hardware */
static void sirfsoc_dma_issue_pending(struct dma_chan *chan)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	unsigned long flags;

	spin_lock_irqsave(&schan->lock, flags);

	if (list_empty(&schan->active) && !list_empty(&schan->queued))
		sirfsoc_dma_execute(schan);

	spin_unlock_irqrestore(&schan->lock, flags);
}

/* Check request completion status */
static enum dma_status
sirfsoc_dma_tx_status(struct dma_chan *chan, dma_cookie_t cookie,
	struct dma_tx_state *txstate)
{
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(chan);
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	unsigned long flags;
	enum dma_status ret;
	struct sirfsoc_dma_desc *sdesc;
	int cid = schan->chan.chan_id;
	unsigned long dma_pos;
	unsigned long dma_request_bytes;
	unsigned long residue;

	spin_lock_irqsave(&schan->lock, flags);

	if (list_empty(&schan->active)) {
		ret = dma_cookie_status(chan, cookie, txstate);
		dma_set_residue(txstate, 0);
		spin_unlock_irqrestore(&schan->lock, flags);
		return ret;
	}
	sdesc = list_first_entry(&schan->active, struct sirfsoc_dma_desc, node);
	if (sdesc->cyclic)
		dma_request_bytes = (sdesc->xlen + 1) * (sdesc->ylen + 1) *
			(sdesc->width * SIRFSOC_DMA_WORD_LEN);
	else
		dma_request_bytes = sdesc->xlen * SIRFSOC_DMA_WORD_LEN;

	ret = dma_cookie_status(chan, cookie, txstate);

	if (sdma->type == SIRFSOC_DMA_VER_A7V2)
		cid = 0;

	if (sdma->type == SIRFSOC_DMA_VER_A7V2) {
		dma_pos = readl_relaxed(sdma->base + SIRFSOC_DMA_CUR_DATA_ADDR);
	} else {
		dma_pos = readl_relaxed(
			sdma->base + cid * 0x10 + SIRFSOC_DMA_CH_ADDR) << 2;
	}

	residue = dma_request_bytes - (dma_pos - sdesc->addr);
	dma_set_residue(txstate, residue);

	spin_unlock_irqrestore(&schan->lock, flags);

	return ret;
}

static struct dma_async_tx_descriptor *sirfsoc_dma_prep_interleaved(
	struct dma_chan *chan, struct dma_interleaved_template *xt,
	unsigned long flags)
{
	struct sirfsoc_dma *sdma = dma_chan_to_sirfsoc_dma(chan);
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	struct sirfsoc_dma_desc *sdesc = NULL;
	unsigned long iflags;
	int ret;

	if ((xt->dir != DMA_MEM_TO_DEV) && (xt->dir != DMA_DEV_TO_MEM)) {
		ret = -EINVAL;
		goto err_dir;
	}

	/* Get free descriptor */
	spin_lock_irqsave(&schan->lock, iflags);
	if (!list_empty(&schan->free)) {
		sdesc = list_first_entry(&schan->free, struct sirfsoc_dma_desc,
			node);
		list_del(&sdesc->node);
	}
	spin_unlock_irqrestore(&schan->lock, iflags);

	if (!sdesc) {
		/* try to free completed descriptors */
		sirfsoc_dma_process_completed(sdma);
		ret = 0;
		goto no_desc;
	}

	/* Place descriptor in prepared list */
	spin_lock_irqsave(&schan->lock, iflags);

	/*
	 * Number of chunks in a frame can only be 1 for prima2
	 * and ylen (number of frame - 1) must be at least 0
	 */
	if ((xt->frame_size == 1) && (xt->numf > 0)) {
		sdesc->cyclic = 0;
		sdesc->xlen = xt->sgl[0].size / SIRFSOC_DMA_WORD_LEN;
		sdesc->width = (xt->sgl[0].size + xt->sgl[0].icg) /
				SIRFSOC_DMA_WORD_LEN;
		sdesc->ylen = xt->numf - 1;
		if (xt->dir == DMA_MEM_TO_DEV) {
			sdesc->addr = xt->src_start;
			sdesc->dir = 1;
		} else {
			sdesc->addr = xt->dst_start;
			sdesc->dir = 0;
		}

		list_add_tail(&sdesc->node, &schan->prepared);
	} else {
		pr_err("sirfsoc DMA Invalid xfer\n");
		ret = -EINVAL;
		goto err_xfer;
	}
	spin_unlock_irqrestore(&schan->lock, iflags);

	return &sdesc->desc;
err_xfer:
	spin_unlock_irqrestore(&schan->lock, iflags);
no_desc:
err_dir:
	return ERR_PTR(ret);
}

static struct dma_async_tx_descriptor *
sirfsoc_dma_prep_cyclic(struct dma_chan *chan, dma_addr_t addr,
	size_t buf_len, size_t period_len,
	enum dma_transfer_direction direction, unsigned long flags)
{
	struct sirfsoc_dma_chan *schan = dma_chan_to_sirfsoc_dma_chan(chan);
	struct sirfsoc_dma_desc *sdesc = NULL;
	unsigned long iflags;

	/*
	 * we only support cycle transfer with 2 period
	 * If the X-length is set to 0, it would be the loop mode.
	 * The DMA address keeps increasing until reaching the end of a loop
	 * area whose size is defined by (DMA_WIDTH x (Y_LENGTH + 1)). Then
	 * the DMA address goes back to the beginning of this area.
	 * In loop mode, the DMA data region is divided into two parts, BUFA
	 * and BUFB. DMA controller generates interrupts twice in each loop:
	 * when the DMA address reaches the end of BUFA or the end of the
	 * BUFB
	 */
	if (buf_len !=  2 * period_len)
		return ERR_PTR(-EINVAL);

	/* Get free descriptor */
	spin_lock_irqsave(&schan->lock, iflags);
	if (!list_empty(&schan->free)) {
		sdesc = list_first_entry(&schan->free, struct sirfsoc_dma_desc,
			node);
		list_del(&sdesc->node);
	}
	spin_unlock_irqrestore(&schan->lock, iflags);

	if (!sdesc)
		return NULL;

	/* Place descriptor in prepared list */
	spin_lock_irqsave(&schan->lock, iflags);
	sdesc->addr = addr;
	sdesc->cyclic = 1;
	sdesc->xlen = 0;
	sdesc->ylen = buf_len / SIRFSOC_DMA_WORD_LEN - 1;
	sdesc->width = 1;
	list_add_tail(&sdesc->node, &schan->prepared);
	spin_unlock_irqrestore(&schan->lock, iflags);

	return &sdesc->desc;
}

/*
 * The DMA controller consists of 16 independent DMA channels.
 * Each channel is allocated to a different function
 */
bool sirfsoc_dma_filter_id(struct dma_chan *chan, void *chan_id)
{
	unsigned int ch_nr = (unsigned int) chan_id;

	if (ch_nr == chan->chan_id +
		chan->device->dev_id * SIRFSOC_DMA_CHANNELS)
		return true;

	return false;
}
EXPORT_SYMBOL(sirfsoc_dma_filter_id);

#define SIRFSOC_DMA_BUSWIDTHS \
	(BIT(DMA_SLAVE_BUSWIDTH_UNDEFINED) | \
	BIT(DMA_SLAVE_BUSWIDTH_1_BYTE) | \
	BIT(DMA_SLAVE_BUSWIDTH_2_BYTES) | \
	BIT(DMA_SLAVE_BUSWIDTH_4_BYTES) | \
	BIT(DMA_SLAVE_BUSWIDTH_8_BYTES))

static struct dma_chan *of_dma_sirfsoc_xlate(struct of_phandle_args *dma_spec,
	struct of_dma *ofdma)
{
	struct sirfsoc_dma *sdma = ofdma->of_dma_data;
	unsigned int request = dma_spec->args[0];

	if (request >= SIRFSOC_DMA_CHANNELS)
		return NULL;

	return dma_get_slave_channel(&sdma->channels[request].chan);
}

static int sirfsoc_dma_probe(struct platform_device *op)
{
	struct device_node *dn = op->dev.of_node;
	struct device *dev = &op->dev;
	struct dma_device *dma;
	struct sirfsoc_dma *sdma;
	struct sirfsoc_dma_chan *schan;
	struct sirfsoc_dmadata *data;
	struct resource res;
	ulong regs_start, regs_size;
	u32 id;
	int ret, i;

	sdma = devm_kzalloc(dev, sizeof(*sdma), GFP_KERNEL);
	if (!sdma)
		return -ENOMEM;

	data = (struct sirfsoc_dmadata *)
		(of_match_device(op->dev.driver->of_match_table,
				 &op->dev)->data);
	sdma->exec_desc = data->exec;
	sdma->type = data->type;

	if (of_property_read_u32(dn, "cell-index", &id)) {
		dev_err(dev, "Fail to get DMAC index\n");
		return -ENODEV;
	}

	sdma->irq = irq_of_parse_and_map(dn, 0);
	if (!sdma->irq) {
		dev_err(dev, "Error mapping IRQ!\n");
		return -EINVAL;
	}

	sdma->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(sdma->clk)) {
		dev_err(dev, "failed to get a clock.\n");
		return PTR_ERR(sdma->clk);
	}

	ret = of_address_to_resource(dn, 0, &res);
	if (ret) {
		dev_err(dev, "Error parsing memory region!\n");
		goto irq_dispose;
	}

	regs_start = res.start;
	regs_size = resource_size(&res);

	sdma->base = devm_ioremap(dev, regs_start, regs_size);
	if (!sdma->base) {
		dev_err(dev, "Error mapping memory region!\n");
		ret = -ENOMEM;
		goto irq_dispose;
	}

	ret = request_irq(sdma->irq, &sirfsoc_dma_irq, 0, DRV_NAME, sdma);
	if (ret) {
		dev_err(dev, "Error requesting IRQ!\n");
		ret = -EINVAL;
		goto irq_dispose;
	}

	dma = &sdma->dma;
	dma->dev = dev;

	dma->device_alloc_chan_resources = sirfsoc_dma_alloc_chan_resources;
	dma->device_free_chan_resources = sirfsoc_dma_free_chan_resources;
	dma->device_issue_pending = sirfsoc_dma_issue_pending;
	dma->device_config = sirfsoc_dma_slave_config;
	dma->device_pause = sirfsoc_dma_pause_chan;
	dma->device_resume = sirfsoc_dma_resume_chan;
	dma->device_terminate_all = sirfsoc_dma_terminate_all;
	dma->device_tx_status = sirfsoc_dma_tx_status;
	dma->device_prep_interleaved_dma = sirfsoc_dma_prep_interleaved;
	dma->device_prep_dma_cyclic = sirfsoc_dma_prep_cyclic;
	dma->src_addr_widths = SIRFSOC_DMA_BUSWIDTHS;
	dma->dst_addr_widths = SIRFSOC_DMA_BUSWIDTHS;
	dma->directions = BIT(DMA_DEV_TO_MEM) | BIT(DMA_MEM_TO_DEV);

	INIT_LIST_HEAD(&dma->channels);
	dma_cap_set(DMA_SLAVE, dma->cap_mask);
	dma_cap_set(DMA_CYCLIC, dma->cap_mask);
	dma_cap_set(DMA_INTERLEAVE, dma->cap_mask);
	dma_cap_set(DMA_PRIVATE, dma->cap_mask);

	for (i = 0; i < SIRFSOC_DMA_CHANNELS; i++) {
		schan = &sdma->channels[i];

		schan->chan.device = dma;
		dma_cookie_init(&schan->chan);

		INIT_LIST_HEAD(&schan->free);
		INIT_LIST_HEAD(&schan->prepared);
		INIT_LIST_HEAD(&schan->queued);
		INIT_LIST_HEAD(&schan->active);
		INIT_LIST_HEAD(&schan->completed);

		spin_lock_init(&schan->lock);
		list_add_tail(&schan->chan.device_node, &dma->channels);
	}

	tasklet_init(&sdma->tasklet, sirfsoc_dma_tasklet, (unsigned long)sdma);

	/* Register DMA engine */
	dev_set_drvdata(dev, sdma);

	ret = dma_async_device_register(dma);
	if (ret)
		goto free_irq;

	/* Device-tree DMA controller registration */
	ret = of_dma_controller_register(dn, of_dma_sirfsoc_xlate, sdma);
	if (ret) {
		dev_err(dev, "failed to register DMA controller\n");
		goto unreg_dma_dev;
	}

	pm_runtime_enable(&op->dev);
	dev_info(dev, "initialized SIRFSOC DMAC driver\n");

	return 0;

unreg_dma_dev:
	dma_async_device_unregister(dma);
free_irq:
	free_irq(sdma->irq, sdma);
irq_dispose:
	irq_dispose_mapping(sdma->irq);
	return ret;
}

static int sirfsoc_dma_remove(struct platform_device *op)
{
	struct device *dev = &op->dev;
	struct sirfsoc_dma *sdma = dev_get_drvdata(dev);

	of_dma_controller_free(op->dev.of_node);
	dma_async_device_unregister(&sdma->dma);
	free_irq(sdma->irq, sdma);
	tasklet_kill(&sdma->tasklet);
	irq_dispose_mapping(sdma->irq);
	pm_runtime_disable(&op->dev);
	if (!pm_runtime_status_suspended(&op->dev))
		sirfsoc_dma_runtime_suspend(&op->dev);

	return 0;
}

static int __maybe_unused sirfsoc_dma_runtime_suspend(struct device *dev)
{
	struct sirfsoc_dma *sdma = dev_get_drvdata(dev);

	clk_disable_unprepare(sdma->clk);
	return 0;
}

static int __maybe_unused sirfsoc_dma_runtime_resume(struct device *dev)
{
	struct sirfsoc_dma *sdma = dev_get_drvdata(dev);
	int ret;

	ret = clk_prepare_enable(sdma->clk);
	if (ret < 0) {
		dev_err(dev, "clk_enable failed: %d\n", ret);
		return ret;
	}
	return 0;
}

static int __maybe_unused sirfsoc_dma_pm_suspend(struct device *dev)
{
	struct sirfsoc_dma *sdma = dev_get_drvdata(dev);
	struct sirfsoc_dma_regs *save = &sdma->regs_save;
	struct sirfsoc_dma_desc *sdesc;
	struct sirfsoc_dma_chan *schan;
	int ch;
	int ret;
	int count;
	u32 int_offset;

	/*
	 * if we were runtime-suspended before, resume to enable clock
	 * before accessing register
	 */
	if (pm_runtime_status_suspended(dev)) {
		ret = sirfsoc_dma_runtime_resume(dev);
		if (ret < 0)
			return ret;
	}

	if (sdma->type == SIRFSOC_DMA_VER_A7V2) {
		count = 1;
		int_offset = SIRFSOC_DMA_INT_EN_ATLAS7;
	} else {
		count = SIRFSOC_DMA_CHANNELS;
		int_offset = SIRFSOC_DMA_INT_EN;
	}

	/*
	 * DMA controller will lose all registers while suspending
	 * so we need to save registers for active channels
	 */
	for (ch = 0; ch < count; ch++) {
		schan = &sdma->channels[ch];
		if (list_empty(&schan->active))
			continue;
		sdesc = list_first_entry(&schan->active,
			struct sirfsoc_dma_desc,
			node);
		save->ctrl[ch] = readl_relaxed(sdma->base +
			ch * 0x10 + SIRFSOC_DMA_CH_CTRL);
	}
	save->interrupt_en = readl_relaxed(sdma->base + int_offset);

	/* Disable clock */
	sirfsoc_dma_runtime_suspend(dev);

	return 0;
}

static int __maybe_unused sirfsoc_dma_pm_resume(struct device *dev)
{
	struct sirfsoc_dma *sdma = dev_get_drvdata(dev);
	struct sirfsoc_dma_regs *save = &sdma->regs_save;
	struct sirfsoc_dma_desc *sdesc;
	struct sirfsoc_dma_chan *schan;
	int ch;
	int ret;
	int count;
	u32 int_offset;
	u32 width_offset;

	/* Enable clock before accessing register */
	ret = sirfsoc_dma_runtime_resume(dev);
	if (ret < 0)
		return ret;

	if (sdma->type == SIRFSOC_DMA_VER_A7V2) {
		count = 1;
		int_offset = SIRFSOC_DMA_INT_EN_ATLAS7;
		width_offset = SIRFSOC_DMA_WIDTH_ATLAS7;
	} else {
		count = SIRFSOC_DMA_CHANNELS;
		int_offset = SIRFSOC_DMA_INT_EN;
		width_offset = SIRFSOC_DMA_WIDTH_0;
	}

	writel_relaxed(save->interrupt_en, sdma->base + int_offset);
	for (ch = 0; ch < count; ch++) {
		schan = &sdma->channels[ch];
		if (list_empty(&schan->active))
			continue;
		sdesc = list_first_entry(&schan->active,
			struct sirfsoc_dma_desc,
			node);
		writel_relaxed(sdesc->width,
			sdma->base + width_offset + ch * 4);
		writel_relaxed(sdesc->xlen,
			sdma->base + ch * 0x10 + SIRFSOC_DMA_CH_XLEN);
		writel_relaxed(sdesc->ylen,
			sdma->base + ch * 0x10 + SIRFSOC_DMA_CH_YLEN);
		writel_relaxed(save->ctrl[ch],
			sdma->base + ch * 0x10 + SIRFSOC_DMA_CH_CTRL);
		if (sdma->type == SIRFSOC_DMA_VER_A7V2) {
			writel_relaxed(sdesc->addr,
				sdma->base + SIRFSOC_DMA_CH_ADDR);
		} else {
			writel_relaxed(sdesc->addr >> 2,
				sdma->base + ch * 0x10 + SIRFSOC_DMA_CH_ADDR);

		}
	}

	/* if we were runtime-suspended before, suspend again */
	if (pm_runtime_status_suspended(dev))
		sirfsoc_dma_runtime_suspend(dev);

	return 0;
}

static const struct dev_pm_ops sirfsoc_dma_pm_ops = {
	SET_RUNTIME_PM_OPS(sirfsoc_dma_runtime_suspend, sirfsoc_dma_runtime_resume, NULL)
	SET_SYSTEM_SLEEP_PM_OPS(sirfsoc_dma_pm_suspend, sirfsoc_dma_pm_resume)
};

static struct sirfsoc_dmadata sirfsoc_dmadata_a6 = {
	.exec = sirfsoc_dma_execute_hw_a6,
	.type = SIRFSOC_DMA_VER_A6,
};

static struct sirfsoc_dmadata sirfsoc_dmadata_a7v1 = {
	.exec = sirfsoc_dma_execute_hw_a7v1,
	.type = SIRFSOC_DMA_VER_A7V1,
};

static struct sirfsoc_dmadata sirfsoc_dmadata_a7v2 = {
	.exec = sirfsoc_dma_execute_hw_a7v2,
	.type = SIRFSOC_DMA_VER_A7V2,
};

static const struct of_device_id sirfsoc_dma_match[] = {
	{ .compatible = "sirf,prima2-dmac", .data = &sirfsoc_dmadata_a6,},
	{ .compatible = "sirf,atlas7-dmac", .data = &sirfsoc_dmadata_a7v1,},
	{ .compatible = "sirf,atlas7-dmac-v2", .data = &sirfsoc_dmadata_a7v2,},
	{},
};
MODULE_DEVICE_TABLE(of, sirfsoc_dma_match);

static struct platform_driver sirfsoc_dma_driver = {
	.probe		= sirfsoc_dma_probe,
	.remove		= sirfsoc_dma_remove,
	.driver = {
		.name = DRV_NAME,
		.pm = &sirfsoc_dma_pm_ops,
		.of_match_table	= sirfsoc_dma_match,
	},
};

static __init int sirfsoc_dma_init(void)
{
	return platform_driver_register(&sirfsoc_dma_driver);
}

static void __exit sirfsoc_dma_exit(void)
{
	platform_driver_unregister(&sirfsoc_dma_driver);
}

subsys_initcall(sirfsoc_dma_init);
module_exit(sirfsoc_dma_exit);

MODULE_AUTHOR("Rongjun Ying <rongjun.ying@csr.com>");
MODULE_AUTHOR("Barry Song <baohua.song@csr.com>");
MODULE_DESCRIPTION("SIRFSOC DMA control driver");
MODULE_LICENSE("GPL v2");
