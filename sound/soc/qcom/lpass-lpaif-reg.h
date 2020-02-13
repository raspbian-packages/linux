/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2010-2011,2013-2015 The Linux Foundation. All rights reserved.
 */

#ifndef __LPASS_LPAIF_REG_H__
#define __LPASS_LPAIF_REG_H__

/* LPAIF I2S */

#define LPAIF_I2SCTL_REG_ADDR(v, addr, port) \
	(v->i2sctrl_reg_base + (addr) + v->i2sctrl_reg_stride * (port))

#define LPAIF_I2SCTL_REG(v, port)	LPAIF_I2SCTL_REG_ADDR(v, 0x0, (port))
#define LPAIF_I2SCTL_LOOPBACK_MASK	0x8000
#define LPAIF_I2SCTL_LOOPBACK_SHIFT	15
#define LPAIF_I2SCTL_LOOPBACK_DISABLE	(0 << LPAIF_I2SCTL_LOOPBACK_SHIFT)
#define LPAIF_I2SCTL_LOOPBACK_ENABLE	(1 << LPAIF_I2SCTL_LOOPBACK_SHIFT)

#define LPAIF_I2SCTL_SPKEN_MASK		0x4000
#define LPAIF_I2SCTL_SPKEN_SHIFT	14
#define LPAIF_I2SCTL_SPKEN_DISABLE	(0 << LPAIF_I2SCTL_SPKEN_SHIFT)
#define LPAIF_I2SCTL_SPKEN_ENABLE	(1 << LPAIF_I2SCTL_SPKEN_SHIFT)

#define LPAIF_I2SCTL_SPKMODE_MASK	0x3C00
#define LPAIF_I2SCTL_SPKMODE_SHIFT	10
#define LPAIF_I2SCTL_SPKMODE_NONE	(0 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_SD0	(1 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_SD1	(2 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_SD2	(3 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_SD3	(4 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_QUAD01	(5 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_QUAD23	(6 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_6CH	(7 << LPAIF_I2SCTL_SPKMODE_SHIFT)
#define LPAIF_I2SCTL_SPKMODE_8CH	(8 << LPAIF_I2SCTL_SPKMODE_SHIFT)

#define LPAIF_I2SCTL_SPKMONO_MASK	0x0200
#define LPAIF_I2SCTL_SPKMONO_SHIFT	9
#define LPAIF_I2SCTL_SPKMONO_STEREO	(0 << LPAIF_I2SCTL_SPKMONO_SHIFT)
#define LPAIF_I2SCTL_SPKMONO_MONO	(1 << LPAIF_I2SCTL_SPKMONO_SHIFT)

#define LPAIF_I2SCTL_MICEN_MASK		GENMASK(8, 8)
#define LPAIF_I2SCTL_MICEN_SHIFT	8
#define LPAIF_I2SCTL_MICEN_DISABLE	(0 << LPAIF_I2SCTL_MICEN_SHIFT)
#define LPAIF_I2SCTL_MICEN_ENABLE	(1 << LPAIF_I2SCTL_MICEN_SHIFT)

#define LPAIF_I2SCTL_MICMODE_MASK	GENMASK(7, 4)
#define LPAIF_I2SCTL_MICMODE_SHIFT	4
#define LPAIF_I2SCTL_MICMODE_NONE	(0 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_SD0	(1 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_SD1	(2 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_SD2	(3 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_SD3	(4 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_QUAD01	(5 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_QUAD23	(6 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_6CH	(7 << LPAIF_I2SCTL_MICMODE_SHIFT)
#define LPAIF_I2SCTL_MICMODE_8CH	(8 << LPAIF_I2SCTL_MICMODE_SHIFT)

#define LPAIF_I2SCTL_MIMONO_MASK	GENMASK(3, 3)
#define LPAIF_I2SCTL_MICMONO_SHIFT	3
#define LPAIF_I2SCTL_MICMONO_STEREO	(0 << LPAIF_I2SCTL_MICMONO_SHIFT)
#define LPAIF_I2SCTL_MICMONO_MONO	(1 << LPAIF_I2SCTL_MICMONO_SHIFT)

#define LPAIF_I2SCTL_WSSRC_MASK		0x0004
#define LPAIF_I2SCTL_WSSRC_SHIFT	2
#define LPAIF_I2SCTL_WSSRC_INTERNAL	(0 << LPAIF_I2SCTL_WSSRC_SHIFT)
#define LPAIF_I2SCTL_WSSRC_EXTERNAL	(1 << LPAIF_I2SCTL_WSSRC_SHIFT)

#define LPAIF_I2SCTL_BITWIDTH_MASK	0x0003
#define LPAIF_I2SCTL_BITWIDTH_SHIFT	0
#define LPAIF_I2SCTL_BITWIDTH_16	(0 << LPAIF_I2SCTL_BITWIDTH_SHIFT)
#define LPAIF_I2SCTL_BITWIDTH_24	(1 << LPAIF_I2SCTL_BITWIDTH_SHIFT)
#define LPAIF_I2SCTL_BITWIDTH_32	(2 << LPAIF_I2SCTL_BITWIDTH_SHIFT)

/* LPAIF IRQ */
#define LPAIF_IRQ_REG_ADDR(v, addr, port) \
	(v->irq_reg_base + (addr) + v->irq_reg_stride * (port))

#define LPAIF_IRQ_PORT_HOST		0

#define LPAIF_IRQEN_REG(v, port)	LPAIF_IRQ_REG_ADDR(v, 0x0, (port))
#define LPAIF_IRQSTAT_REG(v, port)	LPAIF_IRQ_REG_ADDR(v, 0x4, (port))
#define LPAIF_IRQCLEAR_REG(v, port)	LPAIF_IRQ_REG_ADDR(v, 0xC, (port))

#define LPAIF_IRQ_BITSTRIDE		3

#define LPAIF_IRQ_PER(chan)		(1 << (LPAIF_IRQ_BITSTRIDE * (chan)))
#define LPAIF_IRQ_XRUN(chan)		(2 << (LPAIF_IRQ_BITSTRIDE * (chan)))
#define LPAIF_IRQ_ERR(chan)		(4 << (LPAIF_IRQ_BITSTRIDE * (chan)))

#define LPAIF_IRQ_ALL(chan)		(7 << (LPAIF_IRQ_BITSTRIDE * (chan)))

/* LPAIF DMA */

#define LPAIF_RDMA_REG_ADDR(v, addr, chan) \
	(v->rdma_reg_base + (addr) + v->rdma_reg_stride * (chan))

#define LPAIF_RDMACTL_AUDINTF(id)	(id << LPAIF_RDMACTL_AUDINTF_SHIFT)

#define LPAIF_RDMACTL_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x00, (chan))
#define LPAIF_RDMABASE_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x04, (chan))
#define	LPAIF_RDMABUFF_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x08, (chan))
#define LPAIF_RDMACURR_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x0C, (chan))
#define	LPAIF_RDMAPER_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x10, (chan))
#define	LPAIF_RDMAPERCNT_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x14, (chan))

#define LPAIF_WRDMA_REG_ADDR(v, addr, chan) \
	(v->wrdma_reg_base + (addr) + \
	 v->wrdma_reg_stride * (chan - v->wrdma_channel_start))

#define LPAIF_WRDMACTL_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x00, (chan))
#define LPAIF_WRDMABASE_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x04, (chan))
#define	LPAIF_WRDMABUFF_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x08, (chan))
#define LPAIF_WRDMACURR_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x0C, (chan))
#define	LPAIF_WRDMAPER_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x10, (chan))
#define	LPAIF_WRDMAPERCNT_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x14, (chan))

#define __LPAIF_DMA_REG(v, chan, dir, reg)  \
	(dir ==  SNDRV_PCM_STREAM_PLAYBACK) ? \
		LPAIF_RDMA##reg##_REG(v, chan) : \
		LPAIF_WRDMA##reg##_REG(v, chan)

#define LPAIF_DMACTL_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, CTL)
#define LPAIF_DMABASE_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, BASE)
#define	LPAIF_DMABUFF_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, BUFF)
#define LPAIF_DMACURR_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, CURR)
#define	LPAIF_DMAPER_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, PER)
#define	LPAIF_DMAPERCNT_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, PERCNT)

#define LPAIF_DMACTL_BURSTEN_MASK	0x800
#define LPAIF_DMACTL_BURSTEN_SHIFT	11
#define LPAIF_DMACTL_BURSTEN_SINGLE	(0 << LPAIF_DMACTL_BURSTEN_SHIFT)
#define LPAIF_DMACTL_BURSTEN_INCR4	(1 << LPAIF_DMACTL_BURSTEN_SHIFT)

#define LPAIF_DMACTL_WPSCNT_MASK	0x700
#define LPAIF_DMACTL_WPSCNT_SHIFT	8
#define LPAIF_DMACTL_WPSCNT_ONE	(0 << LPAIF_DMACTL_WPSCNT_SHIFT)
#define LPAIF_DMACTL_WPSCNT_TWO	(1 << LPAIF_DMACTL_WPSCNT_SHIFT)
#define LPAIF_DMACTL_WPSCNT_THREE	(2 << LPAIF_DMACTL_WPSCNT_SHIFT)
#define LPAIF_DMACTL_WPSCNT_FOUR	(3 << LPAIF_DMACTL_WPSCNT_SHIFT)
#define LPAIF_DMACTL_WPSCNT_SIX	(5 << LPAIF_DMACTL_WPSCNT_SHIFT)
#define LPAIF_DMACTL_WPSCNT_EIGHT	(7 << LPAIF_DMACTL_WPSCNT_SHIFT)

#define LPAIF_DMACTL_AUDINTF_MASK	0x0F0
#define LPAIF_DMACTL_AUDINTF_SHIFT	4
#define LPAIF_DMACTL_AUDINTF(id)	(id << LPAIF_DMACTL_AUDINTF_SHIFT)

#define LPAIF_DMACTL_FIFOWM_MASK	0x00E
#define LPAIF_DMACTL_FIFOWM_SHIFT	1
#define LPAIF_DMACTL_FIFOWM_1		(0 << LPAIF_DMACTL_FIFOWM_SHIFT)
#define LPAIF_DMACTL_FIFOWM_2		(1 << LPAIF_DMACTL_FIFOWM_SHIFT)
#define LPAIF_DMACTL_FIFOWM_3		(2 << LPAIF_DMACTL_FIFOWM_SHIFT)
#define LPAIF_DMACTL_FIFOWM_4		(3 << LPAIF_DMACTL_FIFOWM_SHIFT)
#define LPAIF_DMACTL_FIFOWM_5		(4 << LPAIF_DMACTL_FIFOWM_SHIFT)
#define LPAIF_DMACTL_FIFOWM_6		(5 << LPAIF_DMACTL_FIFOWM_SHIFT)
#define LPAIF_DMACTL_FIFOWM_7		(6 << LPAIF_DMACTL_FIFOWM_SHIFT)
#define LPAIF_DMACTL_FIFOWM_8		(7 << LPAIF_DMACTL_FIFOWM_SHIFT)

#define LPAIF_DMACTL_ENABLE_MASK	0x1
#define LPAIF_DMACTL_ENABLE_SHIFT	0
#define LPAIF_DMACTL_ENABLE_OFF	(0 << LPAIF_DMACTL_ENABLE_SHIFT)
#define LPAIF_DMACTL_ENABLE_ON		(1 << LPAIF_DMACTL_ENABLE_SHIFT)

#define LPAIF_DMACTL_DYNCLK_MASK	BIT(12)
#define LPAIF_DMACTL_DYNCLK_SHIFT	12
#define LPAIF_DMACTL_DYNCLK_OFF	(0 << LPAIF_DMACTL_DYNCLK_SHIFT)
#define LPAIF_DMACTL_DYNCLK_ON		(1 << LPAIF_DMACTL_DYNCLK_SHIFT)
#endif /* __LPASS_LPAIF_REG_H__ */
