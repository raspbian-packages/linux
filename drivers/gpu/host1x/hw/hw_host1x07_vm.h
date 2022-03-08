/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2018 NVIDIA Corporation.
 */

#define HOST1X_CHANNEL_DMASTART				0x0000
#define HOST1X_CHANNEL_DMASTART_HI			0x0004
#define HOST1X_CHANNEL_DMAPUT				0x0008
#define HOST1X_CHANNEL_DMAPUT_HI			0x000c
#define HOST1X_CHANNEL_DMAGET				0x0010
#define HOST1X_CHANNEL_DMAGET_HI			0x0014
#define HOST1X_CHANNEL_DMAEND				0x0018
#define HOST1X_CHANNEL_DMAEND_HI			0x001c
#define HOST1X_CHANNEL_DMACTRL				0x0020
#define HOST1X_CHANNEL_DMACTRL_DMASTOP			BIT(0)
#define HOST1X_CHANNEL_DMACTRL_DMAGETRST		BIT(1)
#define HOST1X_CHANNEL_DMACTRL_DMAINITGET		BIT(2)
#define HOST1X_CHANNEL_CMDFIFO_STAT			0x0024
#define HOST1X_CHANNEL_CMDFIFO_STAT_EMPTY		BIT(13)
#define HOST1X_CHANNEL_CMDFIFO_RDATA			0x0028
#define HOST1X_CHANNEL_CMDP_OFFSET			0x0030
#define HOST1X_CHANNEL_CMDP_CLASS			0x0034
#define HOST1X_CHANNEL_CHANNELSTAT			0x0038
#define HOST1X_CHANNEL_CMDPROC_STOP			0x0048
#define HOST1X_CHANNEL_TEARDOWN				0x004c

#define HOST1X_SYNC_SYNCPT_CPU_INCR(x)			(0x6400 + 4 * (x))
#define HOST1X_SYNC_SYNCPT_THRESH_CPU0_INT_STATUS(x)	(0x6464 + 4 * (x))
#define HOST1X_SYNC_SYNCPT_THRESH_INT_ENABLE_CPU0(x)	(0x652c + 4 * (x))
#define HOST1X_SYNC_SYNCPT_THRESH_INT_DISABLE(x)	(0x6590 + 4 * (x))
#define HOST1X_SYNC_SYNCPT(x)				(0x8080 + 4 * (x))
#define HOST1X_SYNC_SYNCPT_INT_THRESH(x)		(0x9980 + 4 * (x))
#define HOST1X_SYNC_SYNCPT_CH_APP(x)			(0xa604 + 4 * (x))
#define HOST1X_SYNC_SYNCPT_CH_APP_CH(v)			(((v) & 0x3f) << 8)
