/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018 MediaTek Inc.
 * Author: Houlong Wei <houlong.wei@mediatek.com>
 *
 */

#ifndef _DT_BINDINGS_GCE_MT8173_H
#define _DT_BINDINGS_GCE_MT8173_H

/* GCE HW thread priority */
#define CMDQ_THR_PRIO_LOWEST	0
#define CMDQ_THR_PRIO_HIGHEST	1

/* GCE SUBSYS */
#define SUBSYS_1400XXXX		1
#define SUBSYS_1401XXXX		2
#define SUBSYS_1402XXXX		3

/* GCE HW EVENT */
#define CMDQ_EVENT_DISP_OVL0_SOF		11
#define CMDQ_EVENT_DISP_OVL1_SOF		12
#define CMDQ_EVENT_DISP_RDMA0_SOF		13
#define CMDQ_EVENT_DISP_RDMA1_SOF		14
#define CMDQ_EVENT_DISP_RDMA2_SOF		15
#define CMDQ_EVENT_DISP_WDMA0_SOF		16
#define CMDQ_EVENT_DISP_WDMA1_SOF		17
#define CMDQ_EVENT_DISP_OVL0_EOF		39
#define CMDQ_EVENT_DISP_OVL1_EOF		40
#define CMDQ_EVENT_DISP_RDMA0_EOF		41
#define CMDQ_EVENT_DISP_RDMA1_EOF		42
#define CMDQ_EVENT_DISP_RDMA2_EOF		43
#define CMDQ_EVENT_DISP_WDMA0_EOF		44
#define CMDQ_EVENT_DISP_WDMA1_EOF		45
#define CMDQ_EVENT_MUTEX0_STREAM_EOF		53
#define CMDQ_EVENT_MUTEX1_STREAM_EOF		54
#define CMDQ_EVENT_MUTEX2_STREAM_EOF		55
#define CMDQ_EVENT_MUTEX3_STREAM_EOF		56
#define CMDQ_EVENT_MUTEX4_STREAM_EOF		57
#define CMDQ_EVENT_DISP_RDMA0_UNDERRUN		63
#define CMDQ_EVENT_DISP_RDMA1_UNDERRUN		64
#define CMDQ_EVENT_DISP_RDMA2_UNDERRUN		65

#endif
