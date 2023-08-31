#ifndef DSI_XML
#define DSI_XML

/* Autogenerated file, DO NOT EDIT manually!

This file was generated by the rules-ng-ng headergen tool in this git repository:
http://github.com/freedreno/envytools/
git clone https://github.com/freedreno/envytools.git

The rules-ng-ng source files this header was generated from are:
- /home/robclark/src/mesa/mesa/src/freedreno/registers/msm.xml                   (    944 bytes, from 2022-07-23 20:21:46)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/freedreno_copyright.xml   (   1572 bytes, from 2022-07-23 20:21:46)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/mdp/mdp4.xml              (  20912 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/mdp/mdp_common.xml        (   2849 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/mdp/mdp5.xml              (  37461 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi.xml               (  18746 bytes, from 2022-04-28 17:29:36)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi_phy_v2.xml        (   3236 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi_phy_28nm_8960.xml (   4935 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi_phy_28nm.xml      (   7004 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi_phy_20nm.xml      (   3712 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi_phy_14nm.xml      (   5381 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi_phy_10nm.xml      (   4499 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/dsi_phy_7nm.xml       (  11007 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/sfpb.xml              (    602 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/dsi/mmss_cc.xml           (   1686 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/hdmi/qfprom.xml           (    600 bytes, from 2022-03-08 17:40:42)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/hdmi/hdmi.xml             (  42350 bytes, from 2022-09-20 17:45:56)
- /home/robclark/src/mesa/mesa/src/freedreno/registers/edp/edp.xml               (  10416 bytes, from 2022-03-08 17:40:42)

Copyright (C) 2013-2022 by the following authors:
- Rob Clark <robdclark@gmail.com> (robclark)
- Ilia Mirkin <imirkin@alum.mit.edu> (imirkin)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice (including the
next paragraph) shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE COPYRIGHT OWNER(S) AND/OR ITS SUPPLIERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


enum dsi_traffic_mode {
	NON_BURST_SYNCH_PULSE = 0,
	NON_BURST_SYNCH_EVENT = 1,
	BURST_MODE = 2,
};

enum dsi_vid_dst_format {
	VID_DST_FORMAT_RGB565 = 0,
	VID_DST_FORMAT_RGB666 = 1,
	VID_DST_FORMAT_RGB666_LOOSE = 2,
	VID_DST_FORMAT_RGB888 = 3,
};

enum dsi_rgb_swap {
	SWAP_RGB = 0,
	SWAP_RBG = 1,
	SWAP_BGR = 2,
	SWAP_BRG = 3,
	SWAP_GRB = 4,
	SWAP_GBR = 5,
};

enum dsi_cmd_trigger {
	TRIGGER_NONE = 0,
	TRIGGER_SEOF = 1,
	TRIGGER_TE = 2,
	TRIGGER_SW = 4,
	TRIGGER_SW_SEOF = 5,
	TRIGGER_SW_TE = 6,
};

enum dsi_cmd_dst_format {
	CMD_DST_FORMAT_RGB111 = 0,
	CMD_DST_FORMAT_RGB332 = 3,
	CMD_DST_FORMAT_RGB444 = 4,
	CMD_DST_FORMAT_RGB565 = 6,
	CMD_DST_FORMAT_RGB666 = 7,
	CMD_DST_FORMAT_RGB888 = 8,
};

enum dsi_lane_swap {
	LANE_SWAP_0123 = 0,
	LANE_SWAP_3012 = 1,
	LANE_SWAP_2301 = 2,
	LANE_SWAP_1230 = 3,
	LANE_SWAP_0321 = 4,
	LANE_SWAP_1032 = 5,
	LANE_SWAP_2103 = 6,
	LANE_SWAP_3210 = 7,
};

enum video_config_bpp {
	VIDEO_CONFIG_18BPP = 0,
	VIDEO_CONFIG_24BPP = 1,
};

enum video_pattern_sel {
	VID_PRBS = 0,
	VID_INCREMENTAL = 1,
	VID_FIXED = 2,
	VID_MDSS_GENERAL_PATTERN = 3,
};

enum cmd_mdp_stream0_pattern_sel {
	CMD_MDP_PRBS = 0,
	CMD_MDP_INCREMENTAL = 1,
	CMD_MDP_FIXED = 2,
	CMD_MDP_MDSS_GENERAL_PATTERN = 3,
};

enum cmd_dma_pattern_sel {
	CMD_DMA_PRBS = 0,
	CMD_DMA_INCREMENTAL = 1,
	CMD_DMA_FIXED = 2,
	CMD_DMA_CUSTOM_PATTERN_DMA_FIFO = 3,
};

#define DSI_IRQ_CMD_DMA_DONE					0x00000001
#define DSI_IRQ_MASK_CMD_DMA_DONE				0x00000002
#define DSI_IRQ_CMD_MDP_DONE					0x00000100
#define DSI_IRQ_MASK_CMD_MDP_DONE				0x00000200
#define DSI_IRQ_VIDEO_DONE					0x00010000
#define DSI_IRQ_MASK_VIDEO_DONE					0x00020000
#define DSI_IRQ_BTA_DONE					0x00100000
#define DSI_IRQ_MASK_BTA_DONE					0x00200000
#define DSI_IRQ_ERROR						0x01000000
#define DSI_IRQ_MASK_ERROR					0x02000000
#define REG_DSI_6G_HW_VERSION					0x00000000
#define DSI_6G_HW_VERSION_MAJOR__MASK				0xf0000000
#define DSI_6G_HW_VERSION_MAJOR__SHIFT				28
static inline uint32_t DSI_6G_HW_VERSION_MAJOR(uint32_t val)
{
	return ((val) << DSI_6G_HW_VERSION_MAJOR__SHIFT) & DSI_6G_HW_VERSION_MAJOR__MASK;
}
#define DSI_6G_HW_VERSION_MINOR__MASK				0x0fff0000
#define DSI_6G_HW_VERSION_MINOR__SHIFT				16
static inline uint32_t DSI_6G_HW_VERSION_MINOR(uint32_t val)
{
	return ((val) << DSI_6G_HW_VERSION_MINOR__SHIFT) & DSI_6G_HW_VERSION_MINOR__MASK;
}
#define DSI_6G_HW_VERSION_STEP__MASK				0x0000ffff
#define DSI_6G_HW_VERSION_STEP__SHIFT				0
static inline uint32_t DSI_6G_HW_VERSION_STEP(uint32_t val)
{
	return ((val) << DSI_6G_HW_VERSION_STEP__SHIFT) & DSI_6G_HW_VERSION_STEP__MASK;
}

#define REG_DSI_CTRL						0x00000000
#define DSI_CTRL_ENABLE						0x00000001
#define DSI_CTRL_VID_MODE_EN					0x00000002
#define DSI_CTRL_CMD_MODE_EN					0x00000004
#define DSI_CTRL_LANE0						0x00000010
#define DSI_CTRL_LANE1						0x00000020
#define DSI_CTRL_LANE2						0x00000040
#define DSI_CTRL_LANE3						0x00000080
#define DSI_CTRL_CLK_EN						0x00000100
#define DSI_CTRL_ECC_CHECK					0x00100000
#define DSI_CTRL_CRC_CHECK					0x01000000

#define REG_DSI_STATUS0						0x00000004
#define DSI_STATUS0_CMD_MODE_ENGINE_BUSY			0x00000001
#define DSI_STATUS0_CMD_MODE_DMA_BUSY				0x00000002
#define DSI_STATUS0_CMD_MODE_MDP_BUSY				0x00000004
#define DSI_STATUS0_VIDEO_MODE_ENGINE_BUSY			0x00000008
#define DSI_STATUS0_DSI_BUSY					0x00000010
#define DSI_STATUS0_INTERLEAVE_OP_CONTENTION			0x80000000

#define REG_DSI_FIFO_STATUS					0x00000008
#define DSI_FIFO_STATUS_VIDEO_MDP_FIFO_OVERFLOW			0x00000001
#define DSI_FIFO_STATUS_VIDEO_MDP_FIFO_UNDERFLOW		0x00000008
#define DSI_FIFO_STATUS_CMD_MDP_FIFO_UNDERFLOW			0x00000080
#define DSI_FIFO_STATUS_CMD_DMA_FIFO_RD_WATERMARK_REACH		0x00000100
#define DSI_FIFO_STATUS_CMD_DMA_FIFO_WR_WATERMARK_REACH		0x00000200
#define DSI_FIFO_STATUS_CMD_DMA_FIFO_UNDERFLOW			0x00000400
#define DSI_FIFO_STATUS_DLN0_LP_FIFO_EMPTY			0x00001000
#define DSI_FIFO_STATUS_DLN0_LP_FIFO_FULL			0x00002000
#define DSI_FIFO_STATUS_DLN0_LP_FIFO_OVERFLOW			0x00004000
#define DSI_FIFO_STATUS_DLN0_HS_FIFO_EMPTY			0x00010000
#define DSI_FIFO_STATUS_DLN0_HS_FIFO_FULL			0x00020000
#define DSI_FIFO_STATUS_DLN0_HS_FIFO_OVERFLOW			0x00040000
#define DSI_FIFO_STATUS_DLN0_HS_FIFO_UNDERFLOW			0x00080000
#define DSI_FIFO_STATUS_DLN1_HS_FIFO_EMPTY			0x00100000
#define DSI_FIFO_STATUS_DLN1_HS_FIFO_FULL			0x00200000
#define DSI_FIFO_STATUS_DLN1_HS_FIFO_OVERFLOW			0x00400000
#define DSI_FIFO_STATUS_DLN1_HS_FIFO_UNDERFLOW			0x00800000
#define DSI_FIFO_STATUS_DLN2_HS_FIFO_EMPTY			0x01000000
#define DSI_FIFO_STATUS_DLN2_HS_FIFO_FULL			0x02000000
#define DSI_FIFO_STATUS_DLN2_HS_FIFO_OVERFLOW			0x04000000
#define DSI_FIFO_STATUS_DLN2_HS_FIFO_UNDERFLOW			0x08000000
#define DSI_FIFO_STATUS_DLN3_HS_FIFO_EMPTY			0x10000000
#define DSI_FIFO_STATUS_DLN3_HS_FIFO_FULL			0x20000000
#define DSI_FIFO_STATUS_DLN3_HS_FIFO_OVERFLOW			0x40000000
#define DSI_FIFO_STATUS_DLN3_HS_FIFO_UNDERFLOW			0x80000000

#define REG_DSI_VID_CFG0					0x0000000c
#define DSI_VID_CFG0_VIRT_CHANNEL__MASK				0x00000003
#define DSI_VID_CFG0_VIRT_CHANNEL__SHIFT			0
static inline uint32_t DSI_VID_CFG0_VIRT_CHANNEL(uint32_t val)
{
	return ((val) << DSI_VID_CFG0_VIRT_CHANNEL__SHIFT) & DSI_VID_CFG0_VIRT_CHANNEL__MASK;
}
#define DSI_VID_CFG0_DST_FORMAT__MASK				0x00000030
#define DSI_VID_CFG0_DST_FORMAT__SHIFT				4
static inline uint32_t DSI_VID_CFG0_DST_FORMAT(enum dsi_vid_dst_format val)
{
	return ((val) << DSI_VID_CFG0_DST_FORMAT__SHIFT) & DSI_VID_CFG0_DST_FORMAT__MASK;
}
#define DSI_VID_CFG0_TRAFFIC_MODE__MASK				0x00000300
#define DSI_VID_CFG0_TRAFFIC_MODE__SHIFT			8
static inline uint32_t DSI_VID_CFG0_TRAFFIC_MODE(enum dsi_traffic_mode val)
{
	return ((val) << DSI_VID_CFG0_TRAFFIC_MODE__SHIFT) & DSI_VID_CFG0_TRAFFIC_MODE__MASK;
}
#define DSI_VID_CFG0_BLLP_POWER_STOP				0x00001000
#define DSI_VID_CFG0_EOF_BLLP_POWER_STOP			0x00008000
#define DSI_VID_CFG0_HSA_POWER_STOP				0x00010000
#define DSI_VID_CFG0_HBP_POWER_STOP				0x00100000
#define DSI_VID_CFG0_HFP_POWER_STOP				0x01000000
#define DSI_VID_CFG0_PULSE_MODE_HSA_HE				0x10000000

#define REG_DSI_VID_CFG1					0x0000001c
#define DSI_VID_CFG1_R_SEL					0x00000001
#define DSI_VID_CFG1_G_SEL					0x00000010
#define DSI_VID_CFG1_B_SEL					0x00000100
#define DSI_VID_CFG1_RGB_SWAP__MASK				0x00007000
#define DSI_VID_CFG1_RGB_SWAP__SHIFT				12
static inline uint32_t DSI_VID_CFG1_RGB_SWAP(enum dsi_rgb_swap val)
{
	return ((val) << DSI_VID_CFG1_RGB_SWAP__SHIFT) & DSI_VID_CFG1_RGB_SWAP__MASK;
}

#define REG_DSI_ACTIVE_H					0x00000020
#define DSI_ACTIVE_H_START__MASK				0x00000fff
#define DSI_ACTIVE_H_START__SHIFT				0
static inline uint32_t DSI_ACTIVE_H_START(uint32_t val)
{
	return ((val) << DSI_ACTIVE_H_START__SHIFT) & DSI_ACTIVE_H_START__MASK;
}
#define DSI_ACTIVE_H_END__MASK					0x0fff0000
#define DSI_ACTIVE_H_END__SHIFT					16
static inline uint32_t DSI_ACTIVE_H_END(uint32_t val)
{
	return ((val) << DSI_ACTIVE_H_END__SHIFT) & DSI_ACTIVE_H_END__MASK;
}

#define REG_DSI_ACTIVE_V					0x00000024
#define DSI_ACTIVE_V_START__MASK				0x00000fff
#define DSI_ACTIVE_V_START__SHIFT				0
static inline uint32_t DSI_ACTIVE_V_START(uint32_t val)
{
	return ((val) << DSI_ACTIVE_V_START__SHIFT) & DSI_ACTIVE_V_START__MASK;
}
#define DSI_ACTIVE_V_END__MASK					0x0fff0000
#define DSI_ACTIVE_V_END__SHIFT					16
static inline uint32_t DSI_ACTIVE_V_END(uint32_t val)
{
	return ((val) << DSI_ACTIVE_V_END__SHIFT) & DSI_ACTIVE_V_END__MASK;
}

#define REG_DSI_TOTAL						0x00000028
#define DSI_TOTAL_H_TOTAL__MASK					0x00000fff
#define DSI_TOTAL_H_TOTAL__SHIFT				0
static inline uint32_t DSI_TOTAL_H_TOTAL(uint32_t val)
{
	return ((val) << DSI_TOTAL_H_TOTAL__SHIFT) & DSI_TOTAL_H_TOTAL__MASK;
}
#define DSI_TOTAL_V_TOTAL__MASK					0x0fff0000
#define DSI_TOTAL_V_TOTAL__SHIFT				16
static inline uint32_t DSI_TOTAL_V_TOTAL(uint32_t val)
{
	return ((val) << DSI_TOTAL_V_TOTAL__SHIFT) & DSI_TOTAL_V_TOTAL__MASK;
}

#define REG_DSI_ACTIVE_HSYNC					0x0000002c
#define DSI_ACTIVE_HSYNC_START__MASK				0x00000fff
#define DSI_ACTIVE_HSYNC_START__SHIFT				0
static inline uint32_t DSI_ACTIVE_HSYNC_START(uint32_t val)
{
	return ((val) << DSI_ACTIVE_HSYNC_START__SHIFT) & DSI_ACTIVE_HSYNC_START__MASK;
}
#define DSI_ACTIVE_HSYNC_END__MASK				0x0fff0000
#define DSI_ACTIVE_HSYNC_END__SHIFT				16
static inline uint32_t DSI_ACTIVE_HSYNC_END(uint32_t val)
{
	return ((val) << DSI_ACTIVE_HSYNC_END__SHIFT) & DSI_ACTIVE_HSYNC_END__MASK;
}

#define REG_DSI_ACTIVE_VSYNC_HPOS				0x00000030
#define DSI_ACTIVE_VSYNC_HPOS_START__MASK			0x00000fff
#define DSI_ACTIVE_VSYNC_HPOS_START__SHIFT			0
static inline uint32_t DSI_ACTIVE_VSYNC_HPOS_START(uint32_t val)
{
	return ((val) << DSI_ACTIVE_VSYNC_HPOS_START__SHIFT) & DSI_ACTIVE_VSYNC_HPOS_START__MASK;
}
#define DSI_ACTIVE_VSYNC_HPOS_END__MASK				0x0fff0000
#define DSI_ACTIVE_VSYNC_HPOS_END__SHIFT			16
static inline uint32_t DSI_ACTIVE_VSYNC_HPOS_END(uint32_t val)
{
	return ((val) << DSI_ACTIVE_VSYNC_HPOS_END__SHIFT) & DSI_ACTIVE_VSYNC_HPOS_END__MASK;
}

#define REG_DSI_ACTIVE_VSYNC_VPOS				0x00000034
#define DSI_ACTIVE_VSYNC_VPOS_START__MASK			0x00000fff
#define DSI_ACTIVE_VSYNC_VPOS_START__SHIFT			0
static inline uint32_t DSI_ACTIVE_VSYNC_VPOS_START(uint32_t val)
{
	return ((val) << DSI_ACTIVE_VSYNC_VPOS_START__SHIFT) & DSI_ACTIVE_VSYNC_VPOS_START__MASK;
}
#define DSI_ACTIVE_VSYNC_VPOS_END__MASK				0x0fff0000
#define DSI_ACTIVE_VSYNC_VPOS_END__SHIFT			16
static inline uint32_t DSI_ACTIVE_VSYNC_VPOS_END(uint32_t val)
{
	return ((val) << DSI_ACTIVE_VSYNC_VPOS_END__SHIFT) & DSI_ACTIVE_VSYNC_VPOS_END__MASK;
}

#define REG_DSI_CMD_DMA_CTRL					0x00000038
#define DSI_CMD_DMA_CTRL_BROADCAST_EN				0x80000000
#define DSI_CMD_DMA_CTRL_FROM_FRAME_BUFFER			0x10000000
#define DSI_CMD_DMA_CTRL_LOW_POWER				0x04000000

#define REG_DSI_CMD_CFG0					0x0000003c
#define DSI_CMD_CFG0_DST_FORMAT__MASK				0x0000000f
#define DSI_CMD_CFG0_DST_FORMAT__SHIFT				0
static inline uint32_t DSI_CMD_CFG0_DST_FORMAT(enum dsi_cmd_dst_format val)
{
	return ((val) << DSI_CMD_CFG0_DST_FORMAT__SHIFT) & DSI_CMD_CFG0_DST_FORMAT__MASK;
}
#define DSI_CMD_CFG0_R_SEL					0x00000010
#define DSI_CMD_CFG0_G_SEL					0x00000100
#define DSI_CMD_CFG0_B_SEL					0x00001000
#define DSI_CMD_CFG0_INTERLEAVE_MAX__MASK			0x00f00000
#define DSI_CMD_CFG0_INTERLEAVE_MAX__SHIFT			20
static inline uint32_t DSI_CMD_CFG0_INTERLEAVE_MAX(uint32_t val)
{
	return ((val) << DSI_CMD_CFG0_INTERLEAVE_MAX__SHIFT) & DSI_CMD_CFG0_INTERLEAVE_MAX__MASK;
}
#define DSI_CMD_CFG0_RGB_SWAP__MASK				0x00070000
#define DSI_CMD_CFG0_RGB_SWAP__SHIFT				16
static inline uint32_t DSI_CMD_CFG0_RGB_SWAP(enum dsi_rgb_swap val)
{
	return ((val) << DSI_CMD_CFG0_RGB_SWAP__SHIFT) & DSI_CMD_CFG0_RGB_SWAP__MASK;
}

#define REG_DSI_CMD_CFG1					0x00000040
#define DSI_CMD_CFG1_WR_MEM_START__MASK				0x000000ff
#define DSI_CMD_CFG1_WR_MEM_START__SHIFT			0
static inline uint32_t DSI_CMD_CFG1_WR_MEM_START(uint32_t val)
{
	return ((val) << DSI_CMD_CFG1_WR_MEM_START__SHIFT) & DSI_CMD_CFG1_WR_MEM_START__MASK;
}
#define DSI_CMD_CFG1_WR_MEM_CONTINUE__MASK			0x0000ff00
#define DSI_CMD_CFG1_WR_MEM_CONTINUE__SHIFT			8
static inline uint32_t DSI_CMD_CFG1_WR_MEM_CONTINUE(uint32_t val)
{
	return ((val) << DSI_CMD_CFG1_WR_MEM_CONTINUE__SHIFT) & DSI_CMD_CFG1_WR_MEM_CONTINUE__MASK;
}
#define DSI_CMD_CFG1_INSERT_DCS_COMMAND				0x00010000

#define REG_DSI_DMA_BASE					0x00000044

#define REG_DSI_DMA_LEN						0x00000048

#define REG_DSI_CMD_MDP_STREAM0_CTRL				0x00000054
#define DSI_CMD_MDP_STREAM0_CTRL_DATA_TYPE__MASK		0x0000003f
#define DSI_CMD_MDP_STREAM0_CTRL_DATA_TYPE__SHIFT		0
static inline uint32_t DSI_CMD_MDP_STREAM0_CTRL_DATA_TYPE(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM0_CTRL_DATA_TYPE__SHIFT) & DSI_CMD_MDP_STREAM0_CTRL_DATA_TYPE__MASK;
}
#define DSI_CMD_MDP_STREAM0_CTRL_VIRTUAL_CHANNEL__MASK		0x00000300
#define DSI_CMD_MDP_STREAM0_CTRL_VIRTUAL_CHANNEL__SHIFT		8
static inline uint32_t DSI_CMD_MDP_STREAM0_CTRL_VIRTUAL_CHANNEL(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM0_CTRL_VIRTUAL_CHANNEL__SHIFT) & DSI_CMD_MDP_STREAM0_CTRL_VIRTUAL_CHANNEL__MASK;
}
#define DSI_CMD_MDP_STREAM0_CTRL_WORD_COUNT__MASK		0xffff0000
#define DSI_CMD_MDP_STREAM0_CTRL_WORD_COUNT__SHIFT		16
static inline uint32_t DSI_CMD_MDP_STREAM0_CTRL_WORD_COUNT(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM0_CTRL_WORD_COUNT__SHIFT) & DSI_CMD_MDP_STREAM0_CTRL_WORD_COUNT__MASK;
}

#define REG_DSI_CMD_MDP_STREAM0_TOTAL				0x00000058
#define DSI_CMD_MDP_STREAM0_TOTAL_H_TOTAL__MASK			0x00000fff
#define DSI_CMD_MDP_STREAM0_TOTAL_H_TOTAL__SHIFT		0
static inline uint32_t DSI_CMD_MDP_STREAM0_TOTAL_H_TOTAL(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM0_TOTAL_H_TOTAL__SHIFT) & DSI_CMD_MDP_STREAM0_TOTAL_H_TOTAL__MASK;
}
#define DSI_CMD_MDP_STREAM0_TOTAL_V_TOTAL__MASK			0x0fff0000
#define DSI_CMD_MDP_STREAM0_TOTAL_V_TOTAL__SHIFT		16
static inline uint32_t DSI_CMD_MDP_STREAM0_TOTAL_V_TOTAL(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM0_TOTAL_V_TOTAL__SHIFT) & DSI_CMD_MDP_STREAM0_TOTAL_V_TOTAL__MASK;
}

#define REG_DSI_CMD_MDP_STREAM1_CTRL				0x0000005c
#define DSI_CMD_MDP_STREAM1_CTRL_DATA_TYPE__MASK		0x0000003f
#define DSI_CMD_MDP_STREAM1_CTRL_DATA_TYPE__SHIFT		0
static inline uint32_t DSI_CMD_MDP_STREAM1_CTRL_DATA_TYPE(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM1_CTRL_DATA_TYPE__SHIFT) & DSI_CMD_MDP_STREAM1_CTRL_DATA_TYPE__MASK;
}
#define DSI_CMD_MDP_STREAM1_CTRL_VIRTUAL_CHANNEL__MASK		0x00000300
#define DSI_CMD_MDP_STREAM1_CTRL_VIRTUAL_CHANNEL__SHIFT		8
static inline uint32_t DSI_CMD_MDP_STREAM1_CTRL_VIRTUAL_CHANNEL(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM1_CTRL_VIRTUAL_CHANNEL__SHIFT) & DSI_CMD_MDP_STREAM1_CTRL_VIRTUAL_CHANNEL__MASK;
}
#define DSI_CMD_MDP_STREAM1_CTRL_WORD_COUNT__MASK		0xffff0000
#define DSI_CMD_MDP_STREAM1_CTRL_WORD_COUNT__SHIFT		16
static inline uint32_t DSI_CMD_MDP_STREAM1_CTRL_WORD_COUNT(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM1_CTRL_WORD_COUNT__SHIFT) & DSI_CMD_MDP_STREAM1_CTRL_WORD_COUNT__MASK;
}

#define REG_DSI_CMD_MDP_STREAM1_TOTAL				0x00000060
#define DSI_CMD_MDP_STREAM1_TOTAL_H_TOTAL__MASK			0x0000ffff
#define DSI_CMD_MDP_STREAM1_TOTAL_H_TOTAL__SHIFT		0
static inline uint32_t DSI_CMD_MDP_STREAM1_TOTAL_H_TOTAL(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM1_TOTAL_H_TOTAL__SHIFT) & DSI_CMD_MDP_STREAM1_TOTAL_H_TOTAL__MASK;
}
#define DSI_CMD_MDP_STREAM1_TOTAL_V_TOTAL__MASK			0xffff0000
#define DSI_CMD_MDP_STREAM1_TOTAL_V_TOTAL__SHIFT		16
static inline uint32_t DSI_CMD_MDP_STREAM1_TOTAL_V_TOTAL(uint32_t val)
{
	return ((val) << DSI_CMD_MDP_STREAM1_TOTAL_V_TOTAL__SHIFT) & DSI_CMD_MDP_STREAM1_TOTAL_V_TOTAL__MASK;
}

#define REG_DSI_ACK_ERR_STATUS					0x00000064

static inline uint32_t REG_DSI_RDBK(uint32_t i0) { return 0x00000068 + 0x4*i0; }

static inline uint32_t REG_DSI_RDBK_DATA(uint32_t i0) { return 0x00000068 + 0x4*i0; }

#define REG_DSI_TRIG_CTRL					0x00000080
#define DSI_TRIG_CTRL_DMA_TRIGGER__MASK				0x00000007
#define DSI_TRIG_CTRL_DMA_TRIGGER__SHIFT			0
static inline uint32_t DSI_TRIG_CTRL_DMA_TRIGGER(enum dsi_cmd_trigger val)
{
	return ((val) << DSI_TRIG_CTRL_DMA_TRIGGER__SHIFT) & DSI_TRIG_CTRL_DMA_TRIGGER__MASK;
}
#define DSI_TRIG_CTRL_MDP_TRIGGER__MASK				0x00000070
#define DSI_TRIG_CTRL_MDP_TRIGGER__SHIFT			4
static inline uint32_t DSI_TRIG_CTRL_MDP_TRIGGER(enum dsi_cmd_trigger val)
{
	return ((val) << DSI_TRIG_CTRL_MDP_TRIGGER__SHIFT) & DSI_TRIG_CTRL_MDP_TRIGGER__MASK;
}
#define DSI_TRIG_CTRL_STREAM__MASK				0x00000300
#define DSI_TRIG_CTRL_STREAM__SHIFT				8
static inline uint32_t DSI_TRIG_CTRL_STREAM(uint32_t val)
{
	return ((val) << DSI_TRIG_CTRL_STREAM__SHIFT) & DSI_TRIG_CTRL_STREAM__MASK;
}
#define DSI_TRIG_CTRL_BLOCK_DMA_WITHIN_FRAME			0x00001000
#define DSI_TRIG_CTRL_TE					0x80000000

#define REG_DSI_TRIG_DMA					0x0000008c

#define REG_DSI_DLN0_PHY_ERR					0x000000b0
#define DSI_DLN0_PHY_ERR_DLN0_ERR_ESC				0x00000001
#define DSI_DLN0_PHY_ERR_DLN0_ERR_SYNC_ESC			0x00000010
#define DSI_DLN0_PHY_ERR_DLN0_ERR_CONTROL			0x00000100
#define DSI_DLN0_PHY_ERR_DLN0_ERR_CONTENTION_LP0		0x00001000
#define DSI_DLN0_PHY_ERR_DLN0_ERR_CONTENTION_LP1		0x00010000

#define REG_DSI_LP_TIMER_CTRL					0x000000b4
#define DSI_LP_TIMER_CTRL_LP_RX_TO__MASK			0x0000ffff
#define DSI_LP_TIMER_CTRL_LP_RX_TO__SHIFT			0
static inline uint32_t DSI_LP_TIMER_CTRL_LP_RX_TO(uint32_t val)
{
	return ((val) << DSI_LP_TIMER_CTRL_LP_RX_TO__SHIFT) & DSI_LP_TIMER_CTRL_LP_RX_TO__MASK;
}
#define DSI_LP_TIMER_CTRL_BTA_TO__MASK				0xffff0000
#define DSI_LP_TIMER_CTRL_BTA_TO__SHIFT				16
static inline uint32_t DSI_LP_TIMER_CTRL_BTA_TO(uint32_t val)
{
	return ((val) << DSI_LP_TIMER_CTRL_BTA_TO__SHIFT) & DSI_LP_TIMER_CTRL_BTA_TO__MASK;
}

#define REG_DSI_HS_TIMER_CTRL					0x000000b8
#define DSI_HS_TIMER_CTRL_HS_TX_TO__MASK			0x0000ffff
#define DSI_HS_TIMER_CTRL_HS_TX_TO__SHIFT			0
static inline uint32_t DSI_HS_TIMER_CTRL_HS_TX_TO(uint32_t val)
{
	return ((val) << DSI_HS_TIMER_CTRL_HS_TX_TO__SHIFT) & DSI_HS_TIMER_CTRL_HS_TX_TO__MASK;
}
#define DSI_HS_TIMER_CTRL_TIMER_RESOLUTION__MASK		0x000f0000
#define DSI_HS_TIMER_CTRL_TIMER_RESOLUTION__SHIFT		16
static inline uint32_t DSI_HS_TIMER_CTRL_TIMER_RESOLUTION(uint32_t val)
{
	return ((val) << DSI_HS_TIMER_CTRL_TIMER_RESOLUTION__SHIFT) & DSI_HS_TIMER_CTRL_TIMER_RESOLUTION__MASK;
}
#define DSI_HS_TIMER_CTRL_HS_TX_TO_STOP_EN			0x10000000

#define REG_DSI_TIMEOUT_STATUS					0x000000bc

#define REG_DSI_CLKOUT_TIMING_CTRL				0x000000c0
#define DSI_CLKOUT_TIMING_CTRL_T_CLK_PRE__MASK			0x0000003f
#define DSI_CLKOUT_TIMING_CTRL_T_CLK_PRE__SHIFT			0
static inline uint32_t DSI_CLKOUT_TIMING_CTRL_T_CLK_PRE(uint32_t val)
{
	return ((val) << DSI_CLKOUT_TIMING_CTRL_T_CLK_PRE__SHIFT) & DSI_CLKOUT_TIMING_CTRL_T_CLK_PRE__MASK;
}
#define DSI_CLKOUT_TIMING_CTRL_T_CLK_POST__MASK			0x00003f00
#define DSI_CLKOUT_TIMING_CTRL_T_CLK_POST__SHIFT		8
static inline uint32_t DSI_CLKOUT_TIMING_CTRL_T_CLK_POST(uint32_t val)
{
	return ((val) << DSI_CLKOUT_TIMING_CTRL_T_CLK_POST__SHIFT) & DSI_CLKOUT_TIMING_CTRL_T_CLK_POST__MASK;
}

#define REG_DSI_EOT_PACKET_CTRL					0x000000c8
#define DSI_EOT_PACKET_CTRL_TX_EOT_APPEND			0x00000001
#define DSI_EOT_PACKET_CTRL_RX_EOT_IGNORE			0x00000010

#define REG_DSI_LANE_STATUS					0x000000a4
#define DSI_LANE_STATUS_DLN0_STOPSTATE				0x00000001
#define DSI_LANE_STATUS_DLN1_STOPSTATE				0x00000002
#define DSI_LANE_STATUS_DLN2_STOPSTATE				0x00000004
#define DSI_LANE_STATUS_DLN3_STOPSTATE				0x00000008
#define DSI_LANE_STATUS_CLKLN_STOPSTATE				0x00000010
#define DSI_LANE_STATUS_DLN0_ULPS_ACTIVE_NOT			0x00000100
#define DSI_LANE_STATUS_DLN1_ULPS_ACTIVE_NOT			0x00000200
#define DSI_LANE_STATUS_DLN2_ULPS_ACTIVE_NOT			0x00000400
#define DSI_LANE_STATUS_DLN3_ULPS_ACTIVE_NOT			0x00000800
#define DSI_LANE_STATUS_CLKLN_ULPS_ACTIVE_NOT			0x00001000
#define DSI_LANE_STATUS_DLN0_DIRECTION				0x00010000

#define REG_DSI_LANE_CTRL					0x000000a8
#define DSI_LANE_CTRL_HS_REQ_SEL_PHY				0x01000000
#define DSI_LANE_CTRL_CLKLN_HS_FORCE_REQUEST			0x10000000

#define REG_DSI_LANE_SWAP_CTRL					0x000000ac
#define DSI_LANE_SWAP_CTRL_DLN_SWAP_SEL__MASK			0x00000007
#define DSI_LANE_SWAP_CTRL_DLN_SWAP_SEL__SHIFT			0
static inline uint32_t DSI_LANE_SWAP_CTRL_DLN_SWAP_SEL(enum dsi_lane_swap val)
{
	return ((val) << DSI_LANE_SWAP_CTRL_DLN_SWAP_SEL__SHIFT) & DSI_LANE_SWAP_CTRL_DLN_SWAP_SEL__MASK;
}

#define REG_DSI_ERR_INT_MASK0					0x00000108

#define REG_DSI_INTR_CTRL					0x0000010c

#define REG_DSI_RESET						0x00000114

#define REG_DSI_CLK_CTRL					0x00000118
#define DSI_CLK_CTRL_AHBS_HCLK_ON				0x00000001
#define DSI_CLK_CTRL_AHBM_SCLK_ON				0x00000002
#define DSI_CLK_CTRL_PCLK_ON					0x00000004
#define DSI_CLK_CTRL_DSICLK_ON					0x00000008
#define DSI_CLK_CTRL_BYTECLK_ON					0x00000010
#define DSI_CLK_CTRL_ESCCLK_ON					0x00000020
#define DSI_CLK_CTRL_FORCE_ON_DYN_AHBM_HCLK			0x00000200

#define REG_DSI_CLK_STATUS					0x0000011c
#define DSI_CLK_STATUS_DSI_AON_AHBM_HCLK_ACTIVE			0x00000001
#define DSI_CLK_STATUS_DSI_DYN_AHBM_HCLK_ACTIVE			0x00000002
#define DSI_CLK_STATUS_DSI_AON_AHBS_HCLK_ACTIVE			0x00000004
#define DSI_CLK_STATUS_DSI_DYN_AHBS_HCLK_ACTIVE			0x00000008
#define DSI_CLK_STATUS_DSI_AON_DSICLK_ACTIVE			0x00000010
#define DSI_CLK_STATUS_DSI_DYN_DSICLK_ACTIVE			0x00000020
#define DSI_CLK_STATUS_DSI_AON_BYTECLK_ACTIVE			0x00000040
#define DSI_CLK_STATUS_DSI_DYN_BYTECLK_ACTIVE			0x00000080
#define DSI_CLK_STATUS_DSI_AON_ESCCLK_ACTIVE			0x00000100
#define DSI_CLK_STATUS_DSI_AON_PCLK_ACTIVE			0x00000200
#define DSI_CLK_STATUS_DSI_DYN_PCLK_ACTIVE			0x00000400
#define DSI_CLK_STATUS_DSI_DYN_CMD_PCLK_ACTIVE			0x00001000
#define DSI_CLK_STATUS_DSI_CMD_PCLK_ACTIVE			0x00002000
#define DSI_CLK_STATUS_DSI_VID_PCLK_ACTIVE			0x00004000
#define DSI_CLK_STATUS_DSI_CAM_BIST_PCLK_ACT			0x00008000
#define DSI_CLK_STATUS_PLL_UNLOCKED				0x00010000

#define REG_DSI_PHY_RESET					0x00000128
#define DSI_PHY_RESET_RESET					0x00000001

#define REG_DSI_TEST_PATTERN_GEN_VIDEO_INIT_VAL			0x00000160

#define REG_DSI_TPG_MAIN_CONTROL				0x00000198
#define DSI_TPG_MAIN_CONTROL_CHECKERED_RECTANGLE_PATTERN	0x00000100

#define REG_DSI_TPG_VIDEO_CONFIG				0x000001a0
#define DSI_TPG_VIDEO_CONFIG_BPP__MASK				0x00000003
#define DSI_TPG_VIDEO_CONFIG_BPP__SHIFT				0
static inline uint32_t DSI_TPG_VIDEO_CONFIG_BPP(enum video_config_bpp val)
{
	return ((val) << DSI_TPG_VIDEO_CONFIG_BPP__SHIFT) & DSI_TPG_VIDEO_CONFIG_BPP__MASK;
}
#define DSI_TPG_VIDEO_CONFIG_RGB				0x00000004

#define REG_DSI_TEST_PATTERN_GEN_CTRL				0x00000158
#define DSI_TEST_PATTERN_GEN_CTRL_CMD_DMA_PATTERN_SEL__MASK	0x00030000
#define DSI_TEST_PATTERN_GEN_CTRL_CMD_DMA_PATTERN_SEL__SHIFT	16
static inline uint32_t DSI_TEST_PATTERN_GEN_CTRL_CMD_DMA_PATTERN_SEL(enum cmd_dma_pattern_sel val)
{
	return ((val) << DSI_TEST_PATTERN_GEN_CTRL_CMD_DMA_PATTERN_SEL__SHIFT) & DSI_TEST_PATTERN_GEN_CTRL_CMD_DMA_PATTERN_SEL__MASK;
}
#define DSI_TEST_PATTERN_GEN_CTRL_CMD_MDP_STREAM0_PATTERN_SEL__MASK	0x00000300
#define DSI_TEST_PATTERN_GEN_CTRL_CMD_MDP_STREAM0_PATTERN_SEL__SHIFT	8
static inline uint32_t DSI_TEST_PATTERN_GEN_CTRL_CMD_MDP_STREAM0_PATTERN_SEL(enum cmd_mdp_stream0_pattern_sel val)
{
	return ((val) << DSI_TEST_PATTERN_GEN_CTRL_CMD_MDP_STREAM0_PATTERN_SEL__SHIFT) & DSI_TEST_PATTERN_GEN_CTRL_CMD_MDP_STREAM0_PATTERN_SEL__MASK;
}
#define DSI_TEST_PATTERN_GEN_CTRL_VIDEO_PATTERN_SEL__MASK	0x00000030
#define DSI_TEST_PATTERN_GEN_CTRL_VIDEO_PATTERN_SEL__SHIFT	4
static inline uint32_t DSI_TEST_PATTERN_GEN_CTRL_VIDEO_PATTERN_SEL(enum video_pattern_sel val)
{
	return ((val) << DSI_TEST_PATTERN_GEN_CTRL_VIDEO_PATTERN_SEL__SHIFT) & DSI_TEST_PATTERN_GEN_CTRL_VIDEO_PATTERN_SEL__MASK;
}
#define DSI_TEST_PATTERN_GEN_CTRL_TPG_DMA_FIFO_MODE		0x00000004
#define DSI_TEST_PATTERN_GEN_CTRL_CMD_DMA_TPG_EN		0x00000002
#define DSI_TEST_PATTERN_GEN_CTRL_EN				0x00000001

#define REG_DSI_TEST_PATTERN_GEN_CMD_MDP_INIT_VAL0		0x00000168

#define REG_DSI_TEST_PATTERN_GEN_CMD_STREAM0_TRIGGER		0x00000180
#define DSI_TEST_PATTERN_GEN_CMD_STREAM0_TRIGGER_SW_TRIGGER	0x00000001

#define REG_DSI_TPG_MAIN_CONTROL2				0x0000019c
#define DSI_TPG_MAIN_CONTROL2_CMD_MDP0_CHECKERED_RECTANGLE_PATTERN	0x00000080
#define DSI_TPG_MAIN_CONTROL2_CMD_MDP1_CHECKERED_RECTANGLE_PATTERN	0x00010000
#define DSI_TPG_MAIN_CONTROL2_CMD_MDP2_CHECKERED_RECTANGLE_PATTERN	0x02000000

#define REG_DSI_T_CLK_PRE_EXTEND				0x0000017c
#define DSI_T_CLK_PRE_EXTEND_INC_BY_2_BYTECLK			0x00000001

#define REG_DSI_CMD_MODE_MDP_CTRL2				0x000001b4
#define DSI_CMD_MODE_MDP_CTRL2_DST_FORMAT2__MASK		0x0000000f
#define DSI_CMD_MODE_MDP_CTRL2_DST_FORMAT2__SHIFT		0
static inline uint32_t DSI_CMD_MODE_MDP_CTRL2_DST_FORMAT2(enum dsi_cmd_dst_format val)
{
	return ((val) << DSI_CMD_MODE_MDP_CTRL2_DST_FORMAT2__SHIFT) & DSI_CMD_MODE_MDP_CTRL2_DST_FORMAT2__MASK;
}
#define DSI_CMD_MODE_MDP_CTRL2_R_SEL				0x00000010
#define DSI_CMD_MODE_MDP_CTRL2_G_SEL				0x00000020
#define DSI_CMD_MODE_MDP_CTRL2_B_SEL				0x00000040
#define DSI_CMD_MODE_MDP_CTRL2_BYTE_MSB_LSB_FLIP		0x00000080
#define DSI_CMD_MODE_MDP_CTRL2_RGB_SWAP__MASK			0x00000700
#define DSI_CMD_MODE_MDP_CTRL2_RGB_SWAP__SHIFT			8
static inline uint32_t DSI_CMD_MODE_MDP_CTRL2_RGB_SWAP(enum dsi_rgb_swap val)
{
	return ((val) << DSI_CMD_MODE_MDP_CTRL2_RGB_SWAP__SHIFT) & DSI_CMD_MODE_MDP_CTRL2_RGB_SWAP__MASK;
}
#define DSI_CMD_MODE_MDP_CTRL2_INPUT_RGB_SWAP__MASK		0x00007000
#define DSI_CMD_MODE_MDP_CTRL2_INPUT_RGB_SWAP__SHIFT		12
static inline uint32_t DSI_CMD_MODE_MDP_CTRL2_INPUT_RGB_SWAP(enum dsi_rgb_swap val)
{
	return ((val) << DSI_CMD_MODE_MDP_CTRL2_INPUT_RGB_SWAP__SHIFT) & DSI_CMD_MODE_MDP_CTRL2_INPUT_RGB_SWAP__MASK;
}
#define DSI_CMD_MODE_MDP_CTRL2_BURST_MODE			0x00010000

#define REG_DSI_CMD_MODE_MDP_STREAM2_CTRL			0x000001b8
#define DSI_CMD_MODE_MDP_STREAM2_CTRL_DATA_TYPE__MASK		0x0000003f
#define DSI_CMD_MODE_MDP_STREAM2_CTRL_DATA_TYPE__SHIFT		0
static inline uint32_t DSI_CMD_MODE_MDP_STREAM2_CTRL_DATA_TYPE(uint32_t val)
{
	return ((val) << DSI_CMD_MODE_MDP_STREAM2_CTRL_DATA_TYPE__SHIFT) & DSI_CMD_MODE_MDP_STREAM2_CTRL_DATA_TYPE__MASK;
}
#define DSI_CMD_MODE_MDP_STREAM2_CTRL_VIRTUAL_CHANNEL__MASK	0x00000300
#define DSI_CMD_MODE_MDP_STREAM2_CTRL_VIRTUAL_CHANNEL__SHIFT	8
static inline uint32_t DSI_CMD_MODE_MDP_STREAM2_CTRL_VIRTUAL_CHANNEL(uint32_t val)
{
	return ((val) << DSI_CMD_MODE_MDP_STREAM2_CTRL_VIRTUAL_CHANNEL__SHIFT) & DSI_CMD_MODE_MDP_STREAM2_CTRL_VIRTUAL_CHANNEL__MASK;
}
#define DSI_CMD_MODE_MDP_STREAM2_CTRL_WORD_COUNT__MASK		0xffff0000
#define DSI_CMD_MODE_MDP_STREAM2_CTRL_WORD_COUNT__SHIFT		16
static inline uint32_t DSI_CMD_MODE_MDP_STREAM2_CTRL_WORD_COUNT(uint32_t val)
{
	return ((val) << DSI_CMD_MODE_MDP_STREAM2_CTRL_WORD_COUNT__SHIFT) & DSI_CMD_MODE_MDP_STREAM2_CTRL_WORD_COUNT__MASK;
}

#define REG_DSI_RDBK_DATA_CTRL					0x000001d0
#define DSI_RDBK_DATA_CTRL_COUNT__MASK				0x00ff0000
#define DSI_RDBK_DATA_CTRL_COUNT__SHIFT				16
static inline uint32_t DSI_RDBK_DATA_CTRL_COUNT(uint32_t val)
{
	return ((val) << DSI_RDBK_DATA_CTRL_COUNT__SHIFT) & DSI_RDBK_DATA_CTRL_COUNT__MASK;
}
#define DSI_RDBK_DATA_CTRL_CLR					0x00000001

#define REG_DSI_VERSION						0x000001f0
#define DSI_VERSION_MAJOR__MASK					0xff000000
#define DSI_VERSION_MAJOR__SHIFT				24
static inline uint32_t DSI_VERSION_MAJOR(uint32_t val)
{
	return ((val) << DSI_VERSION_MAJOR__SHIFT) & DSI_VERSION_MAJOR__MASK;
}

#define REG_DSI_CPHY_MODE_CTRL					0x000002d4

#define REG_DSI_VIDEO_COMPRESSION_MODE_CTRL			0x0000029c
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_WC__MASK		0xffff0000
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_WC__SHIFT		16
static inline uint32_t DSI_VIDEO_COMPRESSION_MODE_CTRL_WC(uint32_t val)
{
	return ((val) << DSI_VIDEO_COMPRESSION_MODE_CTRL_WC__SHIFT) & DSI_VIDEO_COMPRESSION_MODE_CTRL_WC__MASK;
}
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_DATATYPE__MASK		0x00003f00
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_DATATYPE__SHIFT		8
static inline uint32_t DSI_VIDEO_COMPRESSION_MODE_CTRL_DATATYPE(uint32_t val)
{
	return ((val) << DSI_VIDEO_COMPRESSION_MODE_CTRL_DATATYPE__SHIFT) & DSI_VIDEO_COMPRESSION_MODE_CTRL_DATATYPE__MASK;
}
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_PKT_PER_LINE__MASK	0x000000c0
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_PKT_PER_LINE__SHIFT	6
static inline uint32_t DSI_VIDEO_COMPRESSION_MODE_CTRL_PKT_PER_LINE(uint32_t val)
{
	return ((val) << DSI_VIDEO_COMPRESSION_MODE_CTRL_PKT_PER_LINE__SHIFT) & DSI_VIDEO_COMPRESSION_MODE_CTRL_PKT_PER_LINE__MASK;
}
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_EOL_BYTE_NUM__MASK	0x00000030
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_EOL_BYTE_NUM__SHIFT	4
static inline uint32_t DSI_VIDEO_COMPRESSION_MODE_CTRL_EOL_BYTE_NUM(uint32_t val)
{
	return ((val) << DSI_VIDEO_COMPRESSION_MODE_CTRL_EOL_BYTE_NUM__SHIFT) & DSI_VIDEO_COMPRESSION_MODE_CTRL_EOL_BYTE_NUM__MASK;
}
#define DSI_VIDEO_COMPRESSION_MODE_CTRL_EN			0x00000001

#define REG_DSI_COMMAND_COMPRESSION_MODE_CTRL			0x000002a4
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_DATATYPE__MASK	0x3f000000
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_DATATYPE__SHIFT	24
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_DATATYPE(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_DATATYPE__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_DATATYPE__MASK;
}
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_PKT_PER_LINE__MASK	0x00c00000
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_PKT_PER_LINE__SHIFT	22
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_PKT_PER_LINE(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_PKT_PER_LINE__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_PKT_PER_LINE__MASK;
}
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_EOL_BYTE_NUM__MASK	0x00300000
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_EOL_BYTE_NUM__SHIFT	20
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_EOL_BYTE_NUM(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_EOL_BYTE_NUM__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_EOL_BYTE_NUM__MASK;
}
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM1_EN		0x00010000
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_DATATYPE__MASK	0x00003f00
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_DATATYPE__SHIFT	8
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_DATATYPE(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_DATATYPE__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_DATATYPE__MASK;
}
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_PKT_PER_LINE__MASK	0x000000c0
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_PKT_PER_LINE__SHIFT	6
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_PKT_PER_LINE(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_PKT_PER_LINE__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_PKT_PER_LINE__MASK;
}
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_EOL_BYTE_NUM__MASK	0x00000030
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_EOL_BYTE_NUM__SHIFT	4
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_EOL_BYTE_NUM(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_EOL_BYTE_NUM__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_EOL_BYTE_NUM__MASK;
}
#define DSI_COMMAND_COMPRESSION_MODE_CTRL_STREAM0_EN		0x00000001

#define REG_DSI_COMMAND_COMPRESSION_MODE_CTRL2			0x000002a8
#define DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM1_SLICE_WIDTH__MASK	0xffff0000
#define DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM1_SLICE_WIDTH__SHIFT	16
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM1_SLICE_WIDTH(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM1_SLICE_WIDTH__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM1_SLICE_WIDTH__MASK;
}
#define DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM0_SLICE_WIDTH__MASK	0x0000ffff
#define DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM0_SLICE_WIDTH__SHIFT	0
static inline uint32_t DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM0_SLICE_WIDTH(uint32_t val)
{
	return ((val) << DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM0_SLICE_WIDTH__SHIFT) & DSI_COMMAND_COMPRESSION_MODE_CTRL2_STREAM0_SLICE_WIDTH__MASK;
}


#endif /* DSI_XML */
