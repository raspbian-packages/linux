/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2020, The Linux Foundation. All rights reserved.
 */

#ifndef _DP_REG_H_
#define _DP_REG_H_

/* DP_TX Registers */
#define REG_DP_HW_VERSION			(0x00000000)

#define REG_DP_SW_RESET				(0x00000010)
#define DP_SW_RESET				(0x00000001)

#define REG_DP_PHY_CTRL				(0x00000014)
#define DP_PHY_CTRL_SW_RESET_PLL		(0x00000001)
#define DP_PHY_CTRL_SW_RESET			(0x00000004)

#define REG_DP_CLK_CTRL				(0x00000018)
#define REG_DP_CLK_ACTIVE			(0x0000001C)
#define REG_DP_INTR_STATUS			(0x00000020)
#define REG_DP_INTR_STATUS2			(0x00000024)
#define REG_DP_INTR_STATUS3			(0x00000028)

#define REG_DP_DP_HPD_CTRL			(0x00000000)
#define DP_DP_HPD_CTRL_HPD_EN			(0x00000001)

#define REG_DP_DP_HPD_INT_STATUS		(0x00000004)

#define REG_DP_DP_HPD_INT_ACK			(0x00000008)
#define DP_DP_HPD_PLUG_INT_ACK			(0x00000001)
#define DP_DP_IRQ_HPD_INT_ACK			(0x00000002)
#define DP_DP_HPD_REPLUG_INT_ACK		(0x00000004)
#define DP_DP_HPD_UNPLUG_INT_ACK		(0x00000008)
#define DP_DP_HPD_STATE_STATUS_BITS_MASK	(0x0000000F)
#define DP_DP_HPD_STATE_STATUS_BITS_SHIFT	(0x1C)

#define REG_DP_DP_HPD_INT_MASK			(0x0000000C)
#define DP_DP_HPD_PLUG_INT_MASK			(0x00000001)
#define DP_DP_IRQ_HPD_INT_MASK			(0x00000002)
#define DP_DP_HPD_REPLUG_INT_MASK		(0x00000004)
#define DP_DP_HPD_UNPLUG_INT_MASK		(0x00000008)
#define DP_DP_HPD_INT_MASK			(DP_DP_HPD_PLUG_INT_MASK | \
						DP_DP_IRQ_HPD_INT_MASK | \
						DP_DP_HPD_REPLUG_INT_MASK | \
						DP_DP_HPD_UNPLUG_INT_MASK)
#define DP_DP_HPD_STATE_STATUS_CONNECTED	(0x40000000)
#define DP_DP_HPD_STATE_STATUS_PENDING		(0x20000000)
#define DP_DP_HPD_STATE_STATUS_DISCONNECTED	(0x00000000)
#define DP_DP_HPD_STATE_STATUS_MASK		(0xE0000000)

#define REG_DP_DP_HPD_REFTIMER			(0x00000018)
#define DP_DP_HPD_REFTIMER_ENABLE		(1 << 16)

#define REG_DP_DP_HPD_EVENT_TIME_0		(0x0000001C)
#define REG_DP_DP_HPD_EVENT_TIME_1		(0x00000020)
#define DP_DP_HPD_EVENT_TIME_0_VAL		(0x3E800FA)
#define DP_DP_HPD_EVENT_TIME_1_VAL		(0x1F407D0)

#define REG_DP_AUX_CTRL				(0x00000030)
#define DP_AUX_CTRL_ENABLE			(0x00000001)
#define DP_AUX_CTRL_RESET			(0x00000002)

#define REG_DP_AUX_DATA				(0x00000034)
#define DP_AUX_DATA_READ			(0x00000001)
#define DP_AUX_DATA_WRITE			(0x00000000)
#define DP_AUX_DATA_OFFSET			(0x00000008)
#define DP_AUX_DATA_INDEX_OFFSET		(0x00000010)
#define DP_AUX_DATA_MASK			(0x0000ff00)
#define DP_AUX_DATA_INDEX_WRITE			(0x80000000)

#define REG_DP_AUX_TRANS_CTRL			(0x00000038)
#define DP_AUX_TRANS_CTRL_I2C			(0x00000100)
#define DP_AUX_TRANS_CTRL_GO			(0x00000200)
#define DP_AUX_TRANS_CTRL_NO_SEND_ADDR		(0x00000400)
#define DP_AUX_TRANS_CTRL_NO_SEND_STOP		(0x00000800)

#define REG_DP_TIMEOUT_COUNT			(0x0000003C)
#define REG_DP_AUX_LIMITS			(0x00000040)
#define REG_DP_AUX_STATUS			(0x00000044)

#define DP_DPCD_CP_IRQ				(0x201)
#define DP_DPCD_RXSTATUS			(0x69493)

#define DP_INTERRUPT_TRANS_NUM			(0x000000A0)

#define REG_DP_MAINLINK_CTRL			(0x00000000)
#define DP_MAINLINK_CTRL_ENABLE			(0x00000001)
#define DP_MAINLINK_CTRL_RESET			(0x00000002)
#define DP_MAINLINK_CTRL_SW_BYPASS_SCRAMBLER	(0x00000010)
#define DP_MAINLINK_FB_BOUNDARY_SEL		(0x02000000)

#define REG_DP_STATE_CTRL			(0x00000004)
#define DP_STATE_CTRL_LINK_TRAINING_PATTERN1	(0x00000001)
#define DP_STATE_CTRL_LINK_TRAINING_PATTERN2	(0x00000002)
#define DP_STATE_CTRL_LINK_TRAINING_PATTERN3	(0x00000004)
#define DP_STATE_CTRL_LINK_TRAINING_PATTERN4	(0x00000008)
#define DP_STATE_CTRL_LINK_SYMBOL_ERR_MEASURE	(0x00000010)
#define DP_STATE_CTRL_LINK_PRBS7		(0x00000020)
#define DP_STATE_CTRL_LINK_TEST_CUSTOM_PATTERN	(0x00000040)
#define DP_STATE_CTRL_SEND_VIDEO		(0x00000080)
#define DP_STATE_CTRL_PUSH_IDLE			(0x00000100)

#define REG_DP_CONFIGURATION_CTRL		(0x00000008)
#define DP_CONFIGURATION_CTRL_SYNC_ASYNC_CLK	(0x00000001)
#define DP_CONFIGURATION_CTRL_STATIC_DYNAMIC_CN (0x00000002)
#define DP_CONFIGURATION_CTRL_P_INTERLACED	(0x00000004)
#define DP_CONFIGURATION_CTRL_INTERLACED_BTF	(0x00000008)
#define DP_CONFIGURATION_CTRL_NUM_OF_LANES	(0x00000010)
#define DP_CONFIGURATION_CTRL_ENHANCED_FRAMING	(0x00000040)
#define DP_CONFIGURATION_CTRL_SEND_VSC		(0x00000080)
#define DP_CONFIGURATION_CTRL_BPC		(0x00000100)
#define DP_CONFIGURATION_CTRL_ASSR		(0x00000400)
#define DP_CONFIGURATION_CTRL_RGB_YUV		(0x00000800)
#define DP_CONFIGURATION_CTRL_LSCLK_DIV		(0x00002000)
#define DP_CONFIGURATION_CTRL_NUM_OF_LANES_SHIFT	(0x04)
#define DP_CONFIGURATION_CTRL_BPC_SHIFT		(0x08)
#define DP_CONFIGURATION_CTRL_LSCLK_DIV_SHIFT	(0x0D)

#define REG_DP_SOFTWARE_MVID			(0x00000010)
#define REG_DP_SOFTWARE_NVID			(0x00000018)
#define REG_DP_TOTAL_HOR_VER			(0x0000001C)
#define REG_DP_START_HOR_VER_FROM_SYNC		(0x00000020)
#define REG_DP_HSYNC_VSYNC_WIDTH_POLARITY	(0x00000024)
#define REG_DP_ACTIVE_HOR_VER			(0x00000028)

#define REG_DP_MISC1_MISC0			(0x0000002C)
#define DP_MISC0_SYNCHRONOUS_CLK		(0x00000001)
#define DP_MISC0_COLORIMETRY_CFG_SHIFT		(0x00000001)
#define DP_MISC0_TEST_BITS_DEPTH_SHIFT		(0x00000005)

#define DP_MISC0_COLORIMERY_CFG_LEGACY_RGB	(0)
#define DP_MISC0_COLORIMERY_CFG_CEA_RGB		(0x04)

#define REG_DP_VALID_BOUNDARY			(0x00000030)
#define REG_DP_VALID_BOUNDARY_2			(0x00000034)

#define REG_DP_LOGICAL2PHYSICAL_LANE_MAPPING	(0x00000038)
#define LANE0_MAPPING_SHIFT			(0x00000000)
#define LANE1_MAPPING_SHIFT			(0x00000002)
#define LANE2_MAPPING_SHIFT			(0x00000004)
#define LANE3_MAPPING_SHIFT			(0x00000006)

#define REG_DP_MAINLINK_READY			(0x00000040)
#define DP_MAINLINK_READY_FOR_VIDEO		(0x00000001)
#define DP_MAINLINK_READY_LINK_TRAINING_SHIFT	(0x00000003)

#define REG_DP_MAINLINK_LEVELS			(0x00000044)
#define DP_MAINLINK_SAFE_TO_EXIT_LEVEL_2	(0x00000002)


#define REG_DP_TU				(0x0000004C)

#define REG_DP_HBR2_COMPLIANCE_SCRAMBLER_RESET	(0x00000054)
#define DP_HBR2_ERM_PATTERN			(0x00010000)

#define REG_DP_TEST_80BIT_CUSTOM_PATTERN_REG0	(0x000000C0)
#define REG_DP_TEST_80BIT_CUSTOM_PATTERN_REG1	(0x000000C4)
#define REG_DP_TEST_80BIT_CUSTOM_PATTERN_REG2	(0x000000C8)

#define MMSS_DP_MISC1_MISC0			(0x0000002C)
#define MMSS_DP_AUDIO_TIMING_GEN		(0x00000080)
#define MMSS_DP_AUDIO_TIMING_RBR_32		(0x00000084)
#define MMSS_DP_AUDIO_TIMING_HBR_32		(0x00000088)
#define MMSS_DP_AUDIO_TIMING_RBR_44		(0x0000008C)
#define MMSS_DP_AUDIO_TIMING_HBR_44		(0x00000090)
#define MMSS_DP_AUDIO_TIMING_RBR_48		(0x00000094)
#define MMSS_DP_AUDIO_TIMING_HBR_48		(0x00000098)

#define MMSS_DP_PSR_CRC_RG			(0x00000154)
#define MMSS_DP_PSR_CRC_B			(0x00000158)

#define REG_DP_COMPRESSION_MODE_CTRL		(0x00000180)

#define MMSS_DP_AUDIO_CFG			(0x00000200)
#define MMSS_DP_AUDIO_STATUS			(0x00000204)
#define MMSS_DP_AUDIO_PKT_CTRL			(0x00000208)
#define MMSS_DP_AUDIO_PKT_CTRL2			(0x0000020C)
#define MMSS_DP_AUDIO_ACR_CTRL			(0x00000210)
#define MMSS_DP_AUDIO_CTRL_RESET		(0x00000214)

#define MMSS_DP_SDP_CFG				(0x00000228)
#define MMSS_DP_SDP_CFG2			(0x0000022C)
#define MMSS_DP_AUDIO_TIMESTAMP_0		(0x00000230)
#define MMSS_DP_AUDIO_TIMESTAMP_1		(0x00000234)

#define MMSS_DP_AUDIO_STREAM_0			(0x00000240)
#define MMSS_DP_AUDIO_STREAM_1			(0x00000244)

#define MMSS_DP_EXTENSION_0			(0x00000250)
#define MMSS_DP_EXTENSION_1			(0x00000254)
#define MMSS_DP_EXTENSION_2			(0x00000258)
#define MMSS_DP_EXTENSION_3			(0x0000025C)
#define MMSS_DP_EXTENSION_4			(0x00000260)
#define MMSS_DP_EXTENSION_5			(0x00000264)
#define MMSS_DP_EXTENSION_6			(0x00000268)
#define MMSS_DP_EXTENSION_7			(0x0000026C)
#define MMSS_DP_EXTENSION_8			(0x00000270)
#define MMSS_DP_EXTENSION_9			(0x00000274)
#define MMSS_DP_AUDIO_COPYMANAGEMENT_0		(0x00000278)
#define MMSS_DP_AUDIO_COPYMANAGEMENT_1		(0x0000027C)
#define MMSS_DP_AUDIO_COPYMANAGEMENT_2		(0x00000280)
#define MMSS_DP_AUDIO_COPYMANAGEMENT_3		(0x00000284)
#define MMSS_DP_AUDIO_COPYMANAGEMENT_4		(0x00000288)
#define MMSS_DP_AUDIO_COPYMANAGEMENT_5		(0x0000028C)
#define MMSS_DP_AUDIO_ISRC_0			(0x00000290)
#define MMSS_DP_AUDIO_ISRC_1			(0x00000294)
#define MMSS_DP_AUDIO_ISRC_2			(0x00000298)
#define MMSS_DP_AUDIO_ISRC_3			(0x0000029C)
#define MMSS_DP_AUDIO_ISRC_4			(0x000002A0)
#define MMSS_DP_AUDIO_ISRC_5			(0x000002A4)
#define MMSS_DP_AUDIO_INFOFRAME_0		(0x000002A8)
#define MMSS_DP_AUDIO_INFOFRAME_1		(0x000002AC)
#define MMSS_DP_AUDIO_INFOFRAME_2		(0x000002B0)

#define MMSS_DP_GENERIC0_0			(0x00000300)
#define MMSS_DP_GENERIC0_1			(0x00000304)
#define MMSS_DP_GENERIC0_2			(0x00000308)
#define MMSS_DP_GENERIC0_3			(0x0000030C)
#define MMSS_DP_GENERIC0_4			(0x00000310)
#define MMSS_DP_GENERIC0_5			(0x00000314)
#define MMSS_DP_GENERIC0_6			(0x00000318)
#define MMSS_DP_GENERIC0_7			(0x0000031C)
#define MMSS_DP_GENERIC0_8			(0x00000320)
#define MMSS_DP_GENERIC0_9			(0x00000324)
#define MMSS_DP_GENERIC1_0			(0x00000328)
#define MMSS_DP_GENERIC1_1			(0x0000032C)
#define MMSS_DP_GENERIC1_2			(0x00000330)
#define MMSS_DP_GENERIC1_3			(0x00000334)
#define MMSS_DP_GENERIC1_4			(0x00000338)
#define MMSS_DP_GENERIC1_5			(0x0000033C)
#define MMSS_DP_GENERIC1_6			(0x00000340)
#define MMSS_DP_GENERIC1_7			(0x00000344)
#define MMSS_DP_GENERIC1_8			(0x00000348)
#define MMSS_DP_GENERIC1_9			(0x0000034C)

#define MMSS_DP_VSCEXT_0			(0x000002D0)
#define MMSS_DP_VSCEXT_1			(0x000002D4)
#define MMSS_DP_VSCEXT_2			(0x000002D8)
#define MMSS_DP_VSCEXT_3			(0x000002DC)
#define MMSS_DP_VSCEXT_4			(0x000002E0)
#define MMSS_DP_VSCEXT_5			(0x000002E4)
#define MMSS_DP_VSCEXT_6			(0x000002E8)
#define MMSS_DP_VSCEXT_7			(0x000002EC)
#define MMSS_DP_VSCEXT_8			(0x000002F0)
#define MMSS_DP_VSCEXT_9			(0x000002F4)

#define MMSS_DP_BIST_ENABLE			(0x00000000)
#define DP_BIST_ENABLE_DPBIST_EN		(0x00000001)

#define MMSS_DP_TIMING_ENGINE_EN		(0x00000010)
#define DP_TIMING_ENGINE_EN_EN			(0x00000001)

#define MMSS_DP_INTF_CONFIG			(0x00000014)
#define MMSS_DP_INTF_HSYNC_CTL			(0x00000018)
#define MMSS_DP_INTF_VSYNC_PERIOD_F0		(0x0000001C)
#define MMSS_DP_INTF_VSYNC_PERIOD_F1		(0x00000020)
#define MMSS_DP_INTF_VSYNC_PULSE_WIDTH_F0	(0x00000024)
#define MMSS_DP_INTF_VSYNC_PULSE_WIDTH_F1	(0x00000028)
#define MMSS_INTF_DISPLAY_V_START_F0		(0x0000002C)
#define MMSS_INTF_DISPLAY_V_START_F1		(0x00000030)
#define MMSS_DP_INTF_DISPLAY_V_END_F0		(0x00000034)
#define MMSS_DP_INTF_DISPLAY_V_END_F1		(0x00000038)
#define MMSS_DP_INTF_ACTIVE_V_START_F0		(0x0000003C)
#define MMSS_DP_INTF_ACTIVE_V_START_F1		(0x00000040)
#define MMSS_DP_INTF_ACTIVE_V_END_F0		(0x00000044)
#define MMSS_DP_INTF_ACTIVE_V_END_F1		(0x00000048)
#define MMSS_DP_INTF_DISPLAY_HCTL		(0x0000004C)
#define MMSS_DP_INTF_ACTIVE_HCTL		(0x00000050)
#define MMSS_DP_INTF_POLARITY_CTL		(0x00000058)

#define MMSS_DP_TPG_MAIN_CONTROL		(0x00000060)
#define MMSS_DP_DSC_DTO				(0x0000007C)
#define DP_TPG_CHECKERED_RECT_PATTERN		(0x00000100)

#define MMSS_DP_TPG_VIDEO_CONFIG		(0x00000064)
#define DP_TPG_VIDEO_CONFIG_BPP_8BIT		(0x00000001)
#define DP_TPG_VIDEO_CONFIG_RGB			(0x00000004)

#define MMSS_DP_ASYNC_FIFO_CONFIG		(0x00000088)

#define REG_DP_PHY_AUX_INTERRUPT_CLEAR          (0x0000004C)
#define REG_DP_PHY_AUX_BIST_CFG			(0x00000050)
#define REG_DP_PHY_AUX_INTERRUPT_STATUS         (0x000000BC)

/* DP HDCP 1.3 registers */
#define DP_HDCP_CTRL                                   (0x0A0)
#define DP_HDCP_STATUS                                 (0x0A4)
#define DP_HDCP_SW_UPPER_AKSV                          (0x098)
#define DP_HDCP_SW_LOWER_AKSV                          (0x09C)
#define DP_HDCP_ENTROPY_CTRL0                          (0x350)
#define DP_HDCP_ENTROPY_CTRL1                          (0x35C)
#define DP_HDCP_SHA_STATUS                             (0x0C8)
#define DP_HDCP_RCVPORT_DATA2_0                        (0x0B0)
#define DP_HDCP_RCVPORT_DATA3                          (0x0A4)
#define DP_HDCP_RCVPORT_DATA4                          (0x0A8)
#define DP_HDCP_RCVPORT_DATA5                          (0x0C0)
#define DP_HDCP_RCVPORT_DATA6                          (0x0C4)

#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_SHA_CTRL           (0x024)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_SHA_DATA           (0x028)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA0      (0x004)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA1      (0x008)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA7      (0x00C)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA8      (0x010)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA9      (0x014)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA10     (0x018)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA11     (0x01C)
#define HDCP_SEC_DP_TZ_HV_HLOS_HDCP_RCVPORT_DATA12     (0x020)

#endif /* _DP_REG_H_ */
