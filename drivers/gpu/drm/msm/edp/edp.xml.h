#ifndef EDP_XML
#define EDP_XML

/* Autogenerated file, DO NOT EDIT manually!

This file was generated by the rules-ng-ng headergen tool in this git repository:
http://github.com/freedreno/envytools/
git clone https://github.com/freedreno/envytools.git

The rules-ng-ng source files this header was generated from are:
- /home/robclark/src/envytools/rnndb/msm.xml                 (    676 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/freedreno_copyright.xml (   1572 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/mdp/mdp4.xml            (  20915 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/mdp/mdp_common.xml      (   2849 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/mdp/mdp5.xml            (  37411 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/dsi/dsi.xml             (  42301 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/dsi/sfpb.xml            (    602 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/dsi/mmss_cc.xml         (   1686 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/hdmi/qfprom.xml         (    600 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/hdmi/hdmi.xml           (  41874 bytes, from 2020-07-23 21:58:14)
- /home/robclark/src/envytools/rnndb/edp/edp.xml             (  10416 bytes, from 2020-07-23 21:58:14)

Copyright (C) 2013-2020 by the following authors:
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


enum edp_color_depth {
	EDP_6BIT = 0,
	EDP_8BIT = 1,
	EDP_10BIT = 2,
	EDP_12BIT = 3,
	EDP_16BIT = 4,
};

enum edp_component_format {
	EDP_RGB = 0,
	EDP_YUV422 = 1,
	EDP_YUV444 = 2,
};

#define REG_EDP_MAINLINK_CTRL					0x00000004
#define EDP_MAINLINK_CTRL_ENABLE				0x00000001
#define EDP_MAINLINK_CTRL_RESET					0x00000002

#define REG_EDP_STATE_CTRL					0x00000008
#define EDP_STATE_CTRL_TRAIN_PATTERN_1				0x00000001
#define EDP_STATE_CTRL_TRAIN_PATTERN_2				0x00000002
#define EDP_STATE_CTRL_TRAIN_PATTERN_3				0x00000004
#define EDP_STATE_CTRL_SYMBOL_ERR_RATE_MEAS			0x00000008
#define EDP_STATE_CTRL_PRBS7					0x00000010
#define EDP_STATE_CTRL_CUSTOM_80_BIT_PATTERN			0x00000020
#define EDP_STATE_CTRL_SEND_VIDEO				0x00000040
#define EDP_STATE_CTRL_PUSH_IDLE				0x00000080

#define REG_EDP_CONFIGURATION_CTRL				0x0000000c
#define EDP_CONFIGURATION_CTRL_SYNC_CLK				0x00000001
#define EDP_CONFIGURATION_CTRL_STATIC_MVID			0x00000002
#define EDP_CONFIGURATION_CTRL_PROGRESSIVE			0x00000004
#define EDP_CONFIGURATION_CTRL_LANES__MASK			0x00000030
#define EDP_CONFIGURATION_CTRL_LANES__SHIFT			4
static inline uint32_t EDP_CONFIGURATION_CTRL_LANES(uint32_t val)
{
	return ((val) << EDP_CONFIGURATION_CTRL_LANES__SHIFT) & EDP_CONFIGURATION_CTRL_LANES__MASK;
}
#define EDP_CONFIGURATION_CTRL_ENHANCED_FRAMING			0x00000040
#define EDP_CONFIGURATION_CTRL_COLOR__MASK			0x00000100
#define EDP_CONFIGURATION_CTRL_COLOR__SHIFT			8
static inline uint32_t EDP_CONFIGURATION_CTRL_COLOR(enum edp_color_depth val)
{
	return ((val) << EDP_CONFIGURATION_CTRL_COLOR__SHIFT) & EDP_CONFIGURATION_CTRL_COLOR__MASK;
}

#define REG_EDP_SOFTWARE_MVID					0x00000014

#define REG_EDP_SOFTWARE_NVID					0x00000018

#define REG_EDP_TOTAL_HOR_VER					0x0000001c
#define EDP_TOTAL_HOR_VER_HORIZ__MASK				0x0000ffff
#define EDP_TOTAL_HOR_VER_HORIZ__SHIFT				0
static inline uint32_t EDP_TOTAL_HOR_VER_HORIZ(uint32_t val)
{
	return ((val) << EDP_TOTAL_HOR_VER_HORIZ__SHIFT) & EDP_TOTAL_HOR_VER_HORIZ__MASK;
}
#define EDP_TOTAL_HOR_VER_VERT__MASK				0xffff0000
#define EDP_TOTAL_HOR_VER_VERT__SHIFT				16
static inline uint32_t EDP_TOTAL_HOR_VER_VERT(uint32_t val)
{
	return ((val) << EDP_TOTAL_HOR_VER_VERT__SHIFT) & EDP_TOTAL_HOR_VER_VERT__MASK;
}

#define REG_EDP_START_HOR_VER_FROM_SYNC				0x00000020
#define EDP_START_HOR_VER_FROM_SYNC_HORIZ__MASK			0x0000ffff
#define EDP_START_HOR_VER_FROM_SYNC_HORIZ__SHIFT		0
static inline uint32_t EDP_START_HOR_VER_FROM_SYNC_HORIZ(uint32_t val)
{
	return ((val) << EDP_START_HOR_VER_FROM_SYNC_HORIZ__SHIFT) & EDP_START_HOR_VER_FROM_SYNC_HORIZ__MASK;
}
#define EDP_START_HOR_VER_FROM_SYNC_VERT__MASK			0xffff0000
#define EDP_START_HOR_VER_FROM_SYNC_VERT__SHIFT			16
static inline uint32_t EDP_START_HOR_VER_FROM_SYNC_VERT(uint32_t val)
{
	return ((val) << EDP_START_HOR_VER_FROM_SYNC_VERT__SHIFT) & EDP_START_HOR_VER_FROM_SYNC_VERT__MASK;
}

#define REG_EDP_HSYNC_VSYNC_WIDTH_POLARITY			0x00000024
#define EDP_HSYNC_VSYNC_WIDTH_POLARITY_HORIZ__MASK		0x00007fff
#define EDP_HSYNC_VSYNC_WIDTH_POLARITY_HORIZ__SHIFT		0
static inline uint32_t EDP_HSYNC_VSYNC_WIDTH_POLARITY_HORIZ(uint32_t val)
{
	return ((val) << EDP_HSYNC_VSYNC_WIDTH_POLARITY_HORIZ__SHIFT) & EDP_HSYNC_VSYNC_WIDTH_POLARITY_HORIZ__MASK;
}
#define EDP_HSYNC_VSYNC_WIDTH_POLARITY_NHSYNC			0x00008000
#define EDP_HSYNC_VSYNC_WIDTH_POLARITY_VERT__MASK		0x7fff0000
#define EDP_HSYNC_VSYNC_WIDTH_POLARITY_VERT__SHIFT		16
static inline uint32_t EDP_HSYNC_VSYNC_WIDTH_POLARITY_VERT(uint32_t val)
{
	return ((val) << EDP_HSYNC_VSYNC_WIDTH_POLARITY_VERT__SHIFT) & EDP_HSYNC_VSYNC_WIDTH_POLARITY_VERT__MASK;
}
#define EDP_HSYNC_VSYNC_WIDTH_POLARITY_NVSYNC			0x80000000

#define REG_EDP_ACTIVE_HOR_VER					0x00000028
#define EDP_ACTIVE_HOR_VER_HORIZ__MASK				0x0000ffff
#define EDP_ACTIVE_HOR_VER_HORIZ__SHIFT				0
static inline uint32_t EDP_ACTIVE_HOR_VER_HORIZ(uint32_t val)
{
	return ((val) << EDP_ACTIVE_HOR_VER_HORIZ__SHIFT) & EDP_ACTIVE_HOR_VER_HORIZ__MASK;
}
#define EDP_ACTIVE_HOR_VER_VERT__MASK				0xffff0000
#define EDP_ACTIVE_HOR_VER_VERT__SHIFT				16
static inline uint32_t EDP_ACTIVE_HOR_VER_VERT(uint32_t val)
{
	return ((val) << EDP_ACTIVE_HOR_VER_VERT__SHIFT) & EDP_ACTIVE_HOR_VER_VERT__MASK;
}

#define REG_EDP_MISC1_MISC0					0x0000002c
#define EDP_MISC1_MISC0_MISC0__MASK				0x000000ff
#define EDP_MISC1_MISC0_MISC0__SHIFT				0
static inline uint32_t EDP_MISC1_MISC0_MISC0(uint32_t val)
{
	return ((val) << EDP_MISC1_MISC0_MISC0__SHIFT) & EDP_MISC1_MISC0_MISC0__MASK;
}
#define EDP_MISC1_MISC0_SYNC					0x00000001
#define EDP_MISC1_MISC0_COMPONENT_FORMAT__MASK			0x00000006
#define EDP_MISC1_MISC0_COMPONENT_FORMAT__SHIFT			1
static inline uint32_t EDP_MISC1_MISC0_COMPONENT_FORMAT(enum edp_component_format val)
{
	return ((val) << EDP_MISC1_MISC0_COMPONENT_FORMAT__SHIFT) & EDP_MISC1_MISC0_COMPONENT_FORMAT__MASK;
}
#define EDP_MISC1_MISC0_CEA					0x00000008
#define EDP_MISC1_MISC0_BT709_5					0x00000010
#define EDP_MISC1_MISC0_COLOR__MASK				0x000000e0
#define EDP_MISC1_MISC0_COLOR__SHIFT				5
static inline uint32_t EDP_MISC1_MISC0_COLOR(enum edp_color_depth val)
{
	return ((val) << EDP_MISC1_MISC0_COLOR__SHIFT) & EDP_MISC1_MISC0_COLOR__MASK;
}
#define EDP_MISC1_MISC0_MISC1__MASK				0x0000ff00
#define EDP_MISC1_MISC0_MISC1__SHIFT				8
static inline uint32_t EDP_MISC1_MISC0_MISC1(uint32_t val)
{
	return ((val) << EDP_MISC1_MISC0_MISC1__SHIFT) & EDP_MISC1_MISC0_MISC1__MASK;
}
#define EDP_MISC1_MISC0_INTERLACED_ODD				0x00000100
#define EDP_MISC1_MISC0_STEREO__MASK				0x00000600
#define EDP_MISC1_MISC0_STEREO__SHIFT				9
static inline uint32_t EDP_MISC1_MISC0_STEREO(uint32_t val)
{
	return ((val) << EDP_MISC1_MISC0_STEREO__SHIFT) & EDP_MISC1_MISC0_STEREO__MASK;
}

#define REG_EDP_PHY_CTRL					0x00000074
#define EDP_PHY_CTRL_SW_RESET_PLL				0x00000001
#define EDP_PHY_CTRL_SW_RESET					0x00000004

#define REG_EDP_MAINLINK_READY					0x00000084
#define EDP_MAINLINK_READY_TRAIN_PATTERN_1_READY		0x00000008
#define EDP_MAINLINK_READY_TRAIN_PATTERN_2_READY		0x00000010
#define EDP_MAINLINK_READY_TRAIN_PATTERN_3_READY		0x00000020

#define REG_EDP_AUX_CTRL					0x00000300
#define EDP_AUX_CTRL_ENABLE					0x00000001
#define EDP_AUX_CTRL_RESET					0x00000002

#define REG_EDP_INTERRUPT_REG_1					0x00000308
#define EDP_INTERRUPT_REG_1_HPD					0x00000001
#define EDP_INTERRUPT_REG_1_HPD_ACK				0x00000002
#define EDP_INTERRUPT_REG_1_HPD_EN				0x00000004
#define EDP_INTERRUPT_REG_1_AUX_I2C_DONE			0x00000008
#define EDP_INTERRUPT_REG_1_AUX_I2C_DONE_ACK			0x00000010
#define EDP_INTERRUPT_REG_1_AUX_I2C_DONE_EN			0x00000020
#define EDP_INTERRUPT_REG_1_WRONG_ADDR				0x00000040
#define EDP_INTERRUPT_REG_1_WRONG_ADDR_ACK			0x00000080
#define EDP_INTERRUPT_REG_1_WRONG_ADDR_EN			0x00000100
#define EDP_INTERRUPT_REG_1_TIMEOUT				0x00000200
#define EDP_INTERRUPT_REG_1_TIMEOUT_ACK				0x00000400
#define EDP_INTERRUPT_REG_1_TIMEOUT_EN				0x00000800
#define EDP_INTERRUPT_REG_1_NACK_DEFER				0x00001000
#define EDP_INTERRUPT_REG_1_NACK_DEFER_ACK			0x00002000
#define EDP_INTERRUPT_REG_1_NACK_DEFER_EN			0x00004000
#define EDP_INTERRUPT_REG_1_WRONG_DATA_CNT			0x00008000
#define EDP_INTERRUPT_REG_1_WRONG_DATA_CNT_ACK			0x00010000
#define EDP_INTERRUPT_REG_1_WRONG_DATA_CNT_EN			0x00020000
#define EDP_INTERRUPT_REG_1_I2C_NACK				0x00040000
#define EDP_INTERRUPT_REG_1_I2C_NACK_ACK			0x00080000
#define EDP_INTERRUPT_REG_1_I2C_NACK_EN				0x00100000
#define EDP_INTERRUPT_REG_1_I2C_DEFER				0x00200000
#define EDP_INTERRUPT_REG_1_I2C_DEFER_ACK			0x00400000
#define EDP_INTERRUPT_REG_1_I2C_DEFER_EN			0x00800000
#define EDP_INTERRUPT_REG_1_PLL_UNLOCK				0x01000000
#define EDP_INTERRUPT_REG_1_PLL_UNLOCK_ACK			0x02000000
#define EDP_INTERRUPT_REG_1_PLL_UNLOCK_EN			0x04000000
#define EDP_INTERRUPT_REG_1_AUX_ERROR				0x08000000
#define EDP_INTERRUPT_REG_1_AUX_ERROR_ACK			0x10000000
#define EDP_INTERRUPT_REG_1_AUX_ERROR_EN			0x20000000

#define REG_EDP_INTERRUPT_REG_2					0x0000030c
#define EDP_INTERRUPT_REG_2_READY_FOR_VIDEO			0x00000001
#define EDP_INTERRUPT_REG_2_READY_FOR_VIDEO_ACK			0x00000002
#define EDP_INTERRUPT_REG_2_READY_FOR_VIDEO_EN			0x00000004
#define EDP_INTERRUPT_REG_2_IDLE_PATTERNs_SENT			0x00000008
#define EDP_INTERRUPT_REG_2_IDLE_PATTERNs_SENT_ACK		0x00000010
#define EDP_INTERRUPT_REG_2_IDLE_PATTERNs_SENT_EN		0x00000020
#define EDP_INTERRUPT_REG_2_FRAME_END				0x00000200
#define EDP_INTERRUPT_REG_2_FRAME_END_ACK			0x00000080
#define EDP_INTERRUPT_REG_2_FRAME_END_EN			0x00000100
#define EDP_INTERRUPT_REG_2_CRC_UPDATED				0x00000200
#define EDP_INTERRUPT_REG_2_CRC_UPDATED_ACK			0x00000400
#define EDP_INTERRUPT_REG_2_CRC_UPDATED_EN			0x00000800

#define REG_EDP_INTERRUPT_TRANS_NUM				0x00000310

#define REG_EDP_AUX_DATA					0x00000314
#define EDP_AUX_DATA_READ					0x00000001
#define EDP_AUX_DATA_DATA__MASK					0x0000ff00
#define EDP_AUX_DATA_DATA__SHIFT				8
static inline uint32_t EDP_AUX_DATA_DATA(uint32_t val)
{
	return ((val) << EDP_AUX_DATA_DATA__SHIFT) & EDP_AUX_DATA_DATA__MASK;
}
#define EDP_AUX_DATA_INDEX__MASK				0x00ff0000
#define EDP_AUX_DATA_INDEX__SHIFT				16
static inline uint32_t EDP_AUX_DATA_INDEX(uint32_t val)
{
	return ((val) << EDP_AUX_DATA_INDEX__SHIFT) & EDP_AUX_DATA_INDEX__MASK;
}
#define EDP_AUX_DATA_INDEX_WRITE				0x80000000

#define REG_EDP_AUX_TRANS_CTRL					0x00000318
#define EDP_AUX_TRANS_CTRL_I2C					0x00000100
#define EDP_AUX_TRANS_CTRL_GO					0x00000200

#define REG_EDP_AUX_STATUS					0x00000324

static inline uint32_t REG_EDP_PHY_LN(uint32_t i0) { return 0x00000400 + 0x40*i0; }

static inline uint32_t REG_EDP_PHY_LN_PD_CTL(uint32_t i0) { return 0x00000404 + 0x40*i0; }

#define REG_EDP_PHY_GLB_VM_CFG0					0x00000510

#define REG_EDP_PHY_GLB_VM_CFG1					0x00000514

#define REG_EDP_PHY_GLB_MISC9					0x00000518

#define REG_EDP_PHY_GLB_CFG					0x00000528

#define REG_EDP_PHY_GLB_PD_CTL					0x0000052c

#define REG_EDP_PHY_GLB_PHY_STATUS				0x00000598

#define REG_EDP_28nm_PHY_PLL_REFCLK_CFG				0x00000000

#define REG_EDP_28nm_PHY_PLL_POSTDIV1_CFG			0x00000004

#define REG_EDP_28nm_PHY_PLL_CHGPUMP_CFG			0x00000008

#define REG_EDP_28nm_PHY_PLL_VCOLPF_CFG				0x0000000c

#define REG_EDP_28nm_PHY_PLL_VREG_CFG				0x00000010

#define REG_EDP_28nm_PHY_PLL_PWRGEN_CFG				0x00000014

#define REG_EDP_28nm_PHY_PLL_DMUX_CFG				0x00000018

#define REG_EDP_28nm_PHY_PLL_AMUX_CFG				0x0000001c

#define REG_EDP_28nm_PHY_PLL_GLB_CFG				0x00000020
#define EDP_28nm_PHY_PLL_GLB_CFG_PLL_PWRDN_B			0x00000001
#define EDP_28nm_PHY_PLL_GLB_CFG_PLL_LDO_PWRDN_B		0x00000002
#define EDP_28nm_PHY_PLL_GLB_CFG_PLL_PWRGEN_PWRDN_B		0x00000004
#define EDP_28nm_PHY_PLL_GLB_CFG_PLL_ENABLE			0x00000008

#define REG_EDP_28nm_PHY_PLL_POSTDIV2_CFG			0x00000024

#define REG_EDP_28nm_PHY_PLL_POSTDIV3_CFG			0x00000028

#define REG_EDP_28nm_PHY_PLL_LPFR_CFG				0x0000002c

#define REG_EDP_28nm_PHY_PLL_LPFC1_CFG				0x00000030

#define REG_EDP_28nm_PHY_PLL_LPFC2_CFG				0x00000034

#define REG_EDP_28nm_PHY_PLL_SDM_CFG0				0x00000038

#define REG_EDP_28nm_PHY_PLL_SDM_CFG1				0x0000003c

#define REG_EDP_28nm_PHY_PLL_SDM_CFG2				0x00000040

#define REG_EDP_28nm_PHY_PLL_SDM_CFG3				0x00000044

#define REG_EDP_28nm_PHY_PLL_SDM_CFG4				0x00000048

#define REG_EDP_28nm_PHY_PLL_SSC_CFG0				0x0000004c

#define REG_EDP_28nm_PHY_PLL_SSC_CFG1				0x00000050

#define REG_EDP_28nm_PHY_PLL_SSC_CFG2				0x00000054

#define REG_EDP_28nm_PHY_PLL_SSC_CFG3				0x00000058

#define REG_EDP_28nm_PHY_PLL_LKDET_CFG0				0x0000005c

#define REG_EDP_28nm_PHY_PLL_LKDET_CFG1				0x00000060

#define REG_EDP_28nm_PHY_PLL_LKDET_CFG2				0x00000064

#define REG_EDP_28nm_PHY_PLL_TEST_CFG				0x00000068
#define EDP_28nm_PHY_PLL_TEST_CFG_PLL_SW_RESET			0x00000001

#define REG_EDP_28nm_PHY_PLL_CAL_CFG0				0x0000006c

#define REG_EDP_28nm_PHY_PLL_CAL_CFG1				0x00000070

#define REG_EDP_28nm_PHY_PLL_CAL_CFG2				0x00000074

#define REG_EDP_28nm_PHY_PLL_CAL_CFG3				0x00000078

#define REG_EDP_28nm_PHY_PLL_CAL_CFG4				0x0000007c

#define REG_EDP_28nm_PHY_PLL_CAL_CFG5				0x00000080

#define REG_EDP_28nm_PHY_PLL_CAL_CFG6				0x00000084

#define REG_EDP_28nm_PHY_PLL_CAL_CFG7				0x00000088

#define REG_EDP_28nm_PHY_PLL_CAL_CFG8				0x0000008c

#define REG_EDP_28nm_PHY_PLL_CAL_CFG9				0x00000090

#define REG_EDP_28nm_PHY_PLL_CAL_CFG10				0x00000094

#define REG_EDP_28nm_PHY_PLL_CAL_CFG11				0x00000098

#define REG_EDP_28nm_PHY_PLL_EFUSE_CFG				0x0000009c

#define REG_EDP_28nm_PHY_PLL_DEBUG_BUS_SEL			0x000000a0


#endif /* EDP_XML */
