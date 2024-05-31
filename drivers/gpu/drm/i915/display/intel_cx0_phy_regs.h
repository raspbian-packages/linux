/* SPDX-License-Identifier: MIT
 *
 * Copyright © 2023 Intel Corporation
 */

#ifndef __INTEL_CX0_PHY_REGS_H__
#define __INTEL_CX0_PHY_REGS_H__

#include "i915_reg_defs.h"

#define _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_A		0x64040
#define _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_B		0x64140
#define _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_USBC1		0x16F240
#define _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_USBC2		0x16F440
#define XELPDP_PORT_M2P_MSGBUS_CTL(port, lane)		_MMIO(_PICK_EVEN_2RANGES(port, PORT_TC1, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_A, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_B, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_USBC1, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_USBC2) + (lane) * 4)
#define   XELPDP_PORT_M2P_TRANSACTION_PENDING		REG_BIT(31)
#define   XELPDP_PORT_M2P_COMMAND_TYPE_MASK		REG_GENMASK(30, 27)
#define   XELPDP_PORT_M2P_COMMAND_WRITE_UNCOMMITTED	REG_FIELD_PREP(XELPDP_PORT_M2P_COMMAND_TYPE_MASK, 0x1)
#define   XELPDP_PORT_M2P_COMMAND_WRITE_COMMITTED	REG_FIELD_PREP(XELPDP_PORT_M2P_COMMAND_TYPE_MASK, 0x2)
#define   XELPDP_PORT_M2P_COMMAND_READ			REG_FIELD_PREP(XELPDP_PORT_M2P_COMMAND_TYPE_MASK, 0x3)
#define   XELPDP_PORT_M2P_DATA_MASK			REG_GENMASK(23, 16)
#define   XELPDP_PORT_M2P_DATA(val)			REG_FIELD_PREP(XELPDP_PORT_M2P_DATA_MASK, val)
#define   XELPDP_PORT_M2P_TRANSACTION_RESET		REG_BIT(15)
#define   XELPDP_PORT_M2P_ADDRESS_MASK			REG_GENMASK(11, 0)
#define   XELPDP_PORT_M2P_ADDRESS(val)			REG_FIELD_PREP(XELPDP_PORT_M2P_ADDRESS_MASK, val)
#define XELPDP_PORT_P2M_MSGBUS_STATUS(port, lane)	_MMIO(_PICK_EVEN_2RANGES(port, PORT_TC1, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_A, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_B, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_USBC1, \
										 _XELPDP_PORT_M2P_MSGBUS_CTL_LN0_USBC2) + (lane) * 4 + 8)
#define   XELPDP_PORT_P2M_RESPONSE_READY		REG_BIT(31)
#define   XELPDP_PORT_P2M_COMMAND_TYPE_MASK		REG_GENMASK(30, 27)
#define   XELPDP_PORT_P2M_COMMAND_READ_ACK		0x4
#define   XELPDP_PORT_P2M_COMMAND_WRITE_ACK		0x5
#define   XELPDP_PORT_P2M_DATA_MASK			REG_GENMASK(23, 16)
#define   XELPDP_PORT_P2M_DATA(val)			REG_FIELD_PREP(XELPDP_PORT_P2M_DATA_MASK, val)
#define   XELPDP_PORT_P2M_ERROR_SET			REG_BIT(15)

#define XELPDP_MSGBUS_TIMEOUT_SLOW			1
#define XELPDP_MSGBUS_TIMEOUT_FAST_US			2
#define XELPDP_PCLK_PLL_ENABLE_TIMEOUT_US		3200
#define XELPDP_PCLK_PLL_DISABLE_TIMEOUT_US		20
#define XELPDP_PORT_BUF_SOC_READY_TIMEOUT_US		100
#define XELPDP_PORT_RESET_START_TIMEOUT_US		5
#define XELPDP_PORT_POWERDOWN_UPDATE_TIMEOUT_US		100
#define XELPDP_PORT_RESET_END_TIMEOUT			15
#define XELPDP_REFCLK_ENABLE_TIMEOUT_US			1

#define _XELPDP_PORT_BUF_CTL1_LN0_A			0x64004
#define _XELPDP_PORT_BUF_CTL1_LN0_B			0x64104
#define _XELPDP_PORT_BUF_CTL1_LN0_USBC1			0x16F200
#define _XELPDP_PORT_BUF_CTL1_LN0_USBC2			0x16F400
#define XELPDP_PORT_BUF_CTL1(port)			_MMIO(_PICK_EVEN_2RANGES(port, PORT_TC1, \
										 _XELPDP_PORT_BUF_CTL1_LN0_A, \
										 _XELPDP_PORT_BUF_CTL1_LN0_B, \
										 _XELPDP_PORT_BUF_CTL1_LN0_USBC1, \
										 _XELPDP_PORT_BUF_CTL1_LN0_USBC2))
#define   XELPDP_PORT_BUF_D2D_LINK_ENABLE		REG_BIT(29)
#define   XELPDP_PORT_BUF_D2D_LINK_STATE		REG_BIT(28)
#define   XELPDP_PORT_BUF_SOC_PHY_READY			REG_BIT(24)
#define   XELPDP_PORT_BUF_PORT_DATA_WIDTH_MASK		REG_GENMASK(19, 18)
#define   XELPDP_PORT_BUF_PORT_DATA_10BIT		REG_FIELD_PREP(XELPDP_PORT_BUF_PORT_DATA_WIDTH_MASK, 0)
#define   XELPDP_PORT_BUF_PORT_DATA_20BIT		REG_FIELD_PREP(XELPDP_PORT_BUF_PORT_DATA_WIDTH_MASK, 1)
#define   XELPDP_PORT_BUF_PORT_DATA_40BIT		REG_FIELD_PREP(XELPDP_PORT_BUF_PORT_DATA_WIDTH_MASK, 2)
#define   XELPDP_PORT_REVERSAL				REG_BIT(16)
#define   XELPDP_PORT_BUF_IO_SELECT_TBT			REG_BIT(11)
#define   XELPDP_PORT_BUF_PHY_IDLE			REG_BIT(7)
#define   XELPDP_TC_PHY_OWNERSHIP			REG_BIT(6)
#define   XELPDP_TCSS_POWER_REQUEST			REG_BIT(5)
#define   XELPDP_TCSS_POWER_STATE			REG_BIT(4)
#define   XELPDP_PORT_WIDTH_MASK			REG_GENMASK(3, 1)
#define   XELPDP_PORT_WIDTH(val)			REG_FIELD_PREP(XELPDP_PORT_WIDTH_MASK, val)

#define XELPDP_PORT_BUF_CTL2(port)			_MMIO(_PICK_EVEN_2RANGES(port, PORT_TC1, \
										 _XELPDP_PORT_BUF_CTL1_LN0_A, \
										 _XELPDP_PORT_BUF_CTL1_LN0_B, \
										 _XELPDP_PORT_BUF_CTL1_LN0_USBC1, \
										 _XELPDP_PORT_BUF_CTL1_LN0_USBC2) + 4)

#define   XELPDP_LANE_PIPE_RESET(lane)			_PICK(lane, REG_BIT(31), REG_BIT(30))
#define   XELPDP_LANE_PHY_CURRENT_STATUS(lane)		_PICK(lane, REG_BIT(29), REG_BIT(28))
#define   XELPDP_LANE_POWERDOWN_UPDATE(lane)		_PICK(lane, REG_BIT(25), REG_BIT(24))
#define   _XELPDP_LANE0_POWERDOWN_NEW_STATE_MASK	REG_GENMASK(23, 20)
#define   _XELPDP_LANE0_POWERDOWN_NEW_STATE(val)	REG_FIELD_PREP(_XELPDP_LANE0_POWERDOWN_NEW_STATE_MASK, val)
#define   _XELPDP_LANE1_POWERDOWN_NEW_STATE_MASK	REG_GENMASK(19, 16)
#define   _XELPDP_LANE1_POWERDOWN_NEW_STATE(val)	REG_FIELD_PREP(_XELPDP_LANE1_POWERDOWN_NEW_STATE_MASK, val)
#define   XELPDP_LANE_POWERDOWN_NEW_STATE(lane, val)	_PICK(lane, \
							      _XELPDP_LANE0_POWERDOWN_NEW_STATE(val), \
							      _XELPDP_LANE1_POWERDOWN_NEW_STATE(val))
#define   XELPDP_LANE_POWERDOWN_NEW_STATE_MASK		REG_GENMASK(3, 0)
#define   XELPDP_POWER_STATE_READY_MASK			REG_GENMASK(7, 4)
#define   XELPDP_POWER_STATE_READY(val)			REG_FIELD_PREP(XELPDP_POWER_STATE_READY_MASK, val)

#define XELPDP_PORT_BUF_CTL3(port)			_MMIO(_PICK_EVEN_2RANGES(port, PORT_TC1, \
										 _XELPDP_PORT_BUF_CTL1_LN0_A, \
										 _XELPDP_PORT_BUF_CTL1_LN0_B, \
										 _XELPDP_PORT_BUF_CTL1_LN0_USBC1, \
										 _XELPDP_PORT_BUF_CTL1_LN0_USBC2) + 8)
#define   XELPDP_PLL_LANE_STAGGERING_DELAY_MASK		REG_GENMASK(15, 8)
#define   XELPDP_PLL_LANE_STAGGERING_DELAY(val)		REG_FIELD_PREP(XELPDP_PLL_LANE_STAGGERING_DELAY_MASK, val)
#define   XELPDP_POWER_STATE_ACTIVE_MASK		REG_GENMASK(3, 0)
#define   XELPDP_POWER_STATE_ACTIVE(val)		REG_FIELD_PREP(XELPDP_POWER_STATE_ACTIVE_MASK, val)
#define   CX0_P0_STATE_ACTIVE				0x0
#define   CX0_P2_STATE_READY				0x2
#define   CX0_P2PG_STATE_DISABLE			0x9
#define   CX0_P4PG_STATE_DISABLE			0xC
#define   CX0_P2_STATE_RESET				0x2

#define _XELPDP_PORT_MSGBUS_TIMER_LN0_A			0x640d8
#define _XELPDP_PORT_MSGBUS_TIMER_LN0_B			0x641d8
#define _XELPDP_PORT_MSGBUS_TIMER_LN0_USBC1		0x16f258
#define _XELPDP_PORT_MSGBUS_TIMER_LN0_USBC2		0x16f458
#define XELPDP_PORT_MSGBUS_TIMER(port, lane)		_MMIO(_PICK_EVEN_2RANGES(port, PORT_TC1, \
										 _XELPDP_PORT_MSGBUS_TIMER_LN0_A, \
										 _XELPDP_PORT_MSGBUS_TIMER_LN0_B, \
										 _XELPDP_PORT_MSGBUS_TIMER_LN0_USBC1, \
										 _XELPDP_PORT_MSGBUS_TIMER_LN0_USBC2) + (lane) * 4)
#define   XELPDP_PORT_MSGBUS_TIMER_TIMED_OUT		REG_BIT(31)
#define   XELPDP_PORT_MSGBUS_TIMER_VAL_MASK		REG_GENMASK(23, 0)
#define   XELPDP_PORT_MSGBUS_TIMER_VAL			REG_FIELD_PREP(XELPDP_PORT_MSGBUS_TIMER_VAL_MASK, 0xa000)

#define _XELPDP_PORT_CLOCK_CTL_A			0x640E0
#define _XELPDP_PORT_CLOCK_CTL_B			0x641E0
#define _XELPDP_PORT_CLOCK_CTL_USBC1			0x16F260
#define _XELPDP_PORT_CLOCK_CTL_USBC2			0x16F460
#define XELPDP_PORT_CLOCK_CTL(port)			_MMIO(_PICK_EVEN_2RANGES(port, PORT_TC1, \
										 _XELPDP_PORT_CLOCK_CTL_A, \
										 _XELPDP_PORT_CLOCK_CTL_B, \
										 _XELPDP_PORT_CLOCK_CTL_USBC1, \
										 _XELPDP_PORT_CLOCK_CTL_USBC2))
#define   XELPDP_LANE_PCLK_PLL_REQUEST(lane)		REG_BIT(31 - ((lane) * 4))
#define   XELPDP_LANE_PCLK_PLL_ACK(lane)		REG_BIT(30 - ((lane) * 4))
#define   XELPDP_LANE_PCLK_REFCLK_REQUEST(lane)		REG_BIT(29 - ((lane) * 4))
#define   XELPDP_LANE_PCLK_REFCLK_ACK(lane)		REG_BIT(28 - ((lane) * 4))

#define   XELPDP_TBT_CLOCK_REQUEST			REG_BIT(19)
#define   XELPDP_TBT_CLOCK_ACK				REG_BIT(18)
#define   XELPDP_DDI_CLOCK_SELECT_MASK			REG_GENMASK(15, 12)
#define   XELPDP_DDI_CLOCK_SELECT(val)			REG_FIELD_PREP(XELPDP_DDI_CLOCK_SELECT_MASK, val)
#define   XELPDP_DDI_CLOCK_SELECT_NONE			0x0
#define   XELPDP_DDI_CLOCK_SELECT_MAXPCLK		0x8
#define   XELPDP_DDI_CLOCK_SELECT_DIV18CLK		0x9
#define   XELPDP_DDI_CLOCK_SELECT_TBT_162		0xc
#define   XELPDP_DDI_CLOCK_SELECT_TBT_270		0xd
#define   XELPDP_DDI_CLOCK_SELECT_TBT_540		0xe
#define   XELPDP_DDI_CLOCK_SELECT_TBT_810		0xf
#define   XELPDP_FORWARD_CLOCK_UNGATE			REG_BIT(10)
#define   XELPDP_LANE1_PHY_CLOCK_SELECT			REG_BIT(8)
#define   XELPDP_SSC_ENABLE_PLLA			REG_BIT(1)
#define   XELPDP_SSC_ENABLE_PLLB			REG_BIT(0)

/* C10 Vendor Registers */
#define PHY_C10_VDR_PLL(idx)		(0xC00 + (idx))
#define   C10_PLL0_FRACEN		REG_BIT8(4)
#define   C10_PLL3_MULTIPLIERH_MASK	REG_GENMASK8(3, 0)
#define   C10_PLL15_TXCLKDIV_MASK	REG_GENMASK8(2, 0)
#define   C10_PLL15_HDMIDIV_MASK	REG_GENMASK8(5, 3)

#define PHY_C10_VDR_CMN(idx)		(0xC20 + (idx))
#define   C10_CMN0_REF_RANGE		REG_FIELD_PREP(REG_GENMASK(4, 0), 1)
#define   C10_CMN0_REF_CLK_MPLLB_DIV	REG_FIELD_PREP(REG_GENMASK(7, 5), 1)
#define   C10_CMN3_TXVBOOST_MASK	REG_GENMASK8(7, 5)
#define   C10_CMN3_TXVBOOST(val)	REG_FIELD_PREP8(C10_CMN3_TXVBOOST_MASK, val)
#define PHY_C10_VDR_TX(idx)		(0xC30 + (idx))
#define   C10_TX0_TX_MPLLB_SEL		REG_BIT(4)
#define   C10_TX1_TERMCTL_MASK		REG_GENMASK8(7, 5)
#define   C10_TX1_TERMCTL(val)		REG_FIELD_PREP8(C10_TX1_TERMCTL_MASK, val)
#define PHY_C10_VDR_CONTROL(idx)	(0xC70 + (idx) - 1)
#define   C10_VDR_CTRL_MSGBUS_ACCESS	REG_BIT8(2)
#define   C10_VDR_CTRL_MASTER_LANE	REG_BIT8(1)
#define   C10_VDR_CTRL_UPDATE_CFG	REG_BIT8(0)
#define PHY_C10_VDR_CUSTOM_WIDTH	0xD02
#define   C10_VDR_CUSTOM_WIDTH_MASK    REG_GENMASK(1, 0)
#define   C10_VDR_CUSTOM_WIDTH_8_10    REG_FIELD_PREP(C10_VDR_CUSTOM_WIDTH_MASK, 0)
#define PHY_C10_VDR_OVRD		0xD71
#define   PHY_C10_VDR_OVRD_TX1		REG_BIT8(0)
#define   PHY_C10_VDR_OVRD_TX2		REG_BIT8(2)
#define PHY_C10_VDR_PRE_OVRD_TX1	0xD80
#define C10_PHY_OVRD_LEVEL_MASK		REG_GENMASK8(5, 0)
#define C10_PHY_OVRD_LEVEL(val)		REG_FIELD_PREP8(C10_PHY_OVRD_LEVEL_MASK, val)
#define PHY_CX0_VDROVRD_CTL(lane, tx, control)				\
					(PHY_C10_VDR_PRE_OVRD_TX1 +	\
					 ((lane) ^ (tx)) * 0x10 + (control))

/* PIPE SPEC Defined Registers */
#define PHY_CX0_TX_CONTROL(tx, control)	(0x400 + ((tx) - 1) * 0x200 + (control))
#define   CONTROL2_DISABLE_SINGLE_TX	REG_BIT(6)

/* C20 Registers */
#define PHY_C20_WR_ADDRESS_L		0xC02
#define PHY_C20_WR_ADDRESS_H		0xC03
#define PHY_C20_WR_DATA_L		0xC04
#define PHY_C20_WR_DATA_H		0xC05
#define PHY_C20_RD_ADDRESS_L		0xC06
#define PHY_C20_RD_ADDRESS_H		0xC07
#define PHY_C20_RD_DATA_L		0xC08
#define PHY_C20_RD_DATA_H		0xC09
#define PHY_C20_VDR_CUSTOM_SERDES_RATE	0xD00
#define PHY_C20_VDR_HDMI_RATE		0xD01
#define   PHY_C20_CONTEXT_TOGGLE	REG_BIT8(0)
#define   PHY_C20_CUSTOM_SERDES_MASK	REG_GENMASK8(4, 1)
#define   PHY_C20_CUSTOM_SERDES(val)	REG_FIELD_PREP8(PHY_C20_CUSTOM_SERDES_MASK, val)
#define PHY_C20_VDR_CUSTOM_WIDTH	0xD02
#define   PHY_C20_CUSTOM_WIDTH_MASK	REG_GENMASK(1, 0)
#define   PHY_C20_CUSTOM_WIDTH(val)	REG_FIELD_PREP8(PHY_C20_CUSTOM_WIDTH_MASK, val)
#define PHY_C20_A_TX_CNTX_CFG(idx)	(0xCF2E - (idx))
#define PHY_C20_B_TX_CNTX_CFG(idx)	(0xCF2A - (idx))
#define   C20_PHY_TX_RATE		REG_GENMASK(2, 0)
#define PHY_C20_A_CMN_CNTX_CFG(idx)	(0xCDAA - (idx))
#define PHY_C20_B_CMN_CNTX_CFG(idx)	(0xCDA5 - (idx))
#define PHY_C20_A_MPLLA_CNTX_CFG(idx)	(0xCCF0 - (idx))
#define PHY_C20_B_MPLLA_CNTX_CFG(idx)	(0xCCE5 - (idx))
#define   C20_MPLLA_FRACEN		REG_BIT(14)
#define   C20_FB_CLK_DIV4_EN		REG_BIT(13)
#define   C20_MPLLA_TX_CLK_DIV_MASK	REG_GENMASK(10, 8)
#define PHY_C20_A_MPLLB_CNTX_CFG(idx)	(0xCB5A - (idx))
#define PHY_C20_B_MPLLB_CNTX_CFG(idx)	(0xCB4E - (idx))
#define   C20_MPLLB_TX_CLK_DIV_MASK	REG_GENMASK(15, 13)
#define   C20_MPLLB_FRACEN		REG_BIT(13)
#define   C20_REF_CLK_MPLLB_DIV_MASK	REG_GENMASK(12, 10)
#define   C20_MULTIPLIER_MASK		REG_GENMASK(11, 0)
#define   C20_PHY_USE_MPLLB		REG_BIT(7)

/* C20 Phy VSwing Masks */
#define C20_PHY_VSWING_PREEMPH_MASK	REG_GENMASK8(5, 0)
#define C20_PHY_VSWING_PREEMPH(val)	REG_FIELD_PREP8(C20_PHY_VSWING_PREEMPH_MASK, val)

#define RAWLANEAONX_DIG_TX_MPLLB_CAL_DONE_BANK(idx) (0x303D + (idx))

/* C20 HDMI computed pll definitions */
#define REFCLK_38_4_MHZ		38400000
#define CLOCK_4999MHZ		4999999999
#define CLOCK_9999MHZ		9999999999
#define DATARATE_3000000000	3000000000
#define DATARATE_3500000000	3500000000
#define DATARATE_4000000000	4000000000
#define MPLL_FRACN_DEN		0xFFFF

#define SSC_UP_SPREAD		REG_BIT16(9)
#define WORD_CLK_DIV		REG_BIT16(8)

#define MPLL_TX_CLK_DIV(val)	REG_FIELD_PREP16(C20_MPLLB_TX_CLK_DIV_MASK, val)
#define MPLL_MULTIPLIER(val)	REG_FIELD_PREP16(C20_MULTIPLIER_MASK, val)

#define MPLLB_ANA_FREQ_VCO_0	0
#define MPLLB_ANA_FREQ_VCO_1	1
#define MPLLB_ANA_FREQ_VCO_2	2
#define MPLLB_ANA_FREQ_VCO_3	3
#define MPLLB_ANA_FREQ_VCO_MASK	REG_GENMASK16(15, 14)
#define MPLLB_ANA_FREQ_VCO(val)	REG_FIELD_PREP16(MPLLB_ANA_FREQ_VCO_MASK, val)

#define MPLL_DIV_MULTIPLIER_MASK	REG_GENMASK16(7, 0)
#define MPLL_DIV_MULTIPLIER(val)	REG_FIELD_PREP16(MPLL_DIV_MULTIPLIER_MASK, val)

#define CAL_DAC_CODE_31		31
#define CAL_DAC_CODE_MASK	REG_GENMASK16(14, 10)
#define CAL_DAC_CODE(val)	REG_FIELD_PREP16(CAL_DAC_CODE_MASK, val)

#define CP_INT_GS_28		28
#define CP_INT_GS_MASK		REG_GENMASK16(6, 0)
#define CP_INT_GS(val)		REG_FIELD_PREP16(CP_INT_GS_MASK, val)

#define CP_PROP_GS_30		30
#define CP_PROP_GS_MASK		REG_GENMASK16(13, 7)
#define CP_PROP_GS(val)		REG_FIELD_PREP16(CP_PROP_GS_MASK, val)

#define CP_INT_6		6
#define CP_INT_MASK		REG_GENMASK16(6, 0)
#define CP_INT(val)		REG_FIELD_PREP16(CP_INT_MASK, val)

#define CP_PROP_20		20
#define CP_PROP_MASK		REG_GENMASK16(13, 7)
#define CP_PROP(val)		REG_FIELD_PREP16(CP_PROP_MASK, val)

#define V2I_2			2
#define V2I_MASK		REG_GENMASK16(15, 14)
#define V2I(val)		REG_FIELD_PREP16(V2I_MASK, val)

#define HDMI_DIV_1		1
#define HDMI_DIV_MASK		REG_GENMASK16(2, 0)
#define HDMI_DIV(val)		REG_FIELD_PREP16(HDMI_DIV_MASK, val)

#endif /* __INTEL_CX0_REG_DEFS_H__ */
