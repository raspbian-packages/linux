/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Linaro Limited
 */

#ifndef QCOM_PHY_QMP_QSERDES_COM_V6_H_
#define QCOM_PHY_QMP_QSERDES_COM_V6_H_

/* Only for QMP V6 PHY - QSERDES COM registers */

#define QSERDES_V6_COM_SSC_STEP_SIZE1_MODE1			0x00
#define QSERDES_V6_COM_SSC_STEP_SIZE2_MODE1			0x04
#define QSERDES_V6_COM_CP_CTRL_MODE1				0x10
#define QSERDES_V6_COM_PLL_RCTRL_MODE1				0x14
#define QSERDES_V6_COM_PLL_CCTRL_MODE1				0x18
#define QSERDES_V6_COM_CORECLK_DIV_MODE1			0x1c
#define QSERDES_V6_COM_LOCK_CMP1_MODE1				0x20
#define QSERDES_V6_COM_LOCK_CMP2_MODE1				0x24
#define QSERDES_V6_COM_DEC_START_MODE1				0x28
#define QSERDES_V6_COM_DEC_START_MSB_MODE1			0x2c
#define QSERDES_V6_COM_DIV_FRAC_START1_MODE1			0x30
#define QSERDES_V6_COM_DIV_FRAC_START2_MODE1			0x34
#define QSERDES_V6_COM_DIV_FRAC_START3_MODE1			0x38
#define QSERDES_V6_COM_HSCLK_SEL_1				0x3c
#define QSERDES_V6_COM_INTEGLOOP_GAIN0_MODE1			0x40
#define QSERDES_V6_COM_INTEGLOOP_GAIN1_MODE1			0x44
#define QSERDES_V6_COM_VCO_TUNE1_MODE1				0x48
#define QSERDES_V6_COM_VCO_TUNE2_MODE1				0x4c
#define QSERDES_V6_COM_BIN_VCOCAL_CMP_CODE1_MODE1		0x50
#define QSERDES_V6_COM_BIN_VCOCAL_CMP_CODE2_MODE1		0x54
#define QSERDES_V6_COM_BIN_VCOCAL_CMP_CODE1_MODE0		0x58
#define QSERDES_V6_COM_BIN_VCOCAL_CMP_CODE2_MODE0		0x5c
#define QSERDES_V6_COM_SSC_STEP_SIZE1_MODE0			0x60
#define QSERDES_V6_COM_SSC_STEP_SIZE2_MODE0			0x64
#define QSERDES_V6_COM_CP_CTRL_MODE0				0x70
#define QSERDES_V6_COM_PLL_RCTRL_MODE0				0x74
#define QSERDES_V6_COM_PLL_CCTRL_MODE0				0x78
#define QSERDES_V6_COM_PLL_CORE_CLK_DIV_MODE0			0x7c
#define QSERDES_V6_COM_LOCK_CMP1_MODE0				0x80
#define QSERDES_V6_COM_LOCK_CMP2_MODE0				0x84
#define QSERDES_V6_COM_DEC_START_MODE0				0x88
#define QSERDES_V6_COM_DEC_START_MSB_MODE0			0x8c
#define QSERDES_V6_COM_DIV_FRAC_START1_MODE0			0x90
#define QSERDES_V6_COM_DIV_FRAC_START2_MODE0			0x94
#define QSERDES_V6_COM_DIV_FRAC_START3_MODE0			0x98
#define QSERDES_V6_COM_HSCLK_HS_SWITCH_SEL_1			0x9c
#define QSERDES_V6_COM_INTEGLOOP_GAIN0_MODE0			0xa0
#define QSERDES_V6_COM_INTEGLOOP_GAIN1_MODE0			0xa4
#define QSERDES_V6_COM_VCO_TUNE1_MODE0				0xa8
#define QSERDES_V6_COM_VCO_TUNE2_MODE0				0xac
#define QSERDES_V6_COM_BG_TIMER					0xbc
#define QSERDES_V6_COM_SSC_EN_CENTER				0xc0
#define QSERDES_V6_COM_SSC_ADJ_PER1				0xc4
#define QSERDES_V6_COM_SSC_PER1					0xcc
#define QSERDES_V6_COM_SSC_PER2					0xd0
#define QSERDES_V6_COM_PLL_POST_DIV_MUX				0xd8
#define QSERDES_V6_COM_PLL_BIAS_EN_CLK_BUFLR_EN			0xdc
#define QSERDES_V6_COM_CLK_ENABLE1				0xe0
#define QSERDES_V6_COM_SYS_CLK_CTRL				0xe4
#define QSERDES_V6_COM_SYSCLK_BUF_ENABLE			0xe8
#define QSERDES_V6_COM_PLL_IVCO					0xf4
#define QSERDES_V6_COM_PLL_IVCO_MODE1				0xf8
#define QSERDES_V6_COM_CMN_IETRIM				0xfc
#define QSERDES_V6_COM_CMN_IPTRIM				0x100
#define QSERDES_V6_COM_SYSCLK_EN_SEL				0x110
#define QSERDES_V6_COM_RESETSM_CNTRL				0x118
#define QSERDES_V6_COM_LOCK_CMP_EN				0x120
#define QSERDES_V6_COM_LOCK_CMP_CFG				0x124
#define QSERDES_V6_COM_VCO_TUNE_CTRL				0x13c
#define QSERDES_V6_COM_VCO_TUNE_MAP				0x140
#define QSERDES_V6_COM_VCO_TUNE_INITVAL2			0x148
#define QSERDES_V6_COM_VCO_TUNE_MAXVAL2				0x158
#define QSERDES_V6_COM_CLK_SELECT				0x164
#define QSERDES_V6_COM_CORE_CLK_EN				0x170
#define QSERDES_V6_COM_CMN_CONFIG_1				0x174
#define QSERDES_V6_COM_SVS_MODE_CLK_SEL				0x17c
#define QSERDES_V6_COM_CMN_MISC_1				0x184
#define QSERDES_V6_COM_CMN_MODE					0x188
#define QSERDES_V6_COM_PLL_VCO_DC_LEVEL_CTRL			0x198
#define QSERDES_V6_COM_AUTO_GAIN_ADJ_CTRL_1			0x1a4
#define QSERDES_V6_COM_AUTO_GAIN_ADJ_CTRL_2			0x1a8
#define QSERDES_V6_COM_AUTO_GAIN_ADJ_CTRL_3			0x1ac
#define QSERDES_V6_COM_ADDITIONAL_MISC				0x1b4
#define QSERDES_V6_COM_ADDITIONAL_MISC_2			0x1b8
#define QSERDES_V6_COM_ADDITIONAL_MISC_3			0x1bc
#define QSERDES_V6_COM_CMN_STATUS				0x1d0
#define QSERDES_V6_COM_C_READY_STATUS				0x1f8

#endif
