/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
 */

#ifndef QCOM_PHY_QMP_QSERDES_COM_H_
#define QCOM_PHY_QMP_QSERDES_COM_H_

/* Only for QMP V2 PHY - QSERDES COM registers */
#define QSERDES_COM_ATB_SEL1				0x000
#define QSERDES_COM_ATB_SEL2				0x004
#define QSERDES_COM_FREQ_UPDATE				0x008
#define QSERDES_COM_BG_TIMER				0x00c
#define QSERDES_COM_SSC_EN_CENTER			0x010
#define QSERDES_COM_SSC_ADJ_PER1			0x014
#define QSERDES_COM_SSC_ADJ_PER2			0x018
#define QSERDES_COM_SSC_PER1				0x01c
#define QSERDES_COM_SSC_PER2				0x020
#define QSERDES_COM_SSC_STEP_SIZE1			0x024
#define QSERDES_COM_SSC_STEP_SIZE2			0x028
#define QSERDES_COM_POST_DIV				0x02c
#define QSERDES_COM_POST_DIV_MUX			0x030
#define QSERDES_COM_BIAS_EN_CLKBUFLR_EN			0x034
#define QSERDES_COM_CLK_ENABLE1				0x038
#define QSERDES_COM_SYS_CLK_CTRL			0x03c
#define QSERDES_COM_SYSCLK_BUF_ENABLE			0x040
#define QSERDES_COM_PLL_EN				0x044
#define QSERDES_COM_PLL_IVCO				0x048
#define QSERDES_COM_LOCK_CMP1_MODE0			0x04c
#define QSERDES_COM_LOCK_CMP2_MODE0			0x050
#define QSERDES_COM_LOCK_CMP3_MODE0			0x054
#define QSERDES_COM_LOCK_CMP1_MODE1			0x058
#define QSERDES_COM_LOCK_CMP2_MODE1			0x05c
#define QSERDES_COM_LOCK_CMP3_MODE1			0x060
#define QSERDES_COM_LOCK_CMP1_MODE2			0x064
#define QSERDES_COM_CMN_RSVD0				0x064
#define QSERDES_COM_LOCK_CMP2_MODE2			0x068
#define QSERDES_COM_EP_CLOCK_DETECT_CTRL		0x068
#define QSERDES_COM_LOCK_CMP3_MODE2			0x06c
#define QSERDES_COM_SYSCLK_DET_COMP_STATUS		0x06c
#define QSERDES_COM_BG_TRIM				0x070
#define QSERDES_COM_CLK_EP_DIV				0x074
#define QSERDES_COM_CP_CTRL_MODE0			0x078
#define QSERDES_COM_CP_CTRL_MODE1			0x07c
#define QSERDES_COM_CP_CTRL_MODE2			0x080
#define QSERDES_COM_CMN_RSVD1				0x080
#define QSERDES_COM_PLL_RCTRL_MODE0			0x084
#define QSERDES_COM_PLL_RCTRL_MODE1			0x088
#define QSERDES_COM_PLL_RCTRL_MODE2			0x08c
#define QSERDES_COM_CMN_RSVD2				0x08c
#define QSERDES_COM_PLL_CCTRL_MODE0			0x090
#define QSERDES_COM_PLL_CCTRL_MODE1			0x094
#define QSERDES_COM_PLL_CCTRL_MODE2			0x098
#define QSERDES_COM_CMN_RSVD3				0x098
#define QSERDES_COM_PLL_CNTRL				0x09c
#define QSERDES_COM_PHASE_SEL_CTRL			0x0a0
#define QSERDES_COM_PHASE_SEL_DC			0x0a4
#define QSERDES_COM_CORE_CLK_IN_SYNC_SEL		0x0a8
#define QSERDES_COM_BIAS_EN_CTRL_BY_PSM			0x0a8
#define QSERDES_COM_SYSCLK_EN_SEL			0x0ac
#define QSERDES_COM_CML_SYSCLK_SEL			0x0b0
#define QSERDES_COM_RESETSM_CNTRL			0x0b4
#define QSERDES_COM_RESETSM_CNTRL2			0x0b8
#define QSERDES_COM_RESTRIM_CTRL			0x0bc
#define QSERDES_COM_RESTRIM_CTRL2			0x0c0
#define QSERDES_COM_RESCODE_DIV_NUM			0x0c4
#define QSERDES_COM_LOCK_CMP_EN				0x0c8
#define QSERDES_COM_LOCK_CMP_CFG			0x0cc
#define QSERDES_COM_DEC_START_MODE0			0x0d0
#define QSERDES_COM_DEC_START_MODE1			0x0d4
#define QSERDES_COM_DEC_START_MODE2			0x0d8
#define QSERDES_COM_VCOCAL_DEADMAN_CTRL			0x0d8
#define QSERDES_COM_DIV_FRAC_START1_MODE0		0x0dc
#define QSERDES_COM_DIV_FRAC_START2_MODE0		0x0e0
#define QSERDES_COM_DIV_FRAC_START3_MODE0		0x0e4
#define QSERDES_COM_DIV_FRAC_START1_MODE1		0x0e8
#define QSERDES_COM_DIV_FRAC_START2_MODE1		0x0ec
#define QSERDES_COM_DIV_FRAC_START3_MODE1		0x0f0
#define QSERDES_COM_DIV_FRAC_START1_MODE2		0x0f4
#define QSERDES_COM_VCO_TUNE_MINVAL1			0x0f4
#define QSERDES_COM_DIV_FRAC_START2_MODE2		0x0f8
#define QSERDES_COM_VCO_TUNE_MINVAL2			0x0f8
#define QSERDES_COM_DIV_FRAC_START3_MODE2		0x0fc
#define QSERDES_COM_CMN_RSVD4				0x0fc
#define QSERDES_COM_INTEGLOOP_INITVAL			0x100
#define QSERDES_COM_INTEGLOOP_EN			0x104
#define QSERDES_COM_INTEGLOOP_GAIN0_MODE0		0x108
#define QSERDES_COM_INTEGLOOP_GAIN1_MODE0		0x10c
#define QSERDES_COM_INTEGLOOP_GAIN0_MODE1		0x110
#define QSERDES_COM_INTEGLOOP_GAIN1_MODE1		0x114
#define QSERDES_COM_INTEGLOOP_GAIN0_MODE2		0x118
#define QSERDES_COM_VCO_TUNE_MAXVAL1			0x118
#define QSERDES_COM_INTEGLOOP_GAIN1_MODE2		0x11c
#define QSERDES_COM_VCO_TUNE_MAXVAL2			0x11c
#define QSERDES_COM_RES_TRIM_CONTROL2			0x120
#define QSERDES_COM_VCO_TUNE_CTRL			0x124
#define QSERDES_COM_VCO_TUNE_MAP			0x128
#define QSERDES_COM_VCO_TUNE1_MODE0			0x12c
#define QSERDES_COM_VCO_TUNE2_MODE0			0x130
#define QSERDES_COM_VCO_TUNE1_MODE1			0x134
#define QSERDES_COM_VCO_TUNE2_MODE1			0x138
#define QSERDES_COM_VCO_TUNE1_MODE2			0x13c
#define QSERDES_COM_VCO_TUNE_INITVAL1			0x13c
#define QSERDES_COM_VCO_TUNE2_MODE2			0x140
#define QSERDES_COM_VCO_TUNE_INITVAL2			0x140
#define QSERDES_COM_VCO_TUNE_TIMER1			0x144
#define QSERDES_COM_VCO_TUNE_TIMER2			0x148
#define QSERDES_COM_SAR					0x14c
#define QSERDES_COM_SAR_CLK				0x150
#define QSERDES_COM_SAR_CODE_OUT_STATUS			0x154
#define QSERDES_COM_SAR_CODE_READY_STATUS		0x158
#define QSERDES_COM_CMN_STATUS				0x15c
#define QSERDES_COM_RESET_SM_STATUS			0x160
#define QSERDES_COM_RESTRIM_CODE_STATUS			0x164
#define QSERDES_COM_PLLCAL_CODE1_STATUS			0x168
#define QSERDES_COM_PLLCAL_CODE2_STATUS			0x16c
#define QSERDES_COM_BG_CTRL				0x170
#define QSERDES_COM_CLK_SELECT				0x174
#define QSERDES_COM_HSCLK_SEL				0x178
#define QSERDES_COM_INTEGLOOP_BINCODE_STATUS		0x17c
#define QSERDES_COM_PLL_ANALOG				0x180
#define QSERDES_COM_CORECLK_DIV				0x184
#define QSERDES_COM_SW_RESET				0x188
#define QSERDES_COM_CORE_CLK_EN				0x18c
#define QSERDES_COM_C_READY_STATUS			0x190
#define QSERDES_COM_CMN_CONFIG				0x194
#define QSERDES_COM_CMN_RATE_OVERRIDE			0x198
#define QSERDES_COM_SVS_MODE_CLK_SEL			0x19c
#define QSERDES_COM_DEBUG_BUS0				0x1a0
#define QSERDES_COM_DEBUG_BUS1				0x1a4
#define QSERDES_COM_DEBUG_BUS2				0x1a8
#define QSERDES_COM_DEBUG_BUS3				0x1ac
#define QSERDES_COM_DEBUG_BUS_SEL			0x1b0
#define QSERDES_COM_CMN_MISC1				0x1b4
#define QSERDES_COM_CMN_MISC2				0x1b8
#define QSERDES_COM_CORECLK_DIV_MODE1			0x1bc
#define QSERDES_COM_CORECLK_DIV_MODE2			0x1c0
#define QSERDES_COM_CMN_RSVD5				0x1c4

#endif
