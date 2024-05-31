/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
 */

#ifndef QCOM_PHY_QMP_PCS_V3_H_
#define QCOM_PHY_QMP_PCS_V3_H_

/* Only for QMP V3 PHY - PCS registers */
#define QPHY_V3_PCS_SW_RESET				0x000
#define QPHY_V3_PCS_POWER_DOWN_CONTROL			0x004
#define QPHY_V3_PCS_START_CONTROL			0x008
#define QPHY_V3_PCS_TXMGN_V0				0x00c
#define QPHY_V3_PCS_TXMGN_V1				0x010
#define QPHY_V3_PCS_TXMGN_V2				0x014
#define QPHY_V3_PCS_TXMGN_V3				0x018
#define QPHY_V3_PCS_TXMGN_V4				0x01c
#define QPHY_V3_PCS_TXMGN_LS				0x020
#define QPHY_V3_PCS_TXDEEMPH_M6DB_V0			0x024
#define QPHY_V3_PCS_TXDEEMPH_M3P5DB_V0			0x028
#define QPHY_V3_PCS_TXDEEMPH_M6DB_V1			0x02c
#define QPHY_V3_PCS_TXDEEMPH_M3P5DB_V1			0x030
#define QPHY_V3_PCS_TXDEEMPH_M6DB_V2			0x034
#define QPHY_V3_PCS_TXDEEMPH_M3P5DB_V2			0x038
#define QPHY_V3_PCS_TXDEEMPH_M6DB_V3			0x03c
#define QPHY_V3_PCS_TXDEEMPH_M3P5DB_V3			0x040
#define QPHY_V3_PCS_TXDEEMPH_M6DB_V4			0x044
#define QPHY_V3_PCS_TXDEEMPH_M3P5DB_V4			0x048
#define QPHY_V3_PCS_TXDEEMPH_M6DB_LS			0x04c
#define QPHY_V3_PCS_TXDEEMPH_M3P5DB_LS			0x050
#define QPHY_V3_PCS_ENDPOINT_REFCLK_DRIVE		0x054
#define QPHY_V3_PCS_RX_IDLE_DTCT_CNTRL			0x058
#define QPHY_V3_PCS_RATE_SLEW_CNTRL			0x05c
#define QPHY_V3_PCS_POWER_STATE_CONFIG1			0x060
#define QPHY_V3_PCS_POWER_STATE_CONFIG2			0x064
#define QPHY_V3_PCS_POWER_STATE_CONFIG3			0x068
#define QPHY_V3_PCS_POWER_STATE_CONFIG4			0x06c
#define QPHY_V3_PCS_RCVR_DTCT_DLY_P1U2_L		0x070
#define QPHY_V3_PCS_RCVR_DTCT_DLY_P1U2_H		0x074
#define QPHY_V3_PCS_RCVR_DTCT_DLY_U3_L			0x078
#define QPHY_V3_PCS_RCVR_DTCT_DLY_U3_H			0x07c
#define QPHY_V3_PCS_LOCK_DETECT_CONFIG1			0x080
#define QPHY_V3_PCS_LOCK_DETECT_CONFIG2			0x084
#define QPHY_V3_PCS_LOCK_DETECT_CONFIG3			0x088
#define QPHY_V3_PCS_TSYNC_RSYNC_TIME			0x08c
#define QPHY_V3_PCS_SIGDET_LOW_2_IDLE_TIME		0x090
#define QPHY_V3_PCS_BEACON_2_IDLE_TIME_L		0x094
#define QPHY_V3_PCS_BEACON_2_IDLE_TIME_H		0x098
#define QPHY_V3_PCS_PWRUP_RESET_DLY_TIME_SYSCLK		0x09c
#define QPHY_V3_PCS_PWRUP_RESET_DLY_TIME_AUXCLK		0x0a0
#define QPHY_V3_PCS_LP_WAKEUP_DLY_TIME_AUXCLK		0x0a4
#define QPHY_V3_PCS_PLL_LOCK_CHK_DLY_TIME		0x0a8
#define QPHY_V3_PCS_LFPS_DET_HIGH_COUNT_VAL		0x0ac
#define QPHY_V3_PCS_LFPS_TX_ECSTART_EQTLOCK		0x0b0
#define QPHY_V3_PCS_LFPS_TX_END_CNT_P2U3_START		0x0b4
#define QPHY_V3_PCS_RXEQTRAINING_WAIT_TIME		0x0b8
#define QPHY_V3_PCS_RXEQTRAINING_RUN_TIME		0x0bc
#define QPHY_V3_PCS_TXONESZEROS_RUN_LENGTH		0x0c0
#define QPHY_V3_PCS_FLL_CNTRL1				0x0c4
#define QPHY_V3_PCS_FLL_CNTRL2				0x0c8
#define QPHY_V3_PCS_FLL_CNT_VAL_L			0x0cc
#define QPHY_V3_PCS_FLL_CNT_VAL_H_TOL			0x0d0
#define QPHY_V3_PCS_FLL_MAN_CODE			0x0d4
#define QPHY_V3_PCS_AUTONOMOUS_MODE_CTRL		0x0d8
#define QPHY_V3_PCS_LFPS_RXTERM_IRQ_CLEAR		0x0dc
#define QPHY_V3_PCS_ARCVR_DTCT_EN_PERIOD		0x0e0
#define QPHY_V3_PCS_ARCVR_DTCT_CM_DLY			0x0e4
#define QPHY_V3_PCS_ALFPS_DEGLITCH_VAL			0x0e8
#define QPHY_V3_PCS_INSIG_SW_CTRL1			0x0ec
#define QPHY_V3_PCS_INSIG_SW_CTRL2			0x0f0
#define QPHY_V3_PCS_INSIG_SW_CTRL3			0x0f4
#define QPHY_V3_PCS_INSIG_MX_CTRL1			0x0f8
#define QPHY_V3_PCS_INSIG_MX_CTRL2			0x0fc
#define QPHY_V3_PCS_INSIG_MX_CTRL3			0x100
#define QPHY_V3_PCS_OUTSIG_SW_CTRL1			0x104
#define QPHY_V3_PCS_OUTSIG_MX_CTRL1			0x108
#define QPHY_V3_PCS_CLK_DEBUG_BYPASS_CTRL		0x10c
#define QPHY_V3_PCS_TEST_CONTROL			0x110
#define QPHY_V3_PCS_TEST_CONTROL2			0x114
#define QPHY_V3_PCS_TEST_CONTROL3			0x118
#define QPHY_V3_PCS_TEST_CONTROL4			0x11c
#define QPHY_V3_PCS_TEST_CONTROL5			0x120
#define QPHY_V3_PCS_TEST_CONTROL6			0x124
#define QPHY_V3_PCS_TEST_CONTROL7			0x128
#define QPHY_V3_PCS_COM_RESET_CONTROL			0x12c
#define QPHY_V3_PCS_BIST_CTRL				0x130
#define QPHY_V3_PCS_PRBS_POLY0				0x134
#define QPHY_V3_PCS_PRBS_POLY1				0x138
#define QPHY_V3_PCS_PRBS_SEED0				0x13c
#define QPHY_V3_PCS_PRBS_SEED1				0x140
#define QPHY_V3_PCS_FIXED_PAT_CTRL			0x144
#define QPHY_V3_PCS_FIXED_PAT0				0x148
#define QPHY_V3_PCS_FIXED_PAT1				0x14c
#define QPHY_V3_PCS_FIXED_PAT2				0x150
#define QPHY_V3_PCS_FIXED_PAT3				0x154
#define QPHY_V3_PCS_COM_CLK_SWITCH_CTRL			0x158
#define QPHY_V3_PCS_ELECIDLE_DLY_SEL			0x15c
#define QPHY_V3_PCS_SPARE1				0x160
#define QPHY_V3_PCS_BIST_CHK_ERR_CNT_L_STATUS		0x164
#define QPHY_V3_PCS_BIST_CHK_ERR_CNT_H_STATUS		0x168
#define QPHY_V3_PCS_BIST_CHK_STATUS			0x16c
#define QPHY_V3_PCS_LFPS_RXTERM_IRQ_SOURCE_STATUS	0x170
#define QPHY_V3_PCS_PCS_STATUS				0x174
#define QPHY_V3_PCS_PCS_STATUS2				0x178
#define QPHY_V3_PCS_PCS_STATUS3				0x17c
#define QPHY_V3_PCS_COM_RESET_STATUS			0x180
#define QPHY_V3_PCS_OSC_DTCT_STATUS			0x184
#define QPHY_V3_PCS_REVISION_ID0			0x188
#define QPHY_V3_PCS_REVISION_ID1			0x18c
#define QPHY_V3_PCS_REVISION_ID2			0x190
#define QPHY_V3_PCS_REVISION_ID3			0x194
#define QPHY_V3_PCS_DEBUG_BUS_0_STATUS			0x198
#define QPHY_V3_PCS_DEBUG_BUS_1_STATUS			0x19c
#define QPHY_V3_PCS_DEBUG_BUS_2_STATUS			0x1a0
#define QPHY_V3_PCS_DEBUG_BUS_3_STATUS			0x1a4
#define QPHY_V3_PCS_LP_WAKEUP_DLY_TIME_AUXCLK_MSB	0x1a8
#define QPHY_V3_PCS_OSC_DTCT_ACTIONS			0x1ac
#define QPHY_V3_PCS_SIGDET_CNTRL			0x1b0
#define QPHY_V3_PCS_IDAC_CAL_CNTRL			0x1b4
#define QPHY_V3_PCS_CMN_ACK_OUT_SEL			0x1b8
#define QPHY_V3_PCS_PLL_LOCK_CHK_DLY_TIME_SYSCLK	0x1bc
#define QPHY_V3_PCS_AUTONOMOUS_MODE_STATUS		0x1c0
#define QPHY_V3_PCS_ENDPOINT_REFCLK_CNTRL		0x1c4
#define QPHY_V3_PCS_EPCLK_PRE_PLL_LOCK_DLY_SYSCLK	0x1c8
#define QPHY_V3_PCS_EPCLK_PRE_PLL_LOCK_DLY_AUXCLK	0x1cc
#define QPHY_V3_PCS_EPCLK_DLY_COUNT_VAL_L		0x1d0
#define QPHY_V3_PCS_EPCLK_DLY_COUNT_VAL_H		0x1d4
#define QPHY_V3_PCS_RX_SIGDET_LVL			0x1d8
#define QPHY_V3_PCS_L1SS_WAKEUP_DLY_TIME_AUXCLK_LSB	0x1dc
#define QPHY_V3_PCS_L1SS_WAKEUP_DLY_TIME_AUXCLK_MSB	0x1e0
#define QPHY_V3_PCS_AUTONOMOUS_MODE_CTRL2		0x1e4
#define QPHY_V3_PCS_RXTERMINATION_DLY_SEL		0x1e8
#define QPHY_V3_PCS_LFPS_PER_TIMER_VAL			0x1ec
#define QPHY_V3_PCS_SIGDET_STARTUP_TIMER_VAL		0x1f0
#define QPHY_V3_PCS_LOCK_DETECT_CONFIG4			0x1f4
#define QPHY_V3_PCS_RX_SIGDET_DTCT_CNTRL		0x1f8
#define QPHY_V3_PCS_PCS_STATUS4				0x1fc
#define QPHY_V3_PCS_PCS_STATUS4_CLEAR			0x200
#define QPHY_V3_PCS_DEC_ERROR_COUNT_STATUS		0x204
#define QPHY_V3_PCS_COMMA_POS_STATUS			0x208
#define QPHY_V3_PCS_REFGEN_REQ_CONFIG1			0x20c
#define QPHY_V3_PCS_REFGEN_REQ_CONFIG2			0x210
#define QPHY_V3_PCS_REFGEN_REQ_CONFIG3			0x214

#endif
