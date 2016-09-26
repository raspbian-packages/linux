/*
 * Realtek RTL2832 DVB-T demodulator driver
 *
 * Copyright (C) 2012 Thomas Mair <thomas.mair86@gmail.com>
 * Copyright (C) 2012-2014 Antti Palosaari <crope@iki.fi>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef RTL2832_PRIV_H
#define RTL2832_PRIV_H

#include <linux/regmap.h>
#include <linux/math64.h>
#include <linux/bitops.h>

#include "dvb_frontend.h"
#include "dvb_math.h"
#include "rtl2832.h"

struct rtl2832_dev {
	struct rtl2832_platform_data *pdata;
	struct i2c_client *client;
	struct regmap_config regmap_config;
	struct regmap *regmap;
	struct i2c_mux_core *muxc;
	struct dvb_frontend fe;
	enum fe_status fe_status;
	u64 post_bit_error_prev; /* for old DVBv3 read_ber() calculation */
	u64 post_bit_error;
	u64 post_bit_count;
	bool sleeping;
	struct delayed_work i2c_gate_work;
	unsigned long filters; /* PID filter */
};

struct rtl2832_reg_entry {
	u16 start_address;
	u8 msb;
	u8 lsb;
};

struct rtl2832_reg_value {
	int reg;
	u32 value;
};

/* Demod register bit names */
enum DVBT_REG_BIT_NAME {
	DVBT_SOFT_RST,
	DVBT_IIC_REPEAT,
	DVBT_TR_WAIT_MIN_8K,
	DVBT_RSD_BER_FAIL_VAL,
	DVBT_EN_BK_TRK,
	DVBT_REG_PI,
	DVBT_REG_PFREQ_1_0,
	DVBT_PD_DA8,
	DVBT_LOCK_TH,
	DVBT_BER_PASS_SCAL,
	DVBT_CE_FFSM_BYPASS,
	DVBT_ALPHAIIR_N,
	DVBT_ALPHAIIR_DIF,
	DVBT_EN_TRK_SPAN,
	DVBT_LOCK_TH_LEN,
	DVBT_CCI_THRE,
	DVBT_CCI_MON_SCAL,
	DVBT_CCI_M0,
	DVBT_CCI_M1,
	DVBT_CCI_M2,
	DVBT_CCI_M3,
	DVBT_SPEC_INIT_0,
	DVBT_SPEC_INIT_1,
	DVBT_SPEC_INIT_2,
	DVBT_AD_EN_REG,
	DVBT_AD_EN_REG1,
	DVBT_EN_BBIN,
	DVBT_MGD_THD0,
	DVBT_MGD_THD1,
	DVBT_MGD_THD2,
	DVBT_MGD_THD3,
	DVBT_MGD_THD4,
	DVBT_MGD_THD5,
	DVBT_MGD_THD6,
	DVBT_MGD_THD7,
	DVBT_EN_CACQ_NOTCH,
	DVBT_AD_AV_REF,
	DVBT_PIP_ON,
	DVBT_SCALE1_B92,
	DVBT_SCALE1_B93,
	DVBT_SCALE1_BA7,
	DVBT_SCALE1_BA9,
	DVBT_SCALE1_BAA,
	DVBT_SCALE1_BAB,
	DVBT_SCALE1_BAC,
	DVBT_SCALE1_BB0,
	DVBT_SCALE1_BB1,
	DVBT_KB_P1,
	DVBT_KB_P2,
	DVBT_KB_P3,
	DVBT_OPT_ADC_IQ,
	DVBT_AD_AVI,
	DVBT_AD_AVQ,
	DVBT_K1_CR_STEP12,
	DVBT_TRK_KS_P2,
	DVBT_TRK_KS_I2,
	DVBT_TR_THD_SET2,
	DVBT_TRK_KC_P2,
	DVBT_TRK_KC_I2,
	DVBT_CR_THD_SET2,
	DVBT_PSET_IFFREQ,
	DVBT_SPEC_INV,
	DVBT_BW_INDEX,
	DVBT_RSAMP_RATIO,
	DVBT_CFREQ_OFF_RATIO,
	DVBT_FSM_STAGE,
	DVBT_RX_CONSTEL,
	DVBT_RX_HIER,
	DVBT_RX_C_RATE_LP,
	DVBT_RX_C_RATE_HP,
	DVBT_GI_IDX,
	DVBT_FFT_MODE_IDX,
	DVBT_RSD_BER_EST,
	DVBT_CE_EST_EVM,
	DVBT_RF_AGC_VAL,
	DVBT_IF_AGC_VAL,
	DVBT_DAGC_VAL,
	DVBT_SFREQ_OFF,
	DVBT_CFREQ_OFF,
	DVBT_POLAR_RF_AGC,
	DVBT_POLAR_IF_AGC,
	DVBT_AAGC_HOLD,
	DVBT_EN_RF_AGC,
	DVBT_EN_IF_AGC,
	DVBT_IF_AGC_MIN,
	DVBT_IF_AGC_MAX,
	DVBT_RF_AGC_MIN,
	DVBT_RF_AGC_MAX,
	DVBT_IF_AGC_MAN,
	DVBT_IF_AGC_MAN_VAL,
	DVBT_RF_AGC_MAN,
	DVBT_RF_AGC_MAN_VAL,
	DVBT_DAGC_TRG_VAL,
	DVBT_AGC_TARG_VAL,
	DVBT_LOOP_GAIN_3_0,
	DVBT_LOOP_GAIN_4,
	DVBT_VTOP,
	DVBT_KRF,
	DVBT_AGC_TARG_VAL_0,
	DVBT_AGC_TARG_VAL_8_1,
	DVBT_AAGC_LOOP_GAIN,
	DVBT_LOOP_GAIN2_3_0,
	DVBT_LOOP_GAIN2_4,
	DVBT_LOOP_GAIN3,
	DVBT_VTOP1,
	DVBT_VTOP2,
	DVBT_VTOP3,
	DVBT_KRF1,
	DVBT_KRF2,
	DVBT_KRF3,
	DVBT_KRF4,
	DVBT_EN_GI_PGA,
	DVBT_THD_LOCK_UP,
	DVBT_THD_LOCK_DW,
	DVBT_THD_UP1,
	DVBT_THD_DW1,
	DVBT_INTER_CNT_LEN,
	DVBT_GI_PGA_STATE,
	DVBT_EN_AGC_PGA,
	DVBT_CKOUTPAR,
	DVBT_CKOUT_PWR,
	DVBT_SYNC_DUR,
	DVBT_ERR_DUR,
	DVBT_SYNC_LVL,
	DVBT_ERR_LVL,
	DVBT_VAL_LVL,
	DVBT_SERIAL,
	DVBT_SER_LSB,
	DVBT_CDIV_PH0,
	DVBT_CDIV_PH1,
	DVBT_MPEG_IO_OPT_2_2,
	DVBT_MPEG_IO_OPT_1_0,
	DVBT_CKOUTPAR_PIP,
	DVBT_CKOUT_PWR_PIP,
	DVBT_SYNC_LVL_PIP,
	DVBT_ERR_LVL_PIP,
	DVBT_VAL_LVL_PIP,
	DVBT_CKOUTPAR_PID,
	DVBT_CKOUT_PWR_PID,
	DVBT_SYNC_LVL_PID,
	DVBT_ERR_LVL_PID,
	DVBT_VAL_LVL_PID,
	DVBT_SM_PASS,
	DVBT_UPDATE_REG_2,
	DVBT_BTHD_P3,
	DVBT_BTHD_D3,
	DVBT_FUNC4_REG0,
	DVBT_FUNC4_REG1,
	DVBT_FUNC4_REG2,
	DVBT_FUNC4_REG3,
	DVBT_FUNC4_REG4,
	DVBT_FUNC4_REG5,
	DVBT_FUNC4_REG6,
	DVBT_FUNC4_REG7,
	DVBT_FUNC4_REG8,
	DVBT_FUNC4_REG9,
	DVBT_FUNC4_REG10,
	DVBT_FUNC5_REG0,
	DVBT_FUNC5_REG1,
	DVBT_FUNC5_REG2,
	DVBT_FUNC5_REG3,
	DVBT_FUNC5_REG4,
	DVBT_FUNC5_REG5,
	DVBT_FUNC5_REG6,
	DVBT_FUNC5_REG7,
	DVBT_FUNC5_REG8,
	DVBT_FUNC5_REG9,
	DVBT_FUNC5_REG10,
	DVBT_FUNC5_REG11,
	DVBT_FUNC5_REG12,
	DVBT_FUNC5_REG13,
	DVBT_FUNC5_REG14,
	DVBT_FUNC5_REG15,
	DVBT_FUNC5_REG16,
	DVBT_FUNC5_REG17,
	DVBT_FUNC5_REG18,
	DVBT_AD7_SETTING,
	DVBT_RSSI_R,
	DVBT_ACI_DET_IND,
	DVBT_REG_MON,
	DVBT_REG_MONSEL,
	DVBT_REG_GPE,
	DVBT_REG_GPO,
	DVBT_REG_4MSEL,
	DVBT_TEST_REG_1,
	DVBT_TEST_REG_2,
	DVBT_TEST_REG_3,
	DVBT_TEST_REG_4,
	DVBT_REG_BIT_NAME_ITEM_TERMINATOR,
};

static const struct rtl2832_reg_value rtl2832_tuner_init_fc2580[] = {
	{DVBT_DAGC_TRG_VAL,             0x39},
	{DVBT_AGC_TARG_VAL_0,            0x0},
	{DVBT_AGC_TARG_VAL_8_1,         0x5a},
	{DVBT_AAGC_LOOP_GAIN,           0x16},
	{DVBT_LOOP_GAIN2_3_0,            0x6},
	{DVBT_LOOP_GAIN2_4,              0x1},
	{DVBT_LOOP_GAIN3,               0x16},
	{DVBT_VTOP1,                    0x35},
	{DVBT_VTOP2,                    0x21},
	{DVBT_VTOP3,                    0x21},
	{DVBT_KRF1,                      0x0},
	{DVBT_KRF2,                     0x40},
	{DVBT_KRF3,                     0x10},
	{DVBT_KRF4,                     0x10},
	{DVBT_IF_AGC_MIN,               0x80},
	{DVBT_IF_AGC_MAX,               0x7f},
	{DVBT_RF_AGC_MIN,               0x9c},
	{DVBT_RF_AGC_MAX,               0x7f},
	{DVBT_POLAR_RF_AGC,              0x0},
	{DVBT_POLAR_IF_AGC,              0x0},
	{DVBT_AD7_SETTING,            0xe9f4},
};

static const struct rtl2832_reg_value rtl2832_tuner_init_tua9001[] = {
	{DVBT_DAGC_TRG_VAL,             0x39},
	{DVBT_AGC_TARG_VAL_0,            0x0},
	{DVBT_AGC_TARG_VAL_8_1,         0x5a},
	{DVBT_AAGC_LOOP_GAIN,           0x16},
	{DVBT_LOOP_GAIN2_3_0,            0x6},
	{DVBT_LOOP_GAIN2_4,              0x1},
	{DVBT_LOOP_GAIN3,               0x16},
	{DVBT_VTOP1,                    0x35},
	{DVBT_VTOP2,                    0x21},
	{DVBT_VTOP3,                    0x21},
	{DVBT_KRF1,                      0x0},
	{DVBT_KRF2,                     0x40},
	{DVBT_KRF3,                     0x10},
	{DVBT_KRF4,                     0x10},
	{DVBT_IF_AGC_MIN,               0x80},
	{DVBT_IF_AGC_MAX,               0x7f},
	{DVBT_RF_AGC_MIN,               0x9c},
	{DVBT_RF_AGC_MAX,               0x7f},
	{DVBT_POLAR_RF_AGC,              0x0},
	{DVBT_POLAR_IF_AGC,              0x0},
	{DVBT_AD7_SETTING,            0xe9f4},
	{DVBT_OPT_ADC_IQ,                0x1},
	{DVBT_AD_AVI,                    0x0},
	{DVBT_AD_AVQ,                    0x0},
	{DVBT_SPEC_INV,                  0x0},
};

static const struct rtl2832_reg_value rtl2832_tuner_init_fc0012[] = {
	{DVBT_DAGC_TRG_VAL,             0x5a},
	{DVBT_AGC_TARG_VAL_0,            0x0},
	{DVBT_AGC_TARG_VAL_8_1,         0x5a},
	{DVBT_AAGC_LOOP_GAIN,           0x16},
	{DVBT_LOOP_GAIN2_3_0,            0x6},
	{DVBT_LOOP_GAIN2_4,              0x1},
	{DVBT_LOOP_GAIN3,               0x16},
	{DVBT_VTOP1,                    0x35},
	{DVBT_VTOP2,                    0x21},
	{DVBT_VTOP3,                    0x21},
	{DVBT_KRF1,                      0x0},
	{DVBT_KRF2,                     0x40},
	{DVBT_KRF3,                     0x10},
	{DVBT_KRF4,                     0x10},
	{DVBT_IF_AGC_MIN,               0x80},
	{DVBT_IF_AGC_MAX,               0x7f},
	{DVBT_RF_AGC_MIN,               0x80},
	{DVBT_RF_AGC_MAX,               0x7f},
	{DVBT_POLAR_RF_AGC,              0x0},
	{DVBT_POLAR_IF_AGC,              0x0},
	{DVBT_AD7_SETTING,            0xe9bf},
	{DVBT_EN_GI_PGA,                 0x0},
	{DVBT_THD_LOCK_UP,               0x0},
	{DVBT_THD_LOCK_DW,               0x0},
	{DVBT_THD_UP1,                  0x11},
	{DVBT_THD_DW1,                  0xef},
	{DVBT_INTER_CNT_LEN,             0xc},
	{DVBT_GI_PGA_STATE,              0x0},
	{DVBT_EN_AGC_PGA,                0x1},
	{DVBT_IF_AGC_MAN,                0x0},
	{DVBT_SPEC_INV,                  0x0},
};

static const struct rtl2832_reg_value rtl2832_tuner_init_e4000[] = {
	{DVBT_DAGC_TRG_VAL,             0x5a},
	{DVBT_AGC_TARG_VAL_0,            0x0},
	{DVBT_AGC_TARG_VAL_8_1,         0x5a},
	{DVBT_AAGC_LOOP_GAIN,           0x18},
	{DVBT_LOOP_GAIN2_3_0,            0x8},
	{DVBT_LOOP_GAIN2_4,              0x1},
	{DVBT_LOOP_GAIN3,               0x18},
	{DVBT_VTOP1,                    0x35},
	{DVBT_VTOP2,                    0x21},
	{DVBT_VTOP3,                    0x21},
	{DVBT_KRF1,                      0x0},
	{DVBT_KRF2,                     0x40},
	{DVBT_KRF3,                     0x10},
	{DVBT_KRF4,                     0x10},
	{DVBT_IF_AGC_MIN,               0x80},
	{DVBT_IF_AGC_MAX,               0x7f},
	{DVBT_RF_AGC_MIN,               0x80},
	{DVBT_RF_AGC_MAX,               0x7f},
	{DVBT_POLAR_RF_AGC,              0x0},
	{DVBT_POLAR_IF_AGC,              0x0},
	{DVBT_AD7_SETTING,            0xe9d4},
	{DVBT_EN_GI_PGA,                 0x0},
	{DVBT_THD_LOCK_UP,               0x0},
	{DVBT_THD_LOCK_DW,               0x0},
	{DVBT_THD_UP1,                  0x14},
	{DVBT_THD_DW1,                  0xec},
	{DVBT_INTER_CNT_LEN,             0xc},
	{DVBT_GI_PGA_STATE,              0x0},
	{DVBT_EN_AGC_PGA,                0x1},
	{DVBT_REG_GPE,                   0x1},
	{DVBT_REG_GPO,                   0x1},
	{DVBT_REG_MONSEL,                0x1},
	{DVBT_REG_MON,                   0x1},
	{DVBT_REG_4MSEL,                 0x0},
	{DVBT_SPEC_INV,                  0x0},
};

static const struct rtl2832_reg_value rtl2832_tuner_init_r820t[] = {
	{DVBT_DAGC_TRG_VAL,             0x39},
	{DVBT_AGC_TARG_VAL_0,            0x0},
	{DVBT_AGC_TARG_VAL_8_1,         0x40},
	{DVBT_AAGC_LOOP_GAIN,           0x16},
	{DVBT_LOOP_GAIN2_3_0,            0x8},
	{DVBT_LOOP_GAIN2_4,              0x1},
	{DVBT_LOOP_GAIN3,               0x18},
	{DVBT_VTOP1,                    0x35},
	{DVBT_VTOP2,                    0x21},
	{DVBT_VTOP3,                    0x21},
	{DVBT_KRF1,                      0x0},
	{DVBT_KRF2,                     0x40},
	{DVBT_KRF3,                     0x10},
	{DVBT_KRF4,                     0x10},
	{DVBT_IF_AGC_MIN,               0x80},
	{DVBT_IF_AGC_MAX,               0x7f},
	{DVBT_RF_AGC_MIN,               0x80},
	{DVBT_RF_AGC_MAX,               0x7f},
	{DVBT_POLAR_RF_AGC,              0x0},
	{DVBT_POLAR_IF_AGC,              0x0},
	{DVBT_AD7_SETTING,            0xe9f4},
	{DVBT_SPEC_INV,                  0x1},
};

static const struct rtl2832_reg_value rtl2832_tuner_init_si2157[] = {
	{DVBT_DAGC_TRG_VAL,             0x39},
	{DVBT_AGC_TARG_VAL_0,            0x0},
	{DVBT_AGC_TARG_VAL_8_1,         0x40},
	{DVBT_AAGC_LOOP_GAIN,           0x16},
	{DVBT_LOOP_GAIN2_3_0,            0x8},
	{DVBT_LOOP_GAIN2_4,              0x1},
	{DVBT_LOOP_GAIN3,               0x18},
	{DVBT_VTOP1,                    0x35},
	{DVBT_VTOP2,                    0x21},
	{DVBT_VTOP3,                    0x21},
	{DVBT_KRF1,                      0x0},
	{DVBT_KRF2,                     0x40},
	{DVBT_KRF3,                     0x10},
	{DVBT_KRF4,                     0x10},
	{DVBT_IF_AGC_MIN,               0x80},
	{DVBT_IF_AGC_MAX,               0x7f},
	{DVBT_RF_AGC_MIN,               0x80},
	{DVBT_RF_AGC_MAX,               0x7f},
	{DVBT_POLAR_RF_AGC,              0x0},
	{DVBT_POLAR_IF_AGC,              0x0},
	{DVBT_AD7_SETTING,            0xe9f4},
	{DVBT_SPEC_INV,                  0x0},
};

#endif /* RTL2832_PRIV_H */
