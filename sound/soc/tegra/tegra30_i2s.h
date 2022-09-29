/*
 * tegra30_i2s.h - Definitions for Tegra30 I2S driver
 *
 * Copyright (c) 2011,2012, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __TEGRA30_I2S_H__
#define __TEGRA30_I2S_H__

#include "tegra_pcm.h"

/* Register offsets from TEGRA30_I2S*_BASE */

#define TEGRA30_I2S_CTRL				0x0
#define TEGRA30_I2S_TIMING				0x4
#define TEGRA30_I2S_OFFSET				0x08
#define TEGRA30_I2S_CH_CTRL				0x0c
#define TEGRA30_I2S_SLOT_CTRL				0x10
#define TEGRA30_I2S_CIF_RX_CTRL				0x14
#define TEGRA30_I2S_CIF_TX_CTRL				0x18
#define TEGRA30_I2S_FLOWCTL				0x1c
#define TEGRA30_I2S_TX_STEP				0x20
#define TEGRA30_I2S_FLOW_STATUS				0x24
#define TEGRA30_I2S_FLOW_TOTAL				0x28
#define TEGRA30_I2S_FLOW_OVER				0x2c
#define TEGRA30_I2S_FLOW_UNDER				0x30
#define TEGRA30_I2S_LCOEF_1_4_0				0x34
#define TEGRA30_I2S_LCOEF_1_4_1				0x38
#define TEGRA30_I2S_LCOEF_1_4_2				0x3c
#define TEGRA30_I2S_LCOEF_1_4_3				0x40
#define TEGRA30_I2S_LCOEF_1_4_4				0x44
#define TEGRA30_I2S_LCOEF_1_4_5				0x48
#define TEGRA30_I2S_LCOEF_2_4_0				0x4c
#define TEGRA30_I2S_LCOEF_2_4_1				0x50
#define TEGRA30_I2S_LCOEF_2_4_2				0x54

/* Fields in TEGRA30_I2S_CTRL */

#define TEGRA30_I2S_CTRL_XFER_EN_TX			(1 << 31)
#define TEGRA30_I2S_CTRL_XFER_EN_RX			(1 << 30)
#define TEGRA30_I2S_CTRL_CG_EN				(1 << 29)
#define TEGRA30_I2S_CTRL_SOFT_RESET			(1 << 28)
#define TEGRA30_I2S_CTRL_TX_FLOWCTL_EN			(1 << 27)

#define TEGRA30_I2S_CTRL_OBS_SEL_SHIFT			24
#define TEGRA30_I2S_CTRL_OBS_SEL_MASK			(7 << TEGRA30_I2S_CTRL_OBS_SEL_SHIFT)

#define TEGRA30_I2S_FRAME_FORMAT_LRCK			0
#define TEGRA30_I2S_FRAME_FORMAT_FSYNC			1

#define TEGRA30_I2S_CTRL_FRAME_FORMAT_SHIFT		12
#define TEGRA30_I2S_CTRL_FRAME_FORMAT_MASK		(7                              << TEGRA30_I2S_CTRL_FRAME_FORMAT_SHIFT)
#define TEGRA30_I2S_CTRL_FRAME_FORMAT_LRCK		(TEGRA30_I2S_FRAME_FORMAT_LRCK  << TEGRA30_I2S_CTRL_FRAME_FORMAT_SHIFT)
#define TEGRA30_I2S_CTRL_FRAME_FORMAT_FSYNC		(TEGRA30_I2S_FRAME_FORMAT_FSYNC << TEGRA30_I2S_CTRL_FRAME_FORMAT_SHIFT)

#define TEGRA30_I2S_CTRL_MASTER_ENABLE			(1 << 10)

#define TEGRA30_I2S_LRCK_LEFT_LOW			0
#define TEGRA30_I2S_LRCK_RIGHT_LOW			1

#define TEGRA30_I2S_CTRL_LRCK_SHIFT			9
#define TEGRA30_I2S_CTRL_LRCK_MASK			(1                          << TEGRA30_I2S_CTRL_LRCK_SHIFT)
#define TEGRA30_I2S_CTRL_LRCK_L_LOW			(TEGRA30_I2S_LRCK_LEFT_LOW  << TEGRA30_I2S_CTRL_LRCK_SHIFT)
#define TEGRA30_I2S_CTRL_LRCK_R_LOW			(TEGRA30_I2S_LRCK_RIGHT_LOW << TEGRA30_I2S_CTRL_LRCK_SHIFT)

#define TEGRA30_I2S_CTRL_LPBK_ENABLE			(1 << 8)

#define TEGRA30_I2S_BIT_CODE_LINEAR			0
#define TEGRA30_I2S_BIT_CODE_ULAW			1
#define TEGRA30_I2S_BIT_CODE_ALAW			2

#define TEGRA30_I2S_CTRL_BIT_CODE_SHIFT			4
#define TEGRA30_I2S_CTRL_BIT_CODE_MASK			(3                           << TEGRA30_I2S_CTRL_BIT_CODE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_CODE_LINEAR		(TEGRA30_I2S_BIT_CODE_LINEAR << TEGRA30_I2S_CTRL_BIT_CODE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_CODE_ULAW			(TEGRA30_I2S_BIT_CODE_ULAW   << TEGRA30_I2S_CTRL_BIT_CODE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_CODE_ALAW			(TEGRA30_I2S_BIT_CODE_ALAW   << TEGRA30_I2S_CTRL_BIT_CODE_SHIFT)

#define TEGRA30_I2S_BITS_8				1
#define TEGRA30_I2S_BITS_12				2
#define TEGRA30_I2S_BITS_16				3
#define TEGRA30_I2S_BITS_20				4
#define TEGRA30_I2S_BITS_24				5
#define TEGRA30_I2S_BITS_28				6
#define TEGRA30_I2S_BITS_32				7

/* Sample container size; see {RX,TX}_MASK field in CH_CTRL below */
#define TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT			0
#define TEGRA30_I2S_CTRL_BIT_SIZE_MASK			(7                   << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_SIZE_8			(TEGRA30_I2S_BITS_8  << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_SIZE_12			(TEGRA30_I2S_BITS_12 << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_SIZE_16			(TEGRA30_I2S_BITS_16 << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_SIZE_20			(TEGRA30_I2S_BITS_20 << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_SIZE_24			(TEGRA30_I2S_BITS_24 << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_SIZE_28			(TEGRA30_I2S_BITS_28 << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)
#define TEGRA30_I2S_CTRL_BIT_SIZE_32			(TEGRA30_I2S_BITS_32 << TEGRA30_I2S_CTRL_BIT_SIZE_SHIFT)

/* Fields in TEGRA30_I2S_TIMING */

#define TEGRA30_I2S_TIMING_NON_SYM_ENABLE		(1 << 12)
#define TEGRA30_I2S_TIMING_CHANNEL_BIT_COUNT_SHIFT	0
#define TEGRA30_I2S_TIMING_CHANNEL_BIT_COUNT_MASK_US	0x7ff
#define TEGRA30_I2S_TIMING_CHANNEL_BIT_COUNT_MASK	(TEGRA30_I2S_TIMING_CHANNEL_BIT_COUNT_MASK_US << TEGRA30_I2S_TIMING_CHANNEL_BIT_COUNT_SHIFT)

/* Fields in TEGRA30_I2S_OFFSET */

#define TEGRA30_I2S_OFFSET_RX_DATA_OFFSET_SHIFT		16
#define TEGRA30_I2S_OFFSET_RX_DATA_OFFSET_MASK_US	0x7ff
#define TEGRA30_I2S_OFFSET_RX_DATA_OFFSET_MASK		(TEGRA30_I2S_OFFSET_RX_DATA_OFFSET_MASK_US << TEGRA30_I2S_OFFSET_RX_DATA_OFFSET_SHIFT)
#define TEGRA30_I2S_OFFSET_TX_DATA_OFFSET_SHIFT		0
#define TEGRA30_I2S_OFFSET_TX_DATA_OFFSET_MASK_US	0x7ff
#define TEGRA30_I2S_OFFSET_TX_DATA_OFFSET_MASK		(TEGRA30_I2S_OFFSET_TX_DATA_OFFSET_MASK_US << TEGRA30_I2S_OFFSET_TX_DATA_OFFSET_SHIFT)

/* Fields in TEGRA30_I2S_CH_CTRL */

/* (FSYNC width - 1) in bit clocks */
#define TEGRA30_I2S_CH_CTRL_FSYNC_WIDTH_SHIFT		24
#define TEGRA30_I2S_CH_CTRL_FSYNC_WIDTH_MASK_US		0xff
#define TEGRA30_I2S_CH_CTRL_FSYNC_WIDTH_MASK		(TEGRA30_I2S_CH_CTRL_FSYNC_WIDTH_MASK_US << TEGRA30_I2S_CH_CTRL_FSYNC_WIDTH_SHIFT)

#define TEGRA30_I2S_HIGHZ_NO				0
#define TEGRA30_I2S_HIGHZ_YES				1
#define TEGRA30_I2S_HIGHZ_ON_HALF_BIT_CLK		2

#define TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_SHIFT		12
#define TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_MASK		(3                                 << TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_SHIFT)
#define TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_NO		(TEGRA30_I2S_HIGHZ_NO              << TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_SHIFT)
#define TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_YES		(TEGRA30_I2S_HIGHZ_YES             << TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_SHIFT)
#define TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_ON_HALF_BIT_CLK	(TEGRA30_I2S_HIGHZ_ON_HALF_BIT_CLK << TEGRA30_I2S_CH_CTRL_HIGHZ_CTRL_SHIFT)

#define TEGRA30_I2S_MSB_FIRST				0
#define TEGRA30_I2S_LSB_FIRST				1

#define TEGRA30_I2S_CH_CTRL_RX_BIT_ORDER_SHIFT		10
#define TEGRA30_I2S_CH_CTRL_RX_BIT_ORDER_MASK		(1                     << TEGRA30_I2S_CH_CTRL_RX_BIT_ORDER_SHIFT)
#define TEGRA30_I2S_CH_CTRL_RX_BIT_ORDER_MSB_FIRST	(TEGRA30_I2S_MSB_FIRST << TEGRA30_I2S_CH_CTRL_RX_BIT_ORDER_SHIFT)
#define TEGRA30_I2S_CH_CTRL_RX_BIT_ORDER_LSB_FIRST	(TEGRA30_I2S_LSB_FIRST << TEGRA30_I2S_CH_CTRL_RX_BIT_ORDER_SHIFT)
#define TEGRA30_I2S_CH_CTRL_TX_BIT_ORDER_SHIFT		9
#define TEGRA30_I2S_CH_CTRL_TX_BIT_ORDER_MASK		(1                     << TEGRA30_I2S_CH_CTRL_TX_BIT_ORDER_SHIFT)
#define TEGRA30_I2S_CH_CTRL_TX_BIT_ORDER_MSB_FIRST	(TEGRA30_I2S_MSB_FIRST << TEGRA30_I2S_CH_CTRL_TX_BIT_ORDER_SHIFT)
#define TEGRA30_I2S_CH_CTRL_TX_BIT_ORDER_LSB_FIRST	(TEGRA30_I2S_LSB_FIRST << TEGRA30_I2S_CH_CTRL_TX_BIT_ORDER_SHIFT)

#define TEGRA30_I2S_POS_EDGE				0
#define TEGRA30_I2S_NEG_EDGE				1

#define TEGRA30_I2S_CH_CTRL_EGDE_CTRL_SHIFT		8
#define TEGRA30_I2S_CH_CTRL_EGDE_CTRL_MASK		(1                    << TEGRA30_I2S_CH_CTRL_EGDE_CTRL_SHIFT)
#define TEGRA30_I2S_CH_CTRL_EGDE_CTRL_POS_EDGE		(TEGRA30_I2S_POS_EDGE << TEGRA30_I2S_CH_CTRL_EGDE_CTRL_SHIFT)
#define TEGRA30_I2S_CH_CTRL_EGDE_CTRL_NEG_EDGE		(TEGRA30_I2S_NEG_EDGE << TEGRA30_I2S_CH_CTRL_EGDE_CTRL_SHIFT)

/* Sample size is # bits from BIT_SIZE minus this field */
#define TEGRA30_I2S_CH_CTRL_RX_MASK_BITS_SHIFT		4
#define TEGRA30_I2S_CH_CTRL_RX_MASK_BITS_MASK_US	7
#define TEGRA30_I2S_CH_CTRL_RX_MASK_BITS_MASK		(TEGRA30_I2S_CH_CTRL_RX_MASK_BITS_MASK_US << TEGRA30_I2S_CH_CTRL_RX_MASK_BITS_SHIFT)

#define TEGRA30_I2S_CH_CTRL_TX_MASK_BITS_SHIFT		0
#define TEGRA30_I2S_CH_CTRL_TX_MASK_BITS_MASK_US	7
#define TEGRA30_I2S_CH_CTRL_TX_MASK_BITS_MASK		(TEGRA30_I2S_CH_CTRL_TX_MASK_BITS_MASK_US << TEGRA30_I2S_CH_CTRL_TX_MASK_BITS_SHIFT)

/* Fields in TEGRA30_I2S_SLOT_CTRL */

/* Number of slots in frame, minus 1 */
#define TEGRA30_I2S_SLOT_CTRL_TOTAL_SLOTS_SHIFT		16
#define TEGRA30_I2S_SLOT_CTRL_TOTAL_SLOTS_MASK_US	7
#define TEGRA30_I2S_SLOT_CTRL_TOTAL_SLOTS_MASK		(TEGRA30_I2S_SLOT_CTRL_TOTAL_SLOTS_MASK_US << TEGRA30_I2S_SLOT_CTRL_TOTAL_SLOTS_SHIFT)

/* TDM mode slot enable bitmask */
#define TEGRA30_I2S_SLOT_CTRL_RX_SLOT_ENABLES_SHIFT	8
#define TEGRA30_I2S_SLOT_CTRL_RX_SLOT_ENABLES_MASK	(0xff << TEGRA30_I2S_SLOT_CTRL_RX_SLOT_ENABLES_SHIFT)

#define TEGRA30_I2S_SLOT_CTRL_TX_SLOT_ENABLES_SHIFT	0
#define TEGRA30_I2S_SLOT_CTRL_TX_SLOT_ENABLES_MASK	(0xff << TEGRA30_I2S_SLOT_CTRL_TX_SLOT_ENABLES_SHIFT)

/* Fields in TEGRA30_I2S_CIF_RX_CTRL */
/* Uses field from TEGRA30_AUDIOCIF_CTRL_* in tegra30_ahub.h */

/* Fields in TEGRA30_I2S_CIF_TX_CTRL */
/* Uses field from TEGRA30_AUDIOCIF_CTRL_* in tegra30_ahub.h */

/* Fields in TEGRA30_I2S_FLOWCTL */

#define TEGRA30_I2S_FILTER_LINEAR			0
#define TEGRA30_I2S_FILTER_QUAD				1

#define TEGRA30_I2S_FLOWCTL_FILTER_SHIFT		31
#define TEGRA30_I2S_FLOWCTL_FILTER_MASK			(1                         << TEGRA30_I2S_FLOWCTL_FILTER_SHIFT)
#define TEGRA30_I2S_FLOWCTL_FILTER_LINEAR		(TEGRA30_I2S_FILTER_LINEAR << TEGRA30_I2S_FLOWCTL_FILTER_SHIFT)
#define TEGRA30_I2S_FLOWCTL_FILTER_QUAD			(TEGRA30_I2S_FILTER_QUAD   << TEGRA30_I2S_FLOWCTL_FILTER_SHIFT)

/* Fields in TEGRA30_I2S_TX_STEP */

#define TEGRA30_I2S_TX_STEP_SHIFT			0
#define TEGRA30_I2S_TX_STEP_MASK_US			0xffff
#define TEGRA30_I2S_TX_STEP_MASK			(TEGRA30_I2S_TX_STEP_MASK_US << TEGRA30_I2S_TX_STEP_SHIFT)

/* Fields in TEGRA30_I2S_FLOW_STATUS */

#define TEGRA30_I2S_FLOW_STATUS_UNDERFLOW		(1 << 31)
#define TEGRA30_I2S_FLOW_STATUS_OVERFLOW		(1 << 30)
#define TEGRA30_I2S_FLOW_STATUS_MONITOR_INT_EN		(1 << 4)
#define TEGRA30_I2S_FLOW_STATUS_COUNTER_CLR		(1 << 3)
#define TEGRA30_I2S_FLOW_STATUS_MONITOR_CLR		(1 << 2)
#define TEGRA30_I2S_FLOW_STATUS_COUNTER_EN		(1 << 1)
#define TEGRA30_I2S_FLOW_STATUS_MONITOR_EN		(1 << 0)

/*
 * There are no fields in TEGRA30_I2S_FLOW_TOTAL, TEGRA30_I2S_FLOW_OVER,
 * TEGRA30_I2S_FLOW_UNDER; they are counters taking the whole register.
 */

/* Fields in TEGRA30_I2S_LCOEF_* */

#define TEGRA30_I2S_LCOEF_COEF_SHIFT			0
#define TEGRA30_I2S_LCOEF_COEF_MASK_US			0xffff
#define TEGRA30_I2S_LCOEF_COEF_MASK			(TEGRA30_I2S_LCOEF_COEF_MASK_US << TEGRA30_I2S_LCOEF_COEF_SHIFT)

struct tegra30_i2s_soc_data {
	void (*set_audio_cif)(struct regmap *regmap,
			      unsigned int reg,
			      struct tegra30_ahub_cif_conf *conf);
};

struct tegra30_i2s {
	const struct tegra30_i2s_soc_data *soc_data;
	struct snd_soc_dai_driver dai;
	int cif_id;
	struct clk *clk_i2s;
	enum tegra30_ahub_txcif capture_i2s_cif;
	enum tegra30_ahub_rxcif capture_fifo_cif;
	char capture_dma_chan[8];
	struct snd_dmaengine_dai_dma_data capture_dma_data;
	enum tegra30_ahub_rxcif playback_i2s_cif;
	enum tegra30_ahub_txcif playback_fifo_cif;
	char playback_dma_chan[8];
	struct snd_dmaengine_dai_dma_data playback_dma_data;
	struct regmap *regmap;
	struct snd_dmaengine_pcm_config dma_config;
};

#endif
