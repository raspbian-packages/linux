/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2011-2018 Magewell Electronics Co., Ltd. (Nanjing)
 * All rights reserved.
 * Author: Yong Deng <yong.deng@magewell.com>
 */

#ifndef __SUN6I_CSI_REG_H__
#define __SUN6I_CSI_REG_H__

#include <linux/kernel.h>

#define CSI_EN_REG			0x0
#define CSI_EN_VER_EN				BIT(30)
#define CSI_EN_CSI_EN				BIT(0)

#define CSI_IF_CFG_REG			0x4
#define CSI_IF_CFG_SRC_TYPE_MASK		BIT(21)
#define CSI_IF_CFG_SRC_TYPE_PROGRESSED		((0 << 21) & CSI_IF_CFG_SRC_TYPE_MASK)
#define CSI_IF_CFG_SRC_TYPE_INTERLACED		((1 << 21) & CSI_IF_CFG_SRC_TYPE_MASK)
#define CSI_IF_CFG_FPS_DS_EN			BIT(20)
#define CSI_IF_CFG_FIELD_MASK			BIT(19)
#define CSI_IF_CFG_FIELD_NEGATIVE		((0 << 19) & CSI_IF_CFG_FIELD_MASK)
#define CSI_IF_CFG_FIELD_POSITIVE		((1 << 19) & CSI_IF_CFG_FIELD_MASK)
#define CSI_IF_CFG_VREF_POL_MASK		BIT(18)
#define CSI_IF_CFG_VREF_POL_NEGATIVE		((0 << 18) & CSI_IF_CFG_VREF_POL_MASK)
#define CSI_IF_CFG_VREF_POL_POSITIVE		((1 << 18) & CSI_IF_CFG_VREF_POL_MASK)
#define CSI_IF_CFG_HREF_POL_MASK		BIT(17)
#define CSI_IF_CFG_HREF_POL_NEGATIVE		((0 << 17) & CSI_IF_CFG_HREF_POL_MASK)
#define CSI_IF_CFG_HREF_POL_POSITIVE		((1 << 17) & CSI_IF_CFG_HREF_POL_MASK)
#define CSI_IF_CFG_CLK_POL_MASK			BIT(16)
#define CSI_IF_CFG_CLK_POL_RISING_EDGE		((0 << 16) & CSI_IF_CFG_CLK_POL_MASK)
#define CSI_IF_CFG_CLK_POL_FALLING_EDGE		((1 << 16) & CSI_IF_CFG_CLK_POL_MASK)
#define CSI_IF_CFG_IF_DATA_WIDTH_MASK		GENMASK(10, 8)
#define CSI_IF_CFG_IF_DATA_WIDTH_8BIT		((0 << 8) & CSI_IF_CFG_IF_DATA_WIDTH_MASK)
#define CSI_IF_CFG_IF_DATA_WIDTH_10BIT		((1 << 8) & CSI_IF_CFG_IF_DATA_WIDTH_MASK)
#define CSI_IF_CFG_IF_DATA_WIDTH_12BIT		((2 << 8) & CSI_IF_CFG_IF_DATA_WIDTH_MASK)
#define CSI_IF_CFG_MIPI_IF_MASK			BIT(7)
#define CSI_IF_CFG_MIPI_IF_CSI			(0 << 7)
#define CSI_IF_CFG_MIPI_IF_MIPI			BIT(7)
#define CSI_IF_CFG_CSI_IF_MASK			GENMASK(4, 0)
#define CSI_IF_CFG_CSI_IF_YUV422_INTLV		((0 << 0) & CSI_IF_CFG_CSI_IF_MASK)
#define CSI_IF_CFG_CSI_IF_YUV422_16BIT		((1 << 0) & CSI_IF_CFG_CSI_IF_MASK)
#define CSI_IF_CFG_CSI_IF_BT656			((4 << 0) & CSI_IF_CFG_CSI_IF_MASK)
#define CSI_IF_CFG_CSI_IF_BT1120		((5 << 0) & CSI_IF_CFG_CSI_IF_MASK)

#define CSI_CAP_REG			0x8
#define CSI_CAP_CH0_CAP_MASK_MASK		GENMASK(5, 2)
#define CSI_CAP_CH0_CAP_MASK(count)		(((count) << 2) & CSI_CAP_CH0_CAP_MASK_MASK)
#define CSI_CAP_CH0_VCAP_ON			BIT(1)
#define CSI_CAP_CH0_SCAP_ON			BIT(0)

#define CSI_SYNC_CNT_REG		0xc
#define CSI_FIFO_THRS_REG		0x10
#define CSI_BT656_HEAD_CFG_REG		0x14
#define CSI_PTN_LEN_REG			0x30
#define CSI_PTN_ADDR_REG		0x34
#define CSI_VER_REG			0x3c

#define CSI_CH_CFG_REG			0x44
#define CSI_CH_CFG_INPUT_FMT_MASK		GENMASK(23, 20)
#define CSI_CH_CFG_INPUT_FMT(fmt)		(((fmt) << 20) & CSI_CH_CFG_INPUT_FMT_MASK)
#define CSI_CH_CFG_OUTPUT_FMT_MASK		GENMASK(19, 16)
#define CSI_CH_CFG_OUTPUT_FMT(fmt)		(((fmt) << 16) & CSI_CH_CFG_OUTPUT_FMT_MASK)
#define CSI_CH_CFG_VFLIP_EN			BIT(13)
#define CSI_CH_CFG_HFLIP_EN			BIT(12)
#define CSI_CH_CFG_FIELD_SEL_MASK		GENMASK(11, 10)
#define CSI_CH_CFG_FIELD_SEL_FIELD0		((0 << 10) & CSI_CH_CFG_FIELD_SEL_MASK)
#define CSI_CH_CFG_FIELD_SEL_FIELD1		((1 << 10) & CSI_CH_CFG_FIELD_SEL_MASK)
#define CSI_CH_CFG_FIELD_SEL_BOTH		((2 << 10) & CSI_CH_CFG_FIELD_SEL_MASK)
#define CSI_CH_CFG_INPUT_SEQ_MASK		GENMASK(9, 8)
#define CSI_CH_CFG_INPUT_SEQ(seq)		(((seq) << 8) & CSI_CH_CFG_INPUT_SEQ_MASK)

#define CSI_CH_SCALE_REG		0x4c
#define CSI_CH_SCALE_QUART_EN			BIT(0)

#define CSI_CH_F0_BUFA_REG		0x50

#define CSI_CH_F1_BUFA_REG		0x58

#define CSI_CH_F2_BUFA_REG		0x60

#define CSI_CH_STA_REG			0x6c
#define CSI_CH_STA_FIELD_STA_MASK		BIT(2)
#define CSI_CH_STA_FIELD_STA_FIELD0		((0 << 2) & CSI_CH_STA_FIELD_STA_MASK)
#define CSI_CH_STA_FIELD_STA_FIELD1		((1 << 2) & CSI_CH_STA_FIELD_STA_MASK)
#define CSI_CH_STA_VCAP_STA			BIT(1)
#define CSI_CH_STA_SCAP_STA			BIT(0)

#define CSI_CH_INT_EN_REG		0x70
#define CSI_CH_INT_EN_VS_INT_EN			BIT(7)
#define CSI_CH_INT_EN_HB_OF_INT_EN		BIT(6)
#define CSI_CH_INT_EN_MUL_ERR_INT_EN		BIT(5)
#define CSI_CH_INT_EN_FIFO2_OF_INT_EN		BIT(4)
#define CSI_CH_INT_EN_FIFO1_OF_INT_EN		BIT(3)
#define CSI_CH_INT_EN_FIFO0_OF_INT_EN		BIT(2)
#define CSI_CH_INT_EN_FD_INT_EN			BIT(1)
#define CSI_CH_INT_EN_CD_INT_EN			BIT(0)

#define CSI_CH_INT_STA_REG		0x74
#define CSI_CH_INT_STA_VS_PD			BIT(7)
#define CSI_CH_INT_STA_HB_OF_PD			BIT(6)
#define CSI_CH_INT_STA_MUL_ERR_PD		BIT(5)
#define CSI_CH_INT_STA_FIFO2_OF_PD		BIT(4)
#define CSI_CH_INT_STA_FIFO1_OF_PD		BIT(3)
#define CSI_CH_INT_STA_FIFO0_OF_PD		BIT(2)
#define CSI_CH_INT_STA_FD_PD			BIT(1)
#define CSI_CH_INT_STA_CD_PD			BIT(0)

#define CSI_CH_FLD1_VSIZE_REG		0x78

#define CSI_CH_HSIZE_REG		0x80
#define CSI_CH_HSIZE_HOR_LEN_MASK		GENMASK(28, 16)
#define CSI_CH_HSIZE_HOR_LEN(len)		(((len) << 16) & CSI_CH_HSIZE_HOR_LEN_MASK)
#define CSI_CH_HSIZE_HOR_START_MASK		GENMASK(12, 0)
#define CSI_CH_HSIZE_HOR_START(start)		(((start) << 0) & CSI_CH_HSIZE_HOR_START_MASK)

#define CSI_CH_VSIZE_REG		0x84
#define CSI_CH_VSIZE_VER_LEN_MASK		GENMASK(28, 16)
#define CSI_CH_VSIZE_VER_LEN(len)		(((len) << 16) & CSI_CH_VSIZE_VER_LEN_MASK)
#define CSI_CH_VSIZE_VER_START_MASK		GENMASK(12, 0)
#define CSI_CH_VSIZE_VER_START(start)		(((start) << 0) & CSI_CH_VSIZE_VER_START_MASK)

#define CSI_CH_BUF_LEN_REG		0x88
#define CSI_CH_BUF_LEN_BUF_LEN_C_MASK		GENMASK(29, 16)
#define CSI_CH_BUF_LEN_BUF_LEN_C(len)		(((len) << 16) & CSI_CH_BUF_LEN_BUF_LEN_C_MASK)
#define CSI_CH_BUF_LEN_BUF_LEN_Y_MASK		GENMASK(13, 0)
#define CSI_CH_BUF_LEN_BUF_LEN_Y(len)		(((len) << 0) & CSI_CH_BUF_LEN_BUF_LEN_Y_MASK)

#define CSI_CH_FLIP_SIZE_REG		0x8c
#define CSI_CH_FLIP_SIZE_VER_LEN_MASK		GENMASK(28, 16)
#define CSI_CH_FLIP_SIZE_VER_LEN(len)		(((len) << 16) & CSI_CH_FLIP_SIZE_VER_LEN_MASK)
#define CSI_CH_FLIP_SIZE_VALID_LEN_MASK		GENMASK(12, 0)
#define CSI_CH_FLIP_SIZE_VALID_LEN(len)		(((len) << 0) & CSI_CH_FLIP_SIZE_VALID_LEN_MASK)

#define CSI_CH_FRM_CLK_CNT_REG		0x90
#define CSI_CH_ACC_ITNL_CLK_CNT_REG	0x94
#define CSI_CH_FIFO_STAT_REG		0x98
#define CSI_CH_PCLK_STAT_REG		0x9c

/*
 * csi input data format
 */
enum csi_input_fmt {
	CSI_INPUT_FORMAT_RAW		= 0,
	CSI_INPUT_FORMAT_YUV422		= 3,
	CSI_INPUT_FORMAT_YUV420		= 4,
};

/*
 * csi output data format
 */
enum csi_output_fmt {
	/* only when input format is RAW */
	CSI_FIELD_RAW_8			= 0,
	CSI_FIELD_RAW_10		= 1,
	CSI_FIELD_RAW_12		= 2,
	CSI_FIELD_RGB565		= 4,
	CSI_FIELD_RGB888		= 5,
	CSI_FIELD_PRGB888		= 6,
	CSI_FRAME_RAW_8			= 8,
	CSI_FRAME_RAW_10		= 9,
	CSI_FRAME_RAW_12		= 10,
	CSI_FRAME_RGB565		= 12,
	CSI_FRAME_RGB888		= 13,
	CSI_FRAME_PRGB888		= 14,

	/* only when input format is YUV422 */
	CSI_FIELD_PLANAR_YUV422		= 0,
	CSI_FIELD_PLANAR_YUV420		= 1,
	CSI_FRAME_PLANAR_YUV420		= 2,
	CSI_FRAME_PLANAR_YUV422		= 3,
	CSI_FIELD_UV_CB_YUV422		= 4,
	CSI_FIELD_UV_CB_YUV420		= 5,
	CSI_FRAME_UV_CB_YUV420		= 6,
	CSI_FRAME_UV_CB_YUV422		= 7,
	CSI_FIELD_MB_YUV422		= 8,
	CSI_FIELD_MB_YUV420		= 9,
	CSI_FRAME_MB_YUV420		= 10,
	CSI_FRAME_MB_YUV422		= 11,
	CSI_FIELD_UV_CB_YUV422_10	= 12,
	CSI_FIELD_UV_CB_YUV420_10	= 13,
};

/*
 * csi YUV input data sequence
 */
enum csi_input_seq {
	/* only when input format is YUV422 */
	CSI_INPUT_SEQ_YUYV = 0,
	CSI_INPUT_SEQ_YVYU,
	CSI_INPUT_SEQ_UYVY,
	CSI_INPUT_SEQ_VYUY,
};

#endif /* __SUN6I_CSI_REG_H__ */
