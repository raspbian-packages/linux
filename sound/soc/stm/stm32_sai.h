/*
 * STM32 ALSA SoC Digital Audio Interface (SAI) driver.
 *
 * Copyright (C) 2016, STMicroelectronics - All Rights Reserved
 * Author(s): Olivier Moysan <olivier.moysan@st.com> for STMicroelectronics.
 *
 * License terms: GPL V2.0.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 */

/******************** SAI Register Map **************************************/

/* common register */
#define STM_SAI_GCR		0x00

/* Sub-block A&B registers offsets, relative to A&B sub-block addresses */
#define STM_SAI_CR1_REGX	0x00	/* A offset: 0x04. B offset: 0x24 */
#define STM_SAI_CR2_REGX	0x04
#define STM_SAI_FRCR_REGX	0x08
#define STM_SAI_SLOTR_REGX	0x0C
#define STM_SAI_IMR_REGX	0x10
#define STM_SAI_SR_REGX		0x14
#define STM_SAI_CLRFR_REGX	0x18
#define STM_SAI_DR_REGX		0x1C

/******************** Bit definition for SAI_GCR register *******************/
#define SAI_GCR_SYNCIN_SHIFT	0
#define SAI_GCR_SYNCIN_MASK	GENMASK(1, SAI_GCR_SYNCIN_SHIFT)
#define SAI_GCR_SYNCIN_SET(x)	((x) << SAI_GCR_SYNCIN_SHIFT)

#define SAI_GCR_SYNCOUT_SHIFT	4
#define SAI_GCR_SYNCOUT_MASK	GENMASK(5, SAI_GCR_SYNCOUT_SHIFT)
#define SAI_GCR_SYNCOUT_SET(x)	((x) << SAI_GCR_SYNCOUT_SHIFT)

/******************* Bit definition for SAI_XCR1 register *******************/
#define SAI_XCR1_RX_TX_SHIFT	0
#define SAI_XCR1_RX_TX		BIT(SAI_XCR1_RX_TX_SHIFT)
#define SAI_XCR1_SLAVE_SHIFT	1
#define SAI_XCR1_SLAVE		BIT(SAI_XCR1_SLAVE_SHIFT)

#define SAI_XCR1_PRTCFG_SHIFT	2
#define SAI_XCR1_PRTCFG_MASK	GENMASK(3, SAI_XCR1_PRTCFG_SHIFT)
#define SAI_XCR1_PRTCFG_SET(x)	((x) << SAI_XCR1_PRTCFG_SHIFT)

#define SAI_XCR1_DS_SHIFT	5
#define SAI_XCR1_DS_MASK	GENMASK(7, SAI_XCR1_DS_SHIFT)
#define SAI_XCR1_DS_SET(x)	((x) << SAI_XCR1_DS_SHIFT)

#define SAI_XCR1_LSBFIRST_SHIFT	8
#define SAI_XCR1_LSBFIRST	BIT(SAI_XCR1_LSBFIRST_SHIFT)
#define SAI_XCR1_CKSTR_SHIFT	9
#define SAI_XCR1_CKSTR		BIT(SAI_XCR1_CKSTR_SHIFT)

#define SAI_XCR1_SYNCEN_SHIFT	10
#define SAI_XCR1_SYNCEN_MASK	GENMASK(11, SAI_XCR1_SYNCEN_SHIFT)
#define SAI_XCR1_SYNCEN_SET(x)	((x) << SAI_XCR1_SYNCEN_SHIFT)

#define SAI_XCR1_MONO_SHIFT	12
#define SAI_XCR1_MONO		BIT(SAI_XCR1_MONO_SHIFT)
#define SAI_XCR1_OUTDRIV_SHIFT	13
#define SAI_XCR1_OUTDRIV	BIT(SAI_XCR1_OUTDRIV_SHIFT)
#define SAI_XCR1_SAIEN_SHIFT	16
#define SAI_XCR1_SAIEN		BIT(SAI_XCR1_SAIEN_SHIFT)
#define SAI_XCR1_DMAEN_SHIFT	17
#define SAI_XCR1_DMAEN		BIT(SAI_XCR1_DMAEN_SHIFT)
#define SAI_XCR1_NODIV_SHIFT	19
#define SAI_XCR1_NODIV		BIT(SAI_XCR1_NODIV_SHIFT)

#define SAI_XCR1_MCKDIV_SHIFT	20
#define SAI_XCR1_MCKDIV_WIDTH	4
#define SAI_XCR1_MCKDIV_MASK	GENMASK(24, SAI_XCR1_MCKDIV_SHIFT)
#define SAI_XCR1_MCKDIV_SET(x)	((x) << SAI_XCR1_MCKDIV_SHIFT)
#define SAI_XCR1_MCKDIV_MAX	((1 << SAI_XCR1_MCKDIV_WIDTH) - 1)

#define SAI_XCR1_OSR_SHIFT	26
#define SAI_XCR1_OSR		BIT(SAI_XCR1_OSR_SHIFT)

/******************* Bit definition for SAI_XCR2 register *******************/
#define SAI_XCR2_FTH_SHIFT	0
#define SAI_XCR2_FTH_MASK	GENMASK(2, SAI_XCR2_FTH_SHIFT)
#define SAI_XCR2_FTH_SET(x)	((x) << SAI_XCR2_FTH_SHIFT)

#define SAI_XCR2_FFLUSH_SHIFT	3
#define SAI_XCR2_FFLUSH		BIT(SAI_XCR2_FFLUSH_SHIFT)
#define SAI_XCR2_TRIS_SHIFT	4
#define SAI_XCR2_TRIS		BIT(SAI_XCR2_TRIS_SHIFT)
#define SAI_XCR2_MUTE_SHIFT	5
#define SAI_XCR2_MUTE		BIT(SAI_XCR2_MUTE_SHIFT)
#define SAI_XCR2_MUTEVAL_SHIFT	6
#define SAI_XCR2_MUTEVAL	BIT(SAI_XCR2_MUTEVAL_SHIFT)

#define SAI_XCR2_MUTECNT_SHIFT	7
#define SAI_XCR2_MUTECNT_MASK	GENMASK(12, SAI_XCR2_MUTECNT_SHIFT)
#define SAI_XCR2_MUTECNT_SET(x)	((x) << SAI_XCR2_MUTECNT_SHIFT)

#define SAI_XCR2_CPL_SHIFT	13
#define SAI_XCR2_CPL		BIT(SAI_XCR2_CPL_SHIFT)

#define SAI_XCR2_COMP_SHIFT	14
#define SAI_XCR2_COMP_MASK	GENMASK(15, SAI_XCR2_COMP_SHIFT)
#define SAI_XCR2_COMP_SET(x)	((x) << SAI_XCR2_COMP_SHIFT)

/****************** Bit definition for SAI_XFRCR register *******************/
#define SAI_XFRCR_FRL_SHIFT	0
#define SAI_XFRCR_FRL_MASK	GENMASK(7, SAI_XFRCR_FRL_SHIFT)
#define SAI_XFRCR_FRL_SET(x)	((x) << SAI_XFRCR_FRL_SHIFT)

#define SAI_XFRCR_FSALL_SHIFT	8
#define SAI_XFRCR_FSALL_MASK	GENMASK(14, SAI_XFRCR_FSALL_SHIFT)
#define SAI_XFRCR_FSALL_SET(x)	((x) << SAI_XFRCR_FSALL_SHIFT)

#define SAI_XFRCR_FSDEF_SHIFT	16
#define SAI_XFRCR_FSDEF		BIT(SAI_XFRCR_FSDEF_SHIFT)
#define SAI_XFRCR_FSPOL_SHIFT	17
#define SAI_XFRCR_FSPOL		BIT(SAI_XFRCR_FSPOL_SHIFT)
#define SAI_XFRCR_FSOFF_SHIFT	18
#define SAI_XFRCR_FSOFF		BIT(SAI_XFRCR_FSOFF_SHIFT)

/****************** Bit definition for SAI_XSLOTR register ******************/

#define SAI_XSLOTR_FBOFF_SHIFT	0
#define SAI_XSLOTR_FBOFF_MASK	GENMASK(4, SAI_XSLOTR_FBOFF_SHIFT)
#define SAI_XSLOTR_FBOFF_SET(x)	((x) << SAI_XSLOTR_FBOFF_SHIFT)

#define SAI_XSLOTR_SLOTSZ_SHIFT	6
#define SAI_XSLOTR_SLOTSZ_MASK	GENMASK(7, SAI_XSLOTR_SLOTSZ_SHIFT)
#define SAI_XSLOTR_SLOTSZ_SET(x)	((x) << SAI_XSLOTR_SLOTSZ_SHIFT)

#define SAI_XSLOTR_NBSLOT_SHIFT 8
#define SAI_XSLOTR_NBSLOT_MASK	GENMASK(11, SAI_XSLOTR_NBSLOT_SHIFT)
#define SAI_XSLOTR_NBSLOT_SET(x) ((x) << SAI_XSLOTR_NBSLOT_SHIFT)

#define SAI_XSLOTR_SLOTEN_SHIFT	16
#define SAI_XSLOTR_SLOTEN_WIDTH	16
#define SAI_XSLOTR_SLOTEN_MASK	GENMASK(31, SAI_XSLOTR_SLOTEN_SHIFT)
#define SAI_XSLOTR_SLOTEN_SET(x) ((x) << SAI_XSLOTR_SLOTEN_SHIFT)

/******************* Bit definition for SAI_XIMR register *******************/
#define SAI_XIMR_OVRUDRIE	BIT(0)
#define SAI_XIMR_MUTEDETIE	BIT(1)
#define SAI_XIMR_WCKCFGIE	BIT(2)
#define SAI_XIMR_FREQIE		BIT(3)
#define SAI_XIMR_CNRDYIE	BIT(4)
#define SAI_XIMR_AFSDETIE	BIT(5)
#define SAI_XIMR_LFSDETIE	BIT(6)

#define SAI_XIMR_SHIFT	0
#define SAI_XIMR_MASK		GENMASK(6, SAI_XIMR_SHIFT)

/******************** Bit definition for SAI_XSR register *******************/
#define SAI_XSR_OVRUDR		BIT(0)
#define SAI_XSR_MUTEDET		BIT(1)
#define SAI_XSR_WCKCFG		BIT(2)
#define SAI_XSR_FREQ		BIT(3)
#define SAI_XSR_CNRDY		BIT(4)
#define SAI_XSR_AFSDET		BIT(5)
#define SAI_XSR_LFSDET		BIT(6)

#define SAI_XSR_SHIFT	0
#define SAI_XSR_MASK		GENMASK(6, SAI_XSR_SHIFT)

/****************** Bit definition for SAI_XCLRFR register ******************/
#define SAI_XCLRFR_COVRUDR	BIT(0)
#define SAI_XCLRFR_CMUTEDET	BIT(1)
#define SAI_XCLRFR_CWCKCFG	BIT(2)
#define SAI_XCLRFR_CFREQ	BIT(3)
#define SAI_XCLRFR_CCNRDY	BIT(4)
#define SAI_XCLRFR_CAFSDET	BIT(5)
#define SAI_XCLRFR_CLFSDET	BIT(6)

#define SAI_XCLRFR_SHIFT	0
#define SAI_XCLRFR_MASK		GENMASK(6, SAI_XCLRFR_SHIFT)

enum stm32_sai_version {
	SAI_STM32F4
};

/**
 * struct stm32_sai_data - private data of SAI instance driver
 * @pdev: device data pointer
 * @clk_x8k: SAI parent clock for sampling frequencies multiple of 8kHz
 * @clk_x11k: SAI parent clock for sampling frequencies multiple of 11kHz
 * @version: SOC version
 * @irq: SAI interrupt line
 */
struct stm32_sai_data {
	struct platform_device *pdev;
	struct clk *clk_x8k;
	struct clk *clk_x11k;
	int version;
	int irq;
};
