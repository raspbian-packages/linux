// SPDX-License-Identifier: GPL-2.0-only
//
// aw88395_reg.h --  AW88395 chip register file
//
// Copyright (c) 2022-2023 AWINIC Technology CO., LTD
//
// Author: Bruce zhao <zhaolei@awinic.com>
//

#ifndef __AW88395_REG_H__
#define __AW88395_REG_H__

#define AW88395_ID_REG			(0x00)
#define AW88395_SYSST_REG		(0x01)
#define AW88395_SYSINT_REG		(0x02)
#define AW88395_SYSINTM_REG		(0x03)
#define AW88395_SYSCTRL_REG		(0x04)
#define AW88395_SYSCTRL2_REG		(0x05)
#define AW88395_I2SCTRL_REG		(0x06)
#define AW88395_I2SCFG1_REG		(0x07)
#define AW88395_I2SCFG2_REG		(0x08)
#define AW88395_HAGCCFG1_REG		(0x09)
#define AW88395_HAGCCFG2_REG		(0x0A)
#define AW88395_HAGCCFG3_REG		(0x0B)
#define AW88395_HAGCCFG4_REG		(0x0C)
#define AW88395_HAGCCFG5_REG		(0x0D)
#define AW88395_HAGCCFG6_REG		(0x0E)
#define AW88395_HAGCCFG7_REG		(0x0F)
#define AW88395_MPDCFG_REG		(0x10)
#define AW88395_PWMCTRL_REG		(0x11)
#define AW88395_I2SCFG3_REG		(0x12)
#define AW88395_DBGCTRL_REG		(0x13)
#define AW88395_HAGCST_REG		(0x20)
#define AW88395_VBAT_REG		(0x21)
#define AW88395_TEMP_REG		(0x22)
#define AW88395_PVDD_REG		(0x23)
#define AW88395_ISNDAT_REG		(0x24)
#define AW88395_VSNDAT_REG		(0x25)
#define AW88395_I2SINT_REG		(0x26)
#define AW88395_I2SCAPCNT_REG		(0x27)
#define AW88395_ANASTA1_REG		(0x28)
#define AW88395_ANASTA2_REG		(0x29)
#define AW88395_ANASTA3_REG		(0x2A)
#define AW88395_ANASTA4_REG		(0x2B)
#define AW88395_TESTDET_REG		(0x2C)
#define AW88395_TESTIN_REG		(0x38)
#define AW88395_TESTOUT_REG		(0x39)
#define AW88395_DSPMADD_REG		(0x40)
#define AW88395_DSPMDAT_REG		(0x41)
#define AW88395_WDT_REG		(0x42)
#define AW88395_ACR1_REG		(0x43)
#define AW88395_ACR2_REG		(0x44)
#define AW88395_ASR1_REG		(0x45)
#define AW88395_ASR2_REG		(0x46)
#define AW88395_DSPCFG_REG		(0x47)
#define AW88395_ASR3_REG		(0x48)
#define AW88395_ASR4_REG		(0x49)
#define AW88395_VSNCTRL1_REG		(0x50)
#define AW88395_ISNCTRL1_REG		(0x51)
#define AW88395_PLLCTRL1_REG		(0x52)
#define AW88395_PLLCTRL2_REG		(0x53)
#define AW88395_PLLCTRL3_REG		(0x54)
#define AW88395_CDACTRL1_REG		(0x55)
#define AW88395_CDACTRL2_REG		(0x56)
#define AW88395_SADCCTRL1_REG		(0x57)
#define AW88395_SADCCTRL2_REG		(0x58)
#define AW88395_CPCTRL1_REG		(0x59)
#define AW88395_BSTCTRL1_REG		(0x60)
#define AW88395_BSTCTRL2_REG		(0x61)
#define AW88395_BSTCTRL3_REG		(0x62)
#define AW88395_BSTCTRL4_REG		(0x63)
#define AW88395_BSTCTRL5_REG		(0x64)
#define AW88395_BSTCTRL6_REG		(0x65)
#define AW88395_BSTCTRL7_REG		(0x66)
#define AW88395_DSMCFG1_REG		(0x67)
#define AW88395_DSMCFG2_REG		(0x68)
#define AW88395_DSMCFG3_REG		(0x69)
#define AW88395_DSMCFG4_REG		(0x6A)
#define AW88395_DSMCFG5_REG		(0x6B)
#define AW88395_DSMCFG6_REG		(0x6C)
#define AW88395_DSMCFG7_REG		(0x6D)
#define AW88395_DSMCFG8_REG		(0x6E)
#define AW88395_TESTCTRL1_REG		(0x70)
#define AW88395_TESTCTRL2_REG		(0x71)
#define AW88395_EFCTRL1_REG		(0x72)
#define AW88395_EFCTRL2_REG		(0x73)
#define AW88395_EFWH_REG		(0x74)
#define AW88395_EFWM2_REG		(0x75)
#define AW88395_EFWM1_REG		(0x76)
#define AW88395_EFWL_REG		(0x77)
#define AW88395_EFRH_REG		(0x78)
#define AW88395_EFRM2_REG		(0x79)
#define AW88395_EFRM1_REG		(0x7A)
#define AW88395_EFRL_REG		(0x7B)
#define AW88395_TM_REG			(0x7C)

enum aw88395_id {
	AW88395_CHIP_ID = 0x2049,
};

#define AW88395_REG_MAX		(0x7D)

#define AW88395_VOLUME_STEP_DB		(6 * 8)

#define AW88395_UVLS_START_BIT		(14)
#define AW88395_UVLS_NORMAL		(0)
#define AW88395_UVLS_NORMAL_VALUE	\
	(AW88395_UVLS_NORMAL << AW88395_UVLS_START_BIT)

#define AW88395_DSPS_START_BIT		(12)
#define AW88395_DSPS_BITS_LEN		(1)
#define AW88395_DSPS_MASK		\
	(~(((1<<AW88395_DSPS_BITS_LEN)-1) << AW88395_DSPS_START_BIT))

#define AW88395_DSPS_NORMAL		(0)
#define AW88395_DSPS_NORMAL_VALUE	\
	(AW88395_DSPS_NORMAL << AW88395_DSPS_START_BIT)

#define AW88395_BSTOCS_START_BIT	(11)
#define AW88395_BSTOCS_OVER_CURRENT	(1)
#define AW88395_BSTOCS_OVER_CURRENT_VALUE	\
	(AW88395_BSTOCS_OVER_CURRENT << AW88395_BSTOCS_START_BIT)

#define AW88395_BSTS_START_BIT		(9)
#define AW88395_BSTS_FINISHED		(1)
#define AW88395_BSTS_FINISHED_VALUE	\
	(AW88395_BSTS_FINISHED << AW88395_BSTS_START_BIT)

#define AW88395_SWS_START_BIT		(8)
#define AW88395_SWS_SWITCHING		(1)
#define AW88395_SWS_SWITCHING_VALUE	\
	(AW88395_SWS_SWITCHING << AW88395_SWS_START_BIT)

#define AW88395_NOCLKS_START_BIT	(5)
#define AW88395_NOCLKS_NO_CLOCK	(1)
#define AW88395_NOCLKS_NO_CLOCK_VALUE	\
	(AW88395_NOCLKS_NO_CLOCK << AW88395_NOCLKS_START_BIT)

#define AW88395_CLKS_START_BIT		(4)
#define AW88395_CLKS_STABLE		(1)
#define AW88395_CLKS_STABLE_VALUE	\
	(AW88395_CLKS_STABLE << AW88395_CLKS_START_BIT)

#define AW88395_OCDS_START_BIT		(3)
#define AW88395_OCDS_OC		(1)
#define AW88395_OCDS_OC_VALUE		\
	(AW88395_OCDS_OC << AW88395_OCDS_START_BIT)

#define AW88395_OTHS_START_BIT		(1)
#define AW88395_OTHS_OT		(1)
#define AW88395_OTHS_OT_VALUE		\
	(AW88395_OTHS_OT << AW88395_OTHS_START_BIT)

#define AW88395_PLLS_START_BIT		(0)
#define AW88395_PLLS_LOCKED		(1)
#define AW88395_PLLS_LOCKED_VALUE	\
	(AW88395_PLLS_LOCKED << AW88395_PLLS_START_BIT)

#define AW88395_BIT_PLL_CHECK \
		(AW88395_CLKS_STABLE_VALUE | \
		AW88395_PLLS_LOCKED_VALUE)

#define AW88395_BIT_SYSST_CHECK_MASK \
		(~(AW88395_UVLS_NORMAL_VALUE | \
		AW88395_BSTOCS_OVER_CURRENT_VALUE | \
		AW88395_BSTS_FINISHED_VALUE | \
		AW88395_SWS_SWITCHING_VALUE | \
		AW88395_NOCLKS_NO_CLOCK_VALUE | \
		AW88395_CLKS_STABLE_VALUE | \
		AW88395_OCDS_OC_VALUE | \
		AW88395_OTHS_OT_VALUE | \
		AW88395_PLLS_LOCKED_VALUE))

#define AW88395_BIT_SYSST_CHECK \
		(AW88395_BSTS_FINISHED_VALUE | \
		AW88395_SWS_SWITCHING_VALUE | \
		AW88395_CLKS_STABLE_VALUE | \
		AW88395_PLLS_LOCKED_VALUE)

#define AW88395_WDI_START_BIT		(6)
#define AW88395_WDI_INT_VALUE		(1)
#define AW88395_WDI_INTERRUPT		\
	(AW88395_WDI_INT_VALUE << AW88395_WDI_START_BIT)

#define AW88395_NOCLKI_START_BIT	(5)
#define AW88395_NOCLKI_INT_VALUE	(1)
#define AW88395_NOCLKI_INTERRUPT	\
	(AW88395_NOCLKI_INT_VALUE << AW88395_NOCLKI_START_BIT)

#define AW88395_CLKI_START_BIT		(4)
#define AW88395_CLKI_INT_VALUE		(1)
#define AW88395_CLKI_INTERRUPT		\
	(AW88395_CLKI_INT_VALUE << AW88395_CLKI_START_BIT)

#define AW88395_PLLI_START_BIT		(0)
#define AW88395_PLLI_INT_VALUE		(1)
#define AW88395_PLLI_INTERRUPT		\
	(AW88395_PLLI_INT_VALUE << AW88395_PLLI_START_BIT)

#define AW88395_BIT_SYSINT_CHECK \
		(AW88395_WDI_INTERRUPT | \
		AW88395_CLKI_INTERRUPT | \
		AW88395_NOCLKI_INTERRUPT | \
		AW88395_PLLI_INTERRUPT)

#define AW88395_HMUTE_START_BIT	(8)
#define AW88395_HMUTE_BITS_LEN		(1)
#define AW88395_HMUTE_MASK		\
	(~(((1<<AW88395_HMUTE_BITS_LEN)-1) << AW88395_HMUTE_START_BIT))

#define AW88395_HMUTE_DISABLE		(0)
#define AW88395_HMUTE_DISABLE_VALUE	\
	(AW88395_HMUTE_DISABLE << AW88395_HMUTE_START_BIT)

#define AW88395_HMUTE_ENABLE		(1)
#define AW88395_HMUTE_ENABLE_VALUE	\
	(AW88395_HMUTE_ENABLE << AW88395_HMUTE_START_BIT)

#define AW88395_RCV_MODE_START_BIT	(7)
#define AW88395_RCV_MODE_BITS_LEN	(1)
#define AW88395_RCV_MODE_MASK		\
	(~(((1<<AW88395_RCV_MODE_BITS_LEN)-1) << AW88395_RCV_MODE_START_BIT))

#define AW88395_RCV_MODE_RECEIVER	(1)
#define AW88395_RCV_MODE_RECEIVER_VALUE	\
	(AW88395_RCV_MODE_RECEIVER << AW88395_RCV_MODE_START_BIT)

#define AW88395_DSPBY_START_BIT	(2)
#define AW88395_DSPBY_BITS_LEN		(1)
#define AW88395_DSPBY_MASK		\
	(~(((1<<AW88395_DSPBY_BITS_LEN)-1) << AW88395_DSPBY_START_BIT))

#define AW88395_DSPBY_WORKING		(0)
#define AW88395_DSPBY_WORKING_VALUE	\
	(AW88395_DSPBY_WORKING << AW88395_DSPBY_START_BIT)

#define AW88395_DSPBY_BYPASS		(1)
#define AW88395_DSPBY_BYPASS_VALUE	\
	(AW88395_DSPBY_BYPASS << AW88395_DSPBY_START_BIT)

#define AW88395_AMPPD_START_BIT	(1)
#define AW88395_AMPPD_BITS_LEN		(1)
#define AW88395_AMPPD_MASK		\
	(~(((1<<AW88395_AMPPD_BITS_LEN)-1) << AW88395_AMPPD_START_BIT))

#define AW88395_AMPPD_WORKING		(0)
#define AW88395_AMPPD_WORKING_VALUE	\
	(AW88395_AMPPD_WORKING << AW88395_AMPPD_START_BIT)

#define AW88395_AMPPD_POWER_DOWN	(1)
#define AW88395_AMPPD_POWER_DOWN_VALUE	\
	(AW88395_AMPPD_POWER_DOWN << AW88395_AMPPD_START_BIT)

#define AW88395_PWDN_START_BIT		(0)
#define AW88395_PWDN_BITS_LEN		(1)
#define AW88395_PWDN_MASK		\
	(~(((1<<AW88395_PWDN_BITS_LEN)-1) << AW88395_PWDN_START_BIT))

#define AW88395_PWDN_WORKING		(0)
#define AW88395_PWDN_WORKING_VALUE	\
	(AW88395_PWDN_WORKING << AW88395_PWDN_START_BIT)

#define AW88395_PWDN_POWER_DOWN	(1)
#define AW88395_PWDN_POWER_DOWN_VALUE	\
	(AW88395_PWDN_POWER_DOWN << AW88395_PWDN_START_BIT)

#define AW88395_MUTE_VOL		(90 * 8)
#define AW88395_VOLUME_STEP_DB		(6 * 8)

#define AW88395_VOL_6DB_START		(6)
#define AW88395_VOL_START_BIT		(6)
#define AW88395_VOL_BITS_LEN		(10)
#define AW88395_VOL_MASK		\
	(~(((1<<AW88395_VOL_BITS_LEN)-1) << AW88395_VOL_START_BIT))

#define AW88395_VOL_DEFAULT_VALUE	(0)

#define AW88395_I2STXEN_START_BIT	(0)
#define AW88395_I2STXEN_BITS_LEN	(1)
#define AW88395_I2STXEN_MASK		\
	(~(((1<<AW88395_I2STXEN_BITS_LEN)-1) << AW88395_I2STXEN_START_BIT))

#define AW88395_I2STXEN_DISABLE	(0)
#define AW88395_I2STXEN_DISABLE_VALUE	\
	(AW88395_I2STXEN_DISABLE << AW88395_I2STXEN_START_BIT)

#define AW88395_I2STXEN_ENABLE		(1)
#define AW88395_I2STXEN_ENABLE_VALUE	\
	(AW88395_I2STXEN_ENABLE << AW88395_I2STXEN_START_BIT)

#define AW88395_AGC_DSP_CTL_START_BIT	(15)
#define AW88395_AGC_DSP_CTL_BITS_LEN	(1)
#define AW88395_AGC_DSP_CTL_MASK	\
	(~(((1<<AW88395_AGC_DSP_CTL_BITS_LEN)-1) << AW88395_AGC_DSP_CTL_START_BIT))

#define AW88395_AGC_DSP_CTL_DISABLE	(0)
#define AW88395_AGC_DSP_CTL_DISABLE_VALUE	\
	(AW88395_AGC_DSP_CTL_DISABLE << AW88395_AGC_DSP_CTL_START_BIT)

#define AW88395_AGC_DSP_CTL_ENABLE	(1)
#define AW88395_AGC_DSP_CTL_ENABLE_VALUE	\
	(AW88395_AGC_DSP_CTL_ENABLE << AW88395_AGC_DSP_CTL_START_BIT)

#define AW88395_VDSEL_START_BIT	(0)
#define AW88395_VDSEL_BITS_LEN		(1)
#define AW88395_VDSEL_MASK		\
	(~(((1<<AW88395_VDSEL_BITS_LEN)-1) << AW88395_VDSEL_START_BIT))

#define AW88395_MEM_CLKSEL_START_BIT	(3)
#define AW88395_MEM_CLKSEL_BITS_LEN	(1)
#define AW88395_MEM_CLKSEL_MASK		\
	(~(((1<<AW88395_MEM_CLKSEL_BITS_LEN)-1) << AW88395_MEM_CLKSEL_START_BIT))

#define AW88395_MEM_CLKSEL_OSC_CLK	(0)
#define AW88395_MEM_CLKSEL_OSC_CLK_VALUE	\
	(AW88395_MEM_CLKSEL_OSC_CLK << AW88395_MEM_CLKSEL_START_BIT)

#define AW88395_MEM_CLKSEL_DAP_HCLK	(1)
#define AW88395_MEM_CLKSEL_DAP_HCLK_VALUE	\
	(AW88395_MEM_CLKSEL_DAP_HCLK << AW88395_MEM_CLKSEL_START_BIT)

#define AW88395_CCO_MUX_START_BIT	(14)
#define AW88395_CCO_MUX_BITS_LEN	(1)
#define AW88395_CCO_MUX_MASK		\
	(~(((1<<AW88395_CCO_MUX_BITS_LEN)-1) << AW88395_CCO_MUX_START_BIT))

#define AW88395_CCO_MUX_DIVIDED	(0)
#define AW88395_CCO_MUX_DIVIDED_VALUE	\
	(AW88395_CCO_MUX_DIVIDED << AW88395_CCO_MUX_START_BIT)

#define AW88395_CCO_MUX_BYPASS		(1)
#define AW88395_CCO_MUX_BYPASS_VALUE	\
	(AW88395_CCO_MUX_BYPASS << AW88395_CCO_MUX_START_BIT)

#define AW88395_EF_VSN_GESLP_START_BIT	(0)
#define AW88395_EF_VSN_GESLP_BITS_LEN	(10)
#define AW88395_EF_VSN_GESLP_MASK	\
	(~(((1<<AW88395_EF_VSN_GESLP_BITS_LEN)-1) << AW88395_EF_VSN_GESLP_START_BIT))

#define AW88395_EF_VSN_GESLP_SIGN_MASK	(~(1 << 9))
#define AW88395_EF_VSN_GESLP_SIGN_NEG	(0xfe00)

#define AW88395_EF_ISN_GESLP_START_BIT	(0)
#define AW88395_EF_ISN_GESLP_BITS_LEN	(10)
#define AW88395_EF_ISN_GESLP_MASK	\
	(~(((1<<AW88395_EF_ISN_GESLP_BITS_LEN)-1) << AW88395_EF_ISN_GESLP_START_BIT))

#define AW88395_EF_ISN_GESLP_SIGN_MASK	(~(1 << 9))
#define AW88395_EF_ISN_GESLP_SIGN_NEG	(0xfe00)

#define AW88395_CABL_BASE_VALUE	(1000)
#define AW88395_ICABLK_FACTOR		(1)
#define AW88395_VCABLK_FACTOR		(1)
#define AW88395_VCAL_FACTOR		(1 << 12)
#define AW88395_VSCAL_FACTOR		(16500)
#define AW88395_ISCAL_FACTOR		(3667)
#define AW88395_EF_VSENSE_GAIN_SHIFT	(0)

#define AW88395_VCABLK_FACTOR_DAC	(2)
#define AW88395_VSCAL_FACTOR_DAC	(11790)
#define AW88395_EF_DAC_GESLP_SHIFT	(10)
#define AW88395_EF_DAC_GESLP_SIGN_MASK	(1 << 5)
#define AW88395_EF_DAC_GESLP_SIGN_NEG	(0xffc0)

#define AW88395_VCALB_ADJ_FACTOR	(12)

#define AW88395_WDT_CNT_START_BIT	(0)
#define AW88395_WDT_CNT_BITS_LEN	(8)
#define AW88395_WDT_CNT_MASK		\
	(~(((1<<AW88395_WDT_CNT_BITS_LEN)-1) << AW88395_WDT_CNT_START_BIT))

#define AW88395_DSP_CFG_ADDR		(0x9C80)
#define AW88395_DSP_FW_ADDR		(0x8C00)
#define AW88395_DSP_REG_VMAX		(0x9C94)
#define AW88395_DSP_REG_CFG_ADPZ_RE	(0x9D00)
#define AW88395_DSP_REG_VCALB		(0x9CF7)
#define AW88395_DSP_RE_SHIFT		(12)

#define AW88395_DSP_REG_CFG_ADPZ_RA	(0x9D02)
#define AW88395_DSP_REG_CRC_ADDR	(0x9F42)
#define AW88395_DSP_CALI_F0_DELAY	(0x9CFD)

#endif
