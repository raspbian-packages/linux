/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * OMAP54xx CM2 instance offset macros
 *
 * Copyright (C) 2013 Texas Instruments Incorporated - https://www.ti.com
 *
 * Paul Walmsley (paul@pwsan.com)
 * Rajendra Nayak (rnayak@ti.com)
 * Benoit Cousson (b-cousson@ti.com)
 *
 * This file is automatically generated from the OMAP hardware databases.
 * We respectfully ask that any modifications to this file be coordinated
 * with the public linux-omap@vger.kernel.org mailing list and the
 * authors above to ensure that the autogeneration scripts are kept
 * up-to-date with the file contents.
 */

#ifndef __ARCH_ARM_MACH_OMAP2_CM2_54XX_H
#define __ARCH_ARM_MACH_OMAP2_CM2_54XX_H

/* CM2 base address */
#define OMAP54XX_CM_CORE_BASE		0x4a008000

#define OMAP54XX_CM_CORE_REGADDR(inst, reg)				\
	OMAP2_L4_IO_ADDRESS(OMAP54XX_CM_CORE_BASE + (inst) + (reg))

/* CM_CORE instances */
#define OMAP54XX_CM_CORE_OCP_SOCKET_INST	0x0000
#define OMAP54XX_CM_CORE_CKGEN_INST		0x0100
#define OMAP54XX_CM_CORE_COREAON_INST		0x0600
#define OMAP54XX_CM_CORE_CORE_INST		0x0700
#define OMAP54XX_CM_CORE_IVA_INST		0x1200
#define OMAP54XX_CM_CORE_CAM_INST		0x1300
#define OMAP54XX_CM_CORE_DSS_INST		0x1400
#define OMAP54XX_CM_CORE_GPU_INST		0x1500
#define OMAP54XX_CM_CORE_L3INIT_INST		0x1600
#define OMAP54XX_CM_CORE_CUSTEFUSE_INST		0x1700
#define OMAP54XX_CM_CORE_RESTORE_INST		0x1e00
#define OMAP54XX_CM_CORE_INSTR_INST		0x1f00

/* CM_CORE clockdomain register offsets (from instance start) */
#define OMAP54XX_CM_CORE_COREAON_COREAON_CDOFFS		0x0000
#define OMAP54XX_CM_CORE_CORE_L3MAIN1_CDOFFS		0x0000
#define OMAP54XX_CM_CORE_CORE_L3MAIN2_CDOFFS		0x0100
#define OMAP54XX_CM_CORE_CORE_IPU_CDOFFS		0x0200
#define OMAP54XX_CM_CORE_CORE_DMA_CDOFFS		0x0300
#define OMAP54XX_CM_CORE_CORE_EMIF_CDOFFS		0x0400
#define OMAP54XX_CM_CORE_CORE_C2C_CDOFFS		0x0500
#define OMAP54XX_CM_CORE_CORE_L4CFG_CDOFFS		0x0600
#define OMAP54XX_CM_CORE_CORE_L3INSTR_CDOFFS		0x0700
#define OMAP54XX_CM_CORE_CORE_MIPIEXT_CDOFFS		0x0800
#define OMAP54XX_CM_CORE_CORE_L4PER_CDOFFS		0x0900
#define OMAP54XX_CM_CORE_CORE_L4SEC_CDOFFS		0x0a80
#define OMAP54XX_CM_CORE_IVA_IVA_CDOFFS			0x0000
#define OMAP54XX_CM_CORE_CAM_CAM_CDOFFS			0x0000
#define OMAP54XX_CM_CORE_DSS_DSS_CDOFFS			0x0000
#define OMAP54XX_CM_CORE_GPU_GPU_CDOFFS			0x0000
#define OMAP54XX_CM_CORE_L3INIT_L3INIT_CDOFFS		0x0000
#define OMAP54XX_CM_CORE_CUSTEFUSE_CUSTEFUSE_CDOFFS	0x0000

/* CM_CORE */

/* CM_CORE.OCP_SOCKET_CM_CORE register offsets */
#define OMAP54XX_REVISION_CM_CORE_OFFSET			0x0000
#define OMAP54XX_CM_CM_CORE_PROFILING_CLKCTRL_OFFSET		0x0040
#define OMAP54XX_CM_CM_CORE_PROFILING_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_OCP_SOCKET_INST, 0x0040)
#define OMAP54XX_CM_CORE_DEBUG_CFG_OFFSET			0x0080
#define OMAP54XX_CM_CORE_DEBUG_OUT_OFFSET			0x0084

/* CM_CORE.CKGEN_CM_CORE register offsets */
#define OMAP54XX_CM_CLKSEL_USB_60MHZ_OFFSET			0x0004
#define OMAP54XX_CM_CLKSEL_USB_60MHZ				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0004)
#define OMAP54XX_CM_CLKMODE_DPLL_PER_OFFSET			0x0040
#define OMAP54XX_CM_CLKMODE_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0040)
#define OMAP54XX_CM_IDLEST_DPLL_PER_OFFSET			0x0044
#define OMAP54XX_CM_IDLEST_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0044)
#define OMAP54XX_CM_AUTOIDLE_DPLL_PER_OFFSET			0x0048
#define OMAP54XX_CM_AUTOIDLE_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0048)
#define OMAP54XX_CM_CLKSEL_DPLL_PER_OFFSET			0x004c
#define OMAP54XX_CM_CLKSEL_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x004c)
#define OMAP54XX_CM_DIV_M2_DPLL_PER_OFFSET			0x0050
#define OMAP54XX_CM_DIV_M2_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0050)
#define OMAP54XX_CM_DIV_M3_DPLL_PER_OFFSET			0x0054
#define OMAP54XX_CM_DIV_M3_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0054)
#define OMAP54XX_CM_DIV_H11_DPLL_PER_OFFSET			0x0058
#define OMAP54XX_CM_DIV_H11_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0058)
#define OMAP54XX_CM_DIV_H12_DPLL_PER_OFFSET			0x005c
#define OMAP54XX_CM_DIV_H12_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x005c)
#define OMAP54XX_CM_DIV_H13_DPLL_PER_OFFSET			0x0060
#define OMAP54XX_CM_DIV_H13_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0060)
#define OMAP54XX_CM_DIV_H14_DPLL_PER_OFFSET			0x0064
#define OMAP54XX_CM_DIV_H14_DPLL_PER				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0064)
#define OMAP54XX_CM_SSC_DELTAMSTEP_DPLL_PER_OFFSET		0x0068
#define OMAP54XX_CM_SSC_MODFREQDIV_DPLL_PER_OFFSET		0x006c
#define OMAP54XX_CM_CLKMODE_DPLL_USB_OFFSET			0x0080
#define OMAP54XX_CM_CLKMODE_DPLL_USB				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0080)
#define OMAP54XX_CM_IDLEST_DPLL_USB_OFFSET			0x0084
#define OMAP54XX_CM_IDLEST_DPLL_USB				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0084)
#define OMAP54XX_CM_AUTOIDLE_DPLL_USB_OFFSET			0x0088
#define OMAP54XX_CM_AUTOIDLE_DPLL_USB				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0088)
#define OMAP54XX_CM_CLKSEL_DPLL_USB_OFFSET			0x008c
#define OMAP54XX_CM_CLKSEL_DPLL_USB				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x008c)
#define OMAP54XX_CM_DIV_M2_DPLL_USB_OFFSET			0x0090
#define OMAP54XX_CM_DIV_M2_DPLL_USB				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0090)
#define OMAP54XX_CM_SSC_DELTAMSTEP_DPLL_USB_OFFSET		0x00a8
#define OMAP54XX_CM_SSC_MODFREQDIV_DPLL_USB_OFFSET		0x00ac
#define OMAP54XX_CM_CLKDCOLDO_DPLL_USB_OFFSET			0x00b4
#define OMAP54XX_CM_CLKDCOLDO_DPLL_USB				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x00b4)
#define OMAP54XX_CM_CLKMODE_DPLL_UNIPRO2_OFFSET			0x00c0
#define OMAP54XX_CM_CLKMODE_DPLL_UNIPRO2			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x00c0)
#define OMAP54XX_CM_IDLEST_DPLL_UNIPRO2_OFFSET			0x00c4
#define OMAP54XX_CM_IDLEST_DPLL_UNIPRO2				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x00c4)
#define OMAP54XX_CM_AUTOIDLE_DPLL_UNIPRO2_OFFSET		0x00c8
#define OMAP54XX_CM_AUTOIDLE_DPLL_UNIPRO2			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x00c8)
#define OMAP54XX_CM_CLKSEL_DPLL_UNIPRO2_OFFSET			0x00cc
#define OMAP54XX_CM_CLKSEL_DPLL_UNIPRO2				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x00cc)
#define OMAP54XX_CM_DIV_M2_DPLL_UNIPRO2_OFFSET			0x00d0
#define OMAP54XX_CM_DIV_M2_DPLL_UNIPRO2				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x00d0)
#define OMAP54XX_CM_SSC_DELTAMSTEP_DPLL_UNIPRO2_OFFSET		0x00e8
#define OMAP54XX_CM_SSC_MODFREQDIV_DPLL_UNIPRO2_OFFSET		0x00ec
#define OMAP54XX_CM_CLKDCOLDO_DPLL_UNIPRO2_OFFSET		0x00f4
#define OMAP54XX_CM_CLKDCOLDO_DPLL_UNIPRO2			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x00f4)
#define OMAP54XX_CM_CLKMODE_DPLL_UNIPRO1_OFFSET			0x0100
#define OMAP54XX_CM_CLKMODE_DPLL_UNIPRO1			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0100)
#define OMAP54XX_CM_IDLEST_DPLL_UNIPRO1_OFFSET			0x0104
#define OMAP54XX_CM_IDLEST_DPLL_UNIPRO1				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0104)
#define OMAP54XX_CM_AUTOIDLE_DPLL_UNIPRO1_OFFSET		0x0108
#define OMAP54XX_CM_AUTOIDLE_DPLL_UNIPRO1			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0108)
#define OMAP54XX_CM_CLKSEL_DPLL_UNIPRO1_OFFSET			0x010c
#define OMAP54XX_CM_CLKSEL_DPLL_UNIPRO1				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x010c)
#define OMAP54XX_CM_DIV_M2_DPLL_UNIPRO1_OFFSET			0x0110
#define OMAP54XX_CM_DIV_M2_DPLL_UNIPRO1				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0110)
#define OMAP54XX_CM_SSC_DELTAMSTEP_DPLL_UNIPRO1_OFFSET		0x0128
#define OMAP54XX_CM_SSC_MODFREQDIV_DPLL_UNIPRO1_OFFSET		0x012c
#define OMAP54XX_CM_CLKDCOLDO_DPLL_UNIPRO1_OFFSET		0x0134
#define OMAP54XX_CM_CLKDCOLDO_DPLL_UNIPRO1			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CKGEN_INST, 0x0134)

/* CM_CORE.COREAON_CM_CORE register offsets */
#define OMAP54XX_CM_COREAON_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_COREAON_SMARTREFLEX_MPU_CLKCTRL_OFFSET	0x0028
#define OMAP54XX_CM_COREAON_SMARTREFLEX_MPU_CLKCTRL		OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_COREAON_INST, 0x0028)
#define OMAP54XX_CM_COREAON_SMARTREFLEX_MM_CLKCTRL_OFFSET	0x0030
#define OMAP54XX_CM_COREAON_SMARTREFLEX_MM_CLKCTRL		OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_COREAON_INST, 0x0030)
#define OMAP54XX_CM_COREAON_SMARTREFLEX_CORE_CLKCTRL_OFFSET	0x0038
#define OMAP54XX_CM_COREAON_SMARTREFLEX_CORE_CLKCTRL		OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_COREAON_INST, 0x0038)
#define OMAP54XX_CM_COREAON_USB_PHY_CORE_CLKCTRL_OFFSET		0x0040
#define OMAP54XX_CM_COREAON_USB_PHY_CORE_CLKCTRL		OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_COREAON_INST, 0x0040)
#define OMAP54XX_CM_COREAON_IO_SRCOMP_CLKCTRL_OFFSET		0x0050
#define OMAP54XX_CM_COREAON_IO_SRCOMP_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_COREAON_INST, 0x0050)

/* CM_CORE.CORE_CM_CORE register offsets */
#define OMAP54XX_CM_L3MAIN1_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_L3MAIN1_DYNAMICDEP_OFFSET			0x0008
#define OMAP54XX_CM_L3MAIN1_L3_MAIN_1_CLKCTRL_OFFSET		0x0020
#define OMAP54XX_CM_L3MAIN1_L3_MAIN_1_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0020)
#define OMAP54XX_CM_L3MAIN2_CLKSTCTRL_OFFSET			0x0100
#define OMAP54XX_CM_L3MAIN2_DYNAMICDEP_OFFSET			0x0108
#define OMAP54XX_CM_L3MAIN2_L3_MAIN_2_CLKCTRL_OFFSET		0x0120
#define OMAP54XX_CM_L3MAIN2_L3_MAIN_2_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0120)
#define OMAP54XX_CM_L3MAIN2_GPMC_CLKCTRL_OFFSET			0x0128
#define OMAP54XX_CM_L3MAIN2_GPMC_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0128)
#define OMAP54XX_CM_L3MAIN2_OCMC_RAM_CLKCTRL_OFFSET		0x0130
#define OMAP54XX_CM_L3MAIN2_OCMC_RAM_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0130)
#define OMAP54XX_CM_IPU_CLKSTCTRL_OFFSET			0x0200
#define OMAP54XX_CM_IPU_STATICDEP_OFFSET			0x0204
#define OMAP54XX_CM_IPU_DYNAMICDEP_OFFSET			0x0208
#define OMAP54XX_CM_IPU_IPU_CLKCTRL_OFFSET			0x0220
#define OMAP54XX_CM_IPU_IPU_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0220)
#define OMAP54XX_CM_DMA_CLKSTCTRL_OFFSET			0x0300
#define OMAP54XX_CM_DMA_STATICDEP_OFFSET			0x0304
#define OMAP54XX_CM_DMA_DYNAMICDEP_OFFSET			0x0308
#define OMAP54XX_CM_DMA_DMA_SYSTEM_CLKCTRL_OFFSET		0x0320
#define OMAP54XX_CM_DMA_DMA_SYSTEM_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0320)
#define OMAP54XX_CM_EMIF_CLKSTCTRL_OFFSET			0x0400
#define OMAP54XX_CM_EMIF_DMM_CLKCTRL_OFFSET			0x0420
#define OMAP54XX_CM_EMIF_DMM_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0420)
#define OMAP54XX_CM_EMIF_EMIF_OCP_FW_CLKCTRL_OFFSET		0x0428
#define OMAP54XX_CM_EMIF_EMIF_OCP_FW_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0428)
#define OMAP54XX_CM_EMIF_EMIF1_CLKCTRL_OFFSET			0x0430
#define OMAP54XX_CM_EMIF_EMIF1_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0430)
#define OMAP54XX_CM_EMIF_EMIF2_CLKCTRL_OFFSET			0x0438
#define OMAP54XX_CM_EMIF_EMIF2_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0438)
#define OMAP54XX_CM_EMIF_EMIF_DLL_CLKCTRL_OFFSET		0x0440
#define OMAP54XX_CM_EMIF_EMIF_DLL_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0440)
#define OMAP54XX_CM_C2C_CLKSTCTRL_OFFSET			0x0500
#define OMAP54XX_CM_C2C_STATICDEP_OFFSET			0x0504
#define OMAP54XX_CM_C2C_DYNAMICDEP_OFFSET			0x0508
#define OMAP54XX_CM_C2C_C2C_CLKCTRL_OFFSET			0x0520
#define OMAP54XX_CM_C2C_C2C_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0520)
#define OMAP54XX_CM_C2C_MODEM_ICR_CLKCTRL_OFFSET		0x0528
#define OMAP54XX_CM_C2C_MODEM_ICR_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0528)
#define OMAP54XX_CM_C2C_C2C_OCP_FW_CLKCTRL_OFFSET		0x0530
#define OMAP54XX_CM_C2C_C2C_OCP_FW_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0530)
#define OMAP54XX_CM_L4CFG_CLKSTCTRL_OFFSET			0x0600
#define OMAP54XX_CM_L4CFG_DYNAMICDEP_OFFSET			0x0608
#define OMAP54XX_CM_L4CFG_L4_CFG_CLKCTRL_OFFSET			0x0620
#define OMAP54XX_CM_L4CFG_L4_CFG_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0620)
#define OMAP54XX_CM_L4CFG_SPINLOCK_CLKCTRL_OFFSET		0x0628
#define OMAP54XX_CM_L4CFG_SPINLOCK_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0628)
#define OMAP54XX_CM_L4CFG_MAILBOX_CLKCTRL_OFFSET		0x0630
#define OMAP54XX_CM_L4CFG_MAILBOX_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0630)
#define OMAP54XX_CM_L4CFG_SAR_ROM_CLKCTRL_OFFSET		0x0638
#define OMAP54XX_CM_L4CFG_SAR_ROM_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0638)
#define OMAP54XX_CM_L4CFG_OCP2SCP2_CLKCTRL_OFFSET		0x0640
#define OMAP54XX_CM_L4CFG_OCP2SCP2_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0640)
#define OMAP54XX_CM_L3INSTR_CLKSTCTRL_OFFSET			0x0700
#define OMAP54XX_CM_L3INSTR_L3_MAIN_3_CLKCTRL_OFFSET		0x0720
#define OMAP54XX_CM_L3INSTR_L3_MAIN_3_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0720)
#define OMAP54XX_CM_L3INSTR_L3_INSTR_CLKCTRL_OFFSET		0x0728
#define OMAP54XX_CM_L3INSTR_L3_INSTR_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0728)
#define OMAP54XX_CM_L3INSTR_OCP_WP_NOC_CLKCTRL_OFFSET		0x0740
#define OMAP54XX_CM_L3INSTR_OCP_WP_NOC_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0740)
#define OMAP54XX_CM_L3INSTR_DLL_AGING_CLKCTRL_OFFSET		0x0748
#define OMAP54XX_CM_L3INSTR_DLL_AGING_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0748)
#define OMAP54XX_CM_L3INSTR_CTRL_MODULE_BANDGAP_CLKCTRL_OFFSET	0x0750
#define OMAP54XX_CM_L3INSTR_CTRL_MODULE_BANDGAP_CLKCTRL		OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0750)
#define OMAP54XX_CM_MIPIEXT_CLKSTCTRL_OFFSET			0x0800
#define OMAP54XX_CM_MIPIEXT_STATICDEP_OFFSET			0x0804
#define OMAP54XX_CM_MIPIEXT_DYNAMICDEP_OFFSET			0x0808
#define OMAP54XX_CM_MIPIEXT_LLI_CLKCTRL_OFFSET			0x0820
#define OMAP54XX_CM_MIPIEXT_LLI_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0820)
#define OMAP54XX_CM_MIPIEXT_LLI_OCP_FW_CLKCTRL_OFFSET		0x0828
#define OMAP54XX_CM_MIPIEXT_LLI_OCP_FW_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0828)
#define OMAP54XX_CM_MIPIEXT_MPHY_CLKCTRL_OFFSET			0x0830
#define OMAP54XX_CM_MIPIEXT_MPHY_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0830)
#define OMAP54XX_CM_L4PER_CLKSTCTRL_OFFSET			0x0900
#define OMAP54XX_CM_L4PER_DYNAMICDEP_OFFSET			0x0908
#define OMAP54XX_CM_L4PER_TIMER10_CLKCTRL_OFFSET		0x0928
#define OMAP54XX_CM_L4PER_TIMER10_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0928)
#define OMAP54XX_CM_L4PER_TIMER11_CLKCTRL_OFFSET		0x0930
#define OMAP54XX_CM_L4PER_TIMER11_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0930)
#define OMAP54XX_CM_L4PER_TIMER2_CLKCTRL_OFFSET			0x0938
#define OMAP54XX_CM_L4PER_TIMER2_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0938)
#define OMAP54XX_CM_L4PER_TIMER3_CLKCTRL_OFFSET			0x0940
#define OMAP54XX_CM_L4PER_TIMER3_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0940)
#define OMAP54XX_CM_L4PER_TIMER4_CLKCTRL_OFFSET			0x0948
#define OMAP54XX_CM_L4PER_TIMER4_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0948)
#define OMAP54XX_CM_L4PER_TIMER9_CLKCTRL_OFFSET			0x0950
#define OMAP54XX_CM_L4PER_TIMER9_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0950)
#define OMAP54XX_CM_L4PER_ELM_CLKCTRL_OFFSET			0x0958
#define OMAP54XX_CM_L4PER_ELM_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0958)
#define OMAP54XX_CM_L4PER_GPIO2_CLKCTRL_OFFSET			0x0960
#define OMAP54XX_CM_L4PER_GPIO2_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0960)
#define OMAP54XX_CM_L4PER_GPIO3_CLKCTRL_OFFSET			0x0968
#define OMAP54XX_CM_L4PER_GPIO3_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0968)
#define OMAP54XX_CM_L4PER_GPIO4_CLKCTRL_OFFSET			0x0970
#define OMAP54XX_CM_L4PER_GPIO4_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0970)
#define OMAP54XX_CM_L4PER_GPIO5_CLKCTRL_OFFSET			0x0978
#define OMAP54XX_CM_L4PER_GPIO5_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0978)
#define OMAP54XX_CM_L4PER_GPIO6_CLKCTRL_OFFSET			0x0980
#define OMAP54XX_CM_L4PER_GPIO6_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0980)
#define OMAP54XX_CM_L4PER_HDQ1W_CLKCTRL_OFFSET			0x0988
#define OMAP54XX_CM_L4PER_HDQ1W_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0988)
#define OMAP54XX_CM_L4PER_I2C1_CLKCTRL_OFFSET			0x09a0
#define OMAP54XX_CM_L4PER_I2C1_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x09a0)
#define OMAP54XX_CM_L4PER_I2C2_CLKCTRL_OFFSET			0x09a8
#define OMAP54XX_CM_L4PER_I2C2_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x09a8)
#define OMAP54XX_CM_L4PER_I2C3_CLKCTRL_OFFSET			0x09b0
#define OMAP54XX_CM_L4PER_I2C3_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x09b0)
#define OMAP54XX_CM_L4PER_I2C4_CLKCTRL_OFFSET			0x09b8
#define OMAP54XX_CM_L4PER_I2C4_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x09b8)
#define OMAP54XX_CM_L4PER_L4_PER_CLKCTRL_OFFSET			0x09c0
#define OMAP54XX_CM_L4PER_L4_PER_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x09c0)
#define OMAP54XX_CM_L4PER_MCSPI1_CLKCTRL_OFFSET			0x09f0
#define OMAP54XX_CM_L4PER_MCSPI1_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x09f0)
#define OMAP54XX_CM_L4PER_MCSPI2_CLKCTRL_OFFSET			0x09f8
#define OMAP54XX_CM_L4PER_MCSPI2_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x09f8)
#define OMAP54XX_CM_L4PER_MCSPI3_CLKCTRL_OFFSET			0x0a00
#define OMAP54XX_CM_L4PER_MCSPI3_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a00)
#define OMAP54XX_CM_L4PER_MCSPI4_CLKCTRL_OFFSET			0x0a08
#define OMAP54XX_CM_L4PER_MCSPI4_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a08)
#define OMAP54XX_CM_L4PER_GPIO7_CLKCTRL_OFFSET			0x0a10
#define OMAP54XX_CM_L4PER_GPIO7_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a10)
#define OMAP54XX_CM_L4PER_GPIO8_CLKCTRL_OFFSET			0x0a18
#define OMAP54XX_CM_L4PER_GPIO8_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a18)
#define OMAP54XX_CM_L4PER_MMC3_CLKCTRL_OFFSET			0x0a20
#define OMAP54XX_CM_L4PER_MMC3_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a20)
#define OMAP54XX_CM_L4PER_MMC4_CLKCTRL_OFFSET			0x0a28
#define OMAP54XX_CM_L4PER_MMC4_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a28)
#define OMAP54XX_CM_L4PER_UART1_CLKCTRL_OFFSET			0x0a40
#define OMAP54XX_CM_L4PER_UART1_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a40)
#define OMAP54XX_CM_L4PER_UART2_CLKCTRL_OFFSET			0x0a48
#define OMAP54XX_CM_L4PER_UART2_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a48)
#define OMAP54XX_CM_L4PER_UART3_CLKCTRL_OFFSET			0x0a50
#define OMAP54XX_CM_L4PER_UART3_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a50)
#define OMAP54XX_CM_L4PER_UART4_CLKCTRL_OFFSET			0x0a58
#define OMAP54XX_CM_L4PER_UART4_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a58)
#define OMAP54XX_CM_L4PER_MMC5_CLKCTRL_OFFSET			0x0a60
#define OMAP54XX_CM_L4PER_MMC5_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a60)
#define OMAP54XX_CM_L4PER_I2C5_CLKCTRL_OFFSET			0x0a68
#define OMAP54XX_CM_L4PER_I2C5_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a68)
#define OMAP54XX_CM_L4PER_UART5_CLKCTRL_OFFSET			0x0a70
#define OMAP54XX_CM_L4PER_UART5_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a70)
#define OMAP54XX_CM_L4PER_UART6_CLKCTRL_OFFSET			0x0a78
#define OMAP54XX_CM_L4PER_UART6_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0a78)
#define OMAP54XX_CM_L4SEC_CLKSTCTRL_OFFSET			0x0a80
#define OMAP54XX_CM_L4SEC_STATICDEP_OFFSET			0x0a84
#define OMAP54XX_CM_L4SEC_DYNAMICDEP_OFFSET			0x0a88
#define OMAP54XX_CM_L4SEC_AES1_CLKCTRL_OFFSET			0x0aa0
#define OMAP54XX_CM_L4SEC_AES1_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0aa0)
#define OMAP54XX_CM_L4SEC_AES2_CLKCTRL_OFFSET			0x0aa8
#define OMAP54XX_CM_L4SEC_AES2_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0aa8)
#define OMAP54XX_CM_L4SEC_DES3DES_CLKCTRL_OFFSET		0x0ab0
#define OMAP54XX_CM_L4SEC_DES3DES_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0ab0)
#define OMAP54XX_CM_L4SEC_FPKA_CLKCTRL_OFFSET			0x0ab8
#define OMAP54XX_CM_L4SEC_FPKA_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0ab8)
#define OMAP54XX_CM_L4SEC_RNG_CLKCTRL_OFFSET			0x0ac0
#define OMAP54XX_CM_L4SEC_RNG_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0ac0)
#define OMAP54XX_CM_L4SEC_SHA2MD5_CLKCTRL_OFFSET		0x0ac8
#define OMAP54XX_CM_L4SEC_SHA2MD5_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0ac8)
#define OMAP54XX_CM_L4SEC_DMA_CRYPTO_CLKCTRL_OFFSET		0x0ad8
#define OMAP54XX_CM_L4SEC_DMA_CRYPTO_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CORE_INST, 0x0ad8)

/* CM_CORE.IVA_CM_CORE register offsets */
#define OMAP54XX_CM_IVA_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_IVA_STATICDEP_OFFSET			0x0004
#define OMAP54XX_CM_IVA_DYNAMICDEP_OFFSET			0x0008
#define OMAP54XX_CM_IVA_IVA_CLKCTRL_OFFSET			0x0020
#define OMAP54XX_CM_IVA_IVA_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_IVA_INST, 0x0020)
#define OMAP54XX_CM_IVA_SL2_CLKCTRL_OFFSET			0x0028
#define OMAP54XX_CM_IVA_SL2_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_IVA_INST, 0x0028)

/* CM_CORE.CAM_CM_CORE register offsets */
#define OMAP54XX_CM_CAM_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_CAM_STATICDEP_OFFSET			0x0004
#define OMAP54XX_CM_CAM_DYNAMICDEP_OFFSET			0x0008
#define OMAP54XX_CM_CAM_ISS_CLKCTRL_OFFSET			0x0020
#define OMAP54XX_CM_CAM_ISS_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CAM_INST, 0x0020)
#define OMAP54XX_CM_CAM_FDIF_CLKCTRL_OFFSET			0x0028
#define OMAP54XX_CM_CAM_FDIF_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CAM_INST, 0x0028)
#define OMAP54XX_CM_CAM_CAL_CLKCTRL_OFFSET			0x0030
#define OMAP54XX_CM_CAM_CAL_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CAM_INST, 0x0030)

/* CM_CORE.DSS_CM_CORE register offsets */
#define OMAP54XX_CM_DSS_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_DSS_STATICDEP_OFFSET			0x0004
#define OMAP54XX_CM_DSS_DYNAMICDEP_OFFSET			0x0008
#define OMAP54XX_CM_DSS_DSS_CLKCTRL_OFFSET			0x0020
#define OMAP54XX_CM_DSS_DSS_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_DSS_INST, 0x0020)
#define OMAP54XX_CM_DSS_BB2D_CLKCTRL_OFFSET			0x0030
#define OMAP54XX_CM_DSS_BB2D_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_DSS_INST, 0x0030)

/* CM_CORE.GPU_CM_CORE register offsets */
#define OMAP54XX_CM_GPU_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_GPU_STATICDEP_OFFSET			0x0004
#define OMAP54XX_CM_GPU_DYNAMICDEP_OFFSET			0x0008
#define OMAP54XX_CM_GPU_GPU_CLKCTRL_OFFSET			0x0020
#define OMAP54XX_CM_GPU_GPU_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_GPU_INST, 0x0020)

/* CM_CORE.L3INIT_CM_CORE register offsets */
#define OMAP54XX_CM_L3INIT_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_L3INIT_STATICDEP_OFFSET			0x0004
#define OMAP54XX_CM_L3INIT_DYNAMICDEP_OFFSET			0x0008
#define OMAP54XX_CM_L3INIT_MMC1_CLKCTRL_OFFSET			0x0028
#define OMAP54XX_CM_L3INIT_MMC1_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0028)
#define OMAP54XX_CM_L3INIT_MMC2_CLKCTRL_OFFSET			0x0030
#define OMAP54XX_CM_L3INIT_MMC2_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0030)
#define OMAP54XX_CM_L3INIT_HSI_CLKCTRL_OFFSET			0x0038
#define OMAP54XX_CM_L3INIT_HSI_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0038)
#define OMAP54XX_CM_L3INIT_UNIPRO2_CLKCTRL_OFFSET		0x0040
#define OMAP54XX_CM_L3INIT_UNIPRO2_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0040)
#define OMAP54XX_CM_L3INIT_MPHY_UNIPRO2_CLKCTRL_OFFSET		0x0048
#define OMAP54XX_CM_L3INIT_MPHY_UNIPRO2_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0048)
#define OMAP54XX_CM_L3INIT_USB_HOST_HS_CLKCTRL_OFFSET		0x0058
#define OMAP54XX_CM_L3INIT_USB_HOST_HS_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0058)
#define OMAP54XX_CM_L3INIT_USB_TLL_HS_CLKCTRL_OFFSET		0x0068
#define OMAP54XX_CM_L3INIT_USB_TLL_HS_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0068)
#define OMAP54XX_CM_L3INIT_IEEE1500_2_OCP_CLKCTRL_OFFSET	0x0078
#define OMAP54XX_CM_L3INIT_IEEE1500_2_OCP_CLKCTRL		OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0078)
#define OMAP54XX_CM_L3INIT_SATA_CLKCTRL_OFFSET			0x0088
#define OMAP54XX_CM_L3INIT_SATA_CLKCTRL				OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x0088)
#define OMAP54XX_CM_L3INIT_OCP2SCP1_CLKCTRL_OFFSET		0x00e0
#define OMAP54XX_CM_L3INIT_OCP2SCP1_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x00e0)
#define OMAP54XX_CM_L3INIT_OCP2SCP3_CLKCTRL_OFFSET		0x00e8
#define OMAP54XX_CM_L3INIT_OCP2SCP3_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x00e8)
#define OMAP54XX_CM_L3INIT_USB_OTG_SS_CLKCTRL_OFFSET		0x00f0
#define OMAP54XX_CM_L3INIT_USB_OTG_SS_CLKCTRL			OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_L3INIT_INST, 0x00f0)

/* CM_CORE.CUSTEFUSE_CM_CORE register offsets */
#define OMAP54XX_CM_CUSTEFUSE_CLKSTCTRL_OFFSET			0x0000
#define OMAP54XX_CM_CUSTEFUSE_EFUSE_CTRL_CUST_CLKCTRL_OFFSET	0x0020
#define OMAP54XX_CM_CUSTEFUSE_EFUSE_CTRL_CUST_CLKCTRL		OMAP54XX_CM_CORE_REGADDR(OMAP54XX_CM_CORE_CUSTEFUSE_INST, 0x0020)

#endif
