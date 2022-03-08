/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * DRA7xx CM2 instance offset macros
 *
 * Copyright (C) 2013 Texas Instruments Incorporated - https://www.ti.com
 *
 * Generated by code originally written by:
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

#ifndef __ARCH_ARM_MACH_OMAP2_CM2_7XX_H
#define __ARCH_ARM_MACH_OMAP2_CM2_7XX_H

/* CM2 base address */
#define DRA7XX_CM_CORE_BASE		0x4a008000

#define DRA7XX_CM_CORE_REGADDR(inst, reg)				\
	OMAP2_L4_IO_ADDRESS(DRA7XX_CM_CORE_BASE + (inst) + (reg))

/* CM_CORE instances */
#define DRA7XX_CM_CORE_OCP_SOCKET_INST	0x0000
#define DRA7XX_CM_CORE_CKGEN_INST	0x0104
#define DRA7XX_CM_CORE_COREAON_INST	0x0600
#define DRA7XX_CM_CORE_CORE_INST	0x0700
#define DRA7XX_CM_CORE_IVA_INST		0x0f00
#define DRA7XX_CM_CORE_CAM_INST		0x1000
#define DRA7XX_CM_CORE_DSS_INST		0x1100
#define DRA7XX_CM_CORE_GPU_INST		0x1200
#define DRA7XX_CM_CORE_L3INIT_INST	0x1300
#define DRA7XX_CM_CORE_CUSTEFUSE_INST	0x1600
#define DRA7XX_CM_CORE_L4PER_INST	0x1700

/* CM_CORE clockdomain register offsets (from instance start) */
#define DRA7XX_CM_CORE_COREAON_COREAON_CDOFFS		0x0000
#define DRA7XX_CM_CORE_CORE_L3MAIN1_CDOFFS		0x0000
#define DRA7XX_CM_CORE_CORE_IPU2_CDOFFS			0x0200
#define DRA7XX_CM_CORE_CORE_DMA_CDOFFS			0x0300
#define DRA7XX_CM_CORE_CORE_EMIF_CDOFFS			0x0400
#define DRA7XX_CM_CORE_CORE_ATL_CDOFFS			0x0520
#define DRA7XX_CM_CORE_CORE_L4CFG_CDOFFS		0x0600
#define DRA7XX_CM_CORE_CORE_L3INSTR_CDOFFS		0x0700
#define DRA7XX_CM_CORE_IVA_IVA_CDOFFS			0x0000
#define DRA7XX_CM_CORE_CAM_CAM_CDOFFS			0x0000
#define DRA7XX_CM_CORE_DSS_DSS_CDOFFS			0x0000
#define DRA7XX_CM_CORE_GPU_GPU_CDOFFS			0x0000
#define DRA7XX_CM_CORE_L3INIT_L3INIT_CDOFFS		0x0000
#define DRA7XX_CM_CORE_L3INIT_PCIE_CDOFFS		0x00a0
#define DRA7XX_CM_CORE_L3INIT_GMAC_CDOFFS		0x00c0
#define DRA7XX_CM_CORE_CUSTEFUSE_CUSTEFUSE_CDOFFS	0x0000
#define DRA7XX_CM_CORE_L4PER_L4PER_CDOFFS		0x0000
#define DRA7XX_CM_CORE_L4PER_L4SEC_CDOFFS		0x0180
#define DRA7XX_CM_CORE_L4PER_L4PER2_CDOFFS		0x01fc
#define DRA7XX_CM_CORE_L4PER_L4PER3_CDOFFS		0x0210

#endif
