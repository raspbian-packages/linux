/*
 * OMAP4 Clock domains framework
 *
 * Copyright (C) 2009-2011 Texas Instruments, Inc.
 * Copyright (C) 2009-2011 Nokia Corporation
 *
 * Abhijit Pagare (abhijitpagare@ti.com)
 * Benoit Cousson (b-cousson@ti.com)
 * Paul Walmsley (paul@pwsan.com)
 *
 * This file is automatically generated from the OMAP hardware databases.
 * We respectfully ask that any modifications to this file be coordinated
 * with the public linux-omap@vger.kernel.org mailing list and the
 * authors above to ensure that the autogeneration scripts are kept
 * up-to-date with the file contents.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/io.h>

#include "clockdomain.h"
#include "cm1_44xx.h"
#include "cm2_44xx.h"

#include "cm-regbits-44xx.h"
#include "prm44xx.h"
#include "prcm44xx.h"
#include "prcm_mpu44xx.h"

/* Static Dependencies for OMAP4 Clock Domains */

static struct clkdm_dep d2d_wkup_sleep_deps[] = {
	{ .clkdm_name = "abe_clkdm" },
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_2_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ .clkdm_name = "l3_init_clkdm" },
	{ .clkdm_name = "l4_cfg_clkdm" },
	{ .clkdm_name = "l4_per_clkdm" },
	{ NULL },
};

static struct clkdm_dep ducati_wkup_sleep_deps[] = {
	{ .clkdm_name = "abe_clkdm" },
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_2_clkdm" },
	{ .clkdm_name = "l3_dss_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ .clkdm_name = "l3_gfx_clkdm" },
	{ .clkdm_name = "l3_init_clkdm" },
	{ .clkdm_name = "l4_cfg_clkdm" },
	{ .clkdm_name = "l4_per_clkdm" },
	{ .clkdm_name = "l4_secure_clkdm" },
	{ .clkdm_name = "l4_wkup_clkdm" },
	{ .clkdm_name = "tesla_clkdm" },
	{ NULL },
};

static struct clkdm_dep iss_wkup_sleep_deps[] = {
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ NULL },
};

static struct clkdm_dep ivahd_wkup_sleep_deps[] = {
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ NULL },
};

static struct clkdm_dep l3_dma_wkup_sleep_deps[] = {
	{ .clkdm_name = "abe_clkdm" },
	{ .clkdm_name = "ducati_clkdm" },
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_dss_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ .clkdm_name = "l3_init_clkdm" },
	{ .clkdm_name = "l4_cfg_clkdm" },
	{ .clkdm_name = "l4_per_clkdm" },
	{ .clkdm_name = "l4_secure_clkdm" },
	{ .clkdm_name = "l4_wkup_clkdm" },
	{ NULL },
};

static struct clkdm_dep l3_dss_wkup_sleep_deps[] = {
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_2_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ NULL },
};

static struct clkdm_dep l3_gfx_wkup_sleep_deps[] = {
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ NULL },
};

static struct clkdm_dep l3_init_wkup_sleep_deps[] = {
	{ .clkdm_name = "abe_clkdm" },
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ .clkdm_name = "l4_cfg_clkdm" },
	{ .clkdm_name = "l4_per_clkdm" },
	{ .clkdm_name = "l4_secure_clkdm" },
	{ .clkdm_name = "l4_wkup_clkdm" },
	{ NULL },
};

static struct clkdm_dep l4_secure_wkup_sleep_deps[] = {
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ .clkdm_name = "l4_per_clkdm" },
	{ NULL },
};

static struct clkdm_dep mpu_wkup_sleep_deps[] = {
	{ .clkdm_name = "abe_clkdm" },
	{ .clkdm_name = "ducati_clkdm" },
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_2_clkdm" },
	{ .clkdm_name = "l3_dss_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ .clkdm_name = "l3_gfx_clkdm" },
	{ .clkdm_name = "l3_init_clkdm" },
	{ .clkdm_name = "l4_cfg_clkdm" },
	{ .clkdm_name = "l4_per_clkdm" },
	{ .clkdm_name = "l4_secure_clkdm" },
	{ .clkdm_name = "l4_wkup_clkdm" },
	{ .clkdm_name = "tesla_clkdm" },
	{ NULL },
};

static struct clkdm_dep tesla_wkup_sleep_deps[] = {
	{ .clkdm_name = "abe_clkdm" },
	{ .clkdm_name = "ivahd_clkdm" },
	{ .clkdm_name = "l3_1_clkdm" },
	{ .clkdm_name = "l3_2_clkdm" },
	{ .clkdm_name = "l3_emif_clkdm" },
	{ .clkdm_name = "l3_init_clkdm" },
	{ .clkdm_name = "l4_cfg_clkdm" },
	{ .clkdm_name = "l4_per_clkdm" },
	{ .clkdm_name = "l4_wkup_clkdm" },
	{ NULL },
};

static struct clockdomain l4_cefuse_44xx_clkdm = {
	.name		  = "l4_cefuse_clkdm",
	.pwrdm		  = { .name = "cefuse_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CEFUSE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CEFUSE_CEFUSE_CDOFFS,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

static struct clockdomain l4_cfg_44xx_clkdm = {
	.name		  = "l4_cfg_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_L4CFG_CDOFFS,
	.dep_bit	  = OMAP4430_L4CFG_STATDEP_SHIFT,
	.flags		  = CLKDM_CAN_HWSUP,
};

static struct clockdomain tesla_44xx_clkdm = {
	.name		  = "tesla_clkdm",
	.pwrdm		  = { .name = "tesla_pwrdm" },
	.prcm_partition	  = OMAP4430_CM1_PARTITION,
	.cm_inst	  = OMAP4430_CM1_TESLA_INST,
	.clkdm_offs	  = OMAP4430_CM1_TESLA_TESLA_CDOFFS,
	.dep_bit	  = OMAP4430_TESLA_STATDEP_SHIFT,
	.wkdep_srcs	  = tesla_wkup_sleep_deps,
	.sleepdep_srcs	  = tesla_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain l3_gfx_44xx_clkdm = {
	.name		  = "l3_gfx_clkdm",
	.pwrdm		  = { .name = "gfx_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_GFX_INST,
	.clkdm_offs	  = OMAP4430_CM2_GFX_GFX_CDOFFS,
	.dep_bit	  = OMAP4430_GFX_STATDEP_SHIFT,
	.wkdep_srcs	  = l3_gfx_wkup_sleep_deps,
	.sleepdep_srcs	  = l3_gfx_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain ivahd_44xx_clkdm = {
	.name		  = "ivahd_clkdm",
	.pwrdm		  = { .name = "ivahd_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_IVAHD_INST,
	.clkdm_offs	  = OMAP4430_CM2_IVAHD_IVAHD_CDOFFS,
	.dep_bit	  = OMAP4430_IVAHD_STATDEP_SHIFT,
	.wkdep_srcs	  = ivahd_wkup_sleep_deps,
	.sleepdep_srcs	  = ivahd_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain l4_secure_44xx_clkdm = {
	.name		  = "l4_secure_clkdm",
	.pwrdm		  = { .name = "l4per_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_L4PER_INST,
	.clkdm_offs	  = OMAP4430_CM2_L4PER_L4SEC_CDOFFS,
	.dep_bit	  = OMAP4430_L4SEC_STATDEP_SHIFT,
	.wkdep_srcs	  = l4_secure_wkup_sleep_deps,
	.sleepdep_srcs	  = l4_secure_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain l4_per_44xx_clkdm = {
	.name		  = "l4_per_clkdm",
	.pwrdm		  = { .name = "l4per_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_L4PER_INST,
	.clkdm_offs	  = OMAP4430_CM2_L4PER_L4PER_CDOFFS,
	.dep_bit	  = OMAP4430_L4PER_STATDEP_SHIFT,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain abe_44xx_clkdm = {
	.name		  = "abe_clkdm",
	.pwrdm		  = { .name = "abe_pwrdm" },
	.prcm_partition	  = OMAP4430_CM1_PARTITION,
	.cm_inst	  = OMAP4430_CM1_ABE_INST,
	.clkdm_offs	  = OMAP4430_CM1_ABE_ABE_CDOFFS,
	.dep_bit	  = OMAP4430_ABE_STATDEP_SHIFT,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain l3_instr_44xx_clkdm = {
	.name		  = "l3_instr_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_L3INSTR_CDOFFS,
};

static struct clockdomain l3_init_44xx_clkdm = {
	.name		  = "l3_init_clkdm",
	.pwrdm		  = { .name = "l3init_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_L3INIT_INST,
	.clkdm_offs	  = OMAP4430_CM2_L3INIT_L3INIT_CDOFFS,
	.dep_bit	  = OMAP4430_L3INIT_STATDEP_SHIFT,
	.wkdep_srcs	  = l3_init_wkup_sleep_deps,
	.sleepdep_srcs	  = l3_init_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain d2d_44xx_clkdm = {
	.name		  = "d2d_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_D2D_CDOFFS,
	.wkdep_srcs	  = d2d_wkup_sleep_deps,
	.sleepdep_srcs	  = d2d_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

static struct clockdomain mpu0_44xx_clkdm = {
	.name		  = "mpu0_clkdm",
	.pwrdm		  = { .name = "cpu0_pwrdm" },
	.prcm_partition	  = OMAP4430_PRCM_MPU_PARTITION,
	.cm_inst	  = OMAP4430_PRCM_MPU_CPU0_INST,
	.clkdm_offs	  = OMAP4430_PRCM_MPU_CPU0_CPU0_CDOFFS,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

static struct clockdomain mpu1_44xx_clkdm = {
	.name		  = "mpu1_clkdm",
	.pwrdm		  = { .name = "cpu1_pwrdm" },
	.prcm_partition	  = OMAP4430_PRCM_MPU_PARTITION,
	.cm_inst	  = OMAP4430_PRCM_MPU_CPU1_INST,
	.clkdm_offs	  = OMAP4430_PRCM_MPU_CPU1_CPU1_CDOFFS,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

static struct clockdomain l3_emif_44xx_clkdm = {
	.name		  = "l3_emif_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_MEMIF_CDOFFS,
	.dep_bit	  = OMAP4430_MEMIF_STATDEP_SHIFT,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

static struct clockdomain l4_ao_44xx_clkdm = {
	.name		  = "l4_ao_clkdm",
	.pwrdm		  = { .name = "always_on_core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_ALWAYS_ON_INST,
	.clkdm_offs	  = OMAP4430_CM2_ALWAYS_ON_ALWON_CDOFFS,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

static struct clockdomain ducati_44xx_clkdm = {
	.name		  = "ducati_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_DUCATI_CDOFFS,
	.dep_bit	  = OMAP4430_DUCATI_STATDEP_SHIFT,
	.wkdep_srcs	  = ducati_wkup_sleep_deps,
	.sleepdep_srcs	  = ducati_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain mpu_44xx_clkdm = {
	.name		  = "mpuss_clkdm",
	.pwrdm		  = { .name = "mpu_pwrdm" },
	.prcm_partition	  = OMAP4430_CM1_PARTITION,
	.cm_inst	  = OMAP4430_CM1_MPU_INST,
	.clkdm_offs	  = OMAP4430_CM1_MPU_MPU_CDOFFS,
	.wkdep_srcs	  = mpu_wkup_sleep_deps,
	.sleepdep_srcs	  = mpu_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

static struct clockdomain l3_2_44xx_clkdm = {
	.name		  = "l3_2_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_L3_2_CDOFFS,
	.dep_bit	  = OMAP4430_L3_2_STATDEP_SHIFT,
	.flags		  = CLKDM_CAN_HWSUP,
};

static struct clockdomain l3_1_44xx_clkdm = {
	.name		  = "l3_1_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_L3_1_CDOFFS,
	.dep_bit	  = OMAP4430_L3_1_STATDEP_SHIFT,
	.flags		  = CLKDM_CAN_HWSUP,
};

static struct clockdomain iss_44xx_clkdm = {
	.name		  = "iss_clkdm",
	.pwrdm		  = { .name = "cam_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CAM_INST,
	.clkdm_offs	  = OMAP4430_CM2_CAM_CAM_CDOFFS,
	.wkdep_srcs	  = iss_wkup_sleep_deps,
	.sleepdep_srcs	  = iss_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_SWSUP,
};

static struct clockdomain l3_dss_44xx_clkdm = {
	.name		  = "l3_dss_clkdm",
	.pwrdm		  = { .name = "dss_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_DSS_INST,
	.clkdm_offs	  = OMAP4430_CM2_DSS_DSS_CDOFFS,
	.dep_bit	  = OMAP4430_DSS_STATDEP_SHIFT,
	.wkdep_srcs	  = l3_dss_wkup_sleep_deps,
	.sleepdep_srcs	  = l3_dss_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_HWSUP_SWSUP,
};

static struct clockdomain l4_wkup_44xx_clkdm = {
	.name		  = "l4_wkup_clkdm",
	.pwrdm		  = { .name = "wkup_pwrdm" },
	.prcm_partition	  = OMAP4430_PRM_PARTITION,
	.cm_inst	  = OMAP4430_PRM_WKUP_CM_INST,
	.clkdm_offs	  = OMAP4430_PRM_WKUP_CM_WKUP_CDOFFS,
	.dep_bit	  = OMAP4430_L4WKUP_STATDEP_SHIFT,
	.flags		  = CLKDM_CAN_HWSUP | CLKDM_ACTIVE_WITH_MPU,
};

static struct clockdomain emu_sys_44xx_clkdm = {
	.name		  = "emu_sys_clkdm",
	.pwrdm		  = { .name = "emu_pwrdm" },
	.prcm_partition	  = OMAP4430_PRM_PARTITION,
	.cm_inst	  = OMAP4430_PRM_EMU_CM_INST,
	.clkdm_offs	  = OMAP4430_PRM_EMU_CM_EMU_CDOFFS,
	.flags		  = (CLKDM_CAN_ENABLE_AUTO | CLKDM_CAN_FORCE_WAKEUP |
			     CLKDM_MISSING_IDLE_REPORTING),
};

static struct clockdomain l3_dma_44xx_clkdm = {
	.name		  = "l3_dma_clkdm",
	.pwrdm		  = { .name = "core_pwrdm" },
	.prcm_partition	  = OMAP4430_CM2_PARTITION,
	.cm_inst	  = OMAP4430_CM2_CORE_INST,
	.clkdm_offs	  = OMAP4430_CM2_CORE_SDMA_CDOFFS,
	.wkdep_srcs	  = l3_dma_wkup_sleep_deps,
	.sleepdep_srcs	  = l3_dma_wkup_sleep_deps,
	.flags		  = CLKDM_CAN_FORCE_WAKEUP | CLKDM_CAN_HWSUP,
};

/* As clockdomains are added or removed above, this list must also be changed */
static struct clockdomain *clockdomains_omap44xx[] __initdata = {
	&l4_cefuse_44xx_clkdm,
	&l4_cfg_44xx_clkdm,
	&tesla_44xx_clkdm,
	&l3_gfx_44xx_clkdm,
	&ivahd_44xx_clkdm,
	&l4_secure_44xx_clkdm,
	&l4_per_44xx_clkdm,
	&abe_44xx_clkdm,
	&l3_instr_44xx_clkdm,
	&l3_init_44xx_clkdm,
	&d2d_44xx_clkdm,
	&mpu0_44xx_clkdm,
	&mpu1_44xx_clkdm,
	&l3_emif_44xx_clkdm,
	&l4_ao_44xx_clkdm,
	&ducati_44xx_clkdm,
	&mpu_44xx_clkdm,
	&l3_2_44xx_clkdm,
	&l3_1_44xx_clkdm,
	&iss_44xx_clkdm,
	&l3_dss_44xx_clkdm,
	&l4_wkup_44xx_clkdm,
	&emu_sys_44xx_clkdm,
	&l3_dma_44xx_clkdm,
	NULL
};


void __init omap44xx_clockdomains_init(void)
{
	clkdm_register_platform_funcs(&omap4_clkdm_operations);
	clkdm_register_clkdms(clockdomains_omap44xx);
	clkdm_complete_init();
}
