/*
 * AM33XX CM offset macros
 *
 * Copyright (C) 2011-2012 Texas Instruments Incorporated - https://www.ti.com/
 * Vaibhav Hiremath <hvaibhav@ti.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __ARCH_ARM_MACH_OMAP2_CM_33XX_H
#define __ARCH_ARM_MACH_OMAP2_CM_33XX_H

#include "cm.h"
#include "cm-regbits-33xx.h"
#include "prcm-common.h"

/* CM base address */
#define AM33XX_CM_BASE		0x44e00000

#define AM33XX_CM_REGADDR(inst, reg)				\
	AM33XX_L4_WK_IO_ADDRESS(AM33XX_CM_BASE + (inst) + (reg))

/* CM instances */
#define AM33XX_CM_PER_MOD		0x0000
#define AM33XX_CM_WKUP_MOD		0x0400
#define AM33XX_CM_DPLL_MOD		0x0500
#define AM33XX_CM_MPU_MOD		0x0600
#define AM33XX_CM_DEVICE_MOD		0x0700
#define AM33XX_CM_RTC_MOD		0x0800
#define AM33XX_CM_GFX_MOD		0x0900
#define AM33XX_CM_CEFUSE_MOD		0x0A00

/* CM.PER_CM register offsets */
#define AM33XX_CM_PER_L4LS_CLKSTCTRL_OFFSET		0x0000
#define AM33XX_CM_PER_L4LS_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0000)
#define AM33XX_CM_PER_L3S_CLKSTCTRL_OFFSET		0x0004
#define AM33XX_CM_PER_L3S_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0004)
#define AM33XX_CM_PER_L4FW_CLKSTCTRL_OFFSET		0x0008
#define AM33XX_CM_PER_L4FW_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0008)
#define AM33XX_CM_PER_L3_CLKSTCTRL_OFFSET		0x000c
#define AM33XX_CM_PER_L3_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x000c)
#define AM33XX_CM_PER_EMIF_CLKCTRL_OFFSET		0x0028
#define AM33XX_CM_PER_EMIF_CLKCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0028)
#define AM33XX_CM_PER_L4HS_CLKSTCTRL_OFFSET		0x011c
#define AM33XX_CM_PER_L4HS_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x011c)
#define AM33XX_CM_PER_OCPWP_L3_CLKSTCTRL_OFFSET		0x012c
#define AM33XX_CM_PER_OCPWP_L3_CLKSTCTRL		AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x012c)
#define AM33XX_CM_PER_PRUSS_CLKSTCTRL_OFFSET		0x0140
#define AM33XX_CM_PER_PRUSS_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0140)
#define AM33XX_CM_PER_CPSW_CLKSTCTRL_OFFSET		0x0144
#define AM33XX_CM_PER_CPSW_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0144)
#define AM33XX_CM_PER_LCDC_CLKSTCTRL_OFFSET		0x0148
#define AM33XX_CM_PER_LCDC_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0148)
#define AM33XX_CM_PER_CLK_24MHZ_CLKSTCTRL_OFFSET	0x0150
#define AM33XX_CM_PER_CLK_24MHZ_CLKSTCTRL		AM33XX_CM_REGADDR(AM33XX_CM_PER_MOD, 0x0150)

/* CM.WKUP_CM register offsets */
#define AM33XX_CM_WKUP_CLKSTCTRL_OFFSET			0x0000
#define AM33XX_CM_WKUP_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_WKUP_MOD, 0x0000)
#define AM33XX_CM_L3_AON_CLKSTCTRL_OFFSET		0x0018
#define AM33XX_CM_L3_AON_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_WKUP_MOD, 0x0018)
#define AM33XX_CM_L4_WKUP_AON_CLKSTCTRL_OFFSET		0x00cc
#define AM33XX_CM_L4_WKUP_AON_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_WKUP_MOD, 0x00cc)

/* CM.DPLL_CM register offsets */
#define AM33XX_CLKSEL_GFX_FCLK				AM33XX_CM_REGADDR(AM33XX_CM_DPLL_MOD, 0x002c)

/* CM.MPU_CM register offsets */
#define AM33XX_CM_MPU_CLKSTCTRL_OFFSET			0x0000
#define AM33XX_CM_MPU_CLKSTCTRL				AM33XX_CM_REGADDR(AM33XX_CM_MPU_MOD, 0x0000)
#define AM33XX_CM_MPU_MPU_CLKCTRL			AM33XX_CM_REGADDR(AM33XX_CM_MPU_MOD, 0x0004)

/* CM.DEVICE_CM register offsets */

/* CM.RTC_CM register offsets */
#define AM33XX_CM_RTC_CLKSTCTRL_OFFSET			0x0004
#define AM33XX_CM_RTC_CLKSTCTRL				AM33XX_CM_REGADDR(AM33XX_CM_RTC_MOD, 0x0004)

/* CM.GFX_CM register offsets */
#define AM33XX_CM_GFX_L3_CLKSTCTRL_OFFSET		0x0000
#define AM33XX_CM_GFX_L3_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_GFX_MOD, 0x0000)
#define AM33XX_CM_GFX_L4LS_GFX_CLKSTCTRL__1_OFFSET	0x000c
#define AM33XX_CM_GFX_L4LS_GFX_CLKSTCTRL__1		AM33XX_CM_REGADDR(AM33XX_CM_GFX_MOD, 0x000c)

/* CM.CEFUSE_CM register offsets */
#define AM33XX_CM_CEFUSE_CLKSTCTRL_OFFSET		0x0000
#define AM33XX_CM_CEFUSE_CLKSTCTRL			AM33XX_CM_REGADDR(AM33XX_CM_CEFUSE_MOD, 0x0000)


#ifndef __ASSEMBLER__
int am33xx_cm_init(const struct omap_prcm_init_data *data);
#endif /* ASSEMBLER */
#endif
