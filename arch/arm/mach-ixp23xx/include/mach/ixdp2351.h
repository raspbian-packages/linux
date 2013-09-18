/*
 * arch/arm/mach-ixp23xx/include/mach/ixdp2351.h
 *
 * Register and other defines for IXDP2351
 *
 * Copyright (c) 2002-2004 Intel Corp.
 * Copytight (c) 2005 MontaVista Software, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef __ASM_ARCH_IXDP2351_H
#define __ASM_ARCH_IXDP2351_H

/*
 * NP module memory map
 */
#define IXDP2351_NP_PHYS_BASE		(IXP23XX_EXP_BUS_CS4_BASE)
#define IXDP2351_NP_PHYS_SIZE		0x00100000
#define IXDP2351_NP_VIRT_BASE		0xeff00000

#define IXDP2351_VIRT_CS8900_BASE	(IXDP2351_NP_VIRT_BASE)
#define IXDP2351_VIRT_CS8900_END	(IXDP2351_VIRT_CS8900_BASE + 16)

#define IXDP2351_VIRT_NP_CPLD_BASE 	(IXP23XX_EXP_BUS_CS4_BASE_VIRT + 0x00010000)

#define IXDP2351_NP_CPLD_REG(reg) ((volatile u16 *)(IXDP2351_VIRT_NP_CPLD_BASE + reg))

#define IXDP2351_NP_CPLD_RESET1_REG	IXDP2351_NP_CPLD_REG(0x00)
#define IXDP2351_NP_CPLD_LED_REG	IXDP2351_NP_CPLD_REG(0x02)
#define IXDP2351_NP_CPLD_VERSION_REG	IXDP2351_NP_CPLD_REG(0x04)

/*
 * Base board module memory map
 */

#define IXDP2351_BB_BASE_PHYS		(IXP23XX_EXP_BUS_CS5_BASE)
#define IXDP2351_BB_SIZE		0x01000000
#define IXDP2351_BB_BASE_VIRT		(0xee000000)

#define IXDP2351_BB_AREA_BASE(offset)	(IXDP2351_BB_BASE_VIRT + offset)

#define IXDP2351_VIRT_NVRAM_BASE	IXDP2351_BB_AREA_BASE(0x0)
#define IXDP2351_NVRAM_SIZE		(0x20000)

#define IXDP2351_VIRT_MB_IXF1104_BASE	IXDP2351_BB_AREA_BASE(0x00020000)
#define IXDP2351_VIRT_ADD_UART_BASE	IXDP2351_BB_AREA_BASE(0x000240C0)
#define IXDP2351_VIRT_FIC_BASE		IXDP2351_BB_AREA_BASE(0x00200000)
#define IXDP2351_VIRT_DB0_BASE		IXDP2351_BB_AREA_BASE(0x00400000)
#define IXDP2351_VIRT_DB1_BASE		IXDP2351_BB_AREA_BASE(0x00600000)
#define IXDP2351_VIRT_CPLD_BASE		IXDP2351_BB_AREA_BASE(0x00024000)

/*
 * On board CPLD registers
 */
#define IXDP2351_CPLD_BB_REG(reg) ((volatile u16 *)(IXDP2351_VIRT_CPLD_BASE + reg))

#define IXDP2351_CPLD_RESET0_REG	IXDP2351_CPLD_BB_REG(0x00)
#define IXDP2351_CPLD_RESET1_REG	IXDP2351_CPLD_BB_REG(0x04)

#define IXDP2351_CPLD_RESET1_MAGIC 	0x55AA
#define IXDP2351_CPLD_RESET1_ENABLE 	0x8000

#define IXDP2351_CPLD_FPGA_CONFIG_REG	IXDP2351_CPLD_BB_REG(0x08)
#define IXDP2351_CPLD_INTB_MASK_SET_REG	IXDP2351_CPLD_BB_REG(0x10)
#define IXDP2351_CPLD_INTA_MASK_SET_REG	IXDP2351_CPLD_BB_REG(0x14)
#define IXDP2351_CPLD_INTB_STAT_REG	IXDP2351_CPLD_BB_REG(0x18)
#define IXDP2351_CPLD_INTA_STAT_REG	IXDP2351_CPLD_BB_REG(0x1C)
#define IXDP2351_CPLD_INTB_RAW_REG	IXDP2351_CPLD_BB_REG(0x20)	/* read */
#define IXDP2351_CPLD_INTA_RAW_REG	IXDP2351_CPLD_BB_REG(0x24)	/* read */
#define IXDP2351_CPLD_INTB_MASK_CLR_REG	IXDP2351_CPLD_INTB_RAW_REG	/* write */
#define IXDP2351_CPLD_INTA_MASK_CLR_REG	IXDP2351_CPLD_INTA_RAW_REG	/* write */
#define IXDP2351_CPLD_INTB_SIM_REG	IXDP2351_CPLD_BB_REG(0x28)
#define IXDP2351_CPLD_INTA_SIM_REG	IXDP2351_CPLD_BB_REG(0x2C)
	/* Interrupt bits are defined in irqs.h */
#define IXDP2351_CPLD_BB_GBE0_REG	IXDP2351_CPLD_BB_REG(0x30)
#define IXDP2351_CPLD_BB_GBE1_REG	IXDP2351_CPLD_BB_REG(0x34)

/* #define IXDP2351_CPLD_BB_MISC_REG	IXDP2351_CPLD_REG(0x1C) */
/* #define IXDP2351_CPLD_BB_MISC_REV_MASK	0xFF		*/
/* #define IXDP2351_CPLD_BB_GDXCS0_REG	IXDP2351_CPLD_REG(0x24) */
/* #define IXDP2351_CPLD_BB_GDXCS1_REG	IXDP2351_CPLD_REG(0x28) */
/* #define IXDP2351_CPLD_BB_CLOCK_REG	IXDP2351_CPLD_REG(0x04) */


#endif
