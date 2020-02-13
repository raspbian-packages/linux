// SPDX-License-Identifier: GPL-2.0+
/*
 *	intel TCO vendor specific watchdog driver support
 *
 *	(c) Copyright 2006-2009 Wim Van Sebroeck <wim@iguana.be>.
 *
 *	Neither Wim Van Sebroeck nor Iguana vzw. admit liability nor
 *	provide warranty for any of this software. This material is
 *	provided "AS-IS" and at no charge.
 */

/*
 *	Includes, defines, variables, module parameters, ...
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/* Module and version information */
#define DRV_NAME	"iTCO_vendor_support"
#define DRV_VERSION	"1.04"

/* Includes */
#include <linux/module.h>		/* For module specific items */
#include <linux/moduleparam.h>		/* For new moduleparam's */
#include <linux/types.h>		/* For standard types (like size_t) */
#include <linux/errno.h>		/* For the -ENODEV/... values */
#include <linux/kernel.h>		/* For printk/panic/... */
#include <linux/init.h>			/* For __init/__exit/... */
#include <linux/ioport.h>		/* For io-port access */
#include <linux/io.h>			/* For inb/outb/... */

#include "iTCO_vendor.h"

/* List of vendor support modes */
/* SuperMicro Pentium 3 Era 370SSE+-OEM1/P3TSSE */
#define SUPERMICRO_OLD_BOARD	1
/* SuperMicro Pentium 4 / Xeon 4 / EMT64T Era Systems - no longer supported */
#define SUPERMICRO_NEW_BOARD	2
/* Broken BIOS */
#define BROKEN_BIOS		911

static int vendorsupport;
module_param(vendorsupport, int, 0);
MODULE_PARM_DESC(vendorsupport, "iTCO vendor specific support mode, default="
			"0 (none), 1=SuperMicro Pent3, 911=Broken SMI BIOS");

/*
 *	Vendor Specific Support
 */

/*
 *	Vendor Support: 1
 *	Board: Super Micro Computer Inc. 370SSE+-OEM1/P3TSSE
 *	iTCO chipset: ICH2
 *
 *	Code contributed by: R. Seretny <lkpatches@paypc.com>
 *	Documentation obtained by R. Seretny from SuperMicro Technical Support
 *
 *	To enable Watchdog function:
 *	    BIOS setup -> Power -> TCO Logic SMI Enable -> Within5Minutes
 *	    This setting enables SMI to clear the watchdog expired flag.
 *	    If BIOS or CPU fail which may cause SMI hang, then system will
 *	    reboot. When application starts to use watchdog function,
 *	    application has to take over the control from SMI.
 *
 *	    For P3TSSE, J36 jumper needs to be removed to enable the Watchdog
 *	    function.
 *
 *	    Note: The system will reboot when Expire Flag is set TWICE.
 *	    So, if the watchdog timer is 20 seconds, then the maximum hang
 *	    time is about 40 seconds, and the minimum hang time is about
 *	    20.6 seconds.
 */

static void supermicro_old_pre_start(struct resource *smires)
{
	unsigned long val32;

	/* Bit 13: TCO_EN -> 0 = Disables TCO logic generating an SMI# */
	val32 = inl(smires->start);
	val32 &= 0xffffdfff;	/* Turn off SMI clearing watchdog */
	outl(val32, smires->start);	/* Needed to activate watchdog */
}

static void supermicro_old_pre_stop(struct resource *smires)
{
	unsigned long val32;

	/* Bit 13: TCO_EN -> 1 = Enables the TCO logic to generate SMI# */
	val32 = inl(smires->start);
	val32 |= 0x00002000;	/* Turn on SMI clearing watchdog */
	outl(val32, smires->start);	/* Needed to deactivate watchdog */
}

/*
 *	Vendor Support: 911
 *	Board: Some Intel ICHx based motherboards
 *	iTCO chipset: ICH7+
 *
 *	Some Intel motherboards have a broken BIOS implementation: i.e.
 *	the SMI handler clear's the TIMEOUT bit in the TC01_STS register
 *	and does not reload the time. Thus the TCO watchdog does not reboot
 *	the system.
 *
 *	These are the conclusions of Andriy Gapon <avg@icyb.net.ua> after
 *	debugging: the SMI handler is quite simple - it tests value in
 *	TCO1_CNT against 0x800, i.e. checks TCO_TMR_HLT. If the bit is set
 *	the handler goes into an infinite loop, apparently to allow the
 *	second timeout and reboot. Otherwise it simply clears TIMEOUT bit
 *	in TCO1_STS and that's it.
 *	So the logic seems to be reversed, because it is hard to see how
 *	TIMEOUT can get set to 1 and SMI generated when TCO_TMR_HLT is set
 *	(other than a transitional effect).
 *
 *	The only fix found to get the motherboard(s) to reboot is to put
 *	the glb_smi_en bit to 0. This is a dirty hack that bypasses the
 *	broken code by disabling Global SMI.
 *
 *	WARNING: globally disabling SMI could possibly lead to dramatic
 *	problems, especially on laptops! I.e. various ACPI things where
 *	SMI is used for communication between OS and firmware.
 *
 *	Don't use this fix if you don't need to!!!
 */

static void broken_bios_start(struct resource *smires)
{
	unsigned long val32;

	val32 = inl(smires->start);
	/* Bit 13: TCO_EN     -> 0 = Disables TCO logic generating an SMI#
	   Bit  0: GBL_SMI_EN -> 0 = No SMI# will be generated by ICH. */
	val32 &= 0xffffdffe;
	outl(val32, smires->start);
}

static void broken_bios_stop(struct resource *smires)
{
	unsigned long val32;

	val32 = inl(smires->start);
	/* Bit 13: TCO_EN     -> 1 = Enables TCO logic generating an SMI#
	   Bit  0: GBL_SMI_EN -> 1 = Turn global SMI on again. */
	val32 |= 0x00002001;
	outl(val32, smires->start);
}

/*
 *	Generic Support Functions
 */

void iTCO_vendor_pre_start(struct resource *smires,
			   unsigned int heartbeat)
{
	switch (vendorsupport) {
	case SUPERMICRO_OLD_BOARD:
		supermicro_old_pre_start(smires);
		break;
	case BROKEN_BIOS:
		broken_bios_start(smires);
		break;
	}
}
EXPORT_SYMBOL(iTCO_vendor_pre_start);

void iTCO_vendor_pre_stop(struct resource *smires)
{
	switch (vendorsupport) {
	case SUPERMICRO_OLD_BOARD:
		supermicro_old_pre_stop(smires);
		break;
	case BROKEN_BIOS:
		broken_bios_stop(smires);
		break;
	}
}
EXPORT_SYMBOL(iTCO_vendor_pre_stop);

int iTCO_vendor_check_noreboot_on(void)
{
	switch (vendorsupport) {
	case SUPERMICRO_OLD_BOARD:
		return 0;
	default:
		return 1;
	}
}
EXPORT_SYMBOL(iTCO_vendor_check_noreboot_on);

static int __init iTCO_vendor_init_module(void)
{
	if (vendorsupport == SUPERMICRO_NEW_BOARD) {
		pr_warn("Option vendorsupport=%d is no longer supported, "
			"please use the w83627hf_wdt driver instead\n",
			SUPERMICRO_NEW_BOARD);
		return -EINVAL;
	}
	pr_info("vendor-support=%d\n", vendorsupport);
	return 0;
}

static void __exit iTCO_vendor_exit_module(void)
{
	pr_info("Module Unloaded\n");
}

module_init(iTCO_vendor_init_module);
module_exit(iTCO_vendor_exit_module);

MODULE_AUTHOR("Wim Van Sebroeck <wim@iguana.be>, "
		"R. Seretny <lkpatches@paypc.com>");
MODULE_DESCRIPTION("Intel TCO Vendor Specific WatchDog Timer Driver Support");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("GPL");
