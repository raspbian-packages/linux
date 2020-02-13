// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Setup code for AT91SAM9
 *
 *  Copyright (C) 2011 Atmel,
 *                2011 Nicolas Ferre <nicolas.ferre@atmel.com>
 */

#include <linux/of.h>
#include <linux/of_platform.h>

#include <asm/mach/arch.h>
#include <asm/system_misc.h>

#include "generic.h"

static void __init at91sam9_init(void)
{
	of_platform_default_populate(NULL, NULL, NULL);

	at91sam9_pm_init();
}

static const char *const at91_dt_board_compat[] __initconst = {
	"atmel,at91sam9",
	NULL
};

DT_MACHINE_START(at91sam_dt, "Atmel AT91SAM9")
	/* Maintainer: Atmel */
	.init_machine	= at91sam9_init,
	.dt_compat	= at91_dt_board_compat,
MACHINE_END

static void __init sam9x60_init(void)
{
	of_platform_default_populate(NULL, NULL, NULL);

	sam9x60_pm_init();
}

static const char *const sam9x60_dt_board_compat[] __initconst = {
	"microchip,sam9x60",
	NULL
};

DT_MACHINE_START(sam9x60_dt, "Microchip SAM9X60")
	/* Maintainer: Microchip */
	.init_machine	= sam9x60_init,
	.dt_compat	= sam9x60_dt_board_compat,
MACHINE_END
