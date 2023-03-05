// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2007 Lemote Inc. & Institute of Computing Technology
 * Author: Fuxin Zhang, zhangfx@lemote.com
 */
#include <linux/export.h>
#include <linux/init.h>

#include <asm/wbflush.h>
#include <asm/bootinfo.h>
#include <linux/libfdt.h>
#include <linux/of_fdt.h>

#include <asm/prom.h>

#include <loongson.h>

void *loongson_fdt_blob;

static void wbflush_loongson(void)
{
	asm(".set\tpush\n\t"
	    ".set\tnoreorder\n\t"
	    ".set mips3\n\t"
	    "sync\n\t"
	    "nop\n\t"
	    ".set\tpop\n\t"
	    ".set mips0\n\t");
}

void (*__wbflush)(void) = wbflush_loongson;
EXPORT_SYMBOL(__wbflush);

void __init plat_mem_setup(void)
{
	if (loongson_fdt_blob)
		__dt_setup_arch(loongson_fdt_blob);
}
