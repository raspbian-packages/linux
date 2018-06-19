/* pci.h: FR-V specific PCI declarations
 *
 * Copyright (C) 2003 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 * - Derived from include/asm-m68k/pci.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _ASM_FRV_PCI_H
#define _ASM_FRV_PCI_H

#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <asm-generic/pci.h>

#define pcibios_assign_all_busses()	0

#ifdef CONFIG_MMU
extern void *consistent_alloc(gfp_t gfp, size_t size, dma_addr_t *dma_handle);
extern void consistent_free(void *vaddr);
extern void consistent_sync(void *vaddr, size_t size, int direction);
extern void consistent_sync_page(struct page *page, unsigned long offset,
				 size_t size, int direction);
#endif

/* Return the index of the PCI controller for device PDEV. */
#define pci_controller_num(PDEV)	(0)

/*
 *	These are pretty much arbitrary with the CoMEM implementation.
 *	We have the whole address space to ourselves.
 */
#define PCIBIOS_MIN_IO		0x100
#define PCIBIOS_MIN_MEM		0x00010000

#endif /* _ASM_FRV_PCI_H */
