/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SPARC64_PCI_H
#define __SPARC64_PCI_H

#ifdef __KERNEL__

#include <linux/dma-mapping.h>

/* Can be used to override the logic in pci_scan_bus for skipping
 * already-configured bus numbers - to be used for buggy BIOSes
 * or architectures with incomplete PCI setup by the loader.
 */
#define pcibios_assign_all_busses()	0

#define PCIBIOS_MIN_IO		0UL
#define PCIBIOS_MIN_MEM		0UL

#define PCI_IRQ_NONE		0xffffffff

/* The PCI address space does not equal the physical memory
 * address space.  The networking and block device layers use
 * this boolean for bounce buffer decisions.
 */
#define PCI_DMA_BUS_IS_PHYS	(0)

/* PCI IOMMU mapping bypass support. */

/* PCI 64-bit addressing works for all slots on all controller
 * types on sparc64.  However, it requires that the device
 * can drive enough of the 64 bits.
 */
#define PCI64_REQUIRED_MASK	(~(u64)0)
#define PCI64_ADDR_BASE		0xfffc000000000000UL

/* Return the index of the PCI controller for device PDEV. */

int pci_domain_nr(struct pci_bus *bus);
static inline int pci_proc_domain(struct pci_bus *bus)
{
	return 1;
}

/* Platform support for /proc/bus/pci/X/Y mmap()s. */

#define HAVE_PCI_MMAP
#define arch_can_pci_mmap_io()	1
#define HAVE_ARCH_PCI_GET_UNMAPPED_AREA
#define get_pci_unmapped_area get_fb_unmapped_area

static inline int pci_get_legacy_ide_irq(struct pci_dev *dev, int channel)
{
	return PCI_IRQ_NONE;
}

#define HAVE_ARCH_PCI_RESOURCE_TO_USER
#endif /* __KERNEL__ */

#endif /* __SPARC64_PCI_H */
