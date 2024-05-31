// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright © 2018 Intel Corporation.
 *
 * Authors: Gayatri Kammela <gayatri.kammela@intel.com>
 *	    Sohil Mehta <sohil.mehta@intel.com>
 *	    Jacob Pan <jacob.jun.pan@linux.intel.com>
 *	    Lu Baolu <baolu.lu@linux.intel.com>
 */

#include <linux/debugfs.h>
#include <linux/dmar.h>
#include <linux/pci.h>

#include <asm/irq_remapping.h>

#include "iommu.h"
#include "pasid.h"
#include "perf.h"

struct tbl_walk {
	u16 bus;
	u16 devfn;
	u32 pasid;
	struct root_entry *rt_entry;
	struct context_entry *ctx_entry;
	struct pasid_entry *pasid_tbl_entry;
};

struct iommu_regset {
	int offset;
	const char *regs;
};

#define DEBUG_BUFFER_SIZE	1024
static char debug_buf[DEBUG_BUFFER_SIZE];

#define IOMMU_REGSET_ENTRY(_reg_)					\
	{ DMAR_##_reg_##_REG, __stringify(_reg_) }

static const struct iommu_regset iommu_regs_32[] = {
	IOMMU_REGSET_ENTRY(VER),
	IOMMU_REGSET_ENTRY(GCMD),
	IOMMU_REGSET_ENTRY(GSTS),
	IOMMU_REGSET_ENTRY(FSTS),
	IOMMU_REGSET_ENTRY(FECTL),
	IOMMU_REGSET_ENTRY(FEDATA),
	IOMMU_REGSET_ENTRY(FEADDR),
	IOMMU_REGSET_ENTRY(FEUADDR),
	IOMMU_REGSET_ENTRY(PMEN),
	IOMMU_REGSET_ENTRY(PLMBASE),
	IOMMU_REGSET_ENTRY(PLMLIMIT),
	IOMMU_REGSET_ENTRY(ICS),
	IOMMU_REGSET_ENTRY(PRS),
	IOMMU_REGSET_ENTRY(PECTL),
	IOMMU_REGSET_ENTRY(PEDATA),
	IOMMU_REGSET_ENTRY(PEADDR),
	IOMMU_REGSET_ENTRY(PEUADDR),
};

static const struct iommu_regset iommu_regs_64[] = {
	IOMMU_REGSET_ENTRY(CAP),
	IOMMU_REGSET_ENTRY(ECAP),
	IOMMU_REGSET_ENTRY(RTADDR),
	IOMMU_REGSET_ENTRY(CCMD),
	IOMMU_REGSET_ENTRY(AFLOG),
	IOMMU_REGSET_ENTRY(PHMBASE),
	IOMMU_REGSET_ENTRY(PHMLIMIT),
	IOMMU_REGSET_ENTRY(IQH),
	IOMMU_REGSET_ENTRY(IQT),
	IOMMU_REGSET_ENTRY(IQA),
	IOMMU_REGSET_ENTRY(IRTA),
	IOMMU_REGSET_ENTRY(PQH),
	IOMMU_REGSET_ENTRY(PQT),
	IOMMU_REGSET_ENTRY(PQA),
	IOMMU_REGSET_ENTRY(MTRRCAP),
	IOMMU_REGSET_ENTRY(MTRRDEF),
	IOMMU_REGSET_ENTRY(MTRR_FIX64K_00000),
	IOMMU_REGSET_ENTRY(MTRR_FIX16K_80000),
	IOMMU_REGSET_ENTRY(MTRR_FIX16K_A0000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_C0000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_C8000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_D0000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_D8000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_E0000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_E8000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_F0000),
	IOMMU_REGSET_ENTRY(MTRR_FIX4K_F8000),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE0),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK0),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE1),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK1),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE2),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK2),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE3),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK3),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE4),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK4),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE5),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK5),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE6),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK6),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE7),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK7),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE8),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK8),
	IOMMU_REGSET_ENTRY(MTRR_PHYSBASE9),
	IOMMU_REGSET_ENTRY(MTRR_PHYSMASK9),
};

static struct dentry *intel_iommu_debug;

static int iommu_regset_show(struct seq_file *m, void *unused)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	unsigned long flag;
	int i, ret = 0;
	u64 value;

	rcu_read_lock();
	for_each_active_iommu(iommu, drhd) {
		if (!drhd->reg_base_addr) {
			seq_puts(m, "IOMMU: Invalid base address\n");
			ret = -EINVAL;
			goto out;
		}

		seq_printf(m, "IOMMU: %s Register Base Address: %llx\n",
			   iommu->name, drhd->reg_base_addr);
		seq_puts(m, "Name\t\t\tOffset\t\tContents\n");
		/*
		 * Publish the contents of the 64-bit hardware registers
		 * by adding the offset to the pointer (virtual address).
		 */
		raw_spin_lock_irqsave(&iommu->register_lock, flag);
		for (i = 0 ; i < ARRAY_SIZE(iommu_regs_32); i++) {
			value = dmar_readl(iommu->reg + iommu_regs_32[i].offset);
			seq_printf(m, "%-16s\t0x%02x\t\t0x%016llx\n",
				   iommu_regs_32[i].regs, iommu_regs_32[i].offset,
				   value);
		}
		for (i = 0 ; i < ARRAY_SIZE(iommu_regs_64); i++) {
			value = dmar_readq(iommu->reg + iommu_regs_64[i].offset);
			seq_printf(m, "%-16s\t0x%02x\t\t0x%016llx\n",
				   iommu_regs_64[i].regs, iommu_regs_64[i].offset,
				   value);
		}
		raw_spin_unlock_irqrestore(&iommu->register_lock, flag);
		seq_putc(m, '\n');
	}
out:
	rcu_read_unlock();

	return ret;
}
DEFINE_SHOW_ATTRIBUTE(iommu_regset);

static inline void print_tbl_walk(struct seq_file *m)
{
	struct tbl_walk *tbl_wlk = m->private;

	seq_printf(m, "%02x:%02x.%x\t0x%016llx:0x%016llx\t0x%016llx:0x%016llx\t",
		   tbl_wlk->bus, PCI_SLOT(tbl_wlk->devfn),
		   PCI_FUNC(tbl_wlk->devfn), tbl_wlk->rt_entry->hi,
		   tbl_wlk->rt_entry->lo, tbl_wlk->ctx_entry->hi,
		   tbl_wlk->ctx_entry->lo);

	/*
	 * A legacy mode DMAR doesn't support PASID, hence default it to -1
	 * indicating that it's invalid. Also, default all PASID related fields
	 * to 0.
	 */
	if (!tbl_wlk->pasid_tbl_entry)
		seq_printf(m, "%-6d\t0x%016llx:0x%016llx:0x%016llx\n", -1,
			   (u64)0, (u64)0, (u64)0);
	else
		seq_printf(m, "%-6d\t0x%016llx:0x%016llx:0x%016llx\n",
			   tbl_wlk->pasid, tbl_wlk->pasid_tbl_entry->val[2],
			   tbl_wlk->pasid_tbl_entry->val[1],
			   tbl_wlk->pasid_tbl_entry->val[0]);
}

static void pasid_tbl_walk(struct seq_file *m, struct pasid_entry *tbl_entry,
			   u16 dir_idx)
{
	struct tbl_walk *tbl_wlk = m->private;
	u8 tbl_idx;

	for (tbl_idx = 0; tbl_idx < PASID_TBL_ENTRIES; tbl_idx++) {
		if (pasid_pte_is_present(tbl_entry)) {
			tbl_wlk->pasid_tbl_entry = tbl_entry;
			tbl_wlk->pasid = (dir_idx << PASID_PDE_SHIFT) + tbl_idx;
			print_tbl_walk(m);
		}

		tbl_entry++;
	}
}

static void pasid_dir_walk(struct seq_file *m, u64 pasid_dir_ptr,
			   u16 pasid_dir_size)
{
	struct pasid_dir_entry *dir_entry = phys_to_virt(pasid_dir_ptr);
	struct pasid_entry *pasid_tbl;
	u16 dir_idx;

	for (dir_idx = 0; dir_idx < pasid_dir_size; dir_idx++) {
		pasid_tbl = get_pasid_table_from_pde(dir_entry);
		if (pasid_tbl)
			pasid_tbl_walk(m, pasid_tbl, dir_idx);

		dir_entry++;
	}
}

static void ctx_tbl_walk(struct seq_file *m, struct intel_iommu *iommu, u16 bus)
{
	struct context_entry *context;
	u16 devfn, pasid_dir_size;
	u64 pasid_dir_ptr;

	for (devfn = 0; devfn < 256; devfn++) {
		struct tbl_walk tbl_wlk = {0};

		/*
		 * Scalable mode root entry points to upper scalable mode
		 * context table and lower scalable mode context table. Each
		 * scalable mode context table has 128 context entries where as
		 * legacy mode context table has 256 context entries. So in
		 * scalable mode, the context entries for former 128 devices are
		 * in the lower scalable mode context table, while the latter
		 * 128 devices are in the upper scalable mode context table.
		 * In scalable mode, when devfn > 127, iommu_context_addr()
		 * automatically refers to upper scalable mode context table and
		 * hence the caller doesn't have to worry about differences
		 * between scalable mode and non scalable mode.
		 */
		context = iommu_context_addr(iommu, bus, devfn, 0);
		if (!context)
			return;

		if (!context_present(context))
			continue;

		tbl_wlk.bus = bus;
		tbl_wlk.devfn = devfn;
		tbl_wlk.rt_entry = &iommu->root_entry[bus];
		tbl_wlk.ctx_entry = context;
		m->private = &tbl_wlk;

		if (dmar_readq(iommu->reg + DMAR_RTADDR_REG) & DMA_RTADDR_SMT) {
			pasid_dir_ptr = context->lo & VTD_PAGE_MASK;
			pasid_dir_size = get_pasid_dir_size(context);
			pasid_dir_walk(m, pasid_dir_ptr, pasid_dir_size);
			continue;
		}

		print_tbl_walk(m);
	}
}

static void root_tbl_walk(struct seq_file *m, struct intel_iommu *iommu)
{
	u16 bus;

	spin_lock(&iommu->lock);
	seq_printf(m, "IOMMU %s: Root Table Address: 0x%llx\n", iommu->name,
		   (u64)virt_to_phys(iommu->root_entry));
	seq_puts(m, "B.D.F\tRoot_entry\t\t\t\tContext_entry\t\t\t\tPASID\tPASID_table_entry\n");

	/*
	 * No need to check if the root entry is present or not because
	 * iommu_context_addr() performs the same check before returning
	 * context entry.
	 */
	for (bus = 0; bus < 256; bus++)
		ctx_tbl_walk(m, iommu, bus);
	spin_unlock(&iommu->lock);
}

static int dmar_translation_struct_show(struct seq_file *m, void *unused)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	u32 sts;

	rcu_read_lock();
	for_each_active_iommu(iommu, drhd) {
		sts = dmar_readl(iommu->reg + DMAR_GSTS_REG);
		if (!(sts & DMA_GSTS_TES)) {
			seq_printf(m, "DMA Remapping is not enabled on %s\n",
				   iommu->name);
			continue;
		}
		root_tbl_walk(m, iommu);
		seq_putc(m, '\n');
	}
	rcu_read_unlock();

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(dmar_translation_struct);

static inline unsigned long level_to_directory_size(int level)
{
	return BIT_ULL(VTD_PAGE_SHIFT + VTD_STRIDE_SHIFT * (level - 1));
}

static inline void
dump_page_info(struct seq_file *m, unsigned long iova, u64 *path)
{
	seq_printf(m, "0x%013lx |\t0x%016llx\t0x%016llx\t0x%016llx",
		   iova >> VTD_PAGE_SHIFT, path[5], path[4], path[3]);
	if (path[2]) {
		seq_printf(m, "\t0x%016llx", path[2]);
		if (path[1])
			seq_printf(m, "\t0x%016llx", path[1]);
	}
	seq_putc(m, '\n');
}

static void pgtable_walk_level(struct seq_file *m, struct dma_pte *pde,
			       int level, unsigned long start,
			       u64 *path)
{
	int i;

	if (level > 5 || level < 1)
		return;

	for (i = 0; i < BIT_ULL(VTD_STRIDE_SHIFT);
			i++, pde++, start += level_to_directory_size(level)) {
		if (!dma_pte_present(pde))
			continue;

		path[level] = pde->val;
		if (dma_pte_superpage(pde) || level == 1)
			dump_page_info(m, start, path);
		else
			pgtable_walk_level(m, phys_to_virt(dma_pte_addr(pde)),
					   level - 1, start, path);
		path[level] = 0;
	}
}

static int domain_translation_struct_show(struct seq_file *m,
					  struct device_domain_info *info,
					  ioasid_t pasid)
{
	bool scalable, found = false;
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	u16 devfn, bus, seg;

	bus = info->bus;
	devfn = info->devfn;
	seg = info->segment;

	rcu_read_lock();
	for_each_active_iommu(iommu, drhd) {
		struct context_entry *context;
		u64 pgd, path[6] = { 0 };
		u32 sts, agaw;

		if (seg != iommu->segment)
			continue;

		sts = dmar_readl(iommu->reg + DMAR_GSTS_REG);
		if (!(sts & DMA_GSTS_TES)) {
			seq_printf(m, "DMA Remapping is not enabled on %s\n",
				   iommu->name);
			continue;
		}
		if (dmar_readq(iommu->reg + DMAR_RTADDR_REG) & DMA_RTADDR_SMT)
			scalable = true;
		else
			scalable = false;

		/*
		 * The iommu->lock is held across the callback, which will
		 * block calls to domain_attach/domain_detach. Hence,
		 * the domain of the device will not change during traversal.
		 *
		 * Traversing page table possibly races with the iommu_unmap()
		 * interface. This could be solved by RCU-freeing the page
		 * table pages in the iommu_unmap() path.
		 */
		spin_lock(&iommu->lock);

		context = iommu_context_addr(iommu, bus, devfn, 0);
		if (!context || !context_present(context))
			goto iommu_unlock;

		if (scalable) {	/* scalable mode */
			struct pasid_entry *pasid_tbl, *pasid_tbl_entry;
			struct pasid_dir_entry *dir_tbl, *dir_entry;
			u16 dir_idx, tbl_idx, pgtt;
			u64 pasid_dir_ptr;

			pasid_dir_ptr = context->lo & VTD_PAGE_MASK;

			/* Dump specified device domain mappings with PASID. */
			dir_idx = pasid >> PASID_PDE_SHIFT;
			tbl_idx = pasid & PASID_PTE_MASK;

			dir_tbl = phys_to_virt(pasid_dir_ptr);
			dir_entry = &dir_tbl[dir_idx];

			pasid_tbl = get_pasid_table_from_pde(dir_entry);
			if (!pasid_tbl)
				goto iommu_unlock;

			pasid_tbl_entry = &pasid_tbl[tbl_idx];
			if (!pasid_pte_is_present(pasid_tbl_entry))
				goto iommu_unlock;

			/*
			 * According to PASID Granular Translation Type(PGTT),
			 * get the page table pointer.
			 */
			pgtt = (u16)(pasid_tbl_entry->val[0] & GENMASK_ULL(8, 6)) >> 6;
			agaw = (u8)(pasid_tbl_entry->val[0] & GENMASK_ULL(4, 2)) >> 2;

			switch (pgtt) {
			case PASID_ENTRY_PGTT_FL_ONLY:
				pgd = pasid_tbl_entry->val[2];
				break;
			case PASID_ENTRY_PGTT_SL_ONLY:
			case PASID_ENTRY_PGTT_NESTED:
				pgd = pasid_tbl_entry->val[0];
				break;
			default:
				goto iommu_unlock;
			}
			pgd &= VTD_PAGE_MASK;
		} else { /* legacy mode */
			pgd = context->lo & VTD_PAGE_MASK;
			agaw = context->hi & 7;
		}

		seq_printf(m, "Device %04x:%02x:%02x.%x ",
			   iommu->segment, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

		if (scalable)
			seq_printf(m, "with pasid %x @0x%llx\n", pasid, pgd);
		else
			seq_printf(m, "@0x%llx\n", pgd);

		seq_printf(m, "%-17s\t%-18s\t%-18s\t%-18s\t%-18s\t%-s\n",
			   "IOVA_PFN", "PML5E", "PML4E", "PDPE", "PDE", "PTE");
		pgtable_walk_level(m, phys_to_virt(pgd), agaw + 2, 0, path);

		found = true;
iommu_unlock:
		spin_unlock(&iommu->lock);
		if (found)
			break;
	}
	rcu_read_unlock();

	return 0;
}

static int dev_domain_translation_struct_show(struct seq_file *m, void *unused)
{
	struct device_domain_info *info = (struct device_domain_info *)m->private;

	return domain_translation_struct_show(m, info, IOMMU_NO_PASID);
}
DEFINE_SHOW_ATTRIBUTE(dev_domain_translation_struct);

static int pasid_domain_translation_struct_show(struct seq_file *m, void *unused)
{
	struct dev_pasid_info *dev_pasid = (struct dev_pasid_info *)m->private;
	struct device_domain_info *info = dev_iommu_priv_get(dev_pasid->dev);

	return domain_translation_struct_show(m, info, dev_pasid->pasid);
}
DEFINE_SHOW_ATTRIBUTE(pasid_domain_translation_struct);

static void invalidation_queue_entry_show(struct seq_file *m,
					  struct intel_iommu *iommu)
{
	int index, shift = qi_shift(iommu);
	struct qi_desc *desc;
	int offset;

	if (ecap_smts(iommu->ecap))
		seq_puts(m, "Index\t\tqw0\t\t\tqw1\t\t\tqw2\t\t\tqw3\t\t\tstatus\n");
	else
		seq_puts(m, "Index\t\tqw0\t\t\tqw1\t\t\tstatus\n");

	for (index = 0; index < QI_LENGTH; index++) {
		offset = index << shift;
		desc = iommu->qi->desc + offset;
		if (ecap_smts(iommu->ecap))
			seq_printf(m, "%5d\t%016llx\t%016llx\t%016llx\t%016llx\t%016x\n",
				   index, desc->qw0, desc->qw1,
				   desc->qw2, desc->qw3,
				   iommu->qi->desc_status[index]);
		else
			seq_printf(m, "%5d\t%016llx\t%016llx\t%016x\n",
				   index, desc->qw0, desc->qw1,
				   iommu->qi->desc_status[index]);
	}
}

static int invalidation_queue_show(struct seq_file *m, void *unused)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	unsigned long flags;
	struct q_inval *qi;
	int shift;

	rcu_read_lock();
	for_each_active_iommu(iommu, drhd) {
		qi = iommu->qi;
		shift = qi_shift(iommu);

		if (!qi || !ecap_qis(iommu->ecap))
			continue;

		seq_printf(m, "Invalidation queue on IOMMU: %s\n", iommu->name);

		raw_spin_lock_irqsave(&qi->q_lock, flags);
		seq_printf(m, " Base: 0x%llx\tHead: %lld\tTail: %lld\n",
			   (u64)virt_to_phys(qi->desc),
			   dmar_readq(iommu->reg + DMAR_IQH_REG) >> shift,
			   dmar_readq(iommu->reg + DMAR_IQT_REG) >> shift);
		invalidation_queue_entry_show(m, iommu);
		raw_spin_unlock_irqrestore(&qi->q_lock, flags);
		seq_putc(m, '\n');
	}
	rcu_read_unlock();

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(invalidation_queue);

#ifdef CONFIG_IRQ_REMAP
static void ir_tbl_remap_entry_show(struct seq_file *m,
				    struct intel_iommu *iommu)
{
	struct irte *ri_entry;
	unsigned long flags;
	int idx;

	seq_puts(m, " Entry SrcID   DstID    Vct IRTE_high\t\tIRTE_low\n");

	raw_spin_lock_irqsave(&irq_2_ir_lock, flags);
	for (idx = 0; idx < INTR_REMAP_TABLE_ENTRIES; idx++) {
		ri_entry = &iommu->ir_table->base[idx];
		if (!ri_entry->present || ri_entry->p_pst)
			continue;

		seq_printf(m, " %-5d %02x:%02x.%01x %08x %02x  %016llx\t%016llx\n",
			   idx, PCI_BUS_NUM(ri_entry->sid),
			   PCI_SLOT(ri_entry->sid), PCI_FUNC(ri_entry->sid),
			   ri_entry->dest_id, ri_entry->vector,
			   ri_entry->high, ri_entry->low);
	}
	raw_spin_unlock_irqrestore(&irq_2_ir_lock, flags);
}

static void ir_tbl_posted_entry_show(struct seq_file *m,
				     struct intel_iommu *iommu)
{
	struct irte *pi_entry;
	unsigned long flags;
	int idx;

	seq_puts(m, " Entry SrcID   PDA_high PDA_low  Vct IRTE_high\t\tIRTE_low\n");

	raw_spin_lock_irqsave(&irq_2_ir_lock, flags);
	for (idx = 0; idx < INTR_REMAP_TABLE_ENTRIES; idx++) {
		pi_entry = &iommu->ir_table->base[idx];
		if (!pi_entry->present || !pi_entry->p_pst)
			continue;

		seq_printf(m, " %-5d %02x:%02x.%01x %08x %08x %02x  %016llx\t%016llx\n",
			   idx, PCI_BUS_NUM(pi_entry->sid),
			   PCI_SLOT(pi_entry->sid), PCI_FUNC(pi_entry->sid),
			   pi_entry->pda_h, pi_entry->pda_l << 6,
			   pi_entry->vector, pi_entry->high,
			   pi_entry->low);
	}
	raw_spin_unlock_irqrestore(&irq_2_ir_lock, flags);
}

/*
 * For active IOMMUs go through the Interrupt remapping
 * table and print valid entries in a table format for
 * Remapped and Posted Interrupts.
 */
static int ir_translation_struct_show(struct seq_file *m, void *unused)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	u64 irta;
	u32 sts;

	rcu_read_lock();
	for_each_active_iommu(iommu, drhd) {
		if (!ecap_ir_support(iommu->ecap))
			continue;

		seq_printf(m, "Remapped Interrupt supported on IOMMU: %s\n",
			   iommu->name);

		sts = dmar_readl(iommu->reg + DMAR_GSTS_REG);
		if (iommu->ir_table && (sts & DMA_GSTS_IRES)) {
			irta = virt_to_phys(iommu->ir_table->base);
			seq_printf(m, " IR table address:%llx\n", irta);
			ir_tbl_remap_entry_show(m, iommu);
		} else {
			seq_puts(m, "Interrupt Remapping is not enabled\n");
		}
		seq_putc(m, '\n');
	}

	seq_puts(m, "****\n\n");

	for_each_active_iommu(iommu, drhd) {
		if (!cap_pi_support(iommu->cap))
			continue;

		seq_printf(m, "Posted Interrupt supported on IOMMU: %s\n",
			   iommu->name);

		if (iommu->ir_table) {
			irta = virt_to_phys(iommu->ir_table->base);
			seq_printf(m, " IR table address:%llx\n", irta);
			ir_tbl_posted_entry_show(m, iommu);
		} else {
			seq_puts(m, "Interrupt Remapping is not enabled\n");
		}
		seq_putc(m, '\n');
	}
	rcu_read_unlock();

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ir_translation_struct);
#endif

static void latency_show_one(struct seq_file *m, struct intel_iommu *iommu,
			     struct dmar_drhd_unit *drhd)
{
	int ret;

	seq_printf(m, "IOMMU: %s Register Base Address: %llx\n",
		   iommu->name, drhd->reg_base_addr);

	ret = dmar_latency_snapshot(iommu, debug_buf, DEBUG_BUFFER_SIZE);
	if (ret < 0)
		seq_puts(m, "Failed to get latency snapshot");
	else
		seq_puts(m, debug_buf);
	seq_puts(m, "\n");
}

static int latency_show(struct seq_file *m, void *v)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;

	rcu_read_lock();
	for_each_active_iommu(iommu, drhd)
		latency_show_one(m, iommu, drhd);
	rcu_read_unlock();

	return 0;
}

static int dmar_perf_latency_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, latency_show, NULL);
}

static ssize_t dmar_perf_latency_write(struct file *filp,
				       const char __user *ubuf,
				       size_t cnt, loff_t *ppos)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	int counting;
	char buf[64];

	if (cnt > 63)
		cnt = 63;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;

	if (kstrtoint(buf, 0, &counting))
		return -EINVAL;

	switch (counting) {
	case 0:
		rcu_read_lock();
		for_each_active_iommu(iommu, drhd) {
			dmar_latency_disable(iommu, DMAR_LATENCY_INV_IOTLB);
			dmar_latency_disable(iommu, DMAR_LATENCY_INV_DEVTLB);
			dmar_latency_disable(iommu, DMAR_LATENCY_INV_IEC);
			dmar_latency_disable(iommu, DMAR_LATENCY_PRQ);
		}
		rcu_read_unlock();
		break;
	case 1:
		rcu_read_lock();
		for_each_active_iommu(iommu, drhd)
			dmar_latency_enable(iommu, DMAR_LATENCY_INV_IOTLB);
		rcu_read_unlock();
		break;
	case 2:
		rcu_read_lock();
		for_each_active_iommu(iommu, drhd)
			dmar_latency_enable(iommu, DMAR_LATENCY_INV_DEVTLB);
		rcu_read_unlock();
		break;
	case 3:
		rcu_read_lock();
		for_each_active_iommu(iommu, drhd)
			dmar_latency_enable(iommu, DMAR_LATENCY_INV_IEC);
		rcu_read_unlock();
		break;
	case 4:
		rcu_read_lock();
		for_each_active_iommu(iommu, drhd)
			dmar_latency_enable(iommu, DMAR_LATENCY_PRQ);
		rcu_read_unlock();
		break;
	default:
		return -EINVAL;
	}

	*ppos += cnt;
	return cnt;
}

static const struct file_operations dmar_perf_latency_fops = {
	.open		= dmar_perf_latency_open,
	.write		= dmar_perf_latency_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void __init intel_iommu_debugfs_init(void)
{
	intel_iommu_debug = debugfs_create_dir("intel", iommu_debugfs_dir);

	debugfs_create_file("iommu_regset", 0444, intel_iommu_debug, NULL,
			    &iommu_regset_fops);
	debugfs_create_file("dmar_translation_struct", 0444, intel_iommu_debug,
			    NULL, &dmar_translation_struct_fops);
	debugfs_create_file("invalidation_queue", 0444, intel_iommu_debug,
			    NULL, &invalidation_queue_fops);
#ifdef CONFIG_IRQ_REMAP
	debugfs_create_file("ir_translation_struct", 0444, intel_iommu_debug,
			    NULL, &ir_translation_struct_fops);
#endif
	debugfs_create_file("dmar_perf_latency", 0644, intel_iommu_debug,
			    NULL, &dmar_perf_latency_fops);
}

/*
 * Create a debugfs directory for each device, and then create a
 * debugfs file in this directory for users to dump the page table
 * of the default domain. e.g.
 * /sys/kernel/debug/iommu/intel/0000:00:01.0/domain_translation_struct
 */
void intel_iommu_debugfs_create_dev(struct device_domain_info *info)
{
	info->debugfs_dentry = debugfs_create_dir(dev_name(info->dev), intel_iommu_debug);

	debugfs_create_file("domain_translation_struct", 0444, info->debugfs_dentry,
			    info, &dev_domain_translation_struct_fops);
}

/* Remove the device debugfs directory. */
void intel_iommu_debugfs_remove_dev(struct device_domain_info *info)
{
	debugfs_remove_recursive(info->debugfs_dentry);
}

/*
 * Create a debugfs directory per pair of {device, pasid}, then create the
 * corresponding debugfs file in this directory for users to dump its page
 * table. e.g.
 * /sys/kernel/debug/iommu/intel/0000:00:01.0/1/domain_translation_struct
 *
 * The debugfs only dumps the page tables whose mappings are created and
 * destroyed by the iommu_map/unmap() interfaces. Check the mapping type
 * of the domain before creating debugfs directory.
 */
void intel_iommu_debugfs_create_dev_pasid(struct dev_pasid_info *dev_pasid)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev_pasid->dev);
	char dir_name[10];

	sprintf(dir_name, "%x", dev_pasid->pasid);
	dev_pasid->debugfs_dentry = debugfs_create_dir(dir_name, info->debugfs_dentry);

	debugfs_create_file("domain_translation_struct", 0444, dev_pasid->debugfs_dentry,
			    dev_pasid, &pasid_domain_translation_struct_fops);
}

/* Remove the device pasid debugfs directory. */
void intel_iommu_debugfs_remove_dev_pasid(struct dev_pasid_info *dev_pasid)
{
	debugfs_remove_recursive(dev_pasid->debugfs_dentry);
}
