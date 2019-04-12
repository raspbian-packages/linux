/*:
 * Hibernate support specific for ARM64
 *
 * Derived from work on ARM hibernation support by:
 *
 * Ubuntu project, hibernation support for mach-dove
 * Copyright (C) 2010 Nokia Corporation (Hiroshi Doyu)
 * Copyright (C) 2010 Texas Instruments, Inc. (Teerth Reddy et al.)
 *  https://lkml.org/lkml/2010/6/18/4
 *  https://lists.linux-foundation.org/pipermail/linux-pm/2010-June/027422.html
 *  https://patchwork.kernel.org/patch/96442/
 *
 * Copyright (C) 2006 Rafael J. Wysocki <rjw@sisk.pl>
 *
 * License terms: GNU General Public License (GPL) version 2
 */
#define pr_fmt(x) "hibernate: " x
#include <linux/cpu.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/pm.h>
#include <linux/sched.h>
#include <linux/suspend.h>
#include <linux/utsname.h>
#include <linux/version.h>

#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/cputype.h>
#include <asm/irqflags.h>
#include <asm/memory.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/sections.h>
#include <asm/smp.h>
#include <asm/smp_plat.h>
#include <asm/suspend.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

/*
 * Hibernate core relies on this value being 0 on resume, and marks it
 * __nosavedata assuming it will keep the resume kernel's '0' value. This
 * doesn't happen with either KASLR.
 *
 * defined as "__visible int in_suspend __nosavedata" in
 * kernel/power/hibernate.c
 */
extern int in_suspend;

/* Find a symbols alias in the linear map */
#define LMADDR(x)	phys_to_virt(virt_to_phys(x))

/* Do we need to reset el2? */
#define el2_reset_needed() (is_hyp_mode_available() && !is_kernel_in_hyp_mode())

/* temporary el2 vectors in the __hibernate_exit_text section. */
extern char hibernate_el2_vectors[];

/* hyp-stub vectors, used to restore el2 during resume from hibernate. */
extern char __hyp_stub_vectors[];

/*
 * The logical cpu number we should resume on, initialised to a non-cpu
 * number.
 */
static int sleep_cpu = -EINVAL;

/*
 * Values that may not change over hibernate/resume. We put the build number
 * and date in here so that we guarantee not to resume with a different
 * kernel.
 */
struct arch_hibernate_hdr_invariants {
	char		uts_version[__NEW_UTS_LEN + 1];
};

/* These values need to be know across a hibernate/restore. */
static struct arch_hibernate_hdr {
	struct arch_hibernate_hdr_invariants invariants;

	/* These are needed to find the relocated kernel if built with kaslr */
	phys_addr_t	ttbr1_el1;
	void		(*reenter_kernel)(void);

	/*
	 * We need to know where the __hyp_stub_vectors are after restore to
	 * re-configure el2.
	 */
	phys_addr_t	__hyp_stub_vectors;

	u64		sleep_cpu_mpidr;
} resume_hdr;

static inline void arch_hdr_invariants(struct arch_hibernate_hdr_invariants *i)
{
	memset(i, 0, sizeof(*i));
	memcpy(i->uts_version, init_utsname()->version, sizeof(i->uts_version));
}

int pfn_is_nosave(unsigned long pfn)
{
	unsigned long nosave_begin_pfn = virt_to_pfn(&__nosave_begin);
	unsigned long nosave_end_pfn = virt_to_pfn(&__nosave_end - 1);

	return (pfn >= nosave_begin_pfn) && (pfn <= nosave_end_pfn);
}

void notrace save_processor_state(void)
{
	WARN_ON(num_online_cpus() != 1);
}

void notrace restore_processor_state(void)
{
}

int arch_hibernation_header_save(void *addr, unsigned int max_size)
{
	struct arch_hibernate_hdr *hdr = addr;

	if (max_size < sizeof(*hdr))
		return -EOVERFLOW;

	arch_hdr_invariants(&hdr->invariants);
	hdr->ttbr1_el1		= virt_to_phys(swapper_pg_dir);
	hdr->reenter_kernel	= _cpu_resume;

	/* We can't use __hyp_get_vectors() because kvm may still be loaded */
	if (el2_reset_needed())
		hdr->__hyp_stub_vectors = virt_to_phys(__hyp_stub_vectors);
	else
		hdr->__hyp_stub_vectors = 0;

	/* Save the mpidr of the cpu we called cpu_suspend() on... */
	if (sleep_cpu < 0) {
		pr_err("Failing to hibernate on an unkown CPU.\n");
		return -ENODEV;
	}
	hdr->sleep_cpu_mpidr = cpu_logical_map(sleep_cpu);
	pr_info("Hibernating on CPU %d [mpidr:0x%llx]\n", sleep_cpu,
		hdr->sleep_cpu_mpidr);

	return 0;
}
EXPORT_SYMBOL(arch_hibernation_header_save);

int arch_hibernation_header_restore(void *addr)
{
	int ret;
	struct arch_hibernate_hdr_invariants invariants;
	struct arch_hibernate_hdr *hdr = addr;

	arch_hdr_invariants(&invariants);
	if (memcmp(&hdr->invariants, &invariants, sizeof(invariants))) {
		pr_crit("Hibernate image not generated by this kernel!\n");
		return -EINVAL;
	}

	sleep_cpu = get_logical_index(hdr->sleep_cpu_mpidr);
	pr_info("Hibernated on CPU %d [mpidr:0x%llx]\n", sleep_cpu,
		hdr->sleep_cpu_mpidr);
	if (sleep_cpu < 0) {
		pr_crit("Hibernated on a CPU not known to this kernel!\n");
		sleep_cpu = -EINVAL;
		return -EINVAL;
	}
	if (!cpu_online(sleep_cpu)) {
		pr_info("Hibernated on a CPU that is offline! Bringing CPU up.\n");
		ret = cpu_up(sleep_cpu);
		if (ret) {
			pr_err("Failed to bring hibernate-CPU up!\n");
			sleep_cpu = -EINVAL;
			return ret;
		}
	}

	resume_hdr = *hdr;

	return 0;
}
EXPORT_SYMBOL(arch_hibernation_header_restore);

/*
 * Copies length bytes, starting at src_start into an new page,
 * perform cache maintentance, then maps it at the specified address low
 * address as executable.
 *
 * This is used by hibernate to copy the code it needs to execute when
 * overwriting the kernel text. This function generates a new set of page
 * tables, which it loads into ttbr0.
 *
 * Length is provided as we probably only want 4K of data, even on a 64K
 * page system.
 */
static int create_safe_exec_page(void *src_start, size_t length,
				 unsigned long dst_addr,
				 phys_addr_t *phys_dst_addr,
				 void *(*allocator)(gfp_t mask),
				 gfp_t mask)
{
	int rc = 0;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long dst = (unsigned long)allocator(mask);

	if (!dst) {
		rc = -ENOMEM;
		goto out;
	}

	memcpy((void *)dst, src_start, length);
	flush_icache_range(dst, dst + length);

	pgd = pgd_offset_raw(allocator(mask), dst_addr);
	if (pgd_none(*pgd)) {
		pud = allocator(mask);
		if (!pud) {
			rc = -ENOMEM;
			goto out;
		}
		pgd_populate(&init_mm, pgd, pud);
	}

	pud = pud_offset(pgd, dst_addr);
	if (pud_none(*pud)) {
		pmd = allocator(mask);
		if (!pmd) {
			rc = -ENOMEM;
			goto out;
		}
		pud_populate(&init_mm, pud, pmd);
	}

	pmd = pmd_offset(pud, dst_addr);
	if (pmd_none(*pmd)) {
		pte = allocator(mask);
		if (!pte) {
			rc = -ENOMEM;
			goto out;
		}
		pmd_populate_kernel(&init_mm, pmd, pte);
	}

	pte = pte_offset_kernel(pmd, dst_addr);
	set_pte(pte, __pte(virt_to_phys((void *)dst) |
			 pgprot_val(PAGE_KERNEL_EXEC)));

	/*
	 * Load our new page tables. A strict BBM approach requires that we
	 * ensure that TLBs are free of any entries that may overlap with the
	 * global mappings we are about to install.
	 *
	 * For a real hibernate/resume cycle TTBR0 currently points to a zero
	 * page, but TLBs may contain stale ASID-tagged entries (e.g. for EFI
	 * runtime services), while for a userspace-driven test_resume cycle it
	 * points to userspace page tables (and we must point it at a zero page
	 * ourselves). Elsewhere we only (un)install the idmap with preemption
	 * disabled, so T0SZ should be as required regardless.
	 */
	cpu_set_reserved_ttbr0();
	local_flush_tlb_all();
	write_sysreg(virt_to_phys(pgd), ttbr0_el1);
	isb();

	*phys_dst_addr = virt_to_phys((void *)dst);

out:
	return rc;
}

#define dcache_clean_range(start, end)	__flush_dcache_area(start, (end - start))

int swsusp_arch_suspend(void)
{
	int ret = 0;
	unsigned long flags;
	struct sleep_stack_data state;

	if (cpus_are_stuck_in_kernel()) {
		pr_err("Can't hibernate: no mechanism to offline secondary CPUs.\n");
		return -EBUSY;
	}

	local_dbg_save(flags);

	if (__cpu_suspend_enter(&state)) {
		sleep_cpu = smp_processor_id();
		ret = swsusp_save();
	} else {
		/* Clean kernel core startup/idle code to PoC*/
		dcache_clean_range(__mmuoff_data_start, __mmuoff_data_end);
		dcache_clean_range(__idmap_text_start, __idmap_text_end);

		/* Clean kvm setup code to PoC? */
		if (el2_reset_needed()) {
			dcache_clean_range(__hyp_idmap_text_start, __hyp_idmap_text_end);
			dcache_clean_range(__hyp_text_start, __hyp_text_end);
		}

		/*
		 * Tell the hibernation core that we've just restored
		 * the memory
		 */
		in_suspend = 0;

		sleep_cpu = -EINVAL;
		__cpu_suspend_exit();

		/*
		 * Just in case the boot kernel did turn the SSBD
		 * mitigation off behind our back, let's set the state
		 * to what we expect it to be.
		 */
		switch (arm64_get_ssbd_state()) {
		case ARM64_SSBD_FORCE_ENABLE:
		case ARM64_SSBD_KERNEL:
			arm64_set_ssbd_mitigation(true);
		}
	}

	local_dbg_restore(flags);

	return ret;
}

static void _copy_pte(pte_t *dst_pte, pte_t *src_pte, unsigned long addr)
{
	pte_t pte = *src_pte;

	if (pte_valid(pte)) {
		/*
		 * Resume will overwrite areas that may be marked
		 * read only (code, rodata). Clear the RDONLY bit from
		 * the temporary mappings we use during restore.
		 */
		set_pte(dst_pte, pte_clear_rdonly(pte));
	} else if (debug_pagealloc_enabled() && !pte_none(pte)) {
		/*
		 * debug_pagealloc will removed the PTE_VALID bit if
		 * the page isn't in use by the resume kernel. It may have
		 * been in use by the original kernel, in which case we need
		 * to put it back in our copy to do the restore.
		 *
		 * Before marking this entry valid, check the pfn should
		 * be mapped.
		 */
		BUG_ON(!pfn_valid(pte_pfn(pte)));

		set_pte(dst_pte, pte_mkpresent(pte_clear_rdonly(pte)));
	}
}

static int copy_pte(pmd_t *dst_pmd, pmd_t *src_pmd, unsigned long start,
		    unsigned long end)
{
	pte_t *src_pte;
	pte_t *dst_pte;
	unsigned long addr = start;

	dst_pte = (pte_t *)get_safe_page(GFP_ATOMIC);
	if (!dst_pte)
		return -ENOMEM;
	pmd_populate_kernel(&init_mm, dst_pmd, dst_pte);
	dst_pte = pte_offset_kernel(dst_pmd, start);

	src_pte = pte_offset_kernel(src_pmd, start);
	do {
		_copy_pte(dst_pte, src_pte, addr);
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	return 0;
}

static int copy_pmd(pud_t *dst_pud, pud_t *src_pud, unsigned long start,
		    unsigned long end)
{
	pmd_t *src_pmd;
	pmd_t *dst_pmd;
	unsigned long next;
	unsigned long addr = start;

	if (pud_none(*dst_pud)) {
		dst_pmd = (pmd_t *)get_safe_page(GFP_ATOMIC);
		if (!dst_pmd)
			return -ENOMEM;
		pud_populate(&init_mm, dst_pud, dst_pmd);
	}
	dst_pmd = pmd_offset(dst_pud, start);

	src_pmd = pmd_offset(src_pud, start);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*src_pmd))
			continue;
		if (pmd_table(*src_pmd)) {
			if (copy_pte(dst_pmd, src_pmd, addr, next))
				return -ENOMEM;
		} else {
			set_pmd(dst_pmd,
				__pmd(pmd_val(*src_pmd) & ~PMD_SECT_RDONLY));
		}
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);

	return 0;
}

static int copy_pud(pgd_t *dst_pgd, pgd_t *src_pgd, unsigned long start,
		    unsigned long end)
{
	pud_t *dst_pud;
	pud_t *src_pud;
	unsigned long next;
	unsigned long addr = start;

	if (pgd_none(*dst_pgd)) {
		dst_pud = (pud_t *)get_safe_page(GFP_ATOMIC);
		if (!dst_pud)
			return -ENOMEM;
		pgd_populate(&init_mm, dst_pgd, dst_pud);
	}
	dst_pud = pud_offset(dst_pgd, start);

	src_pud = pud_offset(src_pgd, start);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*src_pud))
			continue;
		if (pud_table(*(src_pud))) {
			if (copy_pmd(dst_pud, src_pud, addr, next))
				return -ENOMEM;
		} else {
			set_pud(dst_pud,
				__pud(pud_val(*src_pud) & ~PMD_SECT_RDONLY));
		}
	} while (dst_pud++, src_pud++, addr = next, addr != end);

	return 0;
}

static int copy_page_tables(pgd_t *dst_pgd, unsigned long start,
			    unsigned long end)
{
	unsigned long next;
	unsigned long addr = start;
	pgd_t *src_pgd = pgd_offset_k(start);

	dst_pgd = pgd_offset_raw(dst_pgd, start);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(*src_pgd))
			continue;
		if (copy_pud(dst_pgd, src_pgd, addr, next))
			return -ENOMEM;
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	return 0;
}

/*
 * Setup then Resume from the hibernate image using swsusp_arch_suspend_exit().
 *
 * Memory allocated by get_safe_page() will be dealt with by the hibernate code,
 * we don't need to free it here.
 */
int swsusp_arch_resume(void)
{
	int rc = 0;
	void *zero_page;
	size_t exit_size;
	pgd_t *tmp_pg_dir;
	void *lm_restore_pblist;
	phys_addr_t phys_hibernate_exit;
	void __noreturn (*hibernate_exit)(phys_addr_t, phys_addr_t, void *,
					  void *, phys_addr_t, phys_addr_t);

	/*
	 * Restoring the memory image will overwrite the ttbr1 page tables.
	 * Create a second copy of just the linear map, and use this when
	 * restoring.
	 */
	tmp_pg_dir = (pgd_t *)get_safe_page(GFP_ATOMIC);
	if (!tmp_pg_dir) {
		pr_err("Failed to allocate memory for temporary page tables.");
		rc = -ENOMEM;
		goto out;
	}
	rc = copy_page_tables(tmp_pg_dir, PAGE_OFFSET, 0);
	if (rc)
		goto out;

	/*
	 * Since we only copied the linear map, we need to find restore_pblist's
	 * linear map address.
	 */
	lm_restore_pblist = LMADDR(restore_pblist);

	/*
	 * We need a zero page that is zero before & after resume in order to
	 * to break before make on the ttbr1 page tables.
	 */
	zero_page = (void *)get_safe_page(GFP_ATOMIC);
	if (!zero_page) {
		pr_err("Failed to allocate zero page.");
		rc = -ENOMEM;
		goto out;
	}

	/*
	 * Locate the exit code in the bottom-but-one page, so that *NULL
	 * still has disastrous affects.
	 */
	hibernate_exit = (void *)PAGE_SIZE;
	exit_size = __hibernate_exit_text_end - __hibernate_exit_text_start;
	/*
	 * Copy swsusp_arch_suspend_exit() to a safe page. This will generate
	 * a new set of ttbr0 page tables and load them.
	 */
	rc = create_safe_exec_page(__hibernate_exit_text_start, exit_size,
				   (unsigned long)hibernate_exit,
				   &phys_hibernate_exit,
				   (void *)get_safe_page, GFP_ATOMIC);
	if (rc) {
		pr_err("Failed to create safe executable page for hibernate_exit code.");
		goto out;
	}

	/*
	 * The hibernate exit text contains a set of el2 vectors, that will
	 * be executed at el2 with the mmu off in order to reload hyp-stub.
	 */
	__flush_dcache_area(hibernate_exit, exit_size);

	/*
	 * KASLR will cause the el2 vectors to be in a different location in
	 * the resumed kernel. Load hibernate's temporary copy into el2.
	 *
	 * We can skip this step if we booted at EL1, or are running with VHE.
	 */
	if (el2_reset_needed()) {
		phys_addr_t el2_vectors = phys_hibernate_exit;  /* base */
		el2_vectors += hibernate_el2_vectors -
			       __hibernate_exit_text_start;     /* offset */

		__hyp_set_vectors(el2_vectors);
	}

	hibernate_exit(virt_to_phys(tmp_pg_dir), resume_hdr.ttbr1_el1,
		       resume_hdr.reenter_kernel, lm_restore_pblist,
		       resume_hdr.__hyp_stub_vectors, virt_to_phys(zero_page));

out:
	return rc;
}

int hibernate_resume_nonboot_cpu_disable(void)
{
	if (sleep_cpu < 0) {
		pr_err("Failing to resume from hibernate on an unkown CPU.\n");
		return -ENODEV;
	}

	return freeze_secondary_cpus(sleep_cpu);
}
