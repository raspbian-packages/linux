/*
 *  AMD CPU Microcode Update Driver for Linux
 *
 *  This driver allows to upgrade microcode on F10h AMD
 *  CPUs and later.
 *
 *  Copyright (C) 2008-2011 Advanced Micro Devices Inc.
 *
 *  Author: Peter Oruba <peter.oruba@amd.com>
 *
 *  Based on work by:
 *  Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *
 *  early loader:
 *  Copyright (C) 2013 Advanced Micro Devices, Inc.
 *
 *  Author: Jacob Shin <jacob.shin@amd.com>
 *  Fixes: Borislav Petkov <bp@suse.de>
 *
 *  Licensed under the terms of the GNU General Public
 *  License version 2. See file COPYING for details.
 */
#define pr_fmt(fmt) "microcode: " fmt

#include <linux/earlycpio.h>
#include <linux/firmware.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/initrd.h>
#include <linux/kernel.h>
#include <linux/pci.h>

#include <asm/microcode_amd.h>
#include <asm/microcode.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/cpu.h>
#include <asm/msr.h>

static struct equiv_cpu_entry *equiv_cpu_table;

struct ucode_patch {
	struct list_head plist;
	void *data;
	u32 patch_id;
	u16 equiv_cpu;
};

static LIST_HEAD(pcache);

/*
 * This points to the current valid container of microcode patches which we will
 * save from the initrd before jettisoning its contents.
 */
static u8 *container;
static size_t container_size;
static bool ucode_builtin;

static u32 ucode_new_rev;
static u8 amd_ucode_patch[PATCH_MAX_SIZE];
static u16 this_equiv_id;

static struct cpio_data ucode_cpio;

static struct cpio_data __init find_ucode_in_initrd(void)
{
#ifdef CONFIG_BLK_DEV_INITRD
	char *path;
	void *start;
	size_t size;

	/*
	 * Microcode patch container file is prepended to the initrd in cpio
	 * format. See Documentation/x86/early-microcode.txt
	 */
	static __initdata char ucode_path[] = "kernel/x86/microcode/AuthenticAMD.bin";

#ifdef CONFIG_X86_32
	struct boot_params *p;

	/*
	 * On 32-bit, early load occurs before paging is turned on so we need
	 * to use physical addresses.
	 */
	p       = (struct boot_params *)__pa_nodebug(&boot_params);
	path    = (char *)__pa_nodebug(ucode_path);
	start   = (void *)p->hdr.ramdisk_image;
	size    = p->hdr.ramdisk_size;
#else
	path    = ucode_path;
	start   = (void *)(boot_params.hdr.ramdisk_image + PAGE_OFFSET);
	size    = boot_params.hdr.ramdisk_size;
#endif /* !CONFIG_X86_32 */

	return find_cpio_data(path, start, size, NULL);
#else
	return (struct cpio_data){ NULL, 0, "" };
#endif
}

static size_t compute_container_size(u8 *data, u32 total_size)
{
	size_t size = 0;
	u32 *header = (u32 *)data;

	if (header[0] != UCODE_MAGIC ||
	    header[1] != UCODE_EQUIV_CPU_TABLE_TYPE || /* type */
	    header[2] == 0)                            /* size */
		return size;

	size = header[2] + CONTAINER_HDR_SZ;
	total_size -= size;
	data += size;

	while (total_size) {
		u16 patch_size;

		header = (u32 *)data;

		if (header[0] != UCODE_UCODE_TYPE)
			break;

		/*
		 * Sanity-check patch size.
		 */
		patch_size = header[1];
		if (patch_size > PATCH_MAX_SIZE)
			break;

		size	   += patch_size + SECTION_HDR_SIZE;
		data	   += patch_size + SECTION_HDR_SIZE;
		total_size -= patch_size + SECTION_HDR_SIZE;
	}

	return size;
}

static enum ucode_state
load_microcode_amd(bool save, u8 family, const u8 *data, size_t size);

/*
 * Early load occurs before we can vmalloc(). So we look for the microcode
 * patch container file in initrd, traverse equivalent cpu table, look for a
 * matching microcode patch, and update, all in initrd memory in place.
 * When vmalloc() is available for use later -- on 64-bit during first AP load,
 * and on 32-bit during save_microcode_in_initrd_amd() -- we can call
 * load_microcode_amd() to save equivalent cpu table and microcode patches in
 * kernel heap memory.
 */
static void apply_ucode_in_initrd(void *ucode, size_t size, bool save_patch)
{
	struct equiv_cpu_entry *eq;
	size_t *cont_sz;
	u32 *header;
	u8  *data, **cont;
	u8 (*patch)[PATCH_MAX_SIZE];
	u16 eq_id = 0;
	int offset, left;
	u32 rev, eax, ebx, ecx, edx;
	u32 *new_rev;

#ifdef CONFIG_X86_32
	new_rev = (u32 *)__pa_nodebug(&ucode_new_rev);
	cont_sz = (size_t *)__pa_nodebug(&container_size);
	cont	= (u8 **)__pa_nodebug(&container);
	patch	= (u8 (*)[PATCH_MAX_SIZE])__pa_nodebug(&amd_ucode_patch);
#else
	new_rev = &ucode_new_rev;
	cont_sz = &container_size;
	cont	= &container;
	patch	= &amd_ucode_patch;
#endif

	data   = ucode;
	left   = size;
	header = (u32 *)data;

	/* find equiv cpu table */
	if (header[0] != UCODE_MAGIC ||
	    header[1] != UCODE_EQUIV_CPU_TABLE_TYPE || /* type */
	    header[2] == 0)                            /* size */
		return;

	eax = 0x00000001;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);

	while (left > 0) {
		eq = (struct equiv_cpu_entry *)(data + CONTAINER_HDR_SZ);

		*cont = data;

		/* Advance past the container header */
		offset = header[2] + CONTAINER_HDR_SZ;
		data  += offset;
		left  -= offset;

		eq_id = find_equiv_id(eq, eax);
		if (eq_id) {
			this_equiv_id = eq_id;
			*cont_sz = compute_container_size(*cont, left + offset);

			/*
			 * truncate how much we need to iterate over in the
			 * ucode update loop below
			 */
			left = *cont_sz - offset;
			break;
		}

		/*
		 * support multiple container files appended together. if this
		 * one does not have a matching equivalent cpu entry, we fast
		 * forward to the next container file.
		 */
		while (left > 0) {
			header = (u32 *)data;
			if (header[0] == UCODE_MAGIC &&
			    header[1] == UCODE_EQUIV_CPU_TABLE_TYPE)
				break;

			offset = header[1] + SECTION_HDR_SIZE;
			data  += offset;
			left  -= offset;
		}

		/* mark where the next microcode container file starts */
		offset    = data - (u8 *)ucode;
		ucode     = data;
	}

	if (!eq_id) {
		*cont = NULL;
		*cont_sz = 0;
		return;
	}

	if (check_current_patch_level(&rev, true))
		return;

	while (left > 0) {
		struct microcode_amd *mc;

		header = (u32 *)data;
		if (header[0] != UCODE_UCODE_TYPE || /* type */
		    header[1] == 0)                  /* size */
			break;

		mc = (struct microcode_amd *)(data + SECTION_HDR_SIZE);

		if (eq_id == mc->hdr.processor_rev_id && rev < mc->hdr.patch_id) {

			if (!__apply_microcode_amd(mc)) {
				rev = mc->hdr.patch_id;
				*new_rev = rev;

				if (save_patch)
					memcpy(patch, mc,
					       min_t(u32, header[1], PATCH_MAX_SIZE));
			}
		}

		offset  = header[1] + SECTION_HDR_SIZE;
		data   += offset;
		left   -= offset;
	}
}

static bool __init load_builtin_amd_microcode(struct cpio_data *cp,
					      unsigned int family)
{
#ifdef CONFIG_X86_64
	char fw_name[36] = "amd-ucode/microcode_amd.bin";

	if (family >= 0x15)
		snprintf(fw_name, sizeof(fw_name),
			 "amd-ucode/microcode_amd_fam%.2xh.bin", family);

	return get_builtin_firmware(cp, fw_name);
#else
	return false;
#endif
}

void __init load_ucode_amd_bsp(unsigned int family)
{
	struct cpio_data cp;
	bool *builtin;
	void **data;
	size_t *size;

#ifdef CONFIG_X86_32
	data =  (void **)__pa_nodebug(&ucode_cpio.data);
	size = (size_t *)__pa_nodebug(&ucode_cpio.size);
	builtin = (bool *)__pa_nodebug(&ucode_builtin);
#else
	data = &ucode_cpio.data;
	size = &ucode_cpio.size;
	builtin = &ucode_builtin;
#endif

	*builtin = load_builtin_amd_microcode(&cp, family);
	if (!*builtin)
		cp = find_ucode_in_initrd();

	if (!(cp.data && cp.size))
		return;

	*data = cp.data;
	*size = cp.size;

	apply_ucode_in_initrd(cp.data, cp.size, true);
}

#ifdef CONFIG_X86_32
/*
 * On 32-bit, since AP's early load occurs before paging is turned on, we
 * cannot traverse cpu_equiv_table and pcache in kernel heap memory. So during
 * cold boot, AP will apply_ucode_in_initrd() just like the BSP. During
 * save_microcode_in_initrd_amd() BSP's patch is copied to amd_ucode_patch,
 * which is used upon resume from suspend.
 */
void load_ucode_amd_ap(void)
{
	struct microcode_amd *mc;
	size_t *usize;
	void **ucode;

	mc = (struct microcode_amd *)__pa_nodebug(amd_ucode_patch);
	if (mc->hdr.patch_id && mc->hdr.processor_rev_id) {
		__apply_microcode_amd(mc);
		return;
	}

	ucode = (void *)__pa_nodebug(&container);
	usize = (size_t *)__pa_nodebug(&container_size);

	if (!*ucode || !*usize)
		return;

	apply_ucode_in_initrd(*ucode, *usize, false);
}

static void __init collect_cpu_sig_on_bsp(void *arg)
{
	unsigned int cpu = smp_processor_id();
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	uci->cpu_sig.sig = cpuid_eax(0x00000001);
}

static void __init get_bsp_sig(void)
{
	unsigned int bsp = boot_cpu_data.cpu_index;
	struct ucode_cpu_info *uci = ucode_cpu_info + bsp;

	if (!uci->cpu_sig.sig)
		smp_call_function_single(bsp, collect_cpu_sig_on_bsp, NULL, 1);
}
#else
void load_ucode_amd_ap(void)
{
	unsigned int cpu = smp_processor_id();
	struct equiv_cpu_entry *eq;
	struct microcode_amd *mc;
	u8 *cont = container;
	u32 rev, eax;
	u16 eq_id;

	/* Exit if called on the BSP. */
	if (!cpu)
		return;

	if (!container)
		return;

	/*
	 * 64-bit runs with paging enabled, thus early==false.
	 */
	if (check_current_patch_level(&rev, false))
		return;

	/* Add CONFIG_RANDOMIZE_MEMORY offset. */
	if (!ucode_builtin)
		cont += PAGE_OFFSET - __PAGE_OFFSET_BASE;

	eax = cpuid_eax(0x00000001);
	eq  = (struct equiv_cpu_entry *)(cont + CONTAINER_HDR_SZ);

	eq_id = find_equiv_id(eq, eax);
	if (!eq_id)
		return;

	if (eq_id == this_equiv_id) {
		mc = (struct microcode_amd *)amd_ucode_patch;

		if (mc && rev < mc->hdr.patch_id) {
			if (!__apply_microcode_amd(mc))
				ucode_new_rev = mc->hdr.patch_id;
		}

	} else {
		if (!ucode_cpio.data)
			return;

		/*
		 * AP has a different equivalence ID than BSP, looks like
		 * mixed-steppings silicon so go through the ucode blob anew.
		 */
		apply_ucode_in_initrd(ucode_cpio.data, ucode_cpio.size, false);
	}
}
#endif

int __init save_microcode_in_initrd_amd(void)
{
	unsigned long cont;
	int retval = 0;
	enum ucode_state ret;
	u8 *cont_va;
	u32 eax;

	if (!container)
		return -EINVAL;

#ifdef CONFIG_X86_32
	get_bsp_sig();
	cont	= (unsigned long)container;
	cont_va = __va(container);
#else
	/*
	 * We need the physical address of the container for both bitness since
	 * boot_params.hdr.ramdisk_image is a physical address.
	 */
	cont    = __pa_nodebug(container);
	cont_va = container;
#endif

	/*
	 * Take into account the fact that the ramdisk might get relocated and
	 * therefore we need to recompute the container's position in virtual
	 * memory space.
	 */
	if (relocated_ramdisk)
		container = (u8 *)(__va(relocated_ramdisk) +
			     (cont - boot_params.hdr.ramdisk_image));
	else
		container = cont_va;

	/* Add CONFIG_RANDOMIZE_MEMORY offset. */
	if (!ucode_builtin)
		container += PAGE_OFFSET - __PAGE_OFFSET_BASE;

	eax   = cpuid_eax(0x00000001);
	eax   = ((eax >> 8) & 0xf) + ((eax >> 20) & 0xff);

	ret = load_microcode_amd(true, eax, container, container_size);
	if (ret != UCODE_OK)
		retval = -EINVAL;

	/*
	 * This will be freed any msec now, stash patches for the current
	 * family and switch to patch cache for cpu hotplug, etc later.
	 */
	container = NULL;
	container_size = 0;

	return retval;
}

void reload_ucode_amd(void)
{
	struct microcode_amd *mc;
	u32 rev;

	/*
	 * early==false because this is a syscore ->resume path and by
	 * that time paging is long enabled.
	 */
	if (check_current_patch_level(&rev, false))
		return;

	mc = (struct microcode_amd *)amd_ucode_patch;

	if (mc && rev < mc->hdr.patch_id) {
		if (!__apply_microcode_amd(mc)) {
			ucode_new_rev = mc->hdr.patch_id;
			pr_info("reload patch_level=0x%08x\n", ucode_new_rev);
		}
	}
}
static u16 __find_equiv_id(unsigned int cpu)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	return find_equiv_id(equiv_cpu_table, uci->cpu_sig.sig);
}

static u32 find_cpu_family_by_equiv_cpu(u16 equiv_cpu)
{
	int i = 0;

	BUG_ON(!equiv_cpu_table);

	while (equiv_cpu_table[i].equiv_cpu != 0) {
		if (equiv_cpu == equiv_cpu_table[i].equiv_cpu)
			return equiv_cpu_table[i].installed_cpu;
		i++;
	}
	return 0;
}

/*
 * a small, trivial cache of per-family ucode patches
 */
static struct ucode_patch *cache_find_patch(u16 equiv_cpu)
{
	struct ucode_patch *p;

	list_for_each_entry(p, &pcache, plist)
		if (p->equiv_cpu == equiv_cpu)
			return p;
	return NULL;
}

static void update_cache(struct ucode_patch *new_patch)
{
	struct ucode_patch *p;

	list_for_each_entry(p, &pcache, plist) {
		if (p->equiv_cpu == new_patch->equiv_cpu) {
			if (p->patch_id >= new_patch->patch_id)
				/* we already have the latest patch */
				return;

			list_replace(&p->plist, &new_patch->plist);
			kfree(p->data);
			kfree(p);
			return;
		}
	}
	/* no patch found, add it */
	list_add_tail(&new_patch->plist, &pcache);
}

static void free_cache(void)
{
	struct ucode_patch *p, *tmp;

	list_for_each_entry_safe(p, tmp, &pcache, plist) {
		__list_del(p->plist.prev, p->plist.next);
		kfree(p->data);
		kfree(p);
	}
}

static struct ucode_patch *find_patch(unsigned int cpu)
{
	u16 equiv_id;

	equiv_id = __find_equiv_id(cpu);
	if (!equiv_id)
		return NULL;

	return cache_find_patch(equiv_id);
}

static int collect_cpu_info_amd(int cpu, struct cpu_signature *csig)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	struct ucode_patch *p;

	csig->sig = cpuid_eax(0x00000001);
	csig->rev = c->microcode;

	/*
	 * a patch could have been loaded early, set uci->mc so that
	 * mc_bp_resume() can call apply_microcode()
	 */
	p = find_patch(cpu);
	if (p && (p->patch_id == csig->rev))
		uci->mc = p->data;

	pr_info("CPU%d: patch_level=0x%08x\n", cpu, csig->rev);

	return 0;
}

static unsigned int verify_patch_size(u8 family, u32 patch_size,
				      unsigned int size)
{
	u32 max_size;

#define F1XH_MPB_MAX_SIZE 2048
#define F14H_MPB_MAX_SIZE 1824
#define F15H_MPB_MAX_SIZE 4096
#define F16H_MPB_MAX_SIZE 3458
#define F17H_MPB_MAX_SIZE 3200

	switch (family) {
	case 0x14:
		max_size = F14H_MPB_MAX_SIZE;
		break;
	case 0x15:
		max_size = F15H_MPB_MAX_SIZE;
		break;
	case 0x16:
		max_size = F16H_MPB_MAX_SIZE;
		break;
	case 0x17:
		max_size = F17H_MPB_MAX_SIZE;
		break;
	default:
		max_size = F1XH_MPB_MAX_SIZE;
		break;
	}

	if (patch_size > min_t(u32, size, max_size)) {
		pr_err("patch size mismatch\n");
		return 0;
	}

	return patch_size;
}

/*
 * Those patch levels cannot be updated to newer ones and thus should be final.
 */
static u32 final_levels[] = {
	0x01000098,
	0x0100009f,
	0x010000af,
	0, /* T-101 terminator */
};

/*
 * Check the current patch level on this CPU.
 *
 * @rev: Use it to return the patch level. It is set to 0 in the case of
 * error.
 *
 * Returns:
 *  - true: if update should stop
 *  - false: otherwise
 */
bool check_current_patch_level(u32 *rev, bool early)
{
	u32 lvl, dummy, i;
	bool ret = false;
	u32 *levels;

	native_rdmsr(MSR_AMD64_PATCH_LEVEL, lvl, dummy);

	if (IS_ENABLED(CONFIG_X86_32) && early)
		levels = (u32 *)__pa_nodebug(&final_levels);
	else
		levels = final_levels;

	for (i = 0; levels[i]; i++) {
		if (lvl == levels[i]) {
			lvl = 0;
			ret = true;
			break;
		}
	}

	if (rev)
		*rev = lvl;

	return ret;
}

int __apply_microcode_amd(struct microcode_amd *mc_amd)
{
	u32 rev, dummy;

	native_wrmsrl(MSR_AMD64_PATCH_LOADER, (u64)(long)&mc_amd->hdr.data_code);

	/* verify patch application was successful */
	native_rdmsr(MSR_AMD64_PATCH_LEVEL, rev, dummy);
	if (rev != mc_amd->hdr.patch_id)
		return -1;

	return 0;
}

int apply_microcode_amd(int cpu)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	struct microcode_amd *mc_amd;
	struct ucode_cpu_info *uci;
	struct ucode_patch *p;
	u32 rev;

	BUG_ON(raw_smp_processor_id() != cpu);

	uci = ucode_cpu_info + cpu;

	p = find_patch(cpu);
	if (!p)
		return 0;

	mc_amd  = p->data;
	uci->mc = p->data;

	if (check_current_patch_level(&rev, false))
		return -1;

	/* need to apply patch? */
	if (rev >= mc_amd->hdr.patch_id)
		goto out;

	if (__apply_microcode_amd(mc_amd)) {
		pr_err("CPU%d: update failed for patch_level=0x%08x\n",
			cpu, mc_amd->hdr.patch_id);
		return -1;
	}

	rev = mc_amd->hdr.patch_id;

	pr_info("CPU%d: new patch_level=0x%08x\n", cpu, rev);

out:
	uci->cpu_sig.rev = rev;
	c->microcode	 = rev;

	/* Update boot_cpu_data's revision too, if we're on the BSP: */
	if (c->cpu_index == boot_cpu_data.cpu_index)
		boot_cpu_data.microcode = rev;

	return 0;
}

static int install_equiv_cpu_table(const u8 *buf)
{
	unsigned int *ibuf = (unsigned int *)buf;
	unsigned int type = ibuf[1];
	unsigned int size = ibuf[2];

	if (type != UCODE_EQUIV_CPU_TABLE_TYPE || !size) {
		pr_err("empty section/"
		       "invalid type field in container file section header\n");
		return -EINVAL;
	}

	equiv_cpu_table = vmalloc(size);
	if (!equiv_cpu_table) {
		pr_err("failed to allocate equivalent CPU table\n");
		return -ENOMEM;
	}

	memcpy(equiv_cpu_table, buf + CONTAINER_HDR_SZ, size);

	/* add header length */
	return size + CONTAINER_HDR_SZ;
}

static void free_equiv_cpu_table(void)
{
	vfree(equiv_cpu_table);
	equiv_cpu_table = NULL;
}

static void cleanup(void)
{
	free_equiv_cpu_table();
	free_cache();
}

/*
 * We return the current size even if some of the checks failed so that
 * we can skip over the next patch. If we return a negative value, we
 * signal a grave error like a memory allocation has failed and the
 * driver cannot continue functioning normally. In such cases, we tear
 * down everything we've used up so far and exit.
 */
static int verify_and_add_patch(u8 family, u8 *fw, unsigned int leftover)
{
	struct microcode_header_amd *mc_hdr;
	struct ucode_patch *patch;
	unsigned int patch_size, crnt_size, ret;
	u32 proc_fam;
	u16 proc_id;

	patch_size  = *(u32 *)(fw + 4);
	crnt_size   = patch_size + SECTION_HDR_SIZE;
	mc_hdr	    = (struct microcode_header_amd *)(fw + SECTION_HDR_SIZE);
	proc_id	    = mc_hdr->processor_rev_id;

	proc_fam = find_cpu_family_by_equiv_cpu(proc_id);
	if (!proc_fam) {
		pr_err("No patch family for equiv ID: 0x%04x\n", proc_id);
		return crnt_size;
	}

	/* check if patch is for the current family */
	proc_fam = ((proc_fam >> 8) & 0xf) + ((proc_fam >> 20) & 0xff);
	if (proc_fam != family)
		return crnt_size;

	if (mc_hdr->nb_dev_id || mc_hdr->sb_dev_id) {
		pr_err("Patch-ID 0x%08x: chipset-specific code unsupported.\n",
			mc_hdr->patch_id);
		return crnt_size;
	}

	ret = verify_patch_size(family, patch_size, leftover);
	if (!ret) {
		pr_err("Patch-ID 0x%08x: size mismatch.\n", mc_hdr->patch_id);
		return crnt_size;
	}

	patch = kzalloc(sizeof(*patch), GFP_KERNEL);
	if (!patch) {
		pr_err("Patch allocation failure.\n");
		return -EINVAL;
	}

	patch->data = kmemdup(fw + SECTION_HDR_SIZE, patch_size, GFP_KERNEL);
	if (!patch->data) {
		pr_err("Patch data allocation failure.\n");
		kfree(patch);
		return -EINVAL;
	}

	INIT_LIST_HEAD(&patch->plist);
	patch->patch_id  = mc_hdr->patch_id;
	patch->equiv_cpu = proc_id;

	pr_debug("%s: Added patch_id: 0x%08x, proc_id: 0x%04x\n",
		 __func__, patch->patch_id, proc_id);

	/* ... and add to cache. */
	update_cache(patch);

	return crnt_size;
}

static enum ucode_state __load_microcode_amd(u8 family, const u8 *data,
					     size_t size)
{
	enum ucode_state ret = UCODE_ERROR;
	unsigned int leftover;
	u8 *fw = (u8 *)data;
	int crnt_size = 0;
	int offset;

	offset = install_equiv_cpu_table(data);
	if (offset < 0) {
		pr_err("failed to create equivalent cpu table\n");
		return ret;
	}
	fw += offset;
	leftover = size - offset;

	if (*(u32 *)fw != UCODE_UCODE_TYPE) {
		pr_err("invalid type field in container file section header\n");
		free_equiv_cpu_table();
		return ret;
	}

	while (leftover) {
		crnt_size = verify_and_add_patch(family, fw, leftover);
		if (crnt_size < 0)
			return ret;

		fw	 += crnt_size;
		leftover -= crnt_size;
	}

	return UCODE_OK;
}

static enum ucode_state
load_microcode_amd(bool save, u8 family, const u8 *data, size_t size)
{
	enum ucode_state ret;

	/* free old equiv table */
	free_equiv_cpu_table();

	ret = __load_microcode_amd(family, data, size);

	if (ret != UCODE_OK)
		cleanup();

#ifdef CONFIG_X86_32
	/* save BSP's matching patch for early load */
	if (save) {
		struct ucode_patch *p = find_patch(0);
		if (p) {
			memset(amd_ucode_patch, 0, PATCH_MAX_SIZE);
			memcpy(amd_ucode_patch, p->data, min_t(u32, ksize(p->data),
							       PATCH_MAX_SIZE));
		}
	}
#endif
	return ret;
}

/*
 * AMD microcode firmware naming convention, up to family 15h they are in
 * the legacy file:
 *
 *    amd-ucode/microcode_amd.bin
 *
 * This legacy file is always smaller than 2K in size.
 *
 * Beginning with family 15h, they are in family-specific firmware files:
 *
 *    amd-ucode/microcode_amd_fam15h.bin
 *    amd-ucode/microcode_amd_fam16h.bin
 *    ...
 *
 * These might be larger than 2K.
 */
static enum ucode_state request_microcode_amd(int cpu, struct device *device,
					      bool refresh_fw)
{
	char fw_name[36] = "amd-ucode/microcode_amd.bin";
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	bool bsp = c->cpu_index == boot_cpu_data.cpu_index;
	enum ucode_state ret = UCODE_NFOUND;
	const struct firmware *fw;

	/* reload ucode container only on the boot cpu */
	if (!refresh_fw || !bsp)
		return UCODE_OK;

	if (c->x86 >= 0x15)
		snprintf(fw_name, sizeof(fw_name), "amd-ucode/microcode_amd_fam%.2xh.bin", c->x86);

	if (request_firmware_direct(&fw, (const char *)fw_name, device)) {
		pr_debug("failed to load file %s\n", fw_name);
		goto out;
	}

	ret = UCODE_ERROR;
	if (*(u32 *)fw->data != UCODE_MAGIC) {
		pr_err("invalid magic value (0x%08x)\n", *(u32 *)fw->data);
		goto fw_release;
	}

	ret = load_microcode_amd(bsp, c->x86, fw->data, fw->size);

 fw_release:
	release_firmware(fw);

 out:
	return ret;
}

static enum ucode_state
request_microcode_user(int cpu, const void __user *buf, size_t size)
{
	return UCODE_ERROR;
}

static void microcode_fini_cpu_amd(int cpu)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	uci->mc = NULL;
}

static struct microcode_ops microcode_amd_ops = {
	.request_microcode_user           = request_microcode_user,
	.request_microcode_fw             = request_microcode_amd,
	.collect_cpu_info                 = collect_cpu_info_amd,
	.apply_microcode                  = apply_microcode_amd,
	.microcode_fini_cpu               = microcode_fini_cpu_amd,
};

struct microcode_ops * __init init_amd_microcode(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (c->x86_vendor != X86_VENDOR_AMD || c->x86 < 0x10) {
		pr_warn("AMD CPU family 0x%x not supported\n", c->x86);
		return NULL;
	}

	if (ucode_new_rev)
		pr_info_once("microcode updated early to new patch_level=0x%08x\n",
			     ucode_new_rev);

	return &microcode_amd_ops;
}

void __exit exit_amd_microcode(void)
{
	cleanup();
}
