// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 Linaro Ltd;  <ard.biesheuvel@linaro.org>
 */

#include <linux/efi.h>
#include <linux/log2.h>
#include <asm/efi.h>

#include "efistub.h"

typedef union efi_rng_protocol efi_rng_protocol_t;

union efi_rng_protocol {
	struct {
		efi_status_t (__efiapi *get_info)(efi_rng_protocol_t *,
						  unsigned long *,
						  efi_guid_t *);
		efi_status_t (__efiapi *get_rng)(efi_rng_protocol_t *,
						 efi_guid_t *, unsigned long,
						 u8 *out);
	};
	struct {
		u32 get_info;
		u32 get_rng;
	} mixed_mode;
};

efi_status_t efi_get_random_bytes(unsigned long size, u8 *out)
{
	efi_guid_t rng_proto = EFI_RNG_PROTOCOL_GUID;
	efi_status_t status;
	efi_rng_protocol_t *rng = NULL;

	status = efi_bs_call(locate_protocol, &rng_proto, NULL, (void **)&rng);
	if (status != EFI_SUCCESS)
		return status;

	return efi_call_proto(rng, get_rng, NULL, size, out);
}

/*
 * Return the number of slots covered by this entry, i.e., the number of
 * addresses it covers that are suitably aligned and supply enough room
 * for the allocation.
 */
static unsigned long get_entry_num_slots(efi_memory_desc_t *md,
					 unsigned long size,
					 unsigned long align_shift)
{
	unsigned long align = 1UL << align_shift;
	u64 first_slot, last_slot, region_end;

	if (md->type != EFI_CONVENTIONAL_MEMORY)
		return 0;

	if (efi_soft_reserve_enabled() &&
	    (md->attribute & EFI_MEMORY_SP))
		return 0;

	region_end = min((u64)ULONG_MAX, md->phys_addr + md->num_pages*EFI_PAGE_SIZE - 1);

	first_slot = round_up(md->phys_addr, align);
	last_slot = round_down(region_end - size + 1, align);

	if (first_slot > last_slot)
		return 0;

	return ((unsigned long)(last_slot - first_slot) >> align_shift) + 1;
}

/*
 * The UEFI memory descriptors have a virtual address field that is only used
 * when installing the virtual mapping using SetVirtualAddressMap(). Since it
 * is unused here, we can reuse it to keep track of each descriptor's slot
 * count.
 */
#define MD_NUM_SLOTS(md)	((md)->virt_addr)

efi_status_t efi_random_alloc(unsigned long size,
			      unsigned long align,
			      unsigned long *addr,
			      unsigned long random_seed)
{
	unsigned long map_size, desc_size, total_slots = 0, target_slot;
	unsigned long buff_size;
	efi_status_t status;
	efi_memory_desc_t *memory_map;
	int map_offset;
	struct efi_boot_memmap map;

	map.map =	&memory_map;
	map.map_size =	&map_size;
	map.desc_size =	&desc_size;
	map.desc_ver =	NULL;
	map.key_ptr =	NULL;
	map.buff_size =	&buff_size;

	status = efi_get_memory_map(&map);
	if (status != EFI_SUCCESS)
		return status;

	if (align < EFI_ALLOC_ALIGN)
		align = EFI_ALLOC_ALIGN;

	/* count the suitable slots in each memory map entry */
	for (map_offset = 0; map_offset < map_size; map_offset += desc_size) {
		efi_memory_desc_t *md = (void *)memory_map + map_offset;
		unsigned long slots;

		slots = get_entry_num_slots(md, size, ilog2(align));
		MD_NUM_SLOTS(md) = slots;
		total_slots += slots;
	}

	/* find a random number between 0 and total_slots */
	target_slot = (total_slots * (u16)random_seed) >> 16;

	/*
	 * target_slot is now a value in the range [0, total_slots), and so
	 * it corresponds with exactly one of the suitable slots we recorded
	 * when iterating over the memory map the first time around.
	 *
	 * So iterate over the memory map again, subtracting the number of
	 * slots of each entry at each iteration, until we have found the entry
	 * that covers our chosen slot. Use the residual value of target_slot
	 * to calculate the randomly chosen address, and allocate it directly
	 * using EFI_ALLOCATE_ADDRESS.
	 */
	for (map_offset = 0; map_offset < map_size; map_offset += desc_size) {
		efi_memory_desc_t *md = (void *)memory_map + map_offset;
		efi_physical_addr_t target;
		unsigned long pages;

		if (target_slot >= MD_NUM_SLOTS(md)) {
			target_slot -= MD_NUM_SLOTS(md);
			continue;
		}

		target = round_up(md->phys_addr, align) + target_slot * align;
		pages = round_up(size, EFI_PAGE_SIZE) / EFI_PAGE_SIZE;

		status = efi_bs_call(allocate_pages, EFI_ALLOCATE_ADDRESS,
				     EFI_LOADER_DATA, pages, &target);
		if (status == EFI_SUCCESS)
			*addr = target;
		break;
	}

	efi_bs_call(free_pool, memory_map);

	return status;
}

efi_status_t efi_random_get_seed(void)
{
	efi_guid_t rng_proto = EFI_RNG_PROTOCOL_GUID;
	efi_guid_t rng_algo_raw = EFI_RNG_ALGORITHM_RAW;
	efi_guid_t rng_table_guid = LINUX_EFI_RANDOM_SEED_TABLE_GUID;
	efi_rng_protocol_t *rng = NULL;
	struct linux_efi_random_seed *seed = NULL;
	efi_status_t status;

	status = efi_bs_call(locate_protocol, &rng_proto, NULL, (void **)&rng);
	if (status != EFI_SUCCESS)
		return status;

	status = efi_bs_call(allocate_pool, EFI_RUNTIME_SERVICES_DATA,
			     sizeof(*seed) + EFI_RANDOM_SEED_SIZE,
			     (void **)&seed);
	if (status != EFI_SUCCESS)
		return status;

	status = efi_call_proto(rng, get_rng, &rng_algo_raw,
				 EFI_RANDOM_SEED_SIZE, seed->bits);

	if (status == EFI_UNSUPPORTED)
		/*
		 * Use whatever algorithm we have available if the raw algorithm
		 * is not implemented.
		 */
		status = efi_call_proto(rng, get_rng, NULL,
					EFI_RANDOM_SEED_SIZE, seed->bits);

	if (status != EFI_SUCCESS)
		goto err_freepool;

	seed->size = EFI_RANDOM_SEED_SIZE;
	status = efi_bs_call(install_configuration_table, &rng_table_guid, seed);
	if (status != EFI_SUCCESS)
		goto err_freepool;

	return EFI_SUCCESS;

err_freepool:
	efi_bs_call(free_pool, seed);
	return status;
}
