/*
 * Copyright 2014 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "kfd_device_queue_manager.h"
#include "gca/gfx_8_0_enum.h"
#include "gca/gfx_8_0_sh_mask.h"
#include "gca/gfx_8_0_enum.h"
#include "oss/oss_3_0_sh_mask.h"

static bool set_cache_memory_policy_vi(struct device_queue_manager *dqm,
				   struct qcm_process_device *qpd,
				   enum cache_policy default_policy,
				   enum cache_policy alternate_policy,
				   void __user *alternate_aperture_base,
				   uint64_t alternate_aperture_size);
static bool set_cache_memory_policy_vi_tonga(struct device_queue_manager *dqm,
			struct qcm_process_device *qpd,
			enum cache_policy default_policy,
			enum cache_policy alternate_policy,
			void __user *alternate_aperture_base,
			uint64_t alternate_aperture_size);
static int update_qpd_vi(struct device_queue_manager *dqm,
					struct qcm_process_device *qpd);
static int update_qpd_vi_tonga(struct device_queue_manager *dqm,
			struct qcm_process_device *qpd);
static void init_sdma_vm(struct device_queue_manager *dqm, struct queue *q,
				struct qcm_process_device *qpd);
static void init_sdma_vm_tonga(struct device_queue_manager *dqm,
			struct queue *q,
			struct qcm_process_device *qpd);

void device_queue_manager_init_vi(
		struct device_queue_manager_asic_ops *asic_ops)
{
	asic_ops->set_cache_memory_policy = set_cache_memory_policy_vi;
	asic_ops->update_qpd = update_qpd_vi;
	asic_ops->init_sdma_vm = init_sdma_vm;
}

void device_queue_manager_init_vi_tonga(
		struct device_queue_manager_asic_ops *asic_ops)
{
	asic_ops->set_cache_memory_policy = set_cache_memory_policy_vi_tonga;
	asic_ops->update_qpd = update_qpd_vi_tonga;
	asic_ops->init_sdma_vm = init_sdma_vm_tonga;
}

static uint32_t compute_sh_mem_bases_64bit(unsigned int top_address_nybble)
{
	/* In 64-bit mode, we can only control the top 3 bits of the LDS,
	 * scratch and GPUVM apertures.
	 * The hardware fills in the remaining 59 bits according to the
	 * following pattern:
	 * LDS:		X0000000'00000000 - X0000001'00000000 (4GB)
	 * Scratch:	X0000001'00000000 - X0000002'00000000 (4GB)
	 * GPUVM:	Y0010000'00000000 - Y0020000'00000000 (1TB)
	 *
	 * (where X/Y is the configurable nybble with the low-bit 0)
	 *
	 * LDS and scratch will have the same top nybble programmed in the
	 * top 3 bits of SH_MEM_BASES.PRIVATE_BASE.
	 * GPUVM can have a different top nybble programmed in the
	 * top 3 bits of SH_MEM_BASES.SHARED_BASE.
	 * We don't bother to support different top nybbles
	 * for LDS/Scratch and GPUVM.
	 */

	WARN_ON((top_address_nybble & 1) || top_address_nybble > 0xE ||
		top_address_nybble == 0);

	return top_address_nybble << 12 |
			(top_address_nybble << 12) <<
			SH_MEM_BASES__SHARED_BASE__SHIFT;
}

static bool set_cache_memory_policy_vi(struct device_queue_manager *dqm,
				   struct qcm_process_device *qpd,
				   enum cache_policy default_policy,
				   enum cache_policy alternate_policy,
				   void __user *alternate_aperture_base,
				   uint64_t alternate_aperture_size)
{
	uint32_t default_mtype;
	uint32_t ape1_mtype;

	default_mtype = (default_policy == cache_policy_coherent) ?
			MTYPE_CC :
			MTYPE_NC;

	ape1_mtype = (alternate_policy == cache_policy_coherent) ?
			MTYPE_CC :
			MTYPE_NC;

	qpd->sh_mem_config = (qpd->sh_mem_config &
			SH_MEM_CONFIG__ADDRESS_MODE_MASK) |
		SH_MEM_ALIGNMENT_MODE_UNALIGNED <<
				SH_MEM_CONFIG__ALIGNMENT_MODE__SHIFT |
		default_mtype << SH_MEM_CONFIG__DEFAULT_MTYPE__SHIFT |
		ape1_mtype << SH_MEM_CONFIG__APE1_MTYPE__SHIFT |
		SH_MEM_CONFIG__PRIVATE_ATC_MASK;

	return true;
}

static bool set_cache_memory_policy_vi_tonga(struct device_queue_manager *dqm,
		struct qcm_process_device *qpd,
		enum cache_policy default_policy,
		enum cache_policy alternate_policy,
		void __user *alternate_aperture_base,
		uint64_t alternate_aperture_size)
{
	uint32_t default_mtype;
	uint32_t ape1_mtype;

	default_mtype = (default_policy == cache_policy_coherent) ?
			MTYPE_UC :
			MTYPE_NC;

	ape1_mtype = (alternate_policy == cache_policy_coherent) ?
			MTYPE_UC :
			MTYPE_NC;

	qpd->sh_mem_config =
			SH_MEM_ALIGNMENT_MODE_UNALIGNED <<
				   SH_MEM_CONFIG__ALIGNMENT_MODE__SHIFT |
			default_mtype << SH_MEM_CONFIG__DEFAULT_MTYPE__SHIFT |
			ape1_mtype << SH_MEM_CONFIG__APE1_MTYPE__SHIFT;

	return true;
}

static int update_qpd_vi(struct device_queue_manager *dqm,
					struct qcm_process_device *qpd)
{
	struct kfd_process_device *pdd;
	unsigned int temp;

	pdd = qpd_to_pdd(qpd);

	/* check if sh_mem_config register already configured */
	if (qpd->sh_mem_config == 0) {
		qpd->sh_mem_config =
			SH_MEM_ALIGNMENT_MODE_UNALIGNED <<
				SH_MEM_CONFIG__ALIGNMENT_MODE__SHIFT |
			MTYPE_CC << SH_MEM_CONFIG__DEFAULT_MTYPE__SHIFT |
			MTYPE_CC << SH_MEM_CONFIG__APE1_MTYPE__SHIFT |
			SH_MEM_CONFIG__PRIVATE_ATC_MASK;

		qpd->sh_mem_ape1_limit = 0;
		qpd->sh_mem_ape1_base = 0;
	}

	if (qpd->pqm->process->is_32bit_user_mode) {
		temp = get_sh_mem_bases_32(pdd);
		qpd->sh_mem_bases = temp << SH_MEM_BASES__SHARED_BASE__SHIFT;
		qpd->sh_mem_config |= SH_MEM_ADDRESS_MODE_HSA32 <<
					SH_MEM_CONFIG__ADDRESS_MODE__SHIFT;
	} else {
		temp = get_sh_mem_bases_nybble_64(pdd);
		qpd->sh_mem_bases = compute_sh_mem_bases_64bit(temp);
		qpd->sh_mem_config |= SH_MEM_ADDRESS_MODE_HSA64 <<
			SH_MEM_CONFIG__ADDRESS_MODE__SHIFT;
		qpd->sh_mem_config |= 1  <<
			SH_MEM_CONFIG__PRIVATE_ATC__SHIFT;
	}

	pr_debug("is32bit process: %d sh_mem_bases nybble: 0x%X and register 0x%X\n",
		qpd->pqm->process->is_32bit_user_mode, temp, qpd->sh_mem_bases);

	return 0;
}

static int update_qpd_vi_tonga(struct device_queue_manager *dqm,
			struct qcm_process_device *qpd)
{
	struct kfd_process_device *pdd;
	unsigned int temp;

	pdd = qpd_to_pdd(qpd);

	/* check if sh_mem_config register already configured */
	if (qpd->sh_mem_config == 0) {
		qpd->sh_mem_config =
				SH_MEM_ALIGNMENT_MODE_UNALIGNED <<
					SH_MEM_CONFIG__ALIGNMENT_MODE__SHIFT |
				MTYPE_UC <<
					SH_MEM_CONFIG__DEFAULT_MTYPE__SHIFT |
				MTYPE_UC <<
					SH_MEM_CONFIG__APE1_MTYPE__SHIFT;

		qpd->sh_mem_ape1_limit = 0;
		qpd->sh_mem_ape1_base = 0;
	}

	/* On dGPU we're always in GPUVM64 addressing mode with 64-bit
	 * aperture addresses.
	 */
	temp = get_sh_mem_bases_nybble_64(pdd);
	qpd->sh_mem_bases = compute_sh_mem_bases_64bit(temp);

	pr_debug("sh_mem_bases nybble: 0x%X and register 0x%X\n",
		temp, qpd->sh_mem_bases);

	return 0;
}

static void init_sdma_vm(struct device_queue_manager *dqm, struct queue *q,
				struct qcm_process_device *qpd)
{
	uint32_t value = (1 << SDMA0_RLC0_VIRTUAL_ADDR__ATC__SHIFT);

	if (q->process->is_32bit_user_mode)
		value |= (1 << SDMA0_RLC0_VIRTUAL_ADDR__PTR32__SHIFT) |
				get_sh_mem_bases_32(qpd_to_pdd(qpd));
	else
		value |= ((get_sh_mem_bases_nybble_64(qpd_to_pdd(qpd))) <<
				SDMA0_RLC0_VIRTUAL_ADDR__SHARED_BASE__SHIFT) &
				SDMA0_RLC0_VIRTUAL_ADDR__SHARED_BASE_MASK;

	q->properties.sdma_vm_addr = value;
}

static void init_sdma_vm_tonga(struct device_queue_manager *dqm,
			struct queue *q,
			struct qcm_process_device *qpd)
{
	/* On dGPU we're always in GPUVM64 addressing mode with 64-bit
	 * aperture addresses.
	 */
	q->properties.sdma_vm_addr =
		((get_sh_mem_bases_nybble_64(qpd_to_pdd(qpd))) <<
		 SDMA0_RLC0_VIRTUAL_ADDR__SHARED_BASE__SHIFT) &
		SDMA0_RLC0_VIRTUAL_ADDR__SHARED_BASE_MASK;
}
