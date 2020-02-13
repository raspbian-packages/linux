/*
* Copyright 2018 Advanced Micro Devices, Inc.
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
 * Authors: AMD
 *
 */
#ifndef DAL_DC_DCN21_DCN21_HUBBUB_H_
#define DAL_DC_DCN21_DCN21_HUBBUB_H_

#include "dcn20/dcn20_hubbub.h"

#define HUBBUB_HVM_REG_LIST() \
	SR(DCHUBBUB_ARB_FRAC_URG_BW_NOM_A),\
	SR(DCHUBBUB_ARB_FRAC_URG_BW_NOM_B),\
	SR(DCHUBBUB_ARB_FRAC_URG_BW_NOM_C),\
	SR(DCHUBBUB_ARB_FRAC_URG_BW_NOM_D),\
	SR(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_A),\
	SR(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_B),\
	SR(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_C),\
	SR(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_D),\
	SR(DCHUBBUB_ARB_HOSTVM_CNTL), \
	SR(DCHVM_CTRL0), \
	SR(DCHVM_MEM_CTRL), \
	SR(DCHVM_CLK_CTRL), \
	SR(DCHVM_RIOMMU_CTRL0), \
	SR(DCHVM_RIOMMU_STAT0)

#define HUBBUB_REG_LIST_DCN21()\
	HUBBUB_REG_LIST_DCN_COMMON(), \
	HUBBUB_SR_WATERMARK_REG_LIST(), \
	HUBBUB_HVM_REG_LIST(), \
	SR(DCHUBBUB_CRC_CTRL), \
	SR(DCN_VM_FB_LOCATION_BASE),\
	SR(DCN_VM_FB_LOCATION_TOP),\
	SR(DCN_VM_FB_OFFSET),\
	SR(DCN_VM_AGP_BOT),\
	SR(DCN_VM_AGP_TOP),\
	SR(DCN_VM_AGP_BASE)

#define HUBBUB_MASK_SH_LIST_HVM(mask_sh) \
	HUBBUB_SF(DCHUBBUB_ARB_DF_REQ_OUTSTAND, DCHUBBUB_ARB_MIN_REQ_OUTSTAND_COMMIT_THRESHOLD, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_A, DCHUBBUB_ARB_FRAC_URG_BW_FLIP_A, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_B, DCHUBBUB_ARB_FRAC_URG_BW_FLIP_B, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_C, DCHUBBUB_ARB_FRAC_URG_BW_FLIP_C, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_FLIP_D, DCHUBBUB_ARB_FRAC_URG_BW_FLIP_D, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_NOM_A, DCHUBBUB_ARB_FRAC_URG_BW_NOM_A, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_NOM_B, DCHUBBUB_ARB_FRAC_URG_BW_NOM_B, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_NOM_C, DCHUBBUB_ARB_FRAC_URG_BW_NOM_C, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_FRAC_URG_BW_NOM_D, DCHUBBUB_ARB_FRAC_URG_BW_NOM_D, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A, DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_A, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B, DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_B, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_C, DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_C, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_D, DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_D, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_A, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_B, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_B, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_C, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_C, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_D, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_D, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_A, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_B, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_B, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_C, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_C, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_D, DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_D, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A, DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B, DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C, DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D, DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_HOSTVM_CNTL, DCHUBBUB_ARB_MAX_QOS_COMMIT_THRESHOLD, mask_sh), \
	HUBBUB_SF(DCHVM_CTRL0, HOSTVM_INIT_REQ, mask_sh), \
	HUBBUB_SF(DCHVM_MEM_CTRL, HVM_GPUVMRET_PWR_REQ_DIS, mask_sh), \
	HUBBUB_SF(DCHVM_MEM_CTRL, HVM_GPUVMRET_FORCE_REQ, mask_sh), \
	HUBBUB_SF(DCHVM_MEM_CTRL, HVM_GPUVMRET_POWER_STATUS, mask_sh), \
	HUBBUB_SF(DCHVM_CLK_CTRL, HVM_DISPCLK_R_GATE_DIS, mask_sh), \
	HUBBUB_SF(DCHVM_CLK_CTRL, HVM_DISPCLK_G_GATE_DIS, mask_sh), \
	HUBBUB_SF(DCHVM_CLK_CTRL, HVM_DCFCLK_R_GATE_DIS, mask_sh), \
	HUBBUB_SF(DCHVM_CLK_CTRL, HVM_DCFCLK_G_GATE_DIS, mask_sh), \
	HUBBUB_SF(DCHVM_CLK_CTRL, TR_REQ_REQCLKREQ_MODE, mask_sh), \
	HUBBUB_SF(DCHVM_CLK_CTRL, TW_RSP_COMPCLKREQ_MODE, mask_sh), \
	HUBBUB_SF(DCHVM_RIOMMU_CTRL0, HOSTVM_PREFETCH_REQ, mask_sh), \
	HUBBUB_SF(DCHVM_RIOMMU_CTRL0, HOSTVM_POWERSTATUS, mask_sh), \
	HUBBUB_SF(DCHVM_RIOMMU_STAT0, RIOMMU_ACTIVE, mask_sh), \
	HUBBUB_SF(DCHVM_RIOMMU_STAT0, HOSTVM_PREFETCH_DONE, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A, DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_B, DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_B, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_C, DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_C, mask_sh), \
	HUBBUB_SF(DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_D, DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_D, mask_sh)

#define HUBBUB_MASK_SH_LIST_DCN21(mask_sh)\
	HUBBUB_MASK_SH_LIST_HVM(mask_sh),\
	HUBBUB_MASK_SH_LIST_DCN_COMMON(mask_sh), \
	HUBBUB_MASK_SH_LIST_STUTTER(mask_sh), \
	HUBBUB_SF(DCHUBBUB_GLOBAL_TIMER_CNTL, DCHUBBUB_GLOBAL_TIMER_REFDIV, mask_sh), \
	HUBBUB_SF(DCN_VM_FB_LOCATION_BASE, FB_BASE, mask_sh), \
	HUBBUB_SF(DCN_VM_FB_LOCATION_TOP, FB_TOP, mask_sh), \
	HUBBUB_SF(DCN_VM_FB_OFFSET, FB_OFFSET, mask_sh), \
	HUBBUB_SF(DCN_VM_AGP_BOT, AGP_BOT, mask_sh), \
	HUBBUB_SF(DCN_VM_AGP_TOP, AGP_TOP, mask_sh), \
	HUBBUB_SF(DCN_VM_AGP_BASE, AGP_BASE, mask_sh)

void dcn21_dchvm_init(struct hubbub *hubbub);
void hubbub21_program_watermarks(
		struct hubbub *hubbub,
		struct dcn_watermark_set *watermarks,
		unsigned int refclk_mhz,
		bool safe_to_lower);

void hubbub21_wm_read_state(struct hubbub *hubbub,
		struct dcn_hubbub_wm *wm);

void hubbub21_construct(struct dcn20_hubbub *hubbub,
	struct dc_context *ctx,
	const struct dcn_hubbub_registers *hubbub_regs,
	const struct dcn_hubbub_shift *hubbub_shift,
	const struct dcn_hubbub_mask *hubbub_mask);

#endif /* DAL_DC_DCN21_DCN21_HUBBUB_H_ */
