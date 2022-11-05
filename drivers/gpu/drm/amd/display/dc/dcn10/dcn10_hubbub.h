/*
 * Copyright 2016 Advanced Micro Devices, Inc.
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

#ifndef __DC_HUBBUB_DCN10_H__
#define __DC_HUBBUB_DCN10_H__

#include "core_types.h"
#include "dchubbub.h"

#define TO_DCN10_HUBBUB(hubbub)\
	container_of(hubbub, struct dcn10_hubbub, base)

#define HUBBUB_REG_LIST_DCN_COMMON()\
	SR(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A),\
	SR(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A),\
	SR(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B),\
	SR(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B),\
	SR(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_C),\
	SR(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C),\
	SR(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_D),\
	SR(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D),\
	SR(DCHUBBUB_ARB_WATERMARK_CHANGE_CNTL),\
	SR(DCHUBBUB_ARB_DRAM_STATE_CNTL),\
	SR(DCHUBBUB_ARB_SAT_LEVEL),\
	SR(DCHUBBUB_ARB_DF_REQ_OUTSTAND),\
	SR(DCHUBBUB_GLOBAL_TIMER_CNTL), \
	SR(DCHUBBUB_TEST_DEBUG_INDEX), \
	SR(DCHUBBUB_TEST_DEBUG_DATA),\
	SR(DCHUBBUB_SOFT_RESET)

#define HUBBUB_VM_REG_LIST() \
	SR(DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_A),\
	SR(DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_B),\
	SR(DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_C),\
	SR(DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_D)

#define HUBBUB_SR_WATERMARK_REG_LIST()\
	SR(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A),\
	SR(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A),\
	SR(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_B),\
	SR(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_B),\
	SR(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_C),\
	SR(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_C),\
	SR(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_D),\
	SR(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_D)

#define HUBBUB_REG_LIST_DCN10(id)\
	HUBBUB_REG_LIST_DCN_COMMON(), \
	HUBBUB_VM_REG_LIST(), \
	HUBBUB_SR_WATERMARK_REG_LIST(), \
	SR(DCHUBBUB_SDPIF_FB_TOP),\
	SR(DCHUBBUB_SDPIF_FB_BASE),\
	SR(DCHUBBUB_SDPIF_FB_OFFSET),\
	SR(DCHUBBUB_SDPIF_AGP_BASE),\
	SR(DCHUBBUB_SDPIF_AGP_BOT),\
	SR(DCHUBBUB_SDPIF_AGP_TOP)

struct dcn_hubbub_registers {
	uint32_t DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_D;
	uint32_t DCHUBBUB_ARB_PTE_META_URGENCY_WATERMARK_D;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_D;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_D;
	uint32_t DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D;
	uint32_t DCHUBBUB_ARB_WATERMARK_CHANGE_CNTL;
	uint32_t DCHUBBUB_ARB_SAT_LEVEL;
	uint32_t DCHUBBUB_ARB_DF_REQ_OUTSTAND;
	uint32_t DCHUBBUB_GLOBAL_TIMER_CNTL;
	uint32_t DCHUBBUB_ARB_DRAM_STATE_CNTL;
	uint32_t DCHUBBUB_TEST_DEBUG_INDEX;
	uint32_t DCHUBBUB_TEST_DEBUG_DATA;
	uint32_t DCHUBBUB_SDPIF_FB_TOP;
	uint32_t DCHUBBUB_SDPIF_FB_BASE;
	uint32_t DCHUBBUB_SDPIF_FB_OFFSET;
	uint32_t DCHUBBUB_SDPIF_AGP_BASE;
	uint32_t DCHUBBUB_SDPIF_AGP_BOT;
	uint32_t DCHUBBUB_SDPIF_AGP_TOP;
	uint32_t DCHUBBUB_CRC_CTRL;
	uint32_t DCHUBBUB_SOFT_RESET;
	uint32_t DCN_VM_FB_LOCATION_BASE;
	uint32_t DCN_VM_FB_LOCATION_TOP;
	uint32_t DCN_VM_FB_OFFSET;
	uint32_t DCN_VM_AGP_BOT;
	uint32_t DCN_VM_AGP_TOP;
	uint32_t DCN_VM_AGP_BASE;
	uint32_t DCN_VM_PROTECTION_FAULT_DEFAULT_ADDR_MSB;
	uint32_t DCN_VM_PROTECTION_FAULT_DEFAULT_ADDR_LSB;
	uint32_t DCN_VM_FAULT_ADDR_MSB;
	uint32_t DCN_VM_FAULT_ADDR_LSB;
	uint32_t DCN_VM_FAULT_CNTL;
	uint32_t DCN_VM_FAULT_STATUS;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_NOM_A;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_NOM_B;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_NOM_C;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_NOM_D;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_FLIP_A;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_FLIP_B;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_FLIP_C;
	uint32_t DCHUBBUB_ARB_FRAC_URG_BW_FLIP_D;
	uint32_t DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A;
	uint32_t DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_B;
	uint32_t DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_C;
	uint32_t DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_D;
	uint32_t DCHUBBUB_ARB_HOSTVM_CNTL;
	uint32_t DCHVM_CTRL0;
	uint32_t DCHVM_MEM_CTRL;
	uint32_t DCHVM_CLK_CTRL;
	uint32_t DCHVM_RIOMMU_CTRL0;
	uint32_t DCHVM_RIOMMU_STAT0;
	uint32_t DCHUBBUB_DET0_CTRL;
	uint32_t DCHUBBUB_DET1_CTRL;
	uint32_t DCHUBBUB_DET2_CTRL;
	uint32_t DCHUBBUB_DET3_CTRL;
	uint32_t DCHUBBUB_COMPBUF_CTRL;
	uint32_t COMPBUF_RESERVED_SPACE;
	uint32_t DCHUBBUB_DEBUG_CTRL_0;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_A;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_A;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_B;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_B;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_C;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_C;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_D;
	uint32_t DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_D;
	uint32_t DCHUBBUB_ARB_USR_RETRAINING_CNTL;
	uint32_t DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_D;
	uint32_t DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_D;
	uint32_t DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_A;
	uint32_t DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_B;
	uint32_t DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_C;
	uint32_t DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_D;
};

#define HUBBUB_REG_FIELD_LIST_DCN32(type) \
		type DCHUBBUB_ARB_ALLOW_USR_RETRAINING_FORCE_VALUE;\
		type DCHUBBUB_ARB_ALLOW_USR_RETRAINING_FORCE_ENABLE;\
		type DCHUBBUB_ARB_DO_NOT_FORCE_ALLOW_USR_RETRAINING_DURING_PSTATE_CHANGE_REQUEST;\
		type DCHUBBUB_ARB_DO_NOT_FORCE_ALLOW_USR_RETRAINING_DURING_PRE_CSTATE;\
		type DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_A;\
		type DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_B;\
		type DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_C;\
		type DCHUBBUB_ARB_USR_RETRAINING_WATERMARK_D;\
		type DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_A;\
		type DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_B;\
		type DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_C;\
		type DCHUBBUB_ARB_UCLK_PSTATE_CHANGE_WATERMARK_D;\
		type DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_A;\
		type DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_B;\
		type DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_C;\
		type DCHUBBUB_ARB_FCLK_PSTATE_CHANGE_WATERMARK_D

/* set field name */
#define HUBBUB_SF(reg_name, field_name, post_fix)\
	.field_name = reg_name ## __ ## field_name ## post_fix

#define HUBBUB_MASK_SH_LIST_DCN_COMMON(mask_sh)\
		HUBBUB_SF(DCHUBBUB_GLOBAL_TIMER_CNTL, DCHUBBUB_GLOBAL_TIMER_ENABLE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_SOFT_RESET, DCHUBBUB_GLOBAL_SOFT_RESET, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_WATERMARK_CHANGE_CNTL, DCHUBBUB_ARB_WATERMARK_CHANGE_REQUEST, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_WATERMARK_CHANGE_CNTL, DCHUBBUB_ARB_WATERMARK_CHANGE_DONE_INTERRUPT_DISABLE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DRAM_STATE_CNTL, DCHUBBUB_ARB_ALLOW_SELF_REFRESH_FORCE_VALUE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DRAM_STATE_CNTL, DCHUBBUB_ARB_ALLOW_SELF_REFRESH_FORCE_ENABLE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DRAM_STATE_CNTL, DCHUBBUB_ARB_ALLOW_PSTATE_CHANGE_FORCE_VALUE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DRAM_STATE_CNTL, DCHUBBUB_ARB_ALLOW_PSTATE_CHANGE_FORCE_ENABLE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_SAT_LEVEL, DCHUBBUB_ARB_SAT_LEVEL, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DF_REQ_OUTSTAND, DCHUBBUB_ARB_MIN_REQ_OUTSTAND, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A, DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B, DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_C, DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_C, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_D, DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_D, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A, DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B, DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C, DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D, DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D, mask_sh)

#define HUBBUB_MASK_SH_LIST_STUTTER(mask_sh) \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A, DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_B, DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_B, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_C, DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_C, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_D, DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_D, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A, DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_B, DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_B, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_C, DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_C, mask_sh), \
		HUBBUB_SF(DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_D, DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_D, mask_sh)

#define HUBBUB_MASK_SH_LIST_DCN10(mask_sh)\
		HUBBUB_MASK_SH_LIST_DCN_COMMON(mask_sh), \
		HUBBUB_MASK_SH_LIST_STUTTER(mask_sh), \
		HUBBUB_SF(DCHUBBUB_SDPIF_FB_TOP, SDPIF_FB_TOP, mask_sh), \
		HUBBUB_SF(DCHUBBUB_SDPIF_FB_BASE, SDPIF_FB_BASE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_SDPIF_FB_OFFSET, SDPIF_FB_OFFSET, mask_sh), \
		HUBBUB_SF(DCHUBBUB_SDPIF_AGP_BASE, SDPIF_AGP_BASE, mask_sh), \
		HUBBUB_SF(DCHUBBUB_SDPIF_AGP_BOT, SDPIF_AGP_BOT, mask_sh), \
		HUBBUB_SF(DCHUBBUB_SDPIF_AGP_TOP, SDPIF_AGP_TOP, mask_sh)

#define DCN_HUBBUB_REG_FIELD_LIST(type) \
		type DCHUBBUB_GLOBAL_TIMER_ENABLE; \
		type DCHUBBUB_ARB_WATERMARK_CHANGE_REQUEST;\
		type DCHUBBUB_ARB_WATERMARK_CHANGE_DONE_INTERRUPT_DISABLE;\
		type DCHUBBUB_ARB_ALLOW_SELF_REFRESH_FORCE_VALUE;\
		type DCHUBBUB_ARB_ALLOW_SELF_REFRESH_FORCE_ENABLE;\
		type DCHUBBUB_ARB_ALLOW_PSTATE_CHANGE_FORCE_VALUE;\
		type DCHUBBUB_ARB_ALLOW_PSTATE_CHANGE_FORCE_ENABLE;\
		type DCHUBBUB_ARB_SAT_LEVEL;\
		type DCHUBBUB_ARB_MIN_REQ_OUTSTAND;\
		type DCHUBBUB_GLOBAL_TIMER_REFDIV;\
		type DCHUBBUB_GLOBAL_SOFT_RESET; \
		type SDPIF_FB_TOP;\
		type SDPIF_FB_BASE;\
		type SDPIF_FB_OFFSET;\
		type SDPIF_AGP_BASE;\
		type SDPIF_AGP_BOT;\
		type SDPIF_AGP_TOP;\
		type FB_BASE;\
		type FB_TOP;\
		type FB_OFFSET;\
		type AGP_BOT;\
		type AGP_TOP;\
		type AGP_BASE;\
		type DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A;\
		type DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B;\
		type DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_C;\
		type DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_D;\
		type DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A;\
		type DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B;\
		type DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C;\
		type DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D;\
		type DCN_VM_PROTECTION_FAULT_DEFAULT_ADDR_MSB;\
		type DCN_VM_PROTECTION_FAULT_DEFAULT_ADDR_LSB;\
		type DCN_VM_FAULT_ADDR_MSB;\
		type DCN_VM_FAULT_ADDR_LSB;\
		type DCN_VM_ERROR_STATUS_CLEAR;\
		type DCN_VM_ERROR_STATUS_MODE;\
		type DCN_VM_ERROR_INTERRUPT_ENABLE;\
		type DCN_VM_RANGE_FAULT_DISABLE;\
		type DCN_VM_PRQ_FAULT_DISABLE;\
		type DCN_VM_ERROR_STATUS;\
		type DCN_VM_ERROR_VMID;\
		type DCN_VM_ERROR_TABLE_LEVEL;\
		type DCN_VM_ERROR_PIPE;\
		type DCN_VM_ERROR_INTERRUPT_STATUS

#define HUBBUB_STUTTER_REG_FIELD_LIST(type) \
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A;\
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_B;\
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_C;\
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_D;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_B;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_C;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_D

#define HUBBUB_HVM_REG_FIELD_LIST(type) \
		type DCHUBBUB_ARB_MIN_REQ_OUTSTAND_COMMIT_THRESHOLD;\
		type DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_A;\
		type DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_B;\
		type DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_C;\
		type DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_D;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_A;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_B;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_C;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_D;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_A;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_B;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_C;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_SR_EXIT_WATERMARK_D;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_B;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_C;\
		type DCHUBBUB_ARB_VM_ROW_ALLOW_DRAM_CLK_CHANGE_WATERMARK_D;\
		type DCHUBBUB_ARB_FRAC_URG_BW_NOM_A;\
		type DCHUBBUB_ARB_FRAC_URG_BW_NOM_B;\
		type DCHUBBUB_ARB_FRAC_URG_BW_NOM_C;\
		type DCHUBBUB_ARB_FRAC_URG_BW_NOM_D;\
		type DCHUBBUB_ARB_FRAC_URG_BW_FLIP_A;\
		type DCHUBBUB_ARB_FRAC_URG_BW_FLIP_B;\
		type DCHUBBUB_ARB_FRAC_URG_BW_FLIP_C;\
		type DCHUBBUB_ARB_FRAC_URG_BW_FLIP_D;\
		type DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A;\
		type DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_B;\
		type DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_C;\
		type DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_D;\
		type DCHUBBUB_ARB_MAX_QOS_COMMIT_THRESHOLD;\
		type HOSTVM_INIT_REQ; \
		type HVM_GPUVMRET_PWR_REQ_DIS; \
		type HVM_GPUVMRET_FORCE_REQ; \
		type HVM_GPUVMRET_POWER_STATUS; \
		type HVM_DISPCLK_R_GATE_DIS; \
		type HVM_DISPCLK_G_GATE_DIS; \
		type HVM_DCFCLK_R_GATE_DIS; \
		type HVM_DCFCLK_G_GATE_DIS; \
		type TR_REQ_REQCLKREQ_MODE; \
		type TW_RSP_COMPCLKREQ_MODE; \
		type HOSTVM_PREFETCH_REQ; \
		type HOSTVM_POWERSTATUS; \
		type RIOMMU_ACTIVE; \
		type HOSTVM_PREFETCH_DONE

#define HUBBUB_RET_REG_FIELD_LIST(type) \
		type DET_DEPTH;\
		type DET0_SIZE;\
		type DET1_SIZE;\
		type DET2_SIZE;\
		type DET3_SIZE;\
		type DET0_SIZE_CURRENT;\
		type DET1_SIZE_CURRENT;\
		type DET2_SIZE_CURRENT;\
		type DET3_SIZE_CURRENT;\
		type COMPBUF_SIZE;\
		type COMPBUF_SIZE_CURRENT;\
		type CONFIG_ERROR;\
		type COMPBUF_RESERVED_SPACE_64B;\
		type COMPBUF_RESERVED_SPACE_ZS;\
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_A;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_A;\
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_B;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_B;\
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_C;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_C;\
		type DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_D;\
		type DCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_D


struct dcn_hubbub_shift {
	DCN_HUBBUB_REG_FIELD_LIST(uint8_t);
	HUBBUB_STUTTER_REG_FIELD_LIST(uint8_t);
	HUBBUB_HVM_REG_FIELD_LIST(uint8_t);
	HUBBUB_RET_REG_FIELD_LIST(uint8_t);
	HUBBUB_REG_FIELD_LIST_DCN32(uint8_t);
};

struct dcn_hubbub_mask {
	DCN_HUBBUB_REG_FIELD_LIST(uint32_t);
	HUBBUB_STUTTER_REG_FIELD_LIST(uint32_t);
	HUBBUB_HVM_REG_FIELD_LIST(uint32_t);
	HUBBUB_RET_REG_FIELD_LIST(uint32_t);
	HUBBUB_REG_FIELD_LIST_DCN32(uint32_t);
};

struct dc;

struct dcn10_hubbub {
	struct hubbub base;
	const struct dcn_hubbub_registers *regs;
	const struct dcn_hubbub_shift *shifts;
	const struct dcn_hubbub_mask *masks;
	unsigned int debug_test_index_pstate;
	struct dcn_watermark_set watermarks;
};

void hubbub1_update_dchub(
	struct hubbub *hubbub,
	struct dchub_init_data *dh_data);

bool hubbub1_verify_allow_pstate_change_high(
	struct hubbub *hubbub);

void hubbub1_wm_change_req_wa(struct hubbub *hubbub);

bool hubbub1_program_watermarks(
		struct hubbub *hubbub,
		struct dcn_watermark_set *watermarks,
		unsigned int refclk_mhz,
		bool safe_to_lower);

void hubbub1_allow_self_refresh_control(struct hubbub *hubbub, bool allow);

bool hubbub1_is_allow_self_refresh_enabled(struct hubbub *hubub);

void hubbub1_toggle_watermark_change_req(
		struct hubbub *hubbub);

void hubbub1_wm_read_state(struct hubbub *hubbub,
		struct dcn_hubbub_wm *wm);

void hubbub1_soft_reset(struct hubbub *hubbub, bool reset);
void hubbub1_construct(struct hubbub *hubbub,
	struct dc_context *ctx,
	const struct dcn_hubbub_registers *hubbub_regs,
	const struct dcn_hubbub_shift *hubbub_shift,
	const struct dcn_hubbub_mask *hubbub_mask);

bool hubbub1_program_urgent_watermarks(
		struct hubbub *hubbub,
		struct dcn_watermark_set *watermarks,
		unsigned int refclk_mhz,
		bool safe_to_lower);
bool hubbub1_program_stutter_watermarks(
		struct hubbub *hubbub,
		struct dcn_watermark_set *watermarks,
		unsigned int refclk_mhz,
		bool safe_to_lower);
bool hubbub1_program_pstate_watermarks(
		struct hubbub *hubbub,
		struct dcn_watermark_set *watermarks,
		unsigned int refclk_mhz,
		bool safe_to_lower);

#endif
