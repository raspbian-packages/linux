/* Copyright 2012-15 Advanced Micro Devices, Inc.
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

#ifndef __DC_MPCC_DCN20_H__
#define __DC_MPCC_DCN20_H__

#include "dcn10/dcn10_mpc.h"

#define TO_DCN20_MPC(mpc_base) \
	container_of(mpc_base, struct dcn20_mpc, base)

#define MPC_REG_LIST_DCN2_0(inst)\
	MPC_COMMON_REG_LIST_DCN1_0(inst),\
	SRII(MPCC_TOP_GAIN, MPCC, inst),\
	SRII(MPCC_BOT_GAIN_INSIDE, MPCC, inst),\
	SRII(MPCC_BOT_GAIN_OUTSIDE, MPCC, inst),\
	SRII(MPCC_OGAM_RAMA_START_CNTL_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_START_CNTL_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_START_CNTL_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_SLOPE_CNTL_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_SLOPE_CNTL_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_SLOPE_CNTL_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_END_CNTL1_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_END_CNTL2_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_END_CNTL1_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_END_CNTL2_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_END_CNTL1_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_END_CNTL2_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_REGION_0_1, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMA_REGION_32_33, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_START_CNTL_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_START_CNTL_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_START_CNTL_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_SLOPE_CNTL_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_SLOPE_CNTL_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_SLOPE_CNTL_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_END_CNTL1_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_END_CNTL2_B, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_END_CNTL1_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_END_CNTL2_G, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_END_CNTL1_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_END_CNTL2_R, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_REGION_0_1, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_RAMB_REGION_32_33, MPCC_OGAM, inst),\
	SRII(MPCC_MEM_PWR_CTRL, MPCC, inst),\
	SRII(MPCC_OGAM_LUT_INDEX, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_LUT_RAM_CONTROL, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_LUT_DATA, MPCC_OGAM, inst),\
	SRII(MPCC_OGAM_MODE, MPCC_OGAM, inst)

#define MPC_OUT_MUX_REG_LIST_DCN2_0(inst) \
	MPC_OUT_MUX_COMMON_REG_LIST_DCN1_0(inst),\
	SRII(CSC_MODE, MPC_OUT, inst),\
	SRII(CSC_C11_C12_A, MPC_OUT, inst),\
	SRII(CSC_C33_C34_A, MPC_OUT, inst),\
	SRII(CSC_C11_C12_B, MPC_OUT, inst),\
	SRII(CSC_C33_C34_B, MPC_OUT, inst),\
	SRII(DENORM_CONTROL, MPC_OUT, inst),\
	SRII(DENORM_CLAMP_G_Y, MPC_OUT, inst),\
	SRII(DENORM_CLAMP_B_CB, MPC_OUT, inst)

#define MPC_REG_VARIABLE_LIST_DCN2_0 \
	MPC_COMMON_REG_VARIABLE_LIST \
	uint32_t MPCC_TOP_GAIN[MAX_MPCC]; \
	uint32_t MPCC_BOT_GAIN_INSIDE[MAX_MPCC]; \
	uint32_t MPCC_BOT_GAIN_OUTSIDE[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_START_CNTL_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_START_CNTL_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_START_CNTL_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_SLOPE_CNTL_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_SLOPE_CNTL_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_SLOPE_CNTL_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_END_CNTL1_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_END_CNTL2_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_END_CNTL1_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_END_CNTL2_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_END_CNTL1_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_END_CNTL2_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_REGION_0_1[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMA_REGION_32_33[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_START_CNTL_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_START_CNTL_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_START_CNTL_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_SLOPE_CNTL_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_SLOPE_CNTL_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_SLOPE_CNTL_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_END_CNTL1_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_END_CNTL2_B[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_END_CNTL1_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_END_CNTL2_G[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_END_CNTL1_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_END_CNTL2_R[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_REGION_0_1[MAX_MPCC]; \
	uint32_t MPCC_OGAM_RAMB_REGION_32_33[MAX_MPCC];\
	uint32_t MPCC_MEM_PWR_CTRL[MAX_MPCC];\
	uint32_t MPCC_OGAM_LUT_INDEX[MAX_MPCC];\
	uint32_t MPCC_OGAM_LUT_RAM_CONTROL[MAX_MPCC];\
	uint32_t MPCC_OGAM_LUT_DATA[MAX_MPCC];\
	uint32_t MPCC_OGAM_MODE[MAX_MPCC];\
	uint32_t CSC_MODE[MAX_OPP]; \
	uint32_t CSC_C11_C12_A[MAX_OPP]; \
	uint32_t CSC_C33_C34_A[MAX_OPP]; \
	uint32_t CSC_C11_C12_B[MAX_OPP]; \
	uint32_t CSC_C33_C34_B[MAX_OPP]; \
	uint32_t DENORM_CONTROL[MAX_OPP]; \
	uint32_t DENORM_CLAMP_G_Y[MAX_OPP]; \
	uint32_t DENORM_CLAMP_B_CB[MAX_OPP];

#define MPC_COMMON_MASK_SH_LIST_DCN2_0(mask_sh) \
	MPC_COMMON_MASK_SH_LIST_DCN1_0(mask_sh),\
	SF(MPCC0_MPCC_CONTROL, MPCC_BG_BPC, mask_sh),\
	SF(MPCC0_MPCC_CONTROL, MPCC_BOT_GAIN_MODE, mask_sh),\
	SF(MPCC0_MPCC_TOP_GAIN, MPCC_TOP_GAIN, mask_sh),\
	SF(MPCC0_MPCC_BOT_GAIN_INSIDE, MPCC_BOT_GAIN_INSIDE, mask_sh),\
	SF(MPCC0_MPCC_BOT_GAIN_OUTSIDE, MPCC_BOT_GAIN_OUTSIDE, mask_sh),\
	SF(MPC_OUT0_CSC_MODE, MPC_OCSC_MODE, mask_sh),\
	SF(MPC_OUT0_CSC_C11_C12_A, MPC_OCSC_C11_A, mask_sh),\
	SF(MPC_OUT0_CSC_C11_C12_A, MPC_OCSC_C12_A, mask_sh),\
	SF(MPCC0_MPCC_STATUS, MPCC_DISABLED, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_REGION_0_1, MPCC_OGAM_RAMA_EXP_REGION0_LUT_OFFSET, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_REGION_0_1, MPCC_OGAM_RAMA_EXP_REGION0_NUM_SEGMENTS, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_REGION_0_1, MPCC_OGAM_RAMA_EXP_REGION1_LUT_OFFSET, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_REGION_0_1, MPCC_OGAM_RAMA_EXP_REGION1_NUM_SEGMENTS, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_END_CNTL1_B, MPCC_OGAM_RAMA_EXP_REGION_END_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_END_CNTL2_B, MPCC_OGAM_RAMA_EXP_REGION_END_SLOPE_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_END_CNTL2_B, MPCC_OGAM_RAMA_EXP_REGION_END_BASE_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_SLOPE_CNTL_B, MPCC_OGAM_RAMA_EXP_REGION_LINEAR_SLOPE_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_START_CNTL_B, MPCC_OGAM_RAMA_EXP_REGION_START_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMA_START_CNTL_B, MPCC_OGAM_RAMA_EXP_REGION_START_SEGMENT_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_REGION_0_1, MPCC_OGAM_RAMB_EXP_REGION0_LUT_OFFSET, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_REGION_0_1, MPCC_OGAM_RAMB_EXP_REGION0_NUM_SEGMENTS, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_REGION_0_1, MPCC_OGAM_RAMB_EXP_REGION1_LUT_OFFSET, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_REGION_0_1, MPCC_OGAM_RAMB_EXP_REGION1_NUM_SEGMENTS, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_END_CNTL1_B, MPCC_OGAM_RAMB_EXP_REGION_END_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_END_CNTL2_B, MPCC_OGAM_RAMB_EXP_REGION_END_SLOPE_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_END_CNTL2_B, MPCC_OGAM_RAMB_EXP_REGION_END_BASE_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_SLOPE_CNTL_B, MPCC_OGAM_RAMB_EXP_REGION_LINEAR_SLOPE_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_START_CNTL_B, MPCC_OGAM_RAMB_EXP_REGION_START_B, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_RAMB_START_CNTL_B, MPCC_OGAM_RAMB_EXP_REGION_START_SEGMENT_B, mask_sh),\
	SF(MPCC0_MPCC_MEM_PWR_CTRL, MPCC_OGAM_MEM_PWR_FORCE, mask_sh),\
	SF(MPCC0_MPCC_MEM_PWR_CTRL, MPCC_OGAM_MEM_PWR_DIS, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_LUT_INDEX, MPCC_OGAM_LUT_INDEX, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_LUT_RAM_CONTROL, MPCC_OGAM_LUT_WRITE_EN_MASK, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_LUT_RAM_CONTROL, MPCC_OGAM_LUT_RAM_SEL, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_LUT_RAM_CONTROL, MPCC_OGAM_CONFIG_STATUS, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_LUT_DATA, MPCC_OGAM_LUT_DATA, mask_sh),\
	SF(MPCC_OGAM0_MPCC_OGAM_MODE, MPCC_OGAM_MODE, mask_sh),\
	SF(MPC_OUT0_DENORM_CONTROL, MPC_OUT_DENORM_MODE, mask_sh),\
	SF(MPC_OUT0_DENORM_CONTROL, MPC_OUT_DENORM_CLAMP_MAX_R_CR, mask_sh),\
	SF(MPC_OUT0_DENORM_CONTROL, MPC_OUT_DENORM_CLAMP_MIN_R_CR, mask_sh),\
	SF(MPC_OUT0_DENORM_CLAMP_G_Y, MPC_OUT_DENORM_CLAMP_MAX_G_Y, mask_sh),\
	SF(MPC_OUT0_DENORM_CLAMP_G_Y, MPC_OUT_DENORM_CLAMP_MIN_G_Y, mask_sh),\
	SF(MPC_OUT0_DENORM_CLAMP_B_CB, MPC_OUT_DENORM_CLAMP_MAX_B_CB, mask_sh),\
	SF(MPC_OUT0_DENORM_CLAMP_B_CB, MPC_OUT_DENORM_CLAMP_MIN_B_CB, mask_sh)


#define MPC_REG_FIELD_LIST_DCN2_0(type) \
	MPC_REG_FIELD_LIST(type)\
	type MPCC_BG_BPC;\
	type MPCC_BOT_GAIN_MODE;\
	type MPCC_TOP_GAIN;\
	type MPCC_BOT_GAIN_INSIDE;\
	type MPCC_BOT_GAIN_OUTSIDE;\
	type MPC_OCSC_MODE;\
	type MPC_OCSC_C11_A;\
	type MPC_OCSC_C12_A;\
	type MPCC_OGAM_RAMA_EXP_REGION0_LUT_OFFSET;\
	type MPCC_OGAM_RAMA_EXP_REGION0_NUM_SEGMENTS;\
	type MPCC_OGAM_RAMA_EXP_REGION1_LUT_OFFSET;\
	type MPCC_OGAM_RAMA_EXP_REGION1_NUM_SEGMENTS;\
	type MPCC_OGAM_RAMA_EXP_REGION_END_B;\
	type MPCC_OGAM_RAMA_EXP_REGION_END_SLOPE_B;\
	type MPCC_OGAM_RAMA_EXP_REGION_END_BASE_B;\
	type MPCC_OGAM_RAMA_EXP_REGION_LINEAR_SLOPE_B;\
	type MPCC_OGAM_RAMA_EXP_REGION_START_B;\
	type MPCC_OGAM_RAMA_EXP_REGION_START_SEGMENT_B;\
	type MPCC_OGAM_RAMB_EXP_REGION0_LUT_OFFSET;\
	type MPCC_OGAM_RAMB_EXP_REGION0_NUM_SEGMENTS;\
	type MPCC_OGAM_RAMB_EXP_REGION1_LUT_OFFSET;\
	type MPCC_OGAM_RAMB_EXP_REGION1_NUM_SEGMENTS;\
	type MPCC_OGAM_RAMB_EXP_REGION_END_B;\
	type MPCC_OGAM_RAMB_EXP_REGION_END_SLOPE_B;\
	type MPCC_OGAM_RAMB_EXP_REGION_END_BASE_B;\
	type MPCC_OGAM_RAMB_EXP_REGION_LINEAR_SLOPE_B;\
	type MPCC_OGAM_RAMB_EXP_REGION_START_B;\
	type MPCC_OGAM_RAMB_EXP_REGION_START_SEGMENT_B;\
	type MPCC_OGAM_MEM_PWR_FORCE;\
	type MPCC_OGAM_LUT_INDEX;\
	type MPCC_OGAM_LUT_WRITE_EN_MASK;\
	type MPCC_OGAM_LUT_RAM_SEL;\
	type MPCC_OGAM_CONFIG_STATUS;\
	type MPCC_OGAM_LUT_DATA;\
	type MPCC_OGAM_MODE;\
	type MPC_OUT_DENORM_MODE;\
	type MPC_OUT_DENORM_CLAMP_MAX_R_CR;\
	type MPC_OUT_DENORM_CLAMP_MIN_R_CR;\
	type MPC_OUT_DENORM_CLAMP_MAX_G_Y;\
	type MPC_OUT_DENORM_CLAMP_MIN_G_Y;\
	type MPC_OUT_DENORM_CLAMP_MAX_B_CB;\
	type MPC_OUT_DENORM_CLAMP_MIN_B_CB;\
	type MPCC_DISABLED;\
	type MPCC_OGAM_MEM_PWR_DIS;

struct dcn20_mpc_registers {
	MPC_REG_VARIABLE_LIST_DCN2_0
};

struct dcn20_mpc_shift {
	MPC_REG_FIELD_LIST_DCN2_0(uint8_t)
};

struct dcn20_mpc_mask {
	MPC_REG_FIELD_LIST_DCN2_0(uint32_t)
};

struct dcn20_mpc {
	struct mpc base;

	int mpcc_in_use_mask;
	int num_mpcc;
	const struct dcn20_mpc_registers *mpc_regs;
	const struct dcn20_mpc_shift *mpc_shift;
	const struct dcn20_mpc_mask *mpc_mask;
};

void dcn20_mpc_construct(struct dcn20_mpc *mpcc20,
	struct dc_context *ctx,
	const struct dcn20_mpc_registers *mpc_regs,
	const struct dcn20_mpc_shift *mpc_shift,
	const struct dcn20_mpc_mask *mpc_mask,
	int num_mpcc);

void mpc2_update_blending(
	struct mpc *mpc,
	struct mpcc_blnd_cfg *blnd_cfg,
	int mpcc_id);

void mpc2_set_denorm(
	struct mpc *mpc,
	int opp_id,
	enum dc_color_depth output_depth);

void mpc2_set_denorm_clamp(
	struct mpc *mpc,
	int opp_id,
	struct mpc_denorm_clamp denorm_clamp);

void mpc2_set_output_csc(
	struct mpc *mpc,
	int opp_id,
	const uint16_t *regval,
	enum mpc_output_csc_mode ocsc_mode);

void mpc2_set_ocsc_default(
	struct mpc *mpc,
	int opp_id,
	enum dc_color_space color_space,
	enum mpc_output_csc_mode ocsc_mode);

void mpc2_set_output_gamma(
	struct mpc *mpc,
	int mpcc_id,
	const struct pwl_params *params);

void mpc2_assert_idle_mpcc(struct mpc *mpc, int id);
void mpc2_assert_mpcc_idle_before_connect(struct mpc *mpc, int mpcc_id);
void mpc20_power_on_ogam_lut(struct mpc *mpc, int mpcc_id, bool power_on);
#endif
