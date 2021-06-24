/*
 * Copyright 2020 Advanced Micro Devices, Inc.
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

#ifndef __DAL_DCN30_VPG_H__
#define __DAL_DCN30_VPG_H__


#define DCN30_VPG_FROM_VPG(vpg)\
	container_of(vpg, struct dcn30_vpg, base)

#define VPG_DCN3_REG_LIST(id) \
	SRI(VPG_GENERIC_STATUS, VPG, id), \
	SRI(VPG_GENERIC_PACKET_ACCESS_CTRL, VPG, id), \
	SRI(VPG_GENERIC_PACKET_DATA, VPG, id), \
	SRI(VPG_GSP_FRAME_UPDATE_CTRL, VPG, id)

struct dcn30_vpg_registers {
	uint32_t VPG_GENERIC_STATUS;
	uint32_t VPG_GENERIC_PACKET_ACCESS_CTRL;
	uint32_t VPG_GENERIC_PACKET_DATA;
	uint32_t VPG_GSP_FRAME_UPDATE_CTRL;
};

#define DCN3_VPG_MASK_SH_LIST(mask_sh)\
	SE_SF(VPG0_VPG_GENERIC_STATUS, VPG_GENERIC_CONFLICT_OCCURED, mask_sh),\
	SE_SF(VPG0_VPG_GENERIC_STATUS, VPG_GENERIC_CONFLICT_CLR, mask_sh),\
	SE_SF(VPG0_VPG_GENERIC_PACKET_ACCESS_CTRL, VPG_GENERIC_DATA_INDEX, mask_sh),\
	SE_SF(VPG0_VPG_GENERIC_PACKET_DATA, VPG_GENERIC_DATA_BYTE0, mask_sh),\
	SE_SF(VPG0_VPG_GENERIC_PACKET_DATA, VPG_GENERIC_DATA_BYTE1, mask_sh),\
	SE_SF(VPG0_VPG_GENERIC_PACKET_DATA, VPG_GENERIC_DATA_BYTE2, mask_sh),\
	SE_SF(VPG0_VPG_GENERIC_PACKET_DATA, VPG_GENERIC_DATA_BYTE3, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC0_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC1_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC2_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC3_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC4_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC5_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC6_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC7_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC8_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC9_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC10_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC11_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC12_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC13_FRAME_UPDATE, mask_sh),\
	SE_SF(VPG0_VPG_GSP_FRAME_UPDATE_CTRL, VPG_GENERIC14_FRAME_UPDATE, mask_sh)

#define VPG_DCN3_REG_FIELD_LIST(type) \
	type VPG_GENERIC_CONFLICT_OCCURED;\
	type VPG_GENERIC_CONFLICT_CLR;\
	type VPG_GENERIC_DATA_INDEX;\
	type VPG_GENERIC_DATA_BYTE0;\
	type VPG_GENERIC_DATA_BYTE1;\
	type VPG_GENERIC_DATA_BYTE2;\
	type VPG_GENERIC_DATA_BYTE3;\
	type VPG_GENERIC0_FRAME_UPDATE;\
	type VPG_GENERIC1_FRAME_UPDATE;\
	type VPG_GENERIC2_FRAME_UPDATE;\
	type VPG_GENERIC3_FRAME_UPDATE;\
	type VPG_GENERIC4_FRAME_UPDATE;\
	type VPG_GENERIC5_FRAME_UPDATE;\
	type VPG_GENERIC6_FRAME_UPDATE;\
	type VPG_GENERIC7_FRAME_UPDATE;\
	type VPG_GENERIC8_FRAME_UPDATE;\
	type VPG_GENERIC9_FRAME_UPDATE;\
	type VPG_GENERIC10_FRAME_UPDATE;\
	type VPG_GENERIC11_FRAME_UPDATE;\
	type VPG_GENERIC12_FRAME_UPDATE;\
	type VPG_GENERIC13_FRAME_UPDATE;\
	type VPG_GENERIC14_FRAME_UPDATE


struct dcn30_vpg_shift {
	VPG_DCN3_REG_FIELD_LIST(uint8_t);
};

struct dcn30_vpg_mask {
	VPG_DCN3_REG_FIELD_LIST(uint32_t);
};

struct vpg;

struct vpg_funcs {
	void (*update_generic_info_packet)(
		struct vpg *vpg,
		uint32_t packet_index,
		const struct dc_info_packet *info_packet);
};

struct vpg {
	const struct vpg_funcs *funcs;
	struct dc_context *ctx;
	int inst;
};

struct dcn30_vpg {
	struct vpg base;
	const struct dcn30_vpg_registers *regs;
	const struct dcn30_vpg_shift *vpg_shift;
	const struct dcn30_vpg_mask *vpg_mask;
};

void vpg3_construct(struct dcn30_vpg *vpg3,
	struct dc_context *ctx,
	uint32_t inst,
	const struct dcn30_vpg_registers *vpg_regs,
	const struct dcn30_vpg_shift *vpg_shift,
	const struct dcn30_vpg_mask *vpg_mask);


#endif
