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

#ifndef __DC_HUBP_DCN30_H__
#define __DC_HUBP_DCN30_H__

#include "dcn20/dcn20_hubp.h"
#include "dcn21/dcn21_hubp.h"

#define HUBP_REG_LIST_DCN30(id)\
	HUBP_REG_LIST_DCN21(id),\
	SRI(DCN_DMDATA_VM_CNTL, HUBPREQ, id)


#define HUBP_MASK_SH_LIST_DCN30_BASE(mask_sh)\
	HUBP_MASK_SH_LIST_DCN21_COMMON(mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, ALPHA_PLANE_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, REFCYC_PER_VM_DMDATA, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_FAULT_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_FAULT_STATUS_CLEAR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_UNDERFLOW_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_LATE_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_UNDERFLOW_STATUS_CLEAR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_DONE, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, NUM_PKRS, mask_sh)


#define HUBP_MASK_SH_LIST_DCN30(mask_sh)\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, REFCYC_PER_VM_DMDATA, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_FAULT_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_FAULT_STATUS_CLEAR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_UNDERFLOW_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_LATE_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_UNDERFLOW_STATUS_CLEAR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_DONE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_BLANK_EN, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_TTU_DISABLE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_UNDERFLOW_STATUS, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_UNDERFLOW_CLEAR, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_NO_OUTSTANDING_REQ, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_VTG_SEL, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_DISABLE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_IN_BLANK, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, NUM_PIPES, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, PIPE_INTERLEAVE, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, MAX_COMPRESSED_FRAGS, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, NUM_PKRS, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_TILING_CONFIG, SW_MODE, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_TILING_CONFIG, META_LINEAR, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_TILING_CONFIG, PIPE_ALIGNED, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_PITCH, PITCH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_PITCH, META_PITCH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_PITCH_C, PITCH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_PITCH_C, META_PITCH_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, SURFACE_PIXEL_FORMAT, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_TYPE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_MODE_FOR_STEREOSYNC, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_IN_STEREOSYNC, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_PENDING, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_UPDATE_LOCK, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION, PRI_VIEWPORT_WIDTH, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION, PRI_VIEWPORT_HEIGHT, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START, PRI_VIEWPORT_X_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START, PRI_VIEWPORT_Y_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION, SEC_VIEWPORT_WIDTH, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION, SEC_VIEWPORT_HEIGHT, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START, SEC_VIEWPORT_X_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START, SEC_VIEWPORT_Y_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION_C, PRI_VIEWPORT_WIDTH_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION_C, PRI_VIEWPORT_HEIGHT_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START_C, PRI_VIEWPORT_X_START_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START_C, PRI_VIEWPORT_Y_START_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION_C, SEC_VIEWPORT_WIDTH_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION_C, SEC_VIEWPORT_HEIGHT_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START_C, SEC_VIEWPORT_X_START_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START_C, SEC_VIEWPORT_Y_START_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH, PRIMARY_SURFACE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS, PRIMARY_SURFACE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS_HIGH, SECONDARY_SURFACE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS, SECONDARY_SURFACE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_META_SURFACE_ADDRESS_HIGH, PRIMARY_META_SURFACE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_META_SURFACE_ADDRESS, PRIMARY_META_SURFACE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_META_SURFACE_ADDRESS_HIGH, SECONDARY_META_SURFACE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_META_SURFACE_ADDRESS, SECONDARY_META_SURFACE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH_C, PRIMARY_SURFACE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_C, PRIMARY_SURFACE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS_HIGH_C, SECONDARY_SURFACE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS_C, SECONDARY_SURFACE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_META_SURFACE_ADDRESS_HIGH_C, PRIMARY_META_SURFACE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_META_SURFACE_ADDRESS_C, PRIMARY_META_SURFACE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_META_SURFACE_ADDRESS_HIGH_C, SECONDARY_META_SURFACE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_META_SURFACE_ADDRESS_C, SECONDARY_META_SURFACE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE, SURFACE_INUSE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE_HIGH, SURFACE_INUSE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE_C, SURFACE_INUSE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE_HIGH_C, SURFACE_INUSE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE, SURFACE_EARLIEST_INUSE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE_HIGH, SURFACE_EARLIEST_INUSE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE_C, SURFACE_EARLIEST_INUSE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE_HIGH_C, SURFACE_EARLIEST_INUSE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_TMZ, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_TMZ_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_META_SURFACE_TMZ, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_META_SURFACE_TMZ_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_DCC_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_DCC_IND_BLK, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_DCC_IND_BLK_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_TMZ, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_TMZ_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_META_SURFACE_TMZ, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_META_SURFACE_TMZ_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_DCC_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_DCC_IND_BLK, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_DCC_IND_BLK_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_FLIP_INTERRUPT, SURFACE_FLIP_INT_MASK, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, DET_BUF_PLANE1_BASE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_CB_B, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_CR_R, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_Y_G, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_ALPHA, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, PACK_3TO2_ELEMENT_DISABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, DRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, PRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, MRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, CRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, CHUNK_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, MIN_CHUNK_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, META_CHUNK_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, MIN_META_CHUNK_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, DPTE_GROUP_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, SWATH_HEIGHT, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, PTE_ROW_HEIGHT_LINEAR, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, CHUNK_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, MIN_CHUNK_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, META_CHUNK_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, MIN_META_CHUNK_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, DPTE_GROUP_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, SWATH_HEIGHT_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, PTE_ROW_HEIGHT_LINEAR_C, mask_sh),\
	HUBP_SF(HUBPREQ0_BLANK_OFFSET_0, REFCYC_H_BLANK_END, mask_sh),\
	HUBP_SF(HUBPREQ0_BLANK_OFFSET_0, DLG_V_BLANK_END, mask_sh),\
	HUBP_SF(HUBPREQ0_BLANK_OFFSET_1, MIN_DST_Y_NEXT_START, mask_sh),\
	HUBP_SF(HUBPREQ0_DST_DIMENSIONS, REFCYC_PER_HTOTAL, mask_sh),\
	HUBP_SF(HUBPREQ0_DST_AFTER_SCALER, REFCYC_X_AFTER_SCALER, mask_sh),\
	HUBP_SF(HUBPREQ0_DST_AFTER_SCALER, DST_Y_AFTER_SCALER, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_0, DST_Y_PER_VM_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_0, DST_Y_PER_ROW_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_REF_FREQ_TO_PIX_FREQ, REF_FREQ_TO_PIX_FREQ, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_1, REFCYC_PER_PTE_GROUP_VBLANK_L, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_3, REFCYC_PER_META_CHUNK_VBLANK_L, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_4, DST_Y_PER_META_ROW_NOM_L, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_5, REFCYC_PER_META_CHUNK_NOM_L, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY_PRE, REFCYC_PER_LINE_DELIVERY_PRE_L, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY_PRE, REFCYC_PER_LINE_DELIVERY_PRE_C, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY, REFCYC_PER_LINE_DELIVERY_L, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY, REFCYC_PER_LINE_DELIVERY_C, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_2, REFCYC_PER_PTE_GROUP_VBLANK_C, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_4, REFCYC_PER_META_CHUNK_VBLANK_C, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_6, DST_Y_PER_META_ROW_NOM_C, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_7, REFCYC_PER_META_CHUNK_NOM_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_TTU_QOS_WM, QoS_LEVEL_LOW_WM, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_TTU_QOS_WM, QoS_LEVEL_HIGH_WM, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_GLOBAL_TTU_CNTL, MIN_TTU_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_GLOBAL_TTU_CNTL, QoS_LEVEL_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_GLOBAL_TTU_CNTL, ROW_TTU_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL0, REFCYC_PER_REQ_DELIVERY, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL0, QoS_LEVEL_FIXED, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL0, QoS_RAMP_DISABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL1, REFCYC_PER_REQ_DELIVERY_PRE, mask_sh),\
	HUBP_SF(HUBP0_HUBP_CLK_CNTL, HUBP_CLOCK_ENABLE, mask_sh),\
	HUBP_MASK_SH_LIST_DCN_VM(mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, ROTATION_ANGLE, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, H_MIRROR_EN, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, ALPHA_PLANE_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_PREFETCH_SETTINGS, DST_Y_PREFETCH, mask_sh),\
	HUBP_SF(HUBPREQ0_PREFETCH_SETTINGS, VRATIO_PREFETCH, mask_sh),\
	HUBP_SF(HUBPREQ0_PREFETCH_SETTINGS_C, VRATIO_PREFETCH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_VM_SYSTEM_APERTURE_LOW_ADDR, MC_VM_SYSTEM_APERTURE_LOW_ADDR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_VM_SYSTEM_APERTURE_HIGH_ADDR, MC_VM_SYSTEM_APERTURE_HIGH_ADDR, mask_sh),\
	HUBP_SF(HUBPREQ0_CURSOR_SETTINGS, CURSOR0_DST_Y_OFFSET, mask_sh), \
	HUBP_SF(HUBPREQ0_CURSOR_SETTINGS, CURSOR0_CHUNK_HDL_ADJUST, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SURFACE_ADDRESS_HIGH, CURSOR_SURFACE_ADDRESS_HIGH, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SURFACE_ADDRESS, CURSOR_SURFACE_ADDRESS, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SIZE, CURSOR_WIDTH, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SIZE, CURSOR_HEIGHT, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_MODE, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_2X_MAGNIFY, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_PITCH, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_LINES_PER_CHUNK, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_ENABLE, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_POSITION, CURSOR_X_POSITION, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_POSITION, CURSOR_Y_POSITION, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_HOT_SPOT, CURSOR_HOT_SPOT_X, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_HOT_SPOT, CURSOR_HOT_SPOT_Y, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_DST_OFFSET, CURSOR_DST_X_OFFSET, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_ADDRESS_HIGH, DMDATA_ADDRESS_HIGH, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_MODE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_UPDATED, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_REPEAT, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_SIZE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_SW_CNTL, DMDATA_SW_UPDATED, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_SW_CNTL, DMDATA_SW_REPEAT, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_SW_CNTL, DMDATA_SW_SIZE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_QOS_CNTL, DMDATA_QOS_MODE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_QOS_CNTL, DMDATA_QOS_LEVEL, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_QOS_CNTL, DMDATA_DL_DELTA, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_STATUS, DMDATA_DONE, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_0, DST_Y_PER_VM_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_0, DST_Y_PER_ROW_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_1, REFCYC_PER_PTE_GROUP_FLIP_L, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_2, REFCYC_PER_META_CHUNK_FLIP_L, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_VREADY_AT_OR_AFTER_VSYNC, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_DISABLE_STOP_DATA_DURING_VM, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, HUBPREQ_MASTER_UPDATE_LOCK_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL2, SURFACE_GSL_ENABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL2, SURFACE_TRIPLE_BUFFER_ENABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_VMID_SETTINGS_0, VMID, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_3, REFCYC_PER_VM_GROUP_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_4, REFCYC_PER_VM_REQ_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_5, REFCYC_PER_PTE_GROUP_FLIP_C, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_6, REFCYC_PER_META_CHUNK_FLIP_C, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_5, REFCYC_PER_VM_GROUP_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_6, REFCYC_PER_VM_REQ_VBLANK, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, VM_GROUP_SIZE, mask_sh)

bool hubp3_construct(
		struct dcn20_hubp *hubp2,
		struct dc_context *ctx,
		uint32_t inst,
		const struct dcn_hubp2_registers *hubp_regs,
		const struct dcn_hubp2_shift *hubp_shift,
		const struct dcn_hubp2_mask *hubp_mask);

void hubp3_set_vm_system_aperture_settings(struct hubp *hubp,
	struct vm_system_aperture_param *apt);

bool hubp3_program_surface_flip_and_addr(
	struct hubp *hubp,
	const struct dc_plane_address *address,
	bool flip_immediate);

void hubp3_program_surface_config(
	struct hubp *hubp,
	enum surface_pixel_format format,
	union dc_tiling_info *tiling_info,
	struct plane_size *plane_size,
	enum dc_rotation_angle rotation,
	struct dc_plane_dcc_param *dcc,
	bool horizontal_mirror,
	unsigned int compat_level);

void hubp3_setup(
		struct hubp *hubp,
		struct _vcs_dpi_display_dlg_regs_st *dlg_attr,
		struct _vcs_dpi_display_ttu_regs_st *ttu_attr,
		struct _vcs_dpi_display_rq_regs_st *rq_regs,
		struct _vcs_dpi_display_pipe_dest_params_st *pipe_dest);

void hubp3_dcc_control(struct hubp *hubp, bool enable,
		enum hubp_ind_block_size blk_size);

void hubp3_dcc_control_sienna_cichlid(struct hubp *hubp,
		struct dc_plane_dcc_param *dcc);

void hubp3_dmdata_set_attributes(
		struct hubp *hubp,
		const struct dc_dmdata_attributes *attr);

void hubp3_read_state(struct hubp *hubp);

void hubp3_init(struct hubp *hubp);

#endif /* __DC_HUBP_DCN30_H__ */


