/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2016-2020 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

/************************************
 ** This is an auto-generated file **
 **       DO NOT EDIT BELOW        **
 ************************************/

#ifndef ASIC_REG_PMMU_HBW_STLB_MASKS_H_
#define ASIC_REG_PMMU_HBW_STLB_MASKS_H_

/*
 *****************************************
 *   PMMU_HBW_STLB
 *   (Prototype: STLB)
 *****************************************
 */

/* PMMU_HBW_STLB_BUSY */
#define PMMU_HBW_STLB_BUSY_BUSY_SHIFT 0
#define PMMU_HBW_STLB_BUSY_BUSY_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_ASID */
#define PMMU_HBW_STLB_ASID_ASID_SHIFT 0
#define PMMU_HBW_STLB_ASID_ASID_MASK 0x3FF

/* PMMU_HBW_STLB_HOP0_PA43_12 */
#define PMMU_HBW_STLB_HOP0_PA43_12_HOP0_PA43_12_SHIFT 0
#define PMMU_HBW_STLB_HOP0_PA43_12_HOP0_PA43_12_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_HOP0_PA63_44 */
#define PMMU_HBW_STLB_HOP0_PA63_44_HOP0_PA63_44_SHIFT 0
#define PMMU_HBW_STLB_HOP0_PA63_44_HOP0_PA63_44_MASK 0xFFFFF

/* PMMU_HBW_STLB_CACHE_INV */
#define PMMU_HBW_STLB_CACHE_INV_PRODUCER_INDEX_SHIFT 0
#define PMMU_HBW_STLB_CACHE_INV_PRODUCER_INDEX_MASK 0xFF
#define PMMU_HBW_STLB_CACHE_INV_INDEX_MASK_SHIFT 8
#define PMMU_HBW_STLB_CACHE_INV_INDEX_MASK_MASK 0xFF00

/* PMMU_HBW_STLB_CACHE_INV_BASE_39_8 */
#define PMMU_HBW_STLB_CACHE_INV_BASE_39_8_PA_SHIFT 0
#define PMMU_HBW_STLB_CACHE_INV_BASE_39_8_PA_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_CACHE_INV_BASE_63_40 */
#define PMMU_HBW_STLB_CACHE_INV_BASE_63_40_PA_SHIFT 0
#define PMMU_HBW_STLB_CACHE_INV_BASE_63_40_PA_MASK 0xFFFFFF

/* PMMU_HBW_STLB_STLB_FEATURE_EN */
#define PMMU_HBW_STLB_STLB_FEATURE_EN_STLB_CTRL_MULTI_PAGE_SIZE_EN_SHIFT 0
#define PMMU_HBW_STLB_STLB_FEATURE_EN_STLB_CTRL_MULTI_PAGE_SIZE_EN_MASK 0x1
#define PMMU_HBW_STLB_STLB_FEATURE_EN_MULTI_PAGE_SIZE_EN_SHIFT 1
#define PMMU_HBW_STLB_STLB_FEATURE_EN_MULTI_PAGE_SIZE_EN_MASK 0x2
#define PMMU_HBW_STLB_STLB_FEATURE_EN_LOOKUP_EN_SHIFT 2
#define PMMU_HBW_STLB_STLB_FEATURE_EN_LOOKUP_EN_MASK 0x4
#define PMMU_HBW_STLB_STLB_FEATURE_EN_BYPASS_SHIFT 3
#define PMMU_HBW_STLB_STLB_FEATURE_EN_BYPASS_MASK 0x8
#define PMMU_HBW_STLB_STLB_FEATURE_EN_BANK_STOP_SHIFT 4
#define PMMU_HBW_STLB_STLB_FEATURE_EN_BANK_STOP_MASK 0x10
#define PMMU_HBW_STLB_STLB_FEATURE_EN_TRACE_EN_SHIFT 5
#define PMMU_HBW_STLB_STLB_FEATURE_EN_TRACE_EN_MASK 0x20
#define PMMU_HBW_STLB_STLB_FEATURE_EN_FOLLOWER_EN_SHIFT 6
#define PMMU_HBW_STLB_STLB_FEATURE_EN_FOLLOWER_EN_MASK 0x40
#define PMMU_HBW_STLB_STLB_FEATURE_EN_CACHING_EN_SHIFT 7
#define PMMU_HBW_STLB_STLB_FEATURE_EN_CACHING_EN_MASK 0x1F80
#define PMMU_HBW_STLB_STLB_FEATURE_EN_FOLLOWING_NUM_LIMIT_SHIFT 13
#define PMMU_HBW_STLB_STLB_FEATURE_EN_FOLLOWING_NUM_LIMIT_MASK 0xE000

/* PMMU_HBW_STLB_STLB_AXI_CACHE */
#define PMMU_HBW_STLB_STLB_AXI_CACHE_STLB_CTRL_ARCACHE_SHIFT 0
#define PMMU_HBW_STLB_STLB_AXI_CACHE_STLB_CTRL_ARCACHE_MASK 0xF
#define PMMU_HBW_STLB_STLB_AXI_CACHE_STLB_CTRL_AWCACHE_SHIFT 4
#define PMMU_HBW_STLB_STLB_AXI_CACHE_STLB_CTRL_AWCACHE_MASK 0xF0
#define PMMU_HBW_STLB_STLB_AXI_CACHE_INV_ARCACHE_SHIFT 8
#define PMMU_HBW_STLB_STLB_AXI_CACHE_INV_ARCACHE_MASK 0xF00

/* PMMU_HBW_STLB_HOP_CONFIGURATION */
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FIRST_HOP_SHIFT 0
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FIRST_HOP_MASK 0x7
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FIRST_LOOKUP_HOP_SMALL_P_SHIFT 4
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FIRST_LOOKUP_HOP_SMALL_P_MASK 0x70
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FIRST_LOOKUP_HOP_LARGE_P_SHIFT 8
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FIRST_LOOKUP_HOP_LARGE_P_MASK 0x700
#define PMMU_HBW_STLB_HOP_CONFIGURATION_LAST_HOP_SHIFT 12
#define PMMU_HBW_STLB_HOP_CONFIGURATION_LAST_HOP_MASK 0x7000
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FOLLOWER_HOP_SHIFT 16
#define PMMU_HBW_STLB_HOP_CONFIGURATION_FOLLOWER_HOP_MASK 0x70000
#define PMMU_HBW_STLB_HOP_CONFIGURATION_ONLY_LARGE_PAGE_SHIFT 20
#define PMMU_HBW_STLB_HOP_CONFIGURATION_ONLY_LARGE_PAGE_MASK 0x100000
#define PMMU_HBW_STLB_HOP_CONFIGURATION_LARGE_PAGE_INDICATION_BIT_SHIFT 21
#define PMMU_HBW_STLB_HOP_CONFIGURATION_LARGE_PAGE_INDICATION_BIT_MASK 0x7E00000

/* PMMU_HBW_STLB_LINK_LIST_LOOKUP_MASK_63_32 */
#define PMMU_HBW_STLB_LINK_LIST_LOOKUP_MASK_63_32_R_SHIFT 0
#define PMMU_HBW_STLB_LINK_LIST_LOOKUP_MASK_63_32_R_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_LINK_LIST_LOOKUP_MASK_31_0 */
#define PMMU_HBW_STLB_LINK_LIST_LOOKUP_MASK_31_0_R_SHIFT 0
#define PMMU_HBW_STLB_LINK_LIST_LOOKUP_MASK_31_0_R_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_INV_ALL_START */
#define PMMU_HBW_STLB_INV_ALL_START_R_SHIFT 0
#define PMMU_HBW_STLB_INV_ALL_START_R_MASK 0x1

/* PMMU_HBW_STLB_INV_ALL_SET */
#define PMMU_HBW_STLB_INV_ALL_SET_R_SHIFT 0
#define PMMU_HBW_STLB_INV_ALL_SET_R_MASK 0xFF

/* PMMU_HBW_STLB_INV_PS */
#define PMMU_HBW_STLB_INV_PS_R_SHIFT 0
#define PMMU_HBW_STLB_INV_PS_R_MASK 0x3

/* PMMU_HBW_STLB_INV_CONSUMER_INDEX */
#define PMMU_HBW_STLB_INV_CONSUMER_INDEX_R_SHIFT 0
#define PMMU_HBW_STLB_INV_CONSUMER_INDEX_R_MASK 0xFF

/* PMMU_HBW_STLB_INV_HIT_COUNT */
#define PMMU_HBW_STLB_INV_HIT_COUNT_R_SHIFT 0
#define PMMU_HBW_STLB_INV_HIT_COUNT_R_MASK 0x7FF

/* PMMU_HBW_STLB_INV_SET */
#define PMMU_HBW_STLB_INV_SET_R_SHIFT 0
#define PMMU_HBW_STLB_INV_SET_R_MASK 0xFF

/* PMMU_HBW_STLB_SRAM_INIT */
#define PMMU_HBW_STLB_SRAM_INIT_BUSY_TAG_SHIFT 0
#define PMMU_HBW_STLB_SRAM_INIT_BUSY_TAG_MASK 0x3
#define PMMU_HBW_STLB_SRAM_INIT_BUSY_SLICE_SHIFT 2
#define PMMU_HBW_STLB_SRAM_INIT_BUSY_SLICE_MASK 0xC
#define PMMU_HBW_STLB_SRAM_INIT_BUSY_DATA_SHIFT 4
#define PMMU_HBW_STLB_SRAM_INIT_BUSY_DATA_MASK 0x10

/* PMMU_HBW_STLB_MEM_CACHE_INVALIDATION */

/* PMMU_HBW_STLB_MEM_CACHE_INV_STATUS */
#define PMMU_HBW_STLB_MEM_CACHE_INV_STATUS_INVALIDATE_DONE_SHIFT 0
#define PMMU_HBW_STLB_MEM_CACHE_INV_STATUS_INVALIDATE_DONE_MASK 0x1
#define PMMU_HBW_STLB_MEM_CACHE_INV_STATUS_CACHE_IDLE_SHIFT 1
#define PMMU_HBW_STLB_MEM_CACHE_INV_STATUS_CACHE_IDLE_MASK 0x2

/* PMMU_HBW_STLB_MEM_CACHE_BASE_38_7 */
#define PMMU_HBW_STLB_MEM_CACHE_BASE_38_7_R_SHIFT 0
#define PMMU_HBW_STLB_MEM_CACHE_BASE_38_7_R_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_MEM_CACHE_BASE_63_39 */
#define PMMU_HBW_STLB_MEM_CACHE_BASE_63_39_R_SHIFT 0
#define PMMU_HBW_STLB_MEM_CACHE_BASE_63_39_R_MASK 0x1FFFFFF

/* PMMU_HBW_STLB_MEM_CACHE_CONFIG */
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_CACHE_HOP_EN_SHIFT 0
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_CACHE_HOP_EN_MASK 0x3F
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_CACHE_HOP_PREFETCH_EN_SHIFT 6
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_CACHE_HOP_PREFETCH_EN_MASK 0xFC0
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_BYPASS_EN_SHIFT 12
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_BYPASS_EN_MASK 0x1000
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_RELEASE_INVALIDATE_SHIFT 13
#define PMMU_HBW_STLB_MEM_CACHE_CONFIG_RELEASE_INVALIDATE_MASK 0x2000

/* PMMU_HBW_STLB_SET_THRESHOLD_HOP5 */
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP5_MIN_SHIFT 0
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP5_MIN_MASK 0x1FF
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP5_MAX_SHIFT 9
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP5_MAX_MASK 0x3FE00
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP5_MASK_SHIFT 18
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP5_MASK_MASK 0x7FC0000

/* PMMU_HBW_STLB_SET_THRESHOLD_HOP4 */
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP4_MIN_SHIFT 0
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP4_MIN_MASK 0x1FF
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP4_MAX_SHIFT 9
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP4_MAX_MASK 0x3FE00
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP4_MASK_SHIFT 18
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP4_MASK_MASK 0x7FC0000

/* PMMU_HBW_STLB_SET_THRESHOLD_HOP3 */
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP3_MIN_SHIFT 0
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP3_MIN_MASK 0x1FF
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP3_MAX_SHIFT 9
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP3_MAX_MASK 0x3FE00
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP3_MASK_SHIFT 18
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP3_MASK_MASK 0x7FC0000

/* PMMU_HBW_STLB_SET_THRESHOLD_HOP2 */
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP2_MIN_SHIFT 0
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP2_MIN_MASK 0x1FF
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP2_MAX_SHIFT 9
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP2_MAX_MASK 0x3FE00
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP2_MASK_SHIFT 18
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP2_MASK_MASK 0x7FC0000

/* PMMU_HBW_STLB_SET_THRESHOLD_HOP1 */
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP1_MIN_SHIFT 0
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP1_MIN_MASK 0x1FF
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP1_MAX_SHIFT 9
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP1_MAX_MASK 0x3FE00
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP1_MASK_SHIFT 18
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP1_MASK_MASK 0x7FC0000

/* PMMU_HBW_STLB_SET_THRESHOLD_HOP0 */
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP0_MIN_SHIFT 0
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP0_MIN_MASK 0x1FF
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP0_MAX_SHIFT 9
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP0_MAX_MASK 0x3FE00
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP0_MASK_SHIFT 18
#define PMMU_HBW_STLB_SET_THRESHOLD_HOP0_MASK_MASK 0x7FC0000

/* PMMU_HBW_STLB_MULTI_HIT_INTERRUPT_CLR */

/* PMMU_HBW_STLB_MULTI_HIT_INTERRUPT_MASK */
#define PMMU_HBW_STLB_MULTI_HIT_INTERRUPT_MASK_R_SHIFT 0
#define PMMU_HBW_STLB_MULTI_HIT_INTERRUPT_MASK_R_MASK 0x1

/* PMMU_HBW_STLB_MEM_L0_CACHE_CFG */
#define PMMU_HBW_STLB_MEM_L0_CACHE_CFG_PLRU_EVICTION_SHIFT 0
#define PMMU_HBW_STLB_MEM_L0_CACHE_CFG_PLRU_EVICTION_MASK 0x1
#define PMMU_HBW_STLB_MEM_L0_CACHE_CFG_CACHE_STOP_SHIFT 1
#define PMMU_HBW_STLB_MEM_L0_CACHE_CFG_CACHE_STOP_MASK 0x2
#define PMMU_HBW_STLB_MEM_L0_CACHE_CFG_INV_WRITEBACK_SHIFT 2
#define PMMU_HBW_STLB_MEM_L0_CACHE_CFG_INV_WRITEBACK_MASK 0x4

/* PMMU_HBW_STLB_MEM_READ_ARPROT */
#define PMMU_HBW_STLB_MEM_READ_ARPROT_R_SHIFT 0
#define PMMU_HBW_STLB_MEM_READ_ARPROT_R_MASK 0x7

/* PMMU_HBW_STLB_RANGE_CACHE_INVALIDATION */
#define PMMU_HBW_STLB_RANGE_CACHE_INVALIDATION_RANGE_INVALIDATION_ENABLE_SHIFT 0
#define PMMU_HBW_STLB_RANGE_CACHE_INVALIDATION_RANGE_INVALIDATION_ENABLE_MASK \
0x1
#define PMMU_HBW_STLB_RANGE_CACHE_INVALIDATION_INVALIDATION_ASID_EN_SHIFT 1
#define PMMU_HBW_STLB_RANGE_CACHE_INVALIDATION_INVALIDATION_ASID_EN_MASK 0x2
#define PMMU_HBW_STLB_RANGE_CACHE_INVALIDATION_INVALIDATION_ASID_SHIFT 2
#define PMMU_HBW_STLB_RANGE_CACHE_INVALIDATION_INVALIDATION_ASID_MASK 0xFFC

/* PMMU_HBW_STLB_RANGE_INV_START_LSB */
#define PMMU_HBW_STLB_RANGE_INV_START_LSB_INV_START_LSB_SHIFT 0
#define PMMU_HBW_STLB_RANGE_INV_START_LSB_INV_START_LSB_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_RANGE_INV_START_MSB */
#define PMMU_HBW_STLB_RANGE_INV_START_MSB_INV_START_MSB_SHIFT 0
#define PMMU_HBW_STLB_RANGE_INV_START_MSB_INV_START_MSB_MASK 0xFFFFF

/* PMMU_HBW_STLB_RANGE_INV_END_LSB */
#define PMMU_HBW_STLB_RANGE_INV_END_LSB_INV_END_LSB_SHIFT 0
#define PMMU_HBW_STLB_RANGE_INV_END_LSB_INV_END_LSB_MASK 0xFFFFFFFF

/* PMMU_HBW_STLB_RANGE_INV_END_MSB */
#define PMMU_HBW_STLB_RANGE_INV_END_MSB_INV_END_MSB_SHIFT 0
#define PMMU_HBW_STLB_RANGE_INV_END_MSB_INV_END_MSB_MASK 0xFFFFF

/* PMMU_HBW_STLB_ASID_SCRAMBLER_CTRL */
#define PMMU_HBW_STLB_ASID_SCRAMBLER_CTRL_SCRAMBLER_SCRAM_EN_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCRAMBLER_CTRL_SCRAMBLER_SCRAM_EN_MASK 0x1

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_0 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_0_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_0_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_1 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_1_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_1_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_2 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_2_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_2_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_3 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_3_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_3_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_4 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_4_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_4_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_5 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_5_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_5_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_6 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_6_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_6_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_7 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_7_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_7_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_8 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_8_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_8_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_9 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_9_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MATRIX_H3_9_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_10 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_10_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_10_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_11 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_11_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_11_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_12 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_12_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_12_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_13 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_13_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_13_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_14 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_14_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_14_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_15 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_15_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_15_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_16 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_16_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_16_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_17 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_17_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_17_ASID_POLY_MATRIX_H3_MASK 0x1FF

/* PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_18 */
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_18_ASID_POLY_MATRIX_H3_SHIFT 0
#define PMMU_HBW_STLB_ASID_SCR_POLY_MAT_H3_18_ASID_POLY_MATRIX_H3_MASK 0x1FF

#endif /* ASIC_REG_PMMU_HBW_STLB_MASKS_H_ */
