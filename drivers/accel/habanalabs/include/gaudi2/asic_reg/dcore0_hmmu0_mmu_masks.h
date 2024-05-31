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

#ifndef ASIC_REG_DCORE0_HMMU0_MMU_MASKS_H_
#define ASIC_REG_DCORE0_HMMU0_MMU_MASKS_H_

/*
 *****************************************
 *   DCORE0_HMMU0_MMU
 *   (Prototype: MMU)
 *****************************************
 */

/* DCORE0_HMMU0_MMU_MMU_ENABLE */
#define DCORE0_HMMU0_MMU_MMU_ENABLE_R_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_ENABLE_R_MASK 0x1

/* DCORE0_HMMU0_MMU_FORCE_ORDERING */
#define DCORE0_HMMU0_MMU_FORCE_ORDERING_WEAK_ORDERING_SHIFT 0
#define DCORE0_HMMU0_MMU_FORCE_ORDERING_WEAK_ORDERING_MASK 0x1
#define DCORE0_HMMU0_MMU_FORCE_ORDERING_STRONG_ORDERING_SHIFT 1
#define DCORE0_HMMU0_MMU_FORCE_ORDERING_STRONG_ORDERING_MASK 0x2

/* DCORE0_HMMU0_MMU_FEATURE_ENABLE */
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_VA_ORDERING_EN_SHIFT 0
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_VA_ORDERING_EN_MASK 0x1
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_CLEAN_LINK_LIST_SHIFT 1
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_CLEAN_LINK_LIST_MASK 0x2
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_HOP_OFFSET_EN_SHIFT 2
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_HOP_OFFSET_EN_MASK 0x4
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_OBI_ORDERING_EN_SHIFT 3
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_OBI_ORDERING_EN_MASK 0x8
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_STRONG_ORDERING_READ_EN_SHIFT 4
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_STRONG_ORDERING_READ_EN_MASK 0x10
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_TRACE_ENABLE_SHIFT 5
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_TRACE_ENABLE_MASK 0x20
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_TRACE_EV_MMU_OR_STLB_SHIFT 6
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_TRACE_EV_MMU_OR_STLB_MASK 0x40
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_TRACE_CLKH_EQUAL_CLKL_SHIFT 7
#define DCORE0_HMMU0_MMU_FEATURE_ENABLE_TRACE_CLKH_EQUAL_CLKL_MASK 0x80

/* DCORE0_HMMU0_MMU_VA_ORDERING_MASK_38_7 */
#define DCORE0_HMMU0_MMU_VA_ORDERING_MASK_38_7_R_SHIFT 0
#define DCORE0_HMMU0_MMU_VA_ORDERING_MASK_38_7_R_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_VA_ORDERING_MASK_64_39 */
#define DCORE0_HMMU0_MMU_VA_ORDERING_MASK_64_39_R_SHIFT 0
#define DCORE0_HMMU0_MMU_VA_ORDERING_MASK_64_39_R_MASK 0x3FFFFFF

/* DCORE0_HMMU0_MMU_LOG2_DDR_SIZE */
#define DCORE0_HMMU0_MMU_LOG2_DDR_SIZE_R_SHIFT 0
#define DCORE0_HMMU0_MMU_LOG2_DDR_SIZE_R_MASK 0xFF

/* DCORE0_HMMU0_MMU_SCRAMBLER */
#define DCORE0_HMMU0_MMU_SCRAMBLER_ADDR_BIT_SHIFT 0
#define DCORE0_HMMU0_MMU_SCRAMBLER_ADDR_BIT_MASK 0x3F
#define DCORE0_HMMU0_MMU_SCRAMBLER_SINGLE_DDR_EN_SHIFT 6
#define DCORE0_HMMU0_MMU_SCRAMBLER_SINGLE_DDR_EN_MASK 0x40
#define DCORE0_HMMU0_MMU_SCRAMBLER_SINGLE_DDR_ID_SHIFT 7
#define DCORE0_HMMU0_MMU_SCRAMBLER_SINGLE_DDR_ID_MASK 0x80
#define DCORE0_HMMU0_MMU_SCRAMBLER_DDR_CH_LSB_BIT_LOCATION_SHIFT 8
#define DCORE0_HMMU0_MMU_SCRAMBLER_DDR_CH_LSB_BIT_LOCATION_MASK 0x7F00

/* DCORE0_HMMU0_MMU_MEM_INIT_BUSY */
#define DCORE0_HMMU0_MMU_MEM_INIT_BUSY_DATA_SHIFT 0
#define DCORE0_HMMU0_MMU_MEM_INIT_BUSY_DATA_MASK 0x3
#define DCORE0_HMMU0_MMU_MEM_INIT_BUSY_OBI0_SHIFT 2
#define DCORE0_HMMU0_MMU_MEM_INIT_BUSY_OBI0_MASK 0x4
#define DCORE0_HMMU0_MMU_MEM_INIT_BUSY_OBI1_SHIFT 3
#define DCORE0_HMMU0_MMU_MEM_INIT_BUSY_OBI1_MASK 0x8

/* DCORE0_HMMU0_MMU_SPI_SEI_MASK */
#define DCORE0_HMMU0_MMU_SPI_SEI_MASK_R_SHIFT 0
#define DCORE0_HMMU0_MMU_SPI_SEI_MASK_R_MASK 0x7FFFF

/* DCORE0_HMMU0_MMU_SPI_SEI_CAUSE */
#define DCORE0_HMMU0_MMU_SPI_SEI_CAUSE_R_SHIFT 0
#define DCORE0_HMMU0_MMU_SPI_SEI_CAUSE_R_MASK 0x7FFFF

/* DCORE0_HMMU0_MMU_PAGE_ERROR_CAPTURE */
#define DCORE0_HMMU0_MMU_PAGE_ERROR_CAPTURE_VA_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_PAGE_ERROR_CAPTURE_VA_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_PAGE_ERROR_CAPTURE_VA */
#define DCORE0_HMMU0_MMU_PAGE_ERROR_CAPTURE_VA_VA_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_PAGE_ERROR_CAPTURE_VA_VA_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_ACCESS_ERROR_CAPTURE */
#define DCORE0_HMMU0_MMU_ACCESS_ERROR_CAPTURE_VA_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_ACCESS_ERROR_CAPTURE_VA_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_ACCESS_ERROR_CAPTURE_VA */
#define DCORE0_HMMU0_MMU_ACCESS_ERROR_CAPTURE_VA_VA_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_ACCESS_ERROR_CAPTURE_VA_VA_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_ACCESS_PAGE_ERROR_VALID */
#define DCORE0_HMMU0_MMU_ACCESS_PAGE_ERROR_VALID_PAGE_ERR_VALID_ENTRY_SHIFT 0
#define DCORE0_HMMU0_MMU_ACCESS_PAGE_ERROR_VALID_PAGE_ERR_VALID_ENTRY_MASK 0x1
#define DCORE0_HMMU0_MMU_ACCESS_PAGE_ERROR_VALID_ACCESS_ERR_VALID_ENTRY_SHIFT 1
#define DCORE0_HMMU0_MMU_ACCESS_PAGE_ERROR_VALID_ACCESS_ERR_VALID_ENTRY_MASK 0x2

/* DCORE0_HMMU0_MMU_INTERRUPT_CLR */
#define DCORE0_HMMU0_MMU_INTERRUPT_CLR_R_SHIFT 0
#define DCORE0_HMMU0_MMU_INTERRUPT_CLR_R_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_INTERRUPT_MASK */
#define DCORE0_HMMU0_MMU_INTERRUPT_MASK_R_SHIFT 0
#define DCORE0_HMMU0_MMU_INTERRUPT_MASK_R_MASK 0xFF

/* DCORE0_HMMU0_MMU_DBG_MEM_WRAP_RM */
#define DCORE0_HMMU0_MMU_DBG_MEM_WRAP_RM_R_SHIFT 0
#define DCORE0_HMMU0_MMU_DBG_MEM_WRAP_RM_R_MASK 0x3FFFFFFF

/* DCORE0_HMMU0_MMU_SPI_CAUSE_CLR */
#define DCORE0_HMMU0_MMU_SPI_CAUSE_CLR_CLR_SHIFT 0
#define DCORE0_HMMU0_MMU_SPI_CAUSE_CLR_CLR_MASK 0x1

/* DCORE0_HMMU0_MMU_PIPE_CREDIT */
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_READ_CREDIT_SHIFT 0
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_READ_CREDIT_MASK 0xF
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_READ_FORCE_FULL_SHIFT 7
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_READ_FORCE_FULL_MASK 0x80
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_WRITE_CREDIT_SHIFT 8
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_WRITE_CREDIT_MASK 0xF00
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_WRITE_FORCE_FULL_SHIFT 15
#define DCORE0_HMMU0_MMU_PIPE_CREDIT_WRITE_FORCE_FULL_MASK 0x8000

/* DCORE0_HMMU0_MMU_MMU_BYPASS */
#define DCORE0_HMMU0_MMU_MMU_BYPASS_R_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_BYPASS_R_MASK 0x1

/* DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE */
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP5_PAGE_SIZE_SHIFT 0
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP5_PAGE_SIZE_MASK 0xF
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP4_PAGE_SIZE_SHIFT 4
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP4_PAGE_SIZE_MASK 0xF0
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP3_PAGE_SIZE_SHIFT 8
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP3_PAGE_SIZE_MASK 0xF00
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP2_PAGE_SIZE_SHIFT 12
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP2_PAGE_SIZE_MASK 0xF000
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP1_PAGE_SIZE_SHIFT 16
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_HOP1_PAGE_SIZE_MASK 0xF0000
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_CFG_8_BITS_HOP_MODE_EN_SHIFT 20
#define DCORE0_HMMU0_MMU_STATIC_MULTI_PAGE_SIZE_CFG_8_BITS_HOP_MODE_EN_MASK 0x100000

/* DCORE0_HMMU0_MMU_CORE_SEP_CACHE_RNG */
#define DCORE0_HMMU0_MMU_CORE_SEP_CACHE_RNG_CORE_SET_MASK_SHIFT 0
#define DCORE0_HMMU0_MMU_CORE_SEP_CACHE_RNG_CORE_SET_MASK_MASK 0x1FF
#define DCORE0_HMMU0_MMU_CORE_SEP_CACHE_RNG_CORE_SET_MIN_SHIFT 10
#define DCORE0_HMMU0_MMU_CORE_SEP_CACHE_RNG_CORE_SET_MIN_MASK 0x7FC00
#define DCORE0_HMMU0_MMU_CORE_SEP_CACHE_RNG_CORE_SET_MAX_SHIFT 20
#define DCORE0_HMMU0_MMU_CORE_SEP_CACHE_RNG_CORE_SET_MAX_MASK 0x1FF00000

/* DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT */
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_WRITE_CRED_SHIFT 0
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_WRITE_CRED_MASK 0x1FF
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_READ_CRED_SHIFT 9
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_READ_CRED_MASK 0x3FE00
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_TOTAL_SHIFT 18
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_TOTAL_MASK 0x7FC0000
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_FORCE_FULL_WRITE_SHIFT 27
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_FORCE_FULL_WRITE_MASK 0x8000000
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_FORCE_FULL_READ_SHIFT 28
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_FORCE_FULL_READ_MASK 0x10000000
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_FORCE_FULL_TOTAL_SHIFT 29
#define DCORE0_HMMU0_MMU_CORE_SEP_SLICE_CRDT_FORCE_FULL_TOTAL_MASK 0x20000000

/* DCORE0_HMMU0_MMU_TOTAL_SLICE_CREDIT */
#define DCORE0_HMMU0_MMU_TOTAL_SLICE_CREDIT_TOTAL_SHIFT 18
#define DCORE0_HMMU0_MMU_TOTAL_SLICE_CREDIT_TOTAL_MASK 0x7FC0000
#define DCORE0_HMMU0_MMU_TOTAL_SLICE_CREDIT_FORCE_FULL_TOTAL_SHIFT 29
#define DCORE0_HMMU0_MMU_TOTAL_SLICE_CREDIT_FORCE_FULL_TOTAL_MASK 0x20000000

/* DCORE0_HMMU0_MMU_PAGE_FAULT_ID_LSB */
#define DCORE0_HMMU0_MMU_PAGE_FAULT_ID_LSB_PAGE_FAULT_ID_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_PAGE_FAULT_ID_LSB_PAGE_FAULT_ID_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_PAGE_FAULT_ID_MSB */
#define DCORE0_HMMU0_MMU_PAGE_FAULT_ID_MSB_PAGE_FAULT_ID_42_32_SHIFT 0
#define DCORE0_HMMU0_MMU_PAGE_FAULT_ID_MSB_PAGE_FAULT_ID_42_32_MASK 0x7FF

/* DCORE0_HMMU0_MMU_PAGE_ACCESS_ID_LSB */
#define DCORE0_HMMU0_MMU_PAGE_ACCESS_ID_LSB_PAGE_ACCESS_ID_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_PAGE_ACCESS_ID_LSB_PAGE_ACCESS_ID_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_PAGE_ACCESS_ID_MSB */
#define DCORE0_HMMU0_MMU_PAGE_ACCESS_ID_MSB_PAGE_ACCESS_ID_42_32_SHIFT 0
#define DCORE0_HMMU0_MMU_PAGE_ACCESS_ID_MSB_PAGE_ACCESS_ID_42_32_MASK 0x7FF

/* DCORE0_HMMU0_MMU_DDR_RANGE_REG_ENABLE */
#define DCORE0_HMMU0_MMU_DDR_RANGE_REG_ENABLE_ENABLE_SHIFT 0
#define DCORE0_HMMU0_MMU_DDR_RANGE_REG_ENABLE_ENABLE_MASK 0x1

/* DCORE0_HMMU0_MMU_MMU_RR_SEC_MIN_63_32 */
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MIN_63_32_SEC_MIN_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MIN_63_32_SEC_MIN_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_MMU_RR_SEC_MIN_31_0 */
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MIN_31_0_SEC_MIN_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MIN_31_0_SEC_MIN_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_MMU_RR_SEC_MAX_63_32 */
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MAX_63_32_SEC_MAX_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MAX_63_32_SEC_MAX_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_MMU_RR_SEC_MAX_31_0 */
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MAX_31_0_SEC_MAX_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_SEC_MAX_31_0_SEC_MAX_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_MMU_RR_PRIV_MIN_63_32 */
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MIN_63_32_PRIV_MIN_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MIN_63_32_PRIV_MIN_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_MMU_RR_PRIV_MIN_31_0 */
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MIN_31_0_PRIV_MIN_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MIN_31_0_PRIV_MIN_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_MMU_RR_PRIV_MAX_63_32 */
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MAX_63_32_PRIV_MAX_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MAX_63_32_PRIV_MAX_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_MMU_RR_PRIV_MAX_31_0 */
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MAX_31_0_PRIV_MAX_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_RR_PRIV_MAX_31_0_PRIV_MAX_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_ILLEGAL_ADDR_WRITE_63_32 */
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_WRITE_63_32_ILLEGAL_ADDR_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_WRITE_63_32_ILLEGAL_ADDR_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_ILLEGAL_ADDR_WRITE_31_0 */
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_WRITE_31_0_ILLEGAL_ADDR_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_WRITE_31_0_ILLEGAL_ADDR_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_ILLEGAL_ADDR_READ_63_32 */
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_READ_63_32_ILLEGAL_ADDR_63_32_SHIFT 0
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_READ_63_32_ILLEGAL_ADDR_63_32_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_ILLEGAL_ADDR_READ_31_0 */
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_READ_31_0_ILLEGAL_ADDR_31_0_SHIFT 0
#define DCORE0_HMMU0_MMU_ILLEGAL_ADDR_READ_31_0_ILLEGAL_ADDR_31_0_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_RAZWI_WRITE_VLD */
#define DCORE0_HMMU0_MMU_RAZWI_WRITE_VLD_R_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_WRITE_VLD_R_MASK 0x1

/* DCORE0_HMMU0_MMU_RAZWI_WRITE_ID_31_0 */
#define DCORE0_HMMU0_MMU_RAZWI_WRITE_ID_31_0_R_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_WRITE_ID_31_0_R_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_RAZWI_WRITE_ID_42_32 */
#define DCORE0_HMMU0_MMU_RAZWI_WRITE_ID_42_32_R_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_WRITE_ID_42_32_R_MASK 0x7FF

/* DCORE0_HMMU0_MMU_RAZWI_READ_VLD */
#define DCORE0_HMMU0_MMU_RAZWI_READ_VLD_R_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_READ_VLD_R_MASK 0x1

/* DCORE0_HMMU0_MMU_RAZWI_READ_ID_31_0 */
#define DCORE0_HMMU0_MMU_RAZWI_READ_ID_31_0_R_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_READ_ID_31_0_R_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_RAZWI_READ_ID_42_32 */
#define DCORE0_HMMU0_MMU_RAZWI_READ_ID_42_32_R_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_READ_ID_42_32_R_MASK 0x7FF

/* DCORE0_HMMU0_MMU_MMU_SRC_NUM */
#define DCORE0_HMMU0_MMU_MMU_SRC_NUM_OVERRIDE_SRC_NUM_EN_SHIFT 0
#define DCORE0_HMMU0_MMU_MMU_SRC_NUM_OVERRIDE_SRC_NUM_EN_MASK 0x1
#define DCORE0_HMMU0_MMU_MMU_SRC_NUM_SRC_NUM_SHIFT 1
#define DCORE0_HMMU0_MMU_MMU_SRC_NUM_SRC_NUM_MASK 0x1E

/* DCORE0_HMMU0_MMU_RAZWI_ADDR_LSB */
#define DCORE0_HMMU0_MMU_RAZWI_ADDR_LSB_ADDR_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_ADDR_LSB_ADDR_MASK 0xFFFFFFFF

/* DCORE0_HMMU0_MMU_RAZWI_ADDR_MSB */
#define DCORE0_HMMU0_MMU_RAZWI_ADDR_MSB_ADDR_SHIFT 0
#define DCORE0_HMMU0_MMU_RAZWI_ADDR_MSB_ADDR_MASK 0xFFFFFFFF

#endif /* ASIC_REG_DCORE0_HMMU0_MMU_MASKS_H_ */
