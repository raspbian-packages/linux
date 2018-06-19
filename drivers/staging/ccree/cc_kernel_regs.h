/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2012-2018 ARM Limited or its affiliates. */

#ifndef __CC_CRYS_KERNEL_H__
#define __CC_CRYS_KERNEL_H__

// --------------------------------------
// BLOCK: DSCRPTR
// --------------------------------------
#define CC_DSCRPTR_COMPLETION_COUNTER_REG_OFFSET	0xE00UL
#define CC_DSCRPTR_COMPLETION_COUNTER_COMPLETION_COUNTER_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_COMPLETION_COUNTER_COMPLETION_COUNTER_BIT_SIZE	0x6UL
#define CC_DSCRPTR_COMPLETION_COUNTER_OVERFLOW_COUNTER_BIT_SHIFT	0x6UL
#define CC_DSCRPTR_COMPLETION_COUNTER_OVERFLOW_COUNTER_BIT_SIZE	0x1UL
#define CC_DSCRPTR_SW_RESET_REG_OFFSET	0xE40UL
#define CC_DSCRPTR_SW_RESET_VALUE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_SW_RESET_VALUE_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_SRAM_SIZE_REG_OFFSET	0xE60UL
#define CC_DSCRPTR_QUEUE_SRAM_SIZE_NUM_OF_DSCRPTR_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_SRAM_SIZE_NUM_OF_DSCRPTR_BIT_SIZE	0xAUL
#define CC_DSCRPTR_QUEUE_SRAM_SIZE_DSCRPTR_SRAM_SIZE_BIT_SHIFT	0xAUL
#define CC_DSCRPTR_QUEUE_SRAM_SIZE_DSCRPTR_SRAM_SIZE_BIT_SIZE	0xCUL
#define CC_DSCRPTR_QUEUE_SRAM_SIZE_SRAM_SIZE_BIT_SHIFT	0x16UL
#define CC_DSCRPTR_QUEUE_SRAM_SIZE_SRAM_SIZE_BIT_SIZE	0x3UL
#define CC_DSCRPTR_SINGLE_ADDR_EN_REG_OFFSET	0xE64UL
#define CC_DSCRPTR_SINGLE_ADDR_EN_VALUE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_SINGLE_ADDR_EN_VALUE_BIT_SIZE	0x1UL
#define CC_DSCRPTR_MEASURE_CNTR_REG_OFFSET	0xE68UL
#define CC_DSCRPTR_MEASURE_CNTR_VALUE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_MEASURE_CNTR_VALUE_BIT_SIZE	0x20UL
#define CC_DSCRPTR_QUEUE_WORD0_REG_OFFSET	0xE80UL
#define CC_DSCRPTR_QUEUE_WORD0_VALUE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_WORD0_VALUE_BIT_SIZE	0x20UL
#define CC_DSCRPTR_QUEUE_WORD1_REG_OFFSET	0xE84UL
#define CC_DSCRPTR_QUEUE_WORD1_DIN_DMA_MODE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_WORD1_DIN_DMA_MODE_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD1_DIN_SIZE_BIT_SHIFT	0x2UL
#define CC_DSCRPTR_QUEUE_WORD1_DIN_SIZE_BIT_SIZE	0x18UL
#define CC_DSCRPTR_QUEUE_WORD1_NS_BIT_BIT_SHIFT	0x1AUL
#define CC_DSCRPTR_QUEUE_WORD1_NS_BIT_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD1_DIN_CONST_VALUE_BIT_SHIFT	0x1BUL
#define CC_DSCRPTR_QUEUE_WORD1_DIN_CONST_VALUE_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD1_NOT_LAST_BIT_SHIFT	0x1CUL
#define CC_DSCRPTR_QUEUE_WORD1_NOT_LAST_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD1_LOCK_QUEUE_BIT_SHIFT	0x1DUL
#define CC_DSCRPTR_QUEUE_WORD1_LOCK_QUEUE_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD1_NOT_USED_BIT_SHIFT	0x1EUL
#define CC_DSCRPTR_QUEUE_WORD1_NOT_USED_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD2_REG_OFFSET	0xE88UL
#define CC_DSCRPTR_QUEUE_WORD2_VALUE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_WORD2_VALUE_BIT_SIZE	0x20UL
#define CC_DSCRPTR_QUEUE_WORD3_REG_OFFSET	0xE8CUL
#define CC_DSCRPTR_QUEUE_WORD3_DOUT_DMA_MODE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_WORD3_DOUT_DMA_MODE_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD3_DOUT_SIZE_BIT_SHIFT	0x2UL
#define CC_DSCRPTR_QUEUE_WORD3_DOUT_SIZE_BIT_SIZE	0x18UL
#define CC_DSCRPTR_QUEUE_WORD3_NS_BIT_BIT_SHIFT	0x1AUL
#define CC_DSCRPTR_QUEUE_WORD3_NS_BIT_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD3_DOUT_LAST_IND_BIT_SHIFT	0x1BUL
#define CC_DSCRPTR_QUEUE_WORD3_DOUT_LAST_IND_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD3_HASH_XOR_BIT_BIT_SHIFT	0x1DUL
#define CC_DSCRPTR_QUEUE_WORD3_HASH_XOR_BIT_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD3_NOT_USED_BIT_SHIFT	0x1EUL
#define CC_DSCRPTR_QUEUE_WORD3_NOT_USED_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD3_QUEUE_LAST_IND_BIT_SHIFT	0x1FUL
#define CC_DSCRPTR_QUEUE_WORD3_QUEUE_LAST_IND_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_REG_OFFSET	0xE90UL
#define CC_DSCRPTR_QUEUE_WORD4_DATA_FLOW_MODE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_WORD4_DATA_FLOW_MODE_BIT_SIZE	0x6UL
#define CC_DSCRPTR_QUEUE_WORD4_AES_SEL_N_HASH_BIT_SHIFT	0x6UL
#define CC_DSCRPTR_QUEUE_WORD4_AES_SEL_N_HASH_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_AES_XOR_CRYPTO_KEY_BIT_SHIFT	0x7UL
#define CC_DSCRPTR_QUEUE_WORD4_AES_XOR_CRYPTO_KEY_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_ACK_NEEDED_BIT_SHIFT	0x8UL
#define CC_DSCRPTR_QUEUE_WORD4_ACK_NEEDED_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_MODE_BIT_SHIFT	0xAUL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_MODE_BIT_SIZE	0x4UL
#define CC_DSCRPTR_QUEUE_WORD4_CMAC_SIZE0_BIT_SHIFT	0xEUL
#define CC_DSCRPTR_QUEUE_WORD4_CMAC_SIZE0_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_DO_BIT_SHIFT	0xFUL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_DO_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_CONF0_BIT_SHIFT	0x11UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_CONF0_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_CONF1_BIT_SHIFT	0x13UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_CONF1_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_CONF2_BIT_SHIFT	0x14UL
#define CC_DSCRPTR_QUEUE_WORD4_CIPHER_CONF2_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD4_KEY_SIZE_BIT_SHIFT	0x16UL
#define CC_DSCRPTR_QUEUE_WORD4_KEY_SIZE_BIT_SIZE	0x2UL
#define CC_DSCRPTR_QUEUE_WORD4_SETUP_OPERATION_BIT_SHIFT	0x18UL
#define CC_DSCRPTR_QUEUE_WORD4_SETUP_OPERATION_BIT_SIZE	0x4UL
#define CC_DSCRPTR_QUEUE_WORD4_DIN_SRAM_ENDIANNESS_BIT_SHIFT	0x1CUL
#define CC_DSCRPTR_QUEUE_WORD4_DIN_SRAM_ENDIANNESS_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_DOUT_SRAM_ENDIANNESS_BIT_SHIFT	0x1DUL
#define CC_DSCRPTR_QUEUE_WORD4_DOUT_SRAM_ENDIANNESS_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_WORD_SWAP_BIT_SHIFT	0x1EUL
#define CC_DSCRPTR_QUEUE_WORD4_WORD_SWAP_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD4_BYTES_SWAP_BIT_SHIFT	0x1FUL
#define CC_DSCRPTR_QUEUE_WORD4_BYTES_SWAP_BIT_SIZE	0x1UL
#define CC_DSCRPTR_QUEUE_WORD5_REG_OFFSET	0xE94UL
#define CC_DSCRPTR_QUEUE_WORD5_DIN_ADDR_HIGH_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_WORD5_DIN_ADDR_HIGH_BIT_SIZE	0x10UL
#define CC_DSCRPTR_QUEUE_WORD5_DOUT_ADDR_HIGH_BIT_SHIFT	0x10UL
#define CC_DSCRPTR_QUEUE_WORD5_DOUT_ADDR_HIGH_BIT_SIZE	0x10UL
#define CC_DSCRPTR_QUEUE_WATERMARK_REG_OFFSET	0xE98UL
#define CC_DSCRPTR_QUEUE_WATERMARK_VALUE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_WATERMARK_VALUE_BIT_SIZE	0xAUL
#define CC_DSCRPTR_QUEUE_CONTENT_REG_OFFSET	0xE9CUL
#define CC_DSCRPTR_QUEUE_CONTENT_VALUE_BIT_SHIFT	0x0UL
#define CC_DSCRPTR_QUEUE_CONTENT_VALUE_BIT_SIZE	0xAUL
// --------------------------------------
// BLOCK: AXI_P
// --------------------------------------
#define CC_AXIM_MON_INFLIGHT_REG_OFFSET	0xB00UL
#define CC_AXIM_MON_INFLIGHT_VALUE_BIT_SHIFT	0x0UL
#define CC_AXIM_MON_INFLIGHT_VALUE_BIT_SIZE	0x8UL
#define CC_AXIM_MON_INFLIGHTLAST_REG_OFFSET	0xB40UL
#define CC_AXIM_MON_INFLIGHTLAST_VALUE_BIT_SHIFT	0x0UL
#define CC_AXIM_MON_INFLIGHTLAST_VALUE_BIT_SIZE	0x8UL
#define CC_AXIM_MON_COMP_REG_OFFSET	0xB80UL
#define CC_AXIM_MON_COMP_VALUE_BIT_SHIFT	0x0UL
#define CC_AXIM_MON_COMP_VALUE_BIT_SIZE	0x10UL
#define CC_AXIM_MON_ERR_REG_OFFSET	0xBC4UL
#define CC_AXIM_MON_ERR_BRESP_BIT_SHIFT	0x0UL
#define CC_AXIM_MON_ERR_BRESP_BIT_SIZE	0x2UL
#define CC_AXIM_MON_ERR_BID_BIT_SHIFT	0x2UL
#define CC_AXIM_MON_ERR_BID_BIT_SIZE	0x4UL
#define CC_AXIM_MON_ERR_RRESP_BIT_SHIFT	0x10UL
#define CC_AXIM_MON_ERR_RRESP_BIT_SIZE	0x2UL
#define CC_AXIM_MON_ERR_RID_BIT_SHIFT	0x12UL
#define CC_AXIM_MON_ERR_RID_BIT_SIZE	0x4UL
#define CC_AXIM_CFG_REG_OFFSET	0xBE8UL
#define CC_AXIM_CFG_BRESPMASK_BIT_SHIFT	0x4UL
#define CC_AXIM_CFG_BRESPMASK_BIT_SIZE	0x1UL
#define CC_AXIM_CFG_RRESPMASK_BIT_SHIFT	0x5UL
#define CC_AXIM_CFG_RRESPMASK_BIT_SIZE	0x1UL
#define CC_AXIM_CFG_INFLTMASK_BIT_SHIFT	0x6UL
#define CC_AXIM_CFG_INFLTMASK_BIT_SIZE	0x1UL
#define CC_AXIM_CFG_COMPMASK_BIT_SHIFT	0x7UL
#define CC_AXIM_CFG_COMPMASK_BIT_SIZE	0x1UL
#define CC_AXIM_ACE_CONST_REG_OFFSET	0xBECUL
#define CC_AXIM_ACE_CONST_ARDOMAIN_BIT_SHIFT	0x0UL
#define CC_AXIM_ACE_CONST_ARDOMAIN_BIT_SIZE	0x2UL
#define CC_AXIM_ACE_CONST_AWDOMAIN_BIT_SHIFT	0x2UL
#define CC_AXIM_ACE_CONST_AWDOMAIN_BIT_SIZE	0x2UL
#define CC_AXIM_ACE_CONST_ARBAR_BIT_SHIFT	0x4UL
#define CC_AXIM_ACE_CONST_ARBAR_BIT_SIZE	0x2UL
#define CC_AXIM_ACE_CONST_AWBAR_BIT_SHIFT	0x6UL
#define CC_AXIM_ACE_CONST_AWBAR_BIT_SIZE	0x2UL
#define CC_AXIM_ACE_CONST_ARSNOOP_BIT_SHIFT	0x8UL
#define CC_AXIM_ACE_CONST_ARSNOOP_BIT_SIZE	0x4UL
#define CC_AXIM_ACE_CONST_AWSNOOP_NOT_ALIGNED_BIT_SHIFT	0xCUL
#define CC_AXIM_ACE_CONST_AWSNOOP_NOT_ALIGNED_BIT_SIZE	0x3UL
#define CC_AXIM_ACE_CONST_AWSNOOP_ALIGNED_BIT_SHIFT	0xFUL
#define CC_AXIM_ACE_CONST_AWSNOOP_ALIGNED_BIT_SIZE	0x3UL
#define CC_AXIM_ACE_CONST_AWADDR_NOT_MASKED_BIT_SHIFT	0x12UL
#define CC_AXIM_ACE_CONST_AWADDR_NOT_MASKED_BIT_SIZE	0x7UL
#define CC_AXIM_ACE_CONST_AWLEN_VAL_BIT_SHIFT	0x19UL
#define CC_AXIM_ACE_CONST_AWLEN_VAL_BIT_SIZE	0x4UL
#define CC_AXIM_CACHE_PARAMS_REG_OFFSET	0xBF0UL
#define CC_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SHIFT	0x0UL
#define CC_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SIZE	0x4UL
#define CC_AXIM_CACHE_PARAMS_AWCACHE_BIT_SHIFT	0x4UL
#define CC_AXIM_CACHE_PARAMS_AWCACHE_BIT_SIZE	0x4UL
#define CC_AXIM_CACHE_PARAMS_ARCACHE_BIT_SHIFT	0x8UL
#define CC_AXIM_CACHE_PARAMS_ARCACHE_BIT_SIZE	0x4UL
#endif	// __CC_CRYS_KERNEL_H__
