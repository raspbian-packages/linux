/*
 * Copyright (C) 2017  Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef _sdma0_4_1_DEFAULT_HEADER
#define _sdma0_4_1_DEFAULT_HEADER


// addressBlock: sdma0_sdma0dec
#define mmSDMA0_UCODE_ADDR_DEFAULT                                               0x00000000
#define mmSDMA0_UCODE_DATA_DEFAULT                                               0x00000000
#define mmSDMA0_VM_CNTL_DEFAULT                                                  0x00000000
#define mmSDMA0_VM_CTX_LO_DEFAULT                                                0x00000000
#define mmSDMA0_VM_CTX_HI_DEFAULT                                                0x00000000
#define mmSDMA0_ACTIVE_FCN_ID_DEFAULT                                            0x00000000
#define mmSDMA0_VM_CTX_CNTL_DEFAULT                                              0x00000000
#define mmSDMA0_VIRT_RESET_REQ_DEFAULT                                           0x00000000
#define mmSDMA0_CONTEXT_REG_TYPE0_DEFAULT                                        0xfffdf79f
#define mmSDMA0_CONTEXT_REG_TYPE1_DEFAULT                                        0x003fbcff
#define mmSDMA0_CONTEXT_REG_TYPE2_DEFAULT                                        0x000003ff
#define mmSDMA0_CONTEXT_REG_TYPE3_DEFAULT                                        0x00000000
#define mmSDMA0_PUB_REG_TYPE0_DEFAULT                                            0x3c000000
#define mmSDMA0_PUB_REG_TYPE1_DEFAULT                                            0x30003882
#define mmSDMA0_PUB_REG_TYPE2_DEFAULT                                            0x0fc66880
#define mmSDMA0_PUB_REG_TYPE3_DEFAULT                                            0x00000000
#define mmSDMA0_MMHUB_CNTL_DEFAULT                                               0x00000000
#define mmSDMA0_CONTEXT_GROUP_BOUNDARY_DEFAULT                                   0x00000000
#define mmSDMA0_POWER_CNTL_DEFAULT                                               0x4003c050
#define mmSDMA0_CLK_CTRL_DEFAULT                                                 0xff000100
#define mmSDMA0_CNTL_DEFAULT                                                     0x00000002
#define mmSDMA0_CHICKEN_BITS_DEFAULT                                             0x00831f07
#define mmSDMA0_GB_ADDR_CONFIG_DEFAULT                                           0x00100012
#define mmSDMA0_GB_ADDR_CONFIG_READ_DEFAULT                                      0x00100012
#define mmSDMA0_RB_RPTR_FETCH_HI_DEFAULT                                         0x00000000
#define mmSDMA0_SEM_WAIT_FAIL_TIMER_CNTL_DEFAULT                                 0x00000000
#define mmSDMA0_RB_RPTR_FETCH_DEFAULT                                            0x00000000
#define mmSDMA0_IB_OFFSET_FETCH_DEFAULT                                          0x00000000
#define mmSDMA0_PROGRAM_DEFAULT                                                  0x00000000
#define mmSDMA0_STATUS_REG_DEFAULT                                               0x46dee557
#define mmSDMA0_STATUS1_REG_DEFAULT                                              0x000003ff
#define mmSDMA0_RD_BURST_CNTL_DEFAULT                                            0x00000003
#define mmSDMA0_HBM_PAGE_CONFIG_DEFAULT                                          0x00000000
#define mmSDMA0_UCODE_CHECKSUM_DEFAULT                                           0x00000000
#define mmSDMA0_F32_CNTL_DEFAULT                                                 0x00000001
#define mmSDMA0_FREEZE_DEFAULT                                                   0x00000000
#define mmSDMA0_PHASE0_QUANTUM_DEFAULT                                           0x00010002
#define mmSDMA0_PHASE1_QUANTUM_DEFAULT                                           0x00010002
#define mmSDMA_POWER_GATING_DEFAULT                                              0x00000000
#define mmSDMA_PGFSM_CONFIG_DEFAULT                                              0x00000000
#define mmSDMA_PGFSM_WRITE_DEFAULT                                               0x00000000
#define mmSDMA_PGFSM_READ_DEFAULT                                                0x00000000
#define mmSDMA0_EDC_CONFIG_DEFAULT                                               0x00000002
#define mmSDMA0_BA_THRESHOLD_DEFAULT                                             0x03ff03ff
#define mmSDMA0_ID_DEFAULT                                                       0x00000001
#define mmSDMA0_VERSION_DEFAULT                                                  0x00000401
#define mmSDMA0_EDC_COUNTER_DEFAULT                                              0x00000000
#define mmSDMA0_EDC_COUNTER_CLEAR_DEFAULT                                        0x00000000
#define mmSDMA0_STATUS2_REG_DEFAULT                                              0x00000000
#define mmSDMA0_ATOMIC_CNTL_DEFAULT                                              0x00000200
#define mmSDMA0_ATOMIC_PREOP_LO_DEFAULT                                          0x00000000
#define mmSDMA0_ATOMIC_PREOP_HI_DEFAULT                                          0x00000000
#define mmSDMA0_UTCL1_CNTL_DEFAULT                                               0xd0003019
#define mmSDMA0_UTCL1_WATERMK_DEFAULT                                            0xfffbe1fe
#define mmSDMA0_UTCL1_RD_STATUS_DEFAULT                                          0x201001ff
#define mmSDMA0_UTCL1_WR_STATUS_DEFAULT                                          0x503001ff
#define mmSDMA0_UTCL1_INV0_DEFAULT                                               0x00000600
#define mmSDMA0_UTCL1_INV1_DEFAULT                                               0x00000000
#define mmSDMA0_UTCL1_INV2_DEFAULT                                               0x00000000
#define mmSDMA0_UTCL1_RD_XNACK0_DEFAULT                                          0x00000000
#define mmSDMA0_UTCL1_RD_XNACK1_DEFAULT                                          0x00000000
#define mmSDMA0_UTCL1_WR_XNACK0_DEFAULT                                          0x00000000
#define mmSDMA0_UTCL1_WR_XNACK1_DEFAULT                                          0x00000000
#define mmSDMA0_UTCL1_TIMEOUT_DEFAULT                                            0x00010001
#define mmSDMA0_UTCL1_PAGE_DEFAULT                                               0x000003e0
#define mmSDMA0_POWER_CNTL_IDLE_DEFAULT                                          0x06060200
#define mmSDMA0_RELAX_ORDERING_LUT_DEFAULT                                       0xc0000006
#define mmSDMA0_CHICKEN_BITS_2_DEFAULT                                           0x00000005
#define mmSDMA0_STATUS3_REG_DEFAULT                                              0x00100000
#define mmSDMA0_PHYSICAL_ADDR_LO_DEFAULT                                         0x00000000
#define mmSDMA0_PHYSICAL_ADDR_HI_DEFAULT                                         0x00000000
#define mmSDMA0_ERROR_LOG_DEFAULT                                                0x0000000f
#define mmSDMA0_PUB_DUMMY_REG0_DEFAULT                                           0x00000000
#define mmSDMA0_PUB_DUMMY_REG1_DEFAULT                                           0x00000000
#define mmSDMA0_PUB_DUMMY_REG2_DEFAULT                                           0x00000000
#define mmSDMA0_PUB_DUMMY_REG3_DEFAULT                                           0x00000000
#define mmSDMA0_F32_COUNTER_DEFAULT                                              0x00000000
#define mmSDMA0_UNBREAKABLE_DEFAULT                                              0x00000000
#define mmSDMA0_PERFMON_CNTL_DEFAULT                                             0x000ff7fd
#define mmSDMA0_PERFCOUNTER0_RESULT_DEFAULT                                      0x00000000
#define mmSDMA0_PERFCOUNTER1_RESULT_DEFAULT                                      0x00000000
#define mmSDMA0_PERFCOUNTER_TAG_DELAY_RANGE_DEFAULT                              0x00640000
#define mmSDMA0_CRD_CNTL_DEFAULT                                                 0x000085c0
#define mmSDMA0_MMHUB_TRUSTLVL_DEFAULT                                           0x00000000
#define mmSDMA0_GPU_IOV_VIOLATION_LOG_DEFAULT                                    0x00000000
#define mmSDMA0_ULV_CNTL_DEFAULT                                                 0x00000000
#define mmSDMA0_EA_DBIT_ADDR_DATA_DEFAULT                                        0x00000000
#define mmSDMA0_EA_DBIT_ADDR_INDEX_DEFAULT                                       0x00000000
#define mmSDMA0_GFX_RB_CNTL_DEFAULT                                              0x00040000
#define mmSDMA0_GFX_RB_BASE_DEFAULT                                              0x00000000
#define mmSDMA0_GFX_RB_BASE_HI_DEFAULT                                           0x00000000
#define mmSDMA0_GFX_RB_RPTR_DEFAULT                                              0x00000000
#define mmSDMA0_GFX_RB_RPTR_HI_DEFAULT                                           0x00000000
#define mmSDMA0_GFX_RB_WPTR_DEFAULT                                              0x00000000
#define mmSDMA0_GFX_RB_WPTR_HI_DEFAULT                                           0x00000000
#define mmSDMA0_GFX_RB_WPTR_POLL_CNTL_DEFAULT                                    0x00401000
#define mmSDMA0_GFX_RB_RPTR_ADDR_HI_DEFAULT                                      0x00000000
#define mmSDMA0_GFX_RB_RPTR_ADDR_LO_DEFAULT                                      0x00000000
#define mmSDMA0_GFX_IB_CNTL_DEFAULT                                              0x00000100
#define mmSDMA0_GFX_IB_RPTR_DEFAULT                                              0x00000000
#define mmSDMA0_GFX_IB_OFFSET_DEFAULT                                            0x00000000
#define mmSDMA0_GFX_IB_BASE_LO_DEFAULT                                           0x00000000
#define mmSDMA0_GFX_IB_BASE_HI_DEFAULT                                           0x00000000
#define mmSDMA0_GFX_IB_SIZE_DEFAULT                                              0x00000000
#define mmSDMA0_GFX_SKIP_CNTL_DEFAULT                                            0x00000000
#define mmSDMA0_GFX_CONTEXT_STATUS_DEFAULT                                       0x00000005
#define mmSDMA0_GFX_DOORBELL_DEFAULT                                             0x00000000
#define mmSDMA0_GFX_CONTEXT_CNTL_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_STATUS_DEFAULT                                               0x00000000
#define mmSDMA0_GFX_DOORBELL_LOG_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_WATERMARK_DEFAULT                                            0x00000000
#define mmSDMA0_GFX_DOORBELL_OFFSET_DEFAULT                                      0x00000000
#define mmSDMA0_GFX_CSA_ADDR_LO_DEFAULT                                          0x00000000
#define mmSDMA0_GFX_CSA_ADDR_HI_DEFAULT                                          0x00000000
#define mmSDMA0_GFX_IB_SUB_REMAIN_DEFAULT                                        0x00000000
#define mmSDMA0_GFX_PREEMPT_DEFAULT                                              0x00000000
#define mmSDMA0_GFX_DUMMY_REG_DEFAULT                                            0x0000000f
#define mmSDMA0_GFX_RB_WPTR_POLL_ADDR_HI_DEFAULT                                 0x00000000
#define mmSDMA0_GFX_RB_WPTR_POLL_ADDR_LO_DEFAULT                                 0x00000000
#define mmSDMA0_GFX_RB_AQL_CNTL_DEFAULT                                          0x00004000
#define mmSDMA0_GFX_MINOR_PTR_UPDATE_DEFAULT                                     0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA0_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA1_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA2_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA3_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA4_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA5_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA6_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA7_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_DATA8_DEFAULT                                         0x00000000
#define mmSDMA0_GFX_MIDCMD_CNTL_DEFAULT                                          0x00000000
#define mmSDMA0_RLC0_RB_CNTL_DEFAULT                                             0x00040000
#define mmSDMA0_RLC0_RB_BASE_DEFAULT                                             0x00000000
#define mmSDMA0_RLC0_RB_BASE_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC0_RB_RPTR_DEFAULT                                             0x00000000
#define mmSDMA0_RLC0_RB_RPTR_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC0_RB_WPTR_DEFAULT                                             0x00000000
#define mmSDMA0_RLC0_RB_WPTR_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC0_RB_WPTR_POLL_CNTL_DEFAULT                                   0x00401000
#define mmSDMA0_RLC0_RB_RPTR_ADDR_HI_DEFAULT                                     0x00000000
#define mmSDMA0_RLC0_RB_RPTR_ADDR_LO_DEFAULT                                     0x00000000
#define mmSDMA0_RLC0_IB_CNTL_DEFAULT                                             0x00000100
#define mmSDMA0_RLC0_IB_RPTR_DEFAULT                                             0x00000000
#define mmSDMA0_RLC0_IB_OFFSET_DEFAULT                                           0x00000000
#define mmSDMA0_RLC0_IB_BASE_LO_DEFAULT                                          0x00000000
#define mmSDMA0_RLC0_IB_BASE_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC0_IB_SIZE_DEFAULT                                             0x00000000
#define mmSDMA0_RLC0_SKIP_CNTL_DEFAULT                                           0x00000000
#define mmSDMA0_RLC0_CONTEXT_STATUS_DEFAULT                                      0x00000004
#define mmSDMA0_RLC0_DOORBELL_DEFAULT                                            0x00000000
#define mmSDMA0_RLC0_STATUS_DEFAULT                                              0x00000000
#define mmSDMA0_RLC0_DOORBELL_LOG_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_WATERMARK_DEFAULT                                           0x00000000
#define mmSDMA0_RLC0_DOORBELL_OFFSET_DEFAULT                                     0x00000000
#define mmSDMA0_RLC0_CSA_ADDR_LO_DEFAULT                                         0x00000000
#define mmSDMA0_RLC0_CSA_ADDR_HI_DEFAULT                                         0x00000000
#define mmSDMA0_RLC0_IB_SUB_REMAIN_DEFAULT                                       0x00000000
#define mmSDMA0_RLC0_PREEMPT_DEFAULT                                             0x00000000
#define mmSDMA0_RLC0_DUMMY_REG_DEFAULT                                           0x0000000f
#define mmSDMA0_RLC0_RB_WPTR_POLL_ADDR_HI_DEFAULT                                0x00000000
#define mmSDMA0_RLC0_RB_WPTR_POLL_ADDR_LO_DEFAULT                                0x00000000
#define mmSDMA0_RLC0_RB_AQL_CNTL_DEFAULT                                         0x00004000
#define mmSDMA0_RLC0_MINOR_PTR_UPDATE_DEFAULT                                    0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA0_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA1_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA2_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA3_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA4_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA5_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA6_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA7_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_DATA8_DEFAULT                                        0x00000000
#define mmSDMA0_RLC0_MIDCMD_CNTL_DEFAULT                                         0x00000000
#define mmSDMA0_RLC1_RB_CNTL_DEFAULT                                             0x00040000
#define mmSDMA0_RLC1_RB_BASE_DEFAULT                                             0x00000000
#define mmSDMA0_RLC1_RB_BASE_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC1_RB_RPTR_DEFAULT                                             0x00000000
#define mmSDMA0_RLC1_RB_RPTR_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC1_RB_WPTR_DEFAULT                                             0x00000000
#define mmSDMA0_RLC1_RB_WPTR_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC1_RB_WPTR_POLL_CNTL_DEFAULT                                   0x00401000
#define mmSDMA0_RLC1_RB_RPTR_ADDR_HI_DEFAULT                                     0x00000000
#define mmSDMA0_RLC1_RB_RPTR_ADDR_LO_DEFAULT                                     0x00000000
#define mmSDMA0_RLC1_IB_CNTL_DEFAULT                                             0x00000100
#define mmSDMA0_RLC1_IB_RPTR_DEFAULT                                             0x00000000
#define mmSDMA0_RLC1_IB_OFFSET_DEFAULT                                           0x00000000
#define mmSDMA0_RLC1_IB_BASE_LO_DEFAULT                                          0x00000000
#define mmSDMA0_RLC1_IB_BASE_HI_DEFAULT                                          0x00000000
#define mmSDMA0_RLC1_IB_SIZE_DEFAULT                                             0x00000000
#define mmSDMA0_RLC1_SKIP_CNTL_DEFAULT                                           0x00000000
#define mmSDMA0_RLC1_CONTEXT_STATUS_DEFAULT                                      0x00000004
#define mmSDMA0_RLC1_DOORBELL_DEFAULT                                            0x00000000
#define mmSDMA0_RLC1_STATUS_DEFAULT                                              0x00000000
#define mmSDMA0_RLC1_DOORBELL_LOG_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_WATERMARK_DEFAULT                                           0x00000000
#define mmSDMA0_RLC1_DOORBELL_OFFSET_DEFAULT                                     0x00000000
#define mmSDMA0_RLC1_CSA_ADDR_LO_DEFAULT                                         0x00000000
#define mmSDMA0_RLC1_CSA_ADDR_HI_DEFAULT                                         0x00000000
#define mmSDMA0_RLC1_IB_SUB_REMAIN_DEFAULT                                       0x00000000
#define mmSDMA0_RLC1_PREEMPT_DEFAULT                                             0x00000000
#define mmSDMA0_RLC1_DUMMY_REG_DEFAULT                                           0x0000000f
#define mmSDMA0_RLC1_RB_WPTR_POLL_ADDR_HI_DEFAULT                                0x00000000
#define mmSDMA0_RLC1_RB_WPTR_POLL_ADDR_LO_DEFAULT                                0x00000000
#define mmSDMA0_RLC1_RB_AQL_CNTL_DEFAULT                                         0x00004000
#define mmSDMA0_RLC1_MINOR_PTR_UPDATE_DEFAULT                                    0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA0_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA1_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA2_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA3_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA4_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA5_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA6_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA7_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_DATA8_DEFAULT                                        0x00000000
#define mmSDMA0_RLC1_MIDCMD_CNTL_DEFAULT                                         0x00000000

#endif
