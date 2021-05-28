/*
 * Copyright (C) 2019  Advanced Micro Devices, Inc.
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
#ifndef _hdp_5_0_0_OFFSET_HEADER
#define _hdp_5_0_0_OFFSET_HEADER



// addressBlock: hdp_hdpdec
// base address: 0x3c80
#define mmHDP_MMHUB_TLVL                                                                               0x0000
#define mmHDP_MMHUB_TLVL_BASE_IDX                                                                      0
#define mmHDP_MMHUB_UNITID                                                                             0x0001
#define mmHDP_MMHUB_UNITID_BASE_IDX                                                                    0
#define mmHDP_NONSURFACE_BASE                                                                          0x0040
#define mmHDP_NONSURFACE_BASE_BASE_IDX                                                                 0
#define mmHDP_NONSURFACE_INFO                                                                          0x0041
#define mmHDP_NONSURFACE_INFO_BASE_IDX                                                                 0
#define mmHDP_NONSURFACE_BASE_HI                                                                       0x0042
#define mmHDP_NONSURFACE_BASE_HI_BASE_IDX                                                              0
#define mmHDP_SURFACE_WRITE_FLAGS                                                                      0x00c4
#define mmHDP_SURFACE_WRITE_FLAGS_BASE_IDX                                                             0
#define mmHDP_SURFACE_READ_FLAGS                                                                       0x00c5
#define mmHDP_SURFACE_READ_FLAGS_BASE_IDX                                                              0
#define mmHDP_SURFACE_WRITE_FLAGS_CLR                                                                  0x00c6
#define mmHDP_SURFACE_WRITE_FLAGS_CLR_BASE_IDX                                                         0
#define mmHDP_SURFACE_READ_FLAGS_CLR                                                                   0x00c7
#define mmHDP_SURFACE_READ_FLAGS_CLR_BASE_IDX                                                          0
#define mmHDP_NONSURF_FLAGS                                                                            0x00c8
#define mmHDP_NONSURF_FLAGS_BASE_IDX                                                                   0
#define mmHDP_NONSURF_FLAGS_CLR                                                                        0x00c9
#define mmHDP_NONSURF_FLAGS_CLR_BASE_IDX                                                               0
#define mmHDP_HOST_PATH_CNTL                                                                           0x00cc
#define mmHDP_HOST_PATH_CNTL_BASE_IDX                                                                  0
#define mmHDP_SW_SEMAPHORE                                                                             0x00cd
#define mmHDP_SW_SEMAPHORE_BASE_IDX                                                                    0
#define mmHDP_LAST_SURFACE_HIT                                                                         0x00d0
#define mmHDP_LAST_SURFACE_HIT_BASE_IDX                                                                0
#define mmHDP_READ_CACHE_INVALIDATE                                                                    0x00d1
#define mmHDP_READ_CACHE_INVALIDATE_BASE_IDX                                                           0
#define mmHDP_OUTSTANDING_REQ                                                                          0x00d2
#define mmHDP_OUTSTANDING_REQ_BASE_IDX                                                                 0
#define mmHDP_MISC_CNTL                                                                                0x00d3
#define mmHDP_MISC_CNTL_BASE_IDX                                                                       0
#define mmHDP_MEM_POWER_CTRL                                                                           0x00d4
#define mmHDP_MEM_POWER_CTRL_BASE_IDX                                                                  0
#define mmHDP_MMHUB_CNTL                                                                               0x00d5
#define mmHDP_MMHUB_CNTL_BASE_IDX                                                                      0
#define mmHDP_EDC_CNT                                                                                  0x00d6
#define mmHDP_EDC_CNT_BASE_IDX                                                                         0
#define mmHDP_VERSION                                                                                  0x00d7
#define mmHDP_VERSION_BASE_IDX                                                                         0
#define mmHDP_CLK_CNTL                                                                                 0x00d8
#define mmHDP_CLK_CNTL_BASE_IDX                                                                        0
#define mmHDP_MEMIO_CNTL                                                                               0x00f6
#define mmHDP_MEMIO_CNTL_BASE_IDX                                                                      0
#define mmHDP_MEMIO_ADDR                                                                               0x00f7
#define mmHDP_MEMIO_ADDR_BASE_IDX                                                                      0
#define mmHDP_MEMIO_STATUS                                                                             0x00f8
#define mmHDP_MEMIO_STATUS_BASE_IDX                                                                    0
#define mmHDP_MEMIO_WR_DATA                                                                            0x00f9
#define mmHDP_MEMIO_WR_DATA_BASE_IDX                                                                   0
#define mmHDP_MEMIO_RD_DATA                                                                            0x00fa
#define mmHDP_MEMIO_RD_DATA_BASE_IDX                                                                   0
#define mmHDP_XDP_DIRECT2HDP_FIRST                                                                     0x0100
#define mmHDP_XDP_DIRECT2HDP_FIRST_BASE_IDX                                                            0
#define mmHDP_XDP_D2H_FLUSH                                                                            0x0101
#define mmHDP_XDP_D2H_FLUSH_BASE_IDX                                                                   0
#define mmHDP_XDP_D2H_BAR_UPDATE                                                                       0x0102
#define mmHDP_XDP_D2H_BAR_UPDATE_BASE_IDX                                                              0
#define mmHDP_XDP_D2H_RSVD_3                                                                           0x0103
#define mmHDP_XDP_D2H_RSVD_3_BASE_IDX                                                                  0
#define mmHDP_XDP_D2H_RSVD_4                                                                           0x0104
#define mmHDP_XDP_D2H_RSVD_4_BASE_IDX                                                                  0
#define mmHDP_XDP_D2H_RSVD_5                                                                           0x0105
#define mmHDP_XDP_D2H_RSVD_5_BASE_IDX                                                                  0
#define mmHDP_XDP_D2H_RSVD_6                                                                           0x0106
#define mmHDP_XDP_D2H_RSVD_6_BASE_IDX                                                                  0
#define mmHDP_XDP_D2H_RSVD_7                                                                           0x0107
#define mmHDP_XDP_D2H_RSVD_7_BASE_IDX                                                                  0
#define mmHDP_XDP_D2H_RSVD_8                                                                           0x0108
#define mmHDP_XDP_D2H_RSVD_8_BASE_IDX                                                                  0
#define mmHDP_XDP_D2H_RSVD_9                                                                           0x0109
#define mmHDP_XDP_D2H_RSVD_9_BASE_IDX                                                                  0
#define mmHDP_XDP_D2H_RSVD_10                                                                          0x010a
#define mmHDP_XDP_D2H_RSVD_10_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_11                                                                          0x010b
#define mmHDP_XDP_D2H_RSVD_11_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_12                                                                          0x010c
#define mmHDP_XDP_D2H_RSVD_12_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_13                                                                          0x010d
#define mmHDP_XDP_D2H_RSVD_13_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_14                                                                          0x010e
#define mmHDP_XDP_D2H_RSVD_14_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_15                                                                          0x010f
#define mmHDP_XDP_D2H_RSVD_15_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_16                                                                          0x0110
#define mmHDP_XDP_D2H_RSVD_16_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_17                                                                          0x0111
#define mmHDP_XDP_D2H_RSVD_17_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_18                                                                          0x0112
#define mmHDP_XDP_D2H_RSVD_18_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_19                                                                          0x0113
#define mmHDP_XDP_D2H_RSVD_19_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_20                                                                          0x0114
#define mmHDP_XDP_D2H_RSVD_20_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_21                                                                          0x0115
#define mmHDP_XDP_D2H_RSVD_21_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_22                                                                          0x0116
#define mmHDP_XDP_D2H_RSVD_22_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_23                                                                          0x0117
#define mmHDP_XDP_D2H_RSVD_23_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_24                                                                          0x0118
#define mmHDP_XDP_D2H_RSVD_24_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_25                                                                          0x0119
#define mmHDP_XDP_D2H_RSVD_25_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_26                                                                          0x011a
#define mmHDP_XDP_D2H_RSVD_26_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_27                                                                          0x011b
#define mmHDP_XDP_D2H_RSVD_27_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_28                                                                          0x011c
#define mmHDP_XDP_D2H_RSVD_28_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_29                                                                          0x011d
#define mmHDP_XDP_D2H_RSVD_29_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_30                                                                          0x011e
#define mmHDP_XDP_D2H_RSVD_30_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_31                                                                          0x011f
#define mmHDP_XDP_D2H_RSVD_31_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_32                                                                          0x0120
#define mmHDP_XDP_D2H_RSVD_32_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_33                                                                          0x0121
#define mmHDP_XDP_D2H_RSVD_33_BASE_IDX                                                                 0
#define mmHDP_XDP_D2H_RSVD_34                                                                          0x0122
#define mmHDP_XDP_D2H_RSVD_34_BASE_IDX                                                                 0
#define mmHDP_XDP_DIRECT2HDP_LAST                                                                      0x0123
#define mmHDP_XDP_DIRECT2HDP_LAST_BASE_IDX                                                             0
#define mmHDP_XDP_P2P_BAR_CFG                                                                          0x0124
#define mmHDP_XDP_P2P_BAR_CFG_BASE_IDX                                                                 0
#define mmHDP_XDP_P2P_MBX_OFFSET                                                                       0x0125
#define mmHDP_XDP_P2P_MBX_OFFSET_BASE_IDX                                                              0
#define mmHDP_XDP_P2P_MBX_ADDR0                                                                        0x0126
#define mmHDP_XDP_P2P_MBX_ADDR0_BASE_IDX                                                               0
#define mmHDP_XDP_P2P_MBX_ADDR1                                                                        0x0127
#define mmHDP_XDP_P2P_MBX_ADDR1_BASE_IDX                                                               0
#define mmHDP_XDP_P2P_MBX_ADDR2                                                                        0x0128
#define mmHDP_XDP_P2P_MBX_ADDR2_BASE_IDX                                                               0
#define mmHDP_XDP_P2P_MBX_ADDR3                                                                        0x0129
#define mmHDP_XDP_P2P_MBX_ADDR3_BASE_IDX                                                               0
#define mmHDP_XDP_P2P_MBX_ADDR4                                                                        0x012a
#define mmHDP_XDP_P2P_MBX_ADDR4_BASE_IDX                                                               0
#define mmHDP_XDP_P2P_MBX_ADDR5                                                                        0x012b
#define mmHDP_XDP_P2P_MBX_ADDR5_BASE_IDX                                                               0
#define mmHDP_XDP_P2P_MBX_ADDR6                                                                        0x012c
#define mmHDP_XDP_P2P_MBX_ADDR6_BASE_IDX                                                               0
#define mmHDP_XDP_HDP_MBX_MC_CFG                                                                       0x012d
#define mmHDP_XDP_HDP_MBX_MC_CFG_BASE_IDX                                                              0
#define mmHDP_XDP_HDP_MC_CFG                                                                           0x012e
#define mmHDP_XDP_HDP_MC_CFG_BASE_IDX                                                                  0
#define mmHDP_XDP_HST_CFG                                                                              0x012f
#define mmHDP_XDP_HST_CFG_BASE_IDX                                                                     0
#define mmHDP_XDP_HDP_IPH_CFG                                                                          0x0131
#define mmHDP_XDP_HDP_IPH_CFG_BASE_IDX                                                                 0
#define mmHDP_XDP_P2P_BAR0                                                                             0x0134
#define mmHDP_XDP_P2P_BAR0_BASE_IDX                                                                    0
#define mmHDP_XDP_P2P_BAR1                                                                             0x0135
#define mmHDP_XDP_P2P_BAR1_BASE_IDX                                                                    0
#define mmHDP_XDP_P2P_BAR2                                                                             0x0136
#define mmHDP_XDP_P2P_BAR2_BASE_IDX                                                                    0
#define mmHDP_XDP_P2P_BAR3                                                                             0x0137
#define mmHDP_XDP_P2P_BAR3_BASE_IDX                                                                    0
#define mmHDP_XDP_P2P_BAR4                                                                             0x0138
#define mmHDP_XDP_P2P_BAR4_BASE_IDX                                                                    0
#define mmHDP_XDP_P2P_BAR5                                                                             0x0139
#define mmHDP_XDP_P2P_BAR5_BASE_IDX                                                                    0
#define mmHDP_XDP_P2P_BAR6                                                                             0x013a
#define mmHDP_XDP_P2P_BAR6_BASE_IDX                                                                    0
#define mmHDP_XDP_P2P_BAR7                                                                             0x013b
#define mmHDP_XDP_P2P_BAR7_BASE_IDX                                                                    0
#define mmHDP_XDP_FLUSH_ARMED_STS                                                                      0x013c
#define mmHDP_XDP_FLUSH_ARMED_STS_BASE_IDX                                                             0
#define mmHDP_XDP_FLUSH_CNTR0_STS                                                                      0x013d
#define mmHDP_XDP_FLUSH_CNTR0_STS_BASE_IDX                                                             0
#define mmHDP_XDP_BUSY_STS                                                                             0x013e
#define mmHDP_XDP_BUSY_STS_BASE_IDX                                                                    0
#define mmHDP_XDP_STICKY                                                                               0x013f
#define mmHDP_XDP_STICKY_BASE_IDX                                                                      0
#define mmHDP_XDP_CHKN                                                                                 0x0140
#define mmHDP_XDP_CHKN_BASE_IDX                                                                        0
#define mmHDP_XDP_BARS_ADDR_39_36                                                                      0x0144
#define mmHDP_XDP_BARS_ADDR_39_36_BASE_IDX                                                             0
#define mmHDP_XDP_MC_VM_FB_LOCATION_BASE                                                               0x0145
#define mmHDP_XDP_MC_VM_FB_LOCATION_BASE_BASE_IDX                                                      0
#define mmHDP_XDP_GPU_IOV_VIOLATION_LOG                                                                0x0148
#define mmHDP_XDP_GPU_IOV_VIOLATION_LOG_BASE_IDX                                                       0
#define mmHDP_XDP_GPU_IOV_VIOLATION_LOG2                                                               0x0149
#define mmHDP_XDP_GPU_IOV_VIOLATION_LOG2_BASE_IDX                                                      0
#define mmHDP_XDP_MMHUB_ERROR                                                                          0x014a
#define mmHDP_XDP_MMHUB_ERROR_BASE_IDX                                                                 0

#endif
