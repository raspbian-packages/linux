/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * AMD ACP 6.3 Register Documentation
 *
 * Copyright 2022 Advanced Micro Devices, Inc.
 */

#ifndef _acp_ip_OFFSET_HEADER
#define _acp_ip_OFFSET_HEADER

/* Registers from ACP_DMA block */
#define ACP_DMA_CNTL_0                                0x0000000
#define ACP_DMA_CNTL_1                                0x0000004
#define ACP_DMA_CNTL_2                                0x0000008
#define ACP_DMA_CNTL_3                                0x000000C
#define ACP_DMA_CNTL_4                                0x0000010
#define ACP_DMA_CNTL_5                                0x0000014
#define ACP_DMA_CNTL_6                                0x0000018
#define ACP_DMA_CNTL_7                                0x000001C
#define ACP_DMA_DSCR_STRT_IDX_0                       0x0000020
#define ACP_DMA_DSCR_STRT_IDX_1                       0x0000024
#define ACP_DMA_DSCR_STRT_IDX_2                       0x0000028
#define ACP_DMA_DSCR_STRT_IDX_3                       0x000002C
#define ACP_DMA_DSCR_STRT_IDX_4                       0x0000030
#define ACP_DMA_DSCR_STRT_IDX_5                       0x0000034
#define ACP_DMA_DSCR_STRT_IDX_6                       0x0000038
#define ACP_DMA_DSCR_STRT_IDX_7                       0x000003C
#define ACP_DMA_DSCR_CNT_0                            0x0000040
#define ACP_DMA_DSCR_CNT_1                            0x0000044
#define ACP_DMA_DSCR_CNT_2                            0x0000048
#define ACP_DMA_DSCR_CNT_3                            0x000004C
#define ACP_DMA_DSCR_CNT_4                            0x0000050
#define ACP_DMA_DSCR_CNT_5                            0x0000054
#define ACP_DMA_DSCR_CNT_6                            0x0000058
#define ACP_DMA_DSCR_CNT_7                            0x000005C
#define ACP_DMA_PRIO_0                                0x0000060
#define ACP_DMA_PRIO_1                                0x0000064
#define ACP_DMA_PRIO_2                                0x0000068
#define ACP_DMA_PRIO_3                                0x000006C
#define ACP_DMA_PRIO_4                                0x0000070
#define ACP_DMA_PRIO_5                                0x0000074
#define ACP_DMA_PRIO_6                                0x0000078
#define ACP_DMA_PRIO_7                                0x000007C
#define ACP_DMA_CUR_DSCR_0                            0x0000080
#define ACP_DMA_CUR_DSCR_1                            0x0000084
#define ACP_DMA_CUR_DSCR_2                            0x0000088
#define ACP_DMA_CUR_DSCR_3                            0x000008C
#define ACP_DMA_CUR_DSCR_4                            0x0000090
#define ACP_DMA_CUR_DSCR_5                            0x0000094
#define ACP_DMA_CUR_DSCR_6                            0x0000098
#define ACP_DMA_CUR_DSCR_7                            0x000009C
#define ACP_DMA_CUR_TRANS_CNT_0                       0x00000A0
#define ACP_DMA_CUR_TRANS_CNT_1                       0x00000A4
#define ACP_DMA_CUR_TRANS_CNT_2                       0x00000A8
#define ACP_DMA_CUR_TRANS_CNT_3                       0x00000AC
#define ACP_DMA_CUR_TRANS_CNT_4                       0x00000B0
#define ACP_DMA_CUR_TRANS_CNT_5                       0x00000B4
#define ACP_DMA_CUR_TRANS_CNT_6                       0x00000B8
#define ACP_DMA_CUR_TRANS_CNT_7                       0x00000BC
#define ACP_DMA_ERR_STS_0                             0x00000C0
#define ACP_DMA_ERR_STS_1                             0x00000C4
#define ACP_DMA_ERR_STS_2                             0x00000C8
#define ACP_DMA_ERR_STS_3                             0x00000CC
#define ACP_DMA_ERR_STS_4                             0x00000D0
#define ACP_DMA_ERR_STS_5                             0x00000D4
#define ACP_DMA_ERR_STS_6                             0x00000D8
#define ACP_DMA_ERR_STS_7                             0x00000DC
#define ACP_DMA_DESC_BASE_ADDR                        0x00000E0
#define ACP_DMA_DESC_MAX_NUM_DSCR                     0x00000E4
#define ACP_DMA_CH_STS                                0x00000E8
#define ACP_DMA_CH_GROUP                              0x00000EC
#define ACP_DMA_CH_RST_STS                            0x00000F0

/* Registers from ACP_AXI2AXIATU block */
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_1                0x0000C00
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_1                0x0000C04
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_2                0x0000C08
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_2                0x0000C0C
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_3                0x0000C10
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_3                0x0000C14
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_4                0x0000C18
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_4                0x0000C1C
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_5                0x0000C20
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_5                0x0000C24
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_6                0x0000C28
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_6                0x0000C2C
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_7                0x0000C30
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_7                0x0000C34
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_8                0x0000C38
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_8                0x0000C3C
#define ACPAXI2AXI_ATU_CTRL                           0x0000C40
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_9                0x0000C44
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_9                0x0000C48
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_10               0x0000C4C
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_10               0x0000C50
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_11               0x0000C54
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_11               0x0000C58
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_12               0x0000C5C
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_12               0x0000C60
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_13               0x0000C64
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_13               0x0000C68
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_14               0x0000C6C
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_14               0x0000C70
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_15               0x0000C74
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_15               0x0000C78
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_16               0x0000C7C
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_16               0x0000C80

/* Registers from ACP_CLKRST block */
#define ACP_SOFT_RESET                                0x0001000
#define ACP_CONTROL                                   0x0001004
#define ACP_STATUS                                    0x0001008
#define ACP_DYNAMIC_CG_MASTER_CONTROL                 0x0001010
#define ACP_ZSC_DSP_CTRL                              0x0001014
#define ACP_ZSC_STS                                   0x0001018
#define ACP_PGFSM_CONTROL                             0x0001024
#define ACP_PGFSM_STATUS                              0x0001028
#define ACP_CLKMUX_SEL                                0x000102C

/* Registers from ACP_AON block */
#define ACP_PME_EN                                    0x0001400
#define ACP_DEVICE_STATE                              0x0001404
#define AZ_DEVICE_STATE                               0x0001408
#define ACP_PIN_CONFIG                                0x0001440
#define ACP_PAD_PULLUP_CTRL                           0x0001444
#define ACP_PAD_PULLDOWN_CTRL                         0x0001448
#define ACP_PAD_DRIVE_STRENGTH_CTRL                   0x000144C
#define ACP_PAD_SCHMEN_CTRL                           0x0001450
#define ACP_SW0_PAD_KEEPER_EN                         0x0001454
#define ACP_SW0_WAKE_EN                               0x0001458
#define ACP_I2S_WAKE_EN                               0x000145C
#define ACP_SW1_WAKE_EN                               0x0001460

#define ACP_SW0_I2S_ERROR_REASON                      0x00018B4
#define ACP_SW0_POS_TRACK_AUDIO0_TX_CTRL              0x00018B8
#define ACP_SW0_AUDIO0_TX_DMA_POS                     0x00018BC
#define ACP_SW0_POS_TRACK_AUDIO1_TX_CTRL              0x00018C0
#define ACP_SW0_AUDIO1_TX_DMA_POS                     0x00018C4
#define ACP_SW0_POS_TRACK_AUDIO2_TX_CTRL              0x00018C8
#define ACP_SW0_AUDIO2_TX_DMA_POS                     0x00018CC
#define ACP_SW0_POS_TRACK_AUDIO0_RX_CTRL              0x00018D0
#define ACP_SW0_AUDIO0_DMA_POS                        0x00018D4
#define ACP_SW0_POS_TRACK_AUDIO1_RX_CTRL              0x00018D8
#define ACP_SW0_AUDIO1_RX_DMA_POS                     0x00018DC
#define ACP_SW0_POS_TRACK_AUDIO2_RX_CTRL              0x00018E0
#define ACP_SW0_AUDIO2_RX_DMA_POS                     0x00018E4
#define ACP_ERROR_INTR_MASK1                          0X0001974
#define ACP_ERROR_INTR_MASK2                          0X0001978
#define ACP_ERROR_INTR_MASK3                          0X000197C

/* Registers from ACP_P1_MISC block */
#define ACP_EXTERNAL_INTR_ENB                         0x0001A00
#define ACP_EXTERNAL_INTR_CNTL                        0x0001A04
#define ACP_EXTERNAL_INTR_CNTL1                       0x0001A08
#define ACP_EXTERNAL_INTR_STAT                        0x0001A0C
#define ACP_EXTERNAL_INTR_STAT1                       0x0001A10
#define ACP_ERROR_STATUS                              0x0001A4C
#define ACP_SW1_I2S_ERROR_REASON                      0x0001A50
#define ACP_SW1_POS_TRACK_AUDIO0_TX_CTRL              0x0001A6C
#define ACP_SW1_AUDIO0_TX_DMA_POS                     0x0001A70
#define ACP_SW1_POS_TRACK_AUDIO0_RX_CTRL              0x0001A74
#define ACP_SW1_AUDIO0_RX_DMA_POS                     0x0001A78
#define ACP_P1_DMIC_I2S_GPIO_INTR_CTRL                0x0001A7C
#define ACP_P1_DMIC_I2S_GPIO_INTR_STATUS              0x0001A80
#define ACP_SCRATCH_REG_BASE_ADDR                     0x0001A84
#define ACP_SW1_POS_TRACK_AUDIO1_TX_CTRL              0x0001A88
#define ACP_SW1_AUDIO1_TX_DMA_POS                     0x0001A8C
#define ACP_SW1_POS_TRACK_AUDIO2_TX_CTRL              0x0001A90
#define ACP_SW1_AUDIO2_TX_DMA_POS                     0x0001A94
#define ACP_SW1_POS_TRACK_AUDIO1_RX_CTRL              0x0001A98
#define ACP_SW1_AUDIO1_RX_DMA_POS                     0x0001A9C
#define ACP_SW1_POS_TRACK_AUDIO2_RX_CTRL              0x0001AA0
#define ACP_SW1_AUDIO2_RX_DMA_POS                     0x0001AA4
#define ACP_ERROR_INTR_MASK4                          0X0001AEC
#define ACP_ERROR_INTR_MASK5                          0X0001AF0

/* Registers from ACP_AUDIO_BUFFERS block */
#define ACP_AUDIO0_RX_RINGBUFADDR                        0x0002000
#define ACP_AUDIO0_RX_RINGBUFSIZE                        0x0002004
#define ACP_AUDIO0_RX_LINKPOSITIONCNTR                   0x0002008
#define ACP_AUDIO0_RX_FIFOADDR                           0x000200C
#define ACP_AUDIO0_RX_FIFOSIZE                           0x0002010
#define ACP_AUDIO0_RX_DMA_SIZE                           0x0002014
#define ACP_AUDIO0_RX_LINEARPOSITIONCNTR_HIGH            0x0002018
#define ACP_AUDIO0_RX_LINEARPOSITIONCNTR_LOW             0x000201C
#define ACP_AUDIO0_RX_INTR_WATERMARK_SIZE                0x0002020
#define ACP_AUDIO0_TX_RINGBUFADDR                        0x0002024
#define ACP_AUDIO0_TX_RINGBUFSIZE                        0x0002028
#define ACP_AUDIO0_TX_LINKPOSITIONCNTR                   0x000202C
#define ACP_AUDIO0_TX_FIFOADDR                           0x0002030
#define ACP_AUDIO0_TX_FIFOSIZE                           0x0002034
#define ACP_AUDIO0_TX_DMA_SIZE                           0x0002038
#define ACP_AUDIO0_TX_LINEARPOSITIONCNTR_HIGH            0x000203C
#define ACP_AUDIO0_TX_LINEARPOSITIONCNTR_LOW             0x0002040
#define ACP_AUDIO0_TX_INTR_WATERMARK_SIZE                0x0002044
#define ACP_AUDIO1_RX_RINGBUFADDR                        0x0002048
#define ACP_AUDIO1_RX_RINGBUFSIZE                        0x000204C
#define ACP_AUDIO1_RX_LINKPOSITIONCNTR                   0x0002050
#define ACP_AUDIO1_RX_FIFOADDR                           0x0002054
#define ACP_AUDIO1_RX_FIFOSIZE                           0x0002058
#define ACP_AUDIO1_RX_DMA_SIZE                           0x000205C
#define ACP_AUDIO1_RX_LINEARPOSITIONCNTR_HIGH            0x0002060
#define ACP_AUDIO1_RX_LINEARPOSITIONCNTR_LOW             0x0002064
#define ACP_AUDIO1_RX_INTR_WATERMARK_SIZE                0x0002068
#define ACP_AUDIO1_TX_RINGBUFADDR                        0x000206C
#define ACP_AUDIO1_TX_RINGBUFSIZE                        0x0002070
#define ACP_AUDIO1_TX_LINKPOSITIONCNTR                   0x0002074
#define ACP_AUDIO1_TX_FIFOADDR                           0x0002078
#define ACP_AUDIO1_TX_FIFOSIZE                           0x000207C
#define ACP_AUDIO1_TX_DMA_SIZE                           0x0002080
#define ACP_AUDIO1_TX_LINEARPOSITIONCNTR_HIGH            0x0002084
#define ACP_AUDIO1_TX_LINEARPOSITIONCNTR_LOW             0x0002088
#define ACP_AUDIO1_TX_INTR_WATERMARK_SIZE                0x000208C
#define ACP_AUDIO2_RX_RINGBUFADDR                        0x0002090
#define ACP_AUDIO2_RX_RINGBUFSIZE                        0x0002094
#define ACP_AUDIO2_RX_LINKPOSITIONCNTR                   0x0002098
#define ACP_AUDIO2_RX_FIFOADDR                           0x000209C
#define ACP_AUDIO2_RX_FIFOSIZE                           0x00020A0
#define ACP_AUDIO2_RX_DMA_SIZE                           0x00020A4
#define ACP_AUDIO2_RX_LINEARPOSITIONCNTR_HIGH            0x00020A8
#define ACP_AUDIO2_RX_LINEARPOSITIONCNTR_LOW             0x00020AC
#define ACP_AUDIO2_RX_INTR_WATERMARK_SIZE                0x00020B0
#define ACP_AUDIO2_TX_RINGBUFADDR                        0x00020B4
#define ACP_AUDIO2_TX_RINGBUFSIZE                        0x00020B8
#define ACP_AUDIO2_TX_LINKPOSITIONCNTR                   0x00020BC
#define ACP_AUDIO2_TX_FIFOADDR                           0x00020C0
#define ACP_AUDIO2_TX_FIFOSIZE                           0x00020C4
#define ACP_AUDIO2_TX_DMA_SIZE                           0x00020C8
#define ACP_AUDIO2_TX_LINEARPOSITIONCNTR_HIGH            0x00020CC
#define ACP_AUDIO2_TX_LINEARPOSITIONCNTR_LOW             0x00020D0
#define ACP_AUDIO2_TX_INTR_WATERMARK_SIZE                0x00020D4

/* Registers from ACP_I2S_TDM block */
#define ACP_I2STDM_IER                                0x0002400
#define ACP_I2STDM_IRER                               0x0002404
#define ACP_I2STDM_RXFRMT                             0x0002408
#define ACP_I2STDM_ITER                               0x000240C
#define ACP_I2STDM_TXFRMT                             0x0002410
#define ACP_I2STDM0_MSTRCLKGEN                        0x0002414
#define ACP_I2STDM1_MSTRCLKGEN                        0x0002418
#define ACP_I2STDM2_MSTRCLKGEN                        0x000241C
#define ACP_I2STDM_REFCLKGEN                          0x0002420

/* Registers from ACP_BT_TDM block */
#define ACP_BTTDM_IER                                 0x0002800
#define ACP_BTTDM_IRER                                0x0002804
#define ACP_BTTDM_RXFRMT                              0x0002808
#define ACP_BTTDM_ITER                                0x000280C
#define ACP_BTTDM_TXFRMT                              0x0002810
#define ACP_HSTDM_IER                                 0x0002814
#define ACP_HSTDM_IRER                                0x0002818
#define ACP_HSTDM_RXFRMT                              0x000281C
#define ACP_HSTDM_ITER                                0x0002820
#define ACP_HSTDM_TXFRMT                              0x0002824

/* Registers from ACP_WOV block */
#define ACP_WOV_PDM_ENABLE                            0x0002C04
#define ACP_WOV_PDM_DMA_ENABLE                        0x0002C08
#define ACP_WOV_RX_RINGBUFADDR                        0x0002C0C
#define ACP_WOV_RX_RINGBUFSIZE                        0x0002C10
#define ACP_WOV_RX_LINKPOSITIONCNTR                   0x0002C14
#define ACP_WOV_RX_LINEARPOSITIONCNTR_HIGH            0x0002C18
#define ACP_WOV_RX_LINEARPOSITIONCNTR_LOW             0x0002C1C
#define ACP_WOV_RX_INTR_WATERMARK_SIZE                0x0002C20
#define ACP_WOV_PDM_FIFO_FLUSH                        0x0002C24
#define ACP_WOV_PDM_NO_OF_CHANNELS                    0x0002C28
#define ACP_WOV_PDM_DECIMATION_FACTOR                 0x0002C2C
#define ACP_WOV_PDM_VAD_CTRL                          0x0002C30
#define ACP_WOV_WAKE                                  0x0002C54
#define ACP_WOV_BUFFER_STATUS                         0x0002C58
#define ACP_WOV_MISC_CTRL                             0x0002C5C
#define ACP_WOV_CLK_CTRL                              0x0002C60
#define ACP_PDM_VAD_DYNAMIC_CLK_GATING_EN             0x0002C64
#define ACP_WOV_ERROR_STATUS_REGISTER                 0x0002C68
#define ACP_PDM_CLKDIV                                0x0002C6C

/* Registers from ACP_SW0_SWCLK block */
#define ACP_SW0_EN                                     0x0003000
#define ACP_SW0_EN_STATUS                              0x0003004
#define ACP_SW0_FRAMESIZE                              0x0003008
#define ACP_SW0_SSP_COUNTER                            0x000300C
#define ACP_SW0_AUDIO0_TX_EN                           0x0003010
#define ACP_SW0_AUDIO0_TX_EN_STATUS                    0x0003014
#define ACP_SW0_AUDIO0_TX_FRAME_FORMAT                 0x0003018
#define ACP_SW0_AUDIO0_TX_SAMPLEINTERVAL               0x000301C
#define ACP_SW0_AUDIO0_TX_HCTRL_DP0                    0x0003020
#define ACP_SW0_AUDIO0_TX_HCTRL_DP1                    0x0003024
#define ACP_SW0_AUDIO0_TX_HCTRL_DP2                    0x0003028
#define ACP_SW0_AUDIO0_TX_HCTRL_DP3                    0x000302C
#define ACP_SW0_AUDIO0_TX_OFFSET_DP0                   0x0003030
#define ACP_SW0_AUDIO0_TX_OFFSET_DP1                   0x0003034
#define ACP_SW0_AUDIO0_TX_OFFSET_DP2                   0x0003038
#define ACP_SW0_AUDIO0_TX_OFFSET_DP3                   0x000303C
#define ACP_SW0_AUDIO0_TX_CHANNEL_ENABLE_DP0           0x0003040
#define ACP_SW0_AUDIO0_TX_CHANNEL_ENABLE_DP1           0x0003044
#define ACP_SW0_AUDIO0_TX_CHANNEL_ENABLE_DP2           0x0003048
#define ACP_SW0_AUDIO0_TX_CHANNEL_ENABLE_DP3           0x000304C
#define ACP_SW0_AUDIO1_TX_EN                           0x0003050
#define ACP_SW0_AUDIO1_TX_EN_STATUS                    0x0003054
#define ACP_SW0_AUDIO1_TX_FRAME_FORMAT                 0x0003058
#define ACP_SW0_AUDIO1_TX_SAMPLEINTERVAL               0x000305C
#define ACP_SW0_AUDIO1_TX_HCTRL                        0x0003060
#define ACP_SW0_AUDIO1_TX_OFFSET                       0x0003064
#define ACP_SW0_AUDIO1_TX_CHANNEL_ENABLE_DP0           0x0003068
#define ACP_SW0_AUDIO2_TX_EN                           0x000306C
#define ACP_SW0_AUDIO2_TX_EN_STATUS                    0x0003070
#define ACP_SW0_AUDIO2_TX_FRAME_FORMAT                 0x0003074
#define ACP_SW0_AUDIO2_TX_SAMPLEINTERVAL               0x0003078
#define ACP_SW0_AUDIO2_TX_HCTRL                        0x000307C
#define ACP_SW0_AUDIO2_TX_OFFSET                       0x0003080
#define ACP_SW0_AUDIO2_TX_CHANNEL_ENABLE_DP0           0x0003084
#define ACP_SW0_AUDIO0_RX_EN                           0x0003088
#define ACP_SW0_AUDIO0_RX_EN_STATUS                    0x000308C
#define ACP_SW0_AUDIO0_RX_FRAME_FORMAT                 0x0003090
#define ACP_SW0_AUDIO0_RX_SAMPLEINTERVAL               0x0003094
#define ACP_SW0_AUDIO0_RX_HCTRL_DP0                    0x0003098
#define ACP_SW0_AUDIO0_RX_HCTRL_DP1                    0x000309C
#define ACP_SW0_AUDIO0_RX_HCTRL_DP2                    0x0003100
#define ACP_SW0_AUDIO0_RX_HCTRL_DP3                    0x0003104
#define ACP_SW0_AUDIO0_RX_OFFSET_DP0                   0x0003108
#define ACP_SW0_AUDIO0_RX_OFFSET_DP1                   0x000310C
#define ACP_SW0_AUDIO0_RX_OFFSET_DP2                   0x0003110
#define ACP_SW0_AUDIO0_RX_OFFSET_DP3                   0x0003114
#define ACP_SW0_AUDIO0_RX_CHANNEL_ENABLE_DP0           0x0003118
#define ACP_SW0_AUDIO0_RX_CHANNEL_ENABLE_DP1           0x000311C
#define ACP_SW0_AUDIO0_RX_CHANNEL_ENABLE_DP2           0x0003120
#define ACP_SW0_AUDIO0_RX_CHANNEL_ENABLE_DP3           0x0003124
#define ACP_SW0_AUDIO1_RX_EN                           0x0003128
#define ACP_SW0_AUDIO1_RX_EN_STATUS                    0x000312C
#define ACP_SW0_AUDIO1_RX_FRAME_FORMAT                 0x0003130
#define ACP_SW0_AUDIO1_RX_SAMPLEINTERVAL               0x0003134
#define ACP_SW0_AUDIO1_RX_HCTRL                        0x0003138
#define ACP_SW0_AUDIO1_RX_OFFSET                       0x000313C
#define ACP_SW0_AUDIO1_RX_CHANNEL_ENABLE_DP0           0x0003140
#define ACP_SW0_AUDIO2_RX_EN                           0x0003144
#define ACP_SW0_AUDIO2_RX_EN_STATUS                    0x0003148
#define ACP_SW0_AUDIO2_RX_FRAME_FORMAT                 0x000314C
#define ACP_SW0_AUDIO2_RX_SAMPLEINTERVAL               0x0003150
#define ACP_SW0_AUDIO2_RX_HCTRL                        0x0003154
#define ACP_SW0_AUDIO2_RX_OFFSET                       0x0003158
#define ACP_SW0_AUDIO2_RX_CHANNEL_ENABLE_DP0           0x000315C
#define ACP_SW0_BPT_PORT_EN                            0x0003160
#define ACP_SW0_BPT_PORT_EN_STATUS                     0x0003164
#define ACP_SW0_BPT_PORT_FRAME_FORMAT                  0x0003168
#define ACP_SW0_BPT_PORT_SAMPLEINTERVAL                0x000316C
#define ACP_SW0_BPT_PORT_HCTRL                         0x0003170
#define ACP_SW0_BPT_PORT_OFFSET                        0x0003174
#define ACP_SW0_BPT_PORT_CHANNEL_ENABLE                0x0003178
#define ACP_SW0_BPT_PORT_FIRST_BYTE_ADDR               0x000317C
#define ACP_SW0_CLK_RESUME_CTRL                        0x0003180
#define ACP_SW0_CLK_RESUME_DELAY_CNTR                  0x0003184
#define ACP_SW0_BUS_RESET_CTRL                         0x0003188
#define ACP_SW0_PRBS_ERR_STATUS                        0x000318C
#define ACP_SW0_IMM_CMD_UPPER_WORD                     0x0003230
#define ACP_SW0_IMM_CMD_LOWER_QWORD                    0x0003234
#define ACP_SW0_IMM_RESP_UPPER_WORD                    0x0003238
#define ACP_SW0_IMM_RESP_LOWER_QWORD                   0x000323C
#define ACP_SW0_IMM_CMD_STS                            0x0003240
#define ACP_SW0_BRA_BASE_ADDRESS                       0x0003244
#define ACP_SW0_BRA_TRANSFER_SIZE                      0x0003248
#define ACP_SW0_BRA_DMA_BUSY                           0x000324C
#define ACP_SW0_BRA_RESP                               0x0003250
#define ACP_SW0_BRA_RESP_FRAME_ADDR                    0x0003254
#define ACP_SW0_BRA_CURRENT_TRANSFER_SIZE              0x0003258
#define ACP_SW0_STATECHANGE_STATUS_0TO7                0x000325C
#define ACP_SW0_STATECHANGE_STATUS_8TO11               0x0003260
#define ACP_SW0_STATECHANGE_STATUS_MASK_0TO7           0x0003264
#define ACP_SW0_STATECHANGE_STATUS_MASK_8TO11          0x0003268
#define ACP_SW0_CLK_FREQUENCY_CTRL                     0x000326C
#define ACP_SW0_ERROR_INTR_MASK                        0x0003270
#define ACP_SW0_PHY_TEST_MODE_DATA_OFF                 0x0003274

/* Registers from ACP_P1_AUDIO_BUFFERS block */
#define ACP_P1_AUDIO0_RX_RINGBUFADDR                     0x0003A00
#define ACP_P1_AUDIO0_RX_RINGBUFSIZE                     0x0003A04
#define ACP_P1_AUDIO0_RX_LINKPOSITIONCNTR                0x0003A08
#define ACP_P1_AUDIO0_RX_FIFOADDR                        0x0003A0C
#define ACP_P1_AUDIO0_RX_FIFOSIZE                        0x0003A10
#define ACP_P1_AUDIO0_RX_DMA_SIZE                        0x0003A14
#define ACP_P1_AUDIO0_RX_LINEARPOSITIONCNTR_HIGH         0x0003A18
#define ACP_P1_AUDIO0_RX_LINEARPOSITIONCNTR_LOW          0x0003A1C
#define ACP_P1_AUDIO0_RX_INTR_WATERMARK_SIZE             0x0003A20
#define ACP_P1_AUDIO0_TX_RINGBUFADDR                     0x0003A24
#define ACP_P1_AUDIO0_TX_RINGBUFSIZE                     0x0003A28
#define ACP_P1_AUDIO0_TX_LINKPOSITIONCNTR                0x0003A2C
#define ACP_P1_AUDIO0_TX_FIFOADDR                        0x0003A30
#define ACP_P1_AUDIO0_TX_FIFOSIZE                        0x0003A34
#define ACP_P1_AUDIO0_TX_DMA_SIZE                        0x0003A38
#define ACP_P1_AUDIO0_TX_LINEARPOSITIONCNTR_HIGH         0x0003A3C
#define ACP_P1_AUDIO0_TX_LINEARPOSITIONCNTR_LOW          0x0003A40
#define ACP_P1_AUDIO0_TX_INTR_WATERMARK_SIZE             0x0003A44
#define ACP_P1_AUDIO1_RX_RINGBUFADDR                     0x0003A48
#define ACP_P1_AUDIO1_RX_RINGBUFSIZE                     0x0003A4C
#define ACP_P1_AUDIO1_RX_LINKPOSITIONCNTR                0x0003A50
#define ACP_P1_AUDIO1_RX_FIFOADDR                        0x0003A54
#define ACP_P1_AUDIO1_RX_FIFOSIZE                        0x0003A58
#define ACP_P1_AUDIO1_RX_DMA_SIZE                        0x0003A5C
#define ACP_P1_AUDIO1_RX_LINEARPOSITIONCNTR_HIGH         0x0003A60
#define ACP_P1_AUDIO1_RX_LINEARPOSITIONCNTR_LOW          0x0003A64
#define ACP_P1_AUDIO1_RX_INTR_WATERMARK_SIZE             0x0003A68
#define ACP_P1_AUDIO1_TX_RINGBUFADDR                     0x0003A6C
#define ACP_P1_AUDIO1_TX_RINGBUFSIZE                     0x0003A70
#define ACP_P1_AUDIO1_TX_LINKPOSITIONCNTR                0x0003A74
#define ACP_P1_AUDIO1_TX_FIFOADDR                        0x0003A78
#define ACP_P1_AUDIO1_TX_FIFOSIZE                        0x0003A7C
#define ACP_P1_AUDIO1_TX_DMA_SIZE                        0x0003A80
#define ACP_P1_AUDIO1_TX_LINEARPOSITIONCNTR_HIGH         0x0003A84
#define ACP_P1_AUDIO1_TX_LINEARPOSITIONCNTR_LOW          0x0003A88
#define ACP_P1_AUDIO1_TX_INTR_WATERMARK_SIZE             0x0003A8C
#define ACP_P1_AUDIO2_RX_RINGBUFADDR                     0x0003A90
#define ACP_P1_AUDIO2_RX_RINGBUFSIZE                     0x0003A94
#define ACP_P1_AUDIO2_RX_LINKPOSITIONCNTR                0x0003A98
#define ACP_P1_AUDIO2_RX_FIFOADDR                        0x0003A9C
#define ACP_P1_AUDIO2_RX_FIFOSIZE                        0x0003AA0
#define ACP_P1_AUDIO2_RX_DMA_SIZE                        0x0003AA4
#define ACP_P1_AUDIO2_RX_LINEARPOSITIONCNTR_HIGH         0x0003AA8
#define ACP_P1_AUDIO2_RX_LINEARPOSITIONCNTR_LOW          0x0003AAC
#define ACP_P1_AUDIO2_RX_INTR_WATERMARK_SIZE             0x0003AB0
#define ACP_P1_AUDIO2_TX_RINGBUFADDR                     0x0003AB4
#define ACP_P1_AUDIO2_TX_RINGBUFSIZE                     0x0003AB8
#define ACP_P1_AUDIO2_TX_LINKPOSITIONCNTR                0x0003ABC
#define ACP_P1_AUDIO2_TX_FIFOADDR                        0x0003AC0
#define ACP_P1_AUDIO2_TX_FIFOSIZE                        0x0003AC4
#define ACP_P1_AUDIO2_TX_DMA_SIZE                        0x0003AC8
#define ACP_P1_AUDIO2_TX_LINEARPOSITIONCNTR_HIGH         0x0003ACC
#define ACP_P1_AUDIO2_TX_LINEARPOSITIONCNTR_LOW          0x0003AD0
#define ACP_P1_AUDIO2_TX_INTR_WATERMARK_SIZE             0x0003AD4

/* Registers from ACP_SW1_SWCLK block */
#define ACP_SW1_EN                                       0x0003C00
#define ACP_SW1_EN_STATUS                                0x0003C04
#define ACP_SW1_FRAMESIZE                                0x0003C08
#define ACP_SW1_SSP_COUNTER                              0x0003C0C
#define ACP_SW1_AUDIO1_TX_EN                             0x0003C50
#define ACP_SW1_AUDIO1_TX_EN_STATUS                      0x0003C54
#define ACP_SW1_AUDIO1_TX_FRAME_FORMAT                   0x0003C58
#define ACP_SW1_AUDIO1_TX_SAMPLEINTERVAL                 0x0003C5C
#define ACP_SW1_AUDIO1_TX_HCTRL                          0x0003C60
#define ACP_SW1_AUDIO1_TX_OFFSET                         0x0003C64
#define ACP_SW1_AUDIO1_TX_CHANNEL_ENABLE_DP0             0x0003C68
#define ACP_SW1_AUDIO1_RX_EN                             0x0003D28
#define ACP_SW1_AUDIO1_RX_EN_STATUS                      0x0003D2C
#define ACP_SW1_AUDIO1_RX_FRAME_FORMAT                   0x0003D30
#define ACP_SW1_AUDIO1_RX_SAMPLEINTERVAL                 0x0003D34
#define ACP_SW1_AUDIO1_RX_HCTRL                          0x0003D38
#define ACP_SW1_AUDIO1_RX_OFFSET                         0x0003D3C
#define ACP_SW1_AUDIO1_RX_CHANNEL_ENABLE_DP0             0x0003D40
#define ACP_SW1_BPT_PORT_EN                              0x0003D60
#define ACP_SW1_BPT_PORT_EN_STATUS                       0x0003D64
#define ACP_SW1_BPT_PORT_FRAME_FORMAT                    0x0003D68
#define ACP_SW1_BPT_PORT_SAMPLEINTERVAL                  0x0003D6C
#define ACP_SW1_BPT_PORT_HCTRL                           0x0003D70
#define ACP_SW1_BPT_PORT_OFFSET                          0x0003D74
#define ACP_SW1_BPT_PORT_CHANNEL_ENABLE                  0x0003D78
#define ACP_SW1_BPT_PORT_FIRST_BYTE_ADDR                 0x0003D7C
#define ACP_SW1_CLK_RESUME_CTRL                          0x0003D80
#define ACP_SW1_CLK_RESUME_DELAY_CNTR                    0x0003D84
#define ACP_SW1_BUS_RESET_CTRL                           0x0003D88
#define ACP_SW1_PRBS_ERR_STATUS                          0x0003D8C

/* Registers from ACP_SW1_ACLK block */
#define ACP_SW1_CORB_BASE_ADDRESS                       0x0003E00
#define ACP_SW1_CORB_WRITE_POINTER                      0x0003E04
#define ACP_SW1_CORB_READ_POINTER                       0x0003E08
#define ACP_SW1_CORB_CONTROL                            0x0003E0C
#define ACP_SW1_CORB_SIZE                               0x0003E14
#define ACP_SW1_RIRB_BASE_ADDRESS                       0x0003E18
#define ACP_SW1_RIRB_WRITE_POINTER                      0x0003E1C
#define ACP_SW1_RIRB_RESPONSE_INTERRUPT_COUNT           0x0003E20
#define ACP_SW1_RIRB_CONTROL                            0x0003E24
#define ACP_SW1_RIRB_SIZE                               0x0003E28
#define ACP_SW1_RIRB_FIFO_MIN_THDL                      0x0003E2C
#define ACP_SW1_IMM_CMD_UPPER_WORD                      0x0003E30
#define ACP_SW1_IMM_CMD_LOWER_QWORD                     0x0003E34
#define ACP_SW1_IMM_RESP_UPPER_WORD                     0x0003E38
#define ACP_SW1_IMM_RESP_LOWER_QWORD                    0x0003E3C
#define ACP_SW1_IMM_CMD_STS                             0x0003E40
#define ACP_SW1_BRA_BASE_ADDRESS                        0x0003E44
#define ACP_SW1_BRA_TRANSFER_SIZE                       0x0003E48
#define ACP_SW1_BRA_DMA_BUSY                            0x0003E4C
#define ACP_SW1_BRA_RESP                                0x0003E50
#define ACP_SW1_BRA_RESP_FRAME_ADDR                     0x0003E54
#define ACP_SW1_BRA_CURRENT_TRANSFER_SIZE               0x0003E58
#define ACP_SW1_STATECHANGE_STATUS_0TO7                 0x0003E5C
#define ACP_SW1_STATECHANGE_STATUS_8TO11                0x0003E60
#define ACP_SW1_STATECHANGE_STATUS_MASK_0TO7            0x0003E64
#define ACP_SW1_STATECHANGE_STATUS_MASK_8TO11           0x0003E68
#define ACP_SW1_CLK_FREQUENCY_CTRL                      0x0003E6C
#define ACP_SW1_ERROR_INTR_MASK                         0x0003E70
#define ACP_SW1_PHY_TEST_MODE_DATA_OFF                  0x0003E74

/* Registers from ACP_SCRATCH block */
#define ACP_SCRATCH_REG_0                               0x0010000

#endif
