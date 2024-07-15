/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#ifndef __MFD_MT6358_REGISTERS_H__
#define __MFD_MT6358_REGISTERS_H__

/* PMIC Registers */
#define MT6358_SWCID                          0xa
#define MT6358_TOPSTATUS                      0x28
#define MT6358_TOP_RST_MISC                   0x14c
#define MT6358_MISC_TOP_INT_CON0              0x188
#define MT6358_MISC_TOP_INT_STATUS0           0x194
#define MT6358_TOP_INT_STATUS0                0x19e
#define MT6358_SCK_TOP_INT_CON0               0x52e
#define MT6358_SCK_TOP_INT_STATUS0            0x53a
#define MT6358_EOSC_CALI_CON0                 0x540
#define MT6358_EOSC_CALI_CON1                 0x542
#define MT6358_RTC_MIX_CON0                   0x544
#define MT6358_RTC_MIX_CON1                   0x546
#define MT6358_RTC_MIX_CON2                   0x548
#define MT6358_RTC_DSN_ID                     0x580
#define MT6358_RTC_DSN_REV0                   0x582
#define MT6358_RTC_DBI                        0x584
#define MT6358_RTC_DXI                        0x586
#define MT6358_RTC_BBPU                       0x588
#define MT6358_RTC_IRQ_STA                    0x58a
#define MT6358_RTC_IRQ_EN                     0x58c
#define MT6358_RTC_CII_EN                     0x58e
#define MT6358_RTC_AL_MASK                    0x590
#define MT6358_RTC_TC_SEC                     0x592
#define MT6358_RTC_TC_MIN                     0x594
#define MT6358_RTC_TC_HOU                     0x596
#define MT6358_RTC_TC_DOM                     0x598
#define MT6358_RTC_TC_DOW                     0x59a
#define MT6358_RTC_TC_MTH                     0x59c
#define MT6358_RTC_TC_YEA                     0x59e
#define MT6358_RTC_AL_SEC                     0x5a0
#define MT6358_RTC_AL_MIN                     0x5a2
#define MT6358_RTC_AL_HOU                     0x5a4
#define MT6358_RTC_AL_DOM                     0x5a6
#define MT6358_RTC_AL_DOW                     0x5a8
#define MT6358_RTC_AL_MTH                     0x5aa
#define MT6358_RTC_AL_YEA                     0x5ac
#define MT6358_RTC_OSC32CON                   0x5ae
#define MT6358_RTC_POWERKEY1                  0x5b0
#define MT6358_RTC_POWERKEY2                  0x5b2
#define MT6358_RTC_PDN1                       0x5b4
#define MT6358_RTC_PDN2                       0x5b6
#define MT6358_RTC_SPAR0                      0x5b8
#define MT6358_RTC_SPAR1                      0x5ba
#define MT6358_RTC_PROT                       0x5bc
#define MT6358_RTC_DIFF                       0x5be
#define MT6358_RTC_CALI                       0x5c0
#define MT6358_RTC_WRTGR                      0x5c2
#define MT6358_RTC_CON                        0x5c4
#define MT6358_RTC_SEC_CTRL                   0x5c6
#define MT6358_RTC_INT_CNT                    0x5c8
#define MT6358_RTC_SEC_DAT0                   0x5ca
#define MT6358_RTC_SEC_DAT1                   0x5cc
#define MT6358_RTC_SEC_DAT2                   0x5ce
#define MT6358_RTC_SEC_DSN_ID                 0x600
#define MT6358_RTC_SEC_DSN_REV0               0x602
#define MT6358_RTC_SEC_DBI                    0x604
#define MT6358_RTC_SEC_DXI                    0x606
#define MT6358_RTC_TC_SEC_SEC                 0x608
#define MT6358_RTC_TC_MIN_SEC                 0x60a
#define MT6358_RTC_TC_HOU_SEC                 0x60c
#define MT6358_RTC_TC_DOM_SEC                 0x60e
#define MT6358_RTC_TC_DOW_SEC                 0x610
#define MT6358_RTC_TC_MTH_SEC                 0x612
#define MT6358_RTC_TC_YEA_SEC                 0x614
#define MT6358_RTC_SEC_CK_PDN                 0x616
#define MT6358_RTC_SEC_WRTGR                  0x618
#define MT6358_PSC_TOP_INT_CON0               0x910
#define MT6358_PSC_TOP_INT_STATUS0            0x91c
#define MT6358_BM_TOP_INT_CON0                0xc32
#define MT6358_BM_TOP_INT_CON1                0xc38
#define MT6358_BM_TOP_INT_STATUS0             0xc4a
#define MT6358_BM_TOP_INT_STATUS1             0xc4c
#define MT6358_HK_TOP_INT_CON0                0xf92
#define MT6358_HK_TOP_INT_STATUS0             0xf9e
#define MT6358_BUCK_TOP_INT_CON0              0x1318
#define MT6358_BUCK_TOP_INT_STATUS0           0x1324
#define MT6358_BUCK_VPROC11_CON0              0x1388
#define MT6358_BUCK_VPROC11_DBG0              0x139e
#define MT6358_BUCK_VPROC11_DBG1              0x13a0
#define MT6358_BUCK_VPROC11_ELR0              0x13a6
#define MT6358_BUCK_VPROC12_CON0              0x1408
#define MT6358_BUCK_VPROC12_DBG0              0x141e
#define MT6358_BUCK_VPROC12_DBG1              0x1420
#define MT6358_BUCK_VPROC12_ELR0              0x1426
#define MT6358_BUCK_VCORE_CON0                0x1488
#define MT6358_BUCK_VCORE_DBG0                0x149e
#define MT6358_BUCK_VCORE_DBG1                0x14a0
#define MT6358_BUCK_VCORE_SSHUB_CON0          0x14a4
#define MT6358_BUCK_VCORE_SSHUB_CON1          0x14a6
#define MT6358_BUCK_VCORE_SSHUB_ELR0          MT6358_BUCK_VCORE_SSHUB_CON1
#define MT6358_BUCK_VCORE_SSHUB_DBG1          MT6358_BUCK_VCORE_DBG1
#define MT6358_BUCK_VCORE_ELR0                0x14aa
#define MT6358_BUCK_VGPU_CON0                 0x1508
#define MT6358_BUCK_VGPU_DBG0                 0x151e
#define MT6358_BUCK_VGPU_DBG1                 0x1520
#define MT6358_BUCK_VGPU_ELR0                 0x1526
#define MT6358_BUCK_VMODEM_CON0               0x1588
#define MT6358_BUCK_VMODEM_DBG0               0x159e
#define MT6358_BUCK_VMODEM_DBG1               0x15a0
#define MT6358_BUCK_VMODEM_ELR0               0x15a6
#define MT6358_BUCK_VDRAM1_CON0               0x1608
#define MT6358_BUCK_VDRAM1_DBG0               0x161e
#define MT6358_BUCK_VDRAM1_DBG1               0x1620
#define MT6358_BUCK_VDRAM1_ELR0               0x1626
#define MT6358_BUCK_VS1_CON0                  0x1688
#define MT6358_BUCK_VS1_DBG0                  0x169e
#define MT6358_BUCK_VS1_DBG1                  0x16a0
#define MT6358_BUCK_VS1_ELR0                  0x16ae
#define MT6358_BUCK_VS2_CON0                  0x1708
#define MT6358_BUCK_VS2_DBG0                  0x171e
#define MT6358_BUCK_VS2_DBG1                  0x1720
#define MT6358_BUCK_VS2_ELR0                  0x172e
#define MT6358_BUCK_VPA_CON0                  0x1788
#define MT6358_BUCK_VPA_CON1                  0x178a
#define MT6358_BUCK_VPA_ELR0                  MT6358_BUCK_VPA_CON1
#define MT6358_BUCK_VPA_DBG0                  0x1792
#define MT6358_BUCK_VPA_DBG1                  0x1794
#define MT6358_VPROC_ANA_CON0                 0x180c
#define MT6358_VCORE_VGPU_ANA_CON0            0x1828
#define MT6358_VMODEM_ANA_CON0                0x1888
#define MT6358_VDRAM1_ANA_CON0                0x1896
#define MT6358_VS1_ANA_CON0                   0x18a2
#define MT6358_VS2_ANA_CON0                   0x18ae
#define MT6358_VPA_ANA_CON0                   0x18ba
#define MT6358_LDO_TOP_INT_CON0               0x1a50
#define MT6358_LDO_TOP_INT_CON1               0x1a56
#define MT6358_LDO_TOP_INT_STATUS0            0x1a68
#define MT6358_LDO_TOP_INT_STATUS1            0x1a6a
#define MT6358_LDO_VXO22_CON0                 0x1a88
#define MT6358_LDO_VXO22_CON1                 0x1a96
#define MT6358_LDO_VA12_CON0                  0x1a9c
#define MT6358_LDO_VA12_CON1                  0x1aaa
#define MT6358_LDO_VAUX18_CON0                0x1ab0
#define MT6358_LDO_VAUX18_CON1                0x1abe
#define MT6358_LDO_VAUD28_CON0                0x1ac4
#define MT6358_LDO_VAUD28_CON1                0x1ad2
#define MT6358_LDO_VIO28_CON0                 0x1ad8
#define MT6358_LDO_VIO28_CON1                 0x1ae6
#define MT6358_LDO_VIO18_CON0                 0x1aec
#define MT6358_LDO_VIO18_CON1                 0x1afa
#define MT6358_LDO_VDRAM2_CON0                0x1b08
#define MT6358_LDO_VDRAM2_CON1                0x1b16
#define MT6358_LDO_VEMC_CON0                  0x1b1c
#define MT6358_LDO_VEMC_CON1                  0x1b2a
#define MT6358_LDO_VUSB_CON0_0                0x1b30
#define MT6358_LDO_VUSB_CON1                  0x1b40
#define MT6358_LDO_VSRAM_PROC11_CON0          0x1b46
#define MT6358_LDO_VSRAM_PROC11_DBG0          0x1b60
#define MT6358_LDO_VSRAM_PROC11_DBG1          0x1b62
#define MT6358_LDO_VSRAM_PROC11_TRACKING_CON0 0x1b64
#define MT6358_LDO_VSRAM_PROC11_TRACKING_CON1 0x1b66
#define MT6358_LDO_VSRAM_PROC11_TRACKING_CON2 0x1b68
#define MT6358_LDO_VSRAM_PROC11_TRACKING_CON3 0x1b6a
#define MT6358_LDO_VSRAM_PROC12_TRACKING_CON0 0x1b6c
#define MT6358_LDO_VSRAM_PROC12_TRACKING_CON1 0x1b6e
#define MT6358_LDO_VSRAM_PROC12_TRACKING_CON2 0x1b70
#define MT6358_LDO_VSRAM_PROC12_TRACKING_CON3 0x1b72
#define MT6358_LDO_VSRAM_WAKEUP_CON0          0x1b74
#define MT6358_LDO_GON1_ELR_NUM               0x1b76
#define MT6358_LDO_VDRAM2_ELR0                0x1b78
#define MT6358_LDO_VSRAM_PROC12_CON0          0x1b88
#define MT6358_LDO_VSRAM_PROC12_DBG0          0x1ba2
#define MT6358_LDO_VSRAM_PROC12_DBG1          0x1ba4
#define MT6358_LDO_VSRAM_OTHERS_CON0          0x1ba6
#define MT6358_LDO_VSRAM_OTHERS_DBG0          0x1bc0
#define MT6358_LDO_VSRAM_OTHERS_DBG1          0x1bc2
#define MT6358_LDO_VSRAM_OTHERS_SSHUB_CON0    0x1bc4
#define MT6358_LDO_VSRAM_OTHERS_SSHUB_CON1    0x1bc6
#define MT6358_LDO_VSRAM_OTHERS_SSHUB_DBG1    MT6358_LDO_VSRAM_OTHERS_DBG1
#define MT6358_LDO_VSRAM_GPU_CON0             0x1bc8
#define MT6358_LDO_VSRAM_GPU_DBG0             0x1be2
#define MT6358_LDO_VSRAM_GPU_DBG1             0x1be4
#define MT6358_LDO_VSRAM_CON0                 0x1bee
#define MT6358_LDO_VSRAM_CON1                 0x1bf0
#define MT6358_LDO_VSRAM_CON2                 0x1bf2
#define MT6358_LDO_VSRAM_CON3                 0x1bf4
#define MT6358_LDO_VFE28_CON0                 0x1c08
#define MT6358_LDO_VFE28_CON1                 0x1c16
#define MT6358_LDO_VFE28_CON2                 0x1c18
#define MT6358_LDO_VFE28_CON3                 0x1c1a
#define MT6358_LDO_VRF18_CON0                 0x1c1c
#define MT6358_LDO_VRF18_CON1                 0x1c2a
#define MT6358_LDO_VRF18_CON2                 0x1c2c
#define MT6358_LDO_VRF18_CON3                 0x1c2e
#define MT6358_LDO_VRF12_CON0                 0x1c30
#define MT6358_LDO_VRF12_CON1                 0x1c3e
#define MT6358_LDO_VRF12_CON2                 0x1c40
#define MT6358_LDO_VRF12_CON3                 0x1c42
#define MT6358_LDO_VEFUSE_CON0                0x1c44
#define MT6358_LDO_VEFUSE_CON1                0x1c52
#define MT6358_LDO_VEFUSE_CON2                0x1c54
#define MT6358_LDO_VEFUSE_CON3                0x1c56
#define MT6358_LDO_VCN18_CON0                 0x1c58
#define MT6358_LDO_VCN18_CON1                 0x1c66
#define MT6358_LDO_VCN18_CON2                 0x1c68
#define MT6358_LDO_VCN18_CON3                 0x1c6a
#define MT6358_LDO_VCAMA1_CON0                0x1c6c
#define MT6358_LDO_VCAMA1_CON1                0x1c7a
#define MT6358_LDO_VCAMA1_CON2                0x1c7c
#define MT6358_LDO_VCAMA1_CON3                0x1c7e
#define MT6358_LDO_VCAMA2_CON0                0x1c88
#define MT6358_LDO_VCAMA2_CON1                0x1c96
#define MT6358_LDO_VCAMA2_CON2                0x1c98
#define MT6358_LDO_VCAMA2_CON3                0x1c9a
#define MT6358_LDO_VCAMD_CON0                 0x1c9c
#define MT6358_LDO_VCAMD_CON1                 0x1caa
#define MT6358_LDO_VCAMD_CON2                 0x1cac
#define MT6358_LDO_VCAMD_CON3                 0x1cae
#define MT6358_LDO_VCAMIO_CON0                0x1cb0
#define MT6358_LDO_VCAMIO_CON1                0x1cbe
#define MT6358_LDO_VCAMIO_CON2                0x1cc0
#define MT6358_LDO_VCAMIO_CON3                0x1cc2
#define MT6358_LDO_VMC_CON0                   0x1cc4
#define MT6358_LDO_VMC_CON1                   0x1cd2
#define MT6358_LDO_VMC_CON2                   0x1cd4
#define MT6358_LDO_VMC_CON3                   0x1cd6
#define MT6358_LDO_VMCH_CON0                  0x1cd8
#define MT6358_LDO_VMCH_CON1                  0x1ce6
#define MT6358_LDO_VMCH_CON2                  0x1ce8
#define MT6358_LDO_VMCH_CON3                  0x1cea
#define MT6358_LDO_VIBR_CON0                  0x1d08
#define MT6358_LDO_VIBR_CON1                  0x1d16
#define MT6358_LDO_VIBR_CON2                  0x1d18
#define MT6358_LDO_VIBR_CON3                  0x1d1a
#define MT6358_LDO_VCN33_CON0_0               0x1d1c
#define MT6358_LDO_VCN33_CON0_1               0x1d2a
#define MT6358_LDO_VCN33_CON1                 0x1d2c
#define MT6358_LDO_VCN33_BT_CON1              MT6358_LDO_VCN33_CON1
#define MT6358_LDO_VCN33_WIFI_CON1            MT6358_LDO_VCN33_CON1
#define MT6358_LDO_VCN33_CON2                 0x1d2e
#define MT6358_LDO_VCN33_CON3                 0x1d30
#define MT6358_LDO_VLDO28_CON0_0              0x1d32
#define MT6358_LDO_VLDO28_CON0_1              0x1d40
#define MT6358_LDO_VLDO28_CON1                0x1d42
#define MT6358_LDO_VLDO28_CON2                0x1d44
#define MT6358_LDO_VLDO28_CON3                0x1d46
#define MT6358_LDO_VSIM1_CON0                 0x1d48
#define MT6358_LDO_VSIM1_CON1                 0x1d56
#define MT6358_LDO_VSIM1_CON2                 0x1d58
#define MT6358_LDO_VSIM1_CON3                 0x1d5a
#define MT6358_LDO_VSIM2_CON0                 0x1d5c
#define MT6358_LDO_VSIM2_CON1                 0x1d6a
#define MT6358_LDO_VSIM2_CON2                 0x1d6c
#define MT6358_LDO_VSIM2_CON3                 0x1d6e
#define MT6358_LDO_VCN28_CON0                 0x1d88
#define MT6358_LDO_VCN28_CON1                 0x1d96
#define MT6358_LDO_VCN28_CON2                 0x1d98
#define MT6358_LDO_VCN28_CON3                 0x1d9a
#define MT6358_VRTC28_CON0                    0x1d9c
#define MT6358_LDO_VBIF28_CON0                0x1d9e
#define MT6358_LDO_VBIF28_CON1                0x1dac
#define MT6358_LDO_VBIF28_CON2                0x1dae
#define MT6358_LDO_VBIF28_CON3                0x1db0
#define MT6358_VCAMA1_ANA_CON0                0x1e08
#define MT6358_VCAMA2_ANA_CON0                0x1e0c
#define MT6358_VCN33_ANA_CON0                 0x1e28
#define MT6358_VSIM1_ANA_CON0                 0x1e2c
#define MT6358_VSIM2_ANA_CON0                 0x1e30
#define MT6358_VUSB_ANA_CON0                  0x1e34
#define MT6358_VEMC_ANA_CON0                  0x1e38
#define MT6358_VLDO28_ANA_CON0                0x1e3c
#define MT6358_VIO28_ANA_CON0                 0x1e40
#define MT6358_VIBR_ANA_CON0                  0x1e44
#define MT6358_VMCH_ANA_CON0                  0x1e48
#define MT6358_VMC_ANA_CON0                   0x1e4c
#define MT6358_VRF18_ANA_CON0                 0x1e88
#define MT6358_VCN18_ANA_CON0                 0x1e8c
#define MT6358_VCAMIO_ANA_CON0                0x1e90
#define MT6358_VIO18_ANA_CON0                 0x1e94
#define MT6358_VEFUSE_ANA_CON0                0x1e98
#define MT6358_VRF12_ANA_CON0                 0x1e9c
#define MT6358_VSRAM_PROC11_ANA_CON0          0x1ea0
#define MT6358_VSRAM_PROC12_ANA_CON0          0x1ea4
#define MT6358_VSRAM_OTHERS_ANA_CON0          0x1ea6
#define MT6358_VSRAM_GPU_ANA_CON0             0x1ea8
#define MT6358_VDRAM2_ANA_CON0                0x1eaa
#define MT6358_VCAMD_ANA_CON0                 0x1eae
#define MT6358_VA12_ANA_CON0                  0x1eb2
#define MT6358_AUD_TOP_INT_CON0               0x2228
#define MT6358_AUD_TOP_INT_STATUS0            0x2234

#endif /* __MFD_MT6358_REGISTERS_H__ */
