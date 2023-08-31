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

#ifndef ASIC_REG_DCORE0_DEC0_CMD_MASKS_H_
#define ASIC_REG_DCORE0_DEC0_CMD_MASKS_H_

/*
 *****************************************
 *   DCORE0_DEC0_CMD
 *   (Prototype: VSI_CMD)
 *****************************************
 */

/* DCORE0_DEC0_CMD_SWREG0 */
#define DCORE0_DEC0_CMD_SWREG0_SW_HW_VERSION_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG0_SW_HW_VERSION_MASK 0xFFFF
#define DCORE0_DEC0_CMD_SWREG0_SW_HW_ID_SHIFT 16
#define DCORE0_DEC0_CMD_SWREG0_SW_HW_ID_MASK 0xFFFF0000

/* DCORE0_DEC0_CMD_SWREG1 */
#define DCORE0_DEC0_CMD_SWREG1_SW_HW_BUILDDATE_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG1_SW_HW_BUILDDATE_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG2 */
#define DCORE0_DEC0_CMD_SWREG2_SW_EXT_NORM_INTR_SRC_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG2_SW_EXT_NORM_INTR_SRC_MASK 0xFFFF
#define DCORE0_DEC0_CMD_SWREG2_SW_EXT_ABN_INTR_SRC_SHIFT 16
#define DCORE0_DEC0_CMD_SWREG2_SW_EXT_ABN_INTR_SRC_MASK 0xFFFF0000

/* DCORE0_DEC0_CMD_SWREG3 */
#define DCORE0_DEC0_CMD_SWREG3_SW_EXE_CMDBUF_COUNT_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG3_SW_EXE_CMDBUF_COUNT_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG4 */
#define DCORE0_DEC0_CMD_SWREG4_SW_CMD_EXE_LSB_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG4_SW_CMD_EXE_LSB_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG5 */
#define DCORE0_DEC0_CMD_SWREG5_SW_CMD_EXE_MSB_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG5_SW_CMD_EXE_MSB_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG6 */
#define DCORE0_DEC0_CMD_SWREG6_SW_AXI_TOTALARLEN_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG6_SW_AXI_TOTALARLEN_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG7 */
#define DCORE0_DEC0_CMD_SWREG7_SW_AXI_TOTALR_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG7_SW_AXI_TOTALR_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG8 */
#define DCORE0_DEC0_CMD_SWREG8_SW_AXI_TOTALAR_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG8_SW_AXI_TOTALAR_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG9 */
#define DCORE0_DEC0_CMD_SWREG9_SW_AXI_TOTALRLAST_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG9_SW_AXI_TOTALRLAST_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG10 */
#define DCORE0_DEC0_CMD_SWREG10_SW_AXI_TOTALAWLEN_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG10_SW_AXI_TOTALAWLEN_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG11 */
#define DCORE0_DEC0_CMD_SWREG11_SW_AXI_TOTALW_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG11_SW_AXI_TOTALW_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG12 */
#define DCORE0_DEC0_CMD_SWREG12_SW_AXI_TOTALAW_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG12_SW_AXI_TOTALAW_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG13 */
#define DCORE0_DEC0_CMD_SWREG13_SW_AXI_TOTALWLAST_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG13_SW_AXI_TOTALWLAST_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG14 */
#define DCORE0_DEC0_CMD_SWREG14_SW_AXI_TOTALB_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG14_SW_AXI_TOTALB_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG15 */
#define DCORE0_DEC0_CMD_SWREG15_SW_WORK_STATE_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG15_SW_WORK_STATE_MASK 0x7
#define DCORE0_DEC0_CMD_SWREG15_RSV_SHIFT 3
#define DCORE0_DEC0_CMD_SWREG15_RSV_MASK 0x3FFFF8
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_BREADY_SHIFT 22
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_BREADY_MASK 0x400000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_BVALID_SHIFT 23
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_BVALID_MASK 0x800000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_WREADY_SHIFT 24
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_WREADY_MASK 0x1000000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_WVALID_SHIFT 25
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_WVALID_MASK 0x2000000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_AWREADY_SHIFT 26
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_AWREADY_MASK 0x4000000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_AWVALID_SHIFT 27
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_AWVALID_MASK 0x8000000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_RREADY_SHIFT 28
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_RREADY_MASK 0x10000000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_RVALID_SHIFT 29
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_RVALID_MASK 0x20000000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_ARREADY_SHIFT 30
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_ARREADY_MASK 0x40000000
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_ARVALID_SHIFT 31
#define DCORE0_DEC0_CMD_SWREG15_SW_AXI_ARVALID_MASK 0x80000000

/* DCORE0_DEC0_CMD_SWREG16 */
#define DCORE0_DEC0_CMD_SWREG16_SW_START_TRIGGER_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG16_SW_START_TRIGGER_MASK 0x1
#define DCORE0_DEC0_CMD_SWREG16_SW_RESET_ALL_SHIFT 1
#define DCORE0_DEC0_CMD_SWREG16_SW_RESET_ALL_MASK 0x2
#define DCORE0_DEC0_CMD_SWREG16_SW_RESET_CORE_SHIFT 2
#define DCORE0_DEC0_CMD_SWREG16_SW_RESET_CORE_MASK 0x4
#define DCORE0_DEC0_CMD_SWREG16_SW_ABORT_MODE_SHIFT 3
#define DCORE0_DEC0_CMD_SWREG16_SW_ABORT_MODE_MASK 0x8
#define DCORE0_DEC0_CMD_SWREG16_SW_CORE_CLK_GATE_DISABLE_SHIFT 4
#define DCORE0_DEC0_CMD_SWREG16_SW_CORE_CLK_GATE_DISABLE_MASK 0x10
#define DCORE0_DEC0_CMD_SWREG16_SW_MASTER_OUT_CLK_GATE_DISABLE_SHIFT 5
#define DCORE0_DEC0_CMD_SWREG16_SW_MASTER_OUT_CLK_GATE_DISABLE_MASK 0x20
#define DCORE0_DEC0_CMD_SWREG16_SW_AXI_CLK_GATE_DISABLE_SHIFT 6
#define DCORE0_DEC0_CMD_SWREG16_SW_AXI_CLK_GATE_DISABLE_MASK 0x40
#define DCORE0_DEC0_CMD_SWREG16_RSV_SHIFT 7
#define DCORE0_DEC0_CMD_SWREG16_RSV_MASK 0xFFFFFF80

/* DCORE0_DEC0_CMD_SWREG17 */
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_ENDCMD_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_ENDCMD_MASK 0x1
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_BUSERR_SHIFT 1
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_BUSERR_MASK 0x2
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_TIMEOUT_SHIFT 2
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_TIMEOUT_MASK 0x4
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_CMDERR_SHIFT 3
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_CMDERR_MASK 0x8
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_ABORT_SHIFT 4
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_ABORT_MASK 0x10
#define DCORE0_DEC0_CMD_SWREG17_RSV_1_SHIFT 5
#define DCORE0_DEC0_CMD_SWREG17_RSV_1_MASK 0x20
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_JMP_SHIFT 6
#define DCORE0_DEC0_CMD_SWREG17_SW_IRQ_JMP_MASK 0x40
#define DCORE0_DEC0_CMD_SWREG17_RSV_SHIFT 7
#define DCORE0_DEC0_CMD_SWREG17_RSV_MASK 0xFFFFFF80

/* DCORE0_DEC0_CMD_SWREG18 */
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_ENDCMD_EN_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_ENDCMD_EN_MASK 0x1
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_BUSERR_EN_SHIFT 1
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_BUSERR_EN_MASK 0x2
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_TIMEOUT_EN_SHIFT 2
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_TIMEOUT_EN_MASK 0x4
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_CMDERR_EN_SHIFT 3
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_CMDERR_EN_MASK 0x8
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_ABORT_EN_SHIFT 4
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_ABORT_EN_MASK 0x10
#define DCORE0_DEC0_CMD_SWREG18_RSV_1_SHIFT 5
#define DCORE0_DEC0_CMD_SWREG18_RSV_1_MASK 0x20
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_JMP_EN_SHIFT 6
#define DCORE0_DEC0_CMD_SWREG18_SW_IRQ_JMP_EN_MASK 0x40
#define DCORE0_DEC0_CMD_SWREG18_RSV_SHIFT 7
#define DCORE0_DEC0_CMD_SWREG18_RSV_MASK 0xFFFFFF80

/* DCORE0_DEC0_CMD_SWREG19 */
#define DCORE0_DEC0_CMD_SWREG19_SW_TIMEOUT_CYCLES_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG19_SW_TIMEOUT_CYCLES_MASK 0x7FFFFFFF
#define DCORE0_DEC0_CMD_SWREG19_SW_TIMEOUT_ENABLE_SHIFT 31
#define DCORE0_DEC0_CMD_SWREG19_SW_TIMEOUT_ENABLE_MASK 0x80000000

/* DCORE0_DEC0_CMD_SWREG20 */
#define DCORE0_DEC0_CMD_SWREG20_SW_CMDBUF_EXE_ADDR_LSB_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG20_SW_CMDBUF_EXE_ADDR_LSB_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG21 */
#define DCORE0_DEC0_CMD_SWREG21_SW_CMDBUF_EXE_ADDR_MSB_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG21_SW_CMDBUF_EXE_ADDR_MSB_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG22 */
#define DCORE0_DEC0_CMD_SWREG22_SW_CMDBUF_EXE_LENGTH_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG22_SW_CMDBUF_EXE_LENGTH_MASK 0xFFFF
#define DCORE0_DEC0_CMD_SWREG22_RSV_SHIFT 16
#define DCORE0_DEC0_CMD_SWREG22_RSV_MASK 0xFFFF0000

/* DCORE0_DEC0_CMD_SWREG23 */
#define DCORE0_DEC0_CMD_SWREG23_SW_AXI_ID_WR_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG23_SW_AXI_ID_WR_MASK 0xFF
#define DCORE0_DEC0_CMD_SWREG23_SW_AXI_ID_RD_SHIFT 8
#define DCORE0_DEC0_CMD_SWREG23_SW_AXI_ID_RD_MASK 0xFF00
#define DCORE0_DEC0_CMD_SWREG23_SW_MAX_BURST_LEN_SHIFT 16
#define DCORE0_DEC0_CMD_SWREG23_SW_MAX_BURST_LEN_MASK 0xFF0000
#define DCORE0_DEC0_CMD_SWREG23_RSV_SHIFT 24
#define DCORE0_DEC0_CMD_SWREG23_RSV_MASK 0xF000000
#define DCORE0_DEC0_CMD_SWREG23_SW_CMD_SWAP_SHIFT 28
#define DCORE0_DEC0_CMD_SWREG23_SW_CMD_SWAP_MASK 0xF0000000

/* DCORE0_DEC0_CMD_SWREG24 */
#define DCORE0_DEC0_CMD_SWREG24_SW_RDY_CMDBUF_COUNT_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG24_SW_RDY_CMDBUF_COUNT_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG25 */
#define DCORE0_DEC0_CMD_SWREG25_SW_EXT_NORM_INTR_GATE_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG25_SW_EXT_NORM_INTR_GATE_MASK 0xFFFF
#define DCORE0_DEC0_CMD_SWREG25_SW_EXT_ABN_INTR_GATE_SHIFT 16
#define DCORE0_DEC0_CMD_SWREG25_SW_EXT_ABN_INTR_GATE_MASK 0xFFFF0000

/* DCORE0_DEC0_CMD_SWREG26 */
#define DCORE0_DEC0_CMD_SWREG26_SW_CMDBUF_EXE_ID_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG26_SW_CMDBUF_EXE_ID_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG64 */
#define DCORE0_DEC0_CMD_SWREG64_SW_DUMMY0_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG64_SW_DUMMY0_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG65 */
#define DCORE0_DEC0_CMD_SWREG65_SW_DUMMY1_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG65_SW_DUMMY1_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG66 */
#define DCORE0_DEC0_CMD_SWREG66_SW_DUMMY2_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG66_SW_DUMMY2_MASK 0xFFFFFFFF

/* DCORE0_DEC0_CMD_SWREG67 */
#define DCORE0_DEC0_CMD_SWREG67_SW_DUMMY3_SHIFT 0
#define DCORE0_DEC0_CMD_SWREG67_SW_DUMMY3_MASK 0xFFFFFFFF

#endif /* ASIC_REG_DCORE0_DEC0_CMD_MASKS_H_ */
