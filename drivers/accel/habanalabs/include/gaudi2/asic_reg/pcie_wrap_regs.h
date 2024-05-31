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

#ifndef ASIC_REG_PCIE_WRAP_REGS_H_
#define ASIC_REG_PCIE_WRAP_REGS_H_

/*
 *****************************************
 *   PCIE_WRAP
 *   (Prototype: PCIE_WRAP)
 *****************************************
 */

#define mmPCIE_WRAP_INTR_GEN_MASK_MIN_ADDR_0 0x4C01000

#define mmPCIE_WRAP_INTR_GEN_MASK_MIN_ADDR_1 0x4C01004

#define mmPCIE_WRAP_INTR_GEN_MASK_MAX_ADDR_0 0x4C01008

#define mmPCIE_WRAP_INTR_GEN_MASK_MAX_ADDR_1 0x4C0100C

#define mmPCIE_WRAP_INTR_GEN_MASK_TIMER 0x4C01010

#define mmPCIE_WRAP_INTR_GEN_MASK_CTRL 0x4C01014

#define mmPCIE_WRAP_MSIX_DOORBELL_OFF_ADDR 0x4C01018

#define mmPCIE_WRAP_MSIX_MASK_CTRL 0x4C0101C

#define mmPCIE_WRAP_PHY_FW_SRAM_ADDR_L_0 0x4C01020

#define mmPCIE_WRAP_PHY_FW_SRAM_ADDR_L_1 0x4C01024

#define mmPCIE_WRAP_PHY_FW_SRAM_ADDR_H_0 0x4C01028

#define mmPCIE_WRAP_PHY_FW_SRAM_ADDR_H_1 0x4C0102C

#define mmPCIE_WRAP_PHY_FW_SRAM_CFG_ADDR 0x4C01030

#define mmPCIE_WRAP_MSIX_GW 0x4C01034

#define mmPCIE_WRAP_MSIX_GW_VEC 0x4C01038

#define mmPCIE_WRAP_MSIX_GW_INTR 0x4C0103C

#define mmPCIE_WRAP_MSIX_GW_TABLE_0 0x4C01040

#define mmPCIE_WRAP_MSIX_GW_TABLE_1 0x4C01044

#define mmPCIE_WRAP_MSIX_GW_TABLE_2 0x4C01048

#define mmPCIE_WRAP_MSIX_GW_TABLE_3 0x4C0104C

#define mmPCIE_WRAP_MSIX_GW_TABLE_4 0x4C01050

#define mmPCIE_WRAP_MSIX_GW_TABLE_5 0x4C01054

#define mmPCIE_WRAP_MSIX_GW_TABLE_6 0x4C01058

#define mmPCIE_WRAP_MSIX_GW_TABLE_7 0x4C0105C

#define mmPCIE_WRAP_MSIX_GW_TABLE_8 0x4C01060

#define mmPCIE_WRAP_MSIX_GW_TABLE_9 0x4C01064

#define mmPCIE_WRAP_MSIX_GW_TABLE_10 0x4C01068

#define mmPCIE_WRAP_MSIX_GW_TABLE_11 0x4C0106C

#define mmPCIE_WRAP_MSIX_GW_TABLE_12 0x4C01070

#define mmPCIE_WRAP_MSIX_GW_TABLE_13 0x4C01074

#define mmPCIE_WRAP_MSIX_GW_TABLE_14 0x4C01078

#define mmPCIE_WRAP_MSIX_GW_TABLE_15 0x4C0107C

#define mmPCIE_WRAP_VUART_RX_0 0x4C01100

#define mmPCIE_WRAP_VUART_RX_1 0x4C01104

#define mmPCIE_WRAP_VUART_RX_2 0x4C01108

#define mmPCIE_WRAP_VUART_TX_0 0x4C0110C

#define mmPCIE_WRAP_VUART_TX_1 0x4C01110

#define mmPCIE_WRAP_VUART_TX_2 0x4C01114

#define mmPCIE_WRAP_MSI_GW_BLOCK 0x4C01120

#define mmPCIE_WRAP_PHY_FW_FSM_SIZE 0x4C0120C

#define mmPCIE_WRAP_HOST_ACCESS_TERMINATION 0x4C01210

#define mmPCIE_WRAP_ILLEGAL_LBW_REQ_CTRL 0x4C01214

#define mmPCIE_WRAP_ILLEGAL_LBW_REQ_ADDR_0 0x4C01218

#define mmPCIE_WRAP_ILLEGAL_LBW_REQ_ADDR_1 0x4C0121C

#define mmPCIE_WRAP_ILLEGAL_LBW_REQ_INTR 0x4C01220

#define mmPCIE_WRAP_OUTBOUND_ADDR_LSB 0x4C01224

#define mmPCIE_WRAP_LBW_WSTRB_OVRD 0x4C01228

#define mmPCIE_WRAP_LBW_GW_ADDR_0 0x4C01304

#define mmPCIE_WRAP_LBW_GW_ADDR_1 0x4C01308

#define mmPCIE_WRAP_LBW_GW_ADDR_2 0x4C0130C

#define mmPCIE_WRAP_LBW_GW_ADDR_3 0x4C01310

#define mmPCIE_WRAP_LBW_GW_ADDR_4 0x4C01314

#define mmPCIE_WRAP_LBW_GW_ADDR_5 0x4C01318

#define mmPCIE_WRAP_LBW_GW_ADDR_6 0x4C0131C

#define mmPCIE_WRAP_LBW_GW_ADDR_7 0x4C01320

#define mmPCIE_WRAP_LBW_GW_DATA_0 0x4C01324

#define mmPCIE_WRAP_LBW_GW_DATA_1 0x4C01328

#define mmPCIE_WRAP_LBW_GW_DATA_2 0x4C0132C

#define mmPCIE_WRAP_LBW_GW_DATA_3 0x4C01330

#define mmPCIE_WRAP_LBW_GW_DATA_4 0x4C01334

#define mmPCIE_WRAP_LBW_GW_DATA_5 0x4C01338

#define mmPCIE_WRAP_LBW_GW_DATA_6 0x4C0133C

#define mmPCIE_WRAP_LBW_GW_DATA_7 0x4C01340

#define mmPCIE_WRAP_LBW_GW_GO_0 0x4C01344

#define mmPCIE_WRAP_LBW_GW_GO_1 0x4C01348

#define mmPCIE_WRAP_LBW_GW_GO_2 0x4C0134C

#define mmPCIE_WRAP_LBW_GW_GO_3 0x4C01350

#define mmPCIE_WRAP_LBW_GW_GO_4 0x4C01354

#define mmPCIE_WRAP_LBW_GW_GO_5 0x4C01358

#define mmPCIE_WRAP_LBW_GW_GO_6 0x4C0135C

#define mmPCIE_WRAP_LBW_GW_GO_7 0x4C01360

#define mmPCIE_WRAP_LBW_GW_STATUS_0 0x4C01364

#define mmPCIE_WRAP_LBW_GW_STATUS_1 0x4C01368

#define mmPCIE_WRAP_LBW_GW_STATUS_2 0x4C0136C

#define mmPCIE_WRAP_LBW_GW_STATUS_3 0x4C01370

#define mmPCIE_WRAP_LBW_GW_STATUS_4 0x4C01374

#define mmPCIE_WRAP_LBW_GW_STATUS_5 0x4C01378

#define mmPCIE_WRAP_LBW_GW_STATUS_6 0x4C0137C

#define mmPCIE_WRAP_LBW_GW_STATUS_7 0x4C01380

#define mmPCIE_WRAP_OUTBOUND_OUTSTANDING 0x4C013F4

#define mmPCIE_WRAP_MASK_REQ 0x4C01404

#define mmPCIE_WRAP_ONE_IN_FLIGHT 0x4C01408

#define mmPCIE_WRAP_IND_AWPROT 0x4C0140C

#define mmPCIE_WRAP_SLV_AWMISC_INFO 0x4C01500

#define mmPCIE_WRAP_SLV_AWMISC_INFO_HDR_34DW_0 0x4C01504

#define mmPCIE_WRAP_SLV_AWMISC_INFO_HDR_34DW_1 0x4C01508

#define mmPCIE_WRAP_SLV_AWMISC_INFO_P_TAG 0x4C0150C

#define mmPCIE_WRAP_SLV_AWMISC_INFO_ATU_BYPAS 0x4C01510

#define mmPCIE_WRAP_SLV_AWMISC_INFO_FUNC_NUM 0x4C01514

#define mmPCIE_WRAP_SLV_AWMISC_INFO_VFUNC_ACT 0x4C01518

#define mmPCIE_WRAP_SLV_AWMISC_INFO_VFUNC_NUM 0x4C0151C

#define mmPCIE_WRAP_SLV_AWMISC_INFO_TLPPRFX 0x4C01520

#define mmPCIE_WRAP_SLV_ARMISC_INFO 0x4C01524

#define mmPCIE_WRAP_SLV_ARMISC_INFO_TLPPRFX 0x4C01528

#define mmPCIE_WRAP_SLV_ARMISC_INFO_ATU_BYP 0x4C0152C

#define mmPCIE_WRAP_SLV_ARMISC_INFO_FUNC_NUM 0x4C01530

#define mmPCIE_WRAP_SLV_ARMISC_INFO_VFUNC_ACT 0x4C01534

#define mmPCIE_WRAP_SLV_ARMISC_INFO_VFUNC_NUM 0x4C01538

#define mmPCIE_WRAP_MESO_FIFO_CTRL_0 0x4C01640

#define mmPCIE_WRAP_MESO_FIFO_CTRL_1 0x4C01644

#define mmPCIE_WRAP_MESO_FIFO_W_LFSR_POLY_0 0x4C01648

#define mmPCIE_WRAP_MESO_FIFO_W_LFSR_POLY_1 0x4C0164C

#define mmPCIE_WRAP_MESO_FIFO_R_LFSR_POLY_0 0x4C01650

#define mmPCIE_WRAP_MESO_FIFO_R_LFSR_POLY_1 0x4C01654

#define mmPCIE_WRAP_MESO_FIFO_W_PUSH_CNT_0 0x4C01658

#define mmPCIE_WRAP_MESO_FIFO_W_PUSH_CNT_1 0x4C0165C

#define mmPCIE_WRAP_MESO_FIFO_W_BP_CNT_0 0x4C01660

#define mmPCIE_WRAP_MESO_FIFO_W_BP_CNT_1 0x4C01664

#define mmPCIE_WRAP_MESO_FIFO_R_ERR_CNT_0 0x4C01668

#define mmPCIE_WRAP_MESO_FIFO_R_ERR_CNT_1 0x4C0166C

#define mmPCIE_WRAP_MESO_FIFO_R_POP_CNT_0 0x4C01670

#define mmPCIE_WRAP_MESO_FIFO_R_POP_CNT_1 0x4C01674

#define mmPCIE_WRAP_MESO_FIFO_W_LFSR_0 0x4C01678

#define mmPCIE_WRAP_MESO_FIFO_W_LFSR_1 0x4C0167C

#define mmPCIE_WRAP_MESO_FIFO_R_LFSR_0 0x4C01680

#define mmPCIE_WRAP_MESO_FIFO_R_LFSR_1 0x4C01684

#define mmPCIE_WRAP_MESO_FIFO_W_PUSH_LFSR_0 0x4C01688

#define mmPCIE_WRAP_MESO_FIFO_W_PUSH_LFSR_1 0x4C0168C

#define mmPCIE_WRAP_MESO_FIFO_R_POP_LFSR_0 0x4C01690

#define mmPCIE_WRAP_MESO_FIFO_R_POP_LFSR_1 0x4C01694

#define mmPCIE_WRAP_MESO_FIFO_W_BP_PERIOD_0 0x4C01698

#define mmPCIE_WRAP_MESO_FIFO_W_BP_PERIOD_1 0x4C0169C

#define mmPCIE_WRAP_MESO_FIFO_R_BP_PERIOD_0 0x4C016A0

#define mmPCIE_WRAP_MESO_FIFO_R_BP_PERIOD_1 0x4C016A4

#define mmPCIE_WRAP_MESO_FIFO_W_USED_CNT_0 0x4C016A8

#define mmPCIE_WRAP_MESO_FIFO_W_USED_CNT_1 0x4C016AC

#define mmPCIE_WRAP_MESO_FIFO_R_USED_CNT_0 0x4C016B0

#define mmPCIE_WRAP_MESO_FIFO_R_USED_CNT_1 0x4C016B4

#define mmPCIE_WRAP_P2P_TABLE_0 0x4C01900

#define mmPCIE_WRAP_P2P_TABLE_1 0x4C01904

#define mmPCIE_WRAP_P2P_TABLE_2 0x4C01908

#define mmPCIE_WRAP_P2P_TABLE_3 0x4C0190C

#define mmPCIE_WRAP_P2P_TABLE_4 0x4C01910

#define mmPCIE_WRAP_P2P_TABLE_5 0x4C01914

#define mmPCIE_WRAP_P2P_TABLE_6 0x4C01918

#define mmPCIE_WRAP_P2P_TABLE_7 0x4C0191C

#define mmPCIE_WRAP_P2P_TABLE_8 0x4C01920

#define mmPCIE_WRAP_P2P_TABLE_9 0x4C01924

#define mmPCIE_WRAP_P2P_TABLE_10 0x4C01928

#define mmPCIE_WRAP_P2P_TABLE_11 0x4C0192C

#define mmPCIE_WRAP_P2P_TABLE_12 0x4C01930

#define mmPCIE_WRAP_P2P_TABLE_13 0x4C01934

#define mmPCIE_WRAP_P2P_TABLE_14 0x4C01938

#define mmPCIE_WRAP_P2P_TABLE_15 0x4C0193C

#define mmPCIE_WRAP_P2P_TABLE_16 0x4C01940

#define mmPCIE_WRAP_P2P_TABLE_17 0x4C01944

#define mmPCIE_WRAP_P2P_TABLE_18 0x4C01948

#define mmPCIE_WRAP_P2P_TABLE_19 0x4C0194C

#define mmPCIE_WRAP_P2P_TABLE_20 0x4C01950

#define mmPCIE_WRAP_P2P_TABLE_21 0x4C01954

#define mmPCIE_WRAP_P2P_TABLE_22 0x4C01958

#define mmPCIE_WRAP_P2P_TABLE_23 0x4C0195C

#define mmPCIE_WRAP_P2P_TABLE_24 0x4C01960

#define mmPCIE_WRAP_P2P_TABLE_25 0x4C01964

#define mmPCIE_WRAP_P2P_TABLE_26 0x4C01968

#define mmPCIE_WRAP_P2P_TABLE_27 0x4C0196C

#define mmPCIE_WRAP_P2P_TABLE_28 0x4C01970

#define mmPCIE_WRAP_P2P_TABLE_29 0x4C01974

#define mmPCIE_WRAP_P2P_TABLE_30 0x4C01978

#define mmPCIE_WRAP_P2P_TABLE_31 0x4C0197C

#define mmPCIE_WRAP_P2P_TABLE_32 0x4C01980

#define mmPCIE_WRAP_P2P_TABLE_33 0x4C01984

#define mmPCIE_WRAP_P2P_TABLE_34 0x4C01988

#define mmPCIE_WRAP_P2P_TABLE_35 0x4C0198C

#define mmPCIE_WRAP_P2P_TABLE_36 0x4C01990

#define mmPCIE_WRAP_P2P_TABLE_37 0x4C01994

#define mmPCIE_WRAP_P2P_TABLE_38 0x4C01998

#define mmPCIE_WRAP_P2P_TABLE_39 0x4C0199C

#define mmPCIE_WRAP_P2P_TABLE_40 0x4C019A0

#define mmPCIE_WRAP_P2P_TABLE_41 0x4C019A4

#define mmPCIE_WRAP_P2P_TABLE_42 0x4C019A8

#define mmPCIE_WRAP_P2P_TABLE_43 0x4C019AC

#define mmPCIE_WRAP_P2P_TABLE_44 0x4C019B0

#define mmPCIE_WRAP_P2P_TABLE_45 0x4C019B4

#define mmPCIE_WRAP_P2P_TABLE_46 0x4C019B8

#define mmPCIE_WRAP_P2P_TABLE_47 0x4C019BC

#define mmPCIE_WRAP_P2P_TABLE_48 0x4C019C0

#define mmPCIE_WRAP_P2P_TABLE_49 0x4C019C4

#define mmPCIE_WRAP_P2P_TABLE_50 0x4C019C8

#define mmPCIE_WRAP_P2P_TABLE_51 0x4C019CC

#define mmPCIE_WRAP_P2P_TABLE_52 0x4C019D0

#define mmPCIE_WRAP_P2P_TABLE_53 0x4C019D4

#define mmPCIE_WRAP_P2P_TABLE_54 0x4C019D8

#define mmPCIE_WRAP_P2P_TABLE_55 0x4C019DC

#define mmPCIE_WRAP_P2P_TABLE_56 0x4C019E0

#define mmPCIE_WRAP_P2P_TABLE_57 0x4C019E4

#define mmPCIE_WRAP_P2P_TABLE_58 0x4C019E8

#define mmPCIE_WRAP_P2P_TABLE_59 0x4C019EC

#define mmPCIE_WRAP_P2P_TABLE_60 0x4C019F0

#define mmPCIE_WRAP_P2P_TABLE_61 0x4C019F4

#define mmPCIE_WRAP_P2P_TABLE_62 0x4C019F8

#define mmPCIE_WRAP_P2P_TABLE_63 0x4C019FC

#define mmPCIE_WRAP_P2P_EN 0x4C01A00

#define mmPCIE_WRAP_P2P_REQ_ID 0x4C01A04

#define mmPCIE_WRAP_P2P_INTR 0x4C01A08

#define mmPCIE_WRAP_P2P_TERMINATE_RESP 0x4C01A0C

#define mmPCIE_WRAP_GIC_INTR_TERMINATE_CTRL 0x4C01A10

#define mmPCIE_WRAP_GIC_INTR_TERMINATE_CNT 0x4C01A14

#define mmPCIE_WRAP_CPU_HOT_RST 0x4C01AE0

#define mmPCIE_WRAP_LBW_AXI_SPLIT_MAX_OUTSTAN 0x4C01B2C

#define mmPCIE_WRAP_AXI_SPLIT_NO_WR_INFLIGHT 0x4C01B30

#define mmPCIE_WRAP_PCIE_WR_BUF 0x4C01B34

#define mmPCIE_WRAP_PCIE_CACHE_OVR 0x4C01B38

#define mmPCIE_WRAP_PCIE_LOCK_OVR 0x4C01B3C

#define mmPCIE_WRAP_PCIE_PROT_OVR 0x4C01B40

#define mmPCIE_WRAP_PCIE_ARUSER_OVR_0 0x4C01B44

#define mmPCIE_WRAP_PCIE_ARUSER_OVR_1 0x4C01B48

#define mmPCIE_WRAP_PCIE_AWUSER_OVR_0 0x4C01B4C

#define mmPCIE_WRAP_PCIE_AWUSER_OVR_1 0x4C01B50

#define mmPCIE_WRAP_PCIE_ARUSER_OVR_EN_0 0x4C01B54

#define mmPCIE_WRAP_PCIE_ARUSER_OVR_EN_1 0x4C01B58

#define mmPCIE_WRAP_PCIE_AWUSER_OVR_EN_0 0x4C01B5C

#define mmPCIE_WRAP_PCIE_AWUSER_OVR_EN_1 0x4C01B60

#define mmPCIE_WRAP_PCIE_MAX_OUTSTAND 0x4C01B64

#define mmPCIE_WRAP_PCIE_MST_IN 0x4C01B68

#define mmPCIE_WRAP_PCIE_RSP_OK 0x4C01B6C

#define mmPCIE_WRAP_AXI_SPLIT_INTR_0 0x4C01B70

#define mmPCIE_WRAP_AXI_SPLIT_INTR_1 0x4C01B74

#define mmPCIE_WRAP_AXI_DRAIN_MSTR_IF_CFG_0 0x4C01B7C

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_0 0x4C01B80

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_1 0x4C01B84

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_2 0x4C01B88

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_3 0x4C01B8C

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_4 0x4C01B90

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_5 0x4C01B94

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_6 0x4C01B98

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_7 0x4C01B9C

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_8 0x4C01BA0

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_9 0x4C01BA4

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_10 0x4C01BA8

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_11 0x4C01BAC

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_12 0x4C01BB0

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_13 0x4C01BB4

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_14 0x4C01BB8

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_15 0x4C01BBC

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_16 0x4C01BC0

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_17 0x4C01BC4

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_18 0x4C01BC8

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_19 0x4C01BCC

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_20 0x4C01BD0

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_21 0x4C01BD4

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_22 0x4C01BD8

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_23 0x4C01BDC

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_24 0x4C01BE0

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_25 0x4C01BE4

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_26 0x4C01BE8

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_27 0x4C01BEC

#define mmPCIE_WRAP_AXI_DRAIN_EXTMEM_POLY_H3_28 0x4C01BF0

#define mmPCIE_WRAP_AXI_DRAIN_ACTIVE 0x4C01D48

#define mmPCIE_WRAP_AXI_DRAIN_IND 0x4C01D4C

#define mmPCIE_WRAP_HBW_DRAIN_TIMEOUT 0x4C01D50

#define mmPCIE_WRAP_HBW_DRAIN_CFG 0x4C01D54

#define mmPCIE_WRAP_LBW_DRAIN_TIMEOUT 0x4C01D58

#define mmPCIE_WRAP_LBW_DRAIN_CFG 0x4C01D5C

#define mmPCIE_WRAP_LBW_DRAIN_DELAY_EN_CNT 0x4C01D60

#define mmPCIE_WRAP_PHY_FW_FSM 0x4C01D64

#define mmPCIE_WRAP_PCIE_PHY_BASE_ADDR_L 0x4C01D68

#define mmPCIE_WRAP_PCIE_PHY_BASE_ADDR_H 0x4C01D6C

#define mmPCIE_WRAP_PCIE_CORE_BASE_ADDR_L 0x4C01D70

#define mmPCIE_WRAP_PCIE_CORE_BASE_ADDR_H 0x4C01D74

#define mmPCIE_WRAP_SPMU_INTR 0x4C01DE4

#define mmPCIE_WRAP_AXI_INTR 0x4C01DE8

#define mmPCIE_WRAP_PCIE_IC_SEI_INTR_IND 0x4C01DEC

#define mmPCIE_WRAP_PMMU_RTR_CFG 0x4C01DF0

#define mmPCIE_WRAP_PSOC_RST_CTRL 0x4C01DF4

#define mmPCIE_WRAP_PSOC_BOOT_MNG_DONE 0x4C01DF8

#define mmPCIE_WRAP_ASID_MOD_CTRL 0x4C01DFC

#define mmPCIE_WRAP_ASID_MOD_ADDR_L_0 0x4C01E00

#define mmPCIE_WRAP_ASID_MOD_ADDR_L_1 0x4C01E04

#define mmPCIE_WRAP_ASID_MOD_ADDR_H_0 0x4C01E08

#define mmPCIE_WRAP_ASID_MOD_ADDR_H_1 0x4C01E0C

#define mmPCIE_WRAP_CS_TRACE_AXI_CTRL 0x4C01E10

#define mmPCIE_WRAP_FLR_FSM_CTRL 0x4C01E14

#define mmPCIE_WRAP_HBW_DRAIN_WR_ADDR_0 0x4C01E18

#define mmPCIE_WRAP_HBW_DRAIN_WR_ADDR_1 0x4C01E1C

#define mmPCIE_WRAP_HBW_DRAIN_RD_ADDR_0 0x4C01E20

#define mmPCIE_WRAP_HBW_DRAIN_RD_ADDR_1 0x4C01E24

#define mmPCIE_WRAP_HBW_DRAIN_STAMP 0x4C01E28

#define mmPCIE_WRAP_LBW_DRAIN_WR_ADDR_0 0x4C01E2C

#define mmPCIE_WRAP_LBW_DRAIN_WR_ADDR_1 0x4C01E30

#define mmPCIE_WRAP_LBW_DRAIN_RD_ADDR_0 0x4C01E34

#define mmPCIE_WRAP_LBW_DRAIN_RD_ADDR_1 0x4C01E38

#define mmPCIE_WRAP_LBW_DRAIN_STAMP 0x4C01E3C

#define mmPCIE_WRAP_EXTMEM_HBM_LOC 0x4C01E40

#define mmPCIE_WRAP_EXTMEM_PC_LOC 0x4C01E44

#define mmPCIE_WRAP_EXTMEM_NONLIN_HBM 0x4C01E48

#define mmPCIE_WRAP_EXTMEM_NONLIN_PC 0x4C01E4C

#define mmPCIE_WRAP_EXTMEM_NONLIN_HBM_NUM 0x4C01E50

#define mmPCIE_WRAP_EXTMEM_NONLIN_HBM_MAP 0x4C01E54

#endif /* ASIC_REG_PCIE_WRAP_REGS_H_ */
