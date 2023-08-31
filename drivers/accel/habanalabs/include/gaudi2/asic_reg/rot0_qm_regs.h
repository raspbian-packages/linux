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

#ifndef ASIC_REG_ROT0_QM_REGS_H_
#define ASIC_REG_ROT0_QM_REGS_H_

/*
 *****************************************
 *   ROT0_QM
 *   (Prototype: QMAN)
 *****************************************
 */

#define mmROT0_QM_GLBL_CFG0 0x4E0A000

#define mmROT0_QM_GLBL_CFG1 0x4E0A004

#define mmROT0_QM_GLBL_CFG2 0x4E0A008

#define mmROT0_QM_GLBL_ERR_CFG 0x4E0A00C

#define mmROT0_QM_GLBL_ERR_CFG1 0x4E0A010

#define mmROT0_QM_GLBL_ERR_ARC_HALT_EN 0x4E0A014

#define mmROT0_QM_GLBL_AXCACHE 0x4E0A018

#define mmROT0_QM_GLBL_STS0 0x4E0A01C

#define mmROT0_QM_GLBL_STS1 0x4E0A020

#define mmROT0_QM_GLBL_ERR_STS_0 0x4E0A024

#define mmROT0_QM_GLBL_ERR_STS_1 0x4E0A028

#define mmROT0_QM_GLBL_ERR_STS_2 0x4E0A02C

#define mmROT0_QM_GLBL_ERR_STS_3 0x4E0A030

#define mmROT0_QM_GLBL_ERR_STS_4 0x4E0A034

#define mmROT0_QM_GLBL_ERR_MSG_EN_0 0x4E0A038

#define mmROT0_QM_GLBL_ERR_MSG_EN_1 0x4E0A03C

#define mmROT0_QM_GLBL_ERR_MSG_EN_2 0x4E0A040

#define mmROT0_QM_GLBL_ERR_MSG_EN_3 0x4E0A044

#define mmROT0_QM_GLBL_ERR_MSG_EN_4 0x4E0A048

#define mmROT0_QM_GLBL_PROT 0x4E0A04C

#define mmROT0_QM_PQ_BASE_LO_0 0x4E0A050

#define mmROT0_QM_PQ_BASE_LO_1 0x4E0A054

#define mmROT0_QM_PQ_BASE_LO_2 0x4E0A058

#define mmROT0_QM_PQ_BASE_LO_3 0x4E0A05C

#define mmROT0_QM_PQ_BASE_HI_0 0x4E0A060

#define mmROT0_QM_PQ_BASE_HI_1 0x4E0A064

#define mmROT0_QM_PQ_BASE_HI_2 0x4E0A068

#define mmROT0_QM_PQ_BASE_HI_3 0x4E0A06C

#define mmROT0_QM_PQ_SIZE_0 0x4E0A070

#define mmROT0_QM_PQ_SIZE_1 0x4E0A074

#define mmROT0_QM_PQ_SIZE_2 0x4E0A078

#define mmROT0_QM_PQ_SIZE_3 0x4E0A07C

#define mmROT0_QM_PQ_PI_0 0x4E0A080

#define mmROT0_QM_PQ_PI_1 0x4E0A084

#define mmROT0_QM_PQ_PI_2 0x4E0A088

#define mmROT0_QM_PQ_PI_3 0x4E0A08C

#define mmROT0_QM_PQ_CI_0 0x4E0A090

#define mmROT0_QM_PQ_CI_1 0x4E0A094

#define mmROT0_QM_PQ_CI_2 0x4E0A098

#define mmROT0_QM_PQ_CI_3 0x4E0A09C

#define mmROT0_QM_PQ_CFG0_0 0x4E0A0A0

#define mmROT0_QM_PQ_CFG0_1 0x4E0A0A4

#define mmROT0_QM_PQ_CFG0_2 0x4E0A0A8

#define mmROT0_QM_PQ_CFG0_3 0x4E0A0AC

#define mmROT0_QM_PQ_CFG1_0 0x4E0A0B0

#define mmROT0_QM_PQ_CFG1_1 0x4E0A0B4

#define mmROT0_QM_PQ_CFG1_2 0x4E0A0B8

#define mmROT0_QM_PQ_CFG1_3 0x4E0A0BC

#define mmROT0_QM_PQ_STS0_0 0x4E0A0C0

#define mmROT0_QM_PQ_STS0_1 0x4E0A0C4

#define mmROT0_QM_PQ_STS0_2 0x4E0A0C8

#define mmROT0_QM_PQ_STS0_3 0x4E0A0CC

#define mmROT0_QM_PQ_STS1_0 0x4E0A0D0

#define mmROT0_QM_PQ_STS1_1 0x4E0A0D4

#define mmROT0_QM_PQ_STS1_2 0x4E0A0D8

#define mmROT0_QM_PQ_STS1_3 0x4E0A0DC

#define mmROT0_QM_CQ_CFG0_0 0x4E0A0E0

#define mmROT0_QM_CQ_CFG0_1 0x4E0A0E4

#define mmROT0_QM_CQ_CFG0_2 0x4E0A0E8

#define mmROT0_QM_CQ_CFG0_3 0x4E0A0EC

#define mmROT0_QM_CQ_CFG0_4 0x4E0A0F0

#define mmROT0_QM_CQ_STS0_0 0x4E0A0F4

#define mmROT0_QM_CQ_STS0_1 0x4E0A0F8

#define mmROT0_QM_CQ_STS0_2 0x4E0A0FC

#define mmROT0_QM_CQ_STS0_3 0x4E0A100

#define mmROT0_QM_CQ_STS0_4 0x4E0A104

#define mmROT0_QM_CQ_CFG1_0 0x4E0A108

#define mmROT0_QM_CQ_CFG1_1 0x4E0A10C

#define mmROT0_QM_CQ_CFG1_2 0x4E0A110

#define mmROT0_QM_CQ_CFG1_3 0x4E0A114

#define mmROT0_QM_CQ_CFG1_4 0x4E0A118

#define mmROT0_QM_CQ_STS1_0 0x4E0A11C

#define mmROT0_QM_CQ_STS1_1 0x4E0A120

#define mmROT0_QM_CQ_STS1_2 0x4E0A124

#define mmROT0_QM_CQ_STS1_3 0x4E0A128

#define mmROT0_QM_CQ_STS1_4 0x4E0A12C

#define mmROT0_QM_CQ_PTR_LO_0 0x4E0A150

#define mmROT0_QM_CQ_PTR_HI_0 0x4E0A154

#define mmROT0_QM_CQ_TSIZE_0 0x4E0A158

#define mmROT0_QM_CQ_CTL_0 0x4E0A15C

#define mmROT0_QM_CQ_PTR_LO_1 0x4E0A160

#define mmROT0_QM_CQ_PTR_HI_1 0x4E0A164

#define mmROT0_QM_CQ_TSIZE_1 0x4E0A168

#define mmROT0_QM_CQ_CTL_1 0x4E0A16C

#define mmROT0_QM_CQ_PTR_LO_2 0x4E0A170

#define mmROT0_QM_CQ_PTR_HI_2 0x4E0A174

#define mmROT0_QM_CQ_TSIZE_2 0x4E0A178

#define mmROT0_QM_CQ_CTL_2 0x4E0A17C

#define mmROT0_QM_CQ_PTR_LO_3 0x4E0A180

#define mmROT0_QM_CQ_PTR_HI_3 0x4E0A184

#define mmROT0_QM_CQ_TSIZE_3 0x4E0A188

#define mmROT0_QM_CQ_CTL_3 0x4E0A18C

#define mmROT0_QM_CQ_PTR_LO_4 0x4E0A190

#define mmROT0_QM_CQ_PTR_HI_4 0x4E0A194

#define mmROT0_QM_CQ_TSIZE_4 0x4E0A198

#define mmROT0_QM_CQ_CTL_4 0x4E0A19C

#define mmROT0_QM_CQ_TSIZE_STS_0 0x4E0A1A0

#define mmROT0_QM_CQ_TSIZE_STS_1 0x4E0A1A4

#define mmROT0_QM_CQ_TSIZE_STS_2 0x4E0A1A8

#define mmROT0_QM_CQ_TSIZE_STS_3 0x4E0A1AC

#define mmROT0_QM_CQ_TSIZE_STS_4 0x4E0A1B0

#define mmROT0_QM_CQ_PTR_LO_STS_0 0x4E0A1B4

#define mmROT0_QM_CQ_PTR_LO_STS_1 0x4E0A1B8

#define mmROT0_QM_CQ_PTR_LO_STS_2 0x4E0A1BC

#define mmROT0_QM_CQ_PTR_LO_STS_3 0x4E0A1C0

#define mmROT0_QM_CQ_PTR_LO_STS_4 0x4E0A1C4

#define mmROT0_QM_CQ_PTR_HI_STS_0 0x4E0A1C8

#define mmROT0_QM_CQ_PTR_HI_STS_1 0x4E0A1CC

#define mmROT0_QM_CQ_PTR_HI_STS_2 0x4E0A1D0

#define mmROT0_QM_CQ_PTR_HI_STS_3 0x4E0A1D4

#define mmROT0_QM_CQ_PTR_HI_STS_4 0x4E0A1D8

#define mmROT0_QM_CQ_IFIFO_STS_0 0x4E0A1DC

#define mmROT0_QM_CQ_IFIFO_STS_1 0x4E0A1E0

#define mmROT0_QM_CQ_IFIFO_STS_2 0x4E0A1E4

#define mmROT0_QM_CQ_IFIFO_STS_3 0x4E0A1E8

#define mmROT0_QM_CQ_IFIFO_STS_4 0x4E0A1EC

#define mmROT0_QM_CP_MSG_BASE0_ADDR_LO_0 0x4E0A1F0

#define mmROT0_QM_CP_MSG_BASE0_ADDR_LO_1 0x4E0A1F4

#define mmROT0_QM_CP_MSG_BASE0_ADDR_LO_2 0x4E0A1F8

#define mmROT0_QM_CP_MSG_BASE0_ADDR_LO_3 0x4E0A1FC

#define mmROT0_QM_CP_MSG_BASE0_ADDR_LO_4 0x4E0A200

#define mmROT0_QM_CP_MSG_BASE0_ADDR_HI_0 0x4E0A204

#define mmROT0_QM_CP_MSG_BASE0_ADDR_HI_1 0x4E0A208

#define mmROT0_QM_CP_MSG_BASE0_ADDR_HI_2 0x4E0A20C

#define mmROT0_QM_CP_MSG_BASE0_ADDR_HI_3 0x4E0A210

#define mmROT0_QM_CP_MSG_BASE0_ADDR_HI_4 0x4E0A214

#define mmROT0_QM_CP_MSG_BASE1_ADDR_LO_0 0x4E0A218

#define mmROT0_QM_CP_MSG_BASE1_ADDR_LO_1 0x4E0A21C

#define mmROT0_QM_CP_MSG_BASE1_ADDR_LO_2 0x4E0A220

#define mmROT0_QM_CP_MSG_BASE1_ADDR_LO_3 0x4E0A224

#define mmROT0_QM_CP_MSG_BASE1_ADDR_LO_4 0x4E0A228

#define mmROT0_QM_CP_MSG_BASE1_ADDR_HI_0 0x4E0A22C

#define mmROT0_QM_CP_MSG_BASE1_ADDR_HI_1 0x4E0A230

#define mmROT0_QM_CP_MSG_BASE1_ADDR_HI_2 0x4E0A234

#define mmROT0_QM_CP_MSG_BASE1_ADDR_HI_3 0x4E0A238

#define mmROT0_QM_CP_MSG_BASE1_ADDR_HI_4 0x4E0A23C

#define mmROT0_QM_CP_MSG_BASE2_ADDR_LO_0 0x4E0A240

#define mmROT0_QM_CP_MSG_BASE2_ADDR_LO_1 0x4E0A244

#define mmROT0_QM_CP_MSG_BASE2_ADDR_LO_2 0x4E0A248

#define mmROT0_QM_CP_MSG_BASE2_ADDR_LO_3 0x4E0A24C

#define mmROT0_QM_CP_MSG_BASE2_ADDR_LO_4 0x4E0A250

#define mmROT0_QM_CP_MSG_BASE2_ADDR_HI_0 0x4E0A254

#define mmROT0_QM_CP_MSG_BASE2_ADDR_HI_1 0x4E0A258

#define mmROT0_QM_CP_MSG_BASE2_ADDR_HI_2 0x4E0A25C

#define mmROT0_QM_CP_MSG_BASE2_ADDR_HI_3 0x4E0A260

#define mmROT0_QM_CP_MSG_BASE2_ADDR_HI_4 0x4E0A264

#define mmROT0_QM_CP_MSG_BASE3_ADDR_LO_0 0x4E0A268

#define mmROT0_QM_CP_MSG_BASE3_ADDR_LO_1 0x4E0A26C

#define mmROT0_QM_CP_MSG_BASE3_ADDR_LO_2 0x4E0A270

#define mmROT0_QM_CP_MSG_BASE3_ADDR_LO_3 0x4E0A274

#define mmROT0_QM_CP_MSG_BASE3_ADDR_LO_4 0x4E0A278

#define mmROT0_QM_CP_MSG_BASE3_ADDR_HI_0 0x4E0A27C

#define mmROT0_QM_CP_MSG_BASE3_ADDR_HI_1 0x4E0A280

#define mmROT0_QM_CP_MSG_BASE3_ADDR_HI_2 0x4E0A284

#define mmROT0_QM_CP_MSG_BASE3_ADDR_HI_3 0x4E0A288

#define mmROT0_QM_CP_MSG_BASE3_ADDR_HI_4 0x4E0A28C

#define mmROT0_QM_CP_FENCE0_RDATA_0 0x4E0A290

#define mmROT0_QM_CP_FENCE0_RDATA_1 0x4E0A294

#define mmROT0_QM_CP_FENCE0_RDATA_2 0x4E0A298

#define mmROT0_QM_CP_FENCE0_RDATA_3 0x4E0A29C

#define mmROT0_QM_CP_FENCE0_RDATA_4 0x4E0A2A0

#define mmROT0_QM_CP_FENCE1_RDATA_0 0x4E0A2A4

#define mmROT0_QM_CP_FENCE1_RDATA_1 0x4E0A2A8

#define mmROT0_QM_CP_FENCE1_RDATA_2 0x4E0A2AC

#define mmROT0_QM_CP_FENCE1_RDATA_3 0x4E0A2B0

#define mmROT0_QM_CP_FENCE1_RDATA_4 0x4E0A2B4

#define mmROT0_QM_CP_FENCE2_RDATA_0 0x4E0A2B8

#define mmROT0_QM_CP_FENCE2_RDATA_1 0x4E0A2BC

#define mmROT0_QM_CP_FENCE2_RDATA_2 0x4E0A2C0

#define mmROT0_QM_CP_FENCE2_RDATA_3 0x4E0A2C4

#define mmROT0_QM_CP_FENCE2_RDATA_4 0x4E0A2C8

#define mmROT0_QM_CP_FENCE3_RDATA_0 0x4E0A2CC

#define mmROT0_QM_CP_FENCE3_RDATA_1 0x4E0A2D0

#define mmROT0_QM_CP_FENCE3_RDATA_2 0x4E0A2D4

#define mmROT0_QM_CP_FENCE3_RDATA_3 0x4E0A2D8

#define mmROT0_QM_CP_FENCE3_RDATA_4 0x4E0A2DC

#define mmROT0_QM_CP_FENCE0_CNT_0 0x4E0A2E0

#define mmROT0_QM_CP_FENCE0_CNT_1 0x4E0A2E4

#define mmROT0_QM_CP_FENCE0_CNT_2 0x4E0A2E8

#define mmROT0_QM_CP_FENCE0_CNT_3 0x4E0A2EC

#define mmROT0_QM_CP_FENCE0_CNT_4 0x4E0A2F0

#define mmROT0_QM_CP_FENCE1_CNT_0 0x4E0A2F4

#define mmROT0_QM_CP_FENCE1_CNT_1 0x4E0A2F8

#define mmROT0_QM_CP_FENCE1_CNT_2 0x4E0A2FC

#define mmROT0_QM_CP_FENCE1_CNT_3 0x4E0A300

#define mmROT0_QM_CP_FENCE1_CNT_4 0x4E0A304

#define mmROT0_QM_CP_FENCE2_CNT_0 0x4E0A308

#define mmROT0_QM_CP_FENCE2_CNT_1 0x4E0A30C

#define mmROT0_QM_CP_FENCE2_CNT_2 0x4E0A310

#define mmROT0_QM_CP_FENCE2_CNT_3 0x4E0A314

#define mmROT0_QM_CP_FENCE2_CNT_4 0x4E0A318

#define mmROT0_QM_CP_FENCE3_CNT_0 0x4E0A31C

#define mmROT0_QM_CP_FENCE3_CNT_1 0x4E0A320

#define mmROT0_QM_CP_FENCE3_CNT_2 0x4E0A324

#define mmROT0_QM_CP_FENCE3_CNT_3 0x4E0A328

#define mmROT0_QM_CP_FENCE3_CNT_4 0x4E0A32C

#define mmROT0_QM_CP_BARRIER_CFG 0x4E0A330

#define mmROT0_QM_CP_LDMA_SRC_BASE_LO_OFFSET 0x4E0A334

#define mmROT0_QM_CP_LDMA_DST_BASE_LO_OFFSET 0x4E0A338

#define mmROT0_QM_CP_LDMA_TSIZE_OFFSET 0x4E0A33C

#define mmROT0_QM_CP_CQ_PTR_LO_OFFSET_0 0x4E0A340

#define mmROT0_QM_CP_CQ_PTR_LO_OFFSET_1 0x4E0A344

#define mmROT0_QM_CP_CQ_PTR_LO_OFFSET_2 0x4E0A348

#define mmROT0_QM_CP_CQ_PTR_LO_OFFSET_3 0x4E0A34C

#define mmROT0_QM_CP_CQ_PTR_LO_OFFSET_4 0x4E0A350

#define mmROT0_QM_CP_STS_0 0x4E0A368

#define mmROT0_QM_CP_STS_1 0x4E0A36C

#define mmROT0_QM_CP_STS_2 0x4E0A370

#define mmROT0_QM_CP_STS_3 0x4E0A374

#define mmROT0_QM_CP_STS_4 0x4E0A378

#define mmROT0_QM_CP_CURRENT_INST_LO_0 0x4E0A37C

#define mmROT0_QM_CP_CURRENT_INST_LO_1 0x4E0A380

#define mmROT0_QM_CP_CURRENT_INST_LO_2 0x4E0A384

#define mmROT0_QM_CP_CURRENT_INST_LO_3 0x4E0A388

#define mmROT0_QM_CP_CURRENT_INST_LO_4 0x4E0A38C

#define mmROT0_QM_CP_CURRENT_INST_HI_0 0x4E0A390

#define mmROT0_QM_CP_CURRENT_INST_HI_1 0x4E0A394

#define mmROT0_QM_CP_CURRENT_INST_HI_2 0x4E0A398

#define mmROT0_QM_CP_CURRENT_INST_HI_3 0x4E0A39C

#define mmROT0_QM_CP_CURRENT_INST_HI_4 0x4E0A3A0

#define mmROT0_QM_CP_PRED_0 0x4E0A3A4

#define mmROT0_QM_CP_PRED_1 0x4E0A3A8

#define mmROT0_QM_CP_PRED_2 0x4E0A3AC

#define mmROT0_QM_CP_PRED_3 0x4E0A3B0

#define mmROT0_QM_CP_PRED_4 0x4E0A3B4

#define mmROT0_QM_CP_PRED_UPEN_0 0x4E0A3B8

#define mmROT0_QM_CP_PRED_UPEN_1 0x4E0A3BC

#define mmROT0_QM_CP_PRED_UPEN_2 0x4E0A3C0

#define mmROT0_QM_CP_PRED_UPEN_3 0x4E0A3C4

#define mmROT0_QM_CP_PRED_UPEN_4 0x4E0A3C8

#define mmROT0_QM_CP_DBG_0_0 0x4E0A3CC

#define mmROT0_QM_CP_DBG_0_1 0x4E0A3D0

#define mmROT0_QM_CP_DBG_0_2 0x4E0A3D4

#define mmROT0_QM_CP_DBG_0_3 0x4E0A3D8

#define mmROT0_QM_CP_DBG_0_4 0x4E0A3DC

#define mmROT0_QM_CP_CPDMA_UP_CRED_0 0x4E0A3E0

#define mmROT0_QM_CP_CPDMA_UP_CRED_1 0x4E0A3E4

#define mmROT0_QM_CP_CPDMA_UP_CRED_2 0x4E0A3E8

#define mmROT0_QM_CP_CPDMA_UP_CRED_3 0x4E0A3EC

#define mmROT0_QM_CP_CPDMA_UP_CRED_4 0x4E0A3F0

#define mmROT0_QM_CP_IN_DATA_LO_0 0x4E0A3F4

#define mmROT0_QM_CP_IN_DATA_LO_1 0x4E0A3F8

#define mmROT0_QM_CP_IN_DATA_LO_2 0x4E0A3FC

#define mmROT0_QM_CP_IN_DATA_LO_3 0x4E0A400

#define mmROT0_QM_CP_IN_DATA_LO_4 0x4E0A404

#define mmROT0_QM_CP_IN_DATA_HI_0 0x4E0A408

#define mmROT0_QM_CP_IN_DATA_HI_1 0x4E0A40C

#define mmROT0_QM_CP_IN_DATA_HI_2 0x4E0A410

#define mmROT0_QM_CP_IN_DATA_HI_3 0x4E0A414

#define mmROT0_QM_CP_IN_DATA_HI_4 0x4E0A418

#define mmROT0_QM_PQC_HBW_BASE_LO_0 0x4E0A41C

#define mmROT0_QM_PQC_HBW_BASE_LO_1 0x4E0A420

#define mmROT0_QM_PQC_HBW_BASE_LO_2 0x4E0A424

#define mmROT0_QM_PQC_HBW_BASE_LO_3 0x4E0A428

#define mmROT0_QM_PQC_HBW_BASE_HI_0 0x4E0A42C

#define mmROT0_QM_PQC_HBW_BASE_HI_1 0x4E0A430

#define mmROT0_QM_PQC_HBW_BASE_HI_2 0x4E0A434

#define mmROT0_QM_PQC_HBW_BASE_HI_3 0x4E0A438

#define mmROT0_QM_PQC_SIZE_0 0x4E0A43C

#define mmROT0_QM_PQC_SIZE_1 0x4E0A440

#define mmROT0_QM_PQC_SIZE_2 0x4E0A444

#define mmROT0_QM_PQC_SIZE_3 0x4E0A448

#define mmROT0_QM_PQC_PI_0 0x4E0A44C

#define mmROT0_QM_PQC_PI_1 0x4E0A450

#define mmROT0_QM_PQC_PI_2 0x4E0A454

#define mmROT0_QM_PQC_PI_3 0x4E0A458

#define mmROT0_QM_PQC_LBW_WDATA_0 0x4E0A45C

#define mmROT0_QM_PQC_LBW_WDATA_1 0x4E0A460

#define mmROT0_QM_PQC_LBW_WDATA_2 0x4E0A464

#define mmROT0_QM_PQC_LBW_WDATA_3 0x4E0A468

#define mmROT0_QM_PQC_LBW_BASE_LO_0 0x4E0A46C

#define mmROT0_QM_PQC_LBW_BASE_LO_1 0x4E0A470

#define mmROT0_QM_PQC_LBW_BASE_LO_2 0x4E0A474

#define mmROT0_QM_PQC_LBW_BASE_LO_3 0x4E0A478

#define mmROT0_QM_PQC_LBW_BASE_HI_0 0x4E0A47C

#define mmROT0_QM_PQC_LBW_BASE_HI_1 0x4E0A480

#define mmROT0_QM_PQC_LBW_BASE_HI_2 0x4E0A484

#define mmROT0_QM_PQC_LBW_BASE_HI_3 0x4E0A488

#define mmROT0_QM_PQC_CFG 0x4E0A48C

#define mmROT0_QM_PQC_SECURE_PUSH_IND 0x4E0A490

#define mmROT0_QM_ARB_MASK 0x4E0A4A0

#define mmROT0_QM_ARB_CFG_0 0x4E0A4A4

#define mmROT0_QM_ARB_CHOICE_Q_PUSH 0x4E0A4A8

#define mmROT0_QM_ARB_WRR_WEIGHT_0 0x4E0A4AC

#define mmROT0_QM_ARB_WRR_WEIGHT_1 0x4E0A4B0

#define mmROT0_QM_ARB_WRR_WEIGHT_2 0x4E0A4B4

#define mmROT0_QM_ARB_WRR_WEIGHT_3 0x4E0A4B8

#define mmROT0_QM_ARB_CFG_1 0x4E0A4BC

#define mmROT0_QM_ARB_MST_AVAIL_CRED_0 0x4E0A4C0

#define mmROT0_QM_ARB_MST_AVAIL_CRED_1 0x4E0A4C4

#define mmROT0_QM_ARB_MST_AVAIL_CRED_2 0x4E0A4C8

#define mmROT0_QM_ARB_MST_AVAIL_CRED_3 0x4E0A4CC

#define mmROT0_QM_ARB_MST_AVAIL_CRED_4 0x4E0A4D0

#define mmROT0_QM_ARB_MST_AVAIL_CRED_5 0x4E0A4D4

#define mmROT0_QM_ARB_MST_AVAIL_CRED_6 0x4E0A4D8

#define mmROT0_QM_ARB_MST_AVAIL_CRED_7 0x4E0A4DC

#define mmROT0_QM_ARB_MST_AVAIL_CRED_8 0x4E0A4E0

#define mmROT0_QM_ARB_MST_AVAIL_CRED_9 0x4E0A4E4

#define mmROT0_QM_ARB_MST_AVAIL_CRED_10 0x4E0A4E8

#define mmROT0_QM_ARB_MST_AVAIL_CRED_11 0x4E0A4EC

#define mmROT0_QM_ARB_MST_AVAIL_CRED_12 0x4E0A4F0

#define mmROT0_QM_ARB_MST_AVAIL_CRED_13 0x4E0A4F4

#define mmROT0_QM_ARB_MST_AVAIL_CRED_14 0x4E0A4F8

#define mmROT0_QM_ARB_MST_AVAIL_CRED_15 0x4E0A4FC

#define mmROT0_QM_ARB_MST_AVAIL_CRED_16 0x4E0A500

#define mmROT0_QM_ARB_MST_AVAIL_CRED_17 0x4E0A504

#define mmROT0_QM_ARB_MST_AVAIL_CRED_18 0x4E0A508

#define mmROT0_QM_ARB_MST_AVAIL_CRED_19 0x4E0A50C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_20 0x4E0A510

#define mmROT0_QM_ARB_MST_AVAIL_CRED_21 0x4E0A514

#define mmROT0_QM_ARB_MST_AVAIL_CRED_22 0x4E0A518

#define mmROT0_QM_ARB_MST_AVAIL_CRED_23 0x4E0A51C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_24 0x4E0A520

#define mmROT0_QM_ARB_MST_AVAIL_CRED_25 0x4E0A524

#define mmROT0_QM_ARB_MST_AVAIL_CRED_26 0x4E0A528

#define mmROT0_QM_ARB_MST_AVAIL_CRED_27 0x4E0A52C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_28 0x4E0A530

#define mmROT0_QM_ARB_MST_AVAIL_CRED_29 0x4E0A534

#define mmROT0_QM_ARB_MST_AVAIL_CRED_30 0x4E0A538

#define mmROT0_QM_ARB_MST_AVAIL_CRED_31 0x4E0A53C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_32 0x4E0A540

#define mmROT0_QM_ARB_MST_AVAIL_CRED_33 0x4E0A544

#define mmROT0_QM_ARB_MST_AVAIL_CRED_34 0x4E0A548

#define mmROT0_QM_ARB_MST_AVAIL_CRED_35 0x4E0A54C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_36 0x4E0A550

#define mmROT0_QM_ARB_MST_AVAIL_CRED_37 0x4E0A554

#define mmROT0_QM_ARB_MST_AVAIL_CRED_38 0x4E0A558

#define mmROT0_QM_ARB_MST_AVAIL_CRED_39 0x4E0A55C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_40 0x4E0A560

#define mmROT0_QM_ARB_MST_AVAIL_CRED_41 0x4E0A564

#define mmROT0_QM_ARB_MST_AVAIL_CRED_42 0x4E0A568

#define mmROT0_QM_ARB_MST_AVAIL_CRED_43 0x4E0A56C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_44 0x4E0A570

#define mmROT0_QM_ARB_MST_AVAIL_CRED_45 0x4E0A574

#define mmROT0_QM_ARB_MST_AVAIL_CRED_46 0x4E0A578

#define mmROT0_QM_ARB_MST_AVAIL_CRED_47 0x4E0A57C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_48 0x4E0A580

#define mmROT0_QM_ARB_MST_AVAIL_CRED_49 0x4E0A584

#define mmROT0_QM_ARB_MST_AVAIL_CRED_50 0x4E0A588

#define mmROT0_QM_ARB_MST_AVAIL_CRED_51 0x4E0A58C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_52 0x4E0A590

#define mmROT0_QM_ARB_MST_AVAIL_CRED_53 0x4E0A594

#define mmROT0_QM_ARB_MST_AVAIL_CRED_54 0x4E0A598

#define mmROT0_QM_ARB_MST_AVAIL_CRED_55 0x4E0A59C

#define mmROT0_QM_ARB_MST_AVAIL_CRED_56 0x4E0A5A0

#define mmROT0_QM_ARB_MST_AVAIL_CRED_57 0x4E0A5A4

#define mmROT0_QM_ARB_MST_AVAIL_CRED_58 0x4E0A5A8

#define mmROT0_QM_ARB_MST_AVAIL_CRED_59 0x4E0A5AC

#define mmROT0_QM_ARB_MST_AVAIL_CRED_60 0x4E0A5B0

#define mmROT0_QM_ARB_MST_AVAIL_CRED_61 0x4E0A5B4

#define mmROT0_QM_ARB_MST_AVAIL_CRED_62 0x4E0A5B8

#define mmROT0_QM_ARB_MST_AVAIL_CRED_63 0x4E0A5BC

#define mmROT0_QM_ARB_MST_CRED_INC 0x4E0A5E0

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_0 0x4E0A5E4

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_1 0x4E0A5E8

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_2 0x4E0A5EC

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_3 0x4E0A5F0

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_4 0x4E0A5F4

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_5 0x4E0A5F8

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_6 0x4E0A5FC

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_7 0x4E0A600

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_8 0x4E0A604

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_9 0x4E0A608

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_10 0x4E0A60C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_11 0x4E0A610

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_12 0x4E0A614

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_13 0x4E0A618

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_14 0x4E0A61C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_15 0x4E0A620

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_16 0x4E0A624

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_17 0x4E0A628

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_18 0x4E0A62C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_19 0x4E0A630

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_20 0x4E0A634

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_21 0x4E0A638

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_22 0x4E0A63C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_23 0x4E0A640

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_24 0x4E0A644

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_25 0x4E0A648

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_26 0x4E0A64C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_27 0x4E0A650

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_28 0x4E0A654

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_29 0x4E0A658

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_30 0x4E0A65C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_31 0x4E0A660

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_32 0x4E0A664

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_33 0x4E0A668

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_34 0x4E0A66C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_35 0x4E0A670

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_36 0x4E0A674

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_37 0x4E0A678

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_38 0x4E0A67C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_39 0x4E0A680

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_40 0x4E0A684

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_41 0x4E0A688

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_42 0x4E0A68C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_43 0x4E0A690

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_44 0x4E0A694

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_45 0x4E0A698

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_46 0x4E0A69C

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_47 0x4E0A6A0

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_48 0x4E0A6A4

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_49 0x4E0A6A8

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_50 0x4E0A6AC

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_51 0x4E0A6B0

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_52 0x4E0A6B4

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_53 0x4E0A6B8

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_54 0x4E0A6BC

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_55 0x4E0A6C0

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_56 0x4E0A6C4

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_57 0x4E0A6C8

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_58 0x4E0A6CC

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_59 0x4E0A6D0

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_60 0x4E0A6D4

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_61 0x4E0A6D8

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_62 0x4E0A6DC

#define mmROT0_QM_ARB_MST_CHOICE_PUSH_OFST_63 0x4E0A6E0

#define mmROT0_QM_ARB_SLV_MASTER_INC_CRED_OFST 0x4E0A704

#define mmROT0_QM_ARB_MST_SLAVE_EN 0x4E0A708

#define mmROT0_QM_ARB_MST_SLAVE_EN_1 0x4E0A70C

#define mmROT0_QM_ARB_SLV_CHOICE_WDT 0x4E0A710

#define mmROT0_QM_ARB_SLV_ID 0x4E0A714

#define mmROT0_QM_ARB_MST_QUIET_PER 0x4E0A718

#define mmROT0_QM_ARB_MSG_MAX_INFLIGHT 0x4E0A744

#define mmROT0_QM_ARB_BASE_LO 0x4E0A754

#define mmROT0_QM_ARB_BASE_HI 0x4E0A758

#define mmROT0_QM_ARB_STATE_STS 0x4E0A780

#define mmROT0_QM_ARB_CHOICE_FULLNESS_STS 0x4E0A784

#define mmROT0_QM_ARB_MSG_STS 0x4E0A788

#define mmROT0_QM_ARB_SLV_CHOICE_Q_HEAD 0x4E0A78C

#define mmROT0_QM_ARB_ERR_CAUSE 0x4E0A79C

#define mmROT0_QM_ARB_ERR_MSG_EN 0x4E0A7A0

#define mmROT0_QM_ARB_ERR_STS_DRP 0x4E0A7A8

#define mmROT0_QM_ARB_MST_CRED_STS 0x4E0A7B0

#define mmROT0_QM_ARB_MST_CRED_STS_1 0x4E0A7B4

#define mmROT0_QM_CSMR_STRICT_PRIO_CFG 0x4E0A7FC

#define mmROT0_QM_ARC_CQ_CFG0 0x4E0A800

#define mmROT0_QM_ARC_CQ_CFG1 0x4E0A804

#define mmROT0_QM_ARC_CQ_PTR_LO 0x4E0A808

#define mmROT0_QM_ARC_CQ_PTR_HI 0x4E0A80C

#define mmROT0_QM_ARC_CQ_TSIZE 0x4E0A810

#define mmROT0_QM_ARC_CQ_CTL 0x4E0A814

#define mmROT0_QM_ARC_CQ_IFIFO_STS 0x4E0A81C

#define mmROT0_QM_ARC_CQ_STS0 0x4E0A820

#define mmROT0_QM_ARC_CQ_STS1 0x4E0A824

#define mmROT0_QM_ARC_CQ_TSIZE_STS 0x4E0A828

#define mmROT0_QM_ARC_CQ_PTR_LO_STS 0x4E0A82C

#define mmROT0_QM_ARC_CQ_PTR_HI_STS 0x4E0A830

#define mmROT0_QM_CP_WR_ARC_ADDR_HI 0x4E0A834

#define mmROT0_QM_CP_WR_ARC_ADDR_LO 0x4E0A838

#define mmROT0_QM_ARC_CQ_IFIFO_MSG_BASE_HI 0x4E0A83C

#define mmROT0_QM_ARC_CQ_IFIFO_MSG_BASE_LO 0x4E0A840

#define mmROT0_QM_ARC_CQ_CTL_MSG_BASE_HI 0x4E0A844

#define mmROT0_QM_ARC_CQ_CTL_MSG_BASE_LO 0x4E0A848

#define mmROT0_QM_CQ_IFIFO_MSG_BASE_HI 0x4E0A84C

#define mmROT0_QM_CQ_IFIFO_MSG_BASE_LO 0x4E0A850

#define mmROT0_QM_CQ_CTL_MSG_BASE_HI 0x4E0A854

#define mmROT0_QM_CQ_CTL_MSG_BASE_LO 0x4E0A858

#define mmROT0_QM_ADDR_OVRD 0x4E0A85C

#define mmROT0_QM_CQ_IFIFO_CI_0 0x4E0A860

#define mmROT0_QM_CQ_IFIFO_CI_1 0x4E0A864

#define mmROT0_QM_CQ_IFIFO_CI_2 0x4E0A868

#define mmROT0_QM_CQ_IFIFO_CI_3 0x4E0A86C

#define mmROT0_QM_CQ_IFIFO_CI_4 0x4E0A870

#define mmROT0_QM_ARC_CQ_IFIFO_CI 0x4E0A874

#define mmROT0_QM_CQ_CTL_CI_0 0x4E0A878

#define mmROT0_QM_CQ_CTL_CI_1 0x4E0A87C

#define mmROT0_QM_CQ_CTL_CI_2 0x4E0A880

#define mmROT0_QM_CQ_CTL_CI_3 0x4E0A884

#define mmROT0_QM_CQ_CTL_CI_4 0x4E0A888

#define mmROT0_QM_ARC_CQ_CTL_CI 0x4E0A88C

#define mmROT0_QM_CP_CFG 0x4E0A890

#define mmROT0_QM_CP_EXT_SWITCH 0x4E0A894

#define mmROT0_QM_CP_SWITCH_WD_SET 0x4E0A898

#define mmROT0_QM_CP_SWITCH_WD 0x4E0A89C

#define mmROT0_QM_ARC_LB_ADDR_BASE_LO 0x4E0A8A4

#define mmROT0_QM_ARC_LB_ADDR_BASE_HI 0x4E0A8A8

#define mmROT0_QM_ENGINE_BASE_ADDR_HI 0x4E0A8AC

#define mmROT0_QM_ENGINE_BASE_ADDR_LO 0x4E0A8B0

#define mmROT0_QM_ENGINE_ADDR_RANGE_SIZE 0x4E0A8B4

#define mmROT0_QM_QM_ARC_AUX_BASE_ADDR_HI 0x4E0A8B8

#define mmROT0_QM_QM_ARC_AUX_BASE_ADDR_LO 0x4E0A8BC

#define mmROT0_QM_QM_BASE_ADDR_HI 0x4E0A8C0

#define mmROT0_QM_QM_BASE_ADDR_LO 0x4E0A8C4

#define mmROT0_QM_ARC_PQC_SECURE_PUSH_IND 0x4E0A8C8

#define mmROT0_QM_PQC_STS_0_0 0x4E0A8D0

#define mmROT0_QM_PQC_STS_0_1 0x4E0A8D4

#define mmROT0_QM_PQC_STS_0_2 0x4E0A8D8

#define mmROT0_QM_PQC_STS_0_3 0x4E0A8DC

#define mmROT0_QM_PQC_STS_1_0 0x4E0A8E0

#define mmROT0_QM_PQC_STS_1_1 0x4E0A8E4

#define mmROT0_QM_PQC_STS_1_2 0x4E0A8E8

#define mmROT0_QM_PQC_STS_1_3 0x4E0A8EC

#define mmROT0_QM_SEI_STATUS 0x4E0A8F0

#define mmROT0_QM_SEI_MASK 0x4E0A8F4

#define mmROT0_QM_GLBL_ERR_ADDR_LO 0x4E0AD00

#define mmROT0_QM_GLBL_ERR_ADDR_HI 0x4E0AD04

#define mmROT0_QM_GLBL_ERR_WDATA 0x4E0AD08

#define mmROT0_QM_L2H_MASK_LO 0x4E0AD14

#define mmROT0_QM_L2H_MASK_HI 0x4E0AD18

#define mmROT0_QM_L2H_CMPR_LO 0x4E0AD1C

#define mmROT0_QM_L2H_CMPR_HI 0x4E0AD20

#define mmROT0_QM_LOCAL_RANGE_BASE 0x4E0AD24

#define mmROT0_QM_LOCAL_RANGE_SIZE 0x4E0AD28

#define mmROT0_QM_HBW_RD_RATE_LIM_CFG_1 0x4E0AD30

#define mmROT0_QM_LBW_WR_RATE_LIM_CFG_0 0x4E0AD34

#define mmROT0_QM_LBW_WR_RATE_LIM_CFG_1 0x4E0AD38

#define mmROT0_QM_HBW_RD_RATE_LIM_CFG_0 0x4E0AD3C

#define mmROT0_QM_IND_GW_APB_CFG 0x4E0AD40

#define mmROT0_QM_IND_GW_APB_WDATA 0x4E0AD44

#define mmROT0_QM_IND_GW_APB_RDATA 0x4E0AD48

#define mmROT0_QM_IND_GW_APB_STATUS 0x4E0AD4C

#define mmROT0_QM_PERF_CNT_FREE_LO 0x4E0AD60

#define mmROT0_QM_PERF_CNT_FREE_HI 0x4E0AD64

#define mmROT0_QM_PERF_CNT_IDLE_LO 0x4E0AD68

#define mmROT0_QM_PERF_CNT_IDLE_HI 0x4E0AD6C

#define mmROT0_QM_PERF_CNT_CFG 0x4E0AD70

#endif /* ASIC_REG_ROT0_QM_REGS_H_ */
