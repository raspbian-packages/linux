// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Luca Weiss <luca.weiss@fairphone.com>
 */

#include <linux/device.h>
#include <linux/interconnect.h>
#include <linux/interconnect-provider.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <dt-bindings/interconnect/qcom,sm6350.h>

#include "bcm-voter.h"
#include "icc-rpmh.h"
#include "sm6350.h"

DEFINE_QNODE(qhm_a1noc_cfg, SM6350_MASTER_A1NOC_CFG, 1, 4, SM6350_SLAVE_SERVICE_A1NOC);
DEFINE_QNODE(qhm_qup_0, SM6350_MASTER_QUP_0, 1, 4, SM6350_A1NOC_SNOC_SLV);
DEFINE_QNODE(xm_emmc, SM6350_MASTER_EMMC, 1, 8, SM6350_A1NOC_SNOC_SLV);
DEFINE_QNODE(xm_ufs_mem, SM6350_MASTER_UFS_MEM, 1, 8, SM6350_A1NOC_SNOC_SLV);
DEFINE_QNODE(qhm_a2noc_cfg, SM6350_MASTER_A2NOC_CFG, 1, 4, SM6350_SLAVE_SERVICE_A2NOC);
DEFINE_QNODE(qhm_qdss_bam, SM6350_MASTER_QDSS_BAM, 1, 4, SM6350_A2NOC_SNOC_SLV);
DEFINE_QNODE(qhm_qup_1, SM6350_MASTER_QUP_1, 1, 4, SM6350_A2NOC_SNOC_SLV);
DEFINE_QNODE(qxm_crypto, SM6350_MASTER_CRYPTO_CORE_0, 1, 8, SM6350_A2NOC_SNOC_SLV);
DEFINE_QNODE(qxm_ipa, SM6350_MASTER_IPA, 1, 8, SM6350_A2NOC_SNOC_SLV);
DEFINE_QNODE(xm_qdss_etr, SM6350_MASTER_QDSS_ETR, 1, 8, SM6350_A2NOC_SNOC_SLV);
DEFINE_QNODE(xm_sdc2, SM6350_MASTER_SDCC_2, 1, 8, SM6350_A2NOC_SNOC_SLV);
DEFINE_QNODE(xm_usb3_0, SM6350_MASTER_USB3, 1, 8, SM6350_A2NOC_SNOC_SLV);
DEFINE_QNODE(qxm_camnoc_hf0_uncomp, SM6350_MASTER_CAMNOC_HF0_UNCOMP, 2, 32, SM6350_SLAVE_CAMNOC_UNCOMP);
DEFINE_QNODE(qxm_camnoc_icp_uncomp, SM6350_MASTER_CAMNOC_ICP_UNCOMP, 1, 32, SM6350_SLAVE_CAMNOC_UNCOMP);
DEFINE_QNODE(qxm_camnoc_sf_uncomp, SM6350_MASTER_CAMNOC_SF_UNCOMP, 1, 32, SM6350_SLAVE_CAMNOC_UNCOMP);
DEFINE_QNODE(qup0_core_master, SM6350_MASTER_QUP_CORE_0, 1, 4, SM6350_SLAVE_QUP_CORE_0);
DEFINE_QNODE(qup1_core_master, SM6350_MASTER_QUP_CORE_1, 1, 4, SM6350_SLAVE_QUP_CORE_1);
DEFINE_QNODE(qnm_npu, SM6350_MASTER_NPU, 2, 32, SM6350_SLAVE_CDSP_GEM_NOC);
DEFINE_QNODE(qxm_npu_dsp, SM6350_MASTER_NPU_PROC, 1, 8, SM6350_SLAVE_CDSP_GEM_NOC);
DEFINE_QNODE(qnm_snoc, SM6350_SNOC_CNOC_MAS, 1, 8, SM6350_SLAVE_CAMERA_CFG, SM6350_SLAVE_SDCC_2, SM6350_SLAVE_CNOC_MNOC_CFG, SM6350_SLAVE_UFS_MEM_CFG, SM6350_SLAVE_QM_CFG, SM6350_SLAVE_SNOC_CFG, SM6350_SLAVE_QM_MPU_CFG, SM6350_SLAVE_GLM, SM6350_SLAVE_PDM, SM6350_SLAVE_CAMERA_NRT_THROTTLE_CFG, SM6350_SLAVE_A2NOC_CFG, SM6350_SLAVE_QDSS_CFG, SM6350_SLAVE_VSENSE_CTRL_CFG, SM6350_SLAVE_CAMERA_RT_THROTTLE_CFG, SM6350_SLAVE_DISPLAY_CFG, SM6350_SLAVE_TCSR, SM6350_SLAVE_DCC_CFG, SM6350_SLAVE_CNOC_DDRSS, SM6350_SLAVE_DISPLAY_THROTTLE_CFG, SM6350_SLAVE_NPU_CFG, SM6350_SLAVE_AHB2PHY, SM6350_SLAVE_GRAPHICS_3D_CFG, SM6350_SLAVE_BOOT_ROM, SM6350_SLAVE_VENUS_CFG, SM6350_SLAVE_IPA_CFG, SM6350_SLAVE_SECURITY, SM6350_SLAVE_IMEM_CFG, SM6350_SLAVE_CNOC_MSS, SM6350_SLAVE_SERVICE_CNOC, SM6350_SLAVE_USB3, SM6350_SLAVE_VENUS_THROTTLE_CFG, SM6350_SLAVE_RBCPR_CX_CFG, SM6350_SLAVE_A1NOC_CFG, SM6350_SLAVE_AOSS, SM6350_SLAVE_PRNG, SM6350_SLAVE_EMMC_CFG, SM6350_SLAVE_CRYPTO_0_CFG, SM6350_SLAVE_PIMEM_CFG, SM6350_SLAVE_RBCPR_MX_CFG, SM6350_SLAVE_QUP_0, SM6350_SLAVE_QUP_1, SM6350_SLAVE_CLK_CTL);
DEFINE_QNODE(xm_qdss_dap, SM6350_MASTER_QDSS_DAP, 1, 8, SM6350_SLAVE_CAMERA_CFG, SM6350_SLAVE_SDCC_2, SM6350_SLAVE_CNOC_MNOC_CFG, SM6350_SLAVE_UFS_MEM_CFG, SM6350_SLAVE_QM_CFG, SM6350_SLAVE_SNOC_CFG, SM6350_SLAVE_QM_MPU_CFG, SM6350_SLAVE_GLM, SM6350_SLAVE_PDM, SM6350_SLAVE_CAMERA_NRT_THROTTLE_CFG, SM6350_SLAVE_A2NOC_CFG, SM6350_SLAVE_QDSS_CFG, SM6350_SLAVE_VSENSE_CTRL_CFG, SM6350_SLAVE_CAMERA_RT_THROTTLE_CFG, SM6350_SLAVE_DISPLAY_CFG, SM6350_SLAVE_TCSR, SM6350_SLAVE_DCC_CFG, SM6350_SLAVE_CNOC_DDRSS, SM6350_SLAVE_DISPLAY_THROTTLE_CFG, SM6350_SLAVE_NPU_CFG, SM6350_SLAVE_AHB2PHY, SM6350_SLAVE_GRAPHICS_3D_CFG, SM6350_SLAVE_BOOT_ROM, SM6350_SLAVE_VENUS_CFG, SM6350_SLAVE_IPA_CFG, SM6350_SLAVE_SECURITY, SM6350_SLAVE_IMEM_CFG, SM6350_SLAVE_CNOC_MSS, SM6350_SLAVE_SERVICE_CNOC, SM6350_SLAVE_USB3, SM6350_SLAVE_VENUS_THROTTLE_CFG, SM6350_SLAVE_RBCPR_CX_CFG, SM6350_SLAVE_A1NOC_CFG, SM6350_SLAVE_AOSS, SM6350_SLAVE_PRNG, SM6350_SLAVE_EMMC_CFG, SM6350_SLAVE_CRYPTO_0_CFG, SM6350_SLAVE_PIMEM_CFG, SM6350_SLAVE_RBCPR_MX_CFG, SM6350_SLAVE_QUP_0, SM6350_SLAVE_QUP_1, SM6350_SLAVE_CLK_CTL);
DEFINE_QNODE(qhm_cnoc_dc_noc, SM6350_MASTER_CNOC_DC_NOC, 1, 4, SM6350_SLAVE_LLCC_CFG, SM6350_SLAVE_GEM_NOC_CFG);
DEFINE_QNODE(acm_apps, SM6350_MASTER_AMPSS_M0, 1, 16, SM6350_SLAVE_LLCC, SM6350_SLAVE_GEM_NOC_SNOC);
DEFINE_QNODE(acm_sys_tcu, SM6350_MASTER_SYS_TCU, 1, 8, SM6350_SLAVE_LLCC, SM6350_SLAVE_GEM_NOC_SNOC);
DEFINE_QNODE(qhm_gemnoc_cfg, SM6350_MASTER_GEM_NOC_CFG, 1, 4, SM6350_SLAVE_MCDMA_MS_MPU_CFG, SM6350_SLAVE_SERVICE_GEM_NOC, SM6350_SLAVE_MSS_PROC_MS_MPU_CFG);
DEFINE_QNODE(qnm_cmpnoc, SM6350_MASTER_COMPUTE_NOC, 1, 32, SM6350_SLAVE_LLCC, SM6350_SLAVE_GEM_NOC_SNOC);
DEFINE_QNODE(qnm_mnoc_hf, SM6350_MASTER_MNOC_HF_MEM_NOC, 1, 32, SM6350_SLAVE_LLCC, SM6350_SLAVE_GEM_NOC_SNOC);
DEFINE_QNODE(qnm_mnoc_sf, SM6350_MASTER_MNOC_SF_MEM_NOC, 1, 32, SM6350_SLAVE_LLCC, SM6350_SLAVE_GEM_NOC_SNOC);
DEFINE_QNODE(qnm_snoc_gc, SM6350_MASTER_SNOC_GC_MEM_NOC, 1, 8, SM6350_SLAVE_LLCC);
DEFINE_QNODE(qnm_snoc_sf, SM6350_MASTER_SNOC_SF_MEM_NOC, 1, 16, SM6350_SLAVE_LLCC);
DEFINE_QNODE(qxm_gpu, SM6350_MASTER_GRAPHICS_3D, 2, 32, SM6350_SLAVE_LLCC, SM6350_SLAVE_GEM_NOC_SNOC);
DEFINE_QNODE(llcc_mc, SM6350_MASTER_LLCC, 2, 4, SM6350_SLAVE_EBI_CH0);
DEFINE_QNODE(qhm_mnoc_cfg, SM6350_MASTER_CNOC_MNOC_CFG, 1, 4, SM6350_SLAVE_SERVICE_MNOC);
DEFINE_QNODE(qnm_video0, SM6350_MASTER_VIDEO_P0, 1, 32, SM6350_SLAVE_MNOC_SF_MEM_NOC);
DEFINE_QNODE(qnm_video_cvp, SM6350_MASTER_VIDEO_PROC, 1, 8, SM6350_SLAVE_MNOC_SF_MEM_NOC);
DEFINE_QNODE(qxm_camnoc_hf, SM6350_MASTER_CAMNOC_HF, 2, 32, SM6350_SLAVE_MNOC_HF_MEM_NOC);
DEFINE_QNODE(qxm_camnoc_icp, SM6350_MASTER_CAMNOC_ICP, 1, 8, SM6350_SLAVE_MNOC_SF_MEM_NOC);
DEFINE_QNODE(qxm_camnoc_sf, SM6350_MASTER_CAMNOC_SF, 1, 32, SM6350_SLAVE_MNOC_SF_MEM_NOC);
DEFINE_QNODE(qxm_mdp0, SM6350_MASTER_MDP_PORT0, 1, 32, SM6350_SLAVE_MNOC_HF_MEM_NOC);
DEFINE_QNODE(amm_npu_sys, SM6350_MASTER_NPU_SYS, 2, 32, SM6350_SLAVE_NPU_COMPUTE_NOC);
DEFINE_QNODE(qhm_npu_cfg, SM6350_MASTER_NPU_NOC_CFG, 1, 4, SM6350_SLAVE_SERVICE_NPU_NOC, SM6350_SLAVE_ISENSE_CFG, SM6350_SLAVE_NPU_LLM_CFG, SM6350_SLAVE_NPU_INT_DMA_BWMON_CFG, SM6350_SLAVE_NPU_CP, SM6350_SLAVE_NPU_TCM, SM6350_SLAVE_NPU_CAL_DP0, SM6350_SLAVE_NPU_DPM);
DEFINE_QNODE(qhm_snoc_cfg, SM6350_MASTER_SNOC_CFG, 1, 4, SM6350_SLAVE_SERVICE_SNOC);
DEFINE_QNODE(qnm_aggre1_noc, SM6350_A1NOC_SNOC_MAS, 1, 16, SM6350_SLAVE_SNOC_GEM_NOC_SF, SM6350_SLAVE_PIMEM, SM6350_SLAVE_OCIMEM, SM6350_SLAVE_APPSS, SM6350_SNOC_CNOC_SLV, SM6350_SLAVE_QDSS_STM);
DEFINE_QNODE(qnm_aggre2_noc, SM6350_A2NOC_SNOC_MAS, 1, 16, SM6350_SLAVE_SNOC_GEM_NOC_SF, SM6350_SLAVE_PIMEM, SM6350_SLAVE_OCIMEM, SM6350_SLAVE_APPSS, SM6350_SNOC_CNOC_SLV, SM6350_SLAVE_TCU, SM6350_SLAVE_QDSS_STM);
DEFINE_QNODE(qnm_gemnoc, SM6350_MASTER_GEM_NOC_SNOC, 1, 8, SM6350_SLAVE_PIMEM, SM6350_SLAVE_OCIMEM, SM6350_SLAVE_APPSS, SM6350_SNOC_CNOC_SLV, SM6350_SLAVE_TCU, SM6350_SLAVE_QDSS_STM);
DEFINE_QNODE(qxm_pimem, SM6350_MASTER_PIMEM, 1, 8, SM6350_SLAVE_SNOC_GEM_NOC_GC, SM6350_SLAVE_OCIMEM);
DEFINE_QNODE(xm_gic, SM6350_MASTER_GIC, 1, 8, SM6350_SLAVE_SNOC_GEM_NOC_GC);
DEFINE_QNODE(qns_a1noc_snoc, SM6350_A1NOC_SNOC_SLV, 1, 16, SM6350_A1NOC_SNOC_MAS);
DEFINE_QNODE(srvc_aggre1_noc, SM6350_SLAVE_SERVICE_A1NOC, 1, 4);
DEFINE_QNODE(qns_a2noc_snoc, SM6350_A2NOC_SNOC_SLV, 1, 16, SM6350_A2NOC_SNOC_MAS);
DEFINE_QNODE(srvc_aggre2_noc, SM6350_SLAVE_SERVICE_A2NOC, 1, 4);
DEFINE_QNODE(qns_camnoc_uncomp, SM6350_SLAVE_CAMNOC_UNCOMP, 1, 32);
DEFINE_QNODE(qup0_core_slave, SM6350_SLAVE_QUP_CORE_0, 1, 4);
DEFINE_QNODE(qup1_core_slave, SM6350_SLAVE_QUP_CORE_1, 1, 4);
DEFINE_QNODE(qns_cdsp_gemnoc, SM6350_SLAVE_CDSP_GEM_NOC, 1, 32, SM6350_MASTER_COMPUTE_NOC);
DEFINE_QNODE(qhs_a1_noc_cfg, SM6350_SLAVE_A1NOC_CFG, 1, 4, SM6350_MASTER_A1NOC_CFG);
DEFINE_QNODE(qhs_a2_noc_cfg, SM6350_SLAVE_A2NOC_CFG, 1, 4, SM6350_MASTER_A2NOC_CFG);
DEFINE_QNODE(qhs_ahb2phy0, SM6350_SLAVE_AHB2PHY, 1, 4);
DEFINE_QNODE(qhs_ahb2phy2, SM6350_SLAVE_AHB2PHY_2, 1, 4);
DEFINE_QNODE(qhs_aoss, SM6350_SLAVE_AOSS, 1, 4);
DEFINE_QNODE(qhs_boot_rom, SM6350_SLAVE_BOOT_ROM, 1, 4);
DEFINE_QNODE(qhs_camera_cfg, SM6350_SLAVE_CAMERA_CFG, 1, 4);
DEFINE_QNODE(qhs_camera_nrt_thrott_cfg, SM6350_SLAVE_CAMERA_NRT_THROTTLE_CFG, 1, 4);
DEFINE_QNODE(qhs_camera_rt_throttle_cfg, SM6350_SLAVE_CAMERA_RT_THROTTLE_CFG, 1, 4);
DEFINE_QNODE(qhs_clk_ctl, SM6350_SLAVE_CLK_CTL, 1, 4);
DEFINE_QNODE(qhs_cpr_cx, SM6350_SLAVE_RBCPR_CX_CFG, 1, 4);
DEFINE_QNODE(qhs_cpr_mx, SM6350_SLAVE_RBCPR_MX_CFG, 1, 4);
DEFINE_QNODE(qhs_crypto0_cfg, SM6350_SLAVE_CRYPTO_0_CFG, 1, 4);
DEFINE_QNODE(qhs_dcc_cfg, SM6350_SLAVE_DCC_CFG, 1, 4);
DEFINE_QNODE(qhs_ddrss_cfg, SM6350_SLAVE_CNOC_DDRSS, 1, 4, SM6350_MASTER_CNOC_DC_NOC);
DEFINE_QNODE(qhs_display_cfg, SM6350_SLAVE_DISPLAY_CFG, 1, 4);
DEFINE_QNODE(qhs_display_throttle_cfg, SM6350_SLAVE_DISPLAY_THROTTLE_CFG, 1, 4);
DEFINE_QNODE(qhs_emmc_cfg, SM6350_SLAVE_EMMC_CFG, 1, 4);
DEFINE_QNODE(qhs_glm, SM6350_SLAVE_GLM, 1, 4);
DEFINE_QNODE(qhs_gpuss_cfg, SM6350_SLAVE_GRAPHICS_3D_CFG, 1, 8);
DEFINE_QNODE(qhs_imem_cfg, SM6350_SLAVE_IMEM_CFG, 1, 4);
DEFINE_QNODE(qhs_ipa, SM6350_SLAVE_IPA_CFG, 1, 4);
DEFINE_QNODE(qhs_mnoc_cfg, SM6350_SLAVE_CNOC_MNOC_CFG, 1, 4, SM6350_MASTER_CNOC_MNOC_CFG);
DEFINE_QNODE(qhs_mss_cfg, SM6350_SLAVE_CNOC_MSS, 1, 4);
DEFINE_QNODE(qhs_npu_cfg, SM6350_SLAVE_NPU_CFG, 1, 4, SM6350_MASTER_NPU_NOC_CFG);
DEFINE_QNODE(qhs_pdm, SM6350_SLAVE_PDM, 1, 4);
DEFINE_QNODE(qhs_pimem_cfg, SM6350_SLAVE_PIMEM_CFG, 1, 4);
DEFINE_QNODE(qhs_prng, SM6350_SLAVE_PRNG, 1, 4);
DEFINE_QNODE(qhs_qdss_cfg, SM6350_SLAVE_QDSS_CFG, 1, 4);
DEFINE_QNODE(qhs_qm_cfg, SM6350_SLAVE_QM_CFG, 1, 4);
DEFINE_QNODE(qhs_qm_mpu_cfg, SM6350_SLAVE_QM_MPU_CFG, 1, 4);
DEFINE_QNODE(qhs_qup0, SM6350_SLAVE_QUP_0, 1, 4);
DEFINE_QNODE(qhs_qup1, SM6350_SLAVE_QUP_1, 1, 4);
DEFINE_QNODE(qhs_sdc2, SM6350_SLAVE_SDCC_2, 1, 4);
DEFINE_QNODE(qhs_security, SM6350_SLAVE_SECURITY, 1, 4);
DEFINE_QNODE(qhs_snoc_cfg, SM6350_SLAVE_SNOC_CFG, 1, 4, SM6350_MASTER_SNOC_CFG);
DEFINE_QNODE(qhs_tcsr, SM6350_SLAVE_TCSR, 1, 4);
DEFINE_QNODE(qhs_ufs_mem_cfg, SM6350_SLAVE_UFS_MEM_CFG, 1, 4);
DEFINE_QNODE(qhs_usb3_0, SM6350_SLAVE_USB3, 1, 4);
DEFINE_QNODE(qhs_venus_cfg, SM6350_SLAVE_VENUS_CFG, 1, 4);
DEFINE_QNODE(qhs_venus_throttle_cfg, SM6350_SLAVE_VENUS_THROTTLE_CFG, 1, 4);
DEFINE_QNODE(qhs_vsense_ctrl_cfg, SM6350_SLAVE_VSENSE_CTRL_CFG, 1, 4);
DEFINE_QNODE(srvc_cnoc, SM6350_SLAVE_SERVICE_CNOC, 1, 4);
DEFINE_QNODE(qhs_gemnoc, SM6350_SLAVE_GEM_NOC_CFG, 1, 4, SM6350_MASTER_GEM_NOC_CFG);
DEFINE_QNODE(qhs_llcc, SM6350_SLAVE_LLCC_CFG, 1, 4);
DEFINE_QNODE(qhs_mcdma_ms_mpu_cfg, SM6350_SLAVE_MCDMA_MS_MPU_CFG, 1, 4);
DEFINE_QNODE(qhs_mdsp_ms_mpu_cfg, SM6350_SLAVE_MSS_PROC_MS_MPU_CFG, 1, 4);
DEFINE_QNODE(qns_gem_noc_snoc, SM6350_SLAVE_GEM_NOC_SNOC, 1, 8, SM6350_MASTER_GEM_NOC_SNOC);
DEFINE_QNODE(qns_llcc, SM6350_SLAVE_LLCC, 1, 16, SM6350_MASTER_LLCC);
DEFINE_QNODE(srvc_gemnoc, SM6350_SLAVE_SERVICE_GEM_NOC, 1, 4);
DEFINE_QNODE(ebi, SM6350_SLAVE_EBI_CH0, 2, 4);
DEFINE_QNODE(qns_mem_noc_hf, SM6350_SLAVE_MNOC_HF_MEM_NOC, 1, 32, SM6350_MASTER_MNOC_HF_MEM_NOC);
DEFINE_QNODE(qns_mem_noc_sf, SM6350_SLAVE_MNOC_SF_MEM_NOC, 1, 32, SM6350_MASTER_MNOC_SF_MEM_NOC);
DEFINE_QNODE(srvc_mnoc, SM6350_SLAVE_SERVICE_MNOC, 1, 4);
DEFINE_QNODE(qhs_cal_dp0, SM6350_SLAVE_NPU_CAL_DP0, 1, 4);
DEFINE_QNODE(qhs_cp, SM6350_SLAVE_NPU_CP, 1, 4);
DEFINE_QNODE(qhs_dma_bwmon, SM6350_SLAVE_NPU_INT_DMA_BWMON_CFG, 1, 4);
DEFINE_QNODE(qhs_dpm, SM6350_SLAVE_NPU_DPM, 1, 4);
DEFINE_QNODE(qhs_isense, SM6350_SLAVE_ISENSE_CFG, 1, 4);
DEFINE_QNODE(qhs_llm, SM6350_SLAVE_NPU_LLM_CFG, 1, 4);
DEFINE_QNODE(qhs_tcm, SM6350_SLAVE_NPU_TCM, 1, 4);
DEFINE_QNODE(qns_npu_sys, SM6350_SLAVE_NPU_COMPUTE_NOC, 2, 32);
DEFINE_QNODE(srvc_noc, SM6350_SLAVE_SERVICE_NPU_NOC, 1, 4);
DEFINE_QNODE(qhs_apss, SM6350_SLAVE_APPSS, 1, 8);
DEFINE_QNODE(qns_cnoc, SM6350_SNOC_CNOC_SLV, 1, 8, SM6350_SNOC_CNOC_MAS);
DEFINE_QNODE(qns_gemnoc_gc, SM6350_SLAVE_SNOC_GEM_NOC_GC, 1, 8, SM6350_MASTER_SNOC_GC_MEM_NOC);
DEFINE_QNODE(qns_gemnoc_sf, SM6350_SLAVE_SNOC_GEM_NOC_SF, 1, 16, SM6350_MASTER_SNOC_SF_MEM_NOC);
DEFINE_QNODE(qxs_imem, SM6350_SLAVE_OCIMEM, 1, 8);
DEFINE_QNODE(qxs_pimem, SM6350_SLAVE_PIMEM, 1, 8);
DEFINE_QNODE(srvc_snoc, SM6350_SLAVE_SERVICE_SNOC, 1, 4);
DEFINE_QNODE(xs_qdss_stm, SM6350_SLAVE_QDSS_STM, 1, 4);
DEFINE_QNODE(xs_sys_tcu_cfg, SM6350_SLAVE_TCU, 1, 8);

DEFINE_QBCM(bcm_acv, "ACV", false, &ebi);
DEFINE_QBCM(bcm_ce0, "CE0", false, &qxm_crypto);
DEFINE_QBCM(bcm_cn0, "CN0", true, &qnm_snoc, &xm_qdss_dap, &qhs_a1_noc_cfg, &qhs_a2_noc_cfg, &qhs_ahb2phy0, &qhs_aoss, &qhs_boot_rom, &qhs_camera_cfg, &qhs_camera_nrt_thrott_cfg, &qhs_camera_rt_throttle_cfg, &qhs_clk_ctl, &qhs_cpr_cx, &qhs_cpr_mx, &qhs_crypto0_cfg, &qhs_dcc_cfg, &qhs_ddrss_cfg, &qhs_display_cfg, &qhs_display_throttle_cfg, &qhs_glm, &qhs_gpuss_cfg, &qhs_imem_cfg, &qhs_ipa, &qhs_mnoc_cfg, &qhs_mss_cfg, &qhs_npu_cfg, &qhs_pimem_cfg, &qhs_prng, &qhs_qdss_cfg, &qhs_qm_cfg, &qhs_qm_mpu_cfg, &qhs_qup0, &qhs_qup1, &qhs_security, &qhs_snoc_cfg, &qhs_tcsr, &qhs_ufs_mem_cfg, &qhs_usb3_0, &qhs_venus_cfg, &qhs_venus_throttle_cfg, &qhs_vsense_ctrl_cfg, &srvc_cnoc);
DEFINE_QBCM(bcm_cn1, "CN1", false, &xm_emmc, &xm_sdc2, &qhs_ahb2phy2, &qhs_emmc_cfg, &qhs_pdm, &qhs_sdc2);
DEFINE_QBCM(bcm_co0, "CO0", false, &qns_cdsp_gemnoc);
DEFINE_QBCM(bcm_co2, "CO2", false, &qnm_npu);
DEFINE_QBCM(bcm_co3, "CO3", false, &qxm_npu_dsp);
DEFINE_QBCM(bcm_mc0, "MC0", true, &ebi);
DEFINE_QBCM(bcm_mm0, "MM0", true, &qns_mem_noc_hf);
DEFINE_QBCM(bcm_mm1, "MM1", true, &qxm_camnoc_hf0_uncomp, &qxm_camnoc_icp_uncomp, &qxm_camnoc_sf_uncomp, &qxm_camnoc_hf, &qxm_mdp0);
DEFINE_QBCM(bcm_mm2, "MM2", false, &qns_mem_noc_sf);
DEFINE_QBCM(bcm_mm3, "MM3", false, &qhm_mnoc_cfg, &qnm_video0, &qnm_video_cvp, &qxm_camnoc_sf);
DEFINE_QBCM(bcm_qup0, "QUP0", false, &qup0_core_master, &qup1_core_master, &qup0_core_slave, &qup1_core_slave);
DEFINE_QBCM(bcm_sh0, "SH0", true, &qns_llcc);
DEFINE_QBCM(bcm_sh2, "SH2", false, &acm_sys_tcu);
DEFINE_QBCM(bcm_sh3, "SH3", false, &qnm_cmpnoc);
DEFINE_QBCM(bcm_sh4, "SH4", false, &acm_apps);
DEFINE_QBCM(bcm_sn0, "SN0", true, &qns_gemnoc_sf);
DEFINE_QBCM(bcm_sn1, "SN1", false, &qxs_imem);
DEFINE_QBCM(bcm_sn2, "SN2", false, &qns_gemnoc_gc);
DEFINE_QBCM(bcm_sn3, "SN3", false, &qxs_pimem);
DEFINE_QBCM(bcm_sn4, "SN4", false, &xs_qdss_stm);
DEFINE_QBCM(bcm_sn5, "SN5", false, &qnm_aggre1_noc);
DEFINE_QBCM(bcm_sn6, "SN6", false, &qnm_aggre2_noc);
DEFINE_QBCM(bcm_sn10, "SN10", false, &qnm_gemnoc);

static struct qcom_icc_bcm * const aggre1_noc_bcms[] = {
	&bcm_cn1,
};

static struct qcom_icc_node * const aggre1_noc_nodes[] = {
	[MASTER_A1NOC_CFG] = &qhm_a1noc_cfg,
	[MASTER_QUP_0] = &qhm_qup_0,
	[MASTER_EMMC] = &xm_emmc,
	[MASTER_UFS_MEM] = &xm_ufs_mem,
	[A1NOC_SNOC_SLV] = &qns_a1noc_snoc,
	[SLAVE_SERVICE_A1NOC] = &srvc_aggre1_noc,
};

static const struct qcom_icc_desc sm6350_aggre1_noc = {
	.nodes = aggre1_noc_nodes,
	.num_nodes = ARRAY_SIZE(aggre1_noc_nodes),
	.bcms = aggre1_noc_bcms,
	.num_bcms = ARRAY_SIZE(aggre1_noc_bcms),
};

static struct qcom_icc_bcm * const aggre2_noc_bcms[] = {
	&bcm_ce0,
	&bcm_cn1,
};

static struct qcom_icc_node * const aggre2_noc_nodes[] = {
	[MASTER_A2NOC_CFG] = &qhm_a2noc_cfg,
	[MASTER_QDSS_BAM] = &qhm_qdss_bam,
	[MASTER_QUP_1] = &qhm_qup_1,
	[MASTER_CRYPTO_CORE_0] = &qxm_crypto,
	[MASTER_IPA] = &qxm_ipa,
	[MASTER_QDSS_ETR] = &xm_qdss_etr,
	[MASTER_SDCC_2] = &xm_sdc2,
	[MASTER_USB3] = &xm_usb3_0,
	[A2NOC_SNOC_SLV] = &qns_a2noc_snoc,
	[SLAVE_SERVICE_A2NOC] = &srvc_aggre2_noc,
};

static const struct qcom_icc_desc sm6350_aggre2_noc = {
	.nodes = aggre2_noc_nodes,
	.num_nodes = ARRAY_SIZE(aggre2_noc_nodes),
	.bcms = aggre2_noc_bcms,
	.num_bcms = ARRAY_SIZE(aggre2_noc_bcms),
};

static struct qcom_icc_bcm * const clk_virt_bcms[] = {
	&bcm_acv,
	&bcm_mc0,
	&bcm_mm1,
	&bcm_qup0,
};

static struct qcom_icc_node * const clk_virt_nodes[] = {
	[MASTER_CAMNOC_HF0_UNCOMP] = &qxm_camnoc_hf0_uncomp,
	[MASTER_CAMNOC_ICP_UNCOMP] = &qxm_camnoc_icp_uncomp,
	[MASTER_CAMNOC_SF_UNCOMP] = &qxm_camnoc_sf_uncomp,
	[MASTER_QUP_CORE_0] = &qup0_core_master,
	[MASTER_QUP_CORE_1] = &qup1_core_master,
	[MASTER_LLCC] = &llcc_mc,
	[SLAVE_CAMNOC_UNCOMP] = &qns_camnoc_uncomp,
	[SLAVE_QUP_CORE_0] = &qup0_core_slave,
	[SLAVE_QUP_CORE_1] = &qup1_core_slave,
	[SLAVE_EBI_CH0] = &ebi,
};

static const struct qcom_icc_desc sm6350_clk_virt = {
	.nodes = clk_virt_nodes,
	.num_nodes = ARRAY_SIZE(clk_virt_nodes),
	.bcms = clk_virt_bcms,
	.num_bcms = ARRAY_SIZE(clk_virt_bcms),
};

static struct qcom_icc_bcm * const compute_noc_bcms[] = {
	&bcm_co0,
	&bcm_co2,
	&bcm_co3,
};

static struct qcom_icc_node * const compute_noc_nodes[] = {
	[MASTER_NPU] = &qnm_npu,
	[MASTER_NPU_PROC] = &qxm_npu_dsp,
	[SLAVE_CDSP_GEM_NOC] = &qns_cdsp_gemnoc,
};

static const struct qcom_icc_desc sm6350_compute_noc = {
	.nodes = compute_noc_nodes,
	.num_nodes = ARRAY_SIZE(compute_noc_nodes),
	.bcms = compute_noc_bcms,
	.num_bcms = ARRAY_SIZE(compute_noc_bcms),
};

static struct qcom_icc_bcm * const config_noc_bcms[] = {
	&bcm_cn0,
	&bcm_cn1,
};

static struct qcom_icc_node * const config_noc_nodes[] = {
	[SNOC_CNOC_MAS] = &qnm_snoc,
	[MASTER_QDSS_DAP] = &xm_qdss_dap,
	[SLAVE_A1NOC_CFG] = &qhs_a1_noc_cfg,
	[SLAVE_A2NOC_CFG] = &qhs_a2_noc_cfg,
	[SLAVE_AHB2PHY] = &qhs_ahb2phy0,
	[SLAVE_AHB2PHY_2] = &qhs_ahb2phy2,
	[SLAVE_AOSS] = &qhs_aoss,
	[SLAVE_BOOT_ROM] = &qhs_boot_rom,
	[SLAVE_CAMERA_CFG] = &qhs_camera_cfg,
	[SLAVE_CAMERA_NRT_THROTTLE_CFG] = &qhs_camera_nrt_thrott_cfg,
	[SLAVE_CAMERA_RT_THROTTLE_CFG] = &qhs_camera_rt_throttle_cfg,
	[SLAVE_CLK_CTL] = &qhs_clk_ctl,
	[SLAVE_RBCPR_CX_CFG] = &qhs_cpr_cx,
	[SLAVE_RBCPR_MX_CFG] = &qhs_cpr_mx,
	[SLAVE_CRYPTO_0_CFG] = &qhs_crypto0_cfg,
	[SLAVE_DCC_CFG] = &qhs_dcc_cfg,
	[SLAVE_CNOC_DDRSS] = &qhs_ddrss_cfg,
	[SLAVE_DISPLAY_CFG] = &qhs_display_cfg,
	[SLAVE_DISPLAY_THROTTLE_CFG] = &qhs_display_throttle_cfg,
	[SLAVE_EMMC_CFG] = &qhs_emmc_cfg,
	[SLAVE_GLM] = &qhs_glm,
	[SLAVE_GRAPHICS_3D_CFG] = &qhs_gpuss_cfg,
	[SLAVE_IMEM_CFG] = &qhs_imem_cfg,
	[SLAVE_IPA_CFG] = &qhs_ipa,
	[SLAVE_CNOC_MNOC_CFG] = &qhs_mnoc_cfg,
	[SLAVE_CNOC_MSS] = &qhs_mss_cfg,
	[SLAVE_NPU_CFG] = &qhs_npu_cfg,
	[SLAVE_PDM] = &qhs_pdm,
	[SLAVE_PIMEM_CFG] = &qhs_pimem_cfg,
	[SLAVE_PRNG] = &qhs_prng,
	[SLAVE_QDSS_CFG] = &qhs_qdss_cfg,
	[SLAVE_QM_CFG] = &qhs_qm_cfg,
	[SLAVE_QM_MPU_CFG] = &qhs_qm_mpu_cfg,
	[SLAVE_QUP_0] = &qhs_qup0,
	[SLAVE_QUP_1] = &qhs_qup1,
	[SLAVE_SDCC_2] = &qhs_sdc2,
	[SLAVE_SECURITY] = &qhs_security,
	[SLAVE_SNOC_CFG] = &qhs_snoc_cfg,
	[SLAVE_TCSR] = &qhs_tcsr,
	[SLAVE_UFS_MEM_CFG] = &qhs_ufs_mem_cfg,
	[SLAVE_USB3] = &qhs_usb3_0,
	[SLAVE_VENUS_CFG] = &qhs_venus_cfg,
	[SLAVE_VENUS_THROTTLE_CFG] = &qhs_venus_throttle_cfg,
	[SLAVE_VSENSE_CTRL_CFG] = &qhs_vsense_ctrl_cfg,
	[SLAVE_SERVICE_CNOC] = &srvc_cnoc,
};

static const struct qcom_icc_desc sm6350_config_noc = {
	.nodes = config_noc_nodes,
	.num_nodes = ARRAY_SIZE(config_noc_nodes),
	.bcms = config_noc_bcms,
	.num_bcms = ARRAY_SIZE(config_noc_bcms),
};

static struct qcom_icc_bcm * const dc_noc_bcms[] = {
};

static struct qcom_icc_node * const dc_noc_nodes[] = {
	[MASTER_CNOC_DC_NOC] = &qhm_cnoc_dc_noc,
	[SLAVE_GEM_NOC_CFG] = &qhs_gemnoc,
	[SLAVE_LLCC_CFG] = &qhs_llcc,
};

static const struct qcom_icc_desc sm6350_dc_noc = {
	.nodes = dc_noc_nodes,
	.num_nodes = ARRAY_SIZE(dc_noc_nodes),
	.bcms = dc_noc_bcms,
	.num_bcms = ARRAY_SIZE(dc_noc_bcms),
};

static struct qcom_icc_bcm * const gem_noc_bcms[] = {
	&bcm_sh0,
	&bcm_sh2,
	&bcm_sh3,
	&bcm_sh4,
};

static struct qcom_icc_node * const gem_noc_nodes[] = {
	[MASTER_AMPSS_M0] = &acm_apps,
	[MASTER_SYS_TCU] = &acm_sys_tcu,
	[MASTER_GEM_NOC_CFG] = &qhm_gemnoc_cfg,
	[MASTER_COMPUTE_NOC] = &qnm_cmpnoc,
	[MASTER_MNOC_HF_MEM_NOC] = &qnm_mnoc_hf,
	[MASTER_MNOC_SF_MEM_NOC] = &qnm_mnoc_sf,
	[MASTER_SNOC_GC_MEM_NOC] = &qnm_snoc_gc,
	[MASTER_SNOC_SF_MEM_NOC] = &qnm_snoc_sf,
	[MASTER_GRAPHICS_3D] = &qxm_gpu,
	[SLAVE_MCDMA_MS_MPU_CFG] = &qhs_mcdma_ms_mpu_cfg,
	[SLAVE_MSS_PROC_MS_MPU_CFG] = &qhs_mdsp_ms_mpu_cfg,
	[SLAVE_GEM_NOC_SNOC] = &qns_gem_noc_snoc,
	[SLAVE_LLCC] = &qns_llcc,
	[SLAVE_SERVICE_GEM_NOC] = &srvc_gemnoc,
};

static const struct qcom_icc_desc sm6350_gem_noc = {
	.nodes = gem_noc_nodes,
	.num_nodes = ARRAY_SIZE(gem_noc_nodes),
	.bcms = gem_noc_bcms,
	.num_bcms = ARRAY_SIZE(gem_noc_bcms),
};

static struct qcom_icc_bcm * const mmss_noc_bcms[] = {
	&bcm_mm0,
	&bcm_mm1,
	&bcm_mm2,
	&bcm_mm3,
};

static struct qcom_icc_node * const mmss_noc_nodes[] = {
	[MASTER_CNOC_MNOC_CFG] = &qhm_mnoc_cfg,
	[MASTER_VIDEO_P0] = &qnm_video0,
	[MASTER_VIDEO_PROC] = &qnm_video_cvp,
	[MASTER_CAMNOC_HF] = &qxm_camnoc_hf,
	[MASTER_CAMNOC_ICP] = &qxm_camnoc_icp,
	[MASTER_CAMNOC_SF] = &qxm_camnoc_sf,
	[MASTER_MDP_PORT0] = &qxm_mdp0,
	[SLAVE_MNOC_HF_MEM_NOC] = &qns_mem_noc_hf,
	[SLAVE_MNOC_SF_MEM_NOC] = &qns_mem_noc_sf,
	[SLAVE_SERVICE_MNOC] = &srvc_mnoc,
};

static const struct qcom_icc_desc sm6350_mmss_noc = {
	.nodes = mmss_noc_nodes,
	.num_nodes = ARRAY_SIZE(mmss_noc_nodes),
	.bcms = mmss_noc_bcms,
	.num_bcms = ARRAY_SIZE(mmss_noc_bcms),
};

static struct qcom_icc_bcm * const npu_noc_bcms[] = {
};

static struct qcom_icc_node * const npu_noc_nodes[] = {
	[MASTER_NPU_SYS] = &amm_npu_sys,
	[MASTER_NPU_NOC_CFG] = &qhm_npu_cfg,
	[SLAVE_NPU_CAL_DP0] = &qhs_cal_dp0,
	[SLAVE_NPU_CP] = &qhs_cp,
	[SLAVE_NPU_INT_DMA_BWMON_CFG] = &qhs_dma_bwmon,
	[SLAVE_NPU_DPM] = &qhs_dpm,
	[SLAVE_ISENSE_CFG] = &qhs_isense,
	[SLAVE_NPU_LLM_CFG] = &qhs_llm,
	[SLAVE_NPU_TCM] = &qhs_tcm,
	[SLAVE_NPU_COMPUTE_NOC] = &qns_npu_sys,
	[SLAVE_SERVICE_NPU_NOC] = &srvc_noc,
};

static const struct qcom_icc_desc sm6350_npu_noc = {
	.nodes = npu_noc_nodes,
	.num_nodes = ARRAY_SIZE(npu_noc_nodes),
	.bcms = npu_noc_bcms,
	.num_bcms = ARRAY_SIZE(npu_noc_bcms),
};

static struct qcom_icc_bcm * const system_noc_bcms[] = {
	&bcm_sn0,
	&bcm_sn1,
	&bcm_sn10,
	&bcm_sn2,
	&bcm_sn3,
	&bcm_sn4,
	&bcm_sn5,
	&bcm_sn6,
};

static struct qcom_icc_node * const system_noc_nodes[] = {
	[MASTER_SNOC_CFG] = &qhm_snoc_cfg,
	[A1NOC_SNOC_MAS] = &qnm_aggre1_noc,
	[A2NOC_SNOC_MAS] = &qnm_aggre2_noc,
	[MASTER_GEM_NOC_SNOC] = &qnm_gemnoc,
	[MASTER_PIMEM] = &qxm_pimem,
	[MASTER_GIC] = &xm_gic,
	[SLAVE_APPSS] = &qhs_apss,
	[SNOC_CNOC_SLV] = &qns_cnoc,
	[SLAVE_SNOC_GEM_NOC_GC] = &qns_gemnoc_gc,
	[SLAVE_SNOC_GEM_NOC_SF] = &qns_gemnoc_sf,
	[SLAVE_OCIMEM] = &qxs_imem,
	[SLAVE_PIMEM] = &qxs_pimem,
	[SLAVE_SERVICE_SNOC] = &srvc_snoc,
	[SLAVE_QDSS_STM] = &xs_qdss_stm,
	[SLAVE_TCU] = &xs_sys_tcu_cfg,
};

static const struct qcom_icc_desc sm6350_system_noc = {
	.nodes = system_noc_nodes,
	.num_nodes = ARRAY_SIZE(system_noc_nodes),
	.bcms = system_noc_bcms,
	.num_bcms = ARRAY_SIZE(system_noc_bcms),
};

static const struct of_device_id qnoc_of_match[] = {
	{ .compatible = "qcom,sm6350-aggre1-noc",
	  .data = &sm6350_aggre1_noc},
	{ .compatible = "qcom,sm6350-aggre2-noc",
	  .data = &sm6350_aggre2_noc},
	{ .compatible = "qcom,sm6350-clk-virt",
	  .data = &sm6350_clk_virt},
	{ .compatible = "qcom,sm6350-compute-noc",
	  .data = &sm6350_compute_noc},
	{ .compatible = "qcom,sm6350-config-noc",
	  .data = &sm6350_config_noc},
	{ .compatible = "qcom,sm6350-dc-noc",
	  .data = &sm6350_dc_noc},
	{ .compatible = "qcom,sm6350-gem-noc",
	  .data = &sm6350_gem_noc},
	{ .compatible = "qcom,sm6350-mmss-noc",
	  .data = &sm6350_mmss_noc},
	{ .compatible = "qcom,sm6350-npu-noc",
	  .data = &sm6350_npu_noc},
	{ .compatible = "qcom,sm6350-system-noc",
	  .data = &sm6350_system_noc},
	{ }
};
MODULE_DEVICE_TABLE(of, qnoc_of_match);

static struct platform_driver qnoc_driver = {
	.probe = qcom_icc_rpmh_probe,
	.remove = qcom_icc_rpmh_remove,
	.driver = {
		.name = "qnoc-sm6350",
		.of_match_table = qnoc_of_match,
		.sync_state = icc_sync_state,
	},
};
module_platform_driver(qnoc_driver);

MODULE_DESCRIPTION("Qualcomm SM6350 NoC driver");
MODULE_LICENSE("GPL v2");
