/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2013 - 2018 Intel Corporation. */

#ifndef _IAVF_REGISTER_H_
#define _IAVF_REGISTER_H_

#define IAVF_VF_ARQBAH1 0x00006000 /* Reset: EMPR */
#define IAVF_VF_ARQBAL1 0x00006C00 /* Reset: EMPR */
#define IAVF_VF_ARQH1 0x00007400 /* Reset: EMPR */
#define IAVF_VF_ARQH1_ARQH_SHIFT 0
#define IAVF_VF_ARQH1_ARQH_MASK IAVF_MASK(0x3FF, IAVF_VF_ARQH1_ARQH_SHIFT)
#define IAVF_VF_ARQLEN1 0x00008000 /* Reset: EMPR */
#define IAVF_VF_ARQLEN1_ARQVFE_SHIFT 28
#define IAVF_VF_ARQLEN1_ARQVFE_MASK IAVF_MASK(0x1, IAVF_VF_ARQLEN1_ARQVFE_SHIFT)
#define IAVF_VF_ARQLEN1_ARQOVFL_SHIFT 29
#define IAVF_VF_ARQLEN1_ARQOVFL_MASK IAVF_MASK(0x1, IAVF_VF_ARQLEN1_ARQOVFL_SHIFT)
#define IAVF_VF_ARQLEN1_ARQCRIT_SHIFT 30
#define IAVF_VF_ARQLEN1_ARQCRIT_MASK IAVF_MASK(0x1, IAVF_VF_ARQLEN1_ARQCRIT_SHIFT)
#define IAVF_VF_ARQLEN1_ARQENABLE_SHIFT 31
#define IAVF_VF_ARQLEN1_ARQENABLE_MASK IAVF_MASK(0x1, IAVF_VF_ARQLEN1_ARQENABLE_SHIFT)
#define IAVF_VF_ARQT1 0x00007000 /* Reset: EMPR */
#define IAVF_VF_ATQBAH1 0x00007800 /* Reset: EMPR */
#define IAVF_VF_ATQBAL1 0x00007C00 /* Reset: EMPR */
#define IAVF_VF_ATQH1 0x00006400 /* Reset: EMPR */
#define IAVF_VF_ATQLEN1 0x00006800 /* Reset: EMPR */
#define IAVF_VF_ATQLEN1_ATQVFE_SHIFT 28
#define IAVF_VF_ATQLEN1_ATQVFE_MASK IAVF_MASK(0x1, IAVF_VF_ATQLEN1_ATQVFE_SHIFT)
#define IAVF_VF_ATQLEN1_ATQOVFL_SHIFT 29
#define IAVF_VF_ATQLEN1_ATQOVFL_MASK IAVF_MASK(0x1, IAVF_VF_ATQLEN1_ATQOVFL_SHIFT)
#define IAVF_VF_ATQLEN1_ATQCRIT_SHIFT 30
#define IAVF_VF_ATQLEN1_ATQCRIT_MASK IAVF_MASK(0x1, IAVF_VF_ATQLEN1_ATQCRIT_SHIFT)
#define IAVF_VF_ATQLEN1_ATQENABLE_SHIFT 31
#define IAVF_VF_ATQLEN1_ATQENABLE_MASK IAVF_MASK(0x1, IAVF_VF_ATQLEN1_ATQENABLE_SHIFT)
#define IAVF_VF_ATQT1 0x00008400 /* Reset: EMPR */
#define IAVF_VFGEN_RSTAT 0x00008800 /* Reset: VFR */
#define IAVF_VFGEN_RSTAT_VFR_STATE_SHIFT 0
#define IAVF_VFGEN_RSTAT_VFR_STATE_MASK IAVF_MASK(0x3, IAVF_VFGEN_RSTAT_VFR_STATE_SHIFT)
#define IAVF_VFINT_DYN_CTL01 0x00005C00 /* Reset: VFR */
#define IAVF_VFINT_DYN_CTL01_INTENA_SHIFT 0
#define IAVF_VFINT_DYN_CTL01_INTENA_MASK IAVF_MASK(0x1, IAVF_VFINT_DYN_CTL01_INTENA_SHIFT)
#define IAVF_VFINT_DYN_CTL01_ITR_INDX_SHIFT 3
#define IAVF_VFINT_DYN_CTL01_ITR_INDX_MASK IAVF_MASK(0x3, IAVF_VFINT_DYN_CTL01_ITR_INDX_SHIFT)
#define IAVF_VFINT_DYN_CTLN1(_INTVF) (0x00003800 + ((_INTVF) * 4)) /* _i=0...63 */ /* Reset: VFR */
#define IAVF_VFINT_DYN_CTLN1_INTENA_SHIFT 0
#define IAVF_VFINT_DYN_CTLN1_INTENA_MASK IAVF_MASK(0x1, IAVF_VFINT_DYN_CTLN1_INTENA_SHIFT)
#define IAVF_VFINT_DYN_CTLN1_SWINT_TRIG_SHIFT 2
#define IAVF_VFINT_DYN_CTLN1_SWINT_TRIG_MASK IAVF_MASK(0x1, IAVF_VFINT_DYN_CTLN1_SWINT_TRIG_SHIFT)
#define IAVF_VFINT_DYN_CTLN1_ITR_INDX_SHIFT 3
#define IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK IAVF_MASK(0x3, IAVF_VFINT_DYN_CTLN1_ITR_INDX_SHIFT)
#define IAVF_VFINT_DYN_CTLN1_INTERVAL_SHIFT 5
#define IAVF_VFINT_DYN_CTLN1_SW_ITR_INDX_ENA_SHIFT 24
#define IAVF_VFINT_DYN_CTLN1_SW_ITR_INDX_ENA_MASK IAVF_MASK(0x1, IAVF_VFINT_DYN_CTLN1_SW_ITR_INDX_ENA_SHIFT)
#define IAVF_VFINT_ICR0_ENA1 0x00005000 /* Reset: CORER */
#define IAVF_VFINT_ICR0_ENA1_ADMINQ_SHIFT 30
#define IAVF_VFINT_ICR0_ENA1_ADMINQ_MASK IAVF_MASK(0x1, IAVF_VFINT_ICR0_ENA1_ADMINQ_SHIFT)
#define IAVF_VFINT_ICR0_ENA1_RSVD_SHIFT 31
#define IAVF_VFINT_ICR01 0x00004800 /* Reset: CORER */
#define IAVF_VFINT_ITRN1(_i, _INTVF) (0x00002800 + ((_i) * 64 + (_INTVF) * 4)) /* _i=0...2, _INTVF=0...15 */ /* Reset: VFR */
#define IAVF_QRX_TAIL1(_Q) (0x00002000 + ((_Q) * 4)) /* _i=0...15 */ /* Reset: CORER */
#define IAVF_QTX_TAIL1(_Q) (0x00000000 + ((_Q) * 4)) /* _i=0...15 */ /* Reset: PFR */
#define IAVF_VFQF_HENA(_i) (0x0000C400 + ((_i) * 4)) /* _i=0...1 */ /* Reset: CORER */
#define IAVF_VFQF_HKEY(_i) (0x0000CC00 + ((_i) * 4)) /* _i=0...12 */ /* Reset: CORER */
#define IAVF_VFQF_HKEY_MAX_INDEX 12
#define IAVF_VFQF_HLUT(_i) (0x0000D000 + ((_i) * 4)) /* _i=0...15 */ /* Reset: CORER */
#define IAVF_VFQF_HLUT_MAX_INDEX 15
#define IAVF_VFINT_DYN_CTLN1_WB_ON_ITR_SHIFT 30
#define IAVF_VFINT_DYN_CTLN1_WB_ON_ITR_MASK IAVF_MASK(0x1, IAVF_VFINT_DYN_CTLN1_WB_ON_ITR_SHIFT)
#endif /* _IAVF_REGISTER_H_ */
