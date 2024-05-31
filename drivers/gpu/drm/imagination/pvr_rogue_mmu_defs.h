/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/* Copyright (c) 2023 Imagination Technologies Ltd. */

/*  *** Autogenerated C -- do not edit ***  */

#ifndef PVR_ROGUE_MMU_DEFS_H
#define PVR_ROGUE_MMU_DEFS_H

#define ROGUE_MMU_DEFS_REVISION 0

#define ROGUE_BIF_DM_ENCODING_VERTEX (0x00000000U)
#define ROGUE_BIF_DM_ENCODING_PIXEL (0x00000001U)
#define ROGUE_BIF_DM_ENCODING_COMPUTE (0x00000002U)
#define ROGUE_BIF_DM_ENCODING_TLA (0x00000003U)
#define ROGUE_BIF_DM_ENCODING_PB_VCE (0x00000004U)
#define ROGUE_BIF_DM_ENCODING_PB_TE (0x00000005U)
#define ROGUE_BIF_DM_ENCODING_META (0x00000007U)
#define ROGUE_BIF_DM_ENCODING_HOST (0x00000008U)
#define ROGUE_BIF_DM_ENCODING_PM_ALIST (0x00000009U)

#define ROGUE_MMUCTRL_VADDR_PC_INDEX_SHIFT (30U)
#define ROGUE_MMUCTRL_VADDR_PC_INDEX_CLRMSK (0xFFFFFF003FFFFFFFULL)
#define ROGUE_MMUCTRL_VADDR_PD_INDEX_SHIFT (21U)
#define ROGUE_MMUCTRL_VADDR_PD_INDEX_CLRMSK (0xFFFFFFFFC01FFFFFULL)
#define ROGUE_MMUCTRL_VADDR_PT_INDEX_SHIFT (12U)
#define ROGUE_MMUCTRL_VADDR_PT_INDEX_CLRMSK (0xFFFFFFFFFFE00FFFULL)

#define ROGUE_MMUCTRL_ENTRIES_PC_VALUE (0x00000400U)
#define ROGUE_MMUCTRL_ENTRIES_PD_VALUE (0x00000200U)
#define ROGUE_MMUCTRL_ENTRIES_PT_VALUE (0x00000200U)

#define ROGUE_MMUCTRL_ENTRY_SIZE_PC_VALUE (0x00000020U)
#define ROGUE_MMUCTRL_ENTRY_SIZE_PD_VALUE (0x00000040U)
#define ROGUE_MMUCTRL_ENTRY_SIZE_PT_VALUE (0x00000040U)

#define ROGUE_MMUCTRL_PAGE_SIZE_MASK (0x00000007U)
#define ROGUE_MMUCTRL_PAGE_SIZE_4KB (0x00000000U)
#define ROGUE_MMUCTRL_PAGE_SIZE_16KB (0x00000001U)
#define ROGUE_MMUCTRL_PAGE_SIZE_64KB (0x00000002U)
#define ROGUE_MMUCTRL_PAGE_SIZE_256KB (0x00000003U)
#define ROGUE_MMUCTRL_PAGE_SIZE_1MB (0x00000004U)
#define ROGUE_MMUCTRL_PAGE_SIZE_2MB (0x00000005U)

#define ROGUE_MMUCTRL_PAGE_4KB_RANGE_SHIFT (12U)
#define ROGUE_MMUCTRL_PAGE_4KB_RANGE_CLRMSK (0xFFFFFF0000000FFFULL)

#define ROGUE_MMUCTRL_PAGE_16KB_RANGE_SHIFT (14U)
#define ROGUE_MMUCTRL_PAGE_16KB_RANGE_CLRMSK (0xFFFFFF0000003FFFULL)

#define ROGUE_MMUCTRL_PAGE_64KB_RANGE_SHIFT (16U)
#define ROGUE_MMUCTRL_PAGE_64KB_RANGE_CLRMSK (0xFFFFFF000000FFFFULL)

#define ROGUE_MMUCTRL_PAGE_256KB_RANGE_SHIFT (18U)
#define ROGUE_MMUCTRL_PAGE_256KB_RANGE_CLRMSK (0xFFFFFF000003FFFFULL)

#define ROGUE_MMUCTRL_PAGE_1MB_RANGE_SHIFT (20U)
#define ROGUE_MMUCTRL_PAGE_1MB_RANGE_CLRMSK (0xFFFFFF00000FFFFFULL)

#define ROGUE_MMUCTRL_PAGE_2MB_RANGE_SHIFT (21U)
#define ROGUE_MMUCTRL_PAGE_2MB_RANGE_CLRMSK (0xFFFFFF00001FFFFFULL)

#define ROGUE_MMUCTRL_PT_BASE_4KB_RANGE_SHIFT (12U)
#define ROGUE_MMUCTRL_PT_BASE_4KB_RANGE_CLRMSK (0xFFFFFF0000000FFFULL)

#define ROGUE_MMUCTRL_PT_BASE_16KB_RANGE_SHIFT (10U)
#define ROGUE_MMUCTRL_PT_BASE_16KB_RANGE_CLRMSK (0xFFFFFF00000003FFULL)

#define ROGUE_MMUCTRL_PT_BASE_64KB_RANGE_SHIFT (8U)
#define ROGUE_MMUCTRL_PT_BASE_64KB_RANGE_CLRMSK (0xFFFFFF00000000FFULL)

#define ROGUE_MMUCTRL_PT_BASE_256KB_RANGE_SHIFT (6U)
#define ROGUE_MMUCTRL_PT_BASE_256KB_RANGE_CLRMSK (0xFFFFFF000000003FULL)

#define ROGUE_MMUCTRL_PT_BASE_1MB_RANGE_SHIFT (5U)
#define ROGUE_MMUCTRL_PT_BASE_1MB_RANGE_CLRMSK (0xFFFFFF000000001FULL)

#define ROGUE_MMUCTRL_PT_BASE_2MB_RANGE_SHIFT (5U)
#define ROGUE_MMUCTRL_PT_BASE_2MB_RANGE_CLRMSK (0xFFFFFF000000001FULL)

#define ROGUE_MMUCTRL_PT_DATA_PM_META_PROTECT_SHIFT (62U)
#define ROGUE_MMUCTRL_PT_DATA_PM_META_PROTECT_CLRMSK (0xBFFFFFFFFFFFFFFFULL)
#define ROGUE_MMUCTRL_PT_DATA_PM_META_PROTECT_EN (0x4000000000000000ULL)
#define ROGUE_MMUCTRL_PT_DATA_VP_PAGE_HI_SHIFT (40U)
#define ROGUE_MMUCTRL_PT_DATA_VP_PAGE_HI_CLRMSK (0xC00000FFFFFFFFFFULL)
#define ROGUE_MMUCTRL_PT_DATA_PAGE_SHIFT (12U)
#define ROGUE_MMUCTRL_PT_DATA_PAGE_CLRMSK (0xFFFFFF0000000FFFULL)
#define ROGUE_MMUCTRL_PT_DATA_VP_PAGE_LO_SHIFT (6U)
#define ROGUE_MMUCTRL_PT_DATA_VP_PAGE_LO_CLRMSK (0xFFFFFFFFFFFFF03FULL)
#define ROGUE_MMUCTRL_PT_DATA_ENTRY_PENDING_SHIFT (5U)
#define ROGUE_MMUCTRL_PT_DATA_ENTRY_PENDING_CLRMSK (0xFFFFFFFFFFFFFFDFULL)
#define ROGUE_MMUCTRL_PT_DATA_ENTRY_PENDING_EN (0x0000000000000020ULL)
#define ROGUE_MMUCTRL_PT_DATA_PM_SRC_SHIFT (4U)
#define ROGUE_MMUCTRL_PT_DATA_PM_SRC_CLRMSK (0xFFFFFFFFFFFFFFEFULL)
#define ROGUE_MMUCTRL_PT_DATA_PM_SRC_EN (0x0000000000000010ULL)
#define ROGUE_MMUCTRL_PT_DATA_SLC_BYPASS_CTRL_SHIFT (3U)
#define ROGUE_MMUCTRL_PT_DATA_SLC_BYPASS_CTRL_CLRMSK (0xFFFFFFFFFFFFFFF7ULL)
#define ROGUE_MMUCTRL_PT_DATA_SLC_BYPASS_CTRL_EN (0x0000000000000008ULL)
#define ROGUE_MMUCTRL_PT_DATA_CC_SHIFT (2U)
#define ROGUE_MMUCTRL_PT_DATA_CC_CLRMSK (0xFFFFFFFFFFFFFFFBULL)
#define ROGUE_MMUCTRL_PT_DATA_CC_EN (0x0000000000000004ULL)
#define ROGUE_MMUCTRL_PT_DATA_READ_ONLY_SHIFT (1U)
#define ROGUE_MMUCTRL_PT_DATA_READ_ONLY_CLRMSK (0xFFFFFFFFFFFFFFFDULL)
#define ROGUE_MMUCTRL_PT_DATA_READ_ONLY_EN (0x0000000000000002ULL)
#define ROGUE_MMUCTRL_PT_DATA_VALID_SHIFT (0U)
#define ROGUE_MMUCTRL_PT_DATA_VALID_CLRMSK (0xFFFFFFFFFFFFFFFEULL)
#define ROGUE_MMUCTRL_PT_DATA_VALID_EN (0x0000000000000001ULL)

#define ROGUE_MMUCTRL_PD_DATA_ENTRY_PENDING_SHIFT (40U)
#define ROGUE_MMUCTRL_PD_DATA_ENTRY_PENDING_CLRMSK (0xFFFFFEFFFFFFFFFFULL)
#define ROGUE_MMUCTRL_PD_DATA_ENTRY_PENDING_EN (0x0000010000000000ULL)
#define ROGUE_MMUCTRL_PD_DATA_PT_BASE_SHIFT (5U)
#define ROGUE_MMUCTRL_PD_DATA_PT_BASE_CLRMSK (0xFFFFFF000000001FULL)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_SHIFT (1U)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_CLRMSK (0xFFFFFFFFFFFFFFF1ULL)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_4KB (0x0000000000000000ULL)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_16KB (0x0000000000000002ULL)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_64KB (0x0000000000000004ULL)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_256KB (0x0000000000000006ULL)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_1MB (0x0000000000000008ULL)
#define ROGUE_MMUCTRL_PD_DATA_PAGE_SIZE_2MB (0x000000000000000aULL)
#define ROGUE_MMUCTRL_PD_DATA_VALID_SHIFT (0U)
#define ROGUE_MMUCTRL_PD_DATA_VALID_CLRMSK (0xFFFFFFFFFFFFFFFEULL)
#define ROGUE_MMUCTRL_PD_DATA_VALID_EN (0x0000000000000001ULL)

#define ROGUE_MMUCTRL_PC_DATA_PD_BASE_SHIFT (4U)
#define ROGUE_MMUCTRL_PC_DATA_PD_BASE_CLRMSK (0x0000000FU)
#define ROGUE_MMUCTRL_PC_DATA_PD_BASE_ALIGNSHIFT (12U)
#define ROGUE_MMUCTRL_PC_DATA_PD_BASE_ALIGNSIZE (4096U)
#define ROGUE_MMUCTRL_PC_DATA_ENTRY_PENDING_SHIFT (1U)
#define ROGUE_MMUCTRL_PC_DATA_ENTRY_PENDING_CLRMSK (0xFFFFFFFDU)
#define ROGUE_MMUCTRL_PC_DATA_ENTRY_PENDING_EN (0x00000002U)
#define ROGUE_MMUCTRL_PC_DATA_VALID_SHIFT (0U)
#define ROGUE_MMUCTRL_PC_DATA_VALID_CLRMSK (0xFFFFFFFEU)
#define ROGUE_MMUCTRL_PC_DATA_VALID_EN (0x00000001U)

#endif /* PVR_ROGUE_MMU_DEFS_H */
