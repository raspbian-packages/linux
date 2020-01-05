/* SPDX-License-Identifier: GPL-2.0-only */
/**************************************************************************
 *
 * Copyright (c) (2005-2007) Imagination Technologies Limited.
 * Copyright (c) 2007, Intel Corporation.
 * All Rights Reserved.
 *
 **************************************************************************/

#ifndef _PSB_REG_H_
#define _PSB_REG_H_

#define PSB_CR_CLKGATECTL		0x0000
#define _PSB_C_CLKGATECTL_AUTO_MAN_REG		(1 << 24)
#define _PSB_C_CLKGATECTL_USE_CLKG_SHIFT	(20)
#define _PSB_C_CLKGATECTL_USE_CLKG_MASK		(0x3 << 20)
#define _PSB_C_CLKGATECTL_DPM_CLKG_SHIFT	(16)
#define _PSB_C_CLKGATECTL_DPM_CLKG_MASK		(0x3 << 16)
#define _PSB_C_CLKGATECTL_TA_CLKG_SHIFT		(12)
#define _PSB_C_CLKGATECTL_TA_CLKG_MASK		(0x3 << 12)
#define _PSB_C_CLKGATECTL_TSP_CLKG_SHIFT	(8)
#define _PSB_C_CLKGATECTL_TSP_CLKG_MASK		(0x3 << 8)
#define _PSB_C_CLKGATECTL_ISP_CLKG_SHIFT	(4)
#define _PSB_C_CLKGATECTL_ISP_CLKG_MASK		(0x3 << 4)
#define _PSB_C_CLKGATECTL_2D_CLKG_SHIFT		(0)
#define _PSB_C_CLKGATECTL_2D_CLKG_MASK		(0x3 << 0)
#define _PSB_C_CLKGATECTL_CLKG_ENABLED		(0)
#define _PSB_C_CLKGATECTL_CLKG_DISABLED		(1)
#define _PSB_C_CLKGATECTL_CLKG_AUTO		(2)

#define PSB_CR_CORE_ID			0x0010
#define _PSB_CC_ID_ID_SHIFT			(16)
#define _PSB_CC_ID_ID_MASK			(0xFFFF << 16)
#define _PSB_CC_ID_CONFIG_SHIFT			(0)
#define _PSB_CC_ID_CONFIG_MASK			(0xFFFF << 0)

#define PSB_CR_CORE_REVISION		0x0014
#define _PSB_CC_REVISION_DESIGNER_SHIFT		(24)
#define _PSB_CC_REVISION_DESIGNER_MASK		(0xFF << 24)
#define _PSB_CC_REVISION_MAJOR_SHIFT		(16)
#define _PSB_CC_REVISION_MAJOR_MASK		(0xFF << 16)
#define _PSB_CC_REVISION_MINOR_SHIFT		(8)
#define _PSB_CC_REVISION_MINOR_MASK		(0xFF << 8)
#define _PSB_CC_REVISION_MAINTENANCE_SHIFT	(0)
#define _PSB_CC_REVISION_MAINTENANCE_MASK	(0xFF << 0)

#define PSB_CR_DESIGNER_REV_FIELD1	0x0018

#define PSB_CR_SOFT_RESET		0x0080
#define _PSB_CS_RESET_TSP_RESET		(1 << 6)
#define _PSB_CS_RESET_ISP_RESET		(1 << 5)
#define _PSB_CS_RESET_USE_RESET		(1 << 4)
#define _PSB_CS_RESET_TA_RESET		(1 << 3)
#define _PSB_CS_RESET_DPM_RESET		(1 << 2)
#define _PSB_CS_RESET_TWOD_RESET	(1 << 1)
#define _PSB_CS_RESET_BIF_RESET			(1 << 0)

#define PSB_CR_DESIGNER_REV_FIELD2	0x001C

#define PSB_CR_EVENT_HOST_ENABLE2	0x0110

#define PSB_CR_EVENT_STATUS2		0x0118

#define PSB_CR_EVENT_HOST_CLEAR2	0x0114
#define _PSB_CE2_BIF_REQUESTER_FAULT		(1 << 4)

#define PSB_CR_EVENT_STATUS		0x012C

#define PSB_CR_EVENT_HOST_ENABLE	0x0130

#define PSB_CR_EVENT_HOST_CLEAR		0x0134
#define _PSB_CE_MASTER_INTERRUPT		(1 << 31)
#define _PSB_CE_TA_DPM_FAULT			(1 << 28)
#define _PSB_CE_TWOD_COMPLETE			(1 << 27)
#define _PSB_CE_DPM_OUT_OF_MEMORY_ZLS		(1 << 25)
#define _PSB_CE_DPM_TA_MEM_FREE			(1 << 24)
#define _PSB_CE_PIXELBE_END_RENDER		(1 << 18)
#define _PSB_CE_SW_EVENT			(1 << 14)
#define _PSB_CE_TA_FINISHED			(1 << 13)
#define _PSB_CE_TA_TERMINATE			(1 << 12)
#define _PSB_CE_DPM_REACHED_MEM_THRESH		(1 << 3)
#define _PSB_CE_DPM_OUT_OF_MEMORY_GBL		(1 << 2)
#define _PSB_CE_DPM_OUT_OF_MEMORY_MT		(1 << 1)
#define _PSB_CE_DPM_3D_MEM_FREE			(1 << 0)


#define PSB_USE_OFFSET_MASK		0x0007FFFF
#define PSB_USE_OFFSET_SIZE		(PSB_USE_OFFSET_MASK + 1)
#define PSB_CR_USE_CODE_BASE0		0x0A0C
#define PSB_CR_USE_CODE_BASE1		0x0A10
#define PSB_CR_USE_CODE_BASE2		0x0A14
#define PSB_CR_USE_CODE_BASE3		0x0A18
#define PSB_CR_USE_CODE_BASE4		0x0A1C
#define PSB_CR_USE_CODE_BASE5		0x0A20
#define PSB_CR_USE_CODE_BASE6		0x0A24
#define PSB_CR_USE_CODE_BASE7		0x0A28
#define PSB_CR_USE_CODE_BASE8		0x0A2C
#define PSB_CR_USE_CODE_BASE9		0x0A30
#define PSB_CR_USE_CODE_BASE10		0x0A34
#define PSB_CR_USE_CODE_BASE11		0x0A38
#define PSB_CR_USE_CODE_BASE12		0x0A3C
#define PSB_CR_USE_CODE_BASE13		0x0A40
#define PSB_CR_USE_CODE_BASE14		0x0A44
#define PSB_CR_USE_CODE_BASE15		0x0A48
#define PSB_CR_USE_CODE_BASE(_i)	(0x0A0C + ((_i) << 2))
#define _PSB_CUC_BASE_DM_SHIFT			(25)
#define _PSB_CUC_BASE_DM_MASK			(0x3 << 25)
#define _PSB_CUC_BASE_ADDR_SHIFT		(0)	/* 1024-bit aligned address? */
#define _PSB_CUC_BASE_ADDR_ALIGNSHIFT		(7)
#define _PSB_CUC_BASE_ADDR_MASK			(0x1FFFFFF << 0)
#define _PSB_CUC_DM_VERTEX			(0)
#define _PSB_CUC_DM_PIXEL			(1)
#define _PSB_CUC_DM_RESERVED			(2)
#define _PSB_CUC_DM_EDM				(3)

#define PSB_CR_PDS_EXEC_BASE		0x0AB8
#define _PSB_CR_PDS_EXEC_BASE_ADDR_SHIFT	(20)	/* 1MB aligned address */
#define _PSB_CR_PDS_EXEC_BASE_ADDR_ALIGNSHIFT	(20)

#define PSB_CR_EVENT_KICKER		0x0AC4
#define _PSB_CE_KICKER_ADDRESS_SHIFT		(4)	/* 128-bit aligned address */

#define PSB_CR_EVENT_KICK		0x0AC8
#define _PSB_CE_KICK_NOW			(1 << 0)

#define PSB_CR_BIF_DIR_LIST_BASE1	0x0C38

#define PSB_CR_BIF_CTRL			0x0C00
#define _PSB_CB_CTRL_CLEAR_FAULT		(1 << 4)
#define _PSB_CB_CTRL_INVALDC			(1 << 3)
#define _PSB_CB_CTRL_FLUSH			(1 << 2)

#define PSB_CR_BIF_INT_STAT		0x0C04

#define PSB_CR_BIF_FAULT		0x0C08
#define _PSB_CBI_STAT_PF_N_RW			(1 << 14)
#define _PSB_CBI_STAT_FAULT_SHIFT		(0)
#define _PSB_CBI_STAT_FAULT_MASK		(0x3FFF << 0)
#define _PSB_CBI_STAT_FAULT_CACHE		(1 << 1)
#define _PSB_CBI_STAT_FAULT_TA			(1 << 2)
#define _PSB_CBI_STAT_FAULT_VDM			(1 << 3)
#define _PSB_CBI_STAT_FAULT_2D			(1 << 4)
#define _PSB_CBI_STAT_FAULT_PBE			(1 << 5)
#define _PSB_CBI_STAT_FAULT_TSP			(1 << 6)
#define _PSB_CBI_STAT_FAULT_ISP			(1 << 7)
#define _PSB_CBI_STAT_FAULT_USSEPDS		(1 << 8)
#define _PSB_CBI_STAT_FAULT_HOST		(1 << 9)

#define PSB_CR_BIF_BANK0		0x0C78
#define PSB_CR_BIF_BANK1		0x0C7C
#define PSB_CR_BIF_DIR_LIST_BASE0	0x0C84
#define PSB_CR_BIF_TWOD_REQ_BASE	0x0C88
#define PSB_CR_BIF_3D_REQ_BASE		0x0CAC

#define PSB_CR_2D_SOCIF			0x0E18
#define _PSB_C2_SOCIF_FREESPACE_SHIFT		(0)
#define _PSB_C2_SOCIF_FREESPACE_MASK		(0xFF << 0)
#define _PSB_C2_SOCIF_EMPTY			(0x80 << 0)

#define PSB_CR_2D_BLIT_STATUS		0x0E04
#define _PSB_C2B_STATUS_BUSY			(1 << 24)
#define _PSB_C2B_STATUS_COMPLETE_SHIFT		(0)
#define _PSB_C2B_STATUS_COMPLETE_MASK		(0xFFFFFF << 0)

/*
 * 2D defs.
 */

/*
 * 2D Slave Port Data : Block Header's Object Type
 */

#define	PSB_2D_CLIP_BH			(0x00000000)
#define	PSB_2D_PAT_BH			(0x10000000)
#define	PSB_2D_CTRL_BH			(0x20000000)
#define	PSB_2D_SRC_OFF_BH		(0x30000000)
#define	PSB_2D_MASK_OFF_BH		(0x40000000)
#define	PSB_2D_RESERVED1_BH		(0x50000000)
#define	PSB_2D_RESERVED2_BH		(0x60000000)
#define	PSB_2D_FENCE_BH			(0x70000000)
#define	PSB_2D_BLIT_BH			(0x80000000)
#define	PSB_2D_SRC_SURF_BH		(0x90000000)
#define	PSB_2D_DST_SURF_BH		(0xA0000000)
#define	PSB_2D_PAT_SURF_BH		(0xB0000000)
#define	PSB_2D_SRC_PAL_BH		(0xC0000000)
#define	PSB_2D_PAT_PAL_BH		(0xD0000000)
#define	PSB_2D_MASK_SURF_BH		(0xE0000000)
#define	PSB_2D_FLUSH_BH			(0xF0000000)

/*
 * Clip Definition block (PSB_2D_CLIP_BH)
 */
#define PSB_2D_CLIPCOUNT_MAX		(1)
#define PSB_2D_CLIPCOUNT_MASK		(0x00000000)
#define PSB_2D_CLIPCOUNT_CLRMASK	(0xFFFFFFFF)
#define PSB_2D_CLIPCOUNT_SHIFT		(0)
/* clip rectangle min & max */
#define PSB_2D_CLIP_XMAX_MASK		(0x00FFF000)
#define PSB_2D_CLIP_XMAX_CLRMASK	(0xFF000FFF)
#define PSB_2D_CLIP_XMAX_SHIFT		(12)
#define PSB_2D_CLIP_XMIN_MASK		(0x00000FFF)
#define PSB_2D_CLIP_XMIN_CLRMASK	(0x00FFF000)
#define PSB_2D_CLIP_XMIN_SHIFT		(0)
/* clip rectangle offset */
#define PSB_2D_CLIP_YMAX_MASK		(0x00FFF000)
#define PSB_2D_CLIP_YMAX_CLRMASK	(0xFF000FFF)
#define PSB_2D_CLIP_YMAX_SHIFT		(12)
#define PSB_2D_CLIP_YMIN_MASK		(0x00000FFF)
#define PSB_2D_CLIP_YMIN_CLRMASK	(0x00FFF000)
#define PSB_2D_CLIP_YMIN_SHIFT		(0)

/*
 * Pattern Control (PSB_2D_PAT_BH)
 */
#define PSB_2D_PAT_HEIGHT_MASK		(0x0000001F)
#define PSB_2D_PAT_HEIGHT_SHIFT		(0)
#define PSB_2D_PAT_WIDTH_MASK		(0x000003E0)
#define PSB_2D_PAT_WIDTH_SHIFT		(5)
#define PSB_2D_PAT_YSTART_MASK		(0x00007C00)
#define PSB_2D_PAT_YSTART_SHIFT		(10)
#define PSB_2D_PAT_XSTART_MASK		(0x000F8000)
#define PSB_2D_PAT_XSTART_SHIFT		(15)

/*
 * 2D Control block (PSB_2D_CTRL_BH)
 */
/* Present Flags */
#define PSB_2D_SRCCK_CTRL		(0x00000001)
#define PSB_2D_DSTCK_CTRL		(0x00000002)
#define PSB_2D_ALPHA_CTRL		(0x00000004)
/* Colour Key Colour (SRC/DST)*/
#define PSB_2D_CK_COL_MASK		(0xFFFFFFFF)
#define PSB_2D_CK_COL_CLRMASK		(0x00000000)
#define PSB_2D_CK_COL_SHIFT		(0)
/* Colour Key Mask (SRC/DST)*/
#define PSB_2D_CK_MASK_MASK		(0xFFFFFFFF)
#define PSB_2D_CK_MASK_CLRMASK		(0x00000000)
#define PSB_2D_CK_MASK_SHIFT		(0)
/* Alpha Control (Alpha/RGB)*/
#define PSB_2D_GBLALPHA_MASK		(0x000FF000)
#define PSB_2D_GBLALPHA_CLRMASK		(0xFFF00FFF)
#define PSB_2D_GBLALPHA_SHIFT		(12)
#define PSB_2D_SRCALPHA_OP_MASK		(0x00700000)
#define PSB_2D_SRCALPHA_OP_CLRMASK	(0xFF8FFFFF)
#define PSB_2D_SRCALPHA_OP_SHIFT	(20)
#define PSB_2D_SRCALPHA_OP_ONE		(0x00000000)
#define PSB_2D_SRCALPHA_OP_SRC		(0x00100000)
#define PSB_2D_SRCALPHA_OP_DST		(0x00200000)
#define PSB_2D_SRCALPHA_OP_SG		(0x00300000)
#define PSB_2D_SRCALPHA_OP_DG		(0x00400000)
#define PSB_2D_SRCALPHA_OP_GBL		(0x00500000)
#define PSB_2D_SRCALPHA_OP_ZERO		(0x00600000)
#define PSB_2D_SRCALPHA_INVERT		(0x00800000)
#define PSB_2D_SRCALPHA_INVERT_CLR	(0xFF7FFFFF)
#define PSB_2D_DSTALPHA_OP_MASK		(0x07000000)
#define PSB_2D_DSTALPHA_OP_CLRMASK	(0xF8FFFFFF)
#define PSB_2D_DSTALPHA_OP_SHIFT	(24)
#define PSB_2D_DSTALPHA_OP_ONE		(0x00000000)
#define PSB_2D_DSTALPHA_OP_SRC		(0x01000000)
#define PSB_2D_DSTALPHA_OP_DST		(0x02000000)
#define PSB_2D_DSTALPHA_OP_SG		(0x03000000)
#define PSB_2D_DSTALPHA_OP_DG		(0x04000000)
#define PSB_2D_DSTALPHA_OP_GBL		(0x05000000)
#define PSB_2D_DSTALPHA_OP_ZERO		(0x06000000)
#define PSB_2D_DSTALPHA_INVERT		(0x08000000)
#define PSB_2D_DSTALPHA_INVERT_CLR	(0xF7FFFFFF)

#define PSB_2D_PRE_MULTIPLICATION_ENABLE	(0x10000000)
#define PSB_2D_PRE_MULTIPLICATION_CLRMASK	(0xEFFFFFFF)
#define PSB_2D_ZERO_SOURCE_ALPHA_ENABLE		(0x20000000)
#define PSB_2D_ZERO_SOURCE_ALPHA_CLRMASK	(0xDFFFFFFF)

/*
 *Source Offset (PSB_2D_SRC_OFF_BH)
 */
#define PSB_2D_SRCOFF_XSTART_MASK	((0x00000FFF) << 12)
#define PSB_2D_SRCOFF_XSTART_SHIFT	(12)
#define PSB_2D_SRCOFF_YSTART_MASK	(0x00000FFF)
#define PSB_2D_SRCOFF_YSTART_SHIFT	(0)

/*
 * Mask Offset (PSB_2D_MASK_OFF_BH)
 */
#define PSB_2D_MASKOFF_XSTART_MASK	((0x00000FFF) << 12)
#define PSB_2D_MASKOFF_XSTART_SHIFT	(12)
#define PSB_2D_MASKOFF_YSTART_MASK	(0x00000FFF)
#define PSB_2D_MASKOFF_YSTART_SHIFT	(0)

/*
 * 2D Fence (see PSB_2D_FENCE_BH): bits 0:27 are ignored
 */

/*
 *Blit Rectangle (PSB_2D_BLIT_BH)
 */

#define PSB_2D_ROT_MASK			(3 << 25)
#define PSB_2D_ROT_CLRMASK		(~PSB_2D_ROT_MASK)
#define PSB_2D_ROT_NONE			(0 << 25)
#define PSB_2D_ROT_90DEGS		(1 << 25)
#define PSB_2D_ROT_180DEGS		(2 << 25)
#define PSB_2D_ROT_270DEGS		(3 << 25)

#define PSB_2D_COPYORDER_MASK		(3 << 23)
#define PSB_2D_COPYORDER_CLRMASK	(~PSB_2D_COPYORDER_MASK)
#define PSB_2D_COPYORDER_TL2BR		(0 << 23)
#define PSB_2D_COPYORDER_BR2TL		(1 << 23)
#define PSB_2D_COPYORDER_TR2BL		(2 << 23)
#define PSB_2D_COPYORDER_BL2TR		(3 << 23)

#define PSB_2D_DSTCK_CLRMASK		(0xFF9FFFFF)
#define PSB_2D_DSTCK_DISABLE		(0x00000000)
#define PSB_2D_DSTCK_PASS		(0x00200000)
#define PSB_2D_DSTCK_REJECT		(0x00400000)

#define PSB_2D_SRCCK_CLRMASK		(0xFFE7FFFF)
#define PSB_2D_SRCCK_DISABLE		(0x00000000)
#define PSB_2D_SRCCK_PASS		(0x00080000)
#define PSB_2D_SRCCK_REJECT		(0x00100000)

#define PSB_2D_CLIP_ENABLE		(0x00040000)

#define PSB_2D_ALPHA_ENABLE		(0x00020000)

#define PSB_2D_PAT_CLRMASK		(0xFFFEFFFF)
#define PSB_2D_PAT_MASK			(0x00010000)
#define PSB_2D_USE_PAT			(0x00010000)
#define PSB_2D_USE_FILL			(0x00000000)
/*
 * Tungsten Graphics note on rop codes: If rop A and rop B are
 * identical, the mask surface will not be read and need not be
 * set up.
 */

#define PSB_2D_ROP3B_MASK		(0x0000FF00)
#define PSB_2D_ROP3B_CLRMASK		(0xFFFF00FF)
#define PSB_2D_ROP3B_SHIFT		(8)
/* rop code A */
#define PSB_2D_ROP3A_MASK		(0x000000FF)
#define PSB_2D_ROP3A_CLRMASK		(0xFFFFFF00)
#define PSB_2D_ROP3A_SHIFT		(0)

#define PSB_2D_ROP4_MASK		(0x0000FFFF)
/*
 *	DWORD0:	(Only pass if Pattern control == Use Fill Colour)
 *	Fill Colour RGBA8888
 */
#define PSB_2D_FILLCOLOUR_MASK		(0xFFFFFFFF)
#define PSB_2D_FILLCOLOUR_SHIFT		(0)
/*
 *	DWORD1: (Always Present)
 *	X Start (Dest)
 *	Y Start (Dest)
 */
#define PSB_2D_DST_XSTART_MASK		(0x00FFF000)
#define PSB_2D_DST_XSTART_CLRMASK	(0xFF000FFF)
#define PSB_2D_DST_XSTART_SHIFT		(12)
#define PSB_2D_DST_YSTART_MASK		(0x00000FFF)
#define PSB_2D_DST_YSTART_CLRMASK	(0xFFFFF000)
#define PSB_2D_DST_YSTART_SHIFT		(0)
/*
 *	DWORD2: (Always Present)
 *	X Size (Dest)
 *	Y Size (Dest)
 */
#define PSB_2D_DST_XSIZE_MASK		(0x00FFF000)
#define PSB_2D_DST_XSIZE_CLRMASK	(0xFF000FFF)
#define PSB_2D_DST_XSIZE_SHIFT		(12)
#define PSB_2D_DST_YSIZE_MASK		(0x00000FFF)
#define PSB_2D_DST_YSIZE_CLRMASK	(0xFFFFF000)
#define PSB_2D_DST_YSIZE_SHIFT		(0)

/*
 * Source Surface (PSB_2D_SRC_SURF_BH)
 */
/*
 * WORD 0
 */

#define PSB_2D_SRC_FORMAT_MASK		(0x00078000)
#define PSB_2D_SRC_1_PAL		(0x00000000)
#define PSB_2D_SRC_2_PAL		(0x00008000)
#define PSB_2D_SRC_4_PAL		(0x00010000)
#define PSB_2D_SRC_8_PAL		(0x00018000)
#define PSB_2D_SRC_8_ALPHA		(0x00020000)
#define PSB_2D_SRC_4_ALPHA		(0x00028000)
#define PSB_2D_SRC_332RGB		(0x00030000)
#define PSB_2D_SRC_4444ARGB		(0x00038000)
#define PSB_2D_SRC_555RGB		(0x00040000)
#define PSB_2D_SRC_1555ARGB		(0x00048000)
#define PSB_2D_SRC_565RGB		(0x00050000)
#define PSB_2D_SRC_0888ARGB		(0x00058000)
#define PSB_2D_SRC_8888ARGB		(0x00060000)
#define PSB_2D_SRC_8888UYVY		(0x00068000)
#define PSB_2D_SRC_RESERVED		(0x00070000)
#define PSB_2D_SRC_1555ARGB_LOOKUP	(0x00078000)


#define PSB_2D_SRC_STRIDE_MASK		(0x00007FFF)
#define PSB_2D_SRC_STRIDE_CLRMASK	(0xFFFF8000)
#define PSB_2D_SRC_STRIDE_SHIFT		(0)
/*
 *  WORD 1 - Base Address
 */
#define PSB_2D_SRC_ADDR_MASK		(0x0FFFFFFC)
#define PSB_2D_SRC_ADDR_CLRMASK		(0x00000003)
#define PSB_2D_SRC_ADDR_SHIFT		(2)
#define PSB_2D_SRC_ADDR_ALIGNSHIFT	(2)

/*
 * Pattern Surface (PSB_2D_PAT_SURF_BH)
 */
/*
 *  WORD 0
 */

#define PSB_2D_PAT_FORMAT_MASK		(0x00078000)
#define PSB_2D_PAT_1_PAL		(0x00000000)
#define PSB_2D_PAT_2_PAL		(0x00008000)
#define PSB_2D_PAT_4_PAL		(0x00010000)
#define PSB_2D_PAT_8_PAL		(0x00018000)
#define PSB_2D_PAT_8_ALPHA		(0x00020000)
#define PSB_2D_PAT_4_ALPHA		(0x00028000)
#define PSB_2D_PAT_332RGB		(0x00030000)
#define PSB_2D_PAT_4444ARGB		(0x00038000)
#define PSB_2D_PAT_555RGB		(0x00040000)
#define PSB_2D_PAT_1555ARGB		(0x00048000)
#define PSB_2D_PAT_565RGB		(0x00050000)
#define PSB_2D_PAT_0888ARGB		(0x00058000)
#define PSB_2D_PAT_8888ARGB		(0x00060000)

#define PSB_2D_PAT_STRIDE_MASK		(0x00007FFF)
#define PSB_2D_PAT_STRIDE_CLRMASK	(0xFFFF8000)
#define PSB_2D_PAT_STRIDE_SHIFT		(0)
/*
 *  WORD 1 - Base Address
 */
#define PSB_2D_PAT_ADDR_MASK		(0x0FFFFFFC)
#define PSB_2D_PAT_ADDR_CLRMASK		(0x00000003)
#define PSB_2D_PAT_ADDR_SHIFT		(2)
#define PSB_2D_PAT_ADDR_ALIGNSHIFT	(2)

/*
 * Destination Surface (PSB_2D_DST_SURF_BH)
 */
/*
 * WORD 0
 */

#define PSB_2D_DST_FORMAT_MASK		(0x00078000)
#define PSB_2D_DST_332RGB		(0x00030000)
#define PSB_2D_DST_4444ARGB		(0x00038000)
#define PSB_2D_DST_555RGB		(0x00040000)
#define PSB_2D_DST_1555ARGB		(0x00048000)
#define PSB_2D_DST_565RGB		(0x00050000)
#define PSB_2D_DST_0888ARGB		(0x00058000)
#define PSB_2D_DST_8888ARGB		(0x00060000)
#define PSB_2D_DST_8888AYUV		(0x00070000)

#define PSB_2D_DST_STRIDE_MASK		(0x00007FFF)
#define PSB_2D_DST_STRIDE_CLRMASK	(0xFFFF8000)
#define PSB_2D_DST_STRIDE_SHIFT		(0)
/*
 * WORD 1 - Base Address
 */
#define PSB_2D_DST_ADDR_MASK		(0x0FFFFFFC)
#define PSB_2D_DST_ADDR_CLRMASK		(0x00000003)
#define PSB_2D_DST_ADDR_SHIFT		(2)
#define PSB_2D_DST_ADDR_ALIGNSHIFT	(2)

/*
 * Mask Surface (PSB_2D_MASK_SURF_BH)
 */
/*
 * WORD 0
 */
#define PSB_2D_MASK_STRIDE_MASK		(0x00007FFF)
#define PSB_2D_MASK_STRIDE_CLRMASK	(0xFFFF8000)
#define PSB_2D_MASK_STRIDE_SHIFT	(0)
/*
 *  WORD 1 - Base Address
 */
#define PSB_2D_MASK_ADDR_MASK		(0x0FFFFFFC)
#define PSB_2D_MASK_ADDR_CLRMASK	(0x00000003)
#define PSB_2D_MASK_ADDR_SHIFT		(2)
#define PSB_2D_MASK_ADDR_ALIGNSHIFT	(2)

/*
 * Source Palette (PSB_2D_SRC_PAL_BH)
 */

#define PSB_2D_SRCPAL_ADDR_SHIFT	(0)
#define PSB_2D_SRCPAL_ADDR_CLRMASK	(0xF0000007)
#define PSB_2D_SRCPAL_ADDR_MASK		(0x0FFFFFF8)
#define PSB_2D_SRCPAL_BYTEALIGN		(1024)

/*
 * Pattern Palette (PSB_2D_PAT_PAL_BH)
 */

#define PSB_2D_PATPAL_ADDR_SHIFT	(0)
#define PSB_2D_PATPAL_ADDR_CLRMASK	(0xF0000007)
#define PSB_2D_PATPAL_ADDR_MASK		(0x0FFFFFF8)
#define PSB_2D_PATPAL_BYTEALIGN		(1024)

/*
 * Rop3 Codes (2 LS bytes)
 */

#define PSB_2D_ROP3_SRCCOPY		(0xCCCC)
#define PSB_2D_ROP3_PATCOPY		(0xF0F0)
#define PSB_2D_ROP3_WHITENESS		(0xFFFF)
#define PSB_2D_ROP3_BLACKNESS		(0x0000)
#define PSB_2D_ROP3_SRC			(0xCC)
#define PSB_2D_ROP3_PAT			(0xF0)
#define PSB_2D_ROP3_DST			(0xAA)

/*
 * Sizes.
 */

#define PSB_SCENE_HW_COOKIE_SIZE	16
#define PSB_TA_MEM_HW_COOKIE_SIZE	16

/*
 * Scene stuff.
 */

#define PSB_NUM_HW_SCENES		2

/*
 * Scheduler completion actions.
 */

#define PSB_RASTER_BLOCK		0
#define PSB_RASTER			1
#define PSB_RETURN			2
#define PSB_TA				3

/* Power management */
#define PSB_PUNIT_PORT			0x04
#define PSB_OSPMBA			0x78
#define PSB_APMBA			0x7a
#define PSB_APM_CMD			0x0
#define PSB_APM_STS			0x04
#define PSB_PWRGT_VID_ENC_MASK		0x30
#define PSB_PWRGT_VID_DEC_MASK		0xc
#define PSB_PWRGT_GL3_MASK		0xc0

#define PSB_PM_SSC			0x20
#define PSB_PM_SSS			0x30
#define PSB_PWRGT_DISPLAY_MASK		0xc /*on a different BA than video/gfx*/
#define MDFLD_PWRGT_DISPLAY_A_CNTR	0x0000000c
#define MDFLD_PWRGT_DISPLAY_B_CNTR	0x0000c000
#define MDFLD_PWRGT_DISPLAY_C_CNTR	0x00030000
#define MDFLD_PWRGT_DISP_MIPI_CNTR	0x000c0000
#define MDFLD_PWRGT_DISPLAY_CNTR    (MDFLD_PWRGT_DISPLAY_A_CNTR | MDFLD_PWRGT_DISPLAY_B_CNTR | MDFLD_PWRGT_DISPLAY_C_CNTR | MDFLD_PWRGT_DISP_MIPI_CNTR) /* 0x000fc00c */
/* Display SSS register bits are different in A0 vs. B0 */
#define PSB_PWRGT_GFX_MASK		0x3
#define MDFLD_PWRGT_DISPLAY_A_STS	0x000000c0
#define MDFLD_PWRGT_DISPLAY_B_STS	0x00000300
#define MDFLD_PWRGT_DISPLAY_C_STS	0x00000c00
#define PSB_PWRGT_GFX_MASK_B0		0xc3
#define MDFLD_PWRGT_DISPLAY_A_STS_B0	0x0000000c
#define MDFLD_PWRGT_DISPLAY_B_STS_B0	0x0000c000
#define MDFLD_PWRGT_DISPLAY_C_STS_B0	0x00030000
#define MDFLD_PWRGT_DISP_MIPI_STS	0x000c0000
#define MDFLD_PWRGT_DISPLAY_STS_A0    (MDFLD_PWRGT_DISPLAY_A_STS | MDFLD_PWRGT_DISPLAY_B_STS | MDFLD_PWRGT_DISPLAY_C_STS | MDFLD_PWRGT_DISP_MIPI_STS) /* 0x000fc00c */
#define MDFLD_PWRGT_DISPLAY_STS_B0    (MDFLD_PWRGT_DISPLAY_A_STS_B0 | MDFLD_PWRGT_DISPLAY_B_STS_B0 | MDFLD_PWRGT_DISPLAY_C_STS_B0 | MDFLD_PWRGT_DISP_MIPI_STS) /* 0x000fc00c */
#endif
