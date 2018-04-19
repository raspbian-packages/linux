/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __iop_fifo_in_defs_h
#define __iop_fifo_in_defs_h

/*
 * This file is autogenerated from
 *   file:           ../../inst/io_proc/rtl/iop_fifo_in.r
 *     id:           <not found>
 *     last modfied: Mon Apr 11 16:10:07 2005
 *
 *   by /n/asic/design/tools/rdesc/src/rdes2c --outfile iop_fifo_in_defs.h ../../inst/io_proc/rtl/iop_fifo_in.r
 *      id: $Id: iop_fifo_in_defs.h,v 1.4 2005/04/24 18:31:05 starvik Exp $
 * Any changes here will be lost.
 *
 * -*- buffer-read-only: t -*-
 */
/* Main access macros */
#ifndef REG_RD
#define REG_RD( scope, inst, reg ) \
  REG_READ( reg_##scope##_##reg, \
            (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_WR
#define REG_WR( scope, inst, reg, val ) \
  REG_WRITE( reg_##scope##_##reg, \
             (inst) + REG_WR_ADDR_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_VECT
#define REG_RD_VECT( scope, inst, reg, index ) \
  REG_READ( reg_##scope##_##reg, \
            (inst) + REG_RD_ADDR_##scope##_##reg + \
	    (index) * STRIDE_##scope##_##reg )
#endif

#ifndef REG_WR_VECT
#define REG_WR_VECT( scope, inst, reg, index, val ) \
  REG_WRITE( reg_##scope##_##reg, \
             (inst) + REG_WR_ADDR_##scope##_##reg + \
	     (index) * STRIDE_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_INT
#define REG_RD_INT( scope, inst, reg ) \
  REG_READ( int, (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_WR_INT
#define REG_WR_INT( scope, inst, reg, val ) \
  REG_WRITE( int, (inst) + REG_WR_ADDR_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_INT_VECT
#define REG_RD_INT_VECT( scope, inst, reg, index ) \
  REG_READ( int, (inst) + REG_RD_ADDR_##scope##_##reg + \
	    (index) * STRIDE_##scope##_##reg )
#endif

#ifndef REG_WR_INT_VECT
#define REG_WR_INT_VECT( scope, inst, reg, index, val ) \
  REG_WRITE( int, (inst) + REG_WR_ADDR_##scope##_##reg + \
	     (index) * STRIDE_##scope##_##reg, (val) )
#endif

#ifndef REG_TYPE_CONV
#define REG_TYPE_CONV( type, orgtype, val ) \
  ( { union { orgtype o; type n; } r; r.o = val; r.n; } )
#endif

#ifndef reg_page_size
#define reg_page_size 8192
#endif

#ifndef REG_ADDR
#define REG_ADDR( scope, inst, reg ) \
  ( (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_ADDR_VECT
#define REG_ADDR_VECT( scope, inst, reg, index ) \
  ( (inst) + REG_RD_ADDR_##scope##_##reg + \
    (index) * STRIDE_##scope##_##reg )
#endif

/* C-code for register scope iop_fifo_in */

/* Register rw_cfg, scope iop_fifo_in, type rw */
typedef struct {
  unsigned int avail_lim       : 3;
  unsigned int byte_order      : 2;
  unsigned int trig            : 2;
  unsigned int last_dis_dif_in : 1;
  unsigned int mode            : 2;
  unsigned int dummy1          : 22;
} reg_iop_fifo_in_rw_cfg;
#define REG_RD_ADDR_iop_fifo_in_rw_cfg 0
#define REG_WR_ADDR_iop_fifo_in_rw_cfg 0

/* Register rw_ctrl, scope iop_fifo_in, type rw */
typedef struct {
  unsigned int dif_in_en  : 1;
  unsigned int dif_out_en : 1;
  unsigned int dummy1     : 30;
} reg_iop_fifo_in_rw_ctrl;
#define REG_RD_ADDR_iop_fifo_in_rw_ctrl 4
#define REG_WR_ADDR_iop_fifo_in_rw_ctrl 4

/* Register r_stat, scope iop_fifo_in, type r */
typedef struct {
  unsigned int avail_bytes : 4;
  unsigned int last        : 8;
  unsigned int dif_in_en   : 1;
  unsigned int dif_out_en  : 1;
  unsigned int dummy1      : 18;
} reg_iop_fifo_in_r_stat;
#define REG_RD_ADDR_iop_fifo_in_r_stat 8

/* Register rs_rd1byte, scope iop_fifo_in, type rs */
typedef struct {
  unsigned int data : 8;
  unsigned int dummy1 : 24;
} reg_iop_fifo_in_rs_rd1byte;
#define REG_RD_ADDR_iop_fifo_in_rs_rd1byte 12

/* Register r_rd1byte, scope iop_fifo_in, type r */
typedef struct {
  unsigned int data : 8;
  unsigned int dummy1 : 24;
} reg_iop_fifo_in_r_rd1byte;
#define REG_RD_ADDR_iop_fifo_in_r_rd1byte 16

/* Register rs_rd2byte, scope iop_fifo_in, type rs */
typedef struct {
  unsigned int data : 16;
  unsigned int dummy1 : 16;
} reg_iop_fifo_in_rs_rd2byte;
#define REG_RD_ADDR_iop_fifo_in_rs_rd2byte 20

/* Register r_rd2byte, scope iop_fifo_in, type r */
typedef struct {
  unsigned int data : 16;
  unsigned int dummy1 : 16;
} reg_iop_fifo_in_r_rd2byte;
#define REG_RD_ADDR_iop_fifo_in_r_rd2byte 24

/* Register rs_rd3byte, scope iop_fifo_in, type rs */
typedef struct {
  unsigned int data : 24;
  unsigned int dummy1 : 8;
} reg_iop_fifo_in_rs_rd3byte;
#define REG_RD_ADDR_iop_fifo_in_rs_rd3byte 28

/* Register r_rd3byte, scope iop_fifo_in, type r */
typedef struct {
  unsigned int data : 24;
  unsigned int dummy1 : 8;
} reg_iop_fifo_in_r_rd3byte;
#define REG_RD_ADDR_iop_fifo_in_r_rd3byte 32

/* Register rs_rd4byte, scope iop_fifo_in, type rs */
typedef struct {
  unsigned int data : 32;
} reg_iop_fifo_in_rs_rd4byte;
#define REG_RD_ADDR_iop_fifo_in_rs_rd4byte 36

/* Register r_rd4byte, scope iop_fifo_in, type r */
typedef struct {
  unsigned int data : 32;
} reg_iop_fifo_in_r_rd4byte;
#define REG_RD_ADDR_iop_fifo_in_r_rd4byte 40

/* Register rw_set_last, scope iop_fifo_in, type rw */
typedef unsigned int reg_iop_fifo_in_rw_set_last;
#define REG_RD_ADDR_iop_fifo_in_rw_set_last 44
#define REG_WR_ADDR_iop_fifo_in_rw_set_last 44

/* Register rw_strb_dif_in, scope iop_fifo_in, type rw */
typedef struct {
  unsigned int last : 2;
  unsigned int dummy1 : 30;
} reg_iop_fifo_in_rw_strb_dif_in;
#define REG_RD_ADDR_iop_fifo_in_rw_strb_dif_in 48
#define REG_WR_ADDR_iop_fifo_in_rw_strb_dif_in 48

/* Register rw_intr_mask, scope iop_fifo_in, type rw */
typedef struct {
  unsigned int urun      : 1;
  unsigned int last_data : 1;
  unsigned int dav       : 1;
  unsigned int avail     : 1;
  unsigned int orun      : 1;
  unsigned int dummy1    : 27;
} reg_iop_fifo_in_rw_intr_mask;
#define REG_RD_ADDR_iop_fifo_in_rw_intr_mask 52
#define REG_WR_ADDR_iop_fifo_in_rw_intr_mask 52

/* Register rw_ack_intr, scope iop_fifo_in, type rw */
typedef struct {
  unsigned int urun      : 1;
  unsigned int last_data : 1;
  unsigned int dav       : 1;
  unsigned int avail     : 1;
  unsigned int orun      : 1;
  unsigned int dummy1    : 27;
} reg_iop_fifo_in_rw_ack_intr;
#define REG_RD_ADDR_iop_fifo_in_rw_ack_intr 56
#define REG_WR_ADDR_iop_fifo_in_rw_ack_intr 56

/* Register r_intr, scope iop_fifo_in, type r */
typedef struct {
  unsigned int urun      : 1;
  unsigned int last_data : 1;
  unsigned int dav       : 1;
  unsigned int avail     : 1;
  unsigned int orun      : 1;
  unsigned int dummy1    : 27;
} reg_iop_fifo_in_r_intr;
#define REG_RD_ADDR_iop_fifo_in_r_intr 60

/* Register r_masked_intr, scope iop_fifo_in, type r */
typedef struct {
  unsigned int urun      : 1;
  unsigned int last_data : 1;
  unsigned int dav       : 1;
  unsigned int avail     : 1;
  unsigned int orun      : 1;
  unsigned int dummy1    : 27;
} reg_iop_fifo_in_r_masked_intr;
#define REG_RD_ADDR_iop_fifo_in_r_masked_intr 64


/* Constants */
enum {
  regk_iop_fifo_in_dif_in                  = 0x00000002,
  regk_iop_fifo_in_hi                      = 0x00000000,
  regk_iop_fifo_in_neg                     = 0x00000002,
  regk_iop_fifo_in_no                      = 0x00000000,
  regk_iop_fifo_in_order16                 = 0x00000001,
  regk_iop_fifo_in_order24                 = 0x00000002,
  regk_iop_fifo_in_order32                 = 0x00000003,
  regk_iop_fifo_in_order8                  = 0x00000000,
  regk_iop_fifo_in_pos                     = 0x00000001,
  regk_iop_fifo_in_pos_neg                 = 0x00000003,
  regk_iop_fifo_in_rw_cfg_default          = 0x00000024,
  regk_iop_fifo_in_rw_ctrl_default         = 0x00000000,
  regk_iop_fifo_in_rw_intr_mask_default    = 0x00000000,
  regk_iop_fifo_in_rw_set_last_default     = 0x00000000,
  regk_iop_fifo_in_rw_strb_dif_in_default  = 0x00000000,
  regk_iop_fifo_in_size16                  = 0x00000002,
  regk_iop_fifo_in_size24                  = 0x00000001,
  regk_iop_fifo_in_size32                  = 0x00000000,
  regk_iop_fifo_in_size8                   = 0x00000003,
  regk_iop_fifo_in_yes                     = 0x00000001
};
#endif /* __iop_fifo_in_defs_h */
