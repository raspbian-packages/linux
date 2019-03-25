#ifndef __bif_slave_defs_h
#define __bif_slave_defs_h

/*
 * This file is autogenerated from
 *   file:           ../../inst/bif/rtl/bif_slave_regs.r
 *     id:           bif_slave_regs.r,v 1.5 2005/02/04 13:55:28 perz Exp 
 *     last modfied: Mon Apr 11 16:06:34 2005
 * 
 *   by /n/asic/design/tools/rdesc/src/rdes2c --outfile bif_slave_defs.h ../../inst/bif/rtl/bif_slave_regs.r
 *      id: $Id: bif_slave_defs.h,v 1.1 2007/02/13 11:55:30 starvik Exp $
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

/* C-code for register scope bif_slave */

/* Register rw_slave_cfg, scope bif_slave, type rw */
typedef struct {
  unsigned int slave_id     : 3;
  unsigned int use_slave_id : 1;
  unsigned int boot_rdy     : 1;
  unsigned int loopback     : 1;
  unsigned int dis          : 1;
  unsigned int dummy1       : 25;
} reg_bif_slave_rw_slave_cfg;
#define REG_RD_ADDR_bif_slave_rw_slave_cfg 0
#define REG_WR_ADDR_bif_slave_rw_slave_cfg 0

/* Register r_slave_mode, scope bif_slave, type r */
typedef struct {
  unsigned int ch0_mode : 1;
  unsigned int ch1_mode : 1;
  unsigned int ch2_mode : 1;
  unsigned int ch3_mode : 1;
  unsigned int dummy1   : 28;
} reg_bif_slave_r_slave_mode;
#define REG_RD_ADDR_bif_slave_r_slave_mode 4

/* Register rw_ch0_cfg, scope bif_slave, type rw */
typedef struct {
  unsigned int rd_hold     : 2;
  unsigned int access_mode : 1;
  unsigned int access_ctrl : 1;
  unsigned int data_cs     : 2;
  unsigned int dummy1      : 26;
} reg_bif_slave_rw_ch0_cfg;
#define REG_RD_ADDR_bif_slave_rw_ch0_cfg 16
#define REG_WR_ADDR_bif_slave_rw_ch0_cfg 16

/* Register rw_ch1_cfg, scope bif_slave, type rw */
typedef struct {
  unsigned int rd_hold     : 2;
  unsigned int access_mode : 1;
  unsigned int access_ctrl : 1;
  unsigned int data_cs     : 2;
  unsigned int dummy1      : 26;
} reg_bif_slave_rw_ch1_cfg;
#define REG_RD_ADDR_bif_slave_rw_ch1_cfg 20
#define REG_WR_ADDR_bif_slave_rw_ch1_cfg 20

/* Register rw_ch2_cfg, scope bif_slave, type rw */
typedef struct {
  unsigned int rd_hold     : 2;
  unsigned int access_mode : 1;
  unsigned int access_ctrl : 1;
  unsigned int data_cs     : 2;
  unsigned int dummy1      : 26;
} reg_bif_slave_rw_ch2_cfg;
#define REG_RD_ADDR_bif_slave_rw_ch2_cfg 24
#define REG_WR_ADDR_bif_slave_rw_ch2_cfg 24

/* Register rw_ch3_cfg, scope bif_slave, type rw */
typedef struct {
  unsigned int rd_hold     : 2;
  unsigned int access_mode : 1;
  unsigned int access_ctrl : 1;
  unsigned int data_cs     : 2;
  unsigned int dummy1      : 26;
} reg_bif_slave_rw_ch3_cfg;
#define REG_RD_ADDR_bif_slave_rw_ch3_cfg 28
#define REG_WR_ADDR_bif_slave_rw_ch3_cfg 28

/* Register rw_arb_cfg, scope bif_slave, type rw */
typedef struct {
  unsigned int brin_mode   : 1;
  unsigned int brout_mode  : 3;
  unsigned int bg_mode     : 3;
  unsigned int release     : 2;
  unsigned int acquire     : 1;
  unsigned int settle_time : 2;
  unsigned int dram_ctrl   : 1;
  unsigned int dummy1      : 19;
} reg_bif_slave_rw_arb_cfg;
#define REG_RD_ADDR_bif_slave_rw_arb_cfg 32
#define REG_WR_ADDR_bif_slave_rw_arb_cfg 32

/* Register r_arb_stat, scope bif_slave, type r */
typedef struct {
  unsigned int init_mode : 1;
  unsigned int mode      : 1;
  unsigned int brin      : 1;
  unsigned int brout     : 1;
  unsigned int bg        : 1;
  unsigned int dummy1    : 27;
} reg_bif_slave_r_arb_stat;
#define REG_RD_ADDR_bif_slave_r_arb_stat 36

/* Register rw_intr_mask, scope bif_slave, type rw */
typedef struct {
  unsigned int bus_release : 1;
  unsigned int bus_acquire : 1;
  unsigned int dummy1      : 30;
} reg_bif_slave_rw_intr_mask;
#define REG_RD_ADDR_bif_slave_rw_intr_mask 64
#define REG_WR_ADDR_bif_slave_rw_intr_mask 64

/* Register rw_ack_intr, scope bif_slave, type rw */
typedef struct {
  unsigned int bus_release : 1;
  unsigned int bus_acquire : 1;
  unsigned int dummy1      : 30;
} reg_bif_slave_rw_ack_intr;
#define REG_RD_ADDR_bif_slave_rw_ack_intr 68
#define REG_WR_ADDR_bif_slave_rw_ack_intr 68

/* Register r_intr, scope bif_slave, type r */
typedef struct {
  unsigned int bus_release : 1;
  unsigned int bus_acquire : 1;
  unsigned int dummy1      : 30;
} reg_bif_slave_r_intr;
#define REG_RD_ADDR_bif_slave_r_intr 72

/* Register r_masked_intr, scope bif_slave, type r */
typedef struct {
  unsigned int bus_release : 1;
  unsigned int bus_acquire : 1;
  unsigned int dummy1      : 30;
} reg_bif_slave_r_masked_intr;
#define REG_RD_ADDR_bif_slave_r_masked_intr 76


/* Constants */
enum {
  regk_bif_slave_active_hi                 = 0x00000003,
  regk_bif_slave_active_lo                 = 0x00000002,
  regk_bif_slave_addr                      = 0x00000000,
  regk_bif_slave_always                    = 0x00000001,
  regk_bif_slave_at_idle                   = 0x00000002,
  regk_bif_slave_burst_end                 = 0x00000003,
  regk_bif_slave_dma                       = 0x00000001,
  regk_bif_slave_hi                        = 0x00000003,
  regk_bif_slave_inv                       = 0x00000001,
  regk_bif_slave_lo                        = 0x00000002,
  regk_bif_slave_local                     = 0x00000001,
  regk_bif_slave_master                    = 0x00000000,
  regk_bif_slave_mode_reg                  = 0x00000001,
  regk_bif_slave_no                        = 0x00000000,
  regk_bif_slave_norm                      = 0x00000000,
  regk_bif_slave_on_access                 = 0x00000000,
  regk_bif_slave_rw_arb_cfg_default        = 0x00000000,
  regk_bif_slave_rw_ch0_cfg_default        = 0x00000000,
  regk_bif_slave_rw_ch1_cfg_default        = 0x00000000,
  regk_bif_slave_rw_ch2_cfg_default        = 0x00000000,
  regk_bif_slave_rw_ch3_cfg_default        = 0x00000000,
  regk_bif_slave_rw_intr_mask_default      = 0x00000000,
  regk_bif_slave_rw_slave_cfg_default      = 0x00000000,
  regk_bif_slave_shared                    = 0x00000000,
  regk_bif_slave_slave                     = 0x00000001,
  regk_bif_slave_t0ns                      = 0x00000003,
  regk_bif_slave_t10ns                     = 0x00000002,
  regk_bif_slave_t20ns                     = 0x00000003,
  regk_bif_slave_t30ns                     = 0x00000002,
  regk_bif_slave_t40ns                     = 0x00000001,
  regk_bif_slave_t50ns                     = 0x00000000,
  regk_bif_slave_yes                       = 0x00000001,
  regk_bif_slave_z                         = 0x00000004
};
#endif /* __bif_slave_defs_h */
