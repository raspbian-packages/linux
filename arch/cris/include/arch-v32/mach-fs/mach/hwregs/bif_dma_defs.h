#ifndef __bif_dma_defs_h
#define __bif_dma_defs_h

/*
 * This file is autogenerated from
 *   file:           ../../inst/bif/rtl/bif_dma_regs.r
 *     id:           bif_dma_regs.r,v 1.6 2005/02/04 13:28:31 perz Exp 
 *     last modfied: Mon Apr 11 16:06:33 2005
 * 
 *   by /n/asic/design/tools/rdesc/src/rdes2c --outfile bif_dma_defs.h ../../inst/bif/rtl/bif_dma_regs.r
 *      id: $Id: bif_dma_defs.h,v 1.1 2007/02/13 11:55:30 starvik Exp $
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

/* C-code for register scope bif_dma */

/* Register rw_ch0_ctrl, scope bif_dma, type rw */
typedef struct {
  unsigned int bw         : 2;
  unsigned int burst_len  : 1;
  unsigned int cont       : 1;
  unsigned int end_pad    : 1;
  unsigned int cnt        : 1;
  unsigned int dreq_pin   : 3;
  unsigned int dreq_mode  : 2;
  unsigned int tc_in_pin  : 3;
  unsigned int tc_in_mode : 2;
  unsigned int bus_mode   : 2;
  unsigned int rate_en    : 1;
  unsigned int wr_all     : 1;
  unsigned int dummy1     : 12;
} reg_bif_dma_rw_ch0_ctrl;
#define REG_RD_ADDR_bif_dma_rw_ch0_ctrl 0
#define REG_WR_ADDR_bif_dma_rw_ch0_ctrl 0

/* Register rw_ch0_addr, scope bif_dma, type rw */
typedef struct {
  unsigned int addr : 32;
} reg_bif_dma_rw_ch0_addr;
#define REG_RD_ADDR_bif_dma_rw_ch0_addr 4
#define REG_WR_ADDR_bif_dma_rw_ch0_addr 4

/* Register rw_ch0_start, scope bif_dma, type rw */
typedef struct {
  unsigned int run : 1;
  unsigned int dummy1 : 31;
} reg_bif_dma_rw_ch0_start;
#define REG_RD_ADDR_bif_dma_rw_ch0_start 8
#define REG_WR_ADDR_bif_dma_rw_ch0_start 8

/* Register rw_ch0_cnt, scope bif_dma, type rw */
typedef struct {
  unsigned int start_cnt : 16;
  unsigned int dummy1    : 16;
} reg_bif_dma_rw_ch0_cnt;
#define REG_RD_ADDR_bif_dma_rw_ch0_cnt 12
#define REG_WR_ADDR_bif_dma_rw_ch0_cnt 12

/* Register r_ch0_stat, scope bif_dma, type r */
typedef struct {
  unsigned int cnt : 16;
  unsigned int dummy1 : 15;
  unsigned int run : 1;
} reg_bif_dma_r_ch0_stat;
#define REG_RD_ADDR_bif_dma_r_ch0_stat 16

/* Register rw_ch1_ctrl, scope bif_dma, type rw */
typedef struct {
  unsigned int bw          : 2;
  unsigned int burst_len   : 1;
  unsigned int cont        : 1;
  unsigned int end_discard : 1;
  unsigned int cnt         : 1;
  unsigned int dreq_pin    : 3;
  unsigned int dreq_mode   : 2;
  unsigned int tc_in_pin   : 3;
  unsigned int tc_in_mode  : 2;
  unsigned int bus_mode    : 2;
  unsigned int rate_en     : 1;
  unsigned int dummy1      : 13;
} reg_bif_dma_rw_ch1_ctrl;
#define REG_RD_ADDR_bif_dma_rw_ch1_ctrl 32
#define REG_WR_ADDR_bif_dma_rw_ch1_ctrl 32

/* Register rw_ch1_addr, scope bif_dma, type rw */
typedef struct {
  unsigned int addr : 32;
} reg_bif_dma_rw_ch1_addr;
#define REG_RD_ADDR_bif_dma_rw_ch1_addr 36
#define REG_WR_ADDR_bif_dma_rw_ch1_addr 36

/* Register rw_ch1_start, scope bif_dma, type rw */
typedef struct {
  unsigned int run : 1;
  unsigned int dummy1 : 31;
} reg_bif_dma_rw_ch1_start;
#define REG_RD_ADDR_bif_dma_rw_ch1_start 40
#define REG_WR_ADDR_bif_dma_rw_ch1_start 40

/* Register rw_ch1_cnt, scope bif_dma, type rw */
typedef struct {
  unsigned int start_cnt : 16;
  unsigned int dummy1    : 16;
} reg_bif_dma_rw_ch1_cnt;
#define REG_RD_ADDR_bif_dma_rw_ch1_cnt 44
#define REG_WR_ADDR_bif_dma_rw_ch1_cnt 44

/* Register r_ch1_stat, scope bif_dma, type r */
typedef struct {
  unsigned int cnt : 16;
  unsigned int dummy1 : 15;
  unsigned int run : 1;
} reg_bif_dma_r_ch1_stat;
#define REG_RD_ADDR_bif_dma_r_ch1_stat 48

/* Register rw_ch2_ctrl, scope bif_dma, type rw */
typedef struct {
  unsigned int bw         : 2;
  unsigned int burst_len  : 1;
  unsigned int cont       : 1;
  unsigned int end_pad    : 1;
  unsigned int cnt        : 1;
  unsigned int dreq_pin   : 3;
  unsigned int dreq_mode  : 2;
  unsigned int tc_in_pin  : 3;
  unsigned int tc_in_mode : 2;
  unsigned int bus_mode   : 2;
  unsigned int rate_en    : 1;
  unsigned int wr_all     : 1;
  unsigned int dummy1     : 12;
} reg_bif_dma_rw_ch2_ctrl;
#define REG_RD_ADDR_bif_dma_rw_ch2_ctrl 64
#define REG_WR_ADDR_bif_dma_rw_ch2_ctrl 64

/* Register rw_ch2_addr, scope bif_dma, type rw */
typedef struct {
  unsigned int addr : 32;
} reg_bif_dma_rw_ch2_addr;
#define REG_RD_ADDR_bif_dma_rw_ch2_addr 68
#define REG_WR_ADDR_bif_dma_rw_ch2_addr 68

/* Register rw_ch2_start, scope bif_dma, type rw */
typedef struct {
  unsigned int run : 1;
  unsigned int dummy1 : 31;
} reg_bif_dma_rw_ch2_start;
#define REG_RD_ADDR_bif_dma_rw_ch2_start 72
#define REG_WR_ADDR_bif_dma_rw_ch2_start 72

/* Register rw_ch2_cnt, scope bif_dma, type rw */
typedef struct {
  unsigned int start_cnt : 16;
  unsigned int dummy1    : 16;
} reg_bif_dma_rw_ch2_cnt;
#define REG_RD_ADDR_bif_dma_rw_ch2_cnt 76
#define REG_WR_ADDR_bif_dma_rw_ch2_cnt 76

/* Register r_ch2_stat, scope bif_dma, type r */
typedef struct {
  unsigned int cnt : 16;
  unsigned int dummy1 : 15;
  unsigned int run : 1;
} reg_bif_dma_r_ch2_stat;
#define REG_RD_ADDR_bif_dma_r_ch2_stat 80

/* Register rw_ch3_ctrl, scope bif_dma, type rw */
typedef struct {
  unsigned int bw          : 2;
  unsigned int burst_len   : 1;
  unsigned int cont        : 1;
  unsigned int end_discard : 1;
  unsigned int cnt         : 1;
  unsigned int dreq_pin    : 3;
  unsigned int dreq_mode   : 2;
  unsigned int tc_in_pin   : 3;
  unsigned int tc_in_mode  : 2;
  unsigned int bus_mode    : 2;
  unsigned int rate_en     : 1;
  unsigned int dummy1      : 13;
} reg_bif_dma_rw_ch3_ctrl;
#define REG_RD_ADDR_bif_dma_rw_ch3_ctrl 96
#define REG_WR_ADDR_bif_dma_rw_ch3_ctrl 96

/* Register rw_ch3_addr, scope bif_dma, type rw */
typedef struct {
  unsigned int addr : 32;
} reg_bif_dma_rw_ch3_addr;
#define REG_RD_ADDR_bif_dma_rw_ch3_addr 100
#define REG_WR_ADDR_bif_dma_rw_ch3_addr 100

/* Register rw_ch3_start, scope bif_dma, type rw */
typedef struct {
  unsigned int run : 1;
  unsigned int dummy1 : 31;
} reg_bif_dma_rw_ch3_start;
#define REG_RD_ADDR_bif_dma_rw_ch3_start 104
#define REG_WR_ADDR_bif_dma_rw_ch3_start 104

/* Register rw_ch3_cnt, scope bif_dma, type rw */
typedef struct {
  unsigned int start_cnt : 16;
  unsigned int dummy1    : 16;
} reg_bif_dma_rw_ch3_cnt;
#define REG_RD_ADDR_bif_dma_rw_ch3_cnt 108
#define REG_WR_ADDR_bif_dma_rw_ch3_cnt 108

/* Register r_ch3_stat, scope bif_dma, type r */
typedef struct {
  unsigned int cnt : 16;
  unsigned int dummy1 : 15;
  unsigned int run : 1;
} reg_bif_dma_r_ch3_stat;
#define REG_RD_ADDR_bif_dma_r_ch3_stat 112

/* Register rw_intr_mask, scope bif_dma, type rw */
typedef struct {
  unsigned int ext_dma0 : 1;
  unsigned int ext_dma1 : 1;
  unsigned int ext_dma2 : 1;
  unsigned int ext_dma3 : 1;
  unsigned int dummy1   : 28;
} reg_bif_dma_rw_intr_mask;
#define REG_RD_ADDR_bif_dma_rw_intr_mask 128
#define REG_WR_ADDR_bif_dma_rw_intr_mask 128

/* Register rw_ack_intr, scope bif_dma, type rw */
typedef struct {
  unsigned int ext_dma0 : 1;
  unsigned int ext_dma1 : 1;
  unsigned int ext_dma2 : 1;
  unsigned int ext_dma3 : 1;
  unsigned int dummy1   : 28;
} reg_bif_dma_rw_ack_intr;
#define REG_RD_ADDR_bif_dma_rw_ack_intr 132
#define REG_WR_ADDR_bif_dma_rw_ack_intr 132

/* Register r_intr, scope bif_dma, type r */
typedef struct {
  unsigned int ext_dma0 : 1;
  unsigned int ext_dma1 : 1;
  unsigned int ext_dma2 : 1;
  unsigned int ext_dma3 : 1;
  unsigned int dummy1   : 28;
} reg_bif_dma_r_intr;
#define REG_RD_ADDR_bif_dma_r_intr 136

/* Register r_masked_intr, scope bif_dma, type r */
typedef struct {
  unsigned int ext_dma0 : 1;
  unsigned int ext_dma1 : 1;
  unsigned int ext_dma2 : 1;
  unsigned int ext_dma3 : 1;
  unsigned int dummy1   : 28;
} reg_bif_dma_r_masked_intr;
#define REG_RD_ADDR_bif_dma_r_masked_intr 140

/* Register rw_pin0_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin0_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin0_cfg 160
#define REG_WR_ADDR_bif_dma_rw_pin0_cfg 160

/* Register rw_pin1_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin1_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin1_cfg 164
#define REG_WR_ADDR_bif_dma_rw_pin1_cfg 164

/* Register rw_pin2_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin2_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin2_cfg 168
#define REG_WR_ADDR_bif_dma_rw_pin2_cfg 168

/* Register rw_pin3_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin3_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin3_cfg 172
#define REG_WR_ADDR_bif_dma_rw_pin3_cfg 172

/* Register rw_pin4_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin4_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin4_cfg 176
#define REG_WR_ADDR_bif_dma_rw_pin4_cfg 176

/* Register rw_pin5_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin5_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin5_cfg 180
#define REG_WR_ADDR_bif_dma_rw_pin5_cfg 180

/* Register rw_pin6_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin6_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin6_cfg 184
#define REG_WR_ADDR_bif_dma_rw_pin6_cfg 184

/* Register rw_pin7_cfg, scope bif_dma, type rw */
typedef struct {
  unsigned int master_ch   : 2;
  unsigned int master_mode : 3;
  unsigned int slave_ch    : 2;
  unsigned int slave_mode  : 3;
  unsigned int dummy1      : 22;
} reg_bif_dma_rw_pin7_cfg;
#define REG_RD_ADDR_bif_dma_rw_pin7_cfg 188
#define REG_WR_ADDR_bif_dma_rw_pin7_cfg 188

/* Register r_pin_stat, scope bif_dma, type r */
typedef struct {
  unsigned int pin0 : 1;
  unsigned int pin1 : 1;
  unsigned int pin2 : 1;
  unsigned int pin3 : 1;
  unsigned int pin4 : 1;
  unsigned int pin5 : 1;
  unsigned int pin6 : 1;
  unsigned int pin7 : 1;
  unsigned int dummy1 : 24;
} reg_bif_dma_r_pin_stat;
#define REG_RD_ADDR_bif_dma_r_pin_stat 192


/* Constants */
enum {
  regk_bif_dma_as_master                   = 0x00000001,
  regk_bif_dma_as_slave                    = 0x00000001,
  regk_bif_dma_burst1                      = 0x00000000,
  regk_bif_dma_burst8                      = 0x00000001,
  regk_bif_dma_bw16                        = 0x00000001,
  regk_bif_dma_bw32                        = 0x00000002,
  regk_bif_dma_bw8                         = 0x00000000,
  regk_bif_dma_dack                        = 0x00000006,
  regk_bif_dma_dack_inv                    = 0x00000007,
  regk_bif_dma_force                       = 0x00000001,
  regk_bif_dma_hi                          = 0x00000003,
  regk_bif_dma_inv                         = 0x00000003,
  regk_bif_dma_lo                          = 0x00000002,
  regk_bif_dma_master                      = 0x00000001,
  regk_bif_dma_no                          = 0x00000000,
  regk_bif_dma_norm                        = 0x00000002,
  regk_bif_dma_off                         = 0x00000000,
  regk_bif_dma_rw_ch0_ctrl_default         = 0x00000000,
  regk_bif_dma_rw_ch0_start_default        = 0x00000000,
  regk_bif_dma_rw_ch1_ctrl_default         = 0x00000000,
  regk_bif_dma_rw_ch1_start_default        = 0x00000000,
  regk_bif_dma_rw_ch2_ctrl_default         = 0x00000000,
  regk_bif_dma_rw_ch2_start_default        = 0x00000000,
  regk_bif_dma_rw_ch3_ctrl_default         = 0x00000000,
  regk_bif_dma_rw_ch3_start_default        = 0x00000000,
  regk_bif_dma_rw_intr_mask_default        = 0x00000000,
  regk_bif_dma_rw_pin0_cfg_default         = 0x00000000,
  regk_bif_dma_rw_pin1_cfg_default         = 0x00000000,
  regk_bif_dma_rw_pin2_cfg_default         = 0x00000000,
  regk_bif_dma_rw_pin3_cfg_default         = 0x00000000,
  regk_bif_dma_rw_pin4_cfg_default         = 0x00000000,
  regk_bif_dma_rw_pin5_cfg_default         = 0x00000000,
  regk_bif_dma_rw_pin6_cfg_default         = 0x00000000,
  regk_bif_dma_rw_pin7_cfg_default         = 0x00000000,
  regk_bif_dma_slave                       = 0x00000002,
  regk_bif_dma_sreq                        = 0x00000006,
  regk_bif_dma_sreq_inv                    = 0x00000007,
  regk_bif_dma_tc                          = 0x00000004,
  regk_bif_dma_tc_inv                      = 0x00000005,
  regk_bif_dma_yes                         = 0x00000001
};
#endif /* __bif_dma_defs_h */
