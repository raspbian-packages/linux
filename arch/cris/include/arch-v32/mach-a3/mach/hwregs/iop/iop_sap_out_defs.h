#ifndef __iop_sap_out_defs_h
#define __iop_sap_out_defs_h

/*
 * This file is autogenerated from
 *   file:           iop_sap_out.r
 * 
 *   by ../../../tools/rdesc/bin/rdes2c -outfile iop_sap_out_defs.h iop_sap_out.r
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

/* C-code for register scope iop_sap_out */

/* Register rw_gen_gated, scope iop_sap_out, type rw */
typedef struct {
  unsigned int clk0_src       : 2;
  unsigned int clk0_gate_src  : 2;
  unsigned int clk0_force_src : 3;
  unsigned int clk1_src       : 2;
  unsigned int clk1_gate_src  : 2;
  unsigned int clk1_force_src : 3;
  unsigned int dummy1         : 18;
} reg_iop_sap_out_rw_gen_gated;
#define REG_RD_ADDR_iop_sap_out_rw_gen_gated 0
#define REG_WR_ADDR_iop_sap_out_rw_gen_gated 0

/* Register rw_bus, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte0_clk_sel   : 2;
  unsigned int byte0_clk_ext   : 2;
  unsigned int byte0_gated_clk : 1;
  unsigned int byte0_clk_inv   : 1;
  unsigned int byte0_delay     : 1;
  unsigned int byte1_clk_sel   : 2;
  unsigned int byte1_clk_ext   : 2;
  unsigned int byte1_gated_clk : 1;
  unsigned int byte1_clk_inv   : 1;
  unsigned int byte1_delay     : 1;
  unsigned int byte2_clk_sel   : 2;
  unsigned int byte2_clk_ext   : 2;
  unsigned int byte2_gated_clk : 1;
  unsigned int byte2_clk_inv   : 1;
  unsigned int byte2_delay     : 1;
  unsigned int byte3_clk_sel   : 2;
  unsigned int byte3_clk_ext   : 2;
  unsigned int byte3_gated_clk : 1;
  unsigned int byte3_clk_inv   : 1;
  unsigned int byte3_delay     : 1;
  unsigned int dummy1          : 4;
} reg_iop_sap_out_rw_bus;
#define REG_RD_ADDR_iop_sap_out_rw_bus 4
#define REG_WR_ADDR_iop_sap_out_rw_bus 4

/* Register rw_bus_lo_oe, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte0_clk_sel   : 2;
  unsigned int byte0_clk_ext   : 2;
  unsigned int byte0_gated_clk : 1;
  unsigned int byte0_clk_inv   : 1;
  unsigned int byte0_delay     : 1;
  unsigned int byte0_logic     : 2;
  unsigned int byte0_logic_src : 2;
  unsigned int byte1_clk_sel   : 2;
  unsigned int byte1_clk_ext   : 2;
  unsigned int byte1_gated_clk : 1;
  unsigned int byte1_clk_inv   : 1;
  unsigned int byte1_delay     : 1;
  unsigned int byte1_logic     : 2;
  unsigned int byte1_logic_src : 2;
  unsigned int dummy1          : 10;
} reg_iop_sap_out_rw_bus_lo_oe;
#define REG_RD_ADDR_iop_sap_out_rw_bus_lo_oe 8
#define REG_WR_ADDR_iop_sap_out_rw_bus_lo_oe 8

/* Register rw_bus_hi_oe, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte2_clk_sel   : 2;
  unsigned int byte2_clk_ext   : 2;
  unsigned int byte2_gated_clk : 1;
  unsigned int byte2_clk_inv   : 1;
  unsigned int byte2_delay     : 1;
  unsigned int byte2_logic     : 2;
  unsigned int byte2_logic_src : 2;
  unsigned int byte3_clk_sel   : 2;
  unsigned int byte3_clk_ext   : 2;
  unsigned int byte3_gated_clk : 1;
  unsigned int byte3_clk_inv   : 1;
  unsigned int byte3_delay     : 1;
  unsigned int byte3_logic     : 2;
  unsigned int byte3_logic_src : 2;
  unsigned int dummy1          : 10;
} reg_iop_sap_out_rw_bus_hi_oe;
#define REG_RD_ADDR_iop_sap_out_rw_bus_hi_oe 12
#define REG_WR_ADDR_iop_sap_out_rw_bus_hi_oe 12

#define STRIDE_iop_sap_out_rw_gio 4
/* Register rw_gio, scope iop_sap_out, type rw */
typedef struct {
  unsigned int out_clk_sel   : 3;
  unsigned int out_clk_ext   : 2;
  unsigned int out_gated_clk : 1;
  unsigned int out_clk_inv   : 1;
  unsigned int out_delay     : 1;
  unsigned int out_logic     : 2;
  unsigned int out_logic_src : 2;
  unsigned int oe_clk_sel    : 3;
  unsigned int oe_clk_ext    : 2;
  unsigned int oe_gated_clk  : 1;
  unsigned int oe_clk_inv    : 1;
  unsigned int oe_delay      : 1;
  unsigned int oe_logic      : 2;
  unsigned int oe_logic_src  : 2;
  unsigned int dummy1        : 8;
} reg_iop_sap_out_rw_gio;
#define REG_RD_ADDR_iop_sap_out_rw_gio 16
#define REG_WR_ADDR_iop_sap_out_rw_gio 16


/* Constants */
enum {
  regk_iop_sap_out_always                  = 0x00000001,
  regk_iop_sap_out_and                     = 0x00000002,
  regk_iop_sap_out_clk0                    = 0x00000000,
  regk_iop_sap_out_clk1                    = 0x00000001,
  regk_iop_sap_out_clk12                   = 0x00000004,
  regk_iop_sap_out_clk200                  = 0x00000000,
  regk_iop_sap_out_ext                     = 0x00000002,
  regk_iop_sap_out_gated                   = 0x00000003,
  regk_iop_sap_out_gio0                    = 0x00000000,
  regk_iop_sap_out_gio1                    = 0x00000000,
  regk_iop_sap_out_gio16                   = 0x00000002,
  regk_iop_sap_out_gio17                   = 0x00000002,
  regk_iop_sap_out_gio24                   = 0x00000003,
  regk_iop_sap_out_gio25                   = 0x00000003,
  regk_iop_sap_out_gio8                    = 0x00000001,
  regk_iop_sap_out_gio9                    = 0x00000001,
  regk_iop_sap_out_gio_out10               = 0x00000005,
  regk_iop_sap_out_gio_out18               = 0x00000006,
  regk_iop_sap_out_gio_out2                = 0x00000004,
  regk_iop_sap_out_gio_out26               = 0x00000007,
  regk_iop_sap_out_inv                     = 0x00000001,
  regk_iop_sap_out_nand                    = 0x00000003,
  regk_iop_sap_out_no                      = 0x00000000,
  regk_iop_sap_out_none                    = 0x00000000,
  regk_iop_sap_out_one                     = 0x00000001,
  regk_iop_sap_out_rw_bus_default          = 0x00000000,
  regk_iop_sap_out_rw_bus_hi_oe_default    = 0x00000000,
  regk_iop_sap_out_rw_bus_lo_oe_default    = 0x00000000,
  regk_iop_sap_out_rw_gen_gated_default    = 0x00000000,
  regk_iop_sap_out_rw_gio_default          = 0x00000000,
  regk_iop_sap_out_rw_gio_size             = 0x00000020,
  regk_iop_sap_out_spu_gio6                = 0x00000002,
  regk_iop_sap_out_spu_gio7                = 0x00000003,
  regk_iop_sap_out_timer_grp0_tmr2         = 0x00000000,
  regk_iop_sap_out_timer_grp0_tmr3         = 0x00000001,
  regk_iop_sap_out_timer_grp1_tmr2         = 0x00000002,
  regk_iop_sap_out_timer_grp1_tmr3         = 0x00000003,
  regk_iop_sap_out_tmr200                  = 0x00000001,
  regk_iop_sap_out_yes                     = 0x00000001
};
#endif /* __iop_sap_out_defs_h */
