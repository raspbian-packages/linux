#ifndef __clkgen_defs_h
#define __clkgen_defs_h

/*
 * This file is autogenerated from
 *   file:           clkgen.r
 * 
 *   by ../../../tools/rdesc/bin/rdes2c -outfile clkgen_defs.h clkgen.r
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

/* C-code for register scope clkgen */

/* Register r_bootsel, scope clkgen, type r */
typedef struct {
  unsigned int boot_mode       : 5;
  unsigned int intern_main_clk : 1;
  unsigned int extern_usb2_clk : 1;
  unsigned int dummy1          : 25;
} reg_clkgen_r_bootsel;
#define REG_RD_ADDR_clkgen_r_bootsel 0

/* Register rw_clk_ctrl, scope clkgen, type rw */
typedef struct {
  unsigned int pll             : 1;
  unsigned int cpu             : 1;
  unsigned int iop_usb         : 1;
  unsigned int vin             : 1;
  unsigned int sclr            : 1;
  unsigned int h264            : 1;
  unsigned int ddr2            : 1;
  unsigned int vout_hist       : 1;
  unsigned int eth             : 1;
  unsigned int ccd_tg_200      : 1;
  unsigned int dma0_1_eth      : 1;
  unsigned int ccd_tg_100      : 1;
  unsigned int jpeg            : 1;
  unsigned int sser_ser_dma6_7 : 1;
  unsigned int strdma0_2_video : 1;
  unsigned int dma2_3_strcop   : 1;
  unsigned int dma4_5_iop      : 1;
  unsigned int dma9_11         : 1;
  unsigned int memarb_bar_ddr  : 1;
  unsigned int sclr_h264       : 1;
  unsigned int dummy1          : 12;
} reg_clkgen_rw_clk_ctrl;
#define REG_RD_ADDR_clkgen_rw_clk_ctrl 4
#define REG_WR_ADDR_clkgen_rw_clk_ctrl 4


/* Constants */
enum {
  regk_clkgen_eth1000_rx                   = 0x0000000c,
  regk_clkgen_eth1000_tx                   = 0x0000000e,
  regk_clkgen_eth100_rx                    = 0x0000001d,
  regk_clkgen_eth100_rx_half               = 0x0000001c,
  regk_clkgen_eth100_tx                    = 0x0000001f,
  regk_clkgen_eth100_tx_half               = 0x0000001e,
  regk_clkgen_nand_3_2                     = 0x00000000,
  regk_clkgen_nand_3_2_0x30                = 0x00000002,
  regk_clkgen_nand_3_2_0x30_pll            = 0x00000012,
  regk_clkgen_nand_3_2_pll                 = 0x00000010,
  regk_clkgen_nand_3_3                     = 0x00000001,
  regk_clkgen_nand_3_3_0x30                = 0x00000003,
  regk_clkgen_nand_3_3_0x30_pll            = 0x00000013,
  regk_clkgen_nand_3_3_pll                 = 0x00000011,
  regk_clkgen_nand_4_2                     = 0x00000004,
  regk_clkgen_nand_4_2_0x30                = 0x00000006,
  regk_clkgen_nand_4_2_0x30_pll            = 0x00000016,
  regk_clkgen_nand_4_2_pll                 = 0x00000014,
  regk_clkgen_nand_4_3                     = 0x00000005,
  regk_clkgen_nand_4_3_0x30                = 0x00000007,
  regk_clkgen_nand_4_3_0x30_pll            = 0x00000017,
  regk_clkgen_nand_4_3_pll                 = 0x00000015,
  regk_clkgen_nand_5_2                     = 0x00000008,
  regk_clkgen_nand_5_2_0x30                = 0x0000000a,
  regk_clkgen_nand_5_2_0x30_pll            = 0x0000001a,
  regk_clkgen_nand_5_2_pll                 = 0x00000018,
  regk_clkgen_nand_5_3                     = 0x00000009,
  regk_clkgen_nand_5_3_0x30                = 0x0000000b,
  regk_clkgen_nand_5_3_0x30_pll            = 0x0000001b,
  regk_clkgen_nand_5_3_pll                 = 0x00000019,
  regk_clkgen_no                           = 0x00000000,
  regk_clkgen_rw_clk_ctrl_default          = 0x00000002,
  regk_clkgen_ser                          = 0x0000000d,
  regk_clkgen_ser_pll                      = 0x0000000f,
  regk_clkgen_yes                          = 0x00000001
};
#endif /* __clkgen_defs_h */
