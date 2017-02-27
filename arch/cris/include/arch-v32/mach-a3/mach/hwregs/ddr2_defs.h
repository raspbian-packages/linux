#ifndef __ddr2_defs_h
#define __ddr2_defs_h

/*
 * This file is autogenerated from
 *   file:           ddr2.r
 * 
 *   by ../../../tools/rdesc/bin/rdes2c -outfile ddr2_defs.h ddr2.r
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

/* C-code for register scope ddr2 */

/* Register rw_cfg, scope ddr2, type rw */
typedef struct {
  unsigned int col_width        : 4;
  unsigned int nr_banks         : 1;
  unsigned int bw               : 1;
  unsigned int nr_ref           : 4;
  unsigned int ref_interval     : 11;
  unsigned int odt_ctrl         : 2;
  unsigned int odt_mem          : 1;
  unsigned int imp_strength     : 1;
  unsigned int auto_imp_cal     : 1;
  unsigned int imp_cal_override : 1;
  unsigned int dll_override     : 1;
  unsigned int dummy1           : 4;
} reg_ddr2_rw_cfg;
#define REG_RD_ADDR_ddr2_rw_cfg 0
#define REG_WR_ADDR_ddr2_rw_cfg 0

/* Register rw_timing, scope ddr2, type rw */
typedef struct {
  unsigned int wr  : 3;
  unsigned int rcd : 3;
  unsigned int rp  : 3;
  unsigned int ras : 4;
  unsigned int rfc : 7;
  unsigned int rc  : 5;
  unsigned int rtp : 2;
  unsigned int rtw : 3;
  unsigned int wtr : 2;
} reg_ddr2_rw_timing;
#define REG_RD_ADDR_ddr2_rw_timing 4
#define REG_WR_ADDR_ddr2_rw_timing 4

/* Register rw_latency, scope ddr2, type rw */
typedef struct {
  unsigned int cas      : 3;
  unsigned int additive : 3;
  unsigned int dummy1   : 26;
} reg_ddr2_rw_latency;
#define REG_RD_ADDR_ddr2_rw_latency 8
#define REG_WR_ADDR_ddr2_rw_latency 8

/* Register rw_phy_cfg, scope ddr2, type rw */
typedef struct {
  unsigned int en : 1;
  unsigned int dummy1 : 31;
} reg_ddr2_rw_phy_cfg;
#define REG_RD_ADDR_ddr2_rw_phy_cfg 12
#define REG_WR_ADDR_ddr2_rw_phy_cfg 12

/* Register rw_phy_ctrl, scope ddr2, type rw */
typedef struct {
  unsigned int rst       : 1;
  unsigned int cal_rst   : 1;
  unsigned int cal_start : 1;
  unsigned int dummy1    : 29;
} reg_ddr2_rw_phy_ctrl;
#define REG_RD_ADDR_ddr2_rw_phy_ctrl 16
#define REG_WR_ADDR_ddr2_rw_phy_ctrl 16

/* Register rw_ctrl, scope ddr2, type rw */
typedef struct {
  unsigned int mrs_data : 16;
  unsigned int cmd      : 8;
  unsigned int dummy1   : 8;
} reg_ddr2_rw_ctrl;
#define REG_RD_ADDR_ddr2_rw_ctrl 20
#define REG_WR_ADDR_ddr2_rw_ctrl 20

/* Register rw_pwr_down, scope ddr2, type rw */
typedef struct {
  unsigned int self_ref : 2;
  unsigned int phy_en   : 1;
  unsigned int dummy1   : 29;
} reg_ddr2_rw_pwr_down;
#define REG_RD_ADDR_ddr2_rw_pwr_down 24
#define REG_WR_ADDR_ddr2_rw_pwr_down 24

/* Register r_stat, scope ddr2, type r */
typedef struct {
  unsigned int dll_lock       : 1;
  unsigned int dll_delay_code : 7;
  unsigned int imp_cal_done   : 1;
  unsigned int imp_cal_fault  : 1;
  unsigned int cal_imp_pu     : 4;
  unsigned int cal_imp_pd     : 4;
  unsigned int dummy1         : 14;
} reg_ddr2_r_stat;
#define REG_RD_ADDR_ddr2_r_stat 28

/* Register rw_imp_ctrl, scope ddr2, type rw */
typedef struct {
  unsigned int imp_pu : 4;
  unsigned int imp_pd : 4;
  unsigned int dummy1 : 24;
} reg_ddr2_rw_imp_ctrl;
#define REG_RD_ADDR_ddr2_rw_imp_ctrl 32
#define REG_WR_ADDR_ddr2_rw_imp_ctrl 32

#define STRIDE_ddr2_rw_dll_ctrl 4
/* Register rw_dll_ctrl, scope ddr2, type rw */
typedef struct {
  unsigned int mode      : 1;
  unsigned int clk_delay : 7;
  unsigned int dummy1    : 24;
} reg_ddr2_rw_dll_ctrl;
#define REG_RD_ADDR_ddr2_rw_dll_ctrl 36
#define REG_WR_ADDR_ddr2_rw_dll_ctrl 36

#define STRIDE_ddr2_rw_dqs_dll_ctrl 4
/* Register rw_dqs_dll_ctrl, scope ddr2, type rw */
typedef struct {
  unsigned int dqs90_delay  : 7;
  unsigned int dqs180_delay : 7;
  unsigned int dqs270_delay : 7;
  unsigned int dqs360_delay : 7;
  unsigned int dummy1       : 4;
} reg_ddr2_rw_dqs_dll_ctrl;
#define REG_RD_ADDR_ddr2_rw_dqs_dll_ctrl 52
#define REG_WR_ADDR_ddr2_rw_dqs_dll_ctrl 52


/* Constants */
enum {
  regk_ddr2_al0                            = 0x00000000,
  regk_ddr2_al1                            = 0x00000008,
  regk_ddr2_al2                            = 0x00000010,
  regk_ddr2_al3                            = 0x00000018,
  regk_ddr2_al4                            = 0x00000020,
  regk_ddr2_auto                           = 0x00000003,
  regk_ddr2_bank4                          = 0x00000000,
  regk_ddr2_bank8                          = 0x00000001,
  regk_ddr2_bl4                            = 0x00000002,
  regk_ddr2_bl8                            = 0x00000003,
  regk_ddr2_bt_il                          = 0x00000008,
  regk_ddr2_bt_seq                         = 0x00000000,
  regk_ddr2_bw16                           = 0x00000001,
  regk_ddr2_bw32                           = 0x00000000,
  regk_ddr2_cas2                           = 0x00000020,
  regk_ddr2_cas3                           = 0x00000030,
  regk_ddr2_cas4                           = 0x00000040,
  regk_ddr2_cas5                           = 0x00000050,
  regk_ddr2_deselect                       = 0x000000c0,
  regk_ddr2_dic_weak                       = 0x00000002,
  regk_ddr2_direct                         = 0x00000001,
  regk_ddr2_dis                            = 0x00000000,
  regk_ddr2_dll_dis                        = 0x00000001,
  regk_ddr2_dll_en                         = 0x00000000,
  regk_ddr2_dll_rst                        = 0x00000100,
  regk_ddr2_emrs                           = 0x00000081,
  regk_ddr2_emrs2                          = 0x00000082,
  regk_ddr2_emrs3                          = 0x00000083,
  regk_ddr2_full                           = 0x00000001,
  regk_ddr2_hi_ref_rate                    = 0x00000080,
  regk_ddr2_mrs                            = 0x00000080,
  regk_ddr2_no                             = 0x00000000,
  regk_ddr2_nop                            = 0x000000b8,
  regk_ddr2_ocd_adj                        = 0x00000200,
  regk_ddr2_ocd_default                    = 0x00000380,
  regk_ddr2_ocd_drive0                     = 0x00000100,
  regk_ddr2_ocd_drive1                     = 0x00000080,
  regk_ddr2_ocd_exit                       = 0x00000000,
  regk_ddr2_odt_dis                        = 0x00000000,
  regk_ddr2_offs                           = 0x00000000,
  regk_ddr2_pre                            = 0x00000090,
  regk_ddr2_pre_all                        = 0x00000400,
  regk_ddr2_pwr_down_fast                  = 0x00000000,
  regk_ddr2_pwr_down_slow                  = 0x00001000,
  regk_ddr2_ref                            = 0x00000088,
  regk_ddr2_rtt150                         = 0x00000040,
  regk_ddr2_rtt50                          = 0x00000044,
  regk_ddr2_rtt75                          = 0x00000004,
  regk_ddr2_rw_cfg_default                 = 0x00186000,
  regk_ddr2_rw_dll_ctrl_default            = 0x00000000,
  regk_ddr2_rw_dll_ctrl_size               = 0x00000004,
  regk_ddr2_rw_dqs_dll_ctrl_default        = 0x00000000,
  regk_ddr2_rw_dqs_dll_ctrl_size           = 0x00000004,
  regk_ddr2_rw_latency_default             = 0x00000000,
  regk_ddr2_rw_phy_cfg_default             = 0x00000000,
  regk_ddr2_rw_pwr_down_default            = 0x00000000,
  regk_ddr2_rw_timing_default              = 0x00000000,
  regk_ddr2_s1Gb                           = 0x0000001a,
  regk_ddr2_s256Mb                         = 0x0000000f,
  regk_ddr2_s2Gb                           = 0x00000027,
  regk_ddr2_s4Gb                           = 0x00000042,
  regk_ddr2_s512Mb                         = 0x00000015,
  regk_ddr2_temp0_85                       = 0x00000618,
  regk_ddr2_temp85_95                      = 0x0000030c,
  regk_ddr2_term150                        = 0x00000002,
  regk_ddr2_term50                         = 0x00000003,
  regk_ddr2_term75                         = 0x00000001,
  regk_ddr2_test                           = 0x00000080,
  regk_ddr2_weak                           = 0x00000000,
  regk_ddr2_wr2                            = 0x00000200,
  regk_ddr2_wr3                            = 0x00000400,
  regk_ddr2_yes                            = 0x00000001
};
#endif /* __ddr2_defs_h */
