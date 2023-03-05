/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __DRM_MCDE_DISPLAY_REGS
#define __DRM_MCDE_DISPLAY_REGS

/* PP (pixel processor) interrupts */
#define MCDE_IMSCPP 0x00000104
#define MCDE_RISPP 0x00000114
#define MCDE_MISPP 0x00000124
#define MCDE_SISPP 0x00000134

#define MCDE_PP_VCMPA BIT(0)
#define MCDE_PP_VCMPB BIT(1)
#define MCDE_PP_VSCC0 BIT(2)
#define MCDE_PP_VSCC1 BIT(3)
#define MCDE_PP_VCMPC0 BIT(4)
#define MCDE_PP_VCMPC1 BIT(5)
#define MCDE_PP_ROTFD_A BIT(6)
#define MCDE_PP_ROTFD_B BIT(7)

/* Overlay interrupts */
#define MCDE_IMSCOVL 0x00000108
#define MCDE_RISOVL 0x00000118
#define MCDE_MISOVL 0x00000128
#define MCDE_SISOVL 0x00000138

/* Channel interrupts */
#define MCDE_IMSCCHNL 0x0000010C
#define MCDE_RISCHNL 0x0000011C
#define MCDE_MISCHNL 0x0000012C
#define MCDE_SISCHNL 0x0000013C

/* X = 0..9 */
#define MCDE_EXTSRCXA0 0x00000200
#define MCDE_EXTSRCXA0_GROUPOFFSET 0x20
#define MCDE_EXTSRCXA0_BASEADDRESS0_SHIFT 3
#define MCDE_EXTSRCXA0_BASEADDRESS0_MASK 0xFFFFFFF8

#define MCDE_EXTSRCXA1 0x00000204
#define MCDE_EXTSRCXA1_GROUPOFFSET 0x20
#define MCDE_EXTSRCXA1_BASEADDRESS1_SHIFT 3
#define MCDE_EXTSRCXA1_BASEADDRESS1_MASK 0xFFFFFFF8

/* External sources 0..9 */
#define MCDE_EXTSRC0CONF 0x0000020C
#define MCDE_EXTSRC1CONF 0x0000022C
#define MCDE_EXTSRC2CONF 0x0000024C
#define MCDE_EXTSRC3CONF 0x0000026C
#define MCDE_EXTSRC4CONF 0x0000028C
#define MCDE_EXTSRC5CONF 0x000002AC
#define MCDE_EXTSRC6CONF 0x000002CC
#define MCDE_EXTSRC7CONF 0x000002EC
#define MCDE_EXTSRC8CONF 0x0000030C
#define MCDE_EXTSRC9CONF 0x0000032C
#define MCDE_EXTSRCXCONF_GROUPOFFSET 0x20
#define MCDE_EXTSRCXCONF_BUF_ID_SHIFT 0
#define MCDE_EXTSRCXCONF_BUF_ID_MASK 0x00000003
#define MCDE_EXTSRCXCONF_BUF_NB_SHIFT 2
#define MCDE_EXTSRCXCONF_BUF_NB_MASK 0x0000000C
#define MCDE_EXTSRCXCONF_PRI_OVLID_SHIFT 4
#define MCDE_EXTSRCXCONF_PRI_OVLID_MASK 0x000000F0
#define MCDE_EXTSRCXCONF_BPP_SHIFT 8
#define MCDE_EXTSRCXCONF_BPP_MASK 0x00000F00
#define MCDE_EXTSRCXCONF_BPP_1BPP_PAL 0
#define MCDE_EXTSRCXCONF_BPP_2BPP_PAL 1
#define MCDE_EXTSRCXCONF_BPP_4BPP_PAL 2
#define MCDE_EXTSRCXCONF_BPP_8BPP_PAL 3
#define MCDE_EXTSRCXCONF_BPP_RGB444 4
#define MCDE_EXTSRCXCONF_BPP_ARGB4444 5
#define MCDE_EXTSRCXCONF_BPP_IRGB1555 6
#define MCDE_EXTSRCXCONF_BPP_RGB565 7
#define MCDE_EXTSRCXCONF_BPP_RGB888 8
#define MCDE_EXTSRCXCONF_BPP_XRGB8888 9
#define MCDE_EXTSRCXCONF_BPP_ARGB8888 10
#define MCDE_EXTSRCXCONF_BPP_YCBCR422 11
#define MCDE_EXTSRCXCONF_BGR BIT(12)
#define MCDE_EXTSRCXCONF_BEBO BIT(13)
#define MCDE_EXTSRCXCONF_BEPO BIT(14)
#define MCDE_EXTSRCXCONF_TUNNELING_BUFFER_HEIGHT_SHIFT 16
#define MCDE_EXTSRCXCONF_TUNNELING_BUFFER_HEIGHT_MASK 0x0FFF0000

/* External sources 0..9 */
#define MCDE_EXTSRC0CR 0x00000210
#define MCDE_EXTSRC1CR 0x00000230
#define MCDE_EXTSRC2CR 0x00000250
#define MCDE_EXTSRC3CR 0x00000270
#define MCDE_EXTSRC4CR 0x00000290
#define MCDE_EXTSRC5CR 0x000002B0
#define MCDE_EXTSRC6CR 0x000002D0
#define MCDE_EXTSRC7CR 0x000002F0
#define MCDE_EXTSRC8CR 0x00000310
#define MCDE_EXTSRC9CR 0x00000330
#define MCDE_EXTSRCXCR_SEL_MOD_SHIFT 0
#define MCDE_EXTSRCXCR_SEL_MOD_MASK 0x00000003
#define MCDE_EXTSRCXCR_SEL_MOD_EXTERNAL_SEL 0
#define MCDE_EXTSRCXCR_SEL_MOD_AUTO_TOGGLE 1
#define MCDE_EXTSRCXCR_SEL_MOD_SOFTWARE_SEL 2
#define MCDE_EXTSRCXCR_MULTIOVL_CTRL_PRIMARY BIT(2) /* 0 = all */
#define MCDE_EXTSRCXCR_FS_DIV_DISABLE BIT(3)
#define MCDE_EXTSRCXCR_FORCE_FS_DIV BIT(4)

/* Only external source 6 has a second address register */
#define MCDE_EXTSRC6A2 0x000002C8

/* 6 overlays */
#define MCDE_OVL0CR 0x00000400
#define MCDE_OVL1CR 0x00000420
#define MCDE_OVL2CR 0x00000440
#define MCDE_OVL3CR 0x00000460
#define MCDE_OVL4CR 0x00000480
#define MCDE_OVL5CR 0x000004A0
#define MCDE_OVLXCR_OVLEN BIT(0)
#define MCDE_OVLXCR_COLCCTRL_DISABLED 0
#define MCDE_OVLXCR_COLCCTRL_ENABLED_NO_SAT (1 << 1)
#define MCDE_OVLXCR_COLCCTRL_ENABLED_SAT (2 << 1)
#define MCDE_OVLXCR_CKEYGEN BIT(3)
#define MCDE_OVLXCR_ALPHAPMEN BIT(4)
#define MCDE_OVLXCR_OVLF BIT(5)
#define MCDE_OVLXCR_OVLR BIT(6)
#define MCDE_OVLXCR_OVLB BIT(7)
#define MCDE_OVLXCR_FETCH_ROPC_SHIFT 8
#define MCDE_OVLXCR_FETCH_ROPC_MASK 0x0000FF00
#define MCDE_OVLXCR_STBPRIO_SHIFT 16
#define MCDE_OVLXCR_STBPRIO_MASK 0x000F0000
#define MCDE_OVLXCR_BURSTSIZE_SHIFT 20
#define MCDE_OVLXCR_BURSTSIZE_MASK 0x00F00000
#define MCDE_OVLXCR_BURSTSIZE_1W 0
#define MCDE_OVLXCR_BURSTSIZE_2W 1
#define MCDE_OVLXCR_BURSTSIZE_4W 2
#define MCDE_OVLXCR_BURSTSIZE_8W 3
#define MCDE_OVLXCR_BURSTSIZE_16W 4
#define MCDE_OVLXCR_BURSTSIZE_HW_1W 8
#define MCDE_OVLXCR_BURSTSIZE_HW_2W 9
#define MCDE_OVLXCR_BURSTSIZE_HW_4W 10
#define MCDE_OVLXCR_BURSTSIZE_HW_8W 11
#define MCDE_OVLXCR_BURSTSIZE_HW_16W 12
#define MCDE_OVLXCR_MAXOUTSTANDING_SHIFT 24
#define MCDE_OVLXCR_MAXOUTSTANDING_MASK 0x0F000000
#define MCDE_OVLXCR_MAXOUTSTANDING_1_REQ 0
#define MCDE_OVLXCR_MAXOUTSTANDING_2_REQ 1
#define MCDE_OVLXCR_MAXOUTSTANDING_4_REQ 2
#define MCDE_OVLXCR_MAXOUTSTANDING_8_REQ 3
#define MCDE_OVLXCR_MAXOUTSTANDING_16_REQ 4
#define MCDE_OVLXCR_ROTBURSTSIZE_SHIFT 28
#define MCDE_OVLXCR_ROTBURSTSIZE_MASK 0xF0000000
#define MCDE_OVLXCR_ROTBURSTSIZE_1W 0
#define MCDE_OVLXCR_ROTBURSTSIZE_2W 1
#define MCDE_OVLXCR_ROTBURSTSIZE_4W 2
#define MCDE_OVLXCR_ROTBURSTSIZE_8W 3
#define MCDE_OVLXCR_ROTBURSTSIZE_16W 4
#define MCDE_OVLXCR_ROTBURSTSIZE_HW_1W 8
#define MCDE_OVLXCR_ROTBURSTSIZE_HW_2W 9
#define MCDE_OVLXCR_ROTBURSTSIZE_HW_4W 10
#define MCDE_OVLXCR_ROTBURSTSIZE_HW_8W 11
#define MCDE_OVLXCR_ROTBURSTSIZE_HW_16W 12

#define MCDE_OVL0CONF 0x00000404
#define MCDE_OVL1CONF 0x00000424
#define MCDE_OVL2CONF 0x00000444
#define MCDE_OVL3CONF 0x00000464
#define MCDE_OVL4CONF 0x00000484
#define MCDE_OVL5CONF 0x000004A4
#define MCDE_OVLXCONF_PPL_SHIFT 0
#define MCDE_OVLXCONF_PPL_MASK 0x000007FF
#define MCDE_OVLXCONF_EXTSRC_ID_SHIFT 11
#define MCDE_OVLXCONF_EXTSRC_ID_MASK 0x00007800
#define MCDE_OVLXCONF_LPF_SHIFT 16
#define MCDE_OVLXCONF_LPF_MASK 0x07FF0000

#define MCDE_OVL0CONF2 0x00000408
#define MCDE_OVL1CONF2 0x00000428
#define MCDE_OVL2CONF2 0x00000448
#define MCDE_OVL3CONF2 0x00000468
#define MCDE_OVL4CONF2 0x00000488
#define MCDE_OVL5CONF2 0x000004A8
#define MCDE_OVLXCONF2_BP_PER_PIXEL_ALPHA 0
#define MCDE_OVLXCONF2_BP_CONSTANT_ALPHA BIT(0)
#define MCDE_OVLXCONF2_ALPHAVALUE_SHIFT 1
#define MCDE_OVLXCONF2_ALPHAVALUE_MASK 0x000001FE
#define MCDE_OVLXCONF2_OPQ BIT(9)
#define MCDE_OVLXCONF2_PIXOFF_SHIFT 10
#define MCDE_OVLXCONF2_PIXOFF_MASK 0x0000FC00
#define MCDE_OVLXCONF2_PIXELFETCHERWATERMARKLEVEL_SHIFT 16
#define MCDE_OVLXCONF2_PIXELFETCHERWATERMARKLEVEL_MASK 0x1FFF0000

#define MCDE_OVL0LJINC 0x0000040C
#define MCDE_OVL1LJINC 0x0000042C
#define MCDE_OVL2LJINC 0x0000044C
#define MCDE_OVL3LJINC 0x0000046C
#define MCDE_OVL4LJINC 0x0000048C
#define MCDE_OVL5LJINC 0x000004AC

#define MCDE_OVL0CROP 0x00000410
#define MCDE_OVL1CROP 0x00000430
#define MCDE_OVL2CROP 0x00000450
#define MCDE_OVL3CROP 0x00000470
#define MCDE_OVL4CROP 0x00000490
#define MCDE_OVL5CROP 0x000004B0
#define MCDE_OVLXCROP_TMRGN_SHIFT 0
#define MCDE_OVLXCROP_TMRGN_MASK 0x003FFFFF
#define MCDE_OVLXCROP_LMRGN_SHIFT 22
#define MCDE_OVLXCROP_LMRGN_MASK 0xFFC00000

#define MCDE_OVL0COMP 0x00000414
#define MCDE_OVL1COMP 0x00000434
#define MCDE_OVL2COMP 0x00000454
#define MCDE_OVL3COMP 0x00000474
#define MCDE_OVL4COMP 0x00000494
#define MCDE_OVL5COMP 0x000004B4
#define MCDE_OVLXCOMP_XPOS_SHIFT 0
#define MCDE_OVLXCOMP_XPOS_MASK 0x000007FF
#define MCDE_OVLXCOMP_CH_ID_SHIFT 11
#define MCDE_OVLXCOMP_CH_ID_MASK 0x00007800
#define MCDE_OVLXCOMP_YPOS_SHIFT 16
#define MCDE_OVLXCOMP_YPOS_MASK 0x07FF0000
#define MCDE_OVLXCOMP_Z_SHIFT 27
#define MCDE_OVLXCOMP_Z_MASK 0x78000000

/* DPI/TV configuration registers, channel A and B */
#define MCDE_TVCRA 0x00000838
#define MCDE_TVCRB 0x00000A38
#define MCDE_TVCR_MOD_TV BIT(0) /* 0 = LCD mode */
#define MCDE_TVCR_INTEREN BIT(1)
#define MCDE_TVCR_IFIELD BIT(2)
#define MCDE_TVCR_TVMODE_SDTV_656P (0 << 3)
#define MCDE_TVCR_TVMODE_SDTV_656P_LE (3 << 3)
#define MCDE_TVCR_TVMODE_SDTV_656P_BE (4 << 3)
#define MCDE_TVCR_SDTVMODE_Y0CBY1CR (0 << 6)
#define MCDE_TVCR_SDTVMODE_CBY0CRY1 (1 << 6)
#define MCDE_TVCR_AVRGEN BIT(8)
#define MCDE_TVCR_CKINV BIT(9)

/* TV blanking control register 1, channel A and B */
#define MCDE_TVBL1A 0x0000083C
#define MCDE_TVBL1B 0x00000A3C
#define MCDE_TVBL1_BEL1_SHIFT 0 /* VFP vertical front porch 11 bits */
#define MCDE_TVBL1_BSL1_SHIFT 16 /* VSW vertical sync pulse width 11 bits */

/* Pixel processing TV start line, channel A and B */
#define MCDE_TVISLA 0x00000840
#define MCDE_TVISLB 0x00000A40
#define MCDE_TVISL_FSL1_SHIFT 0 /* Field 1 identification start line 11 bits */
#define MCDE_TVISL_FSL2_SHIFT 16 /* Field 2 identification start line 11 bits */

/* Pixel processing TV DVO offset */
#define MCDE_TVDVOA 0x00000844
#define MCDE_TVDVOB 0x00000A44
#define MCDE_TVDVO_DVO1_SHIFT 0 /* VBP vertical back porch 0 = 0 */
#define MCDE_TVDVO_DVO2_SHIFT 16

/*
 * Pixel processing TV Timing 1
 * HBP horizontal back porch 11 bits horizontal offset
 * 0 = 1 pixel HBP, 255 = 256 pixels, so actual value - 1
 */
#define MCDE_TVTIM1A 0x0000084C
#define MCDE_TVTIM1B 0x00000A4C

/* Pixel processing TV LBALW */
/* 0 = 1 clock cycle, 255 = 256 clock cycles */
#define MCDE_TVLBALWA 0x00000850
#define MCDE_TVLBALWB 0x00000A50
#define MCDE_TVLBALW_LBW_SHIFT 0 /* HSW horizonal sync width, line blanking width 11 bits */
#define MCDE_TVLBALW_ALW_SHIFT 16 /* HFP horizontal front porch, active line width 11 bits */

/* TV blanking control register 1, channel A and B */
#define MCDE_TVBL2A 0x00000854
#define MCDE_TVBL2B 0x00000A54
#define MCDE_TVBL2_BEL2_SHIFT 0 /* Field 2 blanking end line 11 bits */
#define MCDE_TVBL2_BSL2_SHIFT 16 /* Field 2 blanking start line 11 bits */

/* Pixel processing TV background */
#define MCDE_TVBLUA 0x00000858
#define MCDE_TVBLUB 0x00000A58
#define MCDE_TVBLU_TVBLU_SHIFT 0 /* 8 bits luminance */
#define MCDE_TVBLU_TVBCB_SHIFT 8 /* 8 bits Cb chrominance */
#define MCDE_TVBLU_TVBCR_SHIFT 16 /* 8 bits Cr chrominance */

/* Pixel processing LCD timing 1 */
#define MCDE_LCDTIM1A 0x00000860
#define MCDE_LCDTIM1B 0x00000A60
/* inverted vertical sync pulse for HRTFT 0 = active low, 1 active high */
#define MCDE_LCDTIM1B_IVP BIT(19)
/* inverted vertical sync, 0 = active high (the normal), 1 = active low */
#define MCDE_LCDTIM1B_IVS BIT(20)
/* inverted horizontal sync, 0 = active high (the normal), 1 = active low */
#define MCDE_LCDTIM1B_IHS BIT(21)
/* inverted panel clock 0 = rising edge data out, 1 = falling edge data out */
#define MCDE_LCDTIM1B_IPC BIT(22)
/* invert output enable 0 = active high, 1 = active low */
#define MCDE_LCDTIM1B_IOE BIT(23)

#define MCDE_CRC 0x00000C00
#define MCDE_CRC_C1EN BIT(2)
#define MCDE_CRC_C2EN BIT(3)
#define MCDE_CRC_SYCEN0 BIT(7)
#define MCDE_CRC_SYCEN1 BIT(8)
#define MCDE_CRC_SIZE1 BIT(9)
#define MCDE_CRC_SIZE2 BIT(10)
#define MCDE_CRC_YUVCONVC1EN BIT(15)
#define MCDE_CRC_CS1EN BIT(16)
#define MCDE_CRC_CS2EN BIT(17)
#define MCDE_CRC_CS1POL BIT(19)
#define MCDE_CRC_CS2POL BIT(20)
#define MCDE_CRC_CD1POL BIT(21)
#define MCDE_CRC_CD2POL BIT(22)
#define MCDE_CRC_WR1POL BIT(23)
#define MCDE_CRC_WR2POL BIT(24)
#define MCDE_CRC_RD1POL BIT(25)
#define MCDE_CRC_RD2POL BIT(26)
#define MCDE_CRC_SYNCCTRL_SHIFT 29
#define MCDE_CRC_SYNCCTRL_MASK 0x60000000
#define MCDE_CRC_SYNCCTRL_NO_SYNC 0
#define MCDE_CRC_SYNCCTRL_DBI0 1
#define MCDE_CRC_SYNCCTRL_DBI1 2
#define MCDE_CRC_SYNCCTRL_PING_PONG 3
#define MCDE_CRC_CLAMPC1EN BIT(31)

#define MCDE_VSCRC0 0x00000C5C
#define MCDE_VSCRC1 0x00000C60
#define MCDE_VSCRC_VSPMIN_MASK 0x00000FFF
#define MCDE_VSCRC_VSPMAX_SHIFT 12
#define MCDE_VSCRC_VSPMAX_MASK 0x00FFF000
#define MCDE_VSCRC_VSPDIV_SHIFT 24
#define MCDE_VSCRC_VSPDIV_MASK 0x07000000
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_1 0
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_2 1
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_4 2
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_8 3
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_16 4
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_32 5
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_64 6
#define MCDE_VSCRC_VSPDIV_MCDECLK_DIV_128 7
#define MCDE_VSCRC_VSPOL BIT(27) /* 0 active high, 1 active low */
#define MCDE_VSCRC_VSSEL BIT(28) /* 0 VSYNC0, 1 VSYNC1 */
#define MCDE_VSCRC_VSDBL BIT(29)

/* Channel config 0..3 */
#define MCDE_CHNL0CONF 0x00000600
#define MCDE_CHNL1CONF 0x00000620
#define MCDE_CHNL2CONF 0x00000640
#define MCDE_CHNL3CONF 0x00000660
#define MCDE_CHNLXCONF_PPL_SHIFT 0
#define MCDE_CHNLXCONF_PPL_MASK 0x000007FF
#define MCDE_CHNLXCONF_LPF_SHIFT 16
#define MCDE_CHNLXCONF_LPF_MASK 0x07FF0000
#define MCDE_MAX_WIDTH 2048

/* Channel status 0..3 */
#define MCDE_CHNL0STAT 0x00000604
#define MCDE_CHNL1STAT 0x00000624
#define MCDE_CHNL2STAT 0x00000644
#define MCDE_CHNL3STAT 0x00000664
#define MCDE_CHNLXSTAT_CHNLRD BIT(0)
#define MCDE_CHNLXSTAT_CHNLA BIT(1)
#define MCDE_CHNLXSTAT_CHNLBLBCKGND_EN BIT(16)
#define MCDE_CHNLXSTAT_PPLX2_V422 BIT(17)
#define MCDE_CHNLXSTAT_LPFX2_V422 BIT(18)

/* Sync settings for channel 0..3 */
#define MCDE_CHNL0SYNCHMOD 0x00000608
#define MCDE_CHNL1SYNCHMOD 0x00000628
#define MCDE_CHNL2SYNCHMOD 0x00000648
#define MCDE_CHNL3SYNCHMOD 0x00000668

#define MCDE_CHNLXSYNCHMOD_SRC_SYNCH_SHIFT 0
#define MCDE_CHNLXSYNCHMOD_SRC_SYNCH_MASK 0x00000003
#define MCDE_CHNLXSYNCHMOD_SRC_SYNCH_HARDWARE 0
#define MCDE_CHNLXSYNCHMOD_SRC_SYNCH_NO_SYNCH 1
#define MCDE_CHNLXSYNCHMOD_SRC_SYNCH_SOFTWARE 2
#define MCDE_CHNLXSYNCHMOD_OUT_SYNCH_SRC_SHIFT 2
#define MCDE_CHNLXSYNCHMOD_OUT_SYNCH_SRC_MASK 0x0000001C
#define MCDE_CHNLXSYNCHMOD_OUT_SYNCH_SRC_FORMATTER 0
#define MCDE_CHNLXSYNCHMOD_OUT_SYNCH_SRC_TE0 1
#define MCDE_CHNLXSYNCHMOD_OUT_SYNCH_SRC_TE1 2

/* Software sync triggers for channel 0..3 */
#define MCDE_CHNL0SYNCHSW 0x0000060C
#define MCDE_CHNL1SYNCHSW 0x0000062C
#define MCDE_CHNL2SYNCHSW 0x0000064C
#define MCDE_CHNL3SYNCHSW 0x0000066C
#define MCDE_CHNLXSYNCHSW_SW_TRIG BIT(0)

#define MCDE_CHNL0BCKGNDCOL 0x00000610
#define MCDE_CHNL1BCKGNDCOL 0x00000630
#define MCDE_CHNL2BCKGNDCOL 0x00000650
#define MCDE_CHNL3BCKGNDCOL 0x00000670
#define MCDE_CHNLXBCKGNDCOL_B_SHIFT 0
#define MCDE_CHNLXBCKGNDCOL_B_MASK 0x000000FF
#define MCDE_CHNLXBCKGNDCOL_G_SHIFT 8
#define MCDE_CHNLXBCKGNDCOL_G_MASK 0x0000FF00
#define MCDE_CHNLXBCKGNDCOL_R_SHIFT 16
#define MCDE_CHNLXBCKGNDCOL_R_MASK 0x00FF0000

#define MCDE_CHNL0MUXING 0x00000614
#define MCDE_CHNL1MUXING 0x00000634
#define MCDE_CHNL2MUXING 0x00000654
#define MCDE_CHNL3MUXING 0x00000674
#define MCDE_CHNLXMUXING_FIFO_ID_FIFO_A 0
#define MCDE_CHNLXMUXING_FIFO_ID_FIFO_B 1
#define MCDE_CHNLXMUXING_FIFO_ID_FIFO_C0 2
#define MCDE_CHNLXMUXING_FIFO_ID_FIFO_C1 3

/* Pixel processing control registers for channel A B,  */
#define MCDE_CRA0 0x00000800
#define MCDE_CRB0 0x00000A00
#define MCDE_CRX0_FLOEN BIT(0)
#define MCDE_CRX0_POWEREN BIT(1)
#define MCDE_CRX0_BLENDEN BIT(2)
#define MCDE_CRX0_AFLICKEN BIT(3)
#define MCDE_CRX0_PALEN BIT(4)
#define MCDE_CRX0_DITHEN BIT(5)
#define MCDE_CRX0_GAMEN BIT(6)
#define MCDE_CRX0_KEYCTRL_SHIFT 7
#define MCDE_CRX0_KEYCTRL_MASK 0x00000380
#define MCDE_CRX0_KEYCTRL_OFF 0
#define MCDE_CRX0_KEYCTRL_ALPHA_RGB 1
#define MCDE_CRX0_KEYCTRL_RGB 2
#define MCDE_CRX0_KEYCTRL_FALPHA_FRGB 4
#define MCDE_CRX0_KEYCTRL_FRGB 5
#define MCDE_CRX0_BLENDCTRL BIT(10)
#define MCDE_CRX0_FLICKMODE_SHIFT 11
#define MCDE_CRX0_FLICKMODE_MASK 0x00001800
#define MCDE_CRX0_FLICKMODE_FORCE_FILTER_0 0
#define MCDE_CRX0_FLICKMODE_ADAPTIVE 1
#define MCDE_CRX0_FLICKMODE_TEST_MODE 2
#define MCDE_CRX0_FLOCKFORMAT_RGB BIT(13) /* 0 = YCVCR */
#define MCDE_CRX0_PALMODE_GAMMA BIT(14) /* 0 = palette */
#define MCDE_CRX0_OLEDEN BIT(15)
#define MCDE_CRX0_ALPHABLEND_SHIFT 16
#define MCDE_CRX0_ALPHABLEND_MASK 0x00FF0000
#define MCDE_CRX0_ROTEN BIT(24)

#define MCDE_CRA1 0x00000804
#define MCDE_CRB1 0x00000A04
#define MCDE_CRX1_PCD_SHIFT 0
#define MCDE_CRX1_PCD_MASK 0x000003FF
#define MCDE_CRX1_PCD_BITS 10
#define MCDE_CRX1_CLKSEL_SHIFT 10
#define MCDE_CRX1_CLKSEL_MASK 0x00001C00
#define MCDE_CRX1_CLKSEL_CLKPLL72 0
#define MCDE_CRX1_CLKSEL_CLKPLL27 2
#define MCDE_CRX1_CLKSEL_TV1CLK 3
#define MCDE_CRX1_CLKSEL_TV2CLK 4
#define MCDE_CRX1_CLKSEL_MCDECLK 5
#define MCDE_CRX1_CDWIN_SHIFT 13
#define MCDE_CRX1_CDWIN_MASK 0x0001E000
#define MCDE_CRX1_CDWIN_8BPP_C1 0
#define MCDE_CRX1_CDWIN_12BPP_C1 1
#define MCDE_CRX1_CDWIN_12BPP_C2 2
#define MCDE_CRX1_CDWIN_16BPP_C1 3
#define MCDE_CRX1_CDWIN_16BPP_C2 4
#define MCDE_CRX1_CDWIN_16BPP_C3 5
#define MCDE_CRX1_CDWIN_18BPP_C1 6
#define MCDE_CRX1_CDWIN_18BPP_C2 7
#define MCDE_CRX1_CDWIN_24BPP 8
#define MCDE_CRX1_OUTBPP_SHIFT 25
#define MCDE_CRX1_OUTBPP_MASK 0x1E000000
#define MCDE_CRX1_OUTBPP_MONO1 0
#define MCDE_CRX1_OUTBPP_MONO2 1
#define MCDE_CRX1_OUTBPP_MONO4 2
#define MCDE_CRX1_OUTBPP_MONO8 3
#define MCDE_CRX1_OUTBPP_8BPP 4
#define MCDE_CRX1_OUTBPP_12BPP 5
#define MCDE_CRX1_OUTBPP_15BPP 6
#define MCDE_CRX1_OUTBPP_16BPP 7
#define MCDE_CRX1_OUTBPP_18BPP 8
#define MCDE_CRX1_OUTBPP_24BPP 9
#define MCDE_CRX1_BCD BIT(29)
#define MCDE_CRA1_CLKTYPE_TVXCLKSEL1 BIT(30) /* 0 = TVXCLKSEL1 */

#define MCDE_COLKEYA 0x00000808
#define MCDE_COLKEYB 0x00000A08

#define MCDE_FCOLKEYA 0x0000080C
#define MCDE_FCOLKEYB 0x00000A0C

#define MCDE_RGBCONV1A 0x00000810
#define MCDE_RGBCONV1B 0x00000A10

#define MCDE_RGBCONV2A 0x00000814
#define MCDE_RGBCONV2B 0x00000A14

#define MCDE_RGBCONV3A 0x00000818
#define MCDE_RGBCONV3B 0x00000A18

#define MCDE_RGBCONV4A 0x0000081C
#define MCDE_RGBCONV4B 0x00000A1C

#define MCDE_RGBCONV5A 0x00000820
#define MCDE_RGBCONV5B 0x00000A20

#define MCDE_RGBCONV6A 0x00000824
#define MCDE_RGBCONV6B 0x00000A24

/* Rotation */
#define MCDE_ROTACONF 0x0000087C
#define MCDE_ROTBCONF 0x00000A7C

/* Synchronization event configuration */
#define MCDE_SYNCHCONFA 0x00000880
#define MCDE_SYNCHCONFB 0x00000A80
#define MCDE_SYNCHCONF_HWREQVEVENT_SHIFT 0
#define MCDE_SYNCHCONF_HWREQVEVENT_VSYNC (0 << 0)
#define MCDE_SYNCHCONF_HWREQVEVENT_BACK_PORCH (1 << 0)
#define MCDE_SYNCHCONF_HWREQVEVENT_ACTIVE_VIDEO (2 << 0)
#define MCDE_SYNCHCONF_HWREQVEVENT_FRONT_PORCH (3 << 0)
#define MCDE_SYNCHCONF_HWREQVCNT_SHIFT 2 /* 14 bits */
#define MCDE_SYNCHCONF_SWINTVEVENT_VSYNC (0 << 16)
#define MCDE_SYNCHCONF_SWINTVEVENT_BACK_PORCH (1 << 16)
#define MCDE_SYNCHCONF_SWINTVEVENT_ACTIVE_VIDEO (2 << 16)
#define MCDE_SYNCHCONF_SWINTVEVENT_FRONT_PORCH (3 << 16)
#define MCDE_SYNCHCONF_SWINTVCNT_SHIFT 18 /* 14 bits */

/* Channel A+B control registers */
#define MCDE_CTRLA 0x00000884
#define MCDE_CTRLB 0x00000A84
#define MCDE_CTRLX_FIFOWTRMRK_SHIFT 0
#define MCDE_CTRLX_FIFOWTRMRK_MASK 0x000003FF
#define MCDE_CTRLX_FIFOEMPTY BIT(12)
#define MCDE_CTRLX_FIFOFULL BIT(13)
#define MCDE_CTRLX_FORMID_SHIFT 16
#define MCDE_CTRLX_FORMID_MASK 0x00070000
#define MCDE_CTRLX_FORMID_DSI0VID 0
#define MCDE_CTRLX_FORMID_DSI0CMD 1
#define MCDE_CTRLX_FORMID_DSI1VID 2
#define MCDE_CTRLX_FORMID_DSI1CMD 3
#define MCDE_CTRLX_FORMID_DSI2VID 4
#define MCDE_CTRLX_FORMID_DSI2CMD 5
#define MCDE_CTRLX_FORMID_DPIA 0
#define MCDE_CTRLX_FORMID_DPIB 1
#define MCDE_CTRLX_FORMTYPE_SHIFT 20
#define MCDE_CTRLX_FORMTYPE_MASK 0x00700000
#define MCDE_CTRLX_FORMTYPE_DPITV 0
#define MCDE_CTRLX_FORMTYPE_DBI 1
#define MCDE_CTRLX_FORMTYPE_DSI 2

#define MCDE_DSIVID0CONF0 0x00000E00
#define MCDE_DSICMD0CONF0 0x00000E20
#define MCDE_DSIVID1CONF0 0x00000E40
#define MCDE_DSICMD1CONF0 0x00000E60
#define MCDE_DSIVID2CONF0 0x00000E80
#define MCDE_DSICMD2CONF0 0x00000EA0
#define MCDE_DSICONF0_BLANKING_SHIFT 0
#define MCDE_DSICONF0_BLANKING_MASK 0x000000FF
#define MCDE_DSICONF0_VID_MODE_CMD 0
#define MCDE_DSICONF0_VID_MODE_VID BIT(12)
#define MCDE_DSICONF0_CMD8 BIT(13)
#define MCDE_DSICONF0_BIT_SWAP BIT(16)
#define MCDE_DSICONF0_BYTE_SWAP BIT(17)
#define MCDE_DSICONF0_DCSVID_NOTGEN BIT(18)
#define MCDE_DSICONF0_PACKING_SHIFT 20
#define MCDE_DSICONF0_PACKING_MASK 0x00700000
#define MCDE_DSICONF0_PACKING_RGB565 0
#define MCDE_DSICONF0_PACKING_RGB666 1
#define MCDE_DSICONF0_PACKING_RGB888 2
#define MCDE_DSICONF0_PACKING_BGR888 3
#define MCDE_DSICONF0_PACKING_HDTV 4

#define MCDE_DSIVID0FRAME 0x00000E04
#define MCDE_DSICMD0FRAME 0x00000E24
#define MCDE_DSIVID1FRAME 0x00000E44
#define MCDE_DSICMD1FRAME 0x00000E64
#define MCDE_DSIVID2FRAME 0x00000E84
#define MCDE_DSICMD2FRAME 0x00000EA4

#define MCDE_DSIVID0PKT 0x00000E08
#define MCDE_DSICMD0PKT 0x00000E28
#define MCDE_DSIVID1PKT 0x00000E48
#define MCDE_DSICMD1PKT 0x00000E68
#define MCDE_DSIVID2PKT 0x00000E88
#define MCDE_DSICMD2PKT 0x00000EA8

#define MCDE_DSIVID0SYNC 0x00000E0C
#define MCDE_DSICMD0SYNC 0x00000E2C
#define MCDE_DSIVID1SYNC 0x00000E4C
#define MCDE_DSICMD1SYNC 0x00000E6C
#define MCDE_DSIVID2SYNC 0x00000E8C
#define MCDE_DSICMD2SYNC 0x00000EAC

#define MCDE_DSIVID0CMDW 0x00000E10
#define MCDE_DSICMD0CMDW 0x00000E30
#define MCDE_DSIVID1CMDW 0x00000E50
#define MCDE_DSICMD1CMDW 0x00000E70
#define MCDE_DSIVID2CMDW 0x00000E90
#define MCDE_DSICMD2CMDW 0x00000EB0
#define MCDE_DSIVIDXCMDW_CMDW_CONTINUE_SHIFT 0
#define MCDE_DSIVIDXCMDW_CMDW_CONTINUE_MASK 0x0000FFFF
#define MCDE_DSIVIDXCMDW_CMDW_START_SHIFT 16
#define MCDE_DSIVIDXCMDW_CMDW_START_MASK 0xFFFF0000

#define MCDE_DSIVID0DELAY0 0x00000E14
#define MCDE_DSICMD0DELAY0 0x00000E34
#define MCDE_DSIVID1DELAY0 0x00000E54
#define MCDE_DSICMD1DELAY0 0x00000E74
#define MCDE_DSIVID2DELAY0 0x00000E94
#define MCDE_DSICMD2DELAY0 0x00000EB4

#define MCDE_DSIVID0DELAY1 0x00000E18
#define MCDE_DSICMD0DELAY1 0x00000E38
#define MCDE_DSIVID1DELAY1 0x00000E58
#define MCDE_DSICMD1DELAY1 0x00000E78
#define MCDE_DSIVID2DELAY1 0x00000E98
#define MCDE_DSICMD2DELAY1 0x00000EB8

#endif /* __DRM_MCDE_DISPLAY_REGS */
