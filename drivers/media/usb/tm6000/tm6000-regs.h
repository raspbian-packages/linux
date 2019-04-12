/*
 *  tm6000-regs.h - driver for TM5600/TM6000/TM6010 USB video capture devices
 *
 *  Copyright (C) 2006-2007 Mauro Carvalho Chehab <mchehab@infradead.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation version 2
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * Define TV Master TM5600/TM6000/TM6010 Request codes
 */
#define REQ_00_SET_IR_VALUE		0
#define REQ_01_SET_WAKEUP_IRCODE	1
#define REQ_02_GET_IR_CODE		2
#define REQ_03_SET_GET_MCU_PIN		3
#define REQ_04_EN_DISABLE_MCU_INT	4
#define REQ_05_SET_GET_USBREG		5
	/* Write: RegNum, Value, 0 */
	/* Read : RegNum, Value, 1, RegStatus */
#define REQ_06_SET_GET_USBREG_BIT	6
#define REQ_07_SET_GET_AVREG		7
	/* Write: RegNum, Value, 0 */
	/* Read : RegNum, Value, 1, RegStatus */
#define REQ_08_SET_GET_AVREG_BIT	8
#define REQ_09_SET_GET_TUNER_FQ		9
#define REQ_10_SET_TUNER_SYSTEM		10
#define REQ_11_SET_EEPROM_ADDR		11
#define REQ_12_SET_GET_EEPROMBYTE	12
#define REQ_13_GET_EEPROM_SEQREAD	13
#define REQ_14_SET_GET_I2C_WR2_RDN	14
#define REQ_15_SET_GET_I2CBYTE		15
	/* Write: Subaddr, Slave Addr, value, 0 */
	/* Read : Subaddr, Slave Addr, value, 1 */
#define REQ_16_SET_GET_I2C_WR1_RDN	16
	/* Subaddr, Slave Addr, 0, length */
#define REQ_17_SET_GET_I2CFP		17
	/* Write: Slave Addr, register, value */
	/* Read : Slave Addr, register, 2, data */
#define REQ_20_DATA_TRANSFER		20
#define REQ_30_I2C_WRITE		30
#define REQ_31_I2C_READ			31
#define REQ_35_AFTEK_TUNER_READ		35
#define REQ_40_GET_VERSION		40
#define REQ_50_SET_START		50
#define REQ_51_SET_STOP			51
#define REQ_52_TRANSMIT_DATA		52
#define REQ_53_SPI_INITIAL		53
#define REQ_54_SPI_SETSTART		54
#define REQ_55_SPI_INOUTDATA		55
#define REQ_56_SPI_SETSTOP		56

/*
 * Define TV Master TM5600/TM6000/TM6010 GPIO lines
 */

#define TM6000_GPIO_CLK		0x101
#define TM6000_GPIO_DATA	0x100

#define TM6000_GPIO_1		0x102
#define TM6000_GPIO_2		0x103
#define TM6000_GPIO_3		0x104
#define TM6000_GPIO_4		0x300
#define TM6000_GPIO_5		0x301
#define TM6000_GPIO_6		0x304
#define TM6000_GPIO_7		0x305

/* tm6010 defines GPIO with different values */
#define TM6010_GPIO_0      0x0102
#define TM6010_GPIO_1      0x0103
#define TM6010_GPIO_2      0x0104
#define TM6010_GPIO_3      0x0105
#define TM6010_GPIO_4      0x0106
#define TM6010_GPIO_5      0x0107
#define TM6010_GPIO_6      0x0300
#define TM6010_GPIO_7      0x0301
#define TM6010_GPIO_9      0x0305
/*
 * Define TV Master TM5600/TM6000/TM6010 URB message codes and length
 */

enum {
	TM6000_URB_MSG_VIDEO = 1,
	TM6000_URB_MSG_AUDIO,
	TM6000_URB_MSG_VBI,
	TM6000_URB_MSG_PTS,
	TM6000_URB_MSG_ERR,
};

/* Define specific TM6000 Video decoder registers */
#define TM6000_REQ07_RD8_TEST_SEL			0x07, 0xd8
#define TM6000_REQ07_RD9_A_SIM_SEL			0x07, 0xd9
#define TM6000_REQ07_RDA_CLK_SEL			0x07, 0xda
#define TM6000_REQ07_RDB_OUT_SEL			0x07, 0xdb
#define TM6000_REQ07_RDC_NSEL_I2S			0x07, 0xdc
#define TM6000_REQ07_RDD_GPIO2_MDRV			0x07, 0xdd
#define TM6000_REQ07_RDE_GPIO1_MDRV			0x07, 0xde
#define TM6000_REQ07_RDF_PWDOWN_ACLK			0x07, 0xdf
#define TM6000_REQ07_RE0_VADC_REF_CTL			0x07, 0xe0
#define TM6000_REQ07_RE1_VADC_DACLIMP			0x07, 0xe1
#define TM6000_REQ07_RE2_VADC_STATUS_CTL		0x07, 0xe2
#define TM6000_REQ07_RE3_VADC_INP_LPF_SEL1		0x07, 0xe3
#define TM6000_REQ07_RE4_VADC_TARGET1			0x07, 0xe4
#define TM6000_REQ07_RE5_VADC_INP_LPF_SEL2		0x07, 0xe5
#define TM6000_REQ07_RE6_VADC_TARGET2			0x07, 0xe6
#define TM6000_REQ07_RE7_VADC_AGAIN_CTL			0x07, 0xe7
#define TM6000_REQ07_RE8_VADC_PWDOWN_CTL		0x07, 0xe8
#define TM6000_REQ07_RE9_VADC_INPUT_CTL1		0x07, 0xe9
#define TM6000_REQ07_REA_VADC_INPUT_CTL2		0x07, 0xea
#define TM6000_REQ07_REB_VADC_AADC_MODE			0x07, 0xeb
#define TM6000_REQ07_REC_VADC_AADC_LVOL			0x07, 0xec
#define TM6000_REQ07_RED_VADC_AADC_RVOL			0x07, 0xed
#define TM6000_REQ07_REE_VADC_CTRL_SEL_CONTROL		0x07, 0xee
#define TM6000_REQ07_REF_VADC_GAIN_MAP_CTL		0x07, 0xef
#define TM6000_REQ07_RFD_BIST_ERR_VST_LOW		0x07, 0xfd
#define TM6000_REQ07_RFE_BIST_ERR_VST_HIGH		0x07, 0xfe

/* Define TM6000/TM6010 Video decoder registers */
#define TM6010_REQ07_R00_VIDEO_CONTROL0			0x07, 0x00
#define TM6010_REQ07_R01_VIDEO_CONTROL1			0x07, 0x01
#define TM6010_REQ07_R02_VIDEO_CONTROL2			0x07, 0x02
#define TM6010_REQ07_R03_YC_SEP_CONTROL			0x07, 0x03
#define TM6010_REQ07_R04_LUMA_HAGC_CONTROL		0x07, 0x04
#define TM6010_REQ07_R05_NOISE_THRESHOLD		0x07, 0x05
#define TM6010_REQ07_R06_AGC_GATE_THRESHOLD		0x07, 0x06
#define TM6010_REQ07_R07_OUTPUT_CONTROL			0x07, 0x07
#define TM6010_REQ07_R08_LUMA_CONTRAST_ADJ		0x07, 0x08
#define TM6010_REQ07_R09_LUMA_BRIGHTNESS_ADJ		0x07, 0x09
#define TM6010_REQ07_R0A_CHROMA_SATURATION_ADJ		0x07, 0x0a
#define TM6010_REQ07_R0B_CHROMA_HUE_PHASE_ADJ		0x07, 0x0b
#define TM6010_REQ07_R0C_CHROMA_AGC_CONTROL		0x07, 0x0c
#define TM6010_REQ07_R0D_CHROMA_KILL_LEVEL		0x07, 0x0d
#define TM6010_REQ07_R0F_CHROMA_AUTO_POSITION		0x07, 0x0f
#define TM6010_REQ07_R10_AGC_PEAK_NOMINAL		0x07, 0x10
#define TM6010_REQ07_R11_AGC_PEAK_CONTROL		0x07, 0x11
#define TM6010_REQ07_R12_AGC_GATE_STARTH		0x07, 0x12
#define TM6010_REQ07_R13_AGC_GATE_STARTL		0x07, 0x13
#define TM6010_REQ07_R14_AGC_GATE_WIDTH			0x07, 0x14
#define TM6010_REQ07_R15_AGC_BP_DELAY			0x07, 0x15
#define TM6010_REQ07_R16_LOCK_COUNT			0x07, 0x16
#define TM6010_REQ07_R17_HLOOP_MAXSTATE			0x07, 0x17
#define TM6010_REQ07_R18_CHROMA_DTO_INCREMENT3		0x07, 0x18
#define TM6010_REQ07_R19_CHROMA_DTO_INCREMENT2		0x07, 0x19
#define TM6010_REQ07_R1A_CHROMA_DTO_INCREMENT1		0x07, 0x1a
#define TM6010_REQ07_R1B_CHROMA_DTO_INCREMENT0		0x07, 0x1b
#define TM6010_REQ07_R1C_HSYNC_DTO_INCREMENT3		0x07, 0x1c
#define TM6010_REQ07_R1D_HSYNC_DTO_INCREMENT2		0x07, 0x1d
#define TM6010_REQ07_R1E_HSYNC_DTO_INCREMENT1		0x07, 0x1e
#define TM6010_REQ07_R1F_HSYNC_DTO_INCREMENT0		0x07, 0x1f
#define TM6010_REQ07_R20_HSYNC_RISING_EDGE_TIME		0x07, 0x20
#define TM6010_REQ07_R21_HSYNC_PHASE_OFFSET		0x07, 0x21
#define TM6010_REQ07_R22_HSYNC_PLL_START_TIME		0x07, 0x22
#define TM6010_REQ07_R23_HSYNC_PLL_END_TIME		0x07, 0x23
#define TM6010_REQ07_R24_HSYNC_TIP_START_TIME		0x07, 0x24
#define TM6010_REQ07_R25_HSYNC_TIP_END_TIME		0x07, 0x25
#define TM6010_REQ07_R26_HSYNC_RISING_EDGE_START	0x07, 0x26
#define TM6010_REQ07_R27_HSYNC_RISING_EDGE_END		0x07, 0x27
#define TM6010_REQ07_R28_BACKPORCH_START		0x07, 0x28
#define TM6010_REQ07_R29_BACKPORCH_END			0x07, 0x29
#define TM6010_REQ07_R2A_HSYNC_FILTER_START		0x07, 0x2a
#define TM6010_REQ07_R2B_HSYNC_FILTER_END		0x07, 0x2b
#define TM6010_REQ07_R2C_CHROMA_BURST_START		0x07, 0x2c
#define TM6010_REQ07_R2D_CHROMA_BURST_END		0x07, 0x2d
#define TM6010_REQ07_R2E_ACTIVE_VIDEO_HSTART		0x07, 0x2e
#define TM6010_REQ07_R2F_ACTIVE_VIDEO_HWIDTH		0x07, 0x2f
#define TM6010_REQ07_R30_ACTIVE_VIDEO_VSTART		0x07, 0x30
#define TM6010_REQ07_R31_ACTIVE_VIDEO_VHIGHT		0x07, 0x31
#define TM6010_REQ07_R32_VSYNC_HLOCK_MIN		0x07, 0x32
#define TM6010_REQ07_R33_VSYNC_HLOCK_MAX		0x07, 0x33
#define TM6010_REQ07_R34_VSYNC_AGC_MIN			0x07, 0x34
#define TM6010_REQ07_R35_VSYNC_AGC_MAX			0x07, 0x35
#define TM6010_REQ07_R36_VSYNC_VBI_MIN			0x07, 0x36
#define TM6010_REQ07_R37_VSYNC_VBI_MAX			0x07, 0x37
#define TM6010_REQ07_R38_VSYNC_THRESHOLD		0x07, 0x38
#define TM6010_REQ07_R39_VSYNC_TIME_CONSTANT		0x07, 0x39
#define TM6010_REQ07_R3A_STATUS1			0x07, 0x3a
#define TM6010_REQ07_R3B_STATUS2			0x07, 0x3b
#define TM6010_REQ07_R3C_STATUS3			0x07, 0x3c
#define TM6010_REQ07_R3F_RESET				0x07, 0x3f
#define TM6010_REQ07_R40_TELETEXT_VBI_CODE0		0x07, 0x40
#define TM6010_REQ07_R41_TELETEXT_VBI_CODE1		0x07, 0x41
#define TM6010_REQ07_R42_VBI_DATA_HIGH_LEVEL		0x07, 0x42
#define TM6010_REQ07_R43_VBI_DATA_TYPE_LINE7		0x07, 0x43
#define TM6010_REQ07_R44_VBI_DATA_TYPE_LINE8		0x07, 0x44
#define TM6010_REQ07_R45_VBI_DATA_TYPE_LINE9		0x07, 0x45
#define TM6010_REQ07_R46_VBI_DATA_TYPE_LINE10		0x07, 0x46
#define TM6010_REQ07_R47_VBI_DATA_TYPE_LINE11		0x07, 0x47
#define TM6010_REQ07_R48_VBI_DATA_TYPE_LINE12		0x07, 0x48
#define TM6010_REQ07_R49_VBI_DATA_TYPE_LINE13		0x07, 0x49
#define TM6010_REQ07_R4A_VBI_DATA_TYPE_LINE14		0x07, 0x4a
#define TM6010_REQ07_R4B_VBI_DATA_TYPE_LINE15		0x07, 0x4b
#define TM6010_REQ07_R4C_VBI_DATA_TYPE_LINE16		0x07, 0x4c
#define TM6010_REQ07_R4D_VBI_DATA_TYPE_LINE17		0x07, 0x4d
#define TM6010_REQ07_R4E_VBI_DATA_TYPE_LINE18		0x07, 0x4e
#define TM6010_REQ07_R4F_VBI_DATA_TYPE_LINE19		0x07, 0x4f
#define TM6010_REQ07_R50_VBI_DATA_TYPE_LINE20		0x07, 0x50
#define TM6010_REQ07_R51_VBI_DATA_TYPE_LINE21		0x07, 0x51
#define TM6010_REQ07_R52_VBI_DATA_TYPE_LINE22		0x07, 0x52
#define TM6010_REQ07_R53_VBI_DATA_TYPE_LINE23		0x07, 0x53
#define TM6010_REQ07_R54_VBI_DATA_TYPE_RLINES		0x07, 0x54
#define TM6010_REQ07_R55_VBI_LOOP_FILTER_GAIN		0x07, 0x55
#define TM6010_REQ07_R56_VBI_LOOP_FILTER_I_GAIN		0x07, 0x56
#define TM6010_REQ07_R57_VBI_LOOP_FILTER_P_GAIN		0x07, 0x57
#define TM6010_REQ07_R58_VBI_CAPTION_DTO1		0x07, 0x58
#define TM6010_REQ07_R59_VBI_CAPTION_DTO0		0x07, 0x59
#define TM6010_REQ07_R5A_VBI_TELETEXT_DTO1		0x07, 0x5a
#define TM6010_REQ07_R5B_VBI_TELETEXT_DTO0		0x07, 0x5b
#define TM6010_REQ07_R5C_VBI_WSS625_DTO1		0x07, 0x5c
#define TM6010_REQ07_R5D_VBI_WSS625_DTO0		0x07, 0x5d
#define TM6010_REQ07_R5E_VBI_CAPTION_FRAME_START	0x07, 0x5e
#define TM6010_REQ07_R5F_VBI_WSS625_FRAME_START		0x07, 0x5f
#define TM6010_REQ07_R60_TELETEXT_FRAME_START		0x07, 0x60
#define TM6010_REQ07_R61_VBI_CCDATA1			0x07, 0x61
#define TM6010_REQ07_R62_VBI_CCDATA2			0x07, 0x62
#define TM6010_REQ07_R63_VBI_WSS625_DATA1		0x07, 0x63
#define TM6010_REQ07_R64_VBI_WSS625_DATA2		0x07, 0x64
#define TM6010_REQ07_R65_VBI_DATA_STATUS		0x07, 0x65
#define TM6010_REQ07_R66_VBI_CAPTION_START		0x07, 0x66
#define TM6010_REQ07_R67_VBI_WSS625_START		0x07, 0x67
#define TM6010_REQ07_R68_VBI_TELETEXT_START		0x07, 0x68
#define TM6010_REQ07_R70_HSYNC_DTO_INC_STATUS3		0x07, 0x70
#define TM6010_REQ07_R71_HSYNC_DTO_INC_STATUS2		0x07, 0x71
#define TM6010_REQ07_R72_HSYNC_DTO_INC_STATUS1		0x07, 0x72
#define TM6010_REQ07_R73_HSYNC_DTO_INC_STATUS0		0x07, 0x73
#define TM6010_REQ07_R74_CHROMA_DTO_INC_STATUS3		0x07, 0x74
#define TM6010_REQ07_R75_CHROMA_DTO_INC_STATUS2		0x07, 0x75
#define TM6010_REQ07_R76_CHROMA_DTO_INC_STATUS1		0x07, 0x76
#define TM6010_REQ07_R77_CHROMA_DTO_INC_STATUS0		0x07, 0x77
#define TM6010_REQ07_R78_AGC_AGAIN_STATUS		0x07, 0x78
#define TM6010_REQ07_R79_AGC_DGAIN_STATUS		0x07, 0x79
#define TM6010_REQ07_R7A_CHROMA_MAG_STATUS		0x07, 0x7a
#define TM6010_REQ07_R7B_CHROMA_GAIN_STATUS1		0x07, 0x7b
#define TM6010_REQ07_R7C_CHROMA_GAIN_STATUS0		0x07, 0x7c
#define TM6010_REQ07_R7D_CORDIC_FREQ_STATUS		0x07, 0x7d
#define TM6010_REQ07_R7F_STATUS_NOISE			0x07, 0x7f
#define TM6010_REQ07_R80_COMB_FILTER_TRESHOLD		0x07, 0x80
#define TM6010_REQ07_R82_COMB_FILTER_CONFIG		0x07, 0x82
#define TM6010_REQ07_R83_CHROMA_LOCK_CONFIG		0x07, 0x83
#define TM6010_REQ07_R84_NOISE_NTSC_C			0x07, 0x84
#define TM6010_REQ07_R85_NOISE_PAL_C			0x07, 0x85
#define TM6010_REQ07_R86_NOISE_PHASE_C			0x07, 0x86
#define TM6010_REQ07_R87_NOISE_PHASE_Y			0x07, 0x87
#define TM6010_REQ07_R8A_CHROMA_LOOPFILTER_STATE	0x07, 0x8a
#define TM6010_REQ07_R8B_CHROMA_HRESAMPLER		0x07, 0x8b
#define TM6010_REQ07_R8D_CPUMP_DELAY_ADJ		0x07, 0x8d
#define TM6010_REQ07_R8E_CPUMP_ADJ			0x07, 0x8e
#define TM6010_REQ07_R8F_CPUMP_DELAY			0x07, 0x8f

/* Define TM6000/TM6010 Miscellaneous registers */
#define TM6010_REQ07_RC0_ACTIVE_VIDEO_SOURCE		0x07, 0xc0
#define TM6010_REQ07_RC1_TRESHOLD			0x07, 0xc1
#define TM6010_REQ07_RC2_HSYNC_WIDTH			0x07, 0xc2
#define TM6010_REQ07_RC3_HSTART1			0x07, 0xc3
#define TM6010_REQ07_RC4_HSTART0			0x07, 0xc4
#define TM6010_REQ07_RC5_HEND1				0x07, 0xc5
#define TM6010_REQ07_RC6_HEND0				0x07, 0xc6
#define TM6010_REQ07_RC7_VSTART1			0x07, 0xc7
#define TM6010_REQ07_RC8_VSTART0			0x07, 0xc8
#define TM6010_REQ07_RC9_VEND1				0x07, 0xc9
#define TM6010_REQ07_RCA_VEND0				0x07, 0xca
#define TM6010_REQ07_RCB_DELAY				0x07, 0xcb
/* ONLY for TM6010 */
#define TM6010_REQ07_RCC_ACTIVE_IF			0x07, 0xcc
#define TM6010_REQ07_RCC_ACTIVE_IF_VIDEO_ENABLE (1 << 5)
#define TM6010_REQ07_RCC_ACTIVE_IF_AUDIO_ENABLE (1 << 6)
#define TM6010_REQ07_RD0_USB_PERIPHERY_CONTROL		0x07, 0xd0
#define TM6010_REQ07_RD1_ADDR_FOR_REQ1			0x07, 0xd1
#define TM6010_REQ07_RD2_ADDR_FOR_REQ2			0x07, 0xd2
#define TM6010_REQ07_RD3_ADDR_FOR_REQ3			0x07, 0xd3
#define TM6010_REQ07_RD4_ADDR_FOR_REQ4			0x07, 0xd4
#define TM6010_REQ07_RD5_POWERSAVE			0x07, 0xd5
#define TM6010_REQ07_RD6_ENDP_REQ1_REQ2			0x07, 0xd6
#define TM6010_REQ07_RD7_ENDP_REQ3_REQ4			0x07, 0xd7
/* ONLY for TM6010 */
#define TM6010_REQ07_RD8_IR				0x07, 0xd8
/* ONLY for TM6010 */
#define TM6010_REQ07_RD9_IR_BSIZE			0x07, 0xd9
/* ONLY for TM6010 */
#define TM6010_REQ07_RDA_IR_WAKEUP_SEL			0x07, 0xda
/* ONLY for TM6010 */
#define TM6010_REQ07_RDB_IR_WAKEUP_ADD			0x07, 0xdb
/* ONLY for TM6010 */
#define TM6010_REQ07_RDC_IR_LEADER1			0x07, 0xdc
/* ONLY for TM6010 */
#define TM6010_REQ07_RDD_IR_LEADER0			0x07, 0xdd
/* ONLY for TM6010 */
#define TM6010_REQ07_RDE_IR_PULSE_CNT1			0x07, 0xde
/* ONLY for TM6010 */
#define TM6010_REQ07_RDF_IR_PULSE_CNT0			0x07, 0xdf
/* ONLY for TM6010 */
#define TM6010_REQ07_RE0_DVIDEO_SOURCE			0x07, 0xe0
/* ONLY for TM6010 */
#define TM6010_REQ07_RE0_DVIDEO_SOURCE_IF		0x07, 0xe1
/* ONLY for TM6010 */
#define TM6010_REQ07_RE2_OUT_SEL2			0x07, 0xe2
/* ONLY for TM6010 */
#define TM6010_REQ07_RE3_OUT_SEL1			0x07, 0xe3
/* ONLY for TM6010 */
#define TM6010_REQ07_RE4_OUT_SEL0			0x07, 0xe4
/* ONLY for TM6010 */
#define TM6010_REQ07_RE5_REMOTE_WAKEUP			0x07, 0xe5
/* ONLY for TM6010 */
#define TM6010_REQ07_RE7_PUB_GPIO			0x07, 0xe7
/* ONLY for TM6010 */
#define TM6010_REQ07_RE8_TYPESEL_MOS_I2S		0x07, 0xe8
/* ONLY for TM6010 */
#define TM6010_REQ07_RE9_TYPESEL_MOS_TS			0x07, 0xe9
/* ONLY for TM6010 */
#define TM6010_REQ07_REA_TYPESEL_MOS_CCIR		0x07, 0xea
/* ONLY for TM6010 */
#define TM6010_REQ07_RF0_BIST_CRC_RESULT0		0x07, 0xf0
/* ONLY for TM6010 */
#define TM6010_REQ07_RF1_BIST_CRC_RESULT1		0x07, 0xf1
/* ONLY for TM6010 */
#define TM6010_REQ07_RF2_BIST_CRC_RESULT2		0x07, 0xf2
/* ONLY for TM6010 */
#define TM6010_REQ07_RF3_BIST_CRC_RESULT3		0x07, 0xf3
/* ONLY for TM6010 */
#define TM6010_REQ07_RF4_BIST_ERR_VST2			0x07, 0xf4
/* ONLY for TM6010 */
#define TM6010_REQ07_RF5_BIST_ERR_VST1			0x07, 0xf5
/* ONLY for TM6010 */
#define TM6010_REQ07_RF6_BIST_ERR_VST0			0x07, 0xf6
/* ONLY for TM6010 */
#define TM6010_REQ07_RF7_BIST				0x07, 0xf7
/* ONLY for TM6010 */
#define TM6010_REQ07_RFE_POWER_DOWN			0x07, 0xfe
#define TM6010_REQ07_RFF_SOFT_RESET			0x07, 0xff

/* Define TM6000/TM6010 USB registers */
#define TM6010_REQ05_R00_MAIN_CTRL		0x05, 0x00
#define TM6010_REQ05_R01_DEVADDR		0x05, 0x01
#define TM6010_REQ05_R02_TEST			0x05, 0x02
#define TM6010_REQ05_R04_SOFN0			0x05, 0x04
#define TM6010_REQ05_R05_SOFN1			0x05, 0x05
#define TM6010_REQ05_R06_SOFTM0			0x05, 0x06
#define TM6010_REQ05_R07_SOFTM1			0x05, 0x07
#define TM6010_REQ05_R08_PHY_TEST		0x05, 0x08
#define TM6010_REQ05_R09_VCTL			0x05, 0x09
#define TM6010_REQ05_R0A_VSTA			0x05, 0x0a
#define TM6010_REQ05_R0B_CX_CFG			0x05, 0x0b
#define TM6010_REQ05_R0C_ENDP0_REG0		0x05, 0x0c
#define TM6010_REQ05_R10_GMASK			0x05, 0x10
#define TM6010_REQ05_R11_IMASK0			0x05, 0x11
#define TM6010_REQ05_R12_IMASK1			0x05, 0x12
#define TM6010_REQ05_R13_IMASK2			0x05, 0x13
#define TM6010_REQ05_R14_IMASK3			0x05, 0x14
#define TM6010_REQ05_R15_IMASK4			0x05, 0x15
#define TM6010_REQ05_R16_IMASK5			0x05, 0x16
#define TM6010_REQ05_R17_IMASK6			0x05, 0x17
#define TM6010_REQ05_R18_IMASK7			0x05, 0x18
#define TM6010_REQ05_R19_ZEROP0			0x05, 0x19
#define TM6010_REQ05_R1A_ZEROP1			0x05, 0x1a
#define TM6010_REQ05_R1C_FIFO_EMP0		0x05, 0x1c
#define TM6010_REQ05_R1D_FIFO_EMP1		0x05, 0x1d
#define TM6010_REQ05_R20_IRQ_GROUP		0x05, 0x20
#define TM6010_REQ05_R21_IRQ_SOURCE0		0x05, 0x21
#define TM6010_REQ05_R22_IRQ_SOURCE1		0x05, 0x22
#define TM6010_REQ05_R23_IRQ_SOURCE2		0x05, 0x23
#define TM6010_REQ05_R24_IRQ_SOURCE3		0x05, 0x24
#define TM6010_REQ05_R25_IRQ_SOURCE4		0x05, 0x25
#define TM6010_REQ05_R26_IRQ_SOURCE5		0x05, 0x26
#define TM6010_REQ05_R27_IRQ_SOURCE6		0x05, 0x27
#define TM6010_REQ05_R28_IRQ_SOURCE7		0x05, 0x28
#define TM6010_REQ05_R29_SEQ_ERR0		0x05, 0x29
#define TM6010_REQ05_R2A_SEQ_ERR1		0x05, 0x2a
#define TM6010_REQ05_R2B_SEQ_ABORT0		0x05, 0x2b
#define TM6010_REQ05_R2C_SEQ_ABORT1		0x05, 0x2c
#define TM6010_REQ05_R2D_TX_ZERO0		0x05, 0x2d
#define TM6010_REQ05_R2E_TX_ZERO1		0x05, 0x2e
#define TM6010_REQ05_R2F_IDLE_CNT		0x05, 0x2f
#define TM6010_REQ05_R30_FNO_P1			0x05, 0x30
#define TM6010_REQ05_R31_FNO_P2			0x05, 0x31
#define TM6010_REQ05_R32_FNO_P3			0x05, 0x32
#define TM6010_REQ05_R33_FNO_P4			0x05, 0x33
#define TM6010_REQ05_R34_FNO_P5			0x05, 0x34
#define TM6010_REQ05_R35_FNO_P6			0x05, 0x35
#define TM6010_REQ05_R36_FNO_P7			0x05, 0x36
#define TM6010_REQ05_R37_FNO_P8			0x05, 0x37
#define TM6010_REQ05_R38_FNO_P9			0x05, 0x38
#define TM6010_REQ05_R30_FNO_P10		0x05, 0x39
#define TM6010_REQ05_R30_FNO_P11		0x05, 0x3a
#define TM6010_REQ05_R30_FNO_P12		0x05, 0x3b
#define TM6010_REQ05_R30_FNO_P13		0x05, 0x3c
#define TM6010_REQ05_R30_FNO_P14		0x05, 0x3d
#define TM6010_REQ05_R30_FNO_P15		0x05, 0x3e
#define TM6010_REQ05_R40_IN_MAXPS_LOW1		0x05, 0x40
#define TM6010_REQ05_R41_IN_MAXPS_HIGH1		0x05, 0x41
#define TM6010_REQ05_R42_IN_MAXPS_LOW2		0x05, 0x42
#define TM6010_REQ05_R43_IN_MAXPS_HIGH2		0x05, 0x43
#define TM6010_REQ05_R44_IN_MAXPS_LOW3		0x05, 0x44
#define TM6010_REQ05_R45_IN_MAXPS_HIGH3		0x05, 0x45
#define TM6010_REQ05_R46_IN_MAXPS_LOW4		0x05, 0x46
#define TM6010_REQ05_R47_IN_MAXPS_HIGH4		0x05, 0x47
#define TM6010_REQ05_R48_IN_MAXPS_LOW5		0x05, 0x48
#define TM6010_REQ05_R49_IN_MAXPS_HIGH5		0x05, 0x49
#define TM6010_REQ05_R4A_IN_MAXPS_LOW6		0x05, 0x4a
#define TM6010_REQ05_R4B_IN_MAXPS_HIGH6		0x05, 0x4b
#define TM6010_REQ05_R4C_IN_MAXPS_LOW7		0x05, 0x4c
#define TM6010_REQ05_R4D_IN_MAXPS_HIGH7		0x05, 0x4d
#define TM6010_REQ05_R4E_IN_MAXPS_LOW8		0x05, 0x4e
#define TM6010_REQ05_R4F_IN_MAXPS_HIGH8		0x05, 0x4f
#define TM6010_REQ05_R50_IN_MAXPS_LOW9		0x05, 0x50
#define TM6010_REQ05_R51_IN_MAXPS_HIGH9		0x05, 0x51
#define TM6010_REQ05_R40_IN_MAXPS_LOW10		0x05, 0x52
#define TM6010_REQ05_R41_IN_MAXPS_HIGH10	0x05, 0x53
#define TM6010_REQ05_R40_IN_MAXPS_LOW11		0x05, 0x54
#define TM6010_REQ05_R41_IN_MAXPS_HIGH11	0x05, 0x55
#define TM6010_REQ05_R40_IN_MAXPS_LOW12		0x05, 0x56
#define TM6010_REQ05_R41_IN_MAXPS_HIGH12	0x05, 0x57
#define TM6010_REQ05_R40_IN_MAXPS_LOW13		0x05, 0x58
#define TM6010_REQ05_R41_IN_MAXPS_HIGH13	0x05, 0x59
#define TM6010_REQ05_R40_IN_MAXPS_LOW14		0x05, 0x5a
#define TM6010_REQ05_R41_IN_MAXPS_HIGH14	0x05, 0x5b
#define TM6010_REQ05_R40_IN_MAXPS_LOW15		0x05, 0x5c
#define TM6010_REQ05_R41_IN_MAXPS_HIGH15	0x05, 0x5d
#define TM6010_REQ05_R60_OUT_MAXPS_LOW1		0x05, 0x60
#define TM6010_REQ05_R61_OUT_MAXPS_HIGH1	0x05, 0x61
#define TM6010_REQ05_R62_OUT_MAXPS_LOW2		0x05, 0x62
#define TM6010_REQ05_R63_OUT_MAXPS_HIGH2	0x05, 0x63
#define TM6010_REQ05_R64_OUT_MAXPS_LOW3		0x05, 0x64
#define TM6010_REQ05_R65_OUT_MAXPS_HIGH3	0x05, 0x65
#define TM6010_REQ05_R66_OUT_MAXPS_LOW4		0x05, 0x66
#define TM6010_REQ05_R67_OUT_MAXPS_HIGH4	0x05, 0x67
#define TM6010_REQ05_R68_OUT_MAXPS_LOW5		0x05, 0x68
#define TM6010_REQ05_R69_OUT_MAXPS_HIGH5	0x05, 0x69
#define TM6010_REQ05_R6A_OUT_MAXPS_LOW6		0x05, 0x6a
#define TM6010_REQ05_R6B_OUT_MAXPS_HIGH6	0x05, 0x6b
#define TM6010_REQ05_R6C_OUT_MAXPS_LOW7		0x05, 0x6c
#define TM6010_REQ05_R6D_OUT_MAXPS_HIGH7	0x05, 0x6d
#define TM6010_REQ05_R6E_OUT_MAXPS_LOW8		0x05, 0x6e
#define TM6010_REQ05_R6F_OUT_MAXPS_HIGH8	0x05, 0x6f
#define TM6010_REQ05_R70_OUT_MAXPS_LOW9		0x05, 0x70
#define TM6010_REQ05_R71_OUT_MAXPS_HIGH9	0x05, 0x71
#define TM6010_REQ05_R60_OUT_MAXPS_LOW10	0x05, 0x72
#define TM6010_REQ05_R61_OUT_MAXPS_HIGH10	0x05, 0x73
#define TM6010_REQ05_R60_OUT_MAXPS_LOW11	0x05, 0x74
#define TM6010_REQ05_R61_OUT_MAXPS_HIGH11	0x05, 0x75
#define TM6010_REQ05_R60_OUT_MAXPS_LOW12	0x05, 0x76
#define TM6010_REQ05_R61_OUT_MAXPS_HIGH12	0x05, 0x77
#define TM6010_REQ05_R60_OUT_MAXPS_LOW13	0x05, 0x78
#define TM6010_REQ05_R61_OUT_MAXPS_HIGH13	0x05, 0x79
#define TM6010_REQ05_R60_OUT_MAXPS_LOW14	0x05, 0x7a
#define TM6010_REQ05_R61_OUT_MAXPS_HIGH14	0x05, 0x7b
#define TM6010_REQ05_R60_OUT_MAXPS_LOW15	0x05, 0x7c
#define TM6010_REQ05_R61_OUT_MAXPS_HIGH15	0x05, 0x7d
#define TM6010_REQ05_R80_FIFO0			0x05, 0x80
#define TM6010_REQ05_R81_FIFO1			0x05, 0x81
#define TM6010_REQ05_R82_FIFO2			0x05, 0x82
#define TM6010_REQ05_R83_FIFO3			0x05, 0x83
#define TM6010_REQ05_R84_FIFO4			0x05, 0x84
#define TM6010_REQ05_R85_FIFO5			0x05, 0x85
#define TM6010_REQ05_R86_FIFO6			0x05, 0x86
#define TM6010_REQ05_R87_FIFO7			0x05, 0x87
#define TM6010_REQ05_R88_FIFO8			0x05, 0x88
#define TM6010_REQ05_R89_FIFO9			0x05, 0x89
#define TM6010_REQ05_R81_FIFO10			0x05, 0x8a
#define TM6010_REQ05_R81_FIFO11			0x05, 0x8b
#define TM6010_REQ05_R81_FIFO12			0x05, 0x8c
#define TM6010_REQ05_R81_FIFO13			0x05, 0x8d
#define TM6010_REQ05_R81_FIFO14			0x05, 0x8e
#define TM6010_REQ05_R81_FIFO15			0x05, 0x8f
#define TM6010_REQ05_R90_CFG_FIFO0		0x05, 0x90
#define TM6010_REQ05_R91_CFG_FIFO1		0x05, 0x91
#define TM6010_REQ05_R92_CFG_FIFO2		0x05, 0x92
#define TM6010_REQ05_R93_CFG_FIFO3		0x05, 0x93
#define TM6010_REQ05_R94_CFG_FIFO4		0x05, 0x94
#define TM6010_REQ05_R95_CFG_FIFO5		0x05, 0x95
#define TM6010_REQ05_R96_CFG_FIFO6		0x05, 0x96
#define TM6010_REQ05_R97_CFG_FIFO7		0x05, 0x97
#define TM6010_REQ05_R98_CFG_FIFO8		0x05, 0x98
#define TM6010_REQ05_R99_CFG_FIFO9		0x05, 0x99
#define TM6010_REQ05_R91_CFG_FIFO10		0x05, 0x9a
#define TM6010_REQ05_R91_CFG_FIFO11		0x05, 0x9b
#define TM6010_REQ05_R91_CFG_FIFO12		0x05, 0x9c
#define TM6010_REQ05_R91_CFG_FIFO13		0x05, 0x9d
#define TM6010_REQ05_R91_CFG_FIFO14		0x05, 0x9e
#define TM6010_REQ05_R91_CFG_FIFO15		0x05, 0x9f
#define TM6010_REQ05_RA0_CTL_FIFO0		0x05, 0xa0
#define TM6010_REQ05_RA1_CTL_FIFO1		0x05, 0xa1
#define TM6010_REQ05_RA2_CTL_FIFO2		0x05, 0xa2
#define TM6010_REQ05_RA3_CTL_FIFO3		0x05, 0xa3
#define TM6010_REQ05_RA4_CTL_FIFO4		0x05, 0xa4
#define TM6010_REQ05_RA5_CTL_FIFO5		0x05, 0xa5
#define TM6010_REQ05_RA6_CTL_FIFO6		0x05, 0xa6
#define TM6010_REQ05_RA7_CTL_FIFO7		0x05, 0xa7
#define TM6010_REQ05_RA8_CTL_FIFO8		0x05, 0xa8
#define TM6010_REQ05_RA9_CTL_FIFO9		0x05, 0xa9
#define TM6010_REQ05_RA1_CTL_FIFO10		0x05, 0xaa
#define TM6010_REQ05_RA1_CTL_FIFO11		0x05, 0xab
#define TM6010_REQ05_RA1_CTL_FIFO12		0x05, 0xac
#define TM6010_REQ05_RA1_CTL_FIFO13		0x05, 0xad
#define TM6010_REQ05_RA1_CTL_FIFO14		0x05, 0xae
#define TM6010_REQ05_RA1_CTL_FIFO15		0x05, 0xaf
#define TM6010_REQ05_RB0_BC_LOW_FIFO0		0x05, 0xb0
#define TM6010_REQ05_RB1_BC_LOW_FIFO1		0x05, 0xb1
#define TM6010_REQ05_RB2_BC_LOW_FIFO2		0x05, 0xb2
#define TM6010_REQ05_RB3_BC_LOW_FIFO3		0x05, 0xb3
#define TM6010_REQ05_RB4_BC_LOW_FIFO4		0x05, 0xb4
#define TM6010_REQ05_RB5_BC_LOW_FIFO5		0x05, 0xb5
#define TM6010_REQ05_RB6_BC_LOW_FIFO6		0x05, 0xb6
#define TM6010_REQ05_RB7_BC_LOW_FIFO7		0x05, 0xb7
#define TM6010_REQ05_RB8_BC_LOW_FIFO8		0x05, 0xb8
#define TM6010_REQ05_RB9_BC_LOW_FIFO9		0x05, 0xb9
#define TM6010_REQ05_RB1_BC_LOW_FIFO10		0x05, 0xba
#define TM6010_REQ05_RB1_BC_LOW_FIFO11		0x05, 0xbb
#define TM6010_REQ05_RB1_BC_LOW_FIFO12		0x05, 0xbc
#define TM6010_REQ05_RB1_BC_LOW_FIFO13		0x05, 0xbd
#define TM6010_REQ05_RB1_BC_LOW_FIFO14		0x05, 0xbe
#define TM6010_REQ05_RB1_BC_LOW_FIFO15		0x05, 0xbf
#define TM6010_REQ05_RC0_DATA_FIFO0		0x05, 0xc0
#define TM6010_REQ05_RC4_DATA_FIFO1		0x05, 0xc4
#define TM6010_REQ05_RC8_DATA_FIFO2		0x05, 0xc8
#define TM6010_REQ05_RCC_DATA_FIFO3		0x05, 0xcc
#define TM6010_REQ05_RD0_DATA_FIFO4		0x05, 0xd0
#define TM6010_REQ05_RD4_DATA_FIFO5		0x05, 0xd4
#define TM6010_REQ05_RD8_DATA_FIFO6		0x05, 0xd8
#define TM6010_REQ05_RDC_DATA_FIFO7		0x05, 0xdc
#define TM6010_REQ05_RE0_DATA_FIFO8		0x05, 0xe0
#define TM6010_REQ05_RE4_DATA_FIFO9		0x05, 0xe4
#define TM6010_REQ05_RC4_DATA_FIFO10		0x05, 0xe8
#define TM6010_REQ05_RC4_DATA_FIFO11		0x05, 0xec
#define TM6010_REQ05_RC4_DATA_FIFO12		0x05, 0xf0
#define TM6010_REQ05_RC4_DATA_FIFO13		0x05, 0xf4
#define TM6010_REQ05_RC4_DATA_FIFO14		0x05, 0xf8
#define TM6010_REQ05_RC4_DATA_FIFO15		0x05, 0xfc

/* Define TM6010 Audio decoder registers */
/* This core available only in TM6010 */
#define TM6010_REQ08_R00_A_VERSION		0x08, 0x00
#define TM6010_REQ08_R01_A_INIT			0x08, 0x01
#define TM6010_REQ08_R02_A_FIX_GAIN_CTRL	0x08, 0x02
#define TM6010_REQ08_R03_A_AUTO_GAIN_CTRL	0x08, 0x03
#define TM6010_REQ08_R04_A_SIF_AMP_CTRL		0x08, 0x04
#define TM6010_REQ08_R05_A_STANDARD_MOD		0x08, 0x05
#define TM6010_REQ08_R06_A_SOUND_MOD		0x08, 0x06
#define TM6010_REQ08_R07_A_LEFT_VOL		0x08, 0x07
#define TM6010_REQ08_R08_A_RIGHT_VOL		0x08, 0x08
#define TM6010_REQ08_R09_A_MAIN_VOL		0x08, 0x09
#define TM6010_REQ08_R0A_A_I2S_MOD		0x08, 0x0a
#define TM6010_REQ08_R0B_A_ASD_THRES1		0x08, 0x0b
#define TM6010_REQ08_R0C_A_ASD_THRES2		0x08, 0x0c
#define TM6010_REQ08_R0D_A_AMD_THRES		0x08, 0x0d
#define TM6010_REQ08_R0E_A_MONO_THRES1		0x08, 0x0e
#define TM6010_REQ08_R0F_A_MONO_THRES2		0x08, 0x0f
#define TM6010_REQ08_R10_A_MUTE_THRES1		0x08, 0x10
#define TM6010_REQ08_R11_A_MUTE_THRES2		0x08, 0x11
#define TM6010_REQ08_R12_A_AGC_U		0x08, 0x12
#define TM6010_REQ08_R13_A_AGC_ERR_T		0x08, 0x13
#define TM6010_REQ08_R14_A_AGC_GAIN_INIT	0x08, 0x14
#define TM6010_REQ08_R15_A_AGC_STEP_THR		0x08, 0x15
#define TM6010_REQ08_R16_A_AGC_GAIN_MAX		0x08, 0x16
#define TM6010_REQ08_R17_A_AGC_GAIN_MIN		0x08, 0x17
#define TM6010_REQ08_R18_A_TR_CTRL		0x08, 0x18
#define TM6010_REQ08_R19_A_FH_2FH_GAIN		0x08, 0x19
#define TM6010_REQ08_R1A_A_NICAM_SER_MAX	0x08, 0x1a
#define TM6010_REQ08_R1B_A_NICAM_SER_MIN	0x08, 0x1b
#define TM6010_REQ08_R1E_A_GAIN_DEEMPH_OUT	0x08, 0x1e
#define TM6010_REQ08_R1F_A_TEST_INTF_SEL	0x08, 0x1f
#define TM6010_REQ08_R20_A_TEST_PIN_SEL		0x08, 0x20
#define TM6010_REQ08_R21_A_AGC_ERR		0x08, 0x21
#define TM6010_REQ08_R22_A_AGC_GAIN		0x08, 0x22
#define TM6010_REQ08_R23_A_NICAM_INFO		0x08, 0x23
#define TM6010_REQ08_R24_A_SER			0x08, 0x24
#define TM6010_REQ08_R25_A_C1_AMP		0x08, 0x25
#define TM6010_REQ08_R26_A_C2_AMP		0x08, 0x26
#define TM6010_REQ08_R27_A_NOISE_AMP		0x08, 0x27
#define TM6010_REQ08_R28_A_AUDIO_MODE_RES	0x08, 0x28

/* Define TM6010 Video ADC registers */
#define TM6010_REQ08_RE0_ADC_REF		0x08, 0xe0
#define TM6010_REQ08_RE1_DAC_CLMP		0x08, 0xe1
#define TM6010_REQ08_RE2_POWER_DOWN_CTRL1	0x08, 0xe2
#define TM6010_REQ08_RE3_ADC_IN1_SEL		0x08, 0xe3
#define TM6010_REQ08_RE4_ADC_IN2_SEL		0x08, 0xe4
#define TM6010_REQ08_RE5_GAIN_PARAM		0x08, 0xe5
#define TM6010_REQ08_RE6_POWER_DOWN_CTRL2	0x08, 0xe6
#define TM6010_REQ08_RE7_REG_GAIN_Y		0x08, 0xe7
#define TM6010_REQ08_RE8_REG_GAIN_C		0x08, 0xe8
#define TM6010_REQ08_RE9_BIAS_CTRL		0x08, 0xe9
#define TM6010_REQ08_REA_BUFF_DRV_CTRL		0x08, 0xea
#define TM6010_REQ08_REB_SIF_GAIN_CTRL		0x08, 0xeb
#define TM6010_REQ08_REC_REVERSE_YC_CTRL	0x08, 0xec
#define TM6010_REQ08_RED_GAIN_SEL		0x08, 0xed

/* Define TM6010 Audio ADC registers */
#define TM6010_REQ08_RF0_DAUDIO_INPUT_CONFIG	0x08, 0xf0
#define TM6010_REQ08_RF1_AADC_POWER_DOWN	0x08, 0xf1
#define TM6010_REQ08_RF2_LEFT_CHANNEL_VOL	0x08, 0xf2
#define TM6010_REQ08_RF3_RIGHT_CHANNEL_VOL	0x08, 0xf3
