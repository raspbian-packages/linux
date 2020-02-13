/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HDMI driver definition for TI OMAP5 processors.
 *
 * Copyright (C) 2011-2012 Texas Instruments Incorporated - http://www.ti.com/
 */

#ifndef _HDMI5_CORE_H_
#define _HDMI5_CORE_H_

#include "hdmi.h"

/* HDMI IP Core System */

/* HDMI Identification */
#define HDMI_CORE_DESIGN_ID			0x00000
#define HDMI_CORE_REVISION_ID			0x00004
#define HDMI_CORE_PRODUCT_ID0			0x00008
#define HDMI_CORE_PRODUCT_ID1			0x0000C
#define HDMI_CORE_CONFIG0_ID			0x00010
#define HDMI_CORE_CONFIG1_ID			0x00014
#define HDMI_CORE_CONFIG2_ID			0x00018
#define HDMI_CORE_CONFIG3_ID			0x0001C

/* HDMI Interrupt */
#define HDMI_CORE_IH_FC_STAT0			0x00400
#define HDMI_CORE_IH_FC_STAT1			0x00404
#define HDMI_CORE_IH_FC_STAT2			0x00408
#define HDMI_CORE_IH_AS_STAT0			0x0040C
#define HDMI_CORE_IH_PHY_STAT0			0x00410
#define HDMI_CORE_IH_I2CM_STAT0			0x00414
#define HDMI_CORE_IH_CEC_STAT0			0x00418
#define HDMI_CORE_IH_VP_STAT0			0x0041C
#define HDMI_CORE_IH_I2CMPHY_STAT0		0x00420
#define HDMI_CORE_IH_MUTE			0x007FC

/* HDMI Video Sampler */
#define HDMI_CORE_TX_INVID0			0x00800
#define HDMI_CORE_TX_INSTUFFING			0x00804
#define HDMI_CORE_TX_RGYDATA0			0x00808
#define HDMI_CORE_TX_RGYDATA1			0x0080C
#define HDMI_CORE_TX_RCRDATA0			0x00810
#define HDMI_CORE_TX_RCRDATA1			0x00814
#define HDMI_CORE_TX_BCBDATA0			0x00818
#define HDMI_CORE_TX_BCBDATA1			0x0081C

/* HDMI Video Packetizer */
#define HDMI_CORE_VP_STATUS			0x02000
#define HDMI_CORE_VP_PR_CD			0x02004
#define HDMI_CORE_VP_STUFF			0x02008
#define HDMI_CORE_VP_REMAP			0x0200C
#define HDMI_CORE_VP_CONF			0x02010
#define HDMI_CORE_VP_STAT			0x02014
#define HDMI_CORE_VP_INT			0x02018
#define HDMI_CORE_VP_MASK			0x0201C
#define HDMI_CORE_VP_POL			0x02020

/* Frame Composer */
#define HDMI_CORE_FC_INVIDCONF			0x04000
#define HDMI_CORE_FC_INHACTIV0			0x04004
#define HDMI_CORE_FC_INHACTIV1			0x04008
#define HDMI_CORE_FC_INHBLANK0			0x0400C
#define HDMI_CORE_FC_INHBLANK1			0x04010
#define HDMI_CORE_FC_INVACTIV0			0x04014
#define HDMI_CORE_FC_INVACTIV1			0x04018
#define HDMI_CORE_FC_INVBLANK			0x0401C
#define HDMI_CORE_FC_HSYNCINDELAY0		0x04020
#define HDMI_CORE_FC_HSYNCINDELAY1		0x04024
#define HDMI_CORE_FC_HSYNCINWIDTH0		0x04028
#define HDMI_CORE_FC_HSYNCINWIDTH1		0x0402C
#define HDMI_CORE_FC_VSYNCINDELAY		0x04030
#define HDMI_CORE_FC_VSYNCINWIDTH		0x04034
#define HDMI_CORE_FC_INFREQ0			0x04038
#define HDMI_CORE_FC_INFREQ1			0x0403C
#define HDMI_CORE_FC_INFREQ2			0x04040
#define HDMI_CORE_FC_CTRLDUR			0x04044
#define HDMI_CORE_FC_EXCTRLDUR			0x04048
#define HDMI_CORE_FC_EXCTRLSPAC			0x0404C
#define HDMI_CORE_FC_CH0PREAM			0x04050
#define HDMI_CORE_FC_CH1PREAM			0x04054
#define HDMI_CORE_FC_CH2PREAM			0x04058
#define HDMI_CORE_FC_AVICONF3			0x0405C
#define HDMI_CORE_FC_GCP			0x04060
#define HDMI_CORE_FC_AVICONF0			0x04064
#define HDMI_CORE_FC_AVICONF1			0x04068
#define HDMI_CORE_FC_AVICONF2			0x0406C
#define HDMI_CORE_FC_AVIVID			0x04070
#define HDMI_CORE_FC_AVIETB0			0x04074
#define HDMI_CORE_FC_AVIETB1			0x04078
#define HDMI_CORE_FC_AVISBB0			0x0407C
#define HDMI_CORE_FC_AVISBB1			0x04080
#define HDMI_CORE_FC_AVIELB0			0x04084
#define HDMI_CORE_FC_AVIELB1			0x04088
#define HDMI_CORE_FC_AVISRB0			0x0408C
#define HDMI_CORE_FC_AVISRB1			0x04090
#define HDMI_CORE_FC_AUDICONF0			0x04094
#define HDMI_CORE_FC_AUDICONF1			0x04098
#define HDMI_CORE_FC_AUDICONF2			0x0409C
#define HDMI_CORE_FC_AUDICONF3			0x040A0
#define HDMI_CORE_FC_VSDIEEEID0			0x040A4
#define HDMI_CORE_FC_VSDSIZE			0x040A8
#define HDMI_CORE_FC_VSDIEEEID1			0x040C0
#define HDMI_CORE_FC_VSDIEEEID2			0x040C4
#define HDMI_CORE_FC_VSDPAYLOAD(n)		(n * 4 + 0x040C8)
#define HDMI_CORE_FC_SPDVENDORNAME(n)		(n * 4 + 0x04128)
#define HDMI_CORE_FC_SPDPRODUCTNAME(n)		(n * 4 + 0x04148)
#define HDMI_CORE_FC_SPDDEVICEINF		0x04188
#define HDMI_CORE_FC_AUDSCONF			0x0418C
#define HDMI_CORE_FC_AUDSSTAT			0x04190
#define HDMI_CORE_FC_AUDSV			0x04194
#define HDMI_CORE_FC_AUDSU			0x04198
#define HDMI_CORE_FC_AUDSCHNLS(n)		(n * 4 + 0x0419C)
#define HDMI_CORE_FC_CTRLQHIGH			0x041CC
#define HDMI_CORE_FC_CTRLQLOW			0x041D0
#define HDMI_CORE_FC_ACP0			0x041D4
#define HDMI_CORE_FC_ACP(n)			((16-n) * 4 + 0x04208)
#define HDMI_CORE_FC_ISCR1_0			0x04248
#define HDMI_CORE_FC_ISCR1(n)			((16-n) * 4 + 0x0424C)
#define HDMI_CORE_FC_ISCR2(n)			((15-n) * 4 + 0x0428C)
#define HDMI_CORE_FC_DATAUTO0			0x042CC
#define HDMI_CORE_FC_DATAUTO1			0x042D0
#define HDMI_CORE_FC_DATAUTO2			0x042D4
#define HDMI_CORE_FC_DATMAN			0x042D8
#define HDMI_CORE_FC_DATAUTO3			0x042DC
#define HDMI_CORE_FC_RDRB(n)			(n * 4 + 0x042E0)
#define HDMI_CORE_FC_STAT0			0x04340
#define HDMI_CORE_FC_INT0			0x04344
#define HDMI_CORE_FC_MASK0			0x04348
#define HDMI_CORE_FC_POL0			0x0434C
#define HDMI_CORE_FC_STAT1			0x04350
#define HDMI_CORE_FC_INT1			0x04354
#define HDMI_CORE_FC_MASK1			0x04358
#define HDMI_CORE_FC_POL1			0x0435C
#define HDMI_CORE_FC_STAT2			0x04360
#define HDMI_CORE_FC_INT2			0x04364
#define HDMI_CORE_FC_MASK2			0x04368
#define HDMI_CORE_FC_POL2			0x0436C
#define HDMI_CORE_FC_PRCONF			0x04380
#define HDMI_CORE_FC_GMD_STAT			0x04400
#define HDMI_CORE_FC_GMD_EN			0x04404
#define HDMI_CORE_FC_GMD_UP			0x04408
#define HDMI_CORE_FC_GMD_CONF			0x0440C
#define HDMI_CORE_FC_GMD_HB			0x04410
#define HDMI_CORE_FC_GMD_PB(n)			(n * 4 + 0x04414)
#define HDMI_CORE_FC_DBGFORCE			0x04800
#define HDMI_CORE_FC_DBGAUD0CH0			0x04804
#define HDMI_CORE_FC_DBGAUD1CH0			0x04808
#define HDMI_CORE_FC_DBGAUD2CH0			0x0480C
#define HDMI_CORE_FC_DBGAUD0CH1			0x04810
#define HDMI_CORE_FC_DBGAUD1CH1			0x04814
#define HDMI_CORE_FC_DBGAUD2CH1			0x04818
#define HDMI_CORE_FC_DBGAUD0CH2			0x0481C
#define HDMI_CORE_FC_DBGAUD1CH2			0x04820
#define HDMI_CORE_FC_DBGAUD2CH2			0x04824
#define HDMI_CORE_FC_DBGAUD0CH3			0x04828
#define HDMI_CORE_FC_DBGAUD1CH3			0x0482C
#define HDMI_CORE_FC_DBGAUD2CH3			0x04830
#define HDMI_CORE_FC_DBGAUD0CH4			0x04834
#define HDMI_CORE_FC_DBGAUD1CH4			0x04838
#define HDMI_CORE_FC_DBGAUD2CH4			0x0483C
#define HDMI_CORE_FC_DBGAUD0CH5			0x04840
#define HDMI_CORE_FC_DBGAUD1CH5			0x04844
#define HDMI_CORE_FC_DBGAUD2CH5			0x04848
#define HDMI_CORE_FC_DBGAUD0CH6			0x0484C
#define HDMI_CORE_FC_DBGAUD1CH6			0x04850
#define HDMI_CORE_FC_DBGAUD2CH6			0x04854
#define HDMI_CORE_FC_DBGAUD0CH7			0x04858
#define HDMI_CORE_FC_DBGAUD1CH7			0x0485C
#define HDMI_CORE_FC_DBGAUD2CH7			0x04860
#define HDMI_CORE_FC_DBGTMDS0			0x04864
#define HDMI_CORE_FC_DBGTMDS1			0x04868
#define HDMI_CORE_FC_DBGTMDS2			0x0486C
#define HDMI_CORE_PHY_MASK0			0x0C018
#define HDMI_CORE_PHY_I2CM_INT_ADDR		0x0C09C
#define HDMI_CORE_PHY_I2CM_CTLINT_ADDR		0x0C0A0

/* HDMI Audio */
#define HDMI_CORE_AUD_CONF0			0x0C400
#define HDMI_CORE_AUD_CONF1			0x0C404
#define HDMI_CORE_AUD_INT			0x0C408
#define HDMI_CORE_AUD_N1			0x0C800
#define HDMI_CORE_AUD_N2			0x0C804
#define HDMI_CORE_AUD_N3			0x0C808
#define HDMI_CORE_AUD_CTS1			0x0C80C
#define HDMI_CORE_AUD_CTS2			0x0C810
#define HDMI_CORE_AUD_CTS3			0x0C814
#define HDMI_CORE_AUD_INCLKFS			0x0C818
#define HDMI_CORE_AUD_CC08			0x0CC08
#define HDMI_CORE_AUD_GP_CONF0			0x0D400
#define HDMI_CORE_AUD_GP_CONF1			0x0D404
#define HDMI_CORE_AUD_GP_CONF2			0x0D408
#define HDMI_CORE_AUD_D010			0x0D010
#define HDMI_CORE_AUD_GP_STAT			0x0D40C
#define HDMI_CORE_AUD_GP_INT			0x0D410
#define HDMI_CORE_AUD_GP_POL			0x0D414
#define HDMI_CORE_AUD_GP_MASK			0x0D418

/* HDMI Main Controller */
#define HDMI_CORE_MC_CLKDIS			0x10004
#define HDMI_CORE_MC_SWRSTZREQ			0x10008
#define HDMI_CORE_MC_FLOWCTRL			0x10010
#define HDMI_CORE_MC_PHYRSTZ			0x10014
#define HDMI_CORE_MC_LOCKONCLOCK		0x10018

/* HDMI COLOR SPACE CONVERTER */
#define HDMI_CORE_CSC_CFG			0x10400
#define HDMI_CORE_CSC_SCALE			0x10404
#define HDMI_CORE_CSC_COEF_A1_MSB		0x10408
#define HDMI_CORE_CSC_COEF_A1_LSB		0x1040C
#define HDMI_CORE_CSC_COEF_A2_MSB		0x10410
#define HDMI_CORE_CSC_COEF_A2_LSB		0x10414
#define HDMI_CORE_CSC_COEF_A3_MSB		0x10418
#define HDMI_CORE_CSC_COEF_A3_LSB		0x1041C
#define HDMI_CORE_CSC_COEF_A4_MSB		0x10420
#define HDMI_CORE_CSC_COEF_A4_LSB		0x10424
#define HDMI_CORE_CSC_COEF_B1_MSB		0x10428
#define HDMI_CORE_CSC_COEF_B1_LSB		0x1042C
#define HDMI_CORE_CSC_COEF_B2_MSB		0x10430
#define HDMI_CORE_CSC_COEF_B2_LSB		0x10434
#define HDMI_CORE_CSC_COEF_B3_MSB		0x10438
#define HDMI_CORE_CSC_COEF_B3_LSB		0x1043C
#define HDMI_CORE_CSC_COEF_B4_MSB		0x10440
#define HDMI_CORE_CSC_COEF_B4_LSB		0x10444
#define HDMI_CORE_CSC_COEF_C1_MSB		0x10448
#define HDMI_CORE_CSC_COEF_C1_LSB		0x1044C
#define HDMI_CORE_CSC_COEF_C2_MSB		0x10450
#define HDMI_CORE_CSC_COEF_C2_LSB		0x10454
#define HDMI_CORE_CSC_COEF_C3_MSB		0x10458
#define HDMI_CORE_CSC_COEF_C3_LSB		0x1045C
#define HDMI_CORE_CSC_COEF_C4_MSB		0x10460
#define HDMI_CORE_CSC_COEF_C4_LSB		0x10464

/* HDMI HDCP */
#define HDMI_CORE_HDCP_MASK			0x14020

/* HDMI CEC */
#define HDMI_CORE_CEC_MASK			0x17408

/* HDMI I2C Master */
#define HDMI_CORE_I2CM_SLAVE			0x157C8
#define HDMI_CORE_I2CM_ADDRESS			0x157CC
#define HDMI_CORE_I2CM_DATAO			0x157D0
#define HDMI_CORE_I2CM_DATAI			0X157D4
#define HDMI_CORE_I2CM_OPERATION		0x157D8
#define HDMI_CORE_I2CM_INT			0x157DC
#define HDMI_CORE_I2CM_CTLINT			0x157E0
#define HDMI_CORE_I2CM_DIV			0x157E4
#define HDMI_CORE_I2CM_SEGADDR			0x157E8
#define HDMI_CORE_I2CM_SOFTRSTZ			0x157EC
#define HDMI_CORE_I2CM_SEGPTR			0x157F0
#define HDMI_CORE_I2CM_SS_SCL_HCNT_1_ADDR	0x157F4
#define HDMI_CORE_I2CM_SS_SCL_HCNT_0_ADDR	0x157F8
#define HDMI_CORE_I2CM_SS_SCL_LCNT_1_ADDR	0x157FC
#define HDMI_CORE_I2CM_SS_SCL_LCNT_0_ADDR	0x15800
#define HDMI_CORE_I2CM_FS_SCL_HCNT_1_ADDR	0x15804
#define HDMI_CORE_I2CM_FS_SCL_HCNT_0_ADDR	0x15808
#define HDMI_CORE_I2CM_FS_SCL_LCNT_1_ADDR	0x1580C
#define HDMI_CORE_I2CM_FS_SCL_LCNT_0_ADDR	0x15810
#define HDMI_CORE_I2CM_SDA_HOLD_ADDR		0x15814

enum hdmi_core_packet_mode {
	HDMI_PACKETMODERESERVEDVALUE = 0,
	HDMI_PACKETMODE24BITPERPIXEL = 4,
	HDMI_PACKETMODE30BITPERPIXEL = 5,
	HDMI_PACKETMODE36BITPERPIXEL = 6,
	HDMI_PACKETMODE48BITPERPIXEL = 7,
};

struct hdmi_core_vid_config {
	struct hdmi_config v_fc_config;
	enum hdmi_core_packet_mode packet_mode;
	int data_enable_pol;
	int vblank_osc;
	int hblank;
	int vblank;
};

struct csc_table {
	u16 a1, a2, a3, a4;
	u16 b1, b2, b3, b4;
	u16 c1, c2, c3, c4;
};

int hdmi5_read_edid(struct hdmi_core_data *core, u8 *edid, int len);
void hdmi5_core_dump(struct hdmi_core_data *core, struct seq_file *s);
int hdmi5_core_handle_irqs(struct hdmi_core_data *core);
void hdmi5_configure(struct hdmi_core_data *core, struct hdmi_wp_data *wp,
			struct hdmi_config *cfg);
int hdmi5_core_init(struct platform_device *pdev, struct hdmi_core_data *core);

int hdmi5_audio_config(struct hdmi_core_data *core, struct hdmi_wp_data *wp,
			struct omap_dss_audio *audio, u32 pclk);
#endif
