#ifndef _VC4_HDMI_REGS_H_
#define _VC4_HDMI_REGS_H_

#include "vc4_hdmi.h"

#define VC4_HDMI_PACKET_STRIDE			0x24

enum vc4_hdmi_regs {
	VC4_INVALID = 0,
	VC4_HDMI,
	VC4_HD,
	VC5_CEC,
	VC5_CSC,
	VC5_DVP,
	VC5_PHY,
	VC5_RAM,
	VC5_RM,
};

enum vc4_hdmi_field {
	HDMI_AUDIO_PACKET_CONFIG,
	HDMI_CEC_CNTRL_1,
	HDMI_CEC_CNTRL_2,
	HDMI_CEC_CNTRL_3,
	HDMI_CEC_CNTRL_4,
	HDMI_CEC_CNTRL_5,
	HDMI_CEC_CPU_CLEAR,
	HDMI_CEC_CPU_MASK_CLEAR,
	HDMI_CEC_CPU_MASK_SET,
	HDMI_CEC_CPU_MASK_STATUS,
	HDMI_CEC_CPU_STATUS,
	HDMI_CEC_CPU_SET,

	/*
	 * Transmit data, first byte is low byte of the 32-bit reg.
	 * MSB of each byte transmitted first.
	 */
	HDMI_CEC_RX_DATA_1,
	HDMI_CEC_RX_DATA_2,
	HDMI_CEC_RX_DATA_3,
	HDMI_CEC_RX_DATA_4,
	HDMI_CEC_TX_DATA_1,
	HDMI_CEC_TX_DATA_2,
	HDMI_CEC_TX_DATA_3,
	HDMI_CEC_TX_DATA_4,
	HDMI_CLOCK_STOP,
	HDMI_CORE_REV,
	HDMI_CRP_CFG,
	HDMI_CSC_12_11,
	HDMI_CSC_14_13,
	HDMI_CSC_22_21,
	HDMI_CSC_24_23,
	HDMI_CSC_32_31,
	HDMI_CSC_34_33,
	HDMI_CSC_CTL,

	/*
	 * 20-bit fields containing CTS values to be transmitted if
	 * !EXTERNAL_CTS_EN
	 */
	HDMI_CTS_0,
	HDMI_CTS_1,
	HDMI_DEEP_COLOR_CONFIG_1,
	HDMI_DVP_CTL,
	HDMI_FIFO_CTL,
	HDMI_FRAME_COUNT,
	HDMI_GCP_CONFIG,
	HDMI_GCP_WORD_1,
	HDMI_HORZA,
	HDMI_HORZB,
	HDMI_HOTPLUG,
	HDMI_HOTPLUG_INT,

	/*
	 * 3 bits per field, where each field maps from that
	 * corresponding MAI bus channel to the given HDMI channel.
	 */
	HDMI_MAI_CHANNEL_MAP,
	HDMI_MAI_CONFIG,
	HDMI_MAI_CTL,

	/*
	 * Register for DMAing in audio data to be transported over
	 * the MAI bus to the Falcon core.
	 */
	HDMI_MAI_DATA,

	/* Format header to be placed on the MAI data. Unused. */
	HDMI_MAI_FMT,

	/* Last received format word on the MAI bus. */
	HDMI_MAI_FORMAT,
	HDMI_MAI_SMP,
	HDMI_MAI_THR,
	HDMI_M_CTL,
	HDMI_RAM_PACKET_CONFIG,
	HDMI_RAM_PACKET_START,
	HDMI_RAM_PACKET_STATUS,
	HDMI_RM_CONTROL,
	HDMI_RM_FORMAT,
	HDMI_RM_OFFSET,
	HDMI_SCHEDULER_CONTROL,
	HDMI_SCRAMBLER_CTL,
	HDMI_SW_RESET_CONTROL,
	HDMI_TX_PHY_CHANNEL_SWAP,
	HDMI_TX_PHY_CLK_DIV,
	HDMI_TX_PHY_CTL_0,
	HDMI_TX_PHY_CTL_1,
	HDMI_TX_PHY_CTL_2,
	HDMI_TX_PHY_CTL_3,
	HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_1,
	HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_2,
	HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_4,
	HDMI_TX_PHY_PLL_CFG,
	HDMI_TX_PHY_PLL_CTL_0,
	HDMI_TX_PHY_PLL_CTL_1,
	HDMI_TX_PHY_POWERDOWN_CTL,
	HDMI_TX_PHY_RESET_CTL,
	HDMI_TX_PHY_TMDS_CLK_WORD_SEL,
	HDMI_VEC_INTERFACE_XBAR,
	HDMI_VERTA0,
	HDMI_VERTA1,
	HDMI_VERTB0,
	HDMI_VERTB1,
	HDMI_VID_CTL,
};

struct vc4_hdmi_register {
	char *name;
	enum vc4_hdmi_regs reg;
	unsigned int offset;
};

#define _VC4_REG(_base, _reg, _offset)	\
	[_reg] = {				\
		.name = #_reg,			\
		.reg = _base,			\
		.offset = _offset,		\
	}

#define VC4_HD_REG(reg, offset)		_VC4_REG(VC4_HD, reg, offset)
#define VC4_HDMI_REG(reg, offset)	_VC4_REG(VC4_HDMI, reg, offset)
#define VC5_CEC_REG(reg, offset)	_VC4_REG(VC5_CEC, reg, offset)
#define VC5_CSC_REG(reg, offset)	_VC4_REG(VC5_CSC, reg, offset)
#define VC5_DVP_REG(reg, offset)	_VC4_REG(VC5_DVP, reg, offset)
#define VC5_PHY_REG(reg, offset)	_VC4_REG(VC5_PHY, reg, offset)
#define VC5_RAM_REG(reg, offset)	_VC4_REG(VC5_RAM, reg, offset)
#define VC5_RM_REG(reg, offset)		_VC4_REG(VC5_RM, reg, offset)

static const struct vc4_hdmi_register __maybe_unused vc4_hdmi_fields[] = {
	VC4_HD_REG(HDMI_M_CTL, 0x000c),
	VC4_HD_REG(HDMI_MAI_CTL, 0x0014),
	VC4_HD_REG(HDMI_MAI_THR, 0x0018),
	VC4_HD_REG(HDMI_MAI_FMT, 0x001c),
	VC4_HD_REG(HDMI_MAI_DATA, 0x0020),
	VC4_HD_REG(HDMI_MAI_SMP, 0x002c),
	VC4_HD_REG(HDMI_VID_CTL, 0x0038),
	VC4_HD_REG(HDMI_CSC_CTL, 0x0040),
	VC4_HD_REG(HDMI_CSC_12_11, 0x0044),
	VC4_HD_REG(HDMI_CSC_14_13, 0x0048),
	VC4_HD_REG(HDMI_CSC_22_21, 0x004c),
	VC4_HD_REG(HDMI_CSC_24_23, 0x0050),
	VC4_HD_REG(HDMI_CSC_32_31, 0x0054),
	VC4_HD_REG(HDMI_CSC_34_33, 0x0058),
	VC4_HD_REG(HDMI_FRAME_COUNT, 0x0068),

	VC4_HDMI_REG(HDMI_CORE_REV, 0x0000),
	VC4_HDMI_REG(HDMI_SW_RESET_CONTROL, 0x0004),
	VC4_HDMI_REG(HDMI_HOTPLUG_INT, 0x0008),
	VC4_HDMI_REG(HDMI_HOTPLUG, 0x000c),
	VC4_HDMI_REG(HDMI_FIFO_CTL, 0x005c),
	VC4_HDMI_REG(HDMI_MAI_CHANNEL_MAP, 0x0090),
	VC4_HDMI_REG(HDMI_MAI_CONFIG, 0x0094),
	VC4_HDMI_REG(HDMI_MAI_FORMAT, 0x0098),
	VC4_HDMI_REG(HDMI_AUDIO_PACKET_CONFIG, 0x009c),
	VC4_HDMI_REG(HDMI_RAM_PACKET_CONFIG, 0x00a0),
	VC4_HDMI_REG(HDMI_RAM_PACKET_STATUS, 0x00a4),
	VC4_HDMI_REG(HDMI_CRP_CFG, 0x00a8),
	VC4_HDMI_REG(HDMI_CTS_0, 0x00ac),
	VC4_HDMI_REG(HDMI_CTS_1, 0x00b0),
	VC4_HDMI_REG(HDMI_SCHEDULER_CONTROL, 0x00c0),
	VC4_HDMI_REG(HDMI_HORZA, 0x00c4),
	VC4_HDMI_REG(HDMI_HORZB, 0x00c8),
	VC4_HDMI_REG(HDMI_VERTA0, 0x00cc),
	VC4_HDMI_REG(HDMI_VERTB0, 0x00d0),
	VC4_HDMI_REG(HDMI_VERTA1, 0x00d4),
	VC4_HDMI_REG(HDMI_VERTB1, 0x00d8),
	VC4_HDMI_REG(HDMI_CEC_CNTRL_1, 0x00e8),
	VC4_HDMI_REG(HDMI_CEC_CNTRL_2, 0x00ec),
	VC4_HDMI_REG(HDMI_CEC_CNTRL_3, 0x00f0),
	VC4_HDMI_REG(HDMI_CEC_CNTRL_4, 0x00f4),
	VC4_HDMI_REG(HDMI_CEC_CNTRL_5, 0x00f8),
	VC4_HDMI_REG(HDMI_CEC_TX_DATA_1, 0x00fc),
	VC4_HDMI_REG(HDMI_CEC_TX_DATA_2, 0x0100),
	VC4_HDMI_REG(HDMI_CEC_TX_DATA_3, 0x0104),
	VC4_HDMI_REG(HDMI_CEC_TX_DATA_4, 0x0108),
	VC4_HDMI_REG(HDMI_CEC_RX_DATA_1, 0x010c),
	VC4_HDMI_REG(HDMI_CEC_RX_DATA_2, 0x0110),
	VC4_HDMI_REG(HDMI_CEC_RX_DATA_3, 0x0114),
	VC4_HDMI_REG(HDMI_CEC_RX_DATA_4, 0x0118),
	VC4_HDMI_REG(HDMI_TX_PHY_RESET_CTL, 0x02c0),
	VC4_HDMI_REG(HDMI_TX_PHY_CTL_0, 0x02c4),
	VC4_HDMI_REG(HDMI_CEC_CPU_STATUS, 0x0340),
	VC4_HDMI_REG(HDMI_CEC_CPU_SET, 0x0344),
	VC4_HDMI_REG(HDMI_CEC_CPU_CLEAR, 0x0348),
	VC4_HDMI_REG(HDMI_CEC_CPU_MASK_STATUS, 0x034c),
	VC4_HDMI_REG(HDMI_CEC_CPU_MASK_SET, 0x0350),
	VC4_HDMI_REG(HDMI_CEC_CPU_MASK_CLEAR, 0x0354),
	VC4_HDMI_REG(HDMI_RAM_PACKET_START, 0x0400),
};

static const struct vc4_hdmi_register __maybe_unused vc5_hdmi_hdmi0_fields[] = {
	VC4_HD_REG(HDMI_DVP_CTL, 0x0000),
	VC4_HD_REG(HDMI_MAI_CTL, 0x0010),
	VC4_HD_REG(HDMI_MAI_THR, 0x0014),
	VC4_HD_REG(HDMI_MAI_FMT, 0x0018),
	VC4_HD_REG(HDMI_MAI_DATA, 0x001c),
	VC4_HD_REG(HDMI_MAI_SMP, 0x0020),
	VC4_HD_REG(HDMI_VID_CTL, 0x0044),
	VC4_HD_REG(HDMI_FRAME_COUNT, 0x0060),

	VC4_HDMI_REG(HDMI_FIFO_CTL, 0x074),
	VC4_HDMI_REG(HDMI_AUDIO_PACKET_CONFIG, 0x0b8),
	VC4_HDMI_REG(HDMI_RAM_PACKET_CONFIG, 0x0bc),
	VC4_HDMI_REG(HDMI_RAM_PACKET_STATUS, 0x0c4),
	VC4_HDMI_REG(HDMI_CRP_CFG, 0x0c8),
	VC4_HDMI_REG(HDMI_CTS_0, 0x0cc),
	VC4_HDMI_REG(HDMI_CTS_1, 0x0d0),
	VC4_HDMI_REG(HDMI_SCHEDULER_CONTROL, 0x0e0),
	VC4_HDMI_REG(HDMI_HORZA, 0x0e4),
	VC4_HDMI_REG(HDMI_HORZB, 0x0e8),
	VC4_HDMI_REG(HDMI_VERTA0, 0x0ec),
	VC4_HDMI_REG(HDMI_VERTB0, 0x0f0),
	VC4_HDMI_REG(HDMI_VERTA1, 0x0f4),
	VC4_HDMI_REG(HDMI_VERTB1, 0x0f8),
	VC4_HDMI_REG(HDMI_MAI_CHANNEL_MAP, 0x09c),
	VC4_HDMI_REG(HDMI_MAI_CONFIG, 0x0a0),
	VC4_HDMI_REG(HDMI_DEEP_COLOR_CONFIG_1, 0x170),
	VC4_HDMI_REG(HDMI_GCP_CONFIG, 0x178),
	VC4_HDMI_REG(HDMI_GCP_WORD_1, 0x17c),
	VC4_HDMI_REG(HDMI_HOTPLUG, 0x1a8),
	VC4_HDMI_REG(HDMI_SCRAMBLER_CTL, 0x1c4),

	VC5_DVP_REG(HDMI_CLOCK_STOP, 0x0bc),
	VC5_DVP_REG(HDMI_VEC_INTERFACE_XBAR, 0x0f0),

	VC5_PHY_REG(HDMI_TX_PHY_RESET_CTL, 0x000),
	VC5_PHY_REG(HDMI_TX_PHY_POWERDOWN_CTL, 0x004),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_0, 0x008),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_1, 0x00c),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_2, 0x010),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_3, 0x014),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CTL_0, 0x01c),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CTL_1, 0x020),
	VC5_PHY_REG(HDMI_TX_PHY_CLK_DIV, 0x028),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CFG, 0x034),
	VC5_PHY_REG(HDMI_TX_PHY_TMDS_CLK_WORD_SEL, 0x044),
	VC5_PHY_REG(HDMI_TX_PHY_CHANNEL_SWAP, 0x04c),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_1, 0x050),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_2, 0x054),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_4, 0x05c),

	VC5_RM_REG(HDMI_RM_CONTROL, 0x000),
	VC5_RM_REG(HDMI_RM_OFFSET, 0x018),
	VC5_RM_REG(HDMI_RM_FORMAT, 0x01c),

	VC5_RAM_REG(HDMI_RAM_PACKET_START, 0x000),

	VC5_CEC_REG(HDMI_CEC_CNTRL_1, 0x010),
	VC5_CEC_REG(HDMI_CEC_CNTRL_2, 0x014),
	VC5_CEC_REG(HDMI_CEC_CNTRL_3, 0x018),
	VC5_CEC_REG(HDMI_CEC_CNTRL_4, 0x01c),
	VC5_CEC_REG(HDMI_CEC_CNTRL_5, 0x020),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_1, 0x028),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_2, 0x02c),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_3, 0x030),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_4, 0x034),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_1, 0x038),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_2, 0x03c),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_3, 0x040),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_4, 0x044),

	VC5_CSC_REG(HDMI_CSC_CTL, 0x000),
	VC5_CSC_REG(HDMI_CSC_12_11, 0x004),
	VC5_CSC_REG(HDMI_CSC_14_13, 0x008),
	VC5_CSC_REG(HDMI_CSC_22_21, 0x00c),
	VC5_CSC_REG(HDMI_CSC_24_23, 0x010),
	VC5_CSC_REG(HDMI_CSC_32_31, 0x014),
	VC5_CSC_REG(HDMI_CSC_34_33, 0x018),
};

static const struct vc4_hdmi_register __maybe_unused vc5_hdmi_hdmi1_fields[] = {
	VC4_HD_REG(HDMI_DVP_CTL, 0x0000),
	VC4_HD_REG(HDMI_MAI_CTL, 0x0030),
	VC4_HD_REG(HDMI_MAI_THR, 0x0034),
	VC4_HD_REG(HDMI_MAI_FMT, 0x0038),
	VC4_HD_REG(HDMI_MAI_DATA, 0x003c),
	VC4_HD_REG(HDMI_MAI_SMP, 0x0040),
	VC4_HD_REG(HDMI_VID_CTL, 0x0048),
	VC4_HD_REG(HDMI_FRAME_COUNT, 0x0064),

	VC4_HDMI_REG(HDMI_FIFO_CTL, 0x074),
	VC4_HDMI_REG(HDMI_AUDIO_PACKET_CONFIG, 0x0b8),
	VC4_HDMI_REG(HDMI_RAM_PACKET_CONFIG, 0x0bc),
	VC4_HDMI_REG(HDMI_RAM_PACKET_STATUS, 0x0c4),
	VC4_HDMI_REG(HDMI_CRP_CFG, 0x0c8),
	VC4_HDMI_REG(HDMI_CTS_0, 0x0cc),
	VC4_HDMI_REG(HDMI_CTS_1, 0x0d0),
	VC4_HDMI_REG(HDMI_SCHEDULER_CONTROL, 0x0e0),
	VC4_HDMI_REG(HDMI_HORZA, 0x0e4),
	VC4_HDMI_REG(HDMI_HORZB, 0x0e8),
	VC4_HDMI_REG(HDMI_VERTA0, 0x0ec),
	VC4_HDMI_REG(HDMI_VERTB0, 0x0f0),
	VC4_HDMI_REG(HDMI_VERTA1, 0x0f4),
	VC4_HDMI_REG(HDMI_VERTB1, 0x0f8),
	VC4_HDMI_REG(HDMI_MAI_CHANNEL_MAP, 0x09c),
	VC4_HDMI_REG(HDMI_MAI_CONFIG, 0x0a0),
	VC4_HDMI_REG(HDMI_DEEP_COLOR_CONFIG_1, 0x170),
	VC4_HDMI_REG(HDMI_GCP_CONFIG, 0x178),
	VC4_HDMI_REG(HDMI_GCP_WORD_1, 0x17c),
	VC4_HDMI_REG(HDMI_HOTPLUG, 0x1a8),
	VC4_HDMI_REG(HDMI_SCRAMBLER_CTL, 0x1c4),

	VC5_DVP_REG(HDMI_CLOCK_STOP, 0x0bc),
	VC5_DVP_REG(HDMI_VEC_INTERFACE_XBAR, 0x0f0),

	VC5_PHY_REG(HDMI_TX_PHY_RESET_CTL, 0x000),
	VC5_PHY_REG(HDMI_TX_PHY_POWERDOWN_CTL, 0x004),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_0, 0x008),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_1, 0x00c),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_2, 0x010),
	VC5_PHY_REG(HDMI_TX_PHY_CTL_3, 0x014),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CTL_0, 0x01c),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CTL_1, 0x020),
	VC5_PHY_REG(HDMI_TX_PHY_CLK_DIV, 0x028),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CFG, 0x034),
	VC5_PHY_REG(HDMI_TX_PHY_CHANNEL_SWAP, 0x04c),
	VC5_PHY_REG(HDMI_TX_PHY_TMDS_CLK_WORD_SEL, 0x044),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_1, 0x050),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_2, 0x054),
	VC5_PHY_REG(HDMI_TX_PHY_PLL_CALIBRATION_CONFIG_4, 0x05c),

	VC5_RM_REG(HDMI_RM_CONTROL, 0x000),
	VC5_RM_REG(HDMI_RM_OFFSET, 0x018),
	VC5_RM_REG(HDMI_RM_FORMAT, 0x01c),

	VC5_RAM_REG(HDMI_RAM_PACKET_START, 0x000),

	VC5_CEC_REG(HDMI_CEC_CNTRL_1, 0x010),
	VC5_CEC_REG(HDMI_CEC_CNTRL_2, 0x014),
	VC5_CEC_REG(HDMI_CEC_CNTRL_3, 0x018),
	VC5_CEC_REG(HDMI_CEC_CNTRL_4, 0x01c),
	VC5_CEC_REG(HDMI_CEC_CNTRL_5, 0x020),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_1, 0x028),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_2, 0x02c),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_3, 0x030),
	VC5_CEC_REG(HDMI_CEC_TX_DATA_4, 0x034),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_1, 0x038),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_2, 0x03c),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_3, 0x040),
	VC5_CEC_REG(HDMI_CEC_RX_DATA_4, 0x044),

	VC5_CSC_REG(HDMI_CSC_CTL, 0x000),
	VC5_CSC_REG(HDMI_CSC_12_11, 0x004),
	VC5_CSC_REG(HDMI_CSC_14_13, 0x008),
	VC5_CSC_REG(HDMI_CSC_22_21, 0x00c),
	VC5_CSC_REG(HDMI_CSC_24_23, 0x010),
	VC5_CSC_REG(HDMI_CSC_32_31, 0x014),
	VC5_CSC_REG(HDMI_CSC_34_33, 0x018),
};

static inline
void __iomem *__vc4_hdmi_get_field_base(struct vc4_hdmi *hdmi,
					enum vc4_hdmi_regs reg)
{
	switch (reg) {
	case VC4_HD:
		return hdmi->hd_regs;

	case VC4_HDMI:
		return hdmi->hdmicore_regs;

	case VC5_CSC:
		return hdmi->csc_regs;

	case VC5_CEC:
		return hdmi->cec_regs;

	case VC5_DVP:
		return hdmi->dvp_regs;

	case VC5_PHY:
		return hdmi->phy_regs;

	case VC5_RAM:
		return hdmi->ram_regs;

	case VC5_RM:
		return hdmi->rm_regs;

	default:
		return NULL;
	}

	return NULL;
}

static inline u32 vc4_hdmi_read(struct vc4_hdmi *hdmi,
				enum vc4_hdmi_field reg)
{
	const struct vc4_hdmi_register *field;
	const struct vc4_hdmi_variant *variant = hdmi->variant;
	void __iomem *base;

	if (reg >= variant->num_registers) {
		dev_warn(&hdmi->pdev->dev,
			 "Invalid register ID %u\n", reg);
		return 0;
	}

	field = &variant->registers[reg];
	base = __vc4_hdmi_get_field_base(hdmi, field->reg);
	if (!base) {
		dev_warn(&hdmi->pdev->dev,
			 "Unknown register ID %u\n", reg);
		return 0;
	}

	return readl(base + field->offset);
}
#define HDMI_READ(reg)		vc4_hdmi_read(vc4_hdmi, reg)

static inline void vc4_hdmi_write(struct vc4_hdmi *hdmi,
				  enum vc4_hdmi_field reg,
				  u32 value)
{
	const struct vc4_hdmi_register *field;
	const struct vc4_hdmi_variant *variant = hdmi->variant;
	void __iomem *base;

	if (reg >= variant->num_registers) {
		dev_warn(&hdmi->pdev->dev,
			 "Invalid register ID %u\n", reg);
		return;
	}

	field = &variant->registers[reg];
	base = __vc4_hdmi_get_field_base(hdmi, field->reg);
	if (!base)
		return;

	writel(value, base + field->offset);
}
#define HDMI_WRITE(reg, val)	vc4_hdmi_write(vc4_hdmi, reg, val)

#endif /* _VC4_HDMI_REGS_H_ */
