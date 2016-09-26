/*
 * Copyright (C) STMicroelectronics SA 2014
 * Author: Vincent Abriou <vincent.abriou@st.com> for STMicroelectronics.
 * License terms:  GNU General Public License (GPL), version 2
 */

#ifndef _STI_HDMI_H_
#define _STI_HDMI_H_

#include <linux/hdmi.h>
#include <linux/platform_device.h>

#include <drm/drmP.h>

#define HDMI_STA           0x0010
#define HDMI_STA_DLL_LCK   BIT(5)
#define HDMI_STA_HOT_PLUG  BIT(4)

struct sti_hdmi;

struct hdmi_phy_ops {
	bool (*start)(struct sti_hdmi *hdmi);
	void (*stop)(struct sti_hdmi *hdmi);
};

/* values for the framing mode property */
enum sti_hdmi_modes {
	HDMI_MODE_HDMI,
	HDMI_MODE_DVI,
};

static const struct drm_prop_enum_list hdmi_mode_names[] = {
	{ HDMI_MODE_HDMI, "hdmi" },
	{ HDMI_MODE_DVI, "dvi" },
};

#define DEFAULT_HDMI_MODE HDMI_MODE_HDMI

static const struct drm_prop_enum_list colorspace_mode_names[] = {
	{ HDMI_COLORSPACE_RGB, "rgb" },
	{ HDMI_COLORSPACE_YUV422, "yuv422" },
	{ HDMI_COLORSPACE_YUV444, "yuv444" },
};

#define DEFAULT_COLORSPACE_MODE HDMI_COLORSPACE_RGB

/**
 * STI hdmi structure
 *
 * @dev: driver device
 * @drm_dev: pointer to drm device
 * @mode: current display mode selected
 * @regs: hdmi register
 * @syscfg: syscfg register for pll rejection configuration
 * @clk_pix: hdmi pixel clock
 * @clk_tmds: hdmi tmds clock
 * @clk_phy: hdmi phy clock
 * @clk_audio: hdmi audio clock
 * @irq: hdmi interrupt number
 * @irq_status: interrupt status register
 * @phy_ops: phy start/stop operations
 * @enabled: true if hdmi is enabled else false
 * @hpd: hot plug detect status
 * @wait_event: wait event
 * @event_received: wait event status
 * @reset: reset control of the hdmi phy
 * @ddc_adapt: i2c ddc adapter
 * @colorspace: current colorspace selected
 * @hdmi_mode: select framing for HDMI or DVI
 */
struct sti_hdmi {
	struct device dev;
	struct drm_device *drm_dev;
	struct drm_display_mode mode;
	void __iomem *regs;
	void __iomem *syscfg;
	struct clk *clk_pix;
	struct clk *clk_tmds;
	struct clk *clk_phy;
	struct clk *clk_audio;
	int irq;
	u32 irq_status;
	struct hdmi_phy_ops *phy_ops;
	bool enabled;
	bool hpd;
	wait_queue_head_t wait_event;
	bool event_received;
	struct reset_control *reset;
	struct i2c_adapter *ddc_adapt;
	enum hdmi_colorspace colorspace;
	enum sti_hdmi_modes hdmi_mode;
};

u32 hdmi_read(struct sti_hdmi *hdmi, int offset);
void hdmi_write(struct sti_hdmi *hdmi, u32 val, int offset);

/**
 * hdmi phy config structure
 *
 * A pointer to an array of these structures is passed to a TMDS (HDMI) output
 * via the control interface to provide board and SoC specific
 * configurations of the HDMI PHY. Each entry in the array specifies a hardware
 * specific configuration for a given TMDS clock frequency range.
 *
 * @min_tmds_freq: Lower bound of TMDS clock frequency this entry applies to
 * @max_tmds_freq: Upper bound of TMDS clock frequency this entry applies to
 * @config: SoC specific register configuration
 */
struct hdmi_phy_config {
	u32 min_tmds_freq;
	u32 max_tmds_freq;
	u32 config[4];
};

#endif
