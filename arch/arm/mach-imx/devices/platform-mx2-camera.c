// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2010 Pengutronix
 * Uwe Kleine-Koenig <u.kleine-koenig@pengutronix.de>
 */
#include "../hardware.h"
#include "devices-common.h"

#define imx_mx2_camera_data_entry_single(soc, _devid)			\
	{								\
		.devid = _devid,					\
		.iobasecsi = soc ## _CSI_BASE_ADDR,			\
		.iosizecsi = SZ_4K,					\
		.irqcsi = soc ## _INT_CSI,				\
	}
#define imx_mx2_camera_data_entry_single_emma(soc, _devid)		\
	{								\
		.devid = _devid,					\
		.iobasecsi = soc ## _CSI_BASE_ADDR,			\
		.iosizecsi = SZ_32,					\
		.irqcsi = soc ## _INT_CSI,				\
		.iobaseemmaprp = soc ## _EMMAPRP_BASE_ADDR,		\
		.iosizeemmaprp = SZ_32,					\
		.irqemmaprp = soc ## _INT_EMMAPRP,			\
	}

#ifdef CONFIG_SOC_IMX27
const struct imx_mx2_camera_data imx27_mx2_camera_data __initconst =
	imx_mx2_camera_data_entry_single_emma(MX27, "imx27-camera");
#endif /* ifdef CONFIG_SOC_IMX27 */

struct platform_device *__init imx_add_mx2_camera(
		const struct imx_mx2_camera_data *data,
		const struct mx2_camera_platform_data *pdata)
{
	struct resource res[] = {
		{
			.start = data->iobasecsi,
			.end = data->iobasecsi + data->iosizecsi - 1,
			.flags = IORESOURCE_MEM,
		}, {
			.start = data->irqcsi,
			.end = data->irqcsi,
			.flags = IORESOURCE_IRQ,
		}, {
			.start = data->iobaseemmaprp,
			.end = data->iobaseemmaprp + data->iosizeemmaprp - 1,
			.flags = IORESOURCE_MEM,
		}, {
			.start = data->irqemmaprp,
			.end = data->irqemmaprp,
			.flags = IORESOURCE_IRQ,
		},
	};
	return imx_add_platform_device_dmamask(data->devid, 0,
			res, data->iobaseemmaprp ? 4 : 2,
			pdata, sizeof(*pdata), DMA_BIT_MASK(32));
}

