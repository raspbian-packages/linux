/*
 * Copyright 2012 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Ben Skeggs
 */
#include "priv.h"

void
g94_gpio_intr_stat(struct nvkm_gpio *gpio, u32 *hi, u32 *lo)
{
	struct nvkm_device *device = gpio->subdev.device;
	u32 intr0 = nvkm_rd32(device, 0x00e054);
	u32 intr1 = nvkm_rd32(device, 0x00e074);
	u32 stat0 = nvkm_rd32(device, 0x00e050) & intr0;
	u32 stat1 = nvkm_rd32(device, 0x00e070) & intr1;
	*lo = (stat1 & 0xffff0000) | (stat0 >> 16);
	*hi = (stat1 << 16) | (stat0 & 0x0000ffff);
	nvkm_wr32(device, 0x00e054, intr0);
	nvkm_wr32(device, 0x00e074, intr1);
}

void
g94_gpio_intr_mask(struct nvkm_gpio *gpio, u32 type, u32 mask, u32 data)
{
	struct nvkm_device *device = gpio->subdev.device;
	u32 inte0 = nvkm_rd32(device, 0x00e050);
	u32 inte1 = nvkm_rd32(device, 0x00e070);
	if (type & NVKM_GPIO_LO)
		inte0 = (inte0 & ~(mask << 16)) | (data << 16);
	if (type & NVKM_GPIO_HI)
		inte0 = (inte0 & ~(mask & 0xffff)) | (data & 0xffff);
	mask >>= 16;
	data >>= 16;
	if (type & NVKM_GPIO_LO)
		inte1 = (inte1 & ~(mask << 16)) | (data << 16);
	if (type & NVKM_GPIO_HI)
		inte1 = (inte1 & ~mask) | data;
	nvkm_wr32(device, 0x00e050, inte0);
	nvkm_wr32(device, 0x00e070, inte1);
}

static const struct nvkm_gpio_func
g94_gpio = {
	.lines = 32,
	.intr_stat = g94_gpio_intr_stat,
	.intr_mask = g94_gpio_intr_mask,
	.drive = nv50_gpio_drive,
	.sense = nv50_gpio_sense,
	.reset = nv50_gpio_reset,
};

int
g94_gpio_new(struct nvkm_device *device, int index, struct nvkm_gpio **pgpio)
{
	return nvkm_gpio_new_(&g94_gpio, device, index, pgpio);
}
