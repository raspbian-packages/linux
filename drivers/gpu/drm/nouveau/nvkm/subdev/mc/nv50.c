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

static const struct nvkm_intr_data
nv50_mc_intrs[] = {
	{ NVKM_ENGINE_DISP , 0, 0, 0x04000000, true },
	{ NVKM_ENGINE_GR   , 0, 0, 0x00001000, true },
	{ NVKM_ENGINE_FIFO , 0, 0, 0x00000100 },
	{ NVKM_ENGINE_MPEG , 0, 0, 0x00000001, true },
	{ NVKM_SUBDEV_FB   , 0, 0, 0x00001101, true },
	{ NVKM_SUBDEV_BUS  , 0, 0, 0x10000000, true },
	{ NVKM_SUBDEV_GPIO , 0, 0, 0x00200000, true },
	{ NVKM_SUBDEV_I2C  , 0, 0, 0x00200000, true },
	{ NVKM_SUBDEV_TIMER, 0, 0, 0x00100000, true },
	{},
};

void
nv50_mc_init(struct nvkm_mc *mc)
{
	struct nvkm_device *device = mc->subdev.device;
	nvkm_wr32(device, 0x000200, 0xffffffff); /* everything on */
}

static const struct nvkm_mc_func
nv50_mc = {
	.init = nv50_mc_init,
	.intr = &nv04_mc_intr,
	.intrs = nv50_mc_intrs,
	.device = &nv04_mc_device,
	.reset = nv17_mc_reset,
};

int
nv50_mc_new(struct nvkm_device *device, enum nvkm_subdev_type type, int inst, struct nvkm_mc **pmc)
{
	return nvkm_mc_new_(&nv50_mc, device, type, inst, pmc);
}
