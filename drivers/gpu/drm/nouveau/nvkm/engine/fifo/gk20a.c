/*
 * Copyright (c) 2014, NVIDIA CORPORATION. All rights reserved.
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
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include "priv.h"

#include <nvif/class.h>

static const struct nvkm_fifo_func
gk20a_fifo = {
	.chid_nr = nv50_fifo_chid_nr,
	.chid_ctor = gk110_fifo_chid_ctor,
	.runq_nr = gf100_fifo_runq_nr,
	.runl_ctor = gk104_fifo_runl_ctor,
	.init = gk104_fifo_init,
	.init_pbdmas = gk104_fifo_init_pbdmas,
	.intr = gk104_fifo_intr,
	.intr_mmu_fault_unit = gf100_fifo_intr_mmu_fault_unit,
	.intr_ctxsw_timeout = gf100_fifo_intr_ctxsw_timeout,
	.mmu_fault = &gk104_fifo_mmu_fault,
	.nonstall = &gf100_fifo_nonstall,
	.runl = &gk110_runl,
	.runq = &gk208_runq,
	.engn = &gk104_engn,
	.engn_ce = &gk104_engn_ce,
	.cgrp = {{                               }, &gk110_cgrp },
	.chan = {{ 0, 0, KEPLER_CHANNEL_GPFIFO_A }, &gk110_chan },
};

int
gk20a_fifo_new(struct nvkm_device *device, enum nvkm_subdev_type type, int inst,
	       struct nvkm_fifo **pfifo)
{
	return nvkm_fifo_new_(&gk20a_fifo, device, type, inst, pfifo);
}
