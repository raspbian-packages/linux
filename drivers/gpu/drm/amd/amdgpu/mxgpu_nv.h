/*
 * Copyright 2014 Advanced Micro Devices, Inc.
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
 */

#ifndef __MXGPU_NV_H__
#define __MXGPU_NV_H__

#define NV_MAILBOX_POLL_ACK_TIMEDOUT	500
#define NV_MAILBOX_POLL_MSG_TIMEDOUT	12000
#define NV_MAILBOX_POLL_FLR_TIMEDOUT	500

extern const struct amdgpu_virt_ops xgpu_nv_virt_ops;

void xgpu_nv_mailbox_set_irq_funcs(struct amdgpu_device *adev);
int xgpu_nv_mailbox_add_irq_id(struct amdgpu_device *adev);
int xgpu_nv_mailbox_get_irq(struct amdgpu_device *adev);
void xgpu_nv_mailbox_put_irq(struct amdgpu_device *adev);

#define NV_MAIBOX_CONTROL_TRN_OFFSET_BYTE (SOC15_REG_OFFSET(NBIO, 0, mmBIF_BX_PF_MAILBOX_CONTROL) * 4)
#define NV_MAIBOX_CONTROL_RCV_OFFSET_BYTE (SOC15_REG_OFFSET(NBIO, 0, mmBIF_BX_PF_MAILBOX_CONTROL) * 4 + 1)

#endif
