/*
 * Copyright 2019 Advanced Micro Devices, Inc.
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

#ifndef __JPEG_V2_0_H__
#define __JPEG_V2_0_H__

void jpeg_v2_0_dec_ring_insert_start(struct amdgpu_ring *ring);
void jpeg_v2_0_dec_ring_insert_end(struct amdgpu_ring *ring);
void jpeg_v2_0_dec_ring_emit_fence(struct amdgpu_ring *ring, u64 addr, u64 seq,
				unsigned flags);
void jpeg_v2_0_dec_ring_emit_ib(struct amdgpu_ring *ring, struct amdgpu_job *job,
				struct amdgpu_ib *ib, uint32_t flags);
void jpeg_v2_0_dec_ring_emit_reg_wait(struct amdgpu_ring *ring, uint32_t reg,
				uint32_t val, uint32_t mask);
void jpeg_v2_0_dec_ring_emit_vm_flush(struct amdgpu_ring *ring,
				unsigned vmid, uint64_t pd_addr);
void jpeg_v2_0_dec_ring_emit_wreg(struct amdgpu_ring *ring, uint32_t reg, uint32_t val);
void jpeg_v2_0_dec_ring_nop(struct amdgpu_ring *ring, uint32_t count);

extern const struct amdgpu_ip_block_version jpeg_v2_0_ip_block;

#endif /* __JPEG_V2_0_H__ */
