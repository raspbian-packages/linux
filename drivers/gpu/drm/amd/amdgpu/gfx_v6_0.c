/*
 * Copyright 2015 Advanced Micro Devices, Inc.
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
#include <linux/firmware.h>
#include "amdgpu.h"
#include "amdgpu_ih.h"
#include "amdgpu_gfx.h"
#include "amdgpu_ucode.h"
#include "clearstate_si.h"
#include "bif/bif_3_0_d.h"
#include "bif/bif_3_0_sh_mask.h"
#include "oss/oss_1_0_d.h"
#include "oss/oss_1_0_sh_mask.h"
#include "gca/gfx_6_0_d.h"
#include "gca/gfx_6_0_sh_mask.h"
#include "gmc/gmc_6_0_d.h"
#include "gmc/gmc_6_0_sh_mask.h"
#include "dce/dce_6_0_d.h"
#include "dce/dce_6_0_sh_mask.h"
#include "gca/gfx_7_2_enum.h"
#include "si_enums.h"

static void gfx_v6_0_set_ring_funcs(struct amdgpu_device *adev);
static void gfx_v6_0_set_irq_funcs(struct amdgpu_device *adev);
static void gfx_v6_0_get_cu_info(struct amdgpu_device *adev);

MODULE_FIRMWARE("radeon/tahiti_pfp.bin");
MODULE_FIRMWARE("radeon/tahiti_me.bin");
MODULE_FIRMWARE("radeon/tahiti_ce.bin");
MODULE_FIRMWARE("radeon/tahiti_rlc.bin");

MODULE_FIRMWARE("radeon/pitcairn_pfp.bin");
MODULE_FIRMWARE("radeon/pitcairn_me.bin");
MODULE_FIRMWARE("radeon/pitcairn_ce.bin");
MODULE_FIRMWARE("radeon/pitcairn_rlc.bin");

MODULE_FIRMWARE("radeon/verde_pfp.bin");
MODULE_FIRMWARE("radeon/verde_me.bin");
MODULE_FIRMWARE("radeon/verde_ce.bin");
MODULE_FIRMWARE("radeon/verde_rlc.bin");

MODULE_FIRMWARE("radeon/oland_pfp.bin");
MODULE_FIRMWARE("radeon/oland_me.bin");
MODULE_FIRMWARE("radeon/oland_ce.bin");
MODULE_FIRMWARE("radeon/oland_rlc.bin");

MODULE_FIRMWARE("radeon/hainan_pfp.bin");
MODULE_FIRMWARE("radeon/hainan_me.bin");
MODULE_FIRMWARE("radeon/hainan_ce.bin");
MODULE_FIRMWARE("radeon/hainan_rlc.bin");

static u32 gfx_v6_0_get_csb_size(struct amdgpu_device *adev);
static void gfx_v6_0_get_csb_buffer(struct amdgpu_device *adev, volatile u32 *buffer);
//static void gfx_v6_0_init_cp_pg_table(struct amdgpu_device *adev);
static void gfx_v6_0_init_pg(struct amdgpu_device *adev);

#define ARRAY_MODE(x)					((x) << GB_TILE_MODE0__ARRAY_MODE__SHIFT)
#define PIPE_CONFIG(x)					((x) << GB_TILE_MODE0__PIPE_CONFIG__SHIFT)
#define TILE_SPLIT(x)					((x) << GB_TILE_MODE0__TILE_SPLIT__SHIFT)
#define MICRO_TILE_MODE(x)				((x) << 0)
#define SAMPLE_SPLIT(x)					((x) << GB_TILE_MODE0__SAMPLE_SPLIT__SHIFT)
#define BANK_WIDTH(x)					((x) << 14)
#define BANK_HEIGHT(x)					((x) << 16)
#define MACRO_TILE_ASPECT(x)				((x) << 18)
#define NUM_BANKS(x)					((x) << 20)

static const u32 verde_rlc_save_restore_register_list[] =
{
	(0x8000 << 16) | (0x98f4 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x98f4 >> 2),
	0x00000000,
	(0x8000 << 16) | (0xe80 >> 2),
	0x00000000,
	(0x8040 << 16) | (0xe80 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x89bc >> 2),
	0x00000000,
	(0x8040 << 16) | (0x89bc >> 2),
	0x00000000,
	(0x8000 << 16) | (0x8c1c >> 2),
	0x00000000,
	(0x8040 << 16) | (0x8c1c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x98f0 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0xe7c >> 2),
	0x00000000,
	(0x8000 << 16) | (0x9148 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x9148 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9150 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x897c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8d8c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0xac54 >> 2),
	0X00000000,
	0x3,
	(0x9c00 << 16) | (0x98f8 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9910 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9914 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9918 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x991c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9920 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9924 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9928 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x992c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9930 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9934 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9938 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x993c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9940 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9944 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9948 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x994c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9950 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9954 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9958 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x995c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9960 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9964 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9968 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x996c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9970 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9974 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9978 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x997c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9980 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9984 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9988 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x998c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8c00 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8c14 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8c04 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8c08 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x9b7c >> 2),
	0x00000000,
	(0x8040 << 16) | (0x9b7c >> 2),
	0x00000000,
	(0x8000 << 16) | (0xe84 >> 2),
	0x00000000,
	(0x8040 << 16) | (0xe84 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x89c0 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x89c0 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x914c >> 2),
	0x00000000,
	(0x8040 << 16) | (0x914c >> 2),
	0x00000000,
	(0x8000 << 16) | (0x8c20 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x8c20 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x9354 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x9354 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9060 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9364 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9100 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x913c >> 2),
	0x00000000,
	(0x8000 << 16) | (0x90e0 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x90e4 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x90e8 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x90e0 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x90e4 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x90e8 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8bcc >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8b24 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x88c4 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8e50 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8c0c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8e58 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8e5c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9508 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x950c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9494 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0xac0c >> 2),
	0x00000000,
	(0x9c00 << 16) | (0xac10 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0xac14 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0xae00 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0xac08 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x88d4 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x88c8 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x88cc >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x89b0 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8b10 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x8a14 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9830 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9834 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9838 >> 2),
	0x00000000,
	(0x9c00 << 16) | (0x9a10 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x9870 >> 2),
	0x00000000,
	(0x8000 << 16) | (0x9874 >> 2),
	0x00000000,
	(0x8001 << 16) | (0x9870 >> 2),
	0x00000000,
	(0x8001 << 16) | (0x9874 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x9870 >> 2),
	0x00000000,
	(0x8040 << 16) | (0x9874 >> 2),
	0x00000000,
	(0x8041 << 16) | (0x9870 >> 2),
	0x00000000,
	(0x8041 << 16) | (0x9874 >> 2),
	0x00000000,
	0x00000000
};

static int gfx_v6_0_init_microcode(struct amdgpu_device *adev)
{
	const char *chip_name;
	char fw_name[30];
	int err;
	const struct gfx_firmware_header_v1_0 *cp_hdr;
	const struct rlc_firmware_header_v1_0 *rlc_hdr;

	DRM_DEBUG("\n");

	switch (adev->asic_type) {
	case CHIP_TAHITI:
		chip_name = "tahiti";
		break;
	case CHIP_PITCAIRN:
		chip_name = "pitcairn";
		break;
	case CHIP_VERDE:
		chip_name = "verde";
		break;
	case CHIP_OLAND:
		chip_name = "oland";
		break;
	case CHIP_HAINAN:
		chip_name = "hainan";
		break;
	default: BUG();
	}

	snprintf(fw_name, sizeof(fw_name), "radeon/%s_pfp.bin", chip_name);
	err = request_firmware(&adev->gfx.pfp_fw, fw_name, adev->dev);
	if (err)
		goto out;
	err = amdgpu_ucode_validate(adev->gfx.pfp_fw);
	if (err)
		goto out;
	cp_hdr = (const struct gfx_firmware_header_v1_0 *)adev->gfx.pfp_fw->data;
	adev->gfx.pfp_fw_version = le32_to_cpu(cp_hdr->header.ucode_version);
	adev->gfx.pfp_feature_version = le32_to_cpu(cp_hdr->ucode_feature_version);

	snprintf(fw_name, sizeof(fw_name), "radeon/%s_me.bin", chip_name);
	err = request_firmware(&adev->gfx.me_fw, fw_name, adev->dev);
	if (err)
		goto out;
	err = amdgpu_ucode_validate(adev->gfx.me_fw);
	if (err)
		goto out;
	cp_hdr = (const struct gfx_firmware_header_v1_0 *)adev->gfx.me_fw->data;
	adev->gfx.me_fw_version = le32_to_cpu(cp_hdr->header.ucode_version);
	adev->gfx.me_feature_version = le32_to_cpu(cp_hdr->ucode_feature_version);

	snprintf(fw_name, sizeof(fw_name), "radeon/%s_ce.bin", chip_name);
	err = request_firmware(&adev->gfx.ce_fw, fw_name, adev->dev);
	if (err)
		goto out;
	err = amdgpu_ucode_validate(adev->gfx.ce_fw);
	if (err)
		goto out;
	cp_hdr = (const struct gfx_firmware_header_v1_0 *)adev->gfx.ce_fw->data;
	adev->gfx.ce_fw_version = le32_to_cpu(cp_hdr->header.ucode_version);
	adev->gfx.ce_feature_version = le32_to_cpu(cp_hdr->ucode_feature_version);

	snprintf(fw_name, sizeof(fw_name), "radeon/%s_rlc.bin", chip_name);
	err = request_firmware(&adev->gfx.rlc_fw, fw_name, adev->dev);
	if (err)
		goto out;
	err = amdgpu_ucode_validate(adev->gfx.rlc_fw);
	rlc_hdr = (const struct rlc_firmware_header_v1_0 *)adev->gfx.rlc_fw->data;
	adev->gfx.rlc_fw_version = le32_to_cpu(rlc_hdr->header.ucode_version);
	adev->gfx.rlc_feature_version = le32_to_cpu(rlc_hdr->ucode_feature_version);

out:
	if (err) {
		printk(KERN_ERR
		       "gfx6: Failed to load firmware \"%s\"\n",
		       fw_name);
		release_firmware(adev->gfx.pfp_fw);
		adev->gfx.pfp_fw = NULL;
		release_firmware(adev->gfx.me_fw);
		adev->gfx.me_fw = NULL;
		release_firmware(adev->gfx.ce_fw);
		adev->gfx.ce_fw = NULL;
		release_firmware(adev->gfx.rlc_fw);
		adev->gfx.rlc_fw = NULL;
	}
	return err;
}

static void gfx_v6_0_tiling_mode_table_init(struct amdgpu_device *adev)
{
	const u32 num_tile_mode_states = 32;
	u32 reg_offset, gb_tile_moden, split_equal_to_row_size;

	switch (adev->gfx.config.mem_row_size_in_kb) {
	case 1:
		split_equal_to_row_size = ADDR_SURF_TILE_SPLIT_1KB;
		break;
	case 2:
	default:
		split_equal_to_row_size = ADDR_SURF_TILE_SPLIT_2KB;
		break;
	case 4:
		split_equal_to_row_size = ADDR_SURF_TILE_SPLIT_4KB;
		break;
	}

	if (adev->asic_type == CHIP_VERDE) {
		for (reg_offset = 0; reg_offset < num_tile_mode_states; reg_offset++) {
			switch (reg_offset) {
			case 0:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_64B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 1:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_128B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 2:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 3:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 4:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16));
				break;
			case 5:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 6:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 7:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 8:
				gb_tile_moden = (ARRAY_MODE(ARRAY_LINEAR_ALIGNED));
				break;
			case 9:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16));
				break;
			case 10:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 11:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 12:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 13:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16));
				break;
			case 14:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 15:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 16:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 17:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 18:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THICK) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16));
				break;
			case 19:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_XTHICK) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 20:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THICK) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 21:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 22:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 23:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 24:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 25:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 26:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 27:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 28:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 29:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 30:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_2KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			default:
				continue;
			}
			adev->gfx.config.tile_mode_array[reg_offset] = gb_tile_moden;
			WREG32(mmGB_TILE_MODE0 + reg_offset, gb_tile_moden);
		}
	} else if (adev->asic_type == CHIP_OLAND ||
	    adev->asic_type == CHIP_HAINAN) {
		for (reg_offset = 0; reg_offset < num_tile_mode_states; reg_offset++) {
			switch (reg_offset) {
			case 0:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_64B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 1:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_128B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 2:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 3:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 4:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2));
				break;
			case 5:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 6:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 7:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 8:
				gb_tile_moden = (ARRAY_MODE(ARRAY_LINEAR_ALIGNED));
				break;
			case 9:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2));
				break;
			case 10:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_4) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 11:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 12:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 13:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2));
				break;
			case 14:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 15:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 16:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 17:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 18:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THICK) |
						 PIPE_CONFIG(ADDR_SURF_P2));
				break;
			case 19:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_XTHICK) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 20:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THICK) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 21:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_2) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 22:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_2) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 23:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 24:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_8_BANK));
				break;
			case 25:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 26:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 27:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 28:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 29:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 30:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P2) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_2KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			default:
				continue;
			}
			adev->gfx.config.tile_mode_array[reg_offset] = gb_tile_moden;
			WREG32(mmGB_TILE_MODE0 + reg_offset, gb_tile_moden);
		}
	} else if ((adev->asic_type == CHIP_TAHITI) || (adev->asic_type == CHIP_PITCAIRN)) {
		for (reg_offset = 0; reg_offset < num_tile_mode_states; reg_offset++) {
			switch (reg_offset) {
			case 0:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_64B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 1:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_128B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 2:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 3:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 4:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16));
				break;
			case 5:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 6:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_8) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 7:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DEPTH_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 8:
				gb_tile_moden = (ARRAY_MODE(ARRAY_LINEAR_ALIGNED));
				break;
			case 9:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16));
				break;
			case 10:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 11:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_2) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 12:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_DISPLAY_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 13:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16));
				break;
			case 14:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 15:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 16:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_16_BANK));
				break;
			case 17:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 18:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_1D_TILED_THICK) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16));
				break;
			case 19:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_XTHICK) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 20:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THICK) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_1) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_16_BANK) |
						 TILE_SPLIT(split_equal_to_row_size));
				break;
			case 21:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_8) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 22:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_4_BANK));
				break;
			case 23:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_256B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_8) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 24:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P8_32x32_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_512B) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 25:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 26:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 27:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 28:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 29:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_1KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_4) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			case 30:
				gb_tile_moden = (MICRO_TILE_MODE(ADDR_SURF_THIN_MICRO_TILING) |
						 ARRAY_MODE(ARRAY_2D_TILED_THIN1) |
						 PIPE_CONFIG(ADDR_SURF_P4_8x16) |
						 TILE_SPLIT(ADDR_SURF_TILE_SPLIT_2KB) |
						 BANK_WIDTH(ADDR_SURF_BANK_WIDTH_1) |
						 BANK_HEIGHT(ADDR_SURF_BANK_HEIGHT_2) |
						 MACRO_TILE_ASPECT(ADDR_SURF_MACRO_ASPECT_1) |
						 NUM_BANKS(ADDR_SURF_2_BANK));
				break;
			default:
				continue;
			}
			adev->gfx.config.tile_mode_array[reg_offset] = gb_tile_moden;
			WREG32(mmGB_TILE_MODE0 + reg_offset, gb_tile_moden);
		}
	} else{

		DRM_ERROR("unknown asic: 0x%x\n", adev->asic_type);
	}

}

static void gfx_v6_0_select_se_sh(struct amdgpu_device *adev, u32 se_num,
				  u32 sh_num, u32 instance)
{
	u32 data;

	if (instance == 0xffffffff)
		data = REG_SET_FIELD(0, GRBM_GFX_INDEX, INSTANCE_BROADCAST_WRITES, 1);
	else
		data = REG_SET_FIELD(0, GRBM_GFX_INDEX, INSTANCE_INDEX, instance);

	if ((se_num == 0xffffffff) && (sh_num == 0xffffffff))
		data |= GRBM_GFX_INDEX__SH_BROADCAST_WRITES_MASK |
			GRBM_GFX_INDEX__SE_BROADCAST_WRITES_MASK;
	else if (se_num == 0xffffffff)
		data |= GRBM_GFX_INDEX__SE_BROADCAST_WRITES_MASK |
			(sh_num << GRBM_GFX_INDEX__SH_INDEX__SHIFT);
	else if (sh_num == 0xffffffff)
		data |= GRBM_GFX_INDEX__SH_BROADCAST_WRITES_MASK |
			(se_num << GRBM_GFX_INDEX__SE_INDEX__SHIFT);
	else
		data |= (sh_num << GRBM_GFX_INDEX__SH_INDEX__SHIFT) |
			(se_num << GRBM_GFX_INDEX__SE_INDEX__SHIFT);
	WREG32(mmGRBM_GFX_INDEX, data);
}

static u32 gfx_v6_0_create_bitmask(u32 bit_width)
{
	return (u32)(((u64)1 << bit_width) - 1);
}

static u32 gfx_v6_0_get_rb_active_bitmap(struct amdgpu_device *adev)
{
	u32 data, mask;

	data = RREG32(mmCC_RB_BACKEND_DISABLE) |
		RREG32(mmGC_USER_RB_BACKEND_DISABLE);

	data = REG_GET_FIELD(data, GC_USER_RB_BACKEND_DISABLE, BACKEND_DISABLE);

	mask = gfx_v6_0_create_bitmask(adev->gfx.config.max_backends_per_se/
					adev->gfx.config.max_sh_per_se);

	return ~data & mask;
}

static void gfx_v6_0_raster_config(struct amdgpu_device *adev, u32 *rconf)
{
	switch (adev->asic_type) {
	case CHIP_TAHITI:
	case CHIP_PITCAIRN:
		*rconf |=
			   (2 << PA_SC_RASTER_CONFIG__RB_XSEL2__SHIFT) |
			   (1 << PA_SC_RASTER_CONFIG__RB_XSEL__SHIFT) |
			   (2 << PA_SC_RASTER_CONFIG__PKR_MAP__SHIFT) |
			   (1 << PA_SC_RASTER_CONFIG__PKR_YSEL__SHIFT) |
			   (2 << PA_SC_RASTER_CONFIG__SE_MAP__SHIFT) |
			   (2 << PA_SC_RASTER_CONFIG__SE_XSEL__SHIFT) |
			   (2 << PA_SC_RASTER_CONFIG__SE_YSEL__SHIFT);
		break;
	case CHIP_VERDE:
		*rconf |=
			   (1 << PA_SC_RASTER_CONFIG__RB_XSEL__SHIFT) |
			   (2 << PA_SC_RASTER_CONFIG__PKR_MAP__SHIFT) |
			   (1 << PA_SC_RASTER_CONFIG__PKR_YSEL__SHIFT);
		break;
	case CHIP_OLAND:
		*rconf |= (1 << PA_SC_RASTER_CONFIG__RB_YSEL__SHIFT);
		break;
	case CHIP_HAINAN:
		*rconf |= 0x0;
		break;
	default:
		DRM_ERROR("unknown asic: 0x%x\n", adev->asic_type);
		break;
	}
}

static void gfx_v6_0_write_harvested_raster_configs(struct amdgpu_device *adev,
						    u32 raster_config, unsigned rb_mask,
						    unsigned num_rb)
{
	unsigned sh_per_se = max_t(unsigned, adev->gfx.config.max_sh_per_se, 1);
	unsigned num_se = max_t(unsigned, adev->gfx.config.max_shader_engines, 1);
	unsigned rb_per_pkr = min_t(unsigned, num_rb / num_se / sh_per_se, 2);
	unsigned rb_per_se = num_rb / num_se;
	unsigned se_mask[4];
	unsigned se;

	se_mask[0] = ((1 << rb_per_se) - 1) & rb_mask;
	se_mask[1] = (se_mask[0] << rb_per_se) & rb_mask;
	se_mask[2] = (se_mask[1] << rb_per_se) & rb_mask;
	se_mask[3] = (se_mask[2] << rb_per_se) & rb_mask;

	WARN_ON(!(num_se == 1 || num_se == 2 || num_se == 4));
	WARN_ON(!(sh_per_se == 1 || sh_per_se == 2));
	WARN_ON(!(rb_per_pkr == 1 || rb_per_pkr == 2));

	for (se = 0; se < num_se; se++) {
		unsigned raster_config_se = raster_config;
		unsigned pkr0_mask = ((1 << rb_per_pkr) - 1) << (se * rb_per_se);
		unsigned pkr1_mask = pkr0_mask << rb_per_pkr;
		int idx = (se / 2) * 2;

		if ((num_se > 1) && (!se_mask[idx] || !se_mask[idx + 1])) {
			raster_config_se &= ~PA_SC_RASTER_CONFIG__SE_MAP_MASK;

			if (!se_mask[idx]) {
				raster_config_se |= RASTER_CONFIG_SE_MAP_3 << PA_SC_RASTER_CONFIG__SE_MAP__SHIFT;
			} else {
				raster_config_se |= RASTER_CONFIG_SE_MAP_0 << PA_SC_RASTER_CONFIG__SE_MAP__SHIFT;
			}
		}

		pkr0_mask &= rb_mask;
		pkr1_mask &= rb_mask;
		if (rb_per_se > 2 && (!pkr0_mask || !pkr1_mask)) {
			raster_config_se &= ~PA_SC_RASTER_CONFIG__PKR_MAP_MASK;

			if (!pkr0_mask) {
				raster_config_se |= RASTER_CONFIG_PKR_MAP_3 << PA_SC_RASTER_CONFIG__PKR_MAP__SHIFT;
			} else {
				raster_config_se |= RASTER_CONFIG_PKR_MAP_0 << PA_SC_RASTER_CONFIG__PKR_MAP__SHIFT;
			}
		}

		if (rb_per_se >= 2) {
			unsigned rb0_mask = 1 << (se * rb_per_se);
			unsigned rb1_mask = rb0_mask << 1;

			rb0_mask &= rb_mask;
			rb1_mask &= rb_mask;
			if (!rb0_mask || !rb1_mask) {
				raster_config_se &= ~PA_SC_RASTER_CONFIG__RB_MAP_PKR0_MASK;

				if (!rb0_mask) {
					raster_config_se |=
						RASTER_CONFIG_RB_MAP_3 << PA_SC_RASTER_CONFIG__RB_MAP_PKR0__SHIFT;
				} else {
					raster_config_se |=
						RASTER_CONFIG_RB_MAP_0 << PA_SC_RASTER_CONFIG__RB_MAP_PKR0__SHIFT;
				}
			}

			if (rb_per_se > 2) {
				rb0_mask = 1 << (se * rb_per_se + rb_per_pkr);
				rb1_mask = rb0_mask << 1;
				rb0_mask &= rb_mask;
				rb1_mask &= rb_mask;
				if (!rb0_mask || !rb1_mask) {
					raster_config_se &= ~PA_SC_RASTER_CONFIG__RB_MAP_PKR1_MASK;

					if (!rb0_mask) {
						raster_config_se |=
							RASTER_CONFIG_RB_MAP_3 << PA_SC_RASTER_CONFIG__RB_MAP_PKR1__SHIFT;
					} else {
						raster_config_se |=
							RASTER_CONFIG_RB_MAP_0 << PA_SC_RASTER_CONFIG__RB_MAP_PKR1__SHIFT;
					}
				}
			}
		}

		/* GRBM_GFX_INDEX has a different offset on SI */
		gfx_v6_0_select_se_sh(adev, se, 0xffffffff, 0xffffffff);
		WREG32(mmPA_SC_RASTER_CONFIG, raster_config_se);
	}

	/* GRBM_GFX_INDEX has a different offset on SI */
	gfx_v6_0_select_se_sh(adev, 0xffffffff, 0xffffffff, 0xffffffff);
}

static void gfx_v6_0_setup_rb(struct amdgpu_device *adev)
{
	int i, j;
	u32 data;
	u32 raster_config = 0;
	u32 active_rbs = 0;
	u32 rb_bitmap_width_per_sh = adev->gfx.config.max_backends_per_se /
					adev->gfx.config.max_sh_per_se;
	unsigned num_rb_pipes;

	mutex_lock(&adev->grbm_idx_mutex);
	for (i = 0; i < adev->gfx.config.max_shader_engines; i++) {
		for (j = 0; j < adev->gfx.config.max_sh_per_se; j++) {
			gfx_v6_0_select_se_sh(adev, i, j, 0xffffffff);
			data = gfx_v6_0_get_rb_active_bitmap(adev);
			active_rbs |= data << ((i * adev->gfx.config.max_sh_per_se + j) *
					rb_bitmap_width_per_sh);
		}
	}
	gfx_v6_0_select_se_sh(adev, 0xffffffff, 0xffffffff, 0xffffffff);

	adev->gfx.config.backend_enable_mask = active_rbs;
	adev->gfx.config.num_rbs = hweight32(active_rbs);

	num_rb_pipes = min_t(unsigned, adev->gfx.config.max_backends_per_se *
			     adev->gfx.config.max_shader_engines, 16);

	gfx_v6_0_raster_config(adev, &raster_config);

	if (!adev->gfx.config.backend_enable_mask ||
			adev->gfx.config.num_rbs >= num_rb_pipes) {
		WREG32(mmPA_SC_RASTER_CONFIG, raster_config);
	} else {
		gfx_v6_0_write_harvested_raster_configs(adev, raster_config,
							adev->gfx.config.backend_enable_mask,
							num_rb_pipes);
	}

	/* cache the values for userspace */
	for (i = 0; i < adev->gfx.config.max_shader_engines; i++) {
		for (j = 0; j < adev->gfx.config.max_sh_per_se; j++) {
			gfx_v6_0_select_se_sh(adev, i, j, 0xffffffff);
			adev->gfx.config.rb_config[i][j].rb_backend_disable =
				RREG32(mmCC_RB_BACKEND_DISABLE);
			adev->gfx.config.rb_config[i][j].user_rb_backend_disable =
				RREG32(mmGC_USER_RB_BACKEND_DISABLE);
			adev->gfx.config.rb_config[i][j].raster_config =
				RREG32(mmPA_SC_RASTER_CONFIG);
		}
	}
	gfx_v6_0_select_se_sh(adev, 0xffffffff, 0xffffffff, 0xffffffff);
	mutex_unlock(&adev->grbm_idx_mutex);
}
/*
static void gmc_v6_0_init_compute_vmid(struct amdgpu_device *adev)
{
}
*/

static void gfx_v6_0_set_user_cu_inactive_bitmap(struct amdgpu_device *adev,
						 u32 bitmap)
{
	u32 data;

	if (!bitmap)
		return;

	data = bitmap << GC_USER_SHADER_ARRAY_CONFIG__INACTIVE_CUS__SHIFT;
	data &= GC_USER_SHADER_ARRAY_CONFIG__INACTIVE_CUS_MASK;

	WREG32(mmGC_USER_SHADER_ARRAY_CONFIG, data);
}

static u32 gfx_v6_0_get_cu_enabled(struct amdgpu_device *adev)
{
	u32 data, mask;

	data = RREG32(mmCC_GC_SHADER_ARRAY_CONFIG) |
		RREG32(mmGC_USER_SHADER_ARRAY_CONFIG);

	mask = gfx_v6_0_create_bitmask(adev->gfx.config.max_cu_per_sh);
	return ~REG_GET_FIELD(data, CC_GC_SHADER_ARRAY_CONFIG, INACTIVE_CUS) & mask;
}


static void gfx_v6_0_setup_spi(struct amdgpu_device *adev)
{
	int i, j, k;
	u32 data, mask;
	u32 active_cu = 0;

	mutex_lock(&adev->grbm_idx_mutex);
	for (i = 0; i < adev->gfx.config.max_shader_engines; i++) {
		for (j = 0; j < adev->gfx.config.max_sh_per_se; j++) {
			gfx_v6_0_select_se_sh(adev, i, j, 0xffffffff);
			data = RREG32(mmSPI_STATIC_THREAD_MGMT_3);
			active_cu = gfx_v6_0_get_cu_enabled(adev);

			mask = 1;
			for (k = 0; k < 16; k++) {
				mask <<= k;
				if (active_cu & mask) {
					data &= ~mask;
					WREG32(mmSPI_STATIC_THREAD_MGMT_3, data);
					break;
				}
			}
		}
	}
	gfx_v6_0_select_se_sh(adev, 0xffffffff, 0xffffffff, 0xffffffff);
	mutex_unlock(&adev->grbm_idx_mutex);
}

static void gfx_v6_0_gpu_init(struct amdgpu_device *adev)
{
	u32 gb_addr_config = 0;
	u32 mc_shared_chmap, mc_arb_ramcfg;
	u32 sx_debug_1;
	u32 hdp_host_path_cntl;
	u32 tmp;

	switch (adev->asic_type) {
	case CHIP_TAHITI:
		adev->gfx.config.max_shader_engines = 2;
		adev->gfx.config.max_tile_pipes = 12;
		adev->gfx.config.max_cu_per_sh = 8;
		adev->gfx.config.max_sh_per_se = 2;
		adev->gfx.config.max_backends_per_se = 4;
		adev->gfx.config.max_texture_channel_caches = 12;
		adev->gfx.config.max_gprs = 256;
		adev->gfx.config.max_gs_threads = 32;
		adev->gfx.config.max_hw_contexts = 8;

		adev->gfx.config.sc_prim_fifo_size_frontend = 0x20;
		adev->gfx.config.sc_prim_fifo_size_backend = 0x100;
		adev->gfx.config.sc_hiz_tile_fifo_size = 0x30;
		adev->gfx.config.sc_earlyz_tile_fifo_size = 0x130;
		gb_addr_config = TAHITI_GB_ADDR_CONFIG_GOLDEN;
		break;
	case CHIP_PITCAIRN:
		adev->gfx.config.max_shader_engines = 2;
		adev->gfx.config.max_tile_pipes = 8;
		adev->gfx.config.max_cu_per_sh = 5;
		adev->gfx.config.max_sh_per_se = 2;
		adev->gfx.config.max_backends_per_se = 4;
		adev->gfx.config.max_texture_channel_caches = 8;
		adev->gfx.config.max_gprs = 256;
		adev->gfx.config.max_gs_threads = 32;
		adev->gfx.config.max_hw_contexts = 8;

		adev->gfx.config.sc_prim_fifo_size_frontend = 0x20;
		adev->gfx.config.sc_prim_fifo_size_backend = 0x100;
		adev->gfx.config.sc_hiz_tile_fifo_size = 0x30;
		adev->gfx.config.sc_earlyz_tile_fifo_size = 0x130;
		gb_addr_config = TAHITI_GB_ADDR_CONFIG_GOLDEN;
		break;
	case CHIP_VERDE:
		adev->gfx.config.max_shader_engines = 1;
		adev->gfx.config.max_tile_pipes = 4;
		adev->gfx.config.max_cu_per_sh = 5;
		adev->gfx.config.max_sh_per_se = 2;
		adev->gfx.config.max_backends_per_se = 4;
		adev->gfx.config.max_texture_channel_caches = 4;
		adev->gfx.config.max_gprs = 256;
		adev->gfx.config.max_gs_threads = 32;
		adev->gfx.config.max_hw_contexts = 8;

		adev->gfx.config.sc_prim_fifo_size_frontend = 0x20;
		adev->gfx.config.sc_prim_fifo_size_backend = 0x40;
		adev->gfx.config.sc_hiz_tile_fifo_size = 0x30;
		adev->gfx.config.sc_earlyz_tile_fifo_size = 0x130;
		gb_addr_config = VERDE_GB_ADDR_CONFIG_GOLDEN;
		break;
	case CHIP_OLAND:
		adev->gfx.config.max_shader_engines = 1;
		adev->gfx.config.max_tile_pipes = 4;
		adev->gfx.config.max_cu_per_sh = 6;
		adev->gfx.config.max_sh_per_se = 1;
		adev->gfx.config.max_backends_per_se = 2;
		adev->gfx.config.max_texture_channel_caches = 4;
		adev->gfx.config.max_gprs = 256;
		adev->gfx.config.max_gs_threads = 16;
		adev->gfx.config.max_hw_contexts = 8;

		adev->gfx.config.sc_prim_fifo_size_frontend = 0x20;
		adev->gfx.config.sc_prim_fifo_size_backend = 0x40;
		adev->gfx.config.sc_hiz_tile_fifo_size = 0x30;
		adev->gfx.config.sc_earlyz_tile_fifo_size = 0x130;
		gb_addr_config = VERDE_GB_ADDR_CONFIG_GOLDEN;
		break;
	case CHIP_HAINAN:
		adev->gfx.config.max_shader_engines = 1;
		adev->gfx.config.max_tile_pipes = 4;
		adev->gfx.config.max_cu_per_sh = 5;
		adev->gfx.config.max_sh_per_se = 1;
		adev->gfx.config.max_backends_per_se = 1;
		adev->gfx.config.max_texture_channel_caches = 2;
		adev->gfx.config.max_gprs = 256;
		adev->gfx.config.max_gs_threads = 16;
		adev->gfx.config.max_hw_contexts = 8;

		adev->gfx.config.sc_prim_fifo_size_frontend = 0x20;
		adev->gfx.config.sc_prim_fifo_size_backend = 0x40;
		adev->gfx.config.sc_hiz_tile_fifo_size = 0x30;
		adev->gfx.config.sc_earlyz_tile_fifo_size = 0x130;
		gb_addr_config = HAINAN_GB_ADDR_CONFIG_GOLDEN;
		break;
	default:
		BUG();
		break;
	}

	WREG32(mmGRBM_CNTL, (0xff << GRBM_CNTL__READ_TIMEOUT__SHIFT));
	WREG32(mmSRBM_INT_CNTL, 1);
	WREG32(mmSRBM_INT_ACK, 1);

	WREG32(mmBIF_FB_EN, BIF_FB_EN__FB_READ_EN_MASK | BIF_FB_EN__FB_WRITE_EN_MASK);

	mc_shared_chmap = RREG32(mmMC_SHARED_CHMAP);
	mc_arb_ramcfg = RREG32(mmMC_ARB_RAMCFG);

	adev->gfx.config.num_tile_pipes = adev->gfx.config.max_tile_pipes;
	adev->gfx.config.mem_max_burst_length_bytes = 256;
	tmp = (mc_arb_ramcfg & MC_ARB_RAMCFG__NOOFCOLS_MASK) >> MC_ARB_RAMCFG__NOOFCOLS__SHIFT;
	adev->gfx.config.mem_row_size_in_kb = (4 * (1 << (8 + tmp))) / 1024;
	if (adev->gfx.config.mem_row_size_in_kb > 4)
		adev->gfx.config.mem_row_size_in_kb = 4;
	adev->gfx.config.shader_engine_tile_size = 32;
	adev->gfx.config.num_gpus = 1;
	adev->gfx.config.multi_gpu_tile_size = 64;

	gb_addr_config &= ~GB_ADDR_CONFIG__ROW_SIZE_MASK;
	switch (adev->gfx.config.mem_row_size_in_kb) {
	case 1:
	default:
		gb_addr_config |= 0 << GB_ADDR_CONFIG__ROW_SIZE__SHIFT;
		break;
	case 2:
		gb_addr_config |= 1 << GB_ADDR_CONFIG__ROW_SIZE__SHIFT;
		break;
	case 4:
		gb_addr_config |= 2 << GB_ADDR_CONFIG__ROW_SIZE__SHIFT;
		break;
	}
	gb_addr_config &= ~GB_ADDR_CONFIG__NUM_SHADER_ENGINES_MASK;
	if (adev->gfx.config.max_shader_engines == 2)
		gb_addr_config |= 1 << GB_ADDR_CONFIG__NUM_SHADER_ENGINES__SHIFT;
	adev->gfx.config.gb_addr_config = gb_addr_config;

	WREG32(mmGB_ADDR_CONFIG, gb_addr_config);
	WREG32(mmDMIF_ADDR_CONFIG, gb_addr_config);
	WREG32(mmDMIF_ADDR_CALC, gb_addr_config);
	WREG32(mmHDP_ADDR_CONFIG, gb_addr_config);
	WREG32(mmDMA_TILING_CONFIG + DMA0_REGISTER_OFFSET, gb_addr_config);
	WREG32(mmDMA_TILING_CONFIG + DMA1_REGISTER_OFFSET, gb_addr_config);

#if 0
	if (adev->has_uvd) {
		WREG32(mmUVD_UDEC_ADDR_CONFIG, gb_addr_config);
		WREG32(mmUVD_UDEC_DB_ADDR_CONFIG, gb_addr_config);
		WREG32(mmUVD_UDEC_DBW_ADDR_CONFIG, gb_addr_config);
	}
#endif
	gfx_v6_0_tiling_mode_table_init(adev);

	gfx_v6_0_setup_rb(adev);

	gfx_v6_0_setup_spi(adev);

	gfx_v6_0_get_cu_info(adev);

	WREG32(mmCP_QUEUE_THRESHOLDS, ((0x16 << CP_QUEUE_THRESHOLDS__ROQ_IB1_START__SHIFT) |
				       (0x2b << CP_QUEUE_THRESHOLDS__ROQ_IB2_START__SHIFT)));
	WREG32(mmCP_MEQ_THRESHOLDS, (0x30 << CP_MEQ_THRESHOLDS__MEQ1_START__SHIFT) |
				    (0x60 << CP_MEQ_THRESHOLDS__MEQ2_START__SHIFT));

	sx_debug_1 = RREG32(mmSX_DEBUG_1);
	WREG32(mmSX_DEBUG_1, sx_debug_1);

	WREG32(mmSPI_CONFIG_CNTL_1, (4 << SPI_CONFIG_CNTL_1__VTX_DONE_DELAY__SHIFT));

	WREG32(mmPA_SC_FIFO_SIZE, ((adev->gfx.config.sc_prim_fifo_size_frontend << PA_SC_FIFO_SIZE__SC_FRONTEND_PRIM_FIFO_SIZE__SHIFT) |
				   (adev->gfx.config.sc_prim_fifo_size_backend << PA_SC_FIFO_SIZE__SC_BACKEND_PRIM_FIFO_SIZE__SHIFT) |
				   (adev->gfx.config.sc_hiz_tile_fifo_size << PA_SC_FIFO_SIZE__SC_HIZ_TILE_FIFO_SIZE__SHIFT) |
				   (adev->gfx.config.sc_earlyz_tile_fifo_size << PA_SC_FIFO_SIZE__SC_EARLYZ_TILE_FIFO_SIZE__SHIFT)));

	WREG32(mmVGT_NUM_INSTANCES, 1);
	WREG32(mmCP_PERFMON_CNTL, 0);
	WREG32(mmSQ_CONFIG, 0);
	WREG32(mmPA_SC_FORCE_EOV_MAX_CNTS, ((4095 << PA_SC_FORCE_EOV_MAX_CNTS__FORCE_EOV_MAX_CLK_CNT__SHIFT) |
					  (255 << PA_SC_FORCE_EOV_MAX_CNTS__FORCE_EOV_MAX_REZ_CNT__SHIFT)));

	WREG32(mmVGT_CACHE_INVALIDATION,
		(VC_AND_TC << VGT_CACHE_INVALIDATION__CACHE_INVALIDATION__SHIFT) |
		(ES_AND_GS_AUTO << VGT_CACHE_INVALIDATION__AUTO_INVLD_EN__SHIFT));

	WREG32(mmVGT_GS_VERTEX_REUSE, 16);
	WREG32(mmPA_SC_LINE_STIPPLE_STATE, 0);

	WREG32(mmCB_PERFCOUNTER0_SELECT0, 0);
	WREG32(mmCB_PERFCOUNTER0_SELECT1, 0);
	WREG32(mmCB_PERFCOUNTER1_SELECT0, 0);
	WREG32(mmCB_PERFCOUNTER1_SELECT1, 0);
	WREG32(mmCB_PERFCOUNTER2_SELECT0, 0);
	WREG32(mmCB_PERFCOUNTER2_SELECT1, 0);
	WREG32(mmCB_PERFCOUNTER3_SELECT0, 0);
	WREG32(mmCB_PERFCOUNTER3_SELECT1, 0);

	hdp_host_path_cntl = RREG32(mmHDP_HOST_PATH_CNTL);
	WREG32(mmHDP_HOST_PATH_CNTL, hdp_host_path_cntl);

	WREG32(mmPA_CL_ENHANCE, PA_CL_ENHANCE__CLIP_VTX_REORDER_ENA_MASK |
				(3 << PA_CL_ENHANCE__NUM_CLIP_SEQ__SHIFT));

	udelay(50);
}


static void gfx_v6_0_scratch_init(struct amdgpu_device *adev)
{
	adev->gfx.scratch.num_reg = 7;
	adev->gfx.scratch.reg_base = mmSCRATCH_REG0;
	adev->gfx.scratch.free_mask = (1u << adev->gfx.scratch.num_reg) - 1;
}

static int gfx_v6_0_ring_test_ring(struct amdgpu_ring *ring)
{
	struct amdgpu_device *adev = ring->adev;
	uint32_t scratch;
	uint32_t tmp = 0;
	unsigned i;
	int r;

	r = amdgpu_gfx_scratch_get(adev, &scratch);
	if (r) {
		DRM_ERROR("amdgpu: cp failed to get scratch reg (%d).\n", r);
		return r;
	}
	WREG32(scratch, 0xCAFEDEAD);

	r = amdgpu_ring_alloc(ring, 3);
	if (r) {
		DRM_ERROR("amdgpu: cp failed to lock ring %d (%d).\n", ring->idx, r);
		amdgpu_gfx_scratch_free(adev, scratch);
		return r;
	}
	amdgpu_ring_write(ring, PACKET3(PACKET3_SET_CONFIG_REG, 1));
	amdgpu_ring_write(ring, (scratch - PACKET3_SET_CONFIG_REG_START));
	amdgpu_ring_write(ring, 0xDEADBEEF);
	amdgpu_ring_commit(ring);

	for (i = 0; i < adev->usec_timeout; i++) {
		tmp = RREG32(scratch);
		if (tmp == 0xDEADBEEF)
			break;
		DRM_UDELAY(1);
	}
	if (i < adev->usec_timeout) {
		DRM_INFO("ring test on %d succeeded in %d usecs\n", ring->idx, i);
	} else {
		DRM_ERROR("amdgpu: ring %d test failed (scratch(0x%04X)=0x%08X)\n",
			  ring->idx, scratch, tmp);
		r = -EINVAL;
	}
	amdgpu_gfx_scratch_free(adev, scratch);
	return r;
}

static void gfx_v6_0_ring_emit_hdp_flush(struct amdgpu_ring *ring)
{
	/* flush hdp cache */
	amdgpu_ring_write(ring, PACKET3(PACKET3_WRITE_DATA, 3));
	amdgpu_ring_write(ring, (WRITE_DATA_ENGINE_SEL(1) |
				 WRITE_DATA_DST_SEL(0)));
	amdgpu_ring_write(ring, mmHDP_MEM_COHERENCY_FLUSH_CNTL);
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, 0x1);
}

static void gfx_v6_0_ring_emit_vgt_flush(struct amdgpu_ring *ring)
{
	amdgpu_ring_write(ring, PACKET3(PACKET3_EVENT_WRITE, 0));
	amdgpu_ring_write(ring, EVENT_TYPE(VGT_FLUSH) |
		EVENT_INDEX(0));
}

/**
 * gfx_v6_0_ring_emit_hdp_invalidate - emit an hdp invalidate on the cp
 *
 * @adev: amdgpu_device pointer
 * @ridx: amdgpu ring index
 *
 * Emits an hdp invalidate on the cp.
 */
static void gfx_v6_0_ring_emit_hdp_invalidate(struct amdgpu_ring *ring)
{
	amdgpu_ring_write(ring, PACKET3(PACKET3_WRITE_DATA, 3));
	amdgpu_ring_write(ring, (WRITE_DATA_ENGINE_SEL(1) |
				 WRITE_DATA_DST_SEL(0)));
	amdgpu_ring_write(ring, mmHDP_DEBUG0);
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, 0x1);
}

static void gfx_v6_0_ring_emit_fence(struct amdgpu_ring *ring, u64 addr,
				     u64 seq, unsigned flags)
{
	bool write64bit = flags & AMDGPU_FENCE_FLAG_64BIT;
	bool int_sel = flags & AMDGPU_FENCE_FLAG_INT;
	/* flush read cache over gart */
	amdgpu_ring_write(ring, PACKET3(PACKET3_SET_CONFIG_REG, 1));
	amdgpu_ring_write(ring, (mmCP_COHER_CNTL2 - PACKET3_SET_CONFIG_REG_START));
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, PACKET3(PACKET3_SURFACE_SYNC, 3));
	amdgpu_ring_write(ring, PACKET3_TCL1_ACTION_ENA |
			  PACKET3_TC_ACTION_ENA |
			  PACKET3_SH_KCACHE_ACTION_ENA |
			  PACKET3_SH_ICACHE_ACTION_ENA);
	amdgpu_ring_write(ring, 0xFFFFFFFF);
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, 10); /* poll interval */
	/* EVENT_WRITE_EOP - flush caches, send int */
	amdgpu_ring_write(ring, PACKET3(PACKET3_EVENT_WRITE_EOP, 4));
	amdgpu_ring_write(ring, EVENT_TYPE(CACHE_FLUSH_AND_INV_TS_EVENT) | EVENT_INDEX(5));
	amdgpu_ring_write(ring, addr & 0xfffffffc);
	amdgpu_ring_write(ring, (upper_32_bits(addr) & 0xffff) |
				((write64bit ? 2 : 1) << CP_EOP_DONE_DATA_CNTL__DATA_SEL__SHIFT) |
				((int_sel ? 2 : 0) << CP_EOP_DONE_DATA_CNTL__INT_SEL__SHIFT));
	amdgpu_ring_write(ring, lower_32_bits(seq));
	amdgpu_ring_write(ring, upper_32_bits(seq));
}

static void gfx_v6_0_ring_emit_ib(struct amdgpu_ring *ring,
				  struct amdgpu_ib *ib,
				  unsigned vm_id, bool ctx_switch)
{
	u32 header, control = 0;

	/* insert SWITCH_BUFFER packet before first IB in the ring frame */
	if (ctx_switch) {
		amdgpu_ring_write(ring, PACKET3(PACKET3_SWITCH_BUFFER, 0));
		amdgpu_ring_write(ring, 0);
	}

	if (ib->flags & AMDGPU_IB_FLAG_CE)
		header = PACKET3(PACKET3_INDIRECT_BUFFER_CONST, 2);
	else
		header = PACKET3(PACKET3_INDIRECT_BUFFER, 2);

	control |= ib->length_dw | (vm_id << 24);

	amdgpu_ring_write(ring, header);
	amdgpu_ring_write(ring,
#ifdef __BIG_ENDIAN
			  (2 << 0) |
#endif
			  (ib->gpu_addr & 0xFFFFFFFC));
	amdgpu_ring_write(ring, upper_32_bits(ib->gpu_addr) & 0xFFFF);
	amdgpu_ring_write(ring, control);
}

/**
 * gfx_v6_0_ring_test_ib - basic ring IB test
 *
 * @ring: amdgpu_ring structure holding ring information
 *
 * Allocate an IB and execute it on the gfx ring (SI).
 * Provides a basic gfx ring test to verify that IBs are working.
 * Returns 0 on success, error on failure.
 */
static int gfx_v6_0_ring_test_ib(struct amdgpu_ring *ring, long timeout)
{
	struct amdgpu_device *adev = ring->adev;
	struct amdgpu_ib ib;
	struct dma_fence *f = NULL;
	uint32_t scratch;
	uint32_t tmp = 0;
	long r;

	r = amdgpu_gfx_scratch_get(adev, &scratch);
	if (r) {
		DRM_ERROR("amdgpu: failed to get scratch reg (%ld).\n", r);
		return r;
	}
	WREG32(scratch, 0xCAFEDEAD);
	memset(&ib, 0, sizeof(ib));
	r = amdgpu_ib_get(adev, NULL, 256, &ib);
	if (r) {
		DRM_ERROR("amdgpu: failed to get ib (%ld).\n", r);
		goto err1;
	}
	ib.ptr[0] = PACKET3(PACKET3_SET_CONFIG_REG, 1);
	ib.ptr[1] = ((scratch - PACKET3_SET_CONFIG_REG_START));
	ib.ptr[2] = 0xDEADBEEF;
	ib.length_dw = 3;

	r = amdgpu_ib_schedule(ring, 1, &ib, NULL, &f);
	if (r)
		goto err2;

	r = dma_fence_wait_timeout(f, false, timeout);
	if (r == 0) {
		DRM_ERROR("amdgpu: IB test timed out\n");
		r = -ETIMEDOUT;
		goto err2;
	} else if (r < 0) {
		DRM_ERROR("amdgpu: fence wait failed (%ld).\n", r);
		goto err2;
	}
	tmp = RREG32(scratch);
	if (tmp == 0xDEADBEEF) {
		DRM_INFO("ib test on ring %d succeeded\n", ring->idx);
		r = 0;
	} else {
		DRM_ERROR("amdgpu: ib test failed (scratch(0x%04X)=0x%08X)\n",
			  scratch, tmp);
		r = -EINVAL;
	}

err2:
	amdgpu_ib_free(adev, &ib, NULL);
	dma_fence_put(f);
err1:
	amdgpu_gfx_scratch_free(adev, scratch);
	return r;
}

static void gfx_v6_0_cp_gfx_enable(struct amdgpu_device *adev, bool enable)
{
	int i;
	if (enable) {
		WREG32(mmCP_ME_CNTL, 0);
	} else {
		WREG32(mmCP_ME_CNTL, (CP_ME_CNTL__ME_HALT_MASK |
				      CP_ME_CNTL__PFP_HALT_MASK |
				      CP_ME_CNTL__CE_HALT_MASK));
		WREG32(mmSCRATCH_UMSK, 0);
		for (i = 0; i < adev->gfx.num_gfx_rings; i++)
			adev->gfx.gfx_ring[i].ready = false;
		for (i = 0; i < adev->gfx.num_compute_rings; i++)
			adev->gfx.compute_ring[i].ready = false;
	}
	udelay(50);
}

static int gfx_v6_0_cp_gfx_load_microcode(struct amdgpu_device *adev)
{
	unsigned i;
	const struct gfx_firmware_header_v1_0 *pfp_hdr;
	const struct gfx_firmware_header_v1_0 *ce_hdr;
	const struct gfx_firmware_header_v1_0 *me_hdr;
	const __le32 *fw_data;
	u32 fw_size;

	if (!adev->gfx.me_fw || !adev->gfx.pfp_fw || !adev->gfx.ce_fw)
		return -EINVAL;

	gfx_v6_0_cp_gfx_enable(adev, false);
	pfp_hdr = (const struct gfx_firmware_header_v1_0 *)adev->gfx.pfp_fw->data;
	ce_hdr = (const struct gfx_firmware_header_v1_0 *)adev->gfx.ce_fw->data;
	me_hdr = (const struct gfx_firmware_header_v1_0 *)adev->gfx.me_fw->data;

	amdgpu_ucode_print_gfx_hdr(&pfp_hdr->header);
	amdgpu_ucode_print_gfx_hdr(&ce_hdr->header);
	amdgpu_ucode_print_gfx_hdr(&me_hdr->header);

	/* PFP */
	fw_data = (const __le32 *)
		(adev->gfx.pfp_fw->data + le32_to_cpu(pfp_hdr->header.ucode_array_offset_bytes));
	fw_size = le32_to_cpu(pfp_hdr->header.ucode_size_bytes) / 4;
	WREG32(mmCP_PFP_UCODE_ADDR, 0);
	for (i = 0; i < fw_size; i++)
		WREG32(mmCP_PFP_UCODE_DATA, le32_to_cpup(fw_data++));
	WREG32(mmCP_PFP_UCODE_ADDR, 0);

	/* CE */
	fw_data = (const __le32 *)
		(adev->gfx.ce_fw->data + le32_to_cpu(ce_hdr->header.ucode_array_offset_bytes));
	fw_size = le32_to_cpu(ce_hdr->header.ucode_size_bytes) / 4;
	WREG32(mmCP_CE_UCODE_ADDR, 0);
	for (i = 0; i < fw_size; i++)
		WREG32(mmCP_CE_UCODE_DATA, le32_to_cpup(fw_data++));
	WREG32(mmCP_CE_UCODE_ADDR, 0);

	/* ME */
	fw_data = (const __be32 *)
		(adev->gfx.me_fw->data + le32_to_cpu(me_hdr->header.ucode_array_offset_bytes));
	fw_size = le32_to_cpu(me_hdr->header.ucode_size_bytes) / 4;
	WREG32(mmCP_ME_RAM_WADDR, 0);
	for (i = 0; i < fw_size; i++)
		WREG32(mmCP_ME_RAM_DATA, le32_to_cpup(fw_data++));
	WREG32(mmCP_ME_RAM_WADDR, 0);

	WREG32(mmCP_PFP_UCODE_ADDR, 0);
	WREG32(mmCP_CE_UCODE_ADDR, 0);
	WREG32(mmCP_ME_RAM_WADDR, 0);
	WREG32(mmCP_ME_RAM_RADDR, 0);
	return 0;
}

static int gfx_v6_0_cp_gfx_start(struct amdgpu_device *adev)
{
	const struct cs_section_def *sect = NULL;
	const struct cs_extent_def *ext = NULL;
	struct amdgpu_ring *ring = &adev->gfx.gfx_ring[0];
	int r, i;

	r = amdgpu_ring_alloc(ring, 7 + 4);
	if (r) {
		DRM_ERROR("amdgpu: cp failed to lock ring (%d).\n", r);
		return r;
	}
	amdgpu_ring_write(ring, PACKET3(PACKET3_ME_INITIALIZE, 5));
	amdgpu_ring_write(ring, 0x1);
	amdgpu_ring_write(ring, 0x0);
	amdgpu_ring_write(ring, adev->gfx.config.max_hw_contexts - 1);
	amdgpu_ring_write(ring, PACKET3_ME_INITIALIZE_DEVICE_ID(1));
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, 0);

	amdgpu_ring_write(ring, PACKET3(PACKET3_SET_BASE, 2));
	amdgpu_ring_write(ring, PACKET3_BASE_INDEX(CE_PARTITION_BASE));
	amdgpu_ring_write(ring, 0xc000);
	amdgpu_ring_write(ring, 0xe000);
	amdgpu_ring_commit(ring);

	gfx_v6_0_cp_gfx_enable(adev, true);

	r = amdgpu_ring_alloc(ring, gfx_v6_0_get_csb_size(adev) + 10);
	if (r) {
		DRM_ERROR("amdgpu: cp failed to lock ring (%d).\n", r);
		return r;
	}

	amdgpu_ring_write(ring, PACKET3(PACKET3_PREAMBLE_CNTL, 0));
	amdgpu_ring_write(ring, PACKET3_PREAMBLE_BEGIN_CLEAR_STATE);

	for (sect = adev->gfx.rlc.cs_data; sect->section != NULL; ++sect) {
		for (ext = sect->section; ext->extent != NULL; ++ext) {
			if (sect->id == SECT_CONTEXT) {
				amdgpu_ring_write(ring,
						  PACKET3(PACKET3_SET_CONTEXT_REG, ext->reg_count));
				amdgpu_ring_write(ring, ext->reg_index - PACKET3_SET_CONTEXT_REG_START);
				for (i = 0; i < ext->reg_count; i++)
					amdgpu_ring_write(ring, ext->extent[i]);
			}
		}
	}

	amdgpu_ring_write(ring, PACKET3(PACKET3_PREAMBLE_CNTL, 0));
	amdgpu_ring_write(ring, PACKET3_PREAMBLE_END_CLEAR_STATE);

	amdgpu_ring_write(ring, PACKET3(PACKET3_CLEAR_STATE, 0));
	amdgpu_ring_write(ring, 0);

	amdgpu_ring_write(ring, PACKET3(PACKET3_SET_CONTEXT_REG, 2));
	amdgpu_ring_write(ring, 0x00000316);
	amdgpu_ring_write(ring, 0x0000000e);
	amdgpu_ring_write(ring, 0x00000010);

	amdgpu_ring_commit(ring);

	return 0;
}

static int gfx_v6_0_cp_gfx_resume(struct amdgpu_device *adev)
{
	struct amdgpu_ring *ring;
	u32 tmp;
	u32 rb_bufsz;
	int r;
	u64 rptr_addr;

	WREG32(mmCP_SEM_WAIT_TIMER, 0x0);
	WREG32(mmCP_SEM_INCOMPLETE_TIMER_CNTL, 0x0);

	/* Set the write pointer delay */
	WREG32(mmCP_RB_WPTR_DELAY, 0);

	WREG32(mmCP_DEBUG, 0);
	WREG32(mmSCRATCH_ADDR, 0);

	/* ring 0 - compute and gfx */
	/* Set ring buffer size */
	ring = &adev->gfx.gfx_ring[0];
	rb_bufsz = order_base_2(ring->ring_size / 8);
	tmp = (order_base_2(AMDGPU_GPU_PAGE_SIZE/8) << 8) | rb_bufsz;

#ifdef __BIG_ENDIAN
	tmp |= BUF_SWAP_32BIT;
#endif
	WREG32(mmCP_RB0_CNTL, tmp);

	/* Initialize the ring buffer's read and write pointers */
	WREG32(mmCP_RB0_CNTL, tmp | CP_RB0_CNTL__RB_RPTR_WR_ENA_MASK);
	ring->wptr = 0;
	WREG32(mmCP_RB0_WPTR, ring->wptr);

	/* set the wb address whether it's enabled or not */
	rptr_addr = adev->wb.gpu_addr + (ring->rptr_offs * 4);
	WREG32(mmCP_RB0_RPTR_ADDR, lower_32_bits(rptr_addr));
	WREG32(mmCP_RB0_RPTR_ADDR_HI, upper_32_bits(rptr_addr) & 0xFF);

	WREG32(mmSCRATCH_UMSK, 0);

	mdelay(1);
	WREG32(mmCP_RB0_CNTL, tmp);

	WREG32(mmCP_RB0_BASE, ring->gpu_addr >> 8);

	/* start the rings */
	gfx_v6_0_cp_gfx_start(adev);
	ring->ready = true;
	r = amdgpu_ring_test_ring(ring);
	if (r) {
		ring->ready = false;
		return r;
	}

	return 0;
}

static u32 gfx_v6_0_ring_get_rptr(struct amdgpu_ring *ring)
{
	return ring->adev->wb.wb[ring->rptr_offs];
}

static u32 gfx_v6_0_ring_get_wptr(struct amdgpu_ring *ring)
{
	struct amdgpu_device *adev = ring->adev;

	if (ring == &adev->gfx.gfx_ring[0])
		return RREG32(mmCP_RB0_WPTR);
	else if (ring == &adev->gfx.compute_ring[0])
		return RREG32(mmCP_RB1_WPTR);
	else if (ring == &adev->gfx.compute_ring[1])
		return RREG32(mmCP_RB2_WPTR);
	else
		BUG();
}

static void gfx_v6_0_ring_set_wptr_gfx(struct amdgpu_ring *ring)
{
	struct amdgpu_device *adev = ring->adev;

	WREG32(mmCP_RB0_WPTR, ring->wptr);
	(void)RREG32(mmCP_RB0_WPTR);
}

static void gfx_v6_0_ring_set_wptr_compute(struct amdgpu_ring *ring)
{
	struct amdgpu_device *adev = ring->adev;

	if (ring == &adev->gfx.compute_ring[0]) {
		WREG32(mmCP_RB1_WPTR, ring->wptr);
		(void)RREG32(mmCP_RB1_WPTR);
	} else if (ring == &adev->gfx.compute_ring[1]) {
		WREG32(mmCP_RB2_WPTR, ring->wptr);
		(void)RREG32(mmCP_RB2_WPTR);
	} else {
		BUG();
	}

}

static int gfx_v6_0_cp_compute_resume(struct amdgpu_device *adev)
{
	struct amdgpu_ring *ring;
	u32 tmp;
	u32 rb_bufsz;
	int i, r;
	u64 rptr_addr;

	/* ring1  - compute only */
	/* Set ring buffer size */

	ring = &adev->gfx.compute_ring[0];
	rb_bufsz = order_base_2(ring->ring_size / 8);
	tmp = (order_base_2(AMDGPU_GPU_PAGE_SIZE/8) << 8) | rb_bufsz;
#ifdef __BIG_ENDIAN
	tmp |= BUF_SWAP_32BIT;
#endif
	WREG32(mmCP_RB1_CNTL, tmp);

	WREG32(mmCP_RB1_CNTL, tmp | CP_RB1_CNTL__RB_RPTR_WR_ENA_MASK);
	ring->wptr = 0;
	WREG32(mmCP_RB1_WPTR, ring->wptr);

	rptr_addr = adev->wb.gpu_addr + (ring->rptr_offs * 4);
	WREG32(mmCP_RB1_RPTR_ADDR, lower_32_bits(rptr_addr));
	WREG32(mmCP_RB1_RPTR_ADDR_HI, upper_32_bits(rptr_addr) & 0xFF);

	mdelay(1);
	WREG32(mmCP_RB1_CNTL, tmp);
	WREG32(mmCP_RB1_BASE, ring->gpu_addr >> 8);

	ring = &adev->gfx.compute_ring[1];
	rb_bufsz = order_base_2(ring->ring_size / 8);
	tmp = (order_base_2(AMDGPU_GPU_PAGE_SIZE/8) << 8) | rb_bufsz;
#ifdef __BIG_ENDIAN
	tmp |= BUF_SWAP_32BIT;
#endif
	WREG32(mmCP_RB2_CNTL, tmp);

	WREG32(mmCP_RB2_CNTL, tmp | CP_RB2_CNTL__RB_RPTR_WR_ENA_MASK);
	ring->wptr = 0;
	WREG32(mmCP_RB2_WPTR, ring->wptr);
	rptr_addr = adev->wb.gpu_addr + (ring->rptr_offs * 4);
	WREG32(mmCP_RB2_RPTR_ADDR, lower_32_bits(rptr_addr));
	WREG32(mmCP_RB2_RPTR_ADDR_HI, upper_32_bits(rptr_addr) & 0xFF);

	mdelay(1);
	WREG32(mmCP_RB2_CNTL, tmp);
	WREG32(mmCP_RB2_BASE, ring->gpu_addr >> 8);

	adev->gfx.compute_ring[0].ready = false;
	adev->gfx.compute_ring[1].ready = false;

	for (i = 0; i < 2; i++) {
		r = amdgpu_ring_test_ring(&adev->gfx.compute_ring[i]);
		if (r)
			return r;
		adev->gfx.compute_ring[i].ready = true;
	}

	return 0;
}

static void gfx_v6_0_cp_enable(struct amdgpu_device *adev, bool enable)
{
	gfx_v6_0_cp_gfx_enable(adev, enable);
}

static int gfx_v6_0_cp_load_microcode(struct amdgpu_device *adev)
{
	return gfx_v6_0_cp_gfx_load_microcode(adev);
}

static void gfx_v6_0_enable_gui_idle_interrupt(struct amdgpu_device *adev,
					       bool enable)
{
	u32 tmp = RREG32(mmCP_INT_CNTL_RING0);
	u32 mask;
	int i;

	if (enable)
		tmp |= (CP_INT_CNTL__CNTX_BUSY_INT_ENABLE_MASK |
			CP_INT_CNTL__CNTX_EMPTY_INT_ENABLE_MASK);
	else
		tmp &= ~(CP_INT_CNTL__CNTX_BUSY_INT_ENABLE_MASK |
			 CP_INT_CNTL__CNTX_EMPTY_INT_ENABLE_MASK);
	WREG32(mmCP_INT_CNTL_RING0, tmp);

	if (!enable) {
		/* read a gfx register */
		tmp = RREG32(mmDB_DEPTH_INFO);

		mask = RLC_BUSY_STATUS | GFX_POWER_STATUS | GFX_CLOCK_STATUS | GFX_LS_STATUS;
		for (i = 0; i < adev->usec_timeout; i++) {
			if ((RREG32(mmRLC_STAT) & mask) == (GFX_CLOCK_STATUS | GFX_POWER_STATUS))
				break;
			udelay(1);
		}
	}
}

static int gfx_v6_0_cp_resume(struct amdgpu_device *adev)
{
	int r;

	gfx_v6_0_enable_gui_idle_interrupt(adev, false);

	r = gfx_v6_0_cp_load_microcode(adev);
	if (r)
		return r;

	r = gfx_v6_0_cp_gfx_resume(adev);
	if (r)
		return r;
	r = gfx_v6_0_cp_compute_resume(adev);
	if (r)
		return r;

	gfx_v6_0_enable_gui_idle_interrupt(adev, true);

	return 0;
}

static void gfx_v6_0_ring_emit_pipeline_sync(struct amdgpu_ring *ring)
{
	int usepfp = (ring->funcs->type == AMDGPU_RING_TYPE_GFX);
	uint32_t seq = ring->fence_drv.sync_seq;
	uint64_t addr = ring->fence_drv.gpu_addr;

	amdgpu_ring_write(ring, PACKET3(PACKET3_WAIT_REG_MEM, 5));
	amdgpu_ring_write(ring, (WAIT_REG_MEM_MEM_SPACE(1) | /* memory */
				 WAIT_REG_MEM_FUNCTION(3) | /* equal */
				 WAIT_REG_MEM_ENGINE(usepfp)));   /* pfp or me */
	amdgpu_ring_write(ring, addr & 0xfffffffc);
	amdgpu_ring_write(ring, upper_32_bits(addr) & 0xffffffff);
	amdgpu_ring_write(ring, seq);
	amdgpu_ring_write(ring, 0xffffffff);
	amdgpu_ring_write(ring, 4); /* poll interval */

	if (usepfp) {
		/* synce CE with ME to prevent CE fetch CEIB before context switch done */
		amdgpu_ring_write(ring, PACKET3(PACKET3_SWITCH_BUFFER, 0));
		amdgpu_ring_write(ring, 0);
		amdgpu_ring_write(ring, PACKET3(PACKET3_SWITCH_BUFFER, 0));
		amdgpu_ring_write(ring, 0);
	}
}

static void gfx_v6_0_ring_emit_vm_flush(struct amdgpu_ring *ring,
					unsigned vm_id, uint64_t pd_addr)
{
	int usepfp = (ring->funcs->type == AMDGPU_RING_TYPE_GFX);

	/* write new base address */
	amdgpu_ring_write(ring, PACKET3(PACKET3_WRITE_DATA, 3));
	amdgpu_ring_write(ring, (WRITE_DATA_ENGINE_SEL(1) |
				 WRITE_DATA_DST_SEL(0)));
	if (vm_id < 8) {
		amdgpu_ring_write(ring, (mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + vm_id ));
	} else {
		amdgpu_ring_write(ring, (mmVM_CONTEXT8_PAGE_TABLE_BASE_ADDR + (vm_id - 8)));
	}
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, pd_addr >> 12);

	/* bits 0-15 are the VM contexts0-15 */
	amdgpu_ring_write(ring, PACKET3(PACKET3_WRITE_DATA, 3));
	amdgpu_ring_write(ring, (WRITE_DATA_ENGINE_SEL(1) |
				 WRITE_DATA_DST_SEL(0)));
	amdgpu_ring_write(ring, mmVM_INVALIDATE_REQUEST);
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, 1 << vm_id);

	/* wait for the invalidate to complete */
	amdgpu_ring_write(ring, PACKET3(PACKET3_WAIT_REG_MEM, 5));
	amdgpu_ring_write(ring, (WAIT_REG_MEM_FUNCTION(0) |  /* always */
				 WAIT_REG_MEM_ENGINE(0))); /* me */
	amdgpu_ring_write(ring, mmVM_INVALIDATE_REQUEST);
	amdgpu_ring_write(ring, 0);
	amdgpu_ring_write(ring, 0); /* ref */
	amdgpu_ring_write(ring, 0); /* mask */
	amdgpu_ring_write(ring, 0x20); /* poll interval */

	if (usepfp) {
		/* sync PFP to ME, otherwise we might get invalid PFP reads */
		amdgpu_ring_write(ring, PACKET3(PACKET3_PFP_SYNC_ME, 0));
		amdgpu_ring_write(ring, 0x0);

		/* synce CE with ME to prevent CE fetch CEIB before context switch done */
		amdgpu_ring_write(ring, PACKET3(PACKET3_SWITCH_BUFFER, 0));
		amdgpu_ring_write(ring, 0);
		amdgpu_ring_write(ring, PACKET3(PACKET3_SWITCH_BUFFER, 0));
		amdgpu_ring_write(ring, 0);
	}
}


static void gfx_v6_0_rlc_fini(struct amdgpu_device *adev)
{
	int r;

	if (adev->gfx.rlc.save_restore_obj) {
		r = amdgpu_bo_reserve(adev->gfx.rlc.save_restore_obj, false);
		if (unlikely(r != 0))
			dev_warn(adev->dev, "(%d) reserve RLC sr bo failed\n", r);
		amdgpu_bo_unpin(adev->gfx.rlc.save_restore_obj);
		amdgpu_bo_unreserve(adev->gfx.rlc.save_restore_obj);

		amdgpu_bo_unref(&adev->gfx.rlc.save_restore_obj);
		adev->gfx.rlc.save_restore_obj = NULL;
	}

	if (adev->gfx.rlc.clear_state_obj) {
		r = amdgpu_bo_reserve(adev->gfx.rlc.clear_state_obj, false);
		if (unlikely(r != 0))
			dev_warn(adev->dev, "(%d) reserve RLC c bo failed\n", r);
		amdgpu_bo_unpin(adev->gfx.rlc.clear_state_obj);
		amdgpu_bo_unreserve(adev->gfx.rlc.clear_state_obj);

		amdgpu_bo_unref(&adev->gfx.rlc.clear_state_obj);
		adev->gfx.rlc.clear_state_obj = NULL;
	}

	if (adev->gfx.rlc.cp_table_obj) {
		r = amdgpu_bo_reserve(adev->gfx.rlc.cp_table_obj, false);
		if (unlikely(r != 0))
			dev_warn(adev->dev, "(%d) reserve RLC cp table bo failed\n", r);
		amdgpu_bo_unpin(adev->gfx.rlc.cp_table_obj);
		amdgpu_bo_unreserve(adev->gfx.rlc.cp_table_obj);

		amdgpu_bo_unref(&adev->gfx.rlc.cp_table_obj);
		adev->gfx.rlc.cp_table_obj = NULL;
	}
}

static int gfx_v6_0_rlc_init(struct amdgpu_device *adev)
{
	const u32 *src_ptr;
	volatile u32 *dst_ptr;
	u32 dws, i;
	u64 reg_list_mc_addr;
	const struct cs_section_def *cs_data;
	int r;

	adev->gfx.rlc.reg_list = verde_rlc_save_restore_register_list;
	adev->gfx.rlc.reg_list_size =
			(u32)ARRAY_SIZE(verde_rlc_save_restore_register_list);

	adev->gfx.rlc.cs_data = si_cs_data;
	src_ptr = adev->gfx.rlc.reg_list;
	dws = adev->gfx.rlc.reg_list_size;
	cs_data = adev->gfx.rlc.cs_data;

	if (src_ptr) {
		/* save restore block */
		if (adev->gfx.rlc.save_restore_obj == NULL) {
			r = amdgpu_bo_create(adev, dws * 4, PAGE_SIZE, true,
					     AMDGPU_GEM_DOMAIN_VRAM,
					     AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED,
					     NULL, NULL,
					     &adev->gfx.rlc.save_restore_obj);

			if (r) {
				dev_warn(adev->dev, "(%d) create RLC sr bo failed\n", r);
				return r;
			}
		}

		r = amdgpu_bo_reserve(adev->gfx.rlc.save_restore_obj, false);
		if (unlikely(r != 0)) {
			gfx_v6_0_rlc_fini(adev);
			return r;
		}
		r = amdgpu_bo_pin(adev->gfx.rlc.save_restore_obj, AMDGPU_GEM_DOMAIN_VRAM,
				  &adev->gfx.rlc.save_restore_gpu_addr);
		if (r) {
			amdgpu_bo_unreserve(adev->gfx.rlc.save_restore_obj);
			dev_warn(adev->dev, "(%d) pin RLC sr bo failed\n", r);
			gfx_v6_0_rlc_fini(adev);
			return r;
		}

		r = amdgpu_bo_kmap(adev->gfx.rlc.save_restore_obj, (void **)&adev->gfx.rlc.sr_ptr);
		if (r) {
			dev_warn(adev->dev, "(%d) map RLC sr bo failed\n", r);
			gfx_v6_0_rlc_fini(adev);
			return r;
		}
		/* write the sr buffer */
		dst_ptr = adev->gfx.rlc.sr_ptr;
		for (i = 0; i < adev->gfx.rlc.reg_list_size; i++)
			dst_ptr[i] = cpu_to_le32(src_ptr[i]);
		amdgpu_bo_kunmap(adev->gfx.rlc.save_restore_obj);
		amdgpu_bo_unreserve(adev->gfx.rlc.save_restore_obj);
	}

	if (cs_data) {
		/* clear state block */
		adev->gfx.rlc.clear_state_size = gfx_v6_0_get_csb_size(adev);
		dws = adev->gfx.rlc.clear_state_size + (256 / 4);

		if (adev->gfx.rlc.clear_state_obj == NULL) {
			r = amdgpu_bo_create(adev, dws * 4, PAGE_SIZE, true,
					     AMDGPU_GEM_DOMAIN_VRAM,
					     AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED,
					     NULL, NULL,
					     &adev->gfx.rlc.clear_state_obj);

			if (r) {
				dev_warn(adev->dev, "(%d) create RLC c bo failed\n", r);
				gfx_v6_0_rlc_fini(adev);
				return r;
			}
		}
		r = amdgpu_bo_reserve(adev->gfx.rlc.clear_state_obj, false);
		if (unlikely(r != 0)) {
			gfx_v6_0_rlc_fini(adev);
			return r;
		}
		r = amdgpu_bo_pin(adev->gfx.rlc.clear_state_obj, AMDGPU_GEM_DOMAIN_VRAM,
				  &adev->gfx.rlc.clear_state_gpu_addr);
		if (r) {
			amdgpu_bo_unreserve(adev->gfx.rlc.clear_state_obj);
			dev_warn(adev->dev, "(%d) pin RLC c bo failed\n", r);
			gfx_v6_0_rlc_fini(adev);
			return r;
		}

		r = amdgpu_bo_kmap(adev->gfx.rlc.clear_state_obj, (void **)&adev->gfx.rlc.cs_ptr);
		if (r) {
			dev_warn(adev->dev, "(%d) map RLC c bo failed\n", r);
			gfx_v6_0_rlc_fini(adev);
			return r;
		}
		/* set up the cs buffer */
		dst_ptr = adev->gfx.rlc.cs_ptr;
		reg_list_mc_addr = adev->gfx.rlc.clear_state_gpu_addr + 256;
		dst_ptr[0] = cpu_to_le32(upper_32_bits(reg_list_mc_addr));
		dst_ptr[1] = cpu_to_le32(lower_32_bits(reg_list_mc_addr));
		dst_ptr[2] = cpu_to_le32(adev->gfx.rlc.clear_state_size);
		gfx_v6_0_get_csb_buffer(adev, &dst_ptr[(256/4)]);
		amdgpu_bo_kunmap(adev->gfx.rlc.clear_state_obj);
		amdgpu_bo_unreserve(adev->gfx.rlc.clear_state_obj);
	}

	return 0;
}

static void gfx_v6_0_enable_lbpw(struct amdgpu_device *adev, bool enable)
{
	WREG32_FIELD(RLC_LB_CNTL, LOAD_BALANCE_ENABLE, enable ? 1 : 0);

	if (!enable) {
		gfx_v6_0_select_se_sh(adev, 0xffffffff, 0xffffffff, 0xffffffff);
		WREG32(mmSPI_LB_CU_MASK, 0x00ff);
	}
}

static void gfx_v6_0_wait_for_rlc_serdes(struct amdgpu_device *adev)
{
	int i;

	for (i = 0; i < adev->usec_timeout; i++) {
		if (RREG32(mmRLC_SERDES_MASTER_BUSY_0) == 0)
			break;
		udelay(1);
	}

	for (i = 0; i < adev->usec_timeout; i++) {
		if (RREG32(mmRLC_SERDES_MASTER_BUSY_1) == 0)
			break;
		udelay(1);
	}
}

static void gfx_v6_0_update_rlc(struct amdgpu_device *adev, u32 rlc)
{
	u32 tmp;

	tmp = RREG32(mmRLC_CNTL);
	if (tmp != rlc)
		WREG32(mmRLC_CNTL, rlc);
}

static u32 gfx_v6_0_halt_rlc(struct amdgpu_device *adev)
{
	u32 data, orig;

	orig = data = RREG32(mmRLC_CNTL);

	if (data & RLC_CNTL__RLC_ENABLE_F32_MASK) {
		data &= ~RLC_CNTL__RLC_ENABLE_F32_MASK;
		WREG32(mmRLC_CNTL, data);

		gfx_v6_0_wait_for_rlc_serdes(adev);
	}

	return orig;
}

static void gfx_v6_0_rlc_stop(struct amdgpu_device *adev)
{
	WREG32(mmRLC_CNTL, 0);

	gfx_v6_0_enable_gui_idle_interrupt(adev, false);
	gfx_v6_0_wait_for_rlc_serdes(adev);
}

static void gfx_v6_0_rlc_start(struct amdgpu_device *adev)
{
	WREG32(mmRLC_CNTL, RLC_CNTL__RLC_ENABLE_F32_MASK);

	gfx_v6_0_enable_gui_idle_interrupt(adev, true);

	udelay(50);
}

static void gfx_v6_0_rlc_reset(struct amdgpu_device *adev)
{
	WREG32_FIELD(GRBM_SOFT_RESET, SOFT_RESET_RLC, 1);
	udelay(50);
	WREG32_FIELD(GRBM_SOFT_RESET, SOFT_RESET_RLC, 0);
	udelay(50);
}

static bool gfx_v6_0_lbpw_supported(struct amdgpu_device *adev)
{
	u32 tmp;

	/* Enable LBPW only for DDR3 */
	tmp = RREG32(mmMC_SEQ_MISC0);
	if ((tmp & 0xF0000000) == 0xB0000000)
		return true;
	return false;
}

static void gfx_v6_0_init_cg(struct amdgpu_device *adev)
{
}

static int gfx_v6_0_rlc_resume(struct amdgpu_device *adev)
{
	u32 i;
	const struct rlc_firmware_header_v1_0 *hdr;
	const __le32 *fw_data;
	u32 fw_size;


	if (!adev->gfx.rlc_fw)
		return -EINVAL;

	gfx_v6_0_rlc_stop(adev);
	gfx_v6_0_rlc_reset(adev);
	gfx_v6_0_init_pg(adev);
	gfx_v6_0_init_cg(adev);

	WREG32(mmRLC_RL_BASE, 0);
	WREG32(mmRLC_RL_SIZE, 0);
	WREG32(mmRLC_LB_CNTL, 0);
	WREG32(mmRLC_LB_CNTR_MAX, 0xffffffff);
	WREG32(mmRLC_LB_CNTR_INIT, 0);
	WREG32(mmRLC_LB_INIT_CU_MASK, 0xffffffff);

	WREG32(mmRLC_MC_CNTL, 0);
	WREG32(mmRLC_UCODE_CNTL, 0);

	hdr = (const struct rlc_firmware_header_v1_0 *)adev->gfx.rlc_fw->data;
	fw_size = le32_to_cpu(hdr->header.ucode_size_bytes) / 4;
	fw_data = (const __le32 *)
		(adev->gfx.rlc_fw->data + le32_to_cpu(hdr->header.ucode_array_offset_bytes));

	amdgpu_ucode_print_rlc_hdr(&hdr->header);

	for (i = 0; i < fw_size; i++) {
		WREG32(mmRLC_UCODE_ADDR, i);
		WREG32(mmRLC_UCODE_DATA, le32_to_cpup(fw_data++));
	}
	WREG32(mmRLC_UCODE_ADDR, 0);

	gfx_v6_0_enable_lbpw(adev, gfx_v6_0_lbpw_supported(adev));
	gfx_v6_0_rlc_start(adev);

	return 0;
}

static void gfx_v6_0_enable_cgcg(struct amdgpu_device *adev, bool enable)
{
	u32 data, orig, tmp;

	orig = data = RREG32(mmRLC_CGCG_CGLS_CTRL);

	if (enable && (adev->cg_flags & AMD_CG_SUPPORT_GFX_CGCG)) {
		gfx_v6_0_enable_gui_idle_interrupt(adev, true);

		WREG32(mmRLC_GCPM_GENERAL_3, 0x00000080);

		tmp = gfx_v6_0_halt_rlc(adev);

		WREG32(mmRLC_SERDES_WR_MASTER_MASK_0, 0xffffffff);
		WREG32(mmRLC_SERDES_WR_MASTER_MASK_1, 0xffffffff);
		WREG32(mmRLC_SERDES_WR_CTRL, 0x00b000ff);

		gfx_v6_0_wait_for_rlc_serdes(adev);
		gfx_v6_0_update_rlc(adev, tmp);

		WREG32(mmRLC_SERDES_WR_CTRL, 0x007000ff);

		data |= RLC_CGCG_CGLS_CTRL__CGCG_EN_MASK | RLC_CGCG_CGLS_CTRL__CGLS_EN_MASK;
	} else {
		gfx_v6_0_enable_gui_idle_interrupt(adev, false);

		RREG32(mmCB_CGTT_SCLK_CTRL);
		RREG32(mmCB_CGTT_SCLK_CTRL);
		RREG32(mmCB_CGTT_SCLK_CTRL);
		RREG32(mmCB_CGTT_SCLK_CTRL);

		data &= ~(RLC_CGCG_CGLS_CTRL__CGCG_EN_MASK | RLC_CGCG_CGLS_CTRL__CGLS_EN_MASK);
	}

	if (orig != data)
		WREG32(mmRLC_CGCG_CGLS_CTRL, data);

}

static void gfx_v6_0_enable_mgcg(struct amdgpu_device *adev, bool enable)
{

	u32 data, orig, tmp = 0;

	if (enable && (adev->cg_flags & AMD_CG_SUPPORT_GFX_MGCG)) {
		orig = data = RREG32(mmCGTS_SM_CTRL_REG);
		data = 0x96940200;
		if (orig != data)
			WREG32(mmCGTS_SM_CTRL_REG, data);

		if (adev->cg_flags & AMD_CG_SUPPORT_GFX_CP_LS) {
			orig = data = RREG32(mmCP_MEM_SLP_CNTL);
			data |= CP_MEM_SLP_CNTL__CP_MEM_LS_EN_MASK;
			if (orig != data)
				WREG32(mmCP_MEM_SLP_CNTL, data);
		}

		orig = data = RREG32(mmRLC_CGTT_MGCG_OVERRIDE);
		data &= 0xffffffc0;
		if (orig != data)
			WREG32(mmRLC_CGTT_MGCG_OVERRIDE, data);

		tmp = gfx_v6_0_halt_rlc(adev);

		WREG32(mmRLC_SERDES_WR_MASTER_MASK_0, 0xffffffff);
		WREG32(mmRLC_SERDES_WR_MASTER_MASK_1, 0xffffffff);
		WREG32(mmRLC_SERDES_WR_CTRL, 0x00d000ff);

		gfx_v6_0_update_rlc(adev, tmp);
	} else {
		orig = data = RREG32(mmRLC_CGTT_MGCG_OVERRIDE);
		data |= 0x00000003;
		if (orig != data)
			WREG32(mmRLC_CGTT_MGCG_OVERRIDE, data);

		data = RREG32(mmCP_MEM_SLP_CNTL);
		if (data & CP_MEM_SLP_CNTL__CP_MEM_LS_EN_MASK) {
			data &= ~CP_MEM_SLP_CNTL__CP_MEM_LS_EN_MASK;
			WREG32(mmCP_MEM_SLP_CNTL, data);
		}
		orig = data = RREG32(mmCGTS_SM_CTRL_REG);
		data |= CGTS_SM_CTRL_REG__LS_OVERRIDE_MASK | CGTS_SM_CTRL_REG__OVERRIDE_MASK;
		if (orig != data)
			WREG32(mmCGTS_SM_CTRL_REG, data);

		tmp = gfx_v6_0_halt_rlc(adev);

		WREG32(mmRLC_SERDES_WR_MASTER_MASK_0, 0xffffffff);
		WREG32(mmRLC_SERDES_WR_MASTER_MASK_1, 0xffffffff);
		WREG32(mmRLC_SERDES_WR_CTRL, 0x00e000ff);

		gfx_v6_0_update_rlc(adev, tmp);
	}
}
/*
static void gfx_v6_0_update_cg(struct amdgpu_device *adev,
			       bool enable)
{
	gfx_v6_0_enable_gui_idle_interrupt(adev, false);
	if (enable) {
		gfx_v6_0_enable_mgcg(adev, true);
		gfx_v6_0_enable_cgcg(adev, true);
	} else {
		gfx_v6_0_enable_cgcg(adev, false);
		gfx_v6_0_enable_mgcg(adev, false);
	}
	gfx_v6_0_enable_gui_idle_interrupt(adev, true);
}
*/

static void gfx_v6_0_enable_sclk_slowdown_on_pu(struct amdgpu_device *adev,
						bool enable)
{
}

static void gfx_v6_0_enable_sclk_slowdown_on_pd(struct amdgpu_device *adev,
						bool enable)
{
}

static void gfx_v6_0_enable_cp_pg(struct amdgpu_device *adev, bool enable)
{
	u32 data, orig;

	orig = data = RREG32(mmRLC_PG_CNTL);
	if (enable && (adev->pg_flags & AMD_PG_SUPPORT_CP))
		data &= ~0x8000;
	else
		data |= 0x8000;
	if (orig != data)
		WREG32(mmRLC_PG_CNTL, data);
}

static void gfx_v6_0_enable_gds_pg(struct amdgpu_device *adev, bool enable)
{
}
/*
static void gfx_v6_0_init_cp_pg_table(struct amdgpu_device *adev)
{
	const __le32 *fw_data;
	volatile u32 *dst_ptr;
	int me, i, max_me = 4;
	u32 bo_offset = 0;
	u32 table_offset, table_size;

	if (adev->asic_type == CHIP_KAVERI)
		max_me = 5;

	if (adev->gfx.rlc.cp_table_ptr == NULL)
		return;

	dst_ptr = adev->gfx.rlc.cp_table_ptr;
	for (me = 0; me < max_me; me++) {
		if (me == 0) {
			const struct gfx_firmware_header_v1_0 *hdr =
				(const struct gfx_firmware_header_v1_0 *)adev->gfx.ce_fw->data;
			fw_data = (const __le32 *)
				(adev->gfx.ce_fw->data +
				 le32_to_cpu(hdr->header.ucode_array_offset_bytes));
			table_offset = le32_to_cpu(hdr->jt_offset);
			table_size = le32_to_cpu(hdr->jt_size);
		} else if (me == 1) {
			const struct gfx_firmware_header_v1_0 *hdr =
				(const struct gfx_firmware_header_v1_0 *)adev->gfx.pfp_fw->data;
			fw_data = (const __le32 *)
				(adev->gfx.pfp_fw->data +
				 le32_to_cpu(hdr->header.ucode_array_offset_bytes));
			table_offset = le32_to_cpu(hdr->jt_offset);
			table_size = le32_to_cpu(hdr->jt_size);
		} else if (me == 2) {
			const struct gfx_firmware_header_v1_0 *hdr =
				(const struct gfx_firmware_header_v1_0 *)adev->gfx.me_fw->data;
			fw_data = (const __le32 *)
				(adev->gfx.me_fw->data +
				 le32_to_cpu(hdr->header.ucode_array_offset_bytes));
			table_offset = le32_to_cpu(hdr->jt_offset);
			table_size = le32_to_cpu(hdr->jt_size);
		} else if (me == 3) {
			const struct gfx_firmware_header_v1_0 *hdr =
				(const struct gfx_firmware_header_v1_0 *)adev->gfx.mec_fw->data;
			fw_data = (const __le32 *)
				(adev->gfx.mec_fw->data +
				 le32_to_cpu(hdr->header.ucode_array_offset_bytes));
			table_offset = le32_to_cpu(hdr->jt_offset);
			table_size = le32_to_cpu(hdr->jt_size);
		} else {
			const struct gfx_firmware_header_v1_0 *hdr =
				(const struct gfx_firmware_header_v1_0 *)adev->gfx.mec2_fw->data;
			fw_data = (const __le32 *)
				(adev->gfx.mec2_fw->data +
				 le32_to_cpu(hdr->header.ucode_array_offset_bytes));
			table_offset = le32_to_cpu(hdr->jt_offset);
			table_size = le32_to_cpu(hdr->jt_size);
		}

		for (i = 0; i < table_size; i ++) {
			dst_ptr[bo_offset + i] =
				cpu_to_le32(le32_to_cpu(fw_data[table_offset + i]));
		}

		bo_offset += table_size;
	}
}
*/
static void gfx_v6_0_enable_gfx_cgpg(struct amdgpu_device *adev,
				     bool enable)
{
	if (enable && (adev->pg_flags & AMD_PG_SUPPORT_GFX_PG)) {
		WREG32(mmRLC_TTOP_D, RLC_PUD(0x10) | RLC_PDD(0x10) | RLC_TTPD(0x10) | RLC_MSD(0x10));
		WREG32_FIELD(RLC_PG_CNTL, GFX_POWER_GATING_ENABLE, 1);
		WREG32_FIELD(RLC_AUTO_PG_CTRL, AUTO_PG_EN, 1);
	} else {
		WREG32_FIELD(RLC_AUTO_PG_CTRL, AUTO_PG_EN, 0);
		(void)RREG32(mmDB_RENDER_CONTROL);
	}
}

static void gfx_v6_0_init_ao_cu_mask(struct amdgpu_device *adev)
{
	u32 tmp;

	WREG32(mmRLC_PG_ALWAYS_ON_CU_MASK, adev->gfx.cu_info.ao_cu_mask);

	tmp = RREG32(mmRLC_MAX_PG_CU);
	tmp &= ~RLC_MAX_PG_CU__MAX_POWERED_UP_CU_MASK;
	tmp |= (adev->gfx.cu_info.number << RLC_MAX_PG_CU__MAX_POWERED_UP_CU__SHIFT);
	WREG32(mmRLC_MAX_PG_CU, tmp);
}

static void gfx_v6_0_enable_gfx_static_mgpg(struct amdgpu_device *adev,
					    bool enable)
{
	u32 data, orig;

	orig = data = RREG32(mmRLC_PG_CNTL);
	if (enable && (adev->pg_flags & AMD_PG_SUPPORT_GFX_SMG))
		data |= RLC_PG_CNTL__STATIC_PER_CU_PG_ENABLE_MASK;
	else
		data &= ~RLC_PG_CNTL__STATIC_PER_CU_PG_ENABLE_MASK;
	if (orig != data)
		WREG32(mmRLC_PG_CNTL, data);
}

static void gfx_v6_0_enable_gfx_dynamic_mgpg(struct amdgpu_device *adev,
					     bool enable)
{
	u32 data, orig;

	orig = data = RREG32(mmRLC_PG_CNTL);
	if (enable && (adev->pg_flags & AMD_PG_SUPPORT_GFX_DMG))
		data |= RLC_PG_CNTL__DYN_PER_CU_PG_ENABLE_MASK;
	else
		data &= ~RLC_PG_CNTL__DYN_PER_CU_PG_ENABLE_MASK;
	if (orig != data)
		WREG32(mmRLC_PG_CNTL, data);
}

static void gfx_v6_0_init_gfx_cgpg(struct amdgpu_device *adev)
{
	u32 tmp;

	WREG32(mmRLC_SAVE_AND_RESTORE_BASE, adev->gfx.rlc.save_restore_gpu_addr >> 8);
	WREG32_FIELD(RLC_PG_CNTL, GFX_POWER_GATING_SRC, 1);
	WREG32(mmRLC_CLEAR_STATE_RESTORE_BASE, adev->gfx.rlc.clear_state_gpu_addr >> 8);

	tmp = RREG32(mmRLC_AUTO_PG_CTRL);
	tmp &= ~RLC_AUTO_PG_CTRL__GRBM_REG_SAVE_GFX_IDLE_THRESHOLD_MASK;
	tmp |= (0x700 << RLC_AUTO_PG_CTRL__GRBM_REG_SAVE_GFX_IDLE_THRESHOLD__SHIFT);
	tmp &= ~RLC_AUTO_PG_CTRL__PG_AFTER_GRBM_REG_SAVE_THRESHOLD_MASK;
	WREG32(mmRLC_AUTO_PG_CTRL, tmp);
}

static void gfx_v6_0_update_gfx_pg(struct amdgpu_device *adev, bool enable)
{
	gfx_v6_0_enable_gfx_cgpg(adev, enable);
	gfx_v6_0_enable_gfx_static_mgpg(adev, enable);
	gfx_v6_0_enable_gfx_dynamic_mgpg(adev, enable);
}

static u32 gfx_v6_0_get_csb_size(struct amdgpu_device *adev)
{
	u32 count = 0;
	const struct cs_section_def *sect = NULL;
	const struct cs_extent_def *ext = NULL;

	if (adev->gfx.rlc.cs_data == NULL)
		return 0;

	/* begin clear state */
	count += 2;
	/* context control state */
	count += 3;

	for (sect = adev->gfx.rlc.cs_data; sect->section != NULL; ++sect) {
		for (ext = sect->section; ext->extent != NULL; ++ext) {
			if (sect->id == SECT_CONTEXT)
				count += 2 + ext->reg_count;
			else
				return 0;
		}
	}
	/* pa_sc_raster_config */
	count += 3;
	/* end clear state */
	count += 2;
	/* clear state */
	count += 2;

	return count;
}

static void gfx_v6_0_get_csb_buffer(struct amdgpu_device *adev,
				    volatile u32 *buffer)
{
	u32 count = 0, i;
	const struct cs_section_def *sect = NULL;
	const struct cs_extent_def *ext = NULL;

	if (adev->gfx.rlc.cs_data == NULL)
		return;
	if (buffer == NULL)
		return;

	buffer[count++] = cpu_to_le32(PACKET3(PACKET3_PREAMBLE_CNTL, 0));
	buffer[count++] = cpu_to_le32(PACKET3_PREAMBLE_BEGIN_CLEAR_STATE);
	buffer[count++] = cpu_to_le32(PACKET3(PACKET3_CONTEXT_CONTROL, 1));
	buffer[count++] = cpu_to_le32(0x80000000);
	buffer[count++] = cpu_to_le32(0x80000000);

	for (sect = adev->gfx.rlc.cs_data; sect->section != NULL; ++sect) {
		for (ext = sect->section; ext->extent != NULL; ++ext) {
			if (sect->id == SECT_CONTEXT) {
				buffer[count++] =
					cpu_to_le32(PACKET3(PACKET3_SET_CONTEXT_REG, ext->reg_count));
				buffer[count++] = cpu_to_le32(ext->reg_index - 0xa000);
				for (i = 0; i < ext->reg_count; i++)
					buffer[count++] = cpu_to_le32(ext->extent[i]);
			} else {
				return;
			}
		}
	}

	buffer[count++] = cpu_to_le32(PACKET3(PACKET3_SET_CONTEXT_REG, 1));
	buffer[count++] = cpu_to_le32(mmPA_SC_RASTER_CONFIG - PACKET3_SET_CONTEXT_REG_START);

	switch (adev->asic_type) {
	case CHIP_TAHITI:
	case CHIP_PITCAIRN:
		buffer[count++] = cpu_to_le32(0x2a00126a);
		break;
	case CHIP_VERDE:
		buffer[count++] = cpu_to_le32(0x0000124a);
		break;
	case CHIP_OLAND:
		buffer[count++] = cpu_to_le32(0x00000082);
		break;
	case CHIP_HAINAN:
		buffer[count++] = cpu_to_le32(0x00000000);
		break;
	default:
		buffer[count++] = cpu_to_le32(0x00000000);
		break;
	}

	buffer[count++] = cpu_to_le32(PACKET3(PACKET3_PREAMBLE_CNTL, 0));
	buffer[count++] = cpu_to_le32(PACKET3_PREAMBLE_END_CLEAR_STATE);

	buffer[count++] = cpu_to_le32(PACKET3(PACKET3_CLEAR_STATE, 0));
	buffer[count++] = cpu_to_le32(0);
}

static void gfx_v6_0_init_pg(struct amdgpu_device *adev)
{
	if (adev->pg_flags & (AMD_PG_SUPPORT_GFX_PG |
			      AMD_PG_SUPPORT_GFX_SMG |
			      AMD_PG_SUPPORT_GFX_DMG |
			      AMD_PG_SUPPORT_CP |
			      AMD_PG_SUPPORT_GDS |
			      AMD_PG_SUPPORT_RLC_SMU_HS)) {
		gfx_v6_0_enable_sclk_slowdown_on_pu(adev, true);
		gfx_v6_0_enable_sclk_slowdown_on_pd(adev, true);
		if (adev->pg_flags & AMD_PG_SUPPORT_GFX_PG) {
			gfx_v6_0_init_gfx_cgpg(adev);
			gfx_v6_0_enable_cp_pg(adev, true);
			gfx_v6_0_enable_gds_pg(adev, true);
		} else {
			WREG32(mmRLC_SAVE_AND_RESTORE_BASE, adev->gfx.rlc.save_restore_gpu_addr >> 8);
			WREG32(mmRLC_CLEAR_STATE_RESTORE_BASE, adev->gfx.rlc.clear_state_gpu_addr >> 8);

		}
		gfx_v6_0_init_ao_cu_mask(adev);
		gfx_v6_0_update_gfx_pg(adev, true);
	} else {

		WREG32(mmRLC_SAVE_AND_RESTORE_BASE, adev->gfx.rlc.save_restore_gpu_addr >> 8);
		WREG32(mmRLC_CLEAR_STATE_RESTORE_BASE, adev->gfx.rlc.clear_state_gpu_addr >> 8);
	}
}

static void gfx_v6_0_fini_pg(struct amdgpu_device *adev)
{
	if (adev->pg_flags & (AMD_PG_SUPPORT_GFX_PG |
			      AMD_PG_SUPPORT_GFX_SMG |
			      AMD_PG_SUPPORT_GFX_DMG |
			      AMD_PG_SUPPORT_CP |
			      AMD_PG_SUPPORT_GDS |
			      AMD_PG_SUPPORT_RLC_SMU_HS)) {
		gfx_v6_0_update_gfx_pg(adev, false);
		if (adev->pg_flags & AMD_PG_SUPPORT_GFX_PG) {
			gfx_v6_0_enable_cp_pg(adev, false);
			gfx_v6_0_enable_gds_pg(adev, false);
		}
	}
}

static uint64_t gfx_v6_0_get_gpu_clock_counter(struct amdgpu_device *adev)
{
	uint64_t clock;

	mutex_lock(&adev->gfx.gpu_clock_mutex);
	WREG32(mmRLC_CAPTURE_GPU_CLOCK_COUNT, 1);
	clock = (uint64_t)RREG32(mmRLC_GPU_CLOCK_COUNT_LSB) |
	        ((uint64_t)RREG32(mmRLC_GPU_CLOCK_COUNT_MSB) << 32ULL);
	mutex_unlock(&adev->gfx.gpu_clock_mutex);
	return clock;
}

static void gfx_v6_ring_emit_cntxcntl(struct amdgpu_ring *ring, uint32_t flags)
{
	if (flags & AMDGPU_HAVE_CTX_SWITCH)
		gfx_v6_0_ring_emit_vgt_flush(ring);
	amdgpu_ring_write(ring, PACKET3(PACKET3_CONTEXT_CONTROL, 1));
	amdgpu_ring_write(ring, 0x80000000);
	amdgpu_ring_write(ring, 0);
}


static uint32_t wave_read_ind(struct amdgpu_device *adev, uint32_t simd, uint32_t wave, uint32_t address)
{
	WREG32(mmSQ_IND_INDEX,
		(wave << SQ_IND_INDEX__WAVE_ID__SHIFT) |
		(simd << SQ_IND_INDEX__SIMD_ID__SHIFT) |
		(address << SQ_IND_INDEX__INDEX__SHIFT) |
		(SQ_IND_INDEX__FORCE_READ_MASK));
	return RREG32(mmSQ_IND_DATA);
}

static void wave_read_regs(struct amdgpu_device *adev, uint32_t simd,
			   uint32_t wave, uint32_t thread,
			   uint32_t regno, uint32_t num, uint32_t *out)
{
	WREG32(mmSQ_IND_INDEX,
		(wave << SQ_IND_INDEX__WAVE_ID__SHIFT) |
		(simd << SQ_IND_INDEX__SIMD_ID__SHIFT) |
		(regno << SQ_IND_INDEX__INDEX__SHIFT) |
		(thread << SQ_IND_INDEX__THREAD_ID__SHIFT) |
		(SQ_IND_INDEX__FORCE_READ_MASK) |
		(SQ_IND_INDEX__AUTO_INCR_MASK));
	while (num--)
		*(out++) = RREG32(mmSQ_IND_DATA);
}

static void gfx_v6_0_read_wave_data(struct amdgpu_device *adev, uint32_t simd, uint32_t wave, uint32_t *dst, int *no_fields)
{
	/* type 0 wave data */
	dst[(*no_fields)++] = 0;
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_STATUS);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_PC_LO);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_PC_HI);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_EXEC_LO);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_EXEC_HI);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_HW_ID);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_INST_DW0);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_INST_DW1);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_GPR_ALLOC);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_LDS_ALLOC);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_TRAPSTS);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_IB_STS);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_TBA_LO);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_TBA_HI);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_TMA_LO);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_TMA_HI);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_IB_DBG0);
	dst[(*no_fields)++] = wave_read_ind(adev, simd, wave, ixSQ_WAVE_M0);
}

static void gfx_v6_0_read_wave_sgprs(struct amdgpu_device *adev, uint32_t simd,
				     uint32_t wave, uint32_t start,
				     uint32_t size, uint32_t *dst)
{
	wave_read_regs(
		adev, simd, wave, 0,
		start + SQIND_WAVE_SGPRS_OFFSET, size, dst);
}

static const struct amdgpu_gfx_funcs gfx_v6_0_gfx_funcs = {
	.get_gpu_clock_counter = &gfx_v6_0_get_gpu_clock_counter,
	.select_se_sh = &gfx_v6_0_select_se_sh,
	.read_wave_data = &gfx_v6_0_read_wave_data,
	.read_wave_sgprs = &gfx_v6_0_read_wave_sgprs,
};

static int gfx_v6_0_early_init(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	adev->gfx.num_gfx_rings = GFX6_NUM_GFX_RINGS;
	adev->gfx.num_compute_rings = GFX6_NUM_COMPUTE_RINGS;
	adev->gfx.funcs = &gfx_v6_0_gfx_funcs;
	gfx_v6_0_set_ring_funcs(adev);
	gfx_v6_0_set_irq_funcs(adev);

	return 0;
}

static int gfx_v6_0_sw_init(void *handle)
{
	struct amdgpu_ring *ring;
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;
	int i, r;

	r = amdgpu_irq_add_id(adev, 181, &adev->gfx.eop_irq);
	if (r)
		return r;

	r = amdgpu_irq_add_id(adev, 184, &adev->gfx.priv_reg_irq);
	if (r)
		return r;

	r = amdgpu_irq_add_id(adev, 185, &adev->gfx.priv_inst_irq);
	if (r)
		return r;

	gfx_v6_0_scratch_init(adev);

	r = gfx_v6_0_init_microcode(adev);
	if (r) {
		DRM_ERROR("Failed to load gfx firmware!\n");
		return r;
	}

	r = gfx_v6_0_rlc_init(adev);
	if (r) {
		DRM_ERROR("Failed to init rlc BOs!\n");
		return r;
	}

	for (i = 0; i < adev->gfx.num_gfx_rings; i++) {
		ring = &adev->gfx.gfx_ring[i];
		ring->ring_obj = NULL;
		sprintf(ring->name, "gfx");
		r = amdgpu_ring_init(adev, ring, 1024,
				     &adev->gfx.eop_irq, AMDGPU_CP_IRQ_GFX_EOP);
		if (r)
			return r;
	}

	for (i = 0; i < adev->gfx.num_compute_rings; i++) {
		unsigned irq_type;

		if ((i >= 32) || (i >= AMDGPU_MAX_COMPUTE_RINGS)) {
			DRM_ERROR("Too many (%d) compute rings!\n", i);
			break;
		}
		ring = &adev->gfx.compute_ring[i];
		ring->ring_obj = NULL;
		ring->use_doorbell = false;
		ring->doorbell_index = 0;
		ring->me = 1;
		ring->pipe = i;
		ring->queue = i;
		sprintf(ring->name, "comp %d.%d.%d", ring->me, ring->pipe, ring->queue);
		irq_type = AMDGPU_CP_IRQ_COMPUTE_MEC1_PIPE0_EOP + ring->pipe;
		r = amdgpu_ring_init(adev, ring, 1024,
				     &adev->gfx.eop_irq, irq_type);
		if (r)
			return r;
	}

	return r;
}

static int gfx_v6_0_sw_fini(void *handle)
{
	int i;
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	amdgpu_bo_unref(&adev->gds.oa_gfx_bo);
	amdgpu_bo_unref(&adev->gds.gws_gfx_bo);
	amdgpu_bo_unref(&adev->gds.gds_gfx_bo);

	for (i = 0; i < adev->gfx.num_gfx_rings; i++)
		amdgpu_ring_fini(&adev->gfx.gfx_ring[i]);
	for (i = 0; i < adev->gfx.num_compute_rings; i++)
		amdgpu_ring_fini(&adev->gfx.compute_ring[i]);

	gfx_v6_0_rlc_fini(adev);

	return 0;
}

static int gfx_v6_0_hw_init(void *handle)
{
	int r;
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	gfx_v6_0_gpu_init(adev);

	r = gfx_v6_0_rlc_resume(adev);
	if (r)
		return r;

	r = gfx_v6_0_cp_resume(adev);
	if (r)
		return r;

	adev->gfx.ce_ram_size = 0x8000;

	return r;
}

static int gfx_v6_0_hw_fini(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	gfx_v6_0_cp_enable(adev, false);
	gfx_v6_0_rlc_stop(adev);
	gfx_v6_0_fini_pg(adev);

	return 0;
}

static int gfx_v6_0_suspend(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	return gfx_v6_0_hw_fini(adev);
}

static int gfx_v6_0_resume(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	return gfx_v6_0_hw_init(adev);
}

static bool gfx_v6_0_is_idle(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	if (RREG32(mmGRBM_STATUS) & GRBM_STATUS__GUI_ACTIVE_MASK)
		return false;
	else
		return true;
}

static int gfx_v6_0_wait_for_idle(void *handle)
{
	unsigned i;
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	for (i = 0; i < adev->usec_timeout; i++) {
		if (gfx_v6_0_is_idle(handle))
			return 0;
		udelay(1);
	}
	return -ETIMEDOUT;
}

static int gfx_v6_0_soft_reset(void *handle)
{
	return 0;
}

static void gfx_v6_0_set_gfx_eop_interrupt_state(struct amdgpu_device *adev,
						 enum amdgpu_interrupt_state state)
{
	u32 cp_int_cntl;

	switch (state) {
	case AMDGPU_IRQ_STATE_DISABLE:
		cp_int_cntl = RREG32(mmCP_INT_CNTL_RING0);
		cp_int_cntl &= ~CP_INT_CNTL_RING0__TIME_STAMP_INT_ENABLE_MASK;
		WREG32(mmCP_INT_CNTL_RING0, cp_int_cntl);
		break;
	case AMDGPU_IRQ_STATE_ENABLE:
		cp_int_cntl = RREG32(mmCP_INT_CNTL_RING0);
		cp_int_cntl |= CP_INT_CNTL_RING0__TIME_STAMP_INT_ENABLE_MASK;
		WREG32(mmCP_INT_CNTL_RING0, cp_int_cntl);
		break;
	default:
		break;
	}
}

static void gfx_v6_0_set_compute_eop_interrupt_state(struct amdgpu_device *adev,
						     int ring,
						     enum amdgpu_interrupt_state state)
{
	u32 cp_int_cntl;
	switch (state){
	case AMDGPU_IRQ_STATE_DISABLE:
		if (ring == 0) {
			cp_int_cntl = RREG32(mmCP_INT_CNTL_RING1);
			cp_int_cntl &= ~CP_INT_CNTL_RING1__TIME_STAMP_INT_ENABLE_MASK;
			WREG32(mmCP_INT_CNTL_RING1, cp_int_cntl);
			break;
		} else {
			cp_int_cntl = RREG32(mmCP_INT_CNTL_RING2);
			cp_int_cntl &= ~CP_INT_CNTL_RING2__TIME_STAMP_INT_ENABLE_MASK;
			WREG32(mmCP_INT_CNTL_RING2, cp_int_cntl);
			break;

		}
	case AMDGPU_IRQ_STATE_ENABLE:
		if (ring == 0) {
			cp_int_cntl = RREG32(mmCP_INT_CNTL_RING1);
			cp_int_cntl |= CP_INT_CNTL_RING1__TIME_STAMP_INT_ENABLE_MASK;
			WREG32(mmCP_INT_CNTL_RING1, cp_int_cntl);
			break;
		} else {
			cp_int_cntl = RREG32(mmCP_INT_CNTL_RING2);
			cp_int_cntl |= CP_INT_CNTL_RING2__TIME_STAMP_INT_ENABLE_MASK;
			WREG32(mmCP_INT_CNTL_RING2, cp_int_cntl);
			break;

		}

	default:
		BUG();
		break;

	}
}

static int gfx_v6_0_set_priv_reg_fault_state(struct amdgpu_device *adev,
					     struct amdgpu_irq_src *src,
					     unsigned type,
					     enum amdgpu_interrupt_state state)
{
	u32 cp_int_cntl;

	switch (state) {
	case AMDGPU_IRQ_STATE_DISABLE:
		cp_int_cntl = RREG32(mmCP_INT_CNTL_RING0);
		cp_int_cntl &= ~CP_INT_CNTL_RING0__PRIV_REG_INT_ENABLE_MASK;
		WREG32(mmCP_INT_CNTL_RING0, cp_int_cntl);
		break;
	case AMDGPU_IRQ_STATE_ENABLE:
		cp_int_cntl = RREG32(mmCP_INT_CNTL_RING0);
		cp_int_cntl |= CP_INT_CNTL_RING0__PRIV_REG_INT_ENABLE_MASK;
		WREG32(mmCP_INT_CNTL_RING0, cp_int_cntl);
		break;
	default:
		break;
	}

	return 0;
}

static int gfx_v6_0_set_priv_inst_fault_state(struct amdgpu_device *adev,
					      struct amdgpu_irq_src *src,
					      unsigned type,
					      enum amdgpu_interrupt_state state)
{
	u32 cp_int_cntl;

	switch (state) {
	case AMDGPU_IRQ_STATE_DISABLE:
		cp_int_cntl = RREG32(mmCP_INT_CNTL_RING0);
		cp_int_cntl &= ~CP_INT_CNTL_RING0__PRIV_INSTR_INT_ENABLE_MASK;
		WREG32(mmCP_INT_CNTL_RING0, cp_int_cntl);
		break;
	case AMDGPU_IRQ_STATE_ENABLE:
		cp_int_cntl = RREG32(mmCP_INT_CNTL_RING0);
		cp_int_cntl |= CP_INT_CNTL_RING0__PRIV_INSTR_INT_ENABLE_MASK;
		WREG32(mmCP_INT_CNTL_RING0, cp_int_cntl);
		break;
	default:
		break;
	}

	return 0;
}

static int gfx_v6_0_set_eop_interrupt_state(struct amdgpu_device *adev,
					    struct amdgpu_irq_src *src,
					    unsigned type,
					    enum amdgpu_interrupt_state state)
{
	switch (type) {
	case AMDGPU_CP_IRQ_GFX_EOP:
		gfx_v6_0_set_gfx_eop_interrupt_state(adev, state);
		break;
	case AMDGPU_CP_IRQ_COMPUTE_MEC1_PIPE0_EOP:
		gfx_v6_0_set_compute_eop_interrupt_state(adev, 0, state);
		break;
	case AMDGPU_CP_IRQ_COMPUTE_MEC1_PIPE1_EOP:
		gfx_v6_0_set_compute_eop_interrupt_state(adev, 1, state);
		break;
	default:
		break;
	}
	return 0;
}

static int gfx_v6_0_eop_irq(struct amdgpu_device *adev,
			    struct amdgpu_irq_src *source,
			    struct amdgpu_iv_entry *entry)
{
	switch (entry->ring_id) {
	case 0:
		amdgpu_fence_process(&adev->gfx.gfx_ring[0]);
		break;
	case 1:
	case 2:
		amdgpu_fence_process(&adev->gfx.compute_ring[entry->ring_id - 1]);
		break;
	default:
		break;
	}
	return 0;
}

static int gfx_v6_0_priv_reg_irq(struct amdgpu_device *adev,
				 struct amdgpu_irq_src *source,
				 struct amdgpu_iv_entry *entry)
{
	DRM_ERROR("Illegal register access in command stream\n");
	schedule_work(&adev->reset_work);
	return 0;
}

static int gfx_v6_0_priv_inst_irq(struct amdgpu_device *adev,
				  struct amdgpu_irq_src *source,
				  struct amdgpu_iv_entry *entry)
{
	DRM_ERROR("Illegal instruction in command stream\n");
	schedule_work(&adev->reset_work);
	return 0;
}

static int gfx_v6_0_set_clockgating_state(void *handle,
					  enum amd_clockgating_state state)
{
	bool gate = false;
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	if (state == AMD_CG_STATE_GATE)
		gate = true;

	gfx_v6_0_enable_gui_idle_interrupt(adev, false);
	if (gate) {
		gfx_v6_0_enable_mgcg(adev, true);
		gfx_v6_0_enable_cgcg(adev, true);
	} else {
		gfx_v6_0_enable_cgcg(adev, false);
		gfx_v6_0_enable_mgcg(adev, false);
	}
	gfx_v6_0_enable_gui_idle_interrupt(adev, true);

	return 0;
}

static int gfx_v6_0_set_powergating_state(void *handle,
					  enum amd_powergating_state state)
{
	bool gate = false;
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	if (state == AMD_PG_STATE_GATE)
		gate = true;

	if (adev->pg_flags & (AMD_PG_SUPPORT_GFX_PG |
			      AMD_PG_SUPPORT_GFX_SMG |
			      AMD_PG_SUPPORT_GFX_DMG |
			      AMD_PG_SUPPORT_CP |
			      AMD_PG_SUPPORT_GDS |
			      AMD_PG_SUPPORT_RLC_SMU_HS)) {
		gfx_v6_0_update_gfx_pg(adev, gate);
		if (adev->pg_flags & AMD_PG_SUPPORT_GFX_PG) {
			gfx_v6_0_enable_cp_pg(adev, gate);
			gfx_v6_0_enable_gds_pg(adev, gate);
		}
	}

	return 0;
}

static const struct amd_ip_funcs gfx_v6_0_ip_funcs = {
	.name = "gfx_v6_0",
	.early_init = gfx_v6_0_early_init,
	.late_init = NULL,
	.sw_init = gfx_v6_0_sw_init,
	.sw_fini = gfx_v6_0_sw_fini,
	.hw_init = gfx_v6_0_hw_init,
	.hw_fini = gfx_v6_0_hw_fini,
	.suspend = gfx_v6_0_suspend,
	.resume = gfx_v6_0_resume,
	.is_idle = gfx_v6_0_is_idle,
	.wait_for_idle = gfx_v6_0_wait_for_idle,
	.soft_reset = gfx_v6_0_soft_reset,
	.set_clockgating_state = gfx_v6_0_set_clockgating_state,
	.set_powergating_state = gfx_v6_0_set_powergating_state,
};

static const struct amdgpu_ring_funcs gfx_v6_0_ring_funcs_gfx = {
	.type = AMDGPU_RING_TYPE_GFX,
	.align_mask = 0xff,
	.nop = 0x80000000,
	.get_rptr = gfx_v6_0_ring_get_rptr,
	.get_wptr = gfx_v6_0_ring_get_wptr,
	.set_wptr = gfx_v6_0_ring_set_wptr_gfx,
	.emit_frame_size =
		5 + /* gfx_v6_0_ring_emit_hdp_flush */
		5 + /* gfx_v6_0_ring_emit_hdp_invalidate */
		14 + 14 + 14 + /* gfx_v6_0_ring_emit_fence x3 for user fence, vm fence */
		7 + 4 + /* gfx_v6_0_ring_emit_pipeline_sync */
		17 + 6 + /* gfx_v6_0_ring_emit_vm_flush */
		3 + 2, /* gfx_v6_ring_emit_cntxcntl including vgt flush */
	.emit_ib_size = 6, /* gfx_v6_0_ring_emit_ib */
	.emit_ib = gfx_v6_0_ring_emit_ib,
	.emit_fence = gfx_v6_0_ring_emit_fence,
	.emit_pipeline_sync = gfx_v6_0_ring_emit_pipeline_sync,
	.emit_vm_flush = gfx_v6_0_ring_emit_vm_flush,
	.emit_hdp_flush = gfx_v6_0_ring_emit_hdp_flush,
	.emit_hdp_invalidate = gfx_v6_0_ring_emit_hdp_invalidate,
	.test_ring = gfx_v6_0_ring_test_ring,
	.test_ib = gfx_v6_0_ring_test_ib,
	.insert_nop = amdgpu_ring_insert_nop,
	.emit_cntxcntl = gfx_v6_ring_emit_cntxcntl,
};

static const struct amdgpu_ring_funcs gfx_v6_0_ring_funcs_compute = {
	.type = AMDGPU_RING_TYPE_COMPUTE,
	.align_mask = 0xff,
	.nop = 0x80000000,
	.get_rptr = gfx_v6_0_ring_get_rptr,
	.get_wptr = gfx_v6_0_ring_get_wptr,
	.set_wptr = gfx_v6_0_ring_set_wptr_compute,
	.emit_frame_size =
		5 + /* gfx_v6_0_ring_emit_hdp_flush */
		5 + /* gfx_v6_0_ring_emit_hdp_invalidate */
		7 + /* gfx_v6_0_ring_emit_pipeline_sync */
		17 + /* gfx_v6_0_ring_emit_vm_flush */
		14 + 14 + 14, /* gfx_v6_0_ring_emit_fence x3 for user fence, vm fence */
	.emit_ib_size = 6, /* gfx_v6_0_ring_emit_ib */
	.emit_ib = gfx_v6_0_ring_emit_ib,
	.emit_fence = gfx_v6_0_ring_emit_fence,
	.emit_pipeline_sync = gfx_v6_0_ring_emit_pipeline_sync,
	.emit_vm_flush = gfx_v6_0_ring_emit_vm_flush,
	.emit_hdp_flush = gfx_v6_0_ring_emit_hdp_flush,
	.emit_hdp_invalidate = gfx_v6_0_ring_emit_hdp_invalidate,
	.test_ring = gfx_v6_0_ring_test_ring,
	.test_ib = gfx_v6_0_ring_test_ib,
	.insert_nop = amdgpu_ring_insert_nop,
};

static void gfx_v6_0_set_ring_funcs(struct amdgpu_device *adev)
{
	int i;

	for (i = 0; i < adev->gfx.num_gfx_rings; i++)
		adev->gfx.gfx_ring[i].funcs = &gfx_v6_0_ring_funcs_gfx;
	for (i = 0; i < adev->gfx.num_compute_rings; i++)
		adev->gfx.compute_ring[i].funcs = &gfx_v6_0_ring_funcs_compute;
}

static const struct amdgpu_irq_src_funcs gfx_v6_0_eop_irq_funcs = {
	.set = gfx_v6_0_set_eop_interrupt_state,
	.process = gfx_v6_0_eop_irq,
};

static const struct amdgpu_irq_src_funcs gfx_v6_0_priv_reg_irq_funcs = {
	.set = gfx_v6_0_set_priv_reg_fault_state,
	.process = gfx_v6_0_priv_reg_irq,
};

static const struct amdgpu_irq_src_funcs gfx_v6_0_priv_inst_irq_funcs = {
	.set = gfx_v6_0_set_priv_inst_fault_state,
	.process = gfx_v6_0_priv_inst_irq,
};

static void gfx_v6_0_set_irq_funcs(struct amdgpu_device *adev)
{
	adev->gfx.eop_irq.num_types = AMDGPU_CP_IRQ_LAST;
	adev->gfx.eop_irq.funcs = &gfx_v6_0_eop_irq_funcs;

	adev->gfx.priv_reg_irq.num_types = 1;
	adev->gfx.priv_reg_irq.funcs = &gfx_v6_0_priv_reg_irq_funcs;

	adev->gfx.priv_inst_irq.num_types = 1;
	adev->gfx.priv_inst_irq.funcs = &gfx_v6_0_priv_inst_irq_funcs;
}

static void gfx_v6_0_get_cu_info(struct amdgpu_device *adev)
{
	int i, j, k, counter, active_cu_number = 0;
	u32 mask, bitmap, ao_bitmap, ao_cu_mask = 0;
	struct amdgpu_cu_info *cu_info = &adev->gfx.cu_info;
	unsigned disable_masks[4 * 2];

	memset(cu_info, 0, sizeof(*cu_info));

	amdgpu_gfx_parse_disable_cu(disable_masks, 4, 2);

	mutex_lock(&adev->grbm_idx_mutex);
	for (i = 0; i < adev->gfx.config.max_shader_engines; i++) {
		for (j = 0; j < adev->gfx.config.max_sh_per_se; j++) {
			mask = 1;
			ao_bitmap = 0;
			counter = 0;
			gfx_v6_0_select_se_sh(adev, i, j, 0xffffffff);
			if (i < 4 && j < 2)
				gfx_v6_0_set_user_cu_inactive_bitmap(
					adev, disable_masks[i * 2 + j]);
			bitmap = gfx_v6_0_get_cu_enabled(adev);
			cu_info->bitmap[i][j] = bitmap;

			for (k = 0; k < 16; k++) {
				if (bitmap & mask) {
					if (counter < 2)
						ao_bitmap |= mask;
					counter ++;
				}
				mask <<= 1;
			}
			active_cu_number += counter;
			ao_cu_mask |= (ao_bitmap << (i * 16 + j * 8));
		}
	}

	gfx_v6_0_select_se_sh(adev, 0xffffffff, 0xffffffff, 0xffffffff);
	mutex_unlock(&adev->grbm_idx_mutex);

	cu_info->number = active_cu_number;
	cu_info->ao_cu_mask = ao_cu_mask;
}

const struct amdgpu_ip_block_version gfx_v6_0_ip_block =
{
	.type = AMD_IP_BLOCK_TYPE_GFX,
	.major = 6,
	.minor = 0,
	.rev = 0,
	.funcs = &gfx_v6_0_ip_funcs,
};
