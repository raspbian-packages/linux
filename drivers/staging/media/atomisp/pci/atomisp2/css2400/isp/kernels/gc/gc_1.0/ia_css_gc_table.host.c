/*
 * Support for Intel Camera Imaging ISP subsystem.
 * Copyright (c) 2015, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <type_support.h>
#include <string_support.h> /* memcpy */
#include "system_global.h"
#include "vamem.h"
#include "ia_css_types.h"
#include "ia_css_gc_table.host.h"

#if defined(HAS_VAMEM_VERSION_2)

struct ia_css_gamma_table default_gamma_table;

static const uint16_t
default_gamma_table_data[IA_CSS_VAMEM_2_GAMMA_TABLE_SIZE] = {
  0,   4,   8,  12,  17,  21,  27,  32,
 38,  44,  49,  55,  61,  66,  71,  76,
 80,  84,  88,  92,  95,  98, 102, 105,
108, 110, 113, 116, 118, 121, 123, 126,
128, 130, 132, 135, 137, 139, 141, 143,
145, 146, 148, 150, 152, 153, 155, 156,
158, 160, 161, 162, 164, 165, 166, 168,
169, 170, 171, 172, 174, 175, 176, 177,
178, 179, 180, 181, 182, 183, 184, 184,
185, 186, 187, 188, 189, 189, 190, 191,
192, 192, 193, 194, 195, 195, 196, 197,
197, 198, 198, 199, 200, 200, 201, 201,
202, 203, 203, 204, 204, 205, 205, 206,
206, 207, 207, 208, 208, 209, 209, 210,
210, 210, 211, 211, 212, 212, 213, 213,
214, 214, 214, 215, 215, 216, 216, 216,
217, 217, 218, 218, 218, 219, 219, 220,
220, 220, 221, 221, 222, 222, 222, 223,
223, 223, 224, 224, 225, 225, 225, 226,
226, 226, 227, 227, 227, 228, 228, 228,
229, 229, 229, 230, 230, 230, 231, 231,
231, 232, 232, 232, 233, 233, 233, 234,
234, 234, 234, 235, 235, 235, 236, 236,
236, 237, 237, 237, 237, 238, 238, 238,
239, 239, 239, 239, 240, 240, 240, 241,
241, 241, 241, 242, 242, 242, 242, 243,
243, 243, 243, 244, 244, 244, 245, 245,
245, 245, 246, 246, 246, 246, 247, 247,
247, 247, 248, 248, 248, 248, 249, 249,
249, 249, 250, 250, 250, 250, 251, 251,
251, 251, 252, 252, 252, 252, 253, 253,
253, 253, 254, 254, 254, 254, 255, 255,
255
};

#elif defined(HAS_VAMEM_VERSION_1)

static const uint16_t
default_gamma_table_data[IA_CSS_VAMEM_1_GAMMA_TABLE_SIZE] = {
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 16,
		17, 18, 19, 20, 21, 23, 24, 25,
		27, 28, 29, 31, 32, 33, 35, 36,
		38, 39, 41, 42, 44, 45, 47, 48,
		49, 51, 52, 54, 55, 57, 58, 60,
		61, 62, 64, 65, 66, 68, 69, 70,
		71, 72, 74, 75, 76, 77, 78, 79,
		80, 81, 82, 83, 84, 85, 86, 87,
		88, 89, 90, 91, 92, 93, 93, 94,
		95, 96, 97, 98, 98, 99, 100, 101,
		102, 102, 103, 104, 105, 105, 106, 107,
		108, 108, 109, 110, 110, 111, 112, 112,
		113, 114, 114, 115, 116, 116, 117, 118,
		118, 119, 120, 120, 121, 121, 122, 123,
		123, 124, 125, 125, 126, 126, 127, 127,	/* 128 */
		128, 129, 129, 130, 130, 131, 131, 132,
		132, 133, 134, 134, 135, 135, 136, 136,
		137, 137, 138, 138, 139, 139, 140, 140,
		141, 141, 142, 142, 143, 143, 144, 144,
		145, 145, 145, 146, 146, 147, 147, 148,
		148, 149, 149, 150, 150, 150, 151, 151,
		152, 152, 152, 153, 153, 154, 154, 155,
		155, 155, 156, 156, 156, 157, 157, 158,
		158, 158, 159, 159, 160, 160, 160, 161,
		161, 161, 162, 162, 162, 163, 163, 163,
		164, 164, 164, 165, 165, 165, 166, 166,
		166, 167, 167, 167, 168, 168, 168, 169,
		169, 169, 170, 170, 170, 170, 171, 171,
		171, 172, 172, 172, 172, 173, 173, 173,
		174, 174, 174, 174, 175, 175, 175, 176,
		176, 176, 176, 177, 177, 177, 177, 178,	/* 256 */
		178, 178, 178, 179, 179, 179, 179, 180,
		180, 180, 180, 181, 181, 181, 181, 182,
		182, 182, 182, 182, 183, 183, 183, 183,
		184, 184, 184, 184, 184, 185, 185, 185,
		185, 186, 186, 186, 186, 186, 187, 187,
		187, 187, 187, 188, 188, 188, 188, 188,
		189, 189, 189, 189, 189, 190, 190, 190,
		190, 190, 191, 191, 191, 191, 191, 192,
		192, 192, 192, 192, 192, 193, 193, 193,
		193, 193, 194, 194, 194, 194, 194, 194,
		195, 195, 195, 195, 195, 195, 196, 196,
		196, 196, 196, 196, 197, 197, 197, 197,
		197, 197, 198, 198, 198, 198, 198, 198,
		198, 199, 199, 199, 199, 199, 199, 200,
		200, 200, 200, 200, 200, 200, 201, 201,
		201, 201, 201, 201, 201, 202, 202, 202,	/* 384 */
		202, 202, 202, 202, 203, 203, 203, 203,
		203, 203, 203, 204, 204, 204, 204, 204,
		204, 204, 204, 205, 205, 205, 205, 205,
		205, 205, 205, 206, 206, 206, 206, 206,
		206, 206, 206, 207, 207, 207, 207, 207,
		207, 207, 207, 208, 208, 208, 208, 208,
		208, 208, 208, 209, 209, 209, 209, 209,
		209, 209, 209, 209, 210, 210, 210, 210,
		210, 210, 210, 210, 210, 211, 211, 211,
		211, 211, 211, 211, 211, 211, 212, 212,
		212, 212, 212, 212, 212, 212, 212, 213,
		213, 213, 213, 213, 213, 213, 213, 213,
		214, 214, 214, 214, 214, 214, 214, 214,
		214, 214, 215, 215, 215, 215, 215, 215,
		215, 215, 215, 216, 216, 216, 216, 216,
		216, 216, 216, 216, 216, 217, 217, 217,	/* 512 */
		217, 217, 217, 217, 217, 217, 217, 218,
		218, 218, 218, 218, 218, 218, 218, 218,
		218, 219, 219, 219, 219, 219, 219, 219,
		219, 219, 219, 220, 220, 220, 220, 220,
		220, 220, 220, 220, 220, 221, 221, 221,
		221, 221, 221, 221, 221, 221, 221, 221,
		222, 222, 222, 222, 222, 222, 222, 222,
		222, 222, 223, 223, 223, 223, 223, 223,
		223, 223, 223, 223, 223, 224, 224, 224,
		224, 224, 224, 224, 224, 224, 224, 224,
		225, 225, 225, 225, 225, 225, 225, 225,
		225, 225, 225, 226, 226, 226, 226, 226,
		226, 226, 226, 226, 226, 226, 226, 227,
		227, 227, 227, 227, 227, 227, 227, 227,
		227, 227, 228, 228, 228, 228, 228, 228,
		228, 228, 228, 228, 228, 228, 229, 229,
		229, 229, 229, 229, 229, 229, 229, 229,
		229, 229, 230, 230, 230, 230, 230, 230,
		230, 230, 230, 230, 230, 230, 231, 231,
		231, 231, 231, 231, 231, 231, 231, 231,
		231, 231, 231, 232, 232, 232, 232, 232,
		232, 232, 232, 232, 232, 232, 232, 233,
		233, 233, 233, 233, 233, 233, 233, 233,
		233, 233, 233, 233, 234, 234, 234, 234,
		234, 234, 234, 234, 234, 234, 234, 234,
		234, 235, 235, 235, 235, 235, 235, 235,
		235, 235, 235, 235, 235, 235, 236, 236,
		236, 236, 236, 236, 236, 236, 236, 236,
		236, 236, 236, 236, 237, 237, 237, 237,
		237, 237, 237, 237, 237, 237, 237, 237,
		237, 237, 238, 238, 238, 238, 238, 238,
		238, 238, 238, 238, 238, 238, 238, 238,
		239, 239, 239, 239, 239, 239, 239, 239,
		239, 239, 239, 239, 239, 239, 240, 240,
		240, 240, 240, 240, 240, 240, 240, 240,
		240, 240, 240, 240, 241, 241, 241, 241,
		241, 241, 241, 241, 241, 241, 241, 241,
		241, 241, 241, 242, 242, 242, 242, 242,
		242, 242, 242, 242, 242, 242, 242, 242,
		242, 242, 243, 243, 243, 243, 243, 243,
		243, 243, 243, 243, 243, 243, 243, 243,
		243, 244, 244, 244, 244, 244, 244, 244,
		244, 244, 244, 244, 244, 244, 244, 244,
		245, 245, 245, 245, 245, 245, 245, 245,
		245, 245, 245, 245, 245, 245, 245, 246,
		246, 246, 246, 246, 246, 246, 246, 246,
		246, 246, 246, 246, 246, 246, 246, 247,
		247, 247, 247, 247, 247, 247, 247, 247,
		247, 247, 247, 247, 247, 247, 247, 248,
		248, 248, 248, 248, 248, 248, 248, 248,
		248, 248, 248, 248, 248, 248, 248, 249,
		249, 249, 249, 249, 249, 249, 249, 249,
		249, 249, 249, 249, 249, 249, 249, 250,
		250, 250, 250, 250, 250, 250, 250, 250,
		250, 250, 250, 250, 250, 250, 250, 251,
		251, 251, 251, 251, 251, 251, 251, 251,
		251, 251, 251, 251, 251, 251, 251, 252,
		252, 252, 252, 252, 252, 252, 252, 252,
		252, 252, 252, 252, 252, 252, 252, 253,
		253, 253, 253, 253, 253, 253, 253, 253,
		253, 253, 253, 253, 253, 253, 253, 253,
		254, 254, 254, 254, 254, 254, 254, 254,
		254, 254, 254, 254, 254, 254, 254, 254,
		255, 255, 255, 255, 255, 255, 255, 255
};

#else
#error "VAMEM version must be one of {VAMEM_VERSION_1, VAMEM_VERSION_2}"
#endif

void
ia_css_config_gamma_table(void)
{
#if defined(HAS_VAMEM_VERSION_2)
	memcpy(default_gamma_table.data.vamem_2, default_gamma_table_data,
	       sizeof(default_gamma_table_data));
	default_gamma_table.vamem_type   = IA_CSS_VAMEM_TYPE_2;
#else
	memcpy(default_gamma_table.data.vamem_1, default_gamma_table_data,
	       sizeof(default_gamma_table_data));
	default_gamma_table.vamem_type   = IA_CSS_VAMEM_TYPE_1;
#endif
}

