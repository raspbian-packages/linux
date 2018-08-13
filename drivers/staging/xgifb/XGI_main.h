/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XGIFB_MAIN
#define _XGIFB_MAIN
/* ------------------- Constant Definitions ------------------------- */
#include "XGIfb.h"
#include "vb_def.h"

#define PCI_DEVICE_ID_XGI_42      0x042
#define PCI_DEVICE_ID_XGI_27      0x027

static const struct pci_device_id xgifb_pci_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_XGI, PCI_DEVICE_ID_XGI_20)},
	{PCI_DEVICE(PCI_VENDOR_ID_XGI, PCI_DEVICE_ID_XGI_27)},
	{PCI_DEVICE(PCI_VENDOR_ID_XGI, PCI_DEVICE_ID_XGI_40)},
	{PCI_DEVICE(PCI_VENDOR_ID_XGI, PCI_DEVICE_ID_XGI_42)},
	{0}
};

MODULE_DEVICE_TABLE(pci, xgifb_pci_table);

#define IND_XGI_SCRATCH_REG_CR30  0x30  /* CRs */
#define IND_XGI_SCRATCH_REG_CR31  0x31
#define IND_XGI_SCRATCH_REG_CR32  0x32
#define IND_XGI_SCRATCH_REG_CR33  0x33
#define IND_XGI_LCD_PANEL         0x36
#define IND_XGI_SCRATCH_REG_CR37  0x37

#define XGI_DRAM_SIZE_MASK     0xF0  /*SR14 */
#define XGI_DRAM_SIZE_1MB      0x00
#define XGI_DRAM_SIZE_2MB      0x01
#define XGI_DRAM_SIZE_4MB      0x02
#define XGI_DRAM_SIZE_8MB      0x03
#define XGI_DRAM_SIZE_16MB     0x04
#define XGI_DRAM_SIZE_32MB     0x05
#define XGI_DRAM_SIZE_64MB     0x06
#define XGI_DRAM_SIZE_128MB    0x07
#define XGI_DRAM_SIZE_256MB    0x08

/* ------------------- Global Variables ----------------------------- */

/* display status */
static int XGIfb_crt1off;
static int XGIfb_forcecrt1 = -1;

/* global flags */
static int XGIfb_tvmode;
static int enable_dstn;
static int XGIfb_ypan = -1;

/* TW: CRT2 type (for overriding autodetection) */
static int XGIfb_crt2type = -1;
/* PR: Tv plug type (for overriding autodetection) */
static int XGIfb_tvplug = -1;

#define MD_XGI315 1

/* mode table */
static const struct _XGIbios_mode {
	u8 mode_no;
	u16 vesa_mode_no_1;  /* "XGI defined" VESA mode number */
	u16 vesa_mode_no_2;  /* Real VESA mode numbers */
	u16 xres;
	u16 yres;
	u16 bpp;
	u8  chipset;
} XGIbios_mode[] = {
	{ 0x56, 0x0000, 0x0000,  320,  240, 16, MD_XGI315 },
	{ 0x5A, 0x0000, 0x0000,  320,  480,  8, MD_XGI315 },
	{ 0x5B, 0x0000, 0x0000,  320,  480, 16, MD_XGI315 },
	{ 0x2E, 0x0101, 0x0101,  640,  480,  8, MD_XGI315 },
	{ 0x44, 0x0111, 0x0111,  640,  480, 16, MD_XGI315 },
	{ 0x62, 0x013a, 0x0112,  640,  480, 32, MD_XGI315 },
	{ 0x31, 0x0000, 0x0000,  720,  480,  8, MD_XGI315 },
	{ 0x33, 0x0000, 0x0000,  720,  480, 16, MD_XGI315 },
	{ 0x35, 0x0000, 0x0000,  720,  480, 32, MD_XGI315 },
	{ 0x32, 0x0000, 0x0000,  720,  576,  8, MD_XGI315 },
	{ 0x34, 0x0000, 0x0000,  720,  576, 16, MD_XGI315 },
	{ 0x36, 0x0000, 0x0000,  720,  576, 32, MD_XGI315 },
	{ 0x36, 0x0000, 0x0000,  720,  576, 32, MD_XGI315 },
	{ 0x70, 0x0000, 0x0000,  800,  480,  8, MD_XGI315 },
	{ 0x7a, 0x0000, 0x0000,  800,  480, 16, MD_XGI315 },
	{ 0x76, 0x0000, 0x0000,  800,  480, 32, MD_XGI315 },
	{ 0x30, 0x0103, 0x0103,  800,  600,  8, MD_XGI315 },
#define DEFAULT_MODE              17 /* index for 800x600x16 */
	{ 0x47, 0x0114, 0x0114,  800,  600, 16, MD_XGI315 },
	{ 0x63, 0x013b, 0x0115,  800,  600, 32, MD_XGI315 },
	{ 0x71, 0x0000, 0x0000, 1024,  576,  8, MD_XGI315 },
	{ 0x74, 0x0000, 0x0000, 1024,  576, 16, MD_XGI315 },
	{ 0x77, 0x0000, 0x0000, 1024,  576, 32, MD_XGI315 },
	{ 0x77, 0x0000, 0x0000, 1024,  576, 32, MD_XGI315 },
	{ 0x20, 0x0000, 0x0000, 1024,  600,  8, },
	{ 0x21, 0x0000, 0x0000, 1024,  600, 16, },
	{ 0x22, 0x0000, 0x0000, 1024,  600, 32, },
	{ 0x38, 0x0105, 0x0105, 1024,  768,  8, MD_XGI315 },
	{ 0x4A, 0x0117, 0x0117, 1024,  768, 16, MD_XGI315 },
	{ 0x64, 0x013c, 0x0118, 1024,  768, 32, MD_XGI315 },
	{ 0x64, 0x013c, 0x0118, 1024,  768, 32, MD_XGI315 },
	{ 0x23, 0x0000, 0x0000, 1152,  768,  8, },
	{ 0x24, 0x0000, 0x0000, 1152,  768, 16, },
	{ 0x25, 0x0000, 0x0000, 1152,  768, 32, },
	{ 0x79, 0x0000, 0x0000, 1280,  720,  8, MD_XGI315 },
	{ 0x75, 0x0000, 0x0000, 1280,  720, 16, MD_XGI315 },
	{ 0x78, 0x0000, 0x0000, 1280,  720, 32, MD_XGI315 },
	{ 0x23, 0x0000, 0x0000, 1280,  768,  8, MD_XGI315 },
	{ 0x24, 0x0000, 0x0000, 1280,  768, 16, MD_XGI315 },
	{ 0x25, 0x0000, 0x0000, 1280,  768, 32, MD_XGI315 },
	{ 0x7C, 0x0000, 0x0000, 1280,  960,  8, MD_XGI315 },
	{ 0x7D, 0x0000, 0x0000, 1280,  960, 16, MD_XGI315 },
	{ 0x7E, 0x0000, 0x0000, 1280,  960, 32, MD_XGI315 },
	{ 0x3A, 0x0107, 0x0107, 1280, 1024,  8, MD_XGI315 },
	{ 0x4D, 0x011a, 0x011a, 1280, 1024, 16, MD_XGI315 },
	{ 0x65, 0x013d, 0x011b, 1280, 1024, 32, MD_XGI315 },
	{ 0x26, 0x0000, 0x0000, 1400, 1050,  8, MD_XGI315 },
	{ 0x27, 0x0000, 0x0000, 1400, 1050, 16, MD_XGI315 },
	{ 0x28, 0x0000, 0x0000, 1400, 1050, 32, MD_XGI315 },
	{ 0x3C, 0x0130, 0x011c, 1600, 1200,  8, MD_XGI315 },
	{ 0x3D, 0x0131, 0x011e, 1600, 1200, 16, MD_XGI315 },
	{ 0x66, 0x013e, 0x011f, 1600, 1200, 32, MD_XGI315 },
	{ 0x68, 0x013f, 0x0000, 1920, 1440,  8, MD_XGI315 },
	{ 0x69, 0x0140, 0x0000, 1920, 1440, 16, MD_XGI315 },
	{ 0x6B, 0x0141, 0x0000, 1920, 1440, 32, MD_XGI315 },
	{ 0x6c, 0x0000, 0x0000, 2048, 1536,  8, MD_XGI315 },
	{ 0x6d, 0x0000, 0x0000, 2048, 1536, 16, MD_XGI315 },
	{ 0x6e, 0x0000, 0x0000, 2048, 1536, 32, MD_XGI315 },
	{ 0 },
};

static const unsigned short XGI310paneltype[] = {
	 LCD_UNKNOWN,   LCD_800x600, LCD_1024x768, LCD_1280x1024,
	 LCD_640x480,  LCD_1024x600, LCD_1152x864,  LCD_1280x960,
	LCD_1152x768, LCD_1400x1050, LCD_1280x768, LCD_1600x1200,
	LCD_1024x768,  LCD_1024x768, LCD_1024x768};

static const struct _XGI_crt2type {
	char name[10];
	int type_no;
	int tvplug_no;
} XGI_crt2type[] = {
	{"NONE",	0,		-1},
	{"LCD",		XGIFB_DISP_LCD,	-1},
	{"TV",		XGIFB_DISP_TV,	-1},
	{"VGA",		XGIFB_DISP_CRT,	-1},
	{"SVIDEO",	XGIFB_DISP_TV,	TVPLUG_SVIDEO},
	{"COMPOSITE",	XGIFB_DISP_TV,	TVPLUG_COMPOSITE},
	{"SCART",	XGIFB_DISP_TV,	TVPLUG_SCART},
	{"none",	0,		-1},
	{"lcd",		XGIFB_DISP_LCD,	-1},
	{"tv",		XGIFB_DISP_TV,	-1},
	{"vga",		XGIFB_DISP_CRT,	-1},
	{"svideo",	XGIFB_DISP_TV,	TVPLUG_SVIDEO},
	{"composite",	XGIFB_DISP_TV,	TVPLUG_COMPOSITE},
	{"scart",	XGIFB_DISP_TV,	TVPLUG_SCART},
	{"\0",		-1,		-1}
};

/* TV standard */
static const struct _XGI_tvtype {
	char name[6];
	int type_no;
} XGI_tvtype[] = {
	{"PAL",		1},
	{"NTSC",	2},
	{"pal",		1},
	{"ntsc",	2},
	{"\0",	       -1}
};

static const struct _XGI_vrate {
	u16 idx;
	u16 xres;
	u16 yres;
	u16 refresh;
} XGIfb_vrate[] = {
	{1,  640,  480,  60}, {2,  640,  480,  72},
	{3,  640,  480,  75}, {4,  640,  480,  85},

	{5,  640,  480, 100}, {6,  640,  480, 120},
	{7,  640,  480, 160}, {8,  640,  480, 200},

	{1,  720,  480,  60},
	{1,  720,  576,  58},
	{1,  800,  480,  60}, {2,  800,  480,  75}, {3,  800,  480,  85},
	{1,  800,  600,  60}, {2,  800,  600,  72}, {3,  800,  600,  75},
	{4,  800,  600,  85}, {5,  800,  600, 100},
	{6,  800,  600, 120}, {7,  800,  600, 160},

	{1, 1024,  768,  60}, {2, 1024,  768,  70}, {3, 1024,  768,  75},
	{4, 1024,  768,  85}, {5, 1024,  768, 100}, {6, 1024,  768, 120},
	{1, 1024,  576,  60}, {2, 1024,  576,  75}, {3, 1024,  576,  85},
	{1, 1024,  600,  60},
	{1, 1152,  768,  60},
	{1, 1280,  720,  60}, {2, 1280,  720,  75}, {3, 1280,  720,  85},
	{1, 1280,  768,  60},
	{1, 1280, 1024,  60}, {2, 1280, 1024,  75}, {3, 1280, 1024,  85},
	{1, 1280,  960,  70},
	{1, 1400, 1050,  60},
	{1, 1600, 1200,  60}, {2, 1600, 1200,  65},
	{3, 1600, 1200,  70}, {4, 1600, 1200,  75},

	{5, 1600, 1200,  85}, {6, 1600, 1200, 100},
	{7, 1600, 1200, 120},

	{1, 1920, 1440,  60}, {2, 1920, 1440,  65},
	{3, 1920, 1440,  70}, {4, 1920, 1440,  75},

	{5, 1920, 1440,  85}, {6, 1920, 1440, 100},
	{1, 2048, 1536,  60}, {2, 2048, 1536,  65},
	{3, 2048, 1536,  70}, {4, 2048, 1536,  75},

	{5, 2048, 1536,  85},
	{0,    0,    0,   0}
};

static const struct _XGI_TV_filter {
	u8 filter[9][4];
} XGI_TV_filter[] = {
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_0 */
	    {0x00, 0xE0, 0x10, 0x60},
	    {0x00, 0xEE, 0x10, 0x44},
	    {0x00, 0xF4, 0x10, 0x38},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xFC, 0xFB, 0x14, 0x2A},
	    {0x00, 0x00, 0x10, 0x20},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_1 */
	    {0x00, 0xE0, 0x10, 0x60},
	    {0x00, 0xEE, 0x10, 0x44},
	    {0x00, 0xF4, 0x10, 0x38},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xFC, 0xFB, 0x14, 0x2A},
	    {0x00, 0x00, 0x10, 0x20},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_2 */
	    {0xF5, 0xEE, 0x1B, 0x44},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xEB, 0x04, 0x25, 0x18},
	    {0xF1, 0x05, 0x1F, 0x16},
	    {0xF6, 0x06, 0x1A, 0x14},
	    {0xFA, 0x06, 0x16, 0x14},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_3 */
	    {0xF1, 0x04, 0x1F, 0x18},
	    {0xEE, 0x0D, 0x22, 0x06},
	    {0xF7, 0x06, 0x19, 0x14},
	    {0xF4, 0x0B, 0x1C, 0x0A},
	    {0xFA, 0x07, 0x16, 0x12},
	    {0xF9, 0x0A, 0x17, 0x0C},
	    {0x00, 0x07, 0x10, 0x12},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_4 */
	    {0x00, 0xE0, 0x10, 0x60},
	    {0x00, 0xEE, 0x10, 0x44},
	    {0x00, 0xF4, 0x10, 0x38},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xFC, 0xFB, 0x14, 0x2A},
	    {0x00, 0x00, 0x10, 0x20},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_5 */
	    {0xF5, 0xEE, 0x1B, 0x44},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xEB, 0x04, 0x25, 0x18},
	    {0xF1, 0x05, 0x1F, 0x16},
	    {0xF6, 0x06, 0x1A, 0x14},
	    {0xFA, 0x06, 0x16, 0x14},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_6 */
	    {0xEB, 0x04, 0x25, 0x18},
	    {0xE7, 0x0E, 0x29, 0x04},
	    {0xEE, 0x0C, 0x22, 0x08},
	    {0xF6, 0x0B, 0x1A, 0x0A},
	    {0xF9, 0x0A, 0x17, 0x0C},
	    {0xFC, 0x0A, 0x14, 0x0C},
	    {0x00, 0x08, 0x10, 0x10},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* NTSCFilter_7 */
	    {0xEC, 0x02, 0x24, 0x1C},
	    {0xF2, 0x04, 0x1E, 0x18},
	    {0xEB, 0x15, 0x25, 0xF6},
	    {0xF4, 0x10, 0x1C, 0x00},
	    {0xF8, 0x0F, 0x18, 0x02},
	    {0x00, 0x04, 0x10, 0x18},
	    {0x01, 0x06, 0x0F, 0x14},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_0 */
	    {0x00, 0xE0, 0x10, 0x60},
	    {0x00, 0xEE, 0x10, 0x44},
	    {0x00, 0xF4, 0x10, 0x38},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xFC, 0xFB, 0x14, 0x2A},
	    {0x00, 0x00, 0x10, 0x20},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_1 */
	    {0x00, 0xE0, 0x10, 0x60},
	    {0x00, 0xEE, 0x10, 0x44},
	    {0x00, 0xF4, 0x10, 0x38},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xFC, 0xFB, 0x14, 0x2A},
	    {0x00, 0x00, 0x10, 0x20},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_2 */
	    {0xF5, 0xEE, 0x1B, 0x44},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xF1, 0xF7, 0x01, 0x32},
	    {0xF5, 0xFB, 0x1B, 0x2A},
	    {0xF9, 0xFF, 0x17, 0x22},
	    {0xFB, 0x01, 0x15, 0x1E},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_3 */
	    {0xF5, 0xFB, 0x1B, 0x2A},
	    {0xEE, 0xFE, 0x22, 0x24},
	    {0xF3, 0x00, 0x1D, 0x20},
	    {0xF9, 0x03, 0x17, 0x1A},
	    {0xFB, 0x02, 0x14, 0x1E},
	    {0xFB, 0x04, 0x15, 0x18},
	    {0x00, 0x06, 0x10, 0x14},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_4 */
	    {0x00, 0xE0, 0x10, 0x60},
	    {0x00, 0xEE, 0x10, 0x44},
	    {0x00, 0xF4, 0x10, 0x38},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xFC, 0xFB, 0x14, 0x2A},
	    {0x00, 0x00, 0x10, 0x20},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_5 */
	    {0xF5, 0xEE, 0x1B, 0x44},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xF1, 0xF7, 0x1F, 0x32},
	    {0xF5, 0xFB, 0x1B, 0x2A},
	    {0xF9, 0xFF, 0x17, 0x22},
	    {0xFB, 0x01, 0x15, 0x1E},
	    {0x00, 0x04, 0x10, 0x18},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_6 */
	    {0xF5, 0xEE, 0x1B, 0x2A},
	    {0xEE, 0xFE, 0x22, 0x24},
	    {0xF3, 0x00, 0x1D, 0x20},
	    {0xF9, 0x03, 0x17, 0x1A},
	    {0xFB, 0x02, 0x14, 0x1E},
	    {0xFB, 0x04, 0x15, 0x18},
	    {0x00, 0x06, 0x10, 0x14},
	    {0xFF, 0xFF, 0xFF, 0xFF} } },
	{ { {0x00, 0x00, 0x00, 0x40},  /* PALFilter_7 */
	    {0xF5, 0xEE, 0x1B, 0x44},
	    {0xF8, 0xF4, 0x18, 0x38},
	    {0xFC, 0xFB, 0x14, 0x2A},
	    {0xEB, 0x05, 0x25, 0x16},
	    {0xF1, 0x05, 0x1F, 0x16},
	    {0xFA, 0x07, 0x16, 0x12},
	    {0x00, 0x07, 0x10, 0x12},
	    {0xFF, 0xFF, 0xFF, 0xFF} } }
};

static int           filter = -1;

#endif
