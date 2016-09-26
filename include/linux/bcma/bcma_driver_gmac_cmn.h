#ifndef LINUX_BCMA_DRIVER_GMAC_CMN_H_
#define LINUX_BCMA_DRIVER_GMAC_CMN_H_

#include <linux/types.h>

#define BCMA_GMAC_CMN_STAG0		0x000
#define BCMA_GMAC_CMN_STAG1		0x004
#define BCMA_GMAC_CMN_STAG2		0x008
#define BCMA_GMAC_CMN_STAG3		0x00C
#define BCMA_GMAC_CMN_PARSER_CTL	0x020
#define BCMA_GMAC_CMN_MIB_MAX_LEN	0x024
#define BCMA_GMAC_CMN_PHY_ACCESS	0x100
#define  BCMA_GMAC_CMN_PA_DATA_MASK	0x0000ffff
#define  BCMA_GMAC_CMN_PA_ADDR_MASK	0x001f0000
#define  BCMA_GMAC_CMN_PA_ADDR_SHIFT	16
#define  BCMA_GMAC_CMN_PA_REG_MASK	0x1f000000
#define  BCMA_GMAC_CMN_PA_REG_SHIFT	24
#define  BCMA_GMAC_CMN_PA_WRITE		0x20000000
#define  BCMA_GMAC_CMN_PA_START		0x40000000
#define BCMA_GMAC_CMN_PHY_CTL		0x104
#define  BCMA_GMAC_CMN_PC_EPA_MASK	0x0000001f
#define  BCMA_GMAC_CMN_PC_MCT_MASK	0x007f0000
#define  BCMA_GMAC_CMN_PC_MCT_SHIFT	16
#define  BCMA_GMAC_CMN_PC_MTE		0x00800000
#define BCMA_GMAC_CMN_GMAC0_RGMII_CTL	0x110
#define BCMA_GMAC_CMN_CFP_ACCESS	0x200
#define BCMA_GMAC_CMN_CFP_TCAM_DATA0	0x210
#define BCMA_GMAC_CMN_CFP_TCAM_DATA1	0x214
#define BCMA_GMAC_CMN_CFP_TCAM_DATA2	0x218
#define BCMA_GMAC_CMN_CFP_TCAM_DATA3	0x21C
#define BCMA_GMAC_CMN_CFP_TCAM_DATA4	0x220
#define BCMA_GMAC_CMN_CFP_TCAM_DATA5	0x224
#define BCMA_GMAC_CMN_CFP_TCAM_DATA6	0x228
#define BCMA_GMAC_CMN_CFP_TCAM_DATA7	0x22C
#define BCMA_GMAC_CMN_CFP_TCAM_MASK0	0x230
#define BCMA_GMAC_CMN_CFP_TCAM_MASK1	0x234
#define BCMA_GMAC_CMN_CFP_TCAM_MASK2	0x238
#define BCMA_GMAC_CMN_CFP_TCAM_MASK3	0x23C
#define BCMA_GMAC_CMN_CFP_TCAM_MASK4	0x240
#define BCMA_GMAC_CMN_CFP_TCAM_MASK5	0x244
#define BCMA_GMAC_CMN_CFP_TCAM_MASK6	0x248
#define BCMA_GMAC_CMN_CFP_TCAM_MASK7	0x24C
#define BCMA_GMAC_CMN_CFP_ACTION_DATA	0x250
#define BCMA_GMAC_CMN_TCAM_BIST_CTL	0x2A0
#define BCMA_GMAC_CMN_TCAM_BIST_STATUS	0x2A4
#define BCMA_GMAC_CMN_TCAM_CMP_STATUS	0x2A8
#define BCMA_GMAC_CMN_TCAM_DISABLE	0x2AC
#define BCMA_GMAC_CMN_TCAM_TEST_CTL	0x2F0
#define BCMA_GMAC_CMN_UDF_0_A3_A0	0x300
#define BCMA_GMAC_CMN_UDF_0_A7_A4	0x304
#define BCMA_GMAC_CMN_UDF_0_A8		0x308
#define BCMA_GMAC_CMN_UDF_1_A3_A0	0x310
#define BCMA_GMAC_CMN_UDF_1_A7_A4	0x314
#define BCMA_GMAC_CMN_UDF_1_A8		0x318
#define BCMA_GMAC_CMN_UDF_2_A3_A0	0x320
#define BCMA_GMAC_CMN_UDF_2_A7_A4	0x324
#define BCMA_GMAC_CMN_UDF_2_A8		0x328
#define BCMA_GMAC_CMN_UDF_0_B3_B0	0x330
#define BCMA_GMAC_CMN_UDF_0_B7_B4	0x334
#define BCMA_GMAC_CMN_UDF_0_B8		0x338
#define BCMA_GMAC_CMN_UDF_1_B3_B0	0x340
#define BCMA_GMAC_CMN_UDF_1_B7_B4	0x344
#define BCMA_GMAC_CMN_UDF_1_B8		0x348
#define BCMA_GMAC_CMN_UDF_2_B3_B0	0x350
#define BCMA_GMAC_CMN_UDF_2_B7_B4	0x354
#define BCMA_GMAC_CMN_UDF_2_B8		0x358
#define BCMA_GMAC_CMN_UDF_0_C3_C0	0x360
#define BCMA_GMAC_CMN_UDF_0_C7_C4	0x364
#define BCMA_GMAC_CMN_UDF_0_C8		0x368
#define BCMA_GMAC_CMN_UDF_1_C3_C0	0x370
#define BCMA_GMAC_CMN_UDF_1_C7_C4	0x374
#define BCMA_GMAC_CMN_UDF_1_C8		0x378
#define BCMA_GMAC_CMN_UDF_2_C3_C0	0x380
#define BCMA_GMAC_CMN_UDF_2_C7_C4	0x384
#define BCMA_GMAC_CMN_UDF_2_C8		0x388
#define BCMA_GMAC_CMN_UDF_0_D3_D0	0x390
#define BCMA_GMAC_CMN_UDF_0_D7_D4	0x394
#define BCMA_GMAC_CMN_UDF_0_D11_D8	0x394

struct bcma_drv_gmac_cmn {
	struct bcma_device *core;

	/* Drivers accessing BCMA_GMAC_CMN_PHY_ACCESS and
	 * BCMA_GMAC_CMN_PHY_CTL need to take that mutex first. */
	struct mutex phy_mutex;
};

/* Register access */
#define gmac_cmn_read16(gc, offset)		bcma_read16((gc)->core, offset)
#define gmac_cmn_read32(gc, offset)		bcma_read32((gc)->core, offset)
#define gmac_cmn_write16(gc, offset, val)	bcma_write16((gc)->core, offset, val)
#define gmac_cmn_write32(gc, offset, val)	bcma_write32((gc)->core, offset, val)

#endif /* LINUX_BCMA_DRIVER_GMAC_CMN_H_ */
