/*
 * AM43x PRCM defines
 *
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com/
 *
 * This file is licensed under the terms of the GNU General Public License
 * version 2.  This program is licensed "as is" without any warranty of any
 * kind, whether express or implied.
 */

#ifndef __ARCH_ARM_MACH_OMAP2_PRCM_43XX_H
#define __ARCH_ARM_MACH_OMAP2_PRCM_43XX_H

#define AM43XX_PRM_PARTITION				1
#define AM43XX_CM_PARTITION				1

/* PRM instances */
#define AM43XX_PRM_OCP_SOCKET_INST			0x0000
#define AM43XX_PRM_MPU_INST				0x0300
#define AM43XX_PRM_GFX_INST				0x0400
#define AM43XX_PRM_RTC_INST				0x0500
#define AM43XX_PRM_TAMPER_INST				0x0600
#define AM43XX_PRM_CEFUSE_INST				0x0700
#define AM43XX_PRM_PER_INST				0x0800
#define AM43XX_PRM_WKUP_INST				0x2000
#define AM43XX_PRM_DEVICE_INST				0x4000

/* PRM_IRQ offsets */
#define AM43XX_PRM_IRQSTATUS_MPU_OFFSET			0x0004
#define AM43XX_PRM_IRQENABLE_MPU_OFFSET			0x0008

/* Other PRM offsets */
#define AM43XX_PRM_IO_PMCTRL_OFFSET			0x0024

/* RM RSTCTRL offsets */
#define AM43XX_RM_PER_RSTCTRL_OFFSET			0x0010
#define AM43XX_RM_GFX_RSTCTRL_OFFSET			0x0010
#define AM43XX_RM_WKUP_RSTCTRL_OFFSET			0x0010

/* RM RSTST offsets */
#define AM43XX_RM_GFX_RSTST_OFFSET			0x0014
#define AM43XX_RM_PER_RSTST_OFFSET			0x0014
#define AM43XX_RM_WKUP_RSTST_OFFSET			0x0014

/* CM instances */
#define AM43XX_CM_WKUP_INST				0x2800
#define AM43XX_CM_DEVICE_INST				0x4100
#define AM43XX_CM_DPLL_INST				0x4200
#define AM43XX_CM_MPU_INST				0x8300
#define AM43XX_CM_GFX_INST				0x8400
#define AM43XX_CM_RTC_INST				0x8500
#define AM43XX_CM_TAMPER_INST				0x8600
#define AM43XX_CM_CEFUSE_INST				0x8700
#define AM43XX_CM_PER_INST				0x8800

/* CD offsets */
#define AM43XX_CM_WKUP_L3_AON_CDOFFS			0x0000
#define AM43XX_CM_WKUP_L3S_TSC_CDOFFS			0x0100
#define AM43XX_CM_WKUP_L4_WKUP_AON_CDOFFS		0x0200
#define AM43XX_CM_WKUP_WKUP_CDOFFS			0x0300
#define AM43XX_CM_MPU_MPU_CDOFFS			0x0000
#define AM43XX_CM_GFX_GFX_L3_CDOFFS			0x0000
#define AM43XX_CM_RTC_RTC_CDOFFS			0x0000
#define AM43XX_CM_TAMPER_TAMPER_CDOFFS			0x0000
#define AM43XX_CM_CEFUSE_CEFUSE_CDOFFS			0x0000
#define AM43XX_CM_PER_L3_CDOFFS				0x0000
#define AM43XX_CM_PER_L3S_CDOFFS			0x0200
#define AM43XX_CM_PER_ICSS_CDOFFS			0x0300
#define AM43XX_CM_PER_L4LS_CDOFFS			0x0400
#define AM43XX_CM_PER_EMIF_CDOFFS			0x0700
#define AM43XX_CM_PER_DSS_CDOFFS			0x0a00
#define AM43XX_CM_PER_CPSW_CDOFFS			0x0b00
#define AM43XX_CM_PER_OCPWP_L3_CDOFFS			0x0c00

/* CLK CTRL offsets */
#define AM43XX_CM_PER_UART1_CLKCTRL_OFFSET		0x0580
#define AM43XX_CM_PER_UART2_CLKCTRL_OFFSET		0x0588
#define AM43XX_CM_PER_UART3_CLKCTRL_OFFSET		0x0590
#define AM43XX_CM_PER_UART4_CLKCTRL_OFFSET		0x0598
#define AM43XX_CM_PER_UART5_CLKCTRL_OFFSET		0x05a0
#define AM43XX_CM_PER_DCAN0_CLKCTRL_OFFSET		0x0428
#define AM43XX_CM_PER_DCAN1_CLKCTRL_OFFSET		0x0430
#define AM43XX_CM_PER_ELM_CLKCTRL_OFFSET		0x0468
#define AM43XX_CM_PER_EPWMSS0_CLKCTRL_OFFSET		0x0438
#define AM43XX_CM_PER_EPWMSS1_CLKCTRL_OFFSET		0x0440
#define AM43XX_CM_PER_EPWMSS2_CLKCTRL_OFFSET		0x0448
#define AM43XX_CM_PER_GPIO1_CLKCTRL_OFFSET		0x0478
#define AM43XX_CM_PER_GPIO2_CLKCTRL_OFFSET		0x0480
#define AM43XX_CM_PER_GPIO3_CLKCTRL_OFFSET		0x0488
#define AM43XX_CM_PER_I2C1_CLKCTRL_OFFSET		0x04a8
#define AM43XX_CM_PER_I2C2_CLKCTRL_OFFSET		0x04b0
#define AM43XX_CM_PER_MAILBOX0_CLKCTRL_OFFSET		0x04b8
#define AM43XX_CM_PER_MMC0_CLKCTRL_OFFSET		0x04c0
#define AM43XX_CM_PER_MMC1_CLKCTRL_OFFSET		0x04c8
#define AM43XX_CM_PER_RNG_CLKCTRL_OFFSET		0x04e0
#define AM43XX_CM_PER_SPI0_CLKCTRL_OFFSET		0x0500
#define AM43XX_CM_PER_SPI1_CLKCTRL_OFFSET		0x0508
#define AM43XX_CM_PER_SPINLOCK_CLKCTRL_OFFSET		0x0528
#define AM43XX_CM_PER_TIMER2_CLKCTRL_OFFSET		0x0530
#define AM43XX_CM_PER_TIMER3_CLKCTRL_OFFSET		0x0538
#define AM43XX_CM_PER_TIMER4_CLKCTRL_OFFSET		0x0540
#define AM43XX_CM_PER_TIMER5_CLKCTRL_OFFSET		0x0548
#define AM43XX_CM_PER_TIMER6_CLKCTRL_OFFSET		0x0550
#define AM43XX_CM_PER_TIMER7_CLKCTRL_OFFSET		0x0558
#define AM43XX_CM_WKUP_WKUP_M3_CLKCTRL_OFFSET		0x0228
#define AM43XX_CM_WKUP_CONTROL_CLKCTRL_OFFSET		0x0360
#define AM43XX_CM_WKUP_SMARTREFLEX0_CLKCTRL_OFFSET	0x0350
#define AM43XX_CM_WKUP_SMARTREFLEX1_CLKCTRL_OFFSET	0x0358
#define AM43XX_CM_WKUP_UART0_CLKCTRL_OFFSET		0x0348
#define AM43XX_CM_WKUP_TIMER1_CLKCTRL_OFFSET		0x0328
#define AM43XX_CM_WKUP_I2C0_CLKCTRL_OFFSET		0x0340
#define AM43XX_CM_WKUP_GPIO0_CLKCTRL_OFFSET		0x0368
#define AM43XX_CM_WKUP_ADC_TSC_CLKCTRL_OFFSET		0x0120
#define AM43XX_CM_WKUP_WDT1_CLKCTRL_OFFSET		0x0338
#define AM43XX_CM_WKUP_L4WKUP_CLKCTRL_OFFSET		0x0220
#define AM43XX_CM_RTC_RTC_CLKCTRL_OFFSET		0x0020
#define AM43XX_CM_PER_MMC2_CLKCTRL_OFFSET		0x0248
#define AM43XX_CM_PER_QSPI_CLKCTRL_OFFSET               0x0258
#define AM43XX_CM_PER_GPMC_CLKCTRL_OFFSET		0x0220
#define AM43XX_CM_PER_MCASP0_CLKCTRL_OFFSET		0x0238
#define AM43XX_CM_PER_MCASP1_CLKCTRL_OFFSET		0x0240
#define AM43XX_CM_PER_L4LS_CLKCTRL_OFFSET		0x0420
#define AM43XX_CM_PER_L3_CLKCTRL_OFFSET			0x0020
#define AM43XX_CM_PER_TPCC_CLKCTRL_OFFSET		0x0078
#define AM43XX_CM_PER_TPTC0_CLKCTRL_OFFSET		0x0080
#define AM43XX_CM_PER_TPTC1_CLKCTRL_OFFSET		0x0088
#define AM43XX_CM_PER_TPTC2_CLKCTRL_OFFSET		0x0090
#define AM43XX_CM_PER_CPGMAC0_CLKCTRL_OFFSET		0x0b20
#define AM43XX_CM_PER_PRUSS_CLKCTRL_OFFSET		0x0320
#define AM43XX_CM_GFX_GFX_CLKCTRL_OFFSET		0x0020
#define AM43XX_CM_PER_L4HS_CLKCTRL_OFFSET		0x00a0
#define AM43XX_CM_MPU_MPU_CLKCTRL_OFFSET		0x0020
#define AM43XX_CM_PER_L3_INSTR_CLKCTRL_OFFSET		0x0040
#define AM43XX_CM_PER_OCMCRAM_CLKCTRL_OFFSET		0x0050
#define AM43XX_CM_PER_SHA0_CLKCTRL_OFFSET		0x0058
#define AM43XX_CM_PER_AES0_CLKCTRL_OFFSET		0x0028
#define AM43XX_CM_PER_DES_CLKCTRL_OFFSET		0x0030
#define AM43XX_CM_PER_TIMER8_CLKCTRL_OFFSET		0x0560
#define AM43XX_CM_PER_TIMER9_CLKCTRL_OFFSET		0x0568
#define AM43XX_CM_PER_TIMER10_CLKCTRL_OFFSET		0x0570
#define AM43XX_CM_PER_TIMER11_CLKCTRL_OFFSET		0x0578
#define AM43XX_CM_WKUP_SYNCTIMER_CLKCTRL_OFFSET		0x0230
#define AM43XX_CM_PER_EPWMSS3_CLKCTRL_OFFSET		0x0450
#define AM43XX_CM_PER_EPWMSS4_CLKCTRL_OFFSET		0x0458
#define AM43XX_CM_PER_EPWMSS5_CLKCTRL_OFFSET		0x0460
#define AM43XX_CM_PER_SPI2_CLKCTRL_OFFSET		0x0510
#define AM43XX_CM_PER_SPI3_CLKCTRL_OFFSET		0x0518
#define AM43XX_CM_PER_SPI4_CLKCTRL_OFFSET		0x0520
#define AM43XX_CM_PER_GPIO4_CLKCTRL_OFFSET		0x0490
#define AM43XX_CM_PER_GPIO5_CLKCTRL_OFFSET		0x0498
#define AM43XX_CM_PER_USB_OTG_SS0_CLKCTRL_OFFSET	0x0260
#define AM43XX_CM_PER_USBPHYOCP2SCP0_CLKCTRL_OFFSET	0x05B8
#define AM43XX_CM_PER_USB_OTG_SS1_CLKCTRL_OFFSET        0x0268
#define AM43XX_CM_PER_USBPHYOCP2SCP1_CLKCTRL_OFFSET	0x05C0
#define AM43XX_CM_PER_DSS_CLKCTRL_OFFSET		0x0a20
#define AM43XX_CM_PER_HDQ1W_CLKCTRL_OFFSET		0x04a0
#define AM43XX_CM_PER_VPFE0_CLKCTRL_OFFSET		0x0068
#define AM43XX_CM_PER_VPFE1_CLKCTRL_OFFSET		0x0070
#define AM43XX_CM_PER_EMIF_CLKCTRL_OFFSET		0x0720

#endif
