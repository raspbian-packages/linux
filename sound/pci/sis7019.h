/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __sis7019_h__
#define __sis7019_h__

/*
 *  Definitions for SiS7019 Audio Accelerator
 *
 *  Copyright (C) 2004-2007, David Dillow
 *  Written by David Dillow <dave@thedillows.org>
 *  Inspired by the Trident 4D-WaveDX/NX driver.
 *
 *  All rights reserved.
 */


/* General Control Register */
#define SIS_GCR		0x00
#define		SIS_GCR_MACRO_POWER_DOWN		0x80000000
#define		SIS_GCR_MODEM_ENABLE			0x00010000
#define		SIS_GCR_SOFTWARE_RESET			0x00000001

/* General Interrupt Enable Register */
#define SIS_GIER	0x04
#define		SIS_GIER_MODEM_TIMER_IRQ_ENABLE		0x00100000
#define		SIS_GIER_MODEM_RX_DMA_IRQ_ENABLE	0x00080000
#define		SIS_GIER_MODEM_TX_DMA_IRQ_ENABLE	0x00040000
#define		SIS_GIER_AC97_GPIO1_IRQ_ENABLE		0x00020000
#define		SIS_GIER_AC97_GPIO0_IRQ_ENABLE		0x00010000
#define		SIS_GIER_AC97_SAMPLE_TIMER_IRQ_ENABLE	0x00000010
#define		SIS_GIER_AUDIO_GLOBAL_TIMER_IRQ_ENABLE	0x00000008
#define		SIS_GIER_AUDIO_RECORD_DMA_IRQ_ENABLE	0x00000004
#define		SIS_GIER_AUDIO_PLAY_DMA_IRQ_ENABLE	0x00000002
#define		SIS_GIER_AUDIO_WAVE_ENGINE_IRQ_ENABLE	0x00000001

/* General Interrupt Status Register */
#define SIS_GISR	0x08
#define		SIS_GISR_MODEM_TIMER_IRQ_STATUS		0x00100000
#define		SIS_GISR_MODEM_RX_DMA_IRQ_STATUS	0x00080000
#define		SIS_GISR_MODEM_TX_DMA_IRQ_STATUS	0x00040000
#define		SIS_GISR_AC97_GPIO1_IRQ_STATUS		0x00020000
#define		SIS_GISR_AC97_GPIO0_IRQ_STATUS		0x00010000
#define		SIS_GISR_AC97_SAMPLE_TIMER_IRQ_STATUS	0x00000010
#define		SIS_GISR_AUDIO_GLOBAL_TIMER_IRQ_STATUS	0x00000008
#define		SIS_GISR_AUDIO_RECORD_DMA_IRQ_STATUS	0x00000004
#define		SIS_GISR_AUDIO_PLAY_DMA_IRQ_STATUS	0x00000002
#define		SIS_GISR_AUDIO_WAVE_ENGINE_IRQ_STATUS	0x00000001

/* DMA Control Register */
#define SIS_DMA_CSR	0x10
#define		SIS_DMA_CSR_PCI_SETTINGS		0x0000001d
#define		SIS_DMA_CSR_CONCURRENT_ENABLE		0x00000200
#define		SIS_DMA_CSR_PIPELINE_ENABLE		0x00000100
#define		SIS_DMA_CSR_RX_DRAIN_ENABLE		0x00000010
#define		SIS_DMA_CSR_RX_FILL_ENABLE		0x00000008
#define		SIS_DMA_CSR_TX_DRAIN_ENABLE		0x00000004
#define		SIS_DMA_CSR_TX_LOWPRI_FILL_ENABLE	0x00000002
#define		SIS_DMA_CSR_TX_HIPRI_FILL_ENABLE	0x00000001

/* Playback Channel Start Registers */
#define SIS_PLAY_START_A_REG	0x14
#define SIS_PLAY_START_B_REG	0x18

/* Playback Channel Stop Registers */
#define SIS_PLAY_STOP_A_REG	0x1c
#define SIS_PLAY_STOP_B_REG	0x20

/* Recording Channel Start Register */
#define SIS_RECORD_START_REG	0x24

/* Recording Channel Stop Register */
#define SIS_RECORD_STOP_REG	0x28

/* Playback Interrupt Status Registers */
#define SIS_PISR_A	0x2c
#define SIS_PISR_B	0x30

/* Recording Interrupt Status Register */
#define SIS_RISR	0x34

/* AC97 AC-link Playback Source Register */
#define SIS_AC97_PSR	0x40
#define		SIS_AC97_PSR_MODEM_HEADSET_SRC_MIXER	0x0f000000
#define		SIS_AC97_PSR_MODEM_LINE2_SRC_MIXER	0x00f00000
#define		SIS_AC97_PSR_MODEM_LINE1_SRC_MIXER	0x000f0000
#define		SIS_AC97_PSR_PCM_LFR_SRC_MIXER		0x0000f000
#define		SIS_AC97_PSR_PCM_SURROUND_SRC_MIXER	0x00000f00
#define		SIS_AC97_PSR_PCM_CENTER_SRC_MIXER	0x000000f0
#define		SIS_AC97_PSR_PCM_LR_SRC_MIXER		0x0000000f

/* AC97 AC-link Command Register */
#define SIS_AC97_CMD	0x50
#define 	SIS_AC97_CMD_DATA_MASK			0xffff0000
#define		SIS_AC97_CMD_REG_MASK			0x0000ff00
#define		SIS_AC97_CMD_CODEC3_READ		0x0000000d
#define		SIS_AC97_CMD_CODEC3_WRITE		0x0000000c
#define		SIS_AC97_CMD_CODEC2_READ		0x0000000b
#define		SIS_AC97_CMD_CODEC2_WRITE		0x0000000a
#define		SIS_AC97_CMD_CODEC_READ			0x00000009
#define		SIS_AC97_CMD_CODEC_WRITE		0x00000008
#define		SIS_AC97_CMD_CODEC_WARM_RESET		0x00000005
#define		SIS_AC97_CMD_CODEC_COLD_RESET		0x00000004
#define		SIS_AC97_CMD_DONE			0x00000000

/* AC97 AC-link Semaphore Register */
#define SIS_AC97_SEMA	0x54
#define		SIS_AC97_SEMA_BUSY			0x00000001
#define		SIS_AC97_SEMA_RELEASE			0x00000000

/* AC97 AC-link Status Register */
#define SIS_AC97_STATUS	0x58
#define		SIS_AC97_STATUS_AUDIO_D2_INACT_SECS	0x03f00000
#define		SIS_AC97_STATUS_MODEM_ALIVE		0x00002000
#define		SIS_AC97_STATUS_AUDIO_ALIVE		0x00001000
#define		SIS_AC97_STATUS_CODEC3_READY		0x00000400
#define		SIS_AC97_STATUS_CODEC2_READY		0x00000200
#define		SIS_AC97_STATUS_CODEC_READY		0x00000100
#define		SIS_AC97_STATUS_WARM_RESET		0x00000080
#define		SIS_AC97_STATUS_COLD_RESET		0x00000040
#define		SIS_AC97_STATUS_POWERED_DOWN		0x00000020
#define		SIS_AC97_STATUS_NORMAL			0x00000010
#define		SIS_AC97_STATUS_READ_EXPIRED		0x00000004
#define		SIS_AC97_STATUS_SEMAPHORE		0x00000002
#define		SIS_AC97_STATUS_BUSY			0x00000001

/* AC97 AC-link Audio Configuration Register */
#define SIS_AC97_CONF	0x5c
#define		SIS_AC97_CONF_AUDIO_ALIVE		0x80000000
#define		SIS_AC97_CONF_WARM_RESET_ENABLE		0x40000000
#define		SIS_AC97_CONF_PR6_ENABLE		0x20000000
#define		SIS_AC97_CONF_PR5_ENABLE		0x10000000
#define		SIS_AC97_CONF_PR4_ENABLE		0x08000000
#define		SIS_AC97_CONF_PR3_ENABLE		0x04000000
#define		SIS_AC97_CONF_PR2_PR7_ENABLE		0x02000000
#define		SIS_AC97_CONF_PR0_PR1_ENABLE		0x01000000
#define		SIS_AC97_CONF_AUTO_PM_ENABLE		0x00800000
#define		SIS_AC97_CONF_PCM_LFE_ENABLE		0x00080000
#define		SIS_AC97_CONF_PCM_SURROUND_ENABLE	0x00040000
#define		SIS_AC97_CONF_PCM_CENTER_ENABLE		0x00020000
#define		SIS_AC97_CONF_PCM_LR_ENABLE		0x00010000
#define		SIS_AC97_CONF_PCM_CAP_MIC_ENABLE	0x00002000
#define		SIS_AC97_CONF_PCM_CAP_LR_ENABLE		0x00001000
#define		SIS_AC97_CONF_PCM_CAP_MIC_FROM_CODEC3	0x00000200
#define		SIS_AC97_CONF_PCM_CAP_LR_FROM_CODEC3	0x00000100
#define		SIS_AC97_CONF_CODEC3_PM_VRM		0x00000080
#define		SIS_AC97_CONF_CODEC_PM_VRM		0x00000040
#define		SIS_AC97_CONF_CODEC3_VRA_ENABLE		0x00000020
#define		SIS_AC97_CONF_CODEC_VRA_ENABLE		0x00000010
#define		SIS_AC97_CONF_CODEC3_PM_EAC		0x00000008
#define		SIS_AC97_CONF_CODEC_PM_EAC		0x00000004
#define		SIS_AC97_CONF_CODEC3_EXISTS		0x00000002
#define		SIS_AC97_CONF_CODEC_EXISTS		0x00000001

/* Playback Channel Sync Group registers */
#define SIS_PLAY_SYNC_GROUP_A	0x80
#define SIS_PLAY_SYNC_GROUP_B	0x84
#define SIS_PLAY_SYNC_GROUP_C	0x88
#define SIS_PLAY_SYNC_GROUP_D	0x8c
#define SIS_MIXER_SYNC_GROUP	0x90

/* Wave Engine Config and Control Register */
#define SIS_WECCR	0xa0
#define		SIS_WECCR_TESTMODE_MASK			0x00300000
#define			SIS_WECCR_TESTMODE_NORMAL		0x00000000
#define			SIS_WECCR_TESTMODE_BYPASS_NSO_ALPHA	0x00100000
#define			SIS_WECCR_TESTMODE_BYPASS_FC		0x00200000
#define			SIS_WECCR_TESTMODE_BYPASS_WOL		0x00300000
#define		SIS_WECCR_RESONANCE_DELAY_MASK		0x00060000
#define			SIS_WECCR_RESONANCE_DELAY_NONE		0x00000000
#define			SIS_WECCR_RESONANCE_DELAY_FC_1F00	0x00020000
#define			SIS_WECCR_RESONANCE_DELAY_FC_1E00	0x00040000
#define			SIS_WECCR_RESONANCE_DELAY_FC_1C00	0x00060000
#define		SIS_WECCR_IGNORE_CHANNEL_PARMS		0x00010000
#define		SIS_WECCR_COMMAND_CHANNEL_ID_MASK	0x0003ff00
#define		SIS_WECCR_COMMAND_MASK			0x00000007
#define			SIS_WECCR_COMMAND_NONE			0x00000000
#define			SIS_WECCR_COMMAND_DONE			0x00000000
#define			SIS_WECCR_COMMAND_PAUSE			0x00000001
#define			SIS_WECCR_COMMAND_TOGGLE_VEG		0x00000002
#define			SIS_WECCR_COMMAND_TOGGLE_MEG		0x00000003
#define			SIS_WECCR_COMMAND_TOGGLE_VEG_MEG	0x00000004

/* Wave Engine Volume Control Register */
#define SIS_WEVCR	0xa4
#define		SIS_WEVCR_LEFT_MUSIC_ATTENUATION_MASK	0xff000000
#define		SIS_WEVCR_RIGHT_MUSIC_ATTENUATION_MASK	0x00ff0000
#define		SIS_WEVCR_LEFT_WAVE_ATTENUATION_MASK	0x0000ff00
#define		SIS_WEVCR_RIGHT_WAVE_ATTENUATION_MASK	0x000000ff

/* Wave Engine Interrupt Status Registers */
#define SIS_WEISR_A	0xa8
#define SIS_WEISR_B	0xac


/* Playback DMA parameters (parameter RAM) */
#define SIS_PLAY_DMA_OFFSET	0x0000
#define SIS_PLAY_DMA_SIZE	0x10
#define SIS_PLAY_DMA_ADDR(addr, num) \
	((num * SIS_PLAY_DMA_SIZE) + (addr) + SIS_PLAY_DMA_OFFSET)

#define SIS_PLAY_DMA_FORMAT_CSO	0x00
#define		SIS_PLAY_DMA_FORMAT_UNSIGNED	0x00080000
#define		SIS_PLAY_DMA_FORMAT_8BIT	0x00040000
#define		SIS_PLAY_DMA_FORMAT_MONO	0x00020000
#define		SIS_PLAY_DMA_CSO_MASK		0x0000ffff
#define SIS_PLAY_DMA_BASE	0x04
#define SIS_PLAY_DMA_CONTROL	0x08
#define		SIS_PLAY_DMA_STOP_AT_SSO	0x04000000
#define		SIS_PLAY_DMA_RELEASE		0x02000000
#define		SIS_PLAY_DMA_LOOP		0x01000000
#define		SIS_PLAY_DMA_INTR_AT_SSO	0x00080000
#define		SIS_PLAY_DMA_INTR_AT_ESO	0x00040000
#define		SIS_PLAY_DMA_INTR_AT_LEO	0x00020000
#define		SIS_PLAY_DMA_INTR_AT_MLP	0x00010000
#define		SIS_PLAY_DMA_LEO_MASK		0x0000ffff
#define SIS_PLAY_DMA_SSO_ESO	0x0c
#define		SIS_PLAY_DMA_SSO_MASK		0xffff0000
#define		SIS_PLAY_DMA_ESO_MASK		0x0000ffff

/* Capture DMA parameters (parameter RAM) */
#define SIS_CAPTURE_DMA_OFFSET	0x0800
#define SIS_CAPTURE_DMA_SIZE	0x10
#define SIS_CAPTURE_DMA_ADDR(addr, num) \
	((num * SIS_CAPTURE_DMA_SIZE) + (addr) + SIS_CAPTURE_DMA_OFFSET)

#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_0	0
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_1	1
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_2	2
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_3	3
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_4	4
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_5	5
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_6	6
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_7	7
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_8	8
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_9	9
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_10	10
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_11	11
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_12	12
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_13	13
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_14	14
#define	SIS_CAPTURE_CHAN_MIXER_ROUTE_BACK_15	15
#define	SIS_CAPTURE_CHAN_AC97_PCM_IN		16
#define	SIS_CAPTURE_CHAN_AC97_MIC_IN		17
#define	SIS_CAPTURE_CHAN_AC97_LINE1_IN		18
#define	SIS_CAPTURE_CHAN_AC97_LINE2_IN		19
#define	SIS_CAPTURE_CHAN_AC97_HANDSE_IN		20

#define SIS_CAPTURE_DMA_FORMAT_CSO	0x00
#define		SIS_CAPTURE_DMA_MONO_MODE_MASK	0xc0000000
#define		SIS_CAPTURE_DMA_MONO_MODE_AVG	0x00000000
#define		SIS_CAPTURE_DMA_MONO_MODE_LEFT	0x40000000
#define		SIS_CAPTURE_DMA_MONO_MODE_RIGHT	0x80000000
#define		SIS_CAPTURE_DMA_FORMAT_UNSIGNED	0x00080000
#define		SIS_CAPTURE_DMA_FORMAT_8BIT	0x00040000
#define		SIS_CAPTURE_DMA_FORMAT_MONO	0x00020000
#define		SIS_CAPTURE_DMA_CSO_MASK		0x0000ffff
#define SIS_CAPTURE_DMA_BASE		0x04
#define SIS_CAPTURE_DMA_CONTROL		0x08
#define		SIS_CAPTURE_DMA_STOP_AT_SSO	0x04000000
#define		SIS_CAPTURE_DMA_RELEASE		0x02000000
#define		SIS_CAPTURE_DMA_LOOP		0x01000000
#define		SIS_CAPTURE_DMA_INTR_AT_LEO	0x00020000
#define		SIS_CAPTURE_DMA_INTR_AT_MLP	0x00010000
#define		SIS_CAPTURE_DMA_LEO_MASK		0x0000ffff
#define SIS_CAPTURE_DMA_RESERVED	0x0c


/* Mixer routing list start pointer (parameter RAM) */
#define SIS_MIXER_START_OFFSET	0x1000
#define SIS_MIXER_START_SIZE	0x04
#define SIS_MIXER_START_ADDR(addr, num) \
	((num * SIS_MIXER_START_SIZE) + (addr) + SIS_MIXER_START_OFFSET)

#define SIS_MIXER_START_MASK	0x0000007f

/* Mixer routing table (parameter RAM) */
#define SIS_MIXER_OFFSET	0x1400
#define SIS_MIXER_SIZE		0x04
#define SIS_MIXER_ADDR(addr, num) \
	((num * SIS_MIXER_SIZE) + (addr) + SIS_MIXER_OFFSET)

#define SIS_MIXER_RIGHT_ATTENUTATION_MASK	0xff000000
#define 	SIS_MIXER_RIGHT_NO_ATTEN		0xff000000
#define SIS_MIXER_LEFT_ATTENUTATION_MASK	0x00ff0000
#define 	SIS_MIXER_LEFT_NO_ATTEN			0x00ff0000
#define SIS_MIXER_NEXT_ENTRY_MASK		0x00007f00
#define 	SIS_MIXER_NEXT_ENTRY_NONE		0x00000000
#define SIS_MIXER_DEST_MASK			0x0000007f
#define 	SIS_MIXER_DEST_0			0x00000020
#define 	SIS_MIXER_DEST_1			0x00000021
#define 	SIS_MIXER_DEST_2			0x00000022
#define 	SIS_MIXER_DEST_3			0x00000023
#define 	SIS_MIXER_DEST_4			0x00000024
#define 	SIS_MIXER_DEST_5			0x00000025
#define 	SIS_MIXER_DEST_6			0x00000026
#define 	SIS_MIXER_DEST_7			0x00000027
#define 	SIS_MIXER_DEST_8			0x00000028
#define 	SIS_MIXER_DEST_9			0x00000029
#define 	SIS_MIXER_DEST_10			0x0000002a
#define 	SIS_MIXER_DEST_11			0x0000002b
#define 	SIS_MIXER_DEST_12			0x0000002c
#define 	SIS_MIXER_DEST_13			0x0000002d
#define 	SIS_MIXER_DEST_14			0x0000002e
#define 	SIS_MIXER_DEST_15			0x0000002f

/* Wave Engine Control Parameters (parameter RAM) */
#define SIS_WAVE_OFFSET		0x2000
#define SIS_WAVE_SIZE		0x40
#define SIS_WAVE_ADDR(addr, num) \
	((num * SIS_WAVE_SIZE) + (addr) + SIS_WAVE_OFFSET)

#define SIS_WAVE_GENERAL		0x00
#define		SIS_WAVE_GENERAL_WAVE_VOLUME			0x80000000
#define		SIS_WAVE_GENERAL_MUSIC_VOLUME			0x00000000
#define		SIS_WAVE_GENERAL_VOLUME_MASK			0x7f000000
#define SIS_WAVE_GENERAL_ARTICULATION	0x04
#define		SIS_WAVE_GENERAL_ARTICULATION_DELTA_MASK	0x3fff0000
#define SIS_WAVE_ARTICULATION		0x08
#define SIS_WAVE_TIMER			0x0c
#define SIS_WAVE_GENERATOR		0x10
#define SIS_WAVE_CHANNEL_CONTROL	0x14
#define		SIS_WAVE_CHANNEL_CONTROL_FIRST_SAMPLE		0x80000000
#define		SIS_WAVE_CHANNEL_CONTROL_AMP_ENABLE		0x40000000
#define		SIS_WAVE_CHANNEL_CONTROL_FILTER_ENABLE		0x20000000
#define		SIS_WAVE_CHANNEL_CONTROL_INTERPOLATE_ENABLE	0x10000000
#define SIS_WAVE_LFO_EG_CONTROL		0x18
#define SIS_WAVE_LFO_EG_CONTROL_2	0x1c
#define SIS_WAVE_LFO_EG_CONTROL_3	0x20
#define SIS_WAVE_LFO_EG_CONTROL_4	0x24

#endif /* __sis7019_h__ */
