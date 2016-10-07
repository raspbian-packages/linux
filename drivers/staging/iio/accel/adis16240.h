#ifndef SPI_ADIS16240_H_
#define SPI_ADIS16240_H_

#define ADIS16240_STARTUP_DELAY	220 /* ms */

/* Flash memory write count */
#define ADIS16240_FLASH_CNT      0x00

/* Output, power supply */
#define ADIS16240_SUPPLY_OUT     0x02

/* Output, x-axis accelerometer */
#define ADIS16240_XACCL_OUT      0x04

/* Output, y-axis accelerometer */
#define ADIS16240_YACCL_OUT      0x06

/* Output, z-axis accelerometer */
#define ADIS16240_ZACCL_OUT      0x08

/* Output, auxiliary ADC input */
#define ADIS16240_AUX_ADC        0x0A

/* Output, temperature */
#define ADIS16240_TEMP_OUT       0x0C

/* Output, x-axis acceleration peak */
#define ADIS16240_XPEAK_OUT      0x0E

/* Output, y-axis acceleration peak */
#define ADIS16240_YPEAK_OUT      0x10

/* Output, z-axis acceleration peak */
#define ADIS16240_ZPEAK_OUT      0x12

/* Output, sum-of-squares acceleration peak */
#define ADIS16240_XYZPEAK_OUT    0x14

/* Output, Capture Buffer 1, X and Y acceleration */
#define ADIS16240_CAPT_BUF1      0x16

/* Output, Capture Buffer 2, Z acceleration */
#define ADIS16240_CAPT_BUF2      0x18

/* Diagnostic, error flags */
#define ADIS16240_DIAG_STAT      0x1A

/* Diagnostic, event counter */
#define ADIS16240_EVNT_CNTR      0x1C

/* Diagnostic, check sum value from firmware test */
#define ADIS16240_CHK_SUM        0x1E

/* Calibration, x-axis acceleration offset adjustment */
#define ADIS16240_XACCL_OFF      0x20

/* Calibration, y-axis acceleration offset adjustment */
#define ADIS16240_YACCL_OFF      0x22

/* Calibration, z-axis acceleration offset adjustment */
#define ADIS16240_ZACCL_OFF      0x24

/* Clock, hour and minute */
#define ADIS16240_CLK_TIME       0x2E

/* Clock, month and day */
#define ADIS16240_CLK_DATE       0x30

/* Clock, year */
#define ADIS16240_CLK_YEAR       0x32

/* Wake-up setting, hour and minute */
#define ADIS16240_WAKE_TIME      0x34

/* Wake-up setting, month and day */
#define ADIS16240_WAKE_DATE      0x36

/* Alarm 1 amplitude threshold */
#define ADIS16240_ALM_MAG1       0x38

/* Alarm 2 amplitude threshold */
#define ADIS16240_ALM_MAG2       0x3A

/* Alarm control */
#define ADIS16240_ALM_CTRL       0x3C

/* Capture, external trigger control */
#define ADIS16240_XTRIG_CTRL     0x3E

/* Capture, address pointer */
#define ADIS16240_CAPT_PNTR      0x40

/* Capture, configuration and control */
#define ADIS16240_CAPT_CTRL      0x42

/* General-purpose digital input/output control */
#define ADIS16240_GPIO_CTRL      0x44

/* Miscellaneous control */
#define ADIS16240_MSC_CTRL       0x46

/* Internal sample period (rate) control */
#define ADIS16240_SMPL_PRD       0x48

/* System command */
#define ADIS16240_GLOB_CMD       0x4A

/* MSC_CTRL */

/* Enables sum-of-squares output (XYZPEAK_OUT) */
#define ADIS16240_MSC_CTRL_XYZPEAK_OUT_EN	BIT(15)

/* Enables peak tracking output (XPEAK_OUT, YPEAK_OUT, and ZPEAK_OUT) */
#define ADIS16240_MSC_CTRL_X_Y_ZPEAK_OUT_EN	BIT(14)

/* Self-test enable: 1 = apply electrostatic force, 0 = disabled */
#define ADIS16240_MSC_CTRL_SELF_TEST_EN	        BIT(8)

/* Data-ready enable: 1 = enabled, 0 = disabled */
#define ADIS16240_MSC_CTRL_DATA_RDY_EN	        BIT(2)

/* Data-ready polarity: 1 = active high, 0 = active low */
#define ADIS16240_MSC_CTRL_ACTIVE_HIGH	        BIT(1)

/* Data-ready line selection: 1 = DIO2, 0 = DIO1 */
#define ADIS16240_MSC_CTRL_DATA_RDY_DIO2	BIT(0)

/* DIAG_STAT */

/* Alarm 2 status: 1 = alarm active, 0 = alarm inactive */
#define ADIS16240_DIAG_STAT_ALARM2      BIT(9)

/* Alarm 1 status: 1 = alarm active, 0 = alarm inactive */
#define ADIS16240_DIAG_STAT_ALARM1      BIT(8)

/* Capture buffer full: 1 = capture buffer is full */
#define ADIS16240_DIAG_STAT_CPT_BUF_FUL BIT(7)

/* Flash test, checksum flag: 1 = mismatch, 0 = match */
#define ADIS16240_DIAG_STAT_CHKSUM      BIT(6)

/* Power-on, self-test flag: 1 = failure, 0 = pass */
#define ADIS16240_DIAG_STAT_PWRON_FAIL_BIT  5

/* Power-on self-test: 1 = in-progress, 0 = complete */
#define ADIS16240_DIAG_STAT_PWRON_BUSY  BIT(4)

/* SPI communications failure */
#define ADIS16240_DIAG_STAT_SPI_FAIL_BIT	3

/* Flash update failure */
#define ADIS16240_DIAG_STAT_FLASH_UPT_BIT	2

/* Power supply above 3.625 V */
#define ADIS16240_DIAG_STAT_POWER_HIGH_BIT	1

 /* Power supply below 3.15 V */
#define ADIS16240_DIAG_STAT_POWER_LOW_BIT	0

/* GLOB_CMD */

#define ADIS16240_GLOB_CMD_RESUME	BIT(8)
#define ADIS16240_GLOB_CMD_SW_RESET	BIT(7)
#define ADIS16240_GLOB_CMD_STANDBY	BIT(2)

#define ADIS16240_ERROR_ACTIVE          BIT(14)

/* At the moment triggers are only used for ring buffer
 * filling. This may change!
 */

#define ADIS16240_SCAN_ACC_X	0
#define ADIS16240_SCAN_ACC_Y	1
#define ADIS16240_SCAN_ACC_Z	2
#define ADIS16240_SCAN_SUPPLY	3
#define ADIS16240_SCAN_AUX_ADC	4
#define ADIS16240_SCAN_TEMP	5

#endif /* SPI_ADIS16240_H_ */
