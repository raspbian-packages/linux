// SPDX-License-Identifier: GPL-2.0-only
/*
 * Samsung Exynos4 SoC series FIMC-IS slave interface driver
 *
 * Error log interface functions
 *
 * Copyright (C) 2011 - 2013 Samsung Electronics Co., Ltd.
 *
 * Authors: Younghwan Joo <yhwan.joo@samsung.com>
 *          Sylwester Nawrocki <s.nawrocki@samsung.com>
 */

#include "fimc-is-errno.h"

const char *fimc_is_param_strerr(unsigned int error)
{
	switch (error) {
	case ERROR_COMMON_CMD:
		return "ERROR_COMMON_CMD: Invalid Command";
	case ERROR_COMMON_PARAMETER:
		return "ERROR_COMMON_PARAMETER: Invalid Parameter";
	case ERROR_COMMON_SETFILE_LOAD:
		return "ERROR_COMMON_SETFILE_LOAD: Illegal Setfile Loading";
	case ERROR_COMMON_SETFILE_ADJUST:
		return "ERROR_COMMON_SETFILE_ADJUST: Setfile isn't adjusted";
	case ERROR_COMMON_SETFILE_INDEX:
		return "ERROR_COMMON_SETFILE_INDEX: Invalid setfile index";
	case ERROR_COMMON_INPUT_PATH:
		return "ERROR_COMMON_INPUT_PATH: Input path can be changed in ready state";
	case ERROR_COMMON_INPUT_INIT:
		return "ERROR_COMMON_INPUT_INIT: IP can not start if input path is not set";
	case ERROR_COMMON_OUTPUT_PATH:
		return "ERROR_COMMON_OUTPUT_PATH: Output path can be changed in ready state (stop)";
	case ERROR_COMMON_OUTPUT_INIT:
		return "ERROR_COMMON_OUTPUT_INIT: IP can not start if output path is not set";
	case ERROR_CONTROL_BYPASS:
		return "ERROR_CONTROL_BYPASS";
	case ERROR_OTF_INPUT_FORMAT:
		return "ERROR_OTF_INPUT_FORMAT: Invalid format  (DRC: YUV444, FD: YUV444, 422, 420)";
	case ERROR_OTF_INPUT_WIDTH:
		return "ERROR_OTF_INPUT_WIDTH: Invalid width (DRC: 128~8192, FD: 32~8190)";
	case ERROR_OTF_INPUT_HEIGHT:
		return "ERROR_OTF_INPUT_HEIGHT: Invalid bit-width (DRC: 8~12bits, FD: 8bit)";
	case ERROR_OTF_INPUT_BIT_WIDTH:
		return "ERROR_OTF_INPUT_BIT_WIDTH: Invalid bit-width (DRC: 8~12bits, FD: 8bit)";
	case ERROR_DMA_INPUT_WIDTH:
		return "ERROR_DMA_INPUT_WIDTH: Invalid width (DRC: 128~8192, FD: 32~8190)";
	case ERROR_DMA_INPUT_HEIGHT:
		return "ERROR_DMA_INPUT_HEIGHT: Invalid height (DRC: 64~8192, FD: 16~8190)";
	case ERROR_DMA_INPUT_FORMAT:
		return "ERROR_DMA_INPUT_FORMAT: Invalid format (DRC: YUV444 or YUV422, FD: YUV444,422,420)";
	case ERROR_DMA_INPUT_BIT_WIDTH:
		return "ERROR_DMA_INPUT_BIT_WIDTH: Invalid bit-width (DRC: 8~12bits, FD: 8bit)";
	case ERROR_DMA_INPUT_ORDER:
		return "ERROR_DMA_INPUT_ORDER: Invalid order(DRC: YYCbCr,YCbYCr,FD:NO,YYCbCr,YCbYCr,CbCr,CrCb)";
	case ERROR_DMA_INPUT_PLANE:
		return "ERROR_DMA_INPUT_PLANE: Invalid plane (DRC: 3, FD: 1, 2, 3)";
	case ERROR_OTF_OUTPUT_WIDTH:
		return "ERROR_OTF_OUTPUT_WIDTH: Invalid width (DRC: 128~8192)";
	case ERROR_OTF_OUTPUT_HEIGHT:
		return "ERROR_OTF_OUTPUT_HEIGHT: Invalid height (DRC: 64~8192)";
	case ERROR_OTF_OUTPUT_FORMAT:
		return "ERROR_OTF_OUTPUT_FORMAT: Invalid format (DRC: YUV444)";
	case ERROR_OTF_OUTPUT_BIT_WIDTH:
		return "ERROR_OTF_OUTPUT_BIT_WIDTH: Invalid bit-width (DRC: 8~12bits, FD: 8bit)";
	case ERROR_DMA_OUTPUT_WIDTH:
		return "ERROR_DMA_OUTPUT_WIDTH";
	case ERROR_DMA_OUTPUT_HEIGHT:
		return "ERROR_DMA_OUTPUT_HEIGHT";
	case ERROR_DMA_OUTPUT_FORMAT:
		return "ERROR_DMA_OUTPUT_FORMAT";
	case ERROR_DMA_OUTPUT_BIT_WIDTH:
		return "ERROR_DMA_OUTPUT_BIT_WIDTH";
	case ERROR_DMA_OUTPUT_PLANE:
		return "ERROR_DMA_OUTPUT_PLANE";
	case ERROR_DMA_OUTPUT_ORDER:
		return "ERROR_DMA_OUTPUT_ORDER";

	/* Sensor Error(100~199) */
	case ERROR_SENSOR_I2C_FAIL:
		return "ERROR_SENSOR_I2C_FAIL";
	case ERROR_SENSOR_INVALID_FRAMERATE:
		return "ERROR_SENSOR_INVALID_FRAMERATE";
	case ERROR_SENSOR_INVALID_EXPOSURETIME:
		return "ERROR_SENSOR_INVALID_EXPOSURETIME";
	case ERROR_SENSOR_INVALID_SIZE:
		return "ERROR_SENSOR_INVALID_SIZE";
	case ERROR_SENSOR_INVALID_SETTING:
		return "ERROR_SENSOR_INVALID_SETTING";
	case ERROR_SENSOR_ACTUATOR_INIT_FAIL:
		return "ERROR_SENSOR_ACTUATOR_INIT_FAIL";
	case ERROR_SENSOR_INVALID_AF_POS:
		return "ERROR_SENSOR_INVALID_AF_POS";
	case ERROR_SENSOR_UNSUPPORT_FUNC:
		return "ERROR_SENSOR_UNSUPPORT_FUNC";
	case ERROR_SENSOR_UNSUPPORT_PERI:
		return "ERROR_SENSOR_UNSUPPORT_PERI";
	case ERROR_SENSOR_UNSUPPORT_AF:
		return "ERROR_SENSOR_UNSUPPORT_AF";

	/* ISP Error (200~299) */
	case ERROR_ISP_AF_BUSY:
		return "ERROR_ISP_AF_BUSY";
	case ERROR_ISP_AF_INVALID_COMMAND:
		return "ERROR_ISP_AF_INVALID_COMMAND";
	case ERROR_ISP_AF_INVALID_MODE:
		return "ERROR_ISP_AF_INVALID_MODE";

	/* DRC Error (300~399) */
	/* FD Error  (400~499) */
	case ERROR_FD_CONFIG_MAX_NUMBER_STATE:
		return "ERROR_FD_CONFIG_MAX_NUMBER_STATE";
	case ERROR_FD_CONFIG_MAX_NUMBER_INVALID:
		return "ERROR_FD_CONFIG_MAX_NUMBER_INVALID";
	case ERROR_FD_CONFIG_YAW_ANGLE_STATE:
		return "ERROR_FD_CONFIG_YAW_ANGLE_STATE";
	case ERROR_FD_CONFIG_YAW_ANGLE_INVALID:
		return "ERROR_FD_CONFIG_YAW_ANGLE_INVALID\n";
	case ERROR_FD_CONFIG_ROLL_ANGLE_STATE:
		return "ERROR_FD_CONFIG_ROLL_ANGLE_STATE";
	case ERROR_FD_CONFIG_ROLL_ANGLE_INVALID:
		return "ERROR_FD_CONFIG_ROLL_ANGLE_INVALID";
	case ERROR_FD_CONFIG_SMILE_MODE_INVALID:
		return "ERROR_FD_CONFIG_SMILE_MODE_INVALID";
	case ERROR_FD_CONFIG_BLINK_MODE_INVALID:
		return "ERROR_FD_CONFIG_BLINK_MODE_INVALID";
	case ERROR_FD_CONFIG_EYES_DETECT_INVALID:
		return "ERROR_FD_CONFIG_EYES_DETECT_INVALID";
	case ERROR_FD_CONFIG_MOUTH_DETECT_INVALID:
		return "ERROR_FD_CONFIG_MOUTH_DETECT_INVALID";
	case ERROR_FD_CONFIG_ORIENTATION_STATE:
		return "ERROR_FD_CONFIG_ORIENTATION_STATE";
	case ERROR_FD_CONFIG_ORIENTATION_INVALID:
		return "ERROR_FD_CONFIG_ORIENTATION_INVALID";
	case ERROR_FD_CONFIG_ORIENTATION_VALUE_INVALID:
		return "ERROR_FD_CONFIG_ORIENTATION_VALUE_INVALID";
	case ERROR_FD_RESULT:
		return "ERROR_FD_RESULT";
	case ERROR_FD_MODE:
		return "ERROR_FD_MODE";
	default:
		return "Unknown";
	}
}

const char *fimc_is_strerr(unsigned int error)
{
	error &= ~IS_ERROR_TIME_OUT_FLAG;

	switch (error) {
	/* General */
	case IS_ERROR_INVALID_COMMAND:
		return "IS_ERROR_INVALID_COMMAND";
	case IS_ERROR_REQUEST_FAIL:
		return "IS_ERROR_REQUEST_FAIL";
	case IS_ERROR_INVALID_SCENARIO:
		return "IS_ERROR_INVALID_SCENARIO";
	case IS_ERROR_INVALID_SENSORID:
		return "IS_ERROR_INVALID_SENSORID";
	case IS_ERROR_INVALID_MODE_CHANGE:
		return "IS_ERROR_INVALID_MODE_CHANGE";
	case IS_ERROR_INVALID_MAGIC_NUMBER:
		return "IS_ERROR_INVALID_MAGIC_NUMBER";
	case IS_ERROR_INVALID_SETFILE_HDR:
		return "IS_ERROR_INVALID_SETFILE_HDR";
	case IS_ERROR_BUSY:
		return "IS_ERROR_BUSY";
	case IS_ERROR_SET_PARAMETER:
		return "IS_ERROR_SET_PARAMETER";
	case IS_ERROR_INVALID_PATH:
		return "IS_ERROR_INVALID_PATH";
	case IS_ERROR_OPEN_SENSOR_FAIL:
		return "IS_ERROR_OPEN_SENSOR_FAIL";
	case IS_ERROR_ENTRY_MSG_THREAD_DOWN:
		return "IS_ERROR_ENTRY_MSG_THREAD_DOWN";
	case IS_ERROR_ISP_FRAME_END_NOT_DONE:
		return "IS_ERROR_ISP_FRAME_END_NOT_DONE";
	case IS_ERROR_DRC_FRAME_END_NOT_DONE:
		return "IS_ERROR_DRC_FRAME_END_NOT_DONE";
	case IS_ERROR_SCALERC_FRAME_END_NOT_DONE:
		return "IS_ERROR_SCALERC_FRAME_END_NOT_DONE";
	case IS_ERROR_ODC_FRAME_END_NOT_DONE:
		return "IS_ERROR_ODC_FRAME_END_NOT_DONE";
	case IS_ERROR_DIS_FRAME_END_NOT_DONE:
		return "IS_ERROR_DIS_FRAME_END_NOT_DONE";
	case IS_ERROR_TDNR_FRAME_END_NOT_DONE:
		return "IS_ERROR_TDNR_FRAME_END_NOT_DONE";
	case IS_ERROR_SCALERP_FRAME_END_NOT_DONE:
		return "IS_ERROR_SCALERP_FRAME_END_NOT_DONE";
	case IS_ERROR_WAIT_STREAM_OFF_NOT_DONE:
		return "IS_ERROR_WAIT_STREAM_OFF_NOT_DONE";
	case IS_ERROR_NO_MSG_IS_RECEIVED:
		return "IS_ERROR_NO_MSG_IS_RECEIVED";
	case IS_ERROR_SENSOR_MSG_FAIL:
		return "IS_ERROR_SENSOR_MSG_FAIL";
	case IS_ERROR_ISP_MSG_FAIL:
		return "IS_ERROR_ISP_MSG_FAIL";
	case IS_ERROR_DRC_MSG_FAIL:
		return "IS_ERROR_DRC_MSG_FAIL";
	case IS_ERROR_LHFD_MSG_FAIL:
		return "IS_ERROR_LHFD_MSG_FAIL";
	case IS_ERROR_UNKNOWN:
		return "IS_ERROR_UNKNOWN";

	/* Sensor */
	case IS_ERROR_SENSOR_PWRDN_FAIL:
		return "IS_ERROR_SENSOR_PWRDN_FAIL";

	/* ISP */
	case IS_ERROR_ISP_PWRDN_FAIL:
		return "IS_ERROR_ISP_PWRDN_FAIL";
	case IS_ERROR_ISP_MULTIPLE_INPUT:
		return "IS_ERROR_ISP_MULTIPLE_INPUT";
	case IS_ERROR_ISP_ABSENT_INPUT:
		return "IS_ERROR_ISP_ABSENT_INPUT";
	case IS_ERROR_ISP_ABSENT_OUTPUT:
		return "IS_ERROR_ISP_ABSENT_OUTPUT";
	case IS_ERROR_ISP_NONADJACENT_OUTPUT:
		return "IS_ERROR_ISP_NONADJACENT_OUTPUT";
	case IS_ERROR_ISP_FORMAT_MISMATCH:
		return "IS_ERROR_ISP_FORMAT_MISMATCH";
	case IS_ERROR_ISP_WIDTH_MISMATCH:
		return "IS_ERROR_ISP_WIDTH_MISMATCH";
	case IS_ERROR_ISP_HEIGHT_MISMATCH:
		return "IS_ERROR_ISP_HEIGHT_MISMATCH";
	case IS_ERROR_ISP_BITWIDTH_MISMATCH:
		return "IS_ERROR_ISP_BITWIDTH_MISMATCH";
	case IS_ERROR_ISP_FRAME_END_TIME_OUT:
		return "IS_ERROR_ISP_FRAME_END_TIME_OUT";

	/* DRC */
	case IS_ERROR_DRC_PWRDN_FAIL:
		return "IS_ERROR_DRC_PWRDN_FAIL";
	case IS_ERROR_DRC_MULTIPLE_INPUT:
		return "IS_ERROR_DRC_MULTIPLE_INPUT";
	case IS_ERROR_DRC_ABSENT_INPUT:
		return "IS_ERROR_DRC_ABSENT_INPUT";
	case IS_ERROR_DRC_NONADJACENT_INPUT:
		return "IS_ERROR_DRC_NONADJACENT_INPUT";
	case IS_ERROR_DRC_ABSENT_OUTPUT:
		return "IS_ERROR_DRC_ABSENT_OUTPUT";
	case IS_ERROR_DRC_NONADJACENT_OUTPUT:
		return "IS_ERROR_DRC_NONADJACENT_OUTPUT";
	case IS_ERROR_DRC_FORMAT_MISMATCH:
		return "IS_ERROR_DRC_FORMAT_MISMATCH";
	case IS_ERROR_DRC_WIDTH_MISMATCH:
		return "IS_ERROR_DRC_WIDTH_MISMATCH";
	case IS_ERROR_DRC_HEIGHT_MISMATCH:
		return "IS_ERROR_DRC_HEIGHT_MISMATCH";
	case IS_ERROR_DRC_BITWIDTH_MISMATCH:
		return "IS_ERROR_DRC_BITWIDTH_MISMATCH";
	case IS_ERROR_DRC_FRAME_END_TIME_OUT:
		return "IS_ERROR_DRC_FRAME_END_TIME_OUT";

	/* FD */
	case IS_ERROR_FD_PWRDN_FAIL:
		return "IS_ERROR_FD_PWRDN_FAIL";
	case IS_ERROR_FD_MULTIPLE_INPUT:
		return "IS_ERROR_FD_MULTIPLE_INPUT";
	case IS_ERROR_FD_ABSENT_INPUT:
		return "IS_ERROR_FD_ABSENT_INPUT";
	case IS_ERROR_FD_NONADJACENT_INPUT:
		return "IS_ERROR_FD_NONADJACENT_INPUT";
	case IS_ERROR_LHFD_FRAME_END_TIME_OUT:
		return "IS_ERROR_LHFD_FRAME_END_TIME_OUT";
	default:
		return "Unknown";
	}
}
