/* SPDX-License-Identifier: GPL-2.0  */
/*
 * Copyright (C) STMicroelectronics 2022 - All Rights Reserved
 * Author: Gabriel Fernandez <gabriel.fernandez@foss.st.com> for STMicroelectronics.
 */

struct clk_stm32_reset_data {
	const struct reset_control_ops *ops;
	unsigned int nr_lines;
	u32 clear_offset;
};

int stm32_rcc_reset_init(struct device *dev, struct clk_stm32_reset_data *data,
			 void __iomem *base);
