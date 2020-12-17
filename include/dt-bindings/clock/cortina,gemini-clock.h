/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DT_BINDINGS_CORTINA_GEMINI_CLOCK_H
#define DT_BINDINGS_CORTINA_GEMINI_CLOCK_H

/* RTC, AHB, APB, CPU, PCI, TVC, UART clocks and 13 gates */
#define GEMINI_NUM_CLKS 20

#define GEMINI_CLK_RTC 0
#define GEMINI_CLK_AHB 1
#define GEMINI_CLK_APB 2
#define GEMINI_CLK_CPU 3
#define GEMINI_CLK_PCI 4
#define GEMINI_CLK_TVC 5
#define GEMINI_CLK_UART 6
#define GEMINI_CLK_GATES 7
#define GEMINI_CLK_GATE_SECURITY 7
#define GEMINI_CLK_GATE_GMAC0 8
#define GEMINI_CLK_GATE_GMAC1 9
#define GEMINI_CLK_GATE_SATA0 10
#define GEMINI_CLK_GATE_SATA1 11
#define GEMINI_CLK_GATE_USB0 12
#define GEMINI_CLK_GATE_USB1 13
#define GEMINI_CLK_GATE_IDE 14
#define GEMINI_CLK_GATE_PCI 15
#define GEMINI_CLK_GATE_DDR 16
#define GEMINI_CLK_GATE_FLASH 17
#define GEMINI_CLK_GATE_TVC 18
#define GEMINI_CLK_GATE_BOOT 19

#endif /* DT_BINDINGS_CORTINA_GEMINI_CLOCK_H */
