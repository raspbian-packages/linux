/*
 * arch/arm/mach-netx/time.c
 *
 * Copyright (c) 2005 Sascha Hauer <s.hauer@pengutronix.de>, Pengutronix
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/io.h>

#include <mach/hardware.h>
#include <asm/mach/time.h>
#include <mach/netx-regs.h>

#define NETX_CLOCK_FREQ 100000000
#define NETX_LATCH DIV_ROUND_CLOSEST(NETX_CLOCK_FREQ, HZ)

#define TIMER_CLOCKEVENT 0
#define TIMER_CLOCKSOURCE 1

static inline void timer_shutdown(struct clock_event_device *evt)
{
	/* disable timer */
	writel(0, NETX_GPIO_COUNTER_CTRL(TIMER_CLOCKEVENT));
}

static int netx_shutdown(struct clock_event_device *evt)
{
	timer_shutdown(evt);

	return 0;
}

static int netx_set_oneshot(struct clock_event_device *evt)
{
	u32 tmode = NETX_GPIO_COUNTER_CTRL_IRQ_EN | NETX_GPIO_COUNTER_CTRL_RUN;

	timer_shutdown(evt);
	writel(0, NETX_GPIO_COUNTER_MAX(TIMER_CLOCKEVENT));
	writel(tmode, NETX_GPIO_COUNTER_CTRL(TIMER_CLOCKEVENT));

	return 0;
}

static int netx_set_periodic(struct clock_event_device *evt)
{
	u32 tmode = NETX_GPIO_COUNTER_CTRL_RST_EN |
		    NETX_GPIO_COUNTER_CTRL_IRQ_EN | NETX_GPIO_COUNTER_CTRL_RUN;

	timer_shutdown(evt);
	writel(NETX_LATCH, NETX_GPIO_COUNTER_MAX(TIMER_CLOCKEVENT));
	writel(tmode, NETX_GPIO_COUNTER_CTRL(TIMER_CLOCKEVENT));

	return 0;
}

static int netx_set_next_event(unsigned long evt,
		struct clock_event_device *clk)
{
	writel(0 - evt, NETX_GPIO_COUNTER_CURRENT(TIMER_CLOCKEVENT));
	return 0;
}

static struct clock_event_device netx_clockevent = {
	.name = "netx-timer" __stringify(TIMER_CLOCKEVENT),
	.features = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.set_next_event = netx_set_next_event,
	.set_state_shutdown = netx_shutdown,
	.set_state_periodic = netx_set_periodic,
	.set_state_oneshot = netx_set_oneshot,
	.tick_resume = netx_shutdown,
};

/*
 * IRQ handler for the timer
 */
static irqreturn_t
netx_timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *evt = &netx_clockevent;

	/* acknowledge interrupt */
	writel(COUNTER_BIT(0), NETX_GPIO_IRQ);

	evt->event_handler(evt);

	return IRQ_HANDLED;
}

static struct irqaction netx_timer_irq = {
	.name		= "NetX Timer Tick",
	.flags		= IRQF_TIMER | IRQF_IRQPOLL,
	.handler	= netx_timer_interrupt,
};

/*
 * Set up timer interrupt
 */
void __init netx_timer_init(void)
{
	/* disable timer initially */
	writel(0, NETX_GPIO_COUNTER_CTRL(0));

	/* Reset the timer value to zero */
	writel(0, NETX_GPIO_COUNTER_CURRENT(0));

	writel(NETX_LATCH, NETX_GPIO_COUNTER_MAX(0));

	/* acknowledge interrupt */
	writel(COUNTER_BIT(0), NETX_GPIO_IRQ);

	/* Enable the interrupt in the specific timer
	 * register and start timer
	 */
	writel(COUNTER_BIT(0), NETX_GPIO_IRQ_ENABLE);
	writel(NETX_GPIO_COUNTER_CTRL_IRQ_EN | NETX_GPIO_COUNTER_CTRL_RUN,
			NETX_GPIO_COUNTER_CTRL(0));

	setup_irq(NETX_IRQ_TIMER0, &netx_timer_irq);

	/* Setup timer one for clocksource */
	writel(0, NETX_GPIO_COUNTER_CTRL(TIMER_CLOCKSOURCE));
	writel(0, NETX_GPIO_COUNTER_CURRENT(TIMER_CLOCKSOURCE));
	writel(0xffffffff, NETX_GPIO_COUNTER_MAX(TIMER_CLOCKSOURCE));

	writel(NETX_GPIO_COUNTER_CTRL_RUN,
			NETX_GPIO_COUNTER_CTRL(TIMER_CLOCKSOURCE));

	clocksource_mmio_init(NETX_GPIO_COUNTER_CURRENT(TIMER_CLOCKSOURCE),
		"netx_timer", NETX_CLOCK_FREQ, 200, 32, clocksource_mmio_readl_up);

	/* with max_delta_ns >= delta2ns(0x800) the system currently runs fine.
	 * Adding some safety ... */
	netx_clockevent.cpumask = cpumask_of(0);
	clockevents_config_and_register(&netx_clockevent, NETX_CLOCK_FREQ,
					0xa00, 0xfffffffe);
}
