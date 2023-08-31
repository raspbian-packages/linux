// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Kajol Jain, IBM Corp.
 */

#include <stdio.h>
#include <stdlib.h>

#include "../event.h"
#include "utils.h"
#include "../sampling_tests/misc.h"

/*
 * Primary PMU events used here are PM_MRK_INST_CMPL (0x401e0) and
 * PM_THRESH_MET (0x101ec).
 * Threshold event selection used is issue to complete
 * Sampling criteria is Load or Store only sampling
 */
#define EventCode_1 0x35340401e0
#define EventCode_2 0x35540101ec
#define EventCode_3 0x35340101ec

/*
 * Testcase for group constraint check of thresh_sel bits which is
 * used to program thresh select field in Monitor Mode Control Register A
 * (MMCRA: 45-57).
 * All events in the group should match thresh sel bits otherwise
 * event_open for the group will fail.
 */
static int group_constraint_thresh_sel(void)
{
	struct event event, leader;

	/* Check for platform support for the test */
	SKIP_IF(platform_check_for_tests());

	/* Init the events for the group contraint thresh select test */
	event_init(&leader, EventCode_1);
	FAIL_IF(event_open(&leader));

	event_init(&event, EventCode_2);

	/* Expected to fail as sibling and leader event request different thresh_sel bits */
	FAIL_IF(!event_open_with_group(&event, leader.fd));

	event_close(&event);

	/* Init the event for the group contraint thresh select test */
	event_init(&event, EventCode_3);

	 /* Expected to succeed as sibling and leader event request same thresh_sel bits */
	FAIL_IF(event_open_with_group(&event, leader.fd));

	event_close(&leader);
	event_close(&event);

	return 0;
}

int main(void)
{
	return test_harness(group_constraint_thresh_sel, "group_constraint_thresh_sel");
}
