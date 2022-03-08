// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include "util/pmu.h"
#include "util/evlist.h"
#include "util/parse-events.h"

#define TOPDOWN_L1_EVENTS	"{slots,topdown-retiring,topdown-bad-spec,topdown-fe-bound,topdown-be-bound}"
#define TOPDOWN_L2_EVENTS	"{slots,topdown-retiring,topdown-bad-spec,topdown-fe-bound,topdown-be-bound,topdown-heavy-ops,topdown-br-mispredict,topdown-fetch-lat,topdown-mem-bound}"

int arch_evlist__add_default_attrs(struct evlist *evlist)
{
	if (!pmu_have_event("cpu", "slots"))
		return 0;

	if (pmu_have_event("cpu", "topdown-heavy-ops"))
		return parse_events(evlist, TOPDOWN_L2_EVENTS, NULL);
	else
		return parse_events(evlist, TOPDOWN_L1_EVENTS, NULL);
}
