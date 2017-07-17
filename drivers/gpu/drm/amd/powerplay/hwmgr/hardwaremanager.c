/*
 * Copyright 2015 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#include "pp_debug.h"
#include <linux/errno.h>
#include "hwmgr.h"
#include "hardwaremanager.h"
#include "power_state.h"

#define PHM_FUNC_CHECK(hw) \
	do {							\
		if ((hw) == NULL || (hw)->hwmgr_func == NULL)	\
			return -EINVAL;				\
	} while (0)

bool phm_is_hw_access_blocked(struct pp_hwmgr *hwmgr)
{
	return hwmgr->block_hw_access;
}

int phm_block_hw_access(struct pp_hwmgr *hwmgr, bool block)
{
	hwmgr->block_hw_access = block;
	return 0;
}

int phm_setup_asic(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
		PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (NULL != hwmgr->hwmgr_func->asic_setup)
			return hwmgr->hwmgr_func->asic_setup(hwmgr);
	} else {
		return phm_dispatch_table(hwmgr, &(hwmgr->setup_asic),
					  NULL, NULL);
	}

	return 0;
}

int phm_power_down_asic(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
		PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (NULL != hwmgr->hwmgr_func->power_off_asic)
			return hwmgr->hwmgr_func->power_off_asic(hwmgr);
	} else {
		return phm_dispatch_table(hwmgr, &(hwmgr->power_down_asic),
					  NULL, NULL);
	}

	return 0;
}

int phm_set_power_state(struct pp_hwmgr *hwmgr,
		    const struct pp_hw_power_state *pcurrent_state,
		    const struct pp_hw_power_state *pnew_power_state)
{
	struct phm_set_power_state_input states;

	PHM_FUNC_CHECK(hwmgr);

	states.pcurrent_state = pcurrent_state;
	states.pnew_state = pnew_power_state;

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
		PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (NULL != hwmgr->hwmgr_func->power_state_set)
			return hwmgr->hwmgr_func->power_state_set(hwmgr, &states);
	} else {
		return phm_dispatch_table(hwmgr, &(hwmgr->set_power_state), &states, NULL);
	}

	return 0;
}

int phm_enable_dynamic_state_management(struct pp_hwmgr *hwmgr)
{
	int ret = 1;
	bool enabled;
	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
		PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (NULL != hwmgr->hwmgr_func->dynamic_state_management_enable)
			ret = hwmgr->hwmgr_func->dynamic_state_management_enable(hwmgr);
	} else {
		ret = phm_dispatch_table(hwmgr,
				&(hwmgr->enable_dynamic_state_management),
				NULL, NULL);
	}

	enabled = ret == 0 ? true : false;

	cgs_notify_dpm_enabled(hwmgr->device, enabled);

	return ret;
}

int phm_disable_dynamic_state_management(struct pp_hwmgr *hwmgr)
{
	int ret = -1;
	bool enabled;

	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
		PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (hwmgr->hwmgr_func->dynamic_state_management_disable)
			ret = hwmgr->hwmgr_func->dynamic_state_management_disable(hwmgr);
	} else {
		ret = phm_dispatch_table(hwmgr,
				&(hwmgr->disable_dynamic_state_management),
				NULL, NULL);
	}

	enabled = ret == 0 ? false : true;

	cgs_notify_dpm_enabled(hwmgr->device, enabled);

	return ret;
}

int phm_force_dpm_levels(struct pp_hwmgr *hwmgr, enum amd_dpm_forced_level level)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->force_dpm_level != NULL)
		return hwmgr->hwmgr_func->force_dpm_level(hwmgr, level);

	return 0;
}

int phm_apply_state_adjust_rules(struct pp_hwmgr *hwmgr,
				   struct pp_power_state *adjusted_ps,
			     const struct pp_power_state *current_ps)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->apply_state_adjust_rules != NULL)
		return hwmgr->hwmgr_func->apply_state_adjust_rules(
									hwmgr,
								 adjusted_ps,
								 current_ps);
	return 0;
}

int phm_powerdown_uvd(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->powerdown_uvd != NULL)
		return hwmgr->hwmgr_func->powerdown_uvd(hwmgr);
	return 0;
}

int phm_powergate_uvd(struct pp_hwmgr *hwmgr, bool gate)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->powergate_uvd != NULL)
		return hwmgr->hwmgr_func->powergate_uvd(hwmgr, gate);
	return 0;
}

int phm_powergate_vce(struct pp_hwmgr *hwmgr, bool gate)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->powergate_vce != NULL)
		return hwmgr->hwmgr_func->powergate_vce(hwmgr, gate);
	return 0;
}

int phm_enable_clock_power_gatings(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
		PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (NULL != hwmgr->hwmgr_func->enable_clock_power_gating)
			return hwmgr->hwmgr_func->enable_clock_power_gating(hwmgr);
	} else {
		return phm_dispatch_table(hwmgr, &(hwmgr->enable_clock_power_gatings), NULL, NULL);
	}
	return 0;
}

int phm_disable_clock_power_gatings(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
		PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (NULL != hwmgr->hwmgr_func->disable_clock_power_gating)
			return hwmgr->hwmgr_func->disable_clock_power_gating(hwmgr);
	}
	return 0;
}


int phm_display_configuration_changed(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
				 PHM_PlatformCaps_TablelessHardwareInterface)) {
		if (NULL != hwmgr->hwmgr_func->display_config_changed)
			hwmgr->hwmgr_func->display_config_changed(hwmgr);
	} else
		return phm_dispatch_table(hwmgr, &hwmgr->display_configuration_changed, NULL, NULL);
	return 0;
}

int phm_notify_smc_display_config_after_ps_adjustment(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps,
				 PHM_PlatformCaps_TablelessHardwareInterface))
		if (NULL != hwmgr->hwmgr_func->notify_smc_display_config_after_ps_adjustment)
			hwmgr->hwmgr_func->notify_smc_display_config_after_ps_adjustment(hwmgr);

	return 0;
}

int phm_stop_thermal_controller(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->stop_thermal_controller == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->stop_thermal_controller(hwmgr);
}

int phm_register_thermal_interrupt(struct pp_hwmgr *hwmgr, const void *info)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->register_internal_thermal_interrupt == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->register_internal_thermal_interrupt(hwmgr, info);
}

/**
* Initializes the thermal controller subsystem.
*
* @param    pHwMgr  the address of the powerplay hardware manager.
* @param    pTemperatureRange the address of the structure holding the temperature range.
* @exception PP_Result_Failed if any of the paramters is NULL, otherwise the return value from the dispatcher.
*/
int phm_start_thermal_controller(struct pp_hwmgr *hwmgr, struct PP_TemperatureRange *temperature_range)
{
	return phm_dispatch_table(hwmgr, &(hwmgr->start_thermal_controller), temperature_range, NULL);
}


bool phm_check_smc_update_required_for_display_configuration(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->check_smc_update_required_for_display_configuration == NULL)
		return false;

	return hwmgr->hwmgr_func->check_smc_update_required_for_display_configuration(hwmgr);
}


int phm_check_states_equal(struct pp_hwmgr *hwmgr,
				 const struct pp_hw_power_state *pstate1,
				 const struct pp_hw_power_state *pstate2,
				 bool *equal)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->check_states_equal == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->check_states_equal(hwmgr, pstate1, pstate2, equal);
}

int phm_store_dal_configuration_data(struct pp_hwmgr *hwmgr,
		    const struct amd_pp_display_configuration *display_config)
{
	PHM_FUNC_CHECK(hwmgr);

	if (display_config == NULL)
		return -EINVAL;

	hwmgr->display_config = *display_config;

	if (hwmgr->hwmgr_func->store_cc6_data == NULL)
		return -EINVAL;

	/* TODO: pass other display configuration in the future */

	if (hwmgr->hwmgr_func->store_cc6_data)
		hwmgr->hwmgr_func->store_cc6_data(hwmgr,
				display_config->cpu_pstate_separation_time,
				display_config->cpu_cc6_disable,
				display_config->cpu_pstate_disable,
				display_config->nb_pstate_switch_disable);

	return 0;
}

int phm_get_dal_power_level(struct pp_hwmgr *hwmgr,
		struct amd_pp_simple_clock_info *info)
{
	PHM_FUNC_CHECK(hwmgr);

	if (info == NULL || hwmgr->hwmgr_func->get_dal_power_level == NULL)
		return -EINVAL;
	return hwmgr->hwmgr_func->get_dal_power_level(hwmgr, info);
}

int phm_set_cpu_power_state(struct pp_hwmgr *hwmgr)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->set_cpu_power_state != NULL)
		return hwmgr->hwmgr_func->set_cpu_power_state(hwmgr);

	return 0;
}


int phm_get_performance_level(struct pp_hwmgr *hwmgr, const struct pp_hw_power_state *state,
				PHM_PerformanceLevelDesignation designation, uint32_t index,
				PHM_PerformanceLevel *level)
{
	PHM_FUNC_CHECK(hwmgr);
	if (hwmgr->hwmgr_func->get_performance_level == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->get_performance_level(hwmgr, state, designation, index, level);


}


/**
* Gets Clock Info.
*
* @param    pHwMgr  the address of the powerplay hardware manager.
* @param    pPowerState the address of the Power State structure.
* @param    pClockInfo the address of PP_ClockInfo structure where the result will be returned.
* @exception PP_Result_Failed if any of the paramters is NULL, otherwise the return value from the back-end.
*/
int phm_get_clock_info(struct pp_hwmgr *hwmgr, const struct pp_hw_power_state *state, struct pp_clock_info *pclock_info,
			PHM_PerformanceLevelDesignation designation)
{
	int result;
	PHM_PerformanceLevel performance_level;

	PHM_FUNC_CHECK(hwmgr);

	PP_ASSERT_WITH_CODE((NULL != state), "Invalid Input!", return -EINVAL);
	PP_ASSERT_WITH_CODE((NULL != pclock_info), "Invalid Input!", return -EINVAL);

	result = phm_get_performance_level(hwmgr, state, PHM_PerformanceLevelDesignation_Activity, 0, &performance_level);

	PP_ASSERT_WITH_CODE((0 == result), "Failed to retrieve minimum clocks.", return result);


	pclock_info->min_mem_clk = performance_level.memory_clock;
	pclock_info->min_eng_clk = performance_level.coreClock;
	pclock_info->min_bus_bandwidth = performance_level.nonLocalMemoryFreq * performance_level.nonLocalMemoryWidth;


	result = phm_get_performance_level(hwmgr, state, designation,
					(hwmgr->platform_descriptor.hardwareActivityPerformanceLevels - 1), &performance_level);

	PP_ASSERT_WITH_CODE((0 == result), "Failed to retrieve maximum clocks.", return result);

	pclock_info->max_mem_clk = performance_level.memory_clock;
	pclock_info->max_eng_clk = performance_level.coreClock;
	pclock_info->max_bus_bandwidth = performance_level.nonLocalMemoryFreq * performance_level.nonLocalMemoryWidth;

	return 0;
}

int phm_get_current_shallow_sleep_clocks(struct pp_hwmgr *hwmgr, const struct pp_hw_power_state *state, struct pp_clock_info *clock_info)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->get_current_shallow_sleep_clocks == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->get_current_shallow_sleep_clocks(hwmgr, state, clock_info);

}

int phm_get_clock_by_type(struct pp_hwmgr *hwmgr, enum amd_pp_clock_type type, struct amd_pp_clocks *clocks)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->get_clock_by_type == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->get_clock_by_type(hwmgr, type, clocks);

}

int phm_get_max_high_clocks(struct pp_hwmgr *hwmgr, struct amd_pp_simple_clock_info *clocks)
{
	PHM_FUNC_CHECK(hwmgr);

	if (hwmgr->hwmgr_func->get_max_high_clocks == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->get_max_high_clocks(hwmgr, clocks);
}
