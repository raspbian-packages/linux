// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include "i915_drv.h"
#include "intel_display.h"
#include "intel_display_types.h"
#include "intel_dp_mst.h"
#include "intel_tc.h"

static const char *tc_port_mode_name(enum tc_port_mode mode)
{
	static const char * const names[] = {
		[TC_PORT_TBT_ALT] = "tbt-alt",
		[TC_PORT_DP_ALT] = "dp-alt",
		[TC_PORT_LEGACY] = "legacy",
	};

	if (WARN_ON(mode >= ARRAY_SIZE(names)))
		mode = TC_PORT_TBT_ALT;

	return names[mode];
}

static void
tc_port_load_fia_params(struct drm_i915_private *i915,
			struct intel_digital_port *dig_port)
{
	enum port port = dig_port->base.port;
	enum tc_port tc_port = intel_port_to_tc(i915, port);
	u32 modular_fia;

	if (INTEL_INFO(i915)->display.has_modular_fia) {
		modular_fia = intel_uncore_read(&i915->uncore,
						PORT_TX_DFLEXDPSP(FIA1));
		modular_fia &= MODULAR_FIA_MASK;
	} else {
		modular_fia = 0;
	}

	/*
	 * Each Modular FIA instance houses 2 TC ports. In SOC that has more
	 * than two TC ports, there are multiple instances of Modular FIA.
	 */
	if (modular_fia) {
		dig_port->tc_phy_fia = tc_port / 2;
		dig_port->tc_phy_fia_idx = tc_port % 2;
	} else {
		dig_port->tc_phy_fia = FIA1;
		dig_port->tc_phy_fia_idx = tc_port;
	}
}

u32 intel_tc_port_get_lane_mask(struct intel_digital_port *dig_port)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	struct intel_uncore *uncore = &i915->uncore;
	u32 lane_mask;

	lane_mask = intel_uncore_read(uncore,
				      PORT_TX_DFLEXDPSP(dig_port->tc_phy_fia));

	WARN_ON(lane_mask == 0xffffffff);

	lane_mask &= DP_LANE_ASSIGNMENT_MASK(dig_port->tc_phy_fia_idx);
	return lane_mask >> DP_LANE_ASSIGNMENT_SHIFT(dig_port->tc_phy_fia_idx);
}

u32 intel_tc_port_get_pin_assignment_mask(struct intel_digital_port *dig_port)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	struct intel_uncore *uncore = &i915->uncore;
	u32 pin_mask;

	pin_mask = intel_uncore_read(uncore,
				     PORT_TX_DFLEXPA1(dig_port->tc_phy_fia));

	WARN_ON(pin_mask == 0xffffffff);

	return (pin_mask & DP_PIN_ASSIGNMENT_MASK(dig_port->tc_phy_fia_idx)) >>
	       DP_PIN_ASSIGNMENT_SHIFT(dig_port->tc_phy_fia_idx);
}

int intel_tc_port_fia_max_lane_count(struct intel_digital_port *dig_port)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	intel_wakeref_t wakeref;
	u32 lane_mask;

	if (dig_port->tc_mode != TC_PORT_DP_ALT)
		return 4;

	lane_mask = 0;
	with_intel_display_power(i915, POWER_DOMAIN_DISPLAY_CORE, wakeref)
		lane_mask = intel_tc_port_get_lane_mask(dig_port);

	switch (lane_mask) {
	default:
		MISSING_CASE(lane_mask);
		/* fall-through */
	case 0x1:
	case 0x2:
	case 0x4:
	case 0x8:
		return 1;
	case 0x3:
	case 0xc:
		return 2;
	case 0xf:
		return 4;
	}
}

void intel_tc_port_set_fia_lane_count(struct intel_digital_port *dig_port,
				      int required_lanes)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	bool lane_reversal = dig_port->saved_port_bits & DDI_BUF_PORT_REVERSAL;
	struct intel_uncore *uncore = &i915->uncore;
	u32 val;

	WARN_ON(lane_reversal && dig_port->tc_mode != TC_PORT_LEGACY);

	val = intel_uncore_read(uncore,
				PORT_TX_DFLEXDPMLE1(dig_port->tc_phy_fia));
	val &= ~DFLEXDPMLE1_DPMLETC_MASK(dig_port->tc_phy_fia_idx);

	switch (required_lanes) {
	case 1:
		val |= lane_reversal ?
			DFLEXDPMLE1_DPMLETC_ML3(dig_port->tc_phy_fia_idx) :
			DFLEXDPMLE1_DPMLETC_ML0(dig_port->tc_phy_fia_idx);
		break;
	case 2:
		val |= lane_reversal ?
			DFLEXDPMLE1_DPMLETC_ML3_2(dig_port->tc_phy_fia_idx) :
			DFLEXDPMLE1_DPMLETC_ML1_0(dig_port->tc_phy_fia_idx);
		break;
	case 4:
		val |= DFLEXDPMLE1_DPMLETC_ML3_0(dig_port->tc_phy_fia_idx);
		break;
	default:
		MISSING_CASE(required_lanes);
	}

	intel_uncore_write(uncore,
			   PORT_TX_DFLEXDPMLE1(dig_port->tc_phy_fia), val);
}

static void tc_port_fixup_legacy_flag(struct intel_digital_port *dig_port,
				      u32 live_status_mask)
{
	u32 valid_hpd_mask;

	if (dig_port->tc_legacy_port)
		valid_hpd_mask = BIT(TC_PORT_LEGACY);
	else
		valid_hpd_mask = BIT(TC_PORT_DP_ALT) |
				 BIT(TC_PORT_TBT_ALT);

	if (!(live_status_mask & ~valid_hpd_mask))
		return;

	/* If live status mismatches the VBT flag, trust the live status. */
	DRM_ERROR("Port %s: live status %08x mismatches the legacy port flag, fix flag\n",
		  dig_port->tc_port_name, live_status_mask);

	dig_port->tc_legacy_port = !dig_port->tc_legacy_port;
}

static u32 tc_port_live_status_mask(struct intel_digital_port *dig_port)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	enum tc_port tc_port = intel_port_to_tc(i915, dig_port->base.port);
	struct intel_uncore *uncore = &i915->uncore;
	u32 mask = 0;
	u32 val;

	val = intel_uncore_read(uncore,
				PORT_TX_DFLEXDPSP(dig_port->tc_phy_fia));

	if (val == 0xffffffff) {
		DRM_DEBUG_KMS("Port %s: PHY in TCCOLD, nothing connected\n",
			      dig_port->tc_port_name);
		return mask;
	}

	if (val & TC_LIVE_STATE_TBT(dig_port->tc_phy_fia_idx))
		mask |= BIT(TC_PORT_TBT_ALT);
	if (val & TC_LIVE_STATE_TC(dig_port->tc_phy_fia_idx))
		mask |= BIT(TC_PORT_DP_ALT);

	if (intel_uncore_read(uncore, SDEISR) & SDE_TC_HOTPLUG_ICP(tc_port))
		mask |= BIT(TC_PORT_LEGACY);

	/* The sink can be connected only in a single mode. */
	if (!WARN_ON(hweight32(mask) > 1))
		tc_port_fixup_legacy_flag(dig_port, mask);

	return mask;
}

static bool icl_tc_phy_status_complete(struct intel_digital_port *dig_port)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	struct intel_uncore *uncore = &i915->uncore;
	u32 val;

	val = intel_uncore_read(uncore,
				PORT_TX_DFLEXDPPMS(dig_port->tc_phy_fia));
	if (val == 0xffffffff) {
		DRM_DEBUG_KMS("Port %s: PHY in TCCOLD, assuming not complete\n",
			      dig_port->tc_port_name);
		return false;
	}

	return val & DP_PHY_MODE_STATUS_COMPLETED(dig_port->tc_phy_fia_idx);
}

static bool icl_tc_phy_set_safe_mode(struct intel_digital_port *dig_port,
				     bool enable)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	struct intel_uncore *uncore = &i915->uncore;
	u32 val;

	val = intel_uncore_read(uncore,
				PORT_TX_DFLEXDPCSSS(dig_port->tc_phy_fia));
	if (val == 0xffffffff) {
		DRM_DEBUG_KMS("Port %s: PHY in TCCOLD, can't set safe-mode to %s\n",
			      dig_port->tc_port_name,
			      enableddisabled(enable));

		return false;
	}

	val &= ~DP_PHY_MODE_STATUS_NOT_SAFE(dig_port->tc_phy_fia_idx);
	if (!enable)
		val |= DP_PHY_MODE_STATUS_NOT_SAFE(dig_port->tc_phy_fia_idx);

	intel_uncore_write(uncore,
			   PORT_TX_DFLEXDPCSSS(dig_port->tc_phy_fia), val);

	if (enable && wait_for(!icl_tc_phy_status_complete(dig_port), 10))
		DRM_DEBUG_KMS("Port %s: PHY complete clear timed out\n",
			      dig_port->tc_port_name);

	return true;
}

static bool icl_tc_phy_is_in_safe_mode(struct intel_digital_port *dig_port)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	struct intel_uncore *uncore = &i915->uncore;
	u32 val;

	val = intel_uncore_read(uncore,
				PORT_TX_DFLEXDPCSSS(dig_port->tc_phy_fia));
	if (val == 0xffffffff) {
		DRM_DEBUG_KMS("Port %s: PHY in TCCOLD, assume safe mode\n",
			      dig_port->tc_port_name);
		return true;
	}

	return !(val & DP_PHY_MODE_STATUS_NOT_SAFE(dig_port->tc_phy_fia_idx));
}

/*
 * This function implements the first part of the Connect Flow described by our
 * specification, Gen11 TypeC Programming chapter. The rest of the flow (reading
 * lanes, EDID, etc) is done as needed in the typical places.
 *
 * Unlike the other ports, type-C ports are not available to use as soon as we
 * get a hotplug. The type-C PHYs can be shared between multiple controllers:
 * display, USB, etc. As a result, handshaking through FIA is required around
 * connect and disconnect to cleanly transfer ownership with the controller and
 * set the type-C power state.
 */
static void icl_tc_phy_connect(struct intel_digital_port *dig_port,
			       int required_lanes)
{
	int max_lanes;

	if (!icl_tc_phy_status_complete(dig_port)) {
		DRM_DEBUG_KMS("Port %s: PHY not ready\n",
			      dig_port->tc_port_name);
		goto out_set_tbt_alt_mode;
	}

	if (!icl_tc_phy_set_safe_mode(dig_port, false) &&
	    !WARN_ON(dig_port->tc_legacy_port))
		goto out_set_tbt_alt_mode;

	max_lanes = intel_tc_port_fia_max_lane_count(dig_port);
	if (dig_port->tc_legacy_port) {
		WARN_ON(max_lanes != 4);
		dig_port->tc_mode = TC_PORT_LEGACY;

		return;
	}

	/*
	 * Now we have to re-check the live state, in case the port recently
	 * became disconnected. Not necessary for legacy mode.
	 */
	if (!(tc_port_live_status_mask(dig_port) & BIT(TC_PORT_DP_ALT))) {
		DRM_DEBUG_KMS("Port %s: PHY sudden disconnect\n",
			      dig_port->tc_port_name);
		goto out_set_safe_mode;
	}

	if (max_lanes < required_lanes) {
		DRM_DEBUG_KMS("Port %s: PHY max lanes %d < required lanes %d\n",
			      dig_port->tc_port_name,
			      max_lanes, required_lanes);
		goto out_set_safe_mode;
	}

	dig_port->tc_mode = TC_PORT_DP_ALT;

	return;

out_set_safe_mode:
	icl_tc_phy_set_safe_mode(dig_port, true);
out_set_tbt_alt_mode:
	dig_port->tc_mode = TC_PORT_TBT_ALT;
}

/*
 * See the comment at the connect function. This implements the Disconnect
 * Flow.
 */
static void icl_tc_phy_disconnect(struct intel_digital_port *dig_port)
{
	switch (dig_port->tc_mode) {
	case TC_PORT_LEGACY:
		/* Nothing to do, we never disconnect from legacy mode */
		break;
	case TC_PORT_DP_ALT:
		icl_tc_phy_set_safe_mode(dig_port, true);
		dig_port->tc_mode = TC_PORT_TBT_ALT;
		break;
	case TC_PORT_TBT_ALT:
		/* Nothing to do, we stay in TBT-alt mode */
		break;
	default:
		MISSING_CASE(dig_port->tc_mode);
	}
}

static bool icl_tc_phy_is_connected(struct intel_digital_port *dig_port)
{
	if (!icl_tc_phy_status_complete(dig_port)) {
		DRM_DEBUG_KMS("Port %s: PHY status not complete\n",
			      dig_port->tc_port_name);
		return dig_port->tc_mode == TC_PORT_TBT_ALT;
	}

	if (icl_tc_phy_is_in_safe_mode(dig_port)) {
		DRM_DEBUG_KMS("Port %s: PHY still in safe mode\n",
			      dig_port->tc_port_name);

		return false;
	}

	return dig_port->tc_mode == TC_PORT_DP_ALT ||
	       dig_port->tc_mode == TC_PORT_LEGACY;
}

static enum tc_port_mode
intel_tc_port_get_current_mode(struct intel_digital_port *dig_port)
{
	u32 live_status_mask = tc_port_live_status_mask(dig_port);
	bool in_safe_mode = icl_tc_phy_is_in_safe_mode(dig_port);
	enum tc_port_mode mode;

	if (in_safe_mode || WARN_ON(!icl_tc_phy_status_complete(dig_port)))
		return TC_PORT_TBT_ALT;

	mode = dig_port->tc_legacy_port ? TC_PORT_LEGACY : TC_PORT_DP_ALT;
	if (live_status_mask) {
		enum tc_port_mode live_mode = fls(live_status_mask) - 1;

		if (!WARN_ON(live_mode == TC_PORT_TBT_ALT))
			mode = live_mode;
	}

	return mode;
}

static enum tc_port_mode
intel_tc_port_get_target_mode(struct intel_digital_port *dig_port)
{
	u32 live_status_mask = tc_port_live_status_mask(dig_port);

	if (live_status_mask)
		return fls(live_status_mask) - 1;

	return icl_tc_phy_status_complete(dig_port) &&
	       dig_port->tc_legacy_port ? TC_PORT_LEGACY :
					  TC_PORT_TBT_ALT;
}

static void intel_tc_port_reset_mode(struct intel_digital_port *dig_port,
				     int required_lanes)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	enum tc_port_mode old_tc_mode = dig_port->tc_mode;

	intel_display_power_flush_work(i915);
	WARN_ON(intel_display_power_is_enabled(i915,
					       intel_aux_power_domain(dig_port)));

	icl_tc_phy_disconnect(dig_port);
	icl_tc_phy_connect(dig_port, required_lanes);

	DRM_DEBUG_KMS("Port %s: TC port mode reset (%s -> %s)\n",
		      dig_port->tc_port_name,
		      tc_port_mode_name(old_tc_mode),
		      tc_port_mode_name(dig_port->tc_mode));
}

static void
intel_tc_port_link_init_refcount(struct intel_digital_port *dig_port,
				 int refcount)
{
	WARN_ON(dig_port->tc_link_refcount);
	dig_port->tc_link_refcount = refcount;
}

void intel_tc_port_sanitize(struct intel_digital_port *dig_port)
{
	struct intel_encoder *encoder = &dig_port->base;
	int active_links = 0;

	mutex_lock(&dig_port->tc_lock);

	dig_port->tc_mode = intel_tc_port_get_current_mode(dig_port);
	if (dig_port->dp.is_mst)
		active_links = intel_dp_mst_encoder_active_links(dig_port);
	else if (encoder->base.crtc)
		active_links = to_intel_crtc(encoder->base.crtc)->active;

	if (active_links) {
		if (!icl_tc_phy_is_connected(dig_port))
			DRM_DEBUG_KMS("Port %s: PHY disconnected with %d active link(s)\n",
				      dig_port->tc_port_name, active_links);
		intel_tc_port_link_init_refcount(dig_port, active_links);

		goto out;
	}

	if (dig_port->tc_legacy_port)
		icl_tc_phy_connect(dig_port, 1);

out:
	DRM_DEBUG_KMS("Port %s: sanitize mode (%s)\n",
		      dig_port->tc_port_name,
		      tc_port_mode_name(dig_port->tc_mode));

	mutex_unlock(&dig_port->tc_lock);
}

static bool intel_tc_port_needs_reset(struct intel_digital_port *dig_port)
{
	return intel_tc_port_get_target_mode(dig_port) != dig_port->tc_mode;
}

/*
 * The type-C ports are different because even when they are connected, they may
 * not be available/usable by the graphics driver: see the comment on
 * icl_tc_phy_connect(). So in our driver instead of adding the additional
 * concept of "usable" and make everything check for "connected and usable" we
 * define a port as "connected" when it is not only connected, but also when it
 * is usable by the rest of the driver. That maintains the old assumption that
 * connected ports are usable, and avoids exposing to the users objects they
 * can't really use.
 */
bool intel_tc_port_connected(struct intel_digital_port *dig_port)
{
	bool is_connected;

	intel_tc_port_lock(dig_port);
	is_connected = tc_port_live_status_mask(dig_port) &
		       BIT(dig_port->tc_mode);
	intel_tc_port_unlock(dig_port);

	return is_connected;
}

static void __intel_tc_port_lock(struct intel_digital_port *dig_port,
				 int required_lanes)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	intel_wakeref_t wakeref;

	wakeref = intel_display_power_get(i915, POWER_DOMAIN_DISPLAY_CORE);

	mutex_lock(&dig_port->tc_lock);

	if (!dig_port->tc_link_refcount &&
	    intel_tc_port_needs_reset(dig_port))
		intel_tc_port_reset_mode(dig_port, required_lanes);

	WARN_ON(dig_port->tc_lock_wakeref);
	dig_port->tc_lock_wakeref = wakeref;
}

void intel_tc_port_lock(struct intel_digital_port *dig_port)
{
	__intel_tc_port_lock(dig_port, 1);
}

void intel_tc_port_unlock(struct intel_digital_port *dig_port)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	intel_wakeref_t wakeref = fetch_and_zero(&dig_port->tc_lock_wakeref);

	mutex_unlock(&dig_port->tc_lock);

	intel_display_power_put_async(i915, POWER_DOMAIN_DISPLAY_CORE,
				      wakeref);
}

bool intel_tc_port_ref_held(struct intel_digital_port *dig_port)
{
	return mutex_is_locked(&dig_port->tc_lock) ||
	       dig_port->tc_link_refcount;
}

void intel_tc_port_get_link(struct intel_digital_port *dig_port,
			    int required_lanes)
{
	__intel_tc_port_lock(dig_port, required_lanes);
	dig_port->tc_link_refcount++;
	intel_tc_port_unlock(dig_port);
}

void intel_tc_port_put_link(struct intel_digital_port *dig_port)
{
	mutex_lock(&dig_port->tc_lock);
	dig_port->tc_link_refcount--;
	mutex_unlock(&dig_port->tc_lock);
}

void intel_tc_port_init(struct intel_digital_port *dig_port, bool is_legacy)
{
	struct drm_i915_private *i915 = to_i915(dig_port->base.base.dev);
	enum port port = dig_port->base.port;
	enum tc_port tc_port = intel_port_to_tc(i915, port);

	if (WARN_ON(tc_port == PORT_TC_NONE))
		return;

	snprintf(dig_port->tc_port_name, sizeof(dig_port->tc_port_name),
		 "%c/TC#%d", port_name(port), tc_port + 1);

	mutex_init(&dig_port->tc_lock);
	dig_port->tc_legacy_port = is_legacy;
	dig_port->tc_link_refcount = 0;
	tc_port_load_fia_params(i915, dig_port);
}
