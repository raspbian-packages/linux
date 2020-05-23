// SPDX-License-Identifier: GPL-2.0
/*
 * PM domains for CPUs via genpd - managed by cpuidle-psci.
 *
 * Copyright (C) 2019 Linaro Ltd.
 * Author: Ulf Hansson <ulf.hansson@linaro.org>
 *
 */

#define pr_fmt(fmt) "CPUidle PSCI: " fmt

#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/psci.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cpuidle-psci.h"

struct psci_pd_provider {
	struct list_head link;
	struct device_node *node;
};

static LIST_HEAD(psci_pd_providers);
static bool osi_mode_enabled __initdata;

static int psci_pd_power_off(struct generic_pm_domain *pd)
{
	struct genpd_power_state *state = &pd->states[pd->state_idx];
	u32 *pd_state;

	if (!state->data)
		return 0;

	/* OSI mode is enabled, set the corresponding domain state. */
	pd_state = state->data;
	psci_set_domain_state(*pd_state);

	return 0;
}

static int __init psci_pd_parse_state_nodes(struct genpd_power_state *states,
					int state_count)
{
	int i, ret;
	u32 psci_state, *psci_state_buf;

	for (i = 0; i < state_count; i++) {
		ret = psci_dt_parse_state_node(to_of_node(states[i].fwnode),
					&psci_state);
		if (ret)
			goto free_state;

		psci_state_buf = kmalloc(sizeof(u32), GFP_KERNEL);
		if (!psci_state_buf) {
			ret = -ENOMEM;
			goto free_state;
		}
		*psci_state_buf = psci_state;
		states[i].data = psci_state_buf;
	}

	return 0;

free_state:
	i--;
	for (; i >= 0; i--)
		kfree(states[i].data);
	return ret;
}

static int __init psci_pd_parse_states(struct device_node *np,
			struct genpd_power_state **states, int *state_count)
{
	int ret;

	/* Parse the domain idle states. */
	ret = of_genpd_parse_idle_states(np, states, state_count);
	if (ret)
		return ret;

	/* Fill out the PSCI specifics for each found state. */
	ret = psci_pd_parse_state_nodes(*states, *state_count);
	if (ret)
		kfree(*states);

	return ret;
}

static void psci_pd_free_states(struct genpd_power_state *states,
				unsigned int state_count)
{
	int i;

	for (i = 0; i < state_count; i++)
		kfree(states[i].data);
	kfree(states);
}

static int __init psci_pd_init(struct device_node *np)
{
	struct generic_pm_domain *pd;
	struct psci_pd_provider *pd_provider;
	struct dev_power_governor *pd_gov;
	struct genpd_power_state *states = NULL;
	int ret = -ENOMEM, state_count = 0;

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		goto out;

	pd_provider = kzalloc(sizeof(*pd_provider), GFP_KERNEL);
	if (!pd_provider)
		goto free_pd;

	pd->name = kasprintf(GFP_KERNEL, "%pOF", np);
	if (!pd->name)
		goto free_pd_prov;

	/*
	 * Parse the domain idle states and let genpd manage the state selection
	 * for those being compatible with "domain-idle-state".
	 */
	ret = psci_pd_parse_states(np, &states, &state_count);
	if (ret)
		goto free_name;

	pd->free_states = psci_pd_free_states;
	pd->name = kbasename(pd->name);
	pd->power_off = psci_pd_power_off;
	pd->states = states;
	pd->state_count = state_count;
	pd->flags |= GENPD_FLAG_IRQ_SAFE | GENPD_FLAG_CPU_DOMAIN;

	/* Use governor for CPU PM domains if it has some states to manage. */
	pd_gov = state_count > 0 ? &pm_domain_cpu_gov : NULL;

	ret = pm_genpd_init(pd, pd_gov, false);
	if (ret) {
		psci_pd_free_states(states, state_count);
		goto free_name;
	}

	ret = of_genpd_add_provider_simple(np, pd);
	if (ret)
		goto remove_pd;

	pd_provider->node = of_node_get(np);
	list_add(&pd_provider->link, &psci_pd_providers);

	pr_debug("init PM domain %s\n", pd->name);
	return 0;

remove_pd:
	pm_genpd_remove(pd);
free_name:
	kfree(pd->name);
free_pd_prov:
	kfree(pd_provider);
free_pd:
	kfree(pd);
out:
	pr_err("failed to init PM domain ret=%d %pOF\n", ret, np);
	return ret;
}

static void __init psci_pd_remove(void)
{
	struct psci_pd_provider *pd_provider, *it;
	struct generic_pm_domain *genpd;

	list_for_each_entry_safe(pd_provider, it, &psci_pd_providers, link) {
		of_genpd_del_provider(pd_provider->node);

		genpd = of_genpd_remove_last(pd_provider->node);
		if (!IS_ERR(genpd))
			kfree(genpd);

		of_node_put(pd_provider->node);
		list_del(&pd_provider->link);
		kfree(pd_provider);
	}
}

static int __init psci_pd_init_topology(struct device_node *np, bool add)
{
	struct device_node *node;
	struct of_phandle_args child, parent;
	int ret;

	for_each_child_of_node(np, node) {
		if (of_parse_phandle_with_args(node, "power-domains",
					"#power-domain-cells", 0, &parent))
			continue;

		child.np = node;
		child.args_count = 0;

		ret = add ? of_genpd_add_subdomain(&parent, &child) :
			of_genpd_remove_subdomain(&parent, &child);
		of_node_put(parent.np);
		if (ret) {
			of_node_put(node);
			return ret;
		}
	}

	return 0;
}

static int __init psci_pd_add_topology(struct device_node *np)
{
	return psci_pd_init_topology(np, true);
}

static void __init psci_pd_remove_topology(struct device_node *np)
{
	psci_pd_init_topology(np, false);
}

static const struct of_device_id psci_of_match[] __initconst = {
	{ .compatible = "arm,psci-1.0" },
	{}
};

static int __init psci_idle_init_domains(void)
{
	struct device_node *np = of_find_matching_node(NULL, psci_of_match);
	struct device_node *node;
	int ret = 0, pd_count = 0;

	if (!np)
		return -ENODEV;

	/* Currently limit the hierarchical topology to be used in OSI mode. */
	if (!psci_has_osi_support())
		goto out;

	/*
	 * Parse child nodes for the "#power-domain-cells" property and
	 * initialize a genpd/genpd-of-provider pair when it's found.
	 */
	for_each_child_of_node(np, node) {
		if (!of_find_property(node, "#power-domain-cells", NULL))
			continue;

		ret = psci_pd_init(node);
		if (ret)
			goto put_node;

		pd_count++;
	}

	/* Bail out if not using the hierarchical CPU topology. */
	if (!pd_count)
		goto out;

	/* Link genpd masters/subdomains to model the CPU topology. */
	ret = psci_pd_add_topology(np);
	if (ret)
		goto remove_pd;

	/* Try to enable OSI mode. */
	ret = psci_set_osi_mode();
	if (ret) {
		pr_warn("failed to enable OSI mode: %d\n", ret);
		psci_pd_remove_topology(np);
		goto remove_pd;
	}

	osi_mode_enabled = true;
	of_node_put(np);
	pr_info("Initialized CPU PM domain topology\n");
	return pd_count;

put_node:
	of_node_put(node);
remove_pd:
	if (pd_count)
		psci_pd_remove();
	pr_err("failed to create CPU PM domains ret=%d\n", ret);
out:
	of_node_put(np);
	return ret;
}
subsys_initcall(psci_idle_init_domains);

struct device __init *psci_dt_attach_cpu(int cpu)
{
	struct device *dev;

	if (!osi_mode_enabled)
		return NULL;

	dev = dev_pm_domain_attach_by_name(get_cpu_device(cpu), "psci");
	if (IS_ERR_OR_NULL(dev))
		return dev;

	pm_runtime_irq_safe(dev);
	if (cpu_online(cpu))
		pm_runtime_get_sync(dev);

	return dev;
}
