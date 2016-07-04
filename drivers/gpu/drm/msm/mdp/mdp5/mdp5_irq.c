/*
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "msm_drv.h"
#include "mdp5_kms.h"

void mdp5_set_irqmask(struct mdp_kms *mdp_kms, uint32_t irqmask)
{
	mdp5_write(to_mdp5_kms(mdp_kms), REG_MDP5_INTR_EN, irqmask);
}

static void mdp5_irq_error_handler(struct mdp_irq *irq, uint32_t irqstatus)
{
	DRM_ERROR("errors: %08x\n", irqstatus);
}

void mdp5_irq_preinstall(struct msm_kms *kms)
{
	struct mdp5_kms *mdp5_kms = to_mdp5_kms(to_mdp_kms(kms));
	mdp5_write(mdp5_kms, REG_MDP5_INTR_CLEAR, 0xffffffff);
}

int mdp5_irq_postinstall(struct msm_kms *kms)
{
	struct mdp_kms *mdp_kms = to_mdp_kms(kms);
	struct mdp5_kms *mdp5_kms = to_mdp5_kms(mdp_kms);
	struct mdp_irq *error_handler = &mdp5_kms->error_handler;

	error_handler->irq = mdp5_irq_error_handler;
	error_handler->irqmask = MDP5_IRQ_INTF0_UNDER_RUN |
			MDP5_IRQ_INTF1_UNDER_RUN |
			MDP5_IRQ_INTF2_UNDER_RUN |
			MDP5_IRQ_INTF3_UNDER_RUN;

	mdp_irq_register(mdp_kms, error_handler);

	return 0;
}

void mdp5_irq_uninstall(struct msm_kms *kms)
{
	struct mdp5_kms *mdp5_kms = to_mdp5_kms(to_mdp_kms(kms));
	mdp5_write(mdp5_kms, REG_MDP5_INTR_EN, 0x00000000);
}

static void mdp5_irq_mdp(struct mdp_kms *mdp_kms)
{
	struct mdp5_kms *mdp5_kms = to_mdp5_kms(mdp_kms);
	struct drm_device *dev = mdp5_kms->dev;
	struct msm_drm_private *priv = dev->dev_private;
	unsigned int id;
	uint32_t status;

	status = mdp5_read(mdp5_kms, REG_MDP5_INTR_STATUS);
	mdp5_write(mdp5_kms, REG_MDP5_INTR_CLEAR, status);

	VERB("status=%08x", status);

	mdp_dispatch_irqs(mdp_kms, status);

	for (id = 0; id < priv->num_crtcs; id++)
		if (status & mdp5_crtc_vblank(priv->crtcs[id]))
			drm_handle_vblank(dev, id);
}

irqreturn_t mdp5_irq(struct msm_kms *kms)
{
	struct mdp_kms *mdp_kms = to_mdp_kms(kms);
	struct mdp5_kms *mdp5_kms = to_mdp5_kms(mdp_kms);
	uint32_t intr;

	intr = mdp5_read(mdp5_kms, REG_MDP5_HW_INTR_STATUS);

	VERB("intr=%08x", intr);

	if (intr & MDP5_HW_INTR_STATUS_INTR_MDP)
		mdp5_irq_mdp(mdp_kms);

	if (intr & MDP5_HW_INTR_STATUS_INTR_HDMI)
		hdmi_irq(0, mdp5_kms->hdmi);

	return IRQ_HANDLED;
}

int mdp5_enable_vblank(struct msm_kms *kms, struct drm_crtc *crtc)
{
	mdp_update_vblank_mask(to_mdp_kms(kms),
			mdp5_crtc_vblank(crtc), true);
	return 0;
}

void mdp5_disable_vblank(struct msm_kms *kms, struct drm_crtc *crtc)
{
	mdp_update_vblank_mask(to_mdp_kms(kms),
			mdp5_crtc_vblank(crtc), false);
}
