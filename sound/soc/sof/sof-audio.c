// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
// This file is provided under a dual BSD/GPLv2 license.  When using or
// redistributing this file, you may do so under either license.
//
// Copyright(c) 2019 Intel Corporation. All rights reserved.
//
// Author: Ranjani Sridharan <ranjani.sridharan@linux.intel.com>
//

#include "sof-audio.h"
#include "ops.h"

bool snd_sof_dsp_d0i3_on_suspend(struct snd_sof_dev *sdev)
{
	struct snd_sof_pcm *spcm;

	list_for_each_entry(spcm, &sdev->pcm_list, list) {
		if (spcm->stream[SNDRV_PCM_STREAM_PLAYBACK].suspend_ignored ||
		    spcm->stream[SNDRV_PCM_STREAM_CAPTURE].suspend_ignored)
			return true;
	}

	return false;
}

int sof_set_hw_params_upon_resume(struct device *dev)
{
	struct snd_sof_dev *sdev = dev_get_drvdata(dev);
	struct snd_pcm_substream *substream;
	struct snd_sof_pcm *spcm;
	snd_pcm_state_t state;
	int dir;

	/*
	 * SOF requires hw_params to be set-up internally upon resume.
	 * So, set the flag to indicate this for those streams that
	 * have been suspended.
	 */
	list_for_each_entry(spcm, &sdev->pcm_list, list) {
		for (dir = 0; dir <= SNDRV_PCM_STREAM_CAPTURE; dir++) {
			substream = spcm->stream[dir].substream;
			if (!substream || !substream->runtime)
				continue;

			state = substream->runtime->status->state;
			if (state == SNDRV_PCM_STATE_SUSPENDED)
				spcm->prepared[dir] = false;
		}
	}

	/* set internal flag for BE */
	return snd_sof_dsp_hw_params_upon_resume(sdev);
}

static int sof_restore_kcontrols(struct device *dev)
{
	struct snd_sof_dev *sdev = dev_get_drvdata(dev);
	struct snd_sof_control *scontrol;
	int ipc_cmd, ctrl_type;
	int ret = 0;

	/* restore kcontrol values */
	list_for_each_entry(scontrol, &sdev->kcontrol_list, list) {
		/* reset readback offset for scontrol after resuming */
		scontrol->readback_offset = 0;

		/* notify DSP of kcontrol values */
		switch (scontrol->cmd) {
		case SOF_CTRL_CMD_VOLUME:
		case SOF_CTRL_CMD_ENUM:
		case SOF_CTRL_CMD_SWITCH:
			ipc_cmd = SOF_IPC_COMP_SET_VALUE;
			ctrl_type = SOF_CTRL_TYPE_VALUE_CHAN_SET;
			ret = snd_sof_ipc_set_get_comp_data(scontrol,
							    ipc_cmd, ctrl_type,
							    scontrol->cmd,
							    true);
			break;
		case SOF_CTRL_CMD_BINARY:
			ipc_cmd = SOF_IPC_COMP_SET_DATA;
			ctrl_type = SOF_CTRL_TYPE_DATA_SET;
			ret = snd_sof_ipc_set_get_comp_data(scontrol,
							    ipc_cmd, ctrl_type,
							    scontrol->cmd,
							    true);
			break;

		default:
			break;
		}

		if (ret < 0) {
			dev_err(dev,
				"error: failed kcontrol value set for widget: %d\n",
				scontrol->comp_id);

			return ret;
		}
	}

	return 0;
}

int sof_restore_pipelines(struct device *dev)
{
	struct snd_sof_dev *sdev = dev_get_drvdata(dev);
	struct snd_sof_widget *swidget;
	struct snd_sof_route *sroute;
	struct sof_ipc_pipe_new *pipeline;
	struct snd_sof_dai *dai;
	struct sof_ipc_comp_dai *comp_dai;
	struct sof_ipc_cmd_hdr *hdr;
	int ret;

	/* restore pipeline components */
	list_for_each_entry_reverse(swidget, &sdev->widget_list, list) {
		struct sof_ipc_comp_reply r;

		/* skip if there is no private data */
		if (!swidget->private)
			continue;

		switch (swidget->id) {
		case snd_soc_dapm_dai_in:
		case snd_soc_dapm_dai_out:
			dai = swidget->private;
			comp_dai = &dai->comp_dai;
			ret = sof_ipc_tx_message(sdev->ipc,
						 comp_dai->comp.hdr.cmd,
						 comp_dai, sizeof(*comp_dai),
						 &r, sizeof(r));
			break;
		case snd_soc_dapm_scheduler:

			/*
			 * During suspend, all DSP cores are powered off.
			 * Therefore upon resume, create the pipeline comp
			 * and power up the core that the pipeline is
			 * scheduled on.
			 */
			pipeline = swidget->private;
			ret = sof_load_pipeline_ipc(dev, pipeline, &r);
			break;
		default:
			hdr = swidget->private;
			ret = sof_ipc_tx_message(sdev->ipc, hdr->cmd,
						 swidget->private, hdr->size,
						 &r, sizeof(r));
			break;
		}
		if (ret < 0) {
			dev_err(dev,
				"error: failed to load widget type %d with ID: %d\n",
				swidget->widget->id, swidget->comp_id);

			return ret;
		}
	}

	/* restore pipeline connections */
	list_for_each_entry_reverse(sroute, &sdev->route_list, list) {
		struct sof_ipc_pipe_comp_connect *connect;
		struct sof_ipc_reply reply;

		/* skip if there's no private data */
		if (!sroute->private)
			continue;

		connect = sroute->private;

		/* send ipc */
		ret = sof_ipc_tx_message(sdev->ipc,
					 connect->hdr.cmd,
					 connect, sizeof(*connect),
					 &reply, sizeof(reply));
		if (ret < 0) {
			dev_err(dev,
				"error: failed to load route sink %s control %s source %s\n",
				sroute->route->sink,
				sroute->route->control ? sroute->route->control
					: "none",
				sroute->route->source);

			return ret;
		}
	}

	/* restore dai links */
	list_for_each_entry_reverse(dai, &sdev->dai_list, list) {
		struct sof_ipc_reply reply;
		struct sof_ipc_dai_config *config = dai->dai_config;

		if (!config) {
			dev_err(dev, "error: no config for DAI %s\n",
				dai->name);
			continue;
		}

		/*
		 * The link DMA channel would be invalidated for running
		 * streams but not for streams that were in the PAUSED
		 * state during suspend. So invalidate it here before setting
		 * the dai config in the DSP.
		 */
		if (config->type == SOF_DAI_INTEL_HDA)
			config->hda.link_dma_ch = DMA_CHAN_INVALID;

		ret = sof_ipc_tx_message(sdev->ipc,
					 config->hdr.cmd, config,
					 config->hdr.size,
					 &reply, sizeof(reply));

		if (ret < 0) {
			dev_err(dev,
				"error: failed to set dai config for %s\n",
				dai->name);

			return ret;
		}
	}

	/* complete pipeline */
	list_for_each_entry(swidget, &sdev->widget_list, list) {
		switch (swidget->id) {
		case snd_soc_dapm_scheduler:
			swidget->complete =
				snd_sof_complete_pipeline(dev, swidget);
			break;
		default:
			break;
		}
	}

	/* restore pipeline kcontrols */
	ret = sof_restore_kcontrols(dev);
	if (ret < 0)
		dev_err(dev,
			"error: restoring kcontrols after resume\n");

	return ret;
}

/*
 * Generic object lookup APIs.
 */

struct snd_sof_pcm *snd_sof_find_spcm_name(struct snd_soc_component *scomp,
					   const char *name)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	struct snd_sof_pcm *spcm;

	list_for_each_entry(spcm, &sdev->pcm_list, list) {
		/* match with PCM dai name */
		if (strcmp(spcm->pcm.dai_name, name) == 0)
			return spcm;

		/* match with playback caps name if set */
		if (*spcm->pcm.caps[0].name &&
		    !strcmp(spcm->pcm.caps[0].name, name))
			return spcm;

		/* match with capture caps name if set */
		if (*spcm->pcm.caps[1].name &&
		    !strcmp(spcm->pcm.caps[1].name, name))
			return spcm;
	}

	return NULL;
}

struct snd_sof_pcm *snd_sof_find_spcm_comp(struct snd_soc_component *scomp,
					   unsigned int comp_id,
					   int *direction)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	struct snd_sof_pcm *spcm;
	int dir;

	list_for_each_entry(spcm, &sdev->pcm_list, list) {
		dir = SNDRV_PCM_STREAM_PLAYBACK;
		if (spcm->stream[dir].comp_id == comp_id) {
			*direction = dir;
			return spcm;
		}

		dir = SNDRV_PCM_STREAM_CAPTURE;
		if (spcm->stream[dir].comp_id == comp_id) {
			*direction = dir;
			return spcm;
		}
	}

	return NULL;
}

struct snd_sof_pcm *snd_sof_find_spcm_pcm_id(struct snd_soc_component *scomp,
					     unsigned int pcm_id)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	struct snd_sof_pcm *spcm;

	list_for_each_entry(spcm, &sdev->pcm_list, list) {
		if (le32_to_cpu(spcm->pcm.pcm_id) == pcm_id)
			return spcm;
	}

	return NULL;
}

struct snd_sof_widget *snd_sof_find_swidget(struct snd_soc_component *scomp,
					    const char *name)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	struct snd_sof_widget *swidget;

	list_for_each_entry(swidget, &sdev->widget_list, list) {
		if (strcmp(name, swidget->widget->name) == 0)
			return swidget;
	}

	return NULL;
}

/* find widget by stream name and direction */
struct snd_sof_widget *
snd_sof_find_swidget_sname(struct snd_soc_component *scomp,
			   const char *pcm_name, int dir)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	struct snd_sof_widget *swidget;
	enum snd_soc_dapm_type type;

	if (dir == SNDRV_PCM_STREAM_PLAYBACK)
		type = snd_soc_dapm_aif_in;
	else
		type = snd_soc_dapm_aif_out;

	list_for_each_entry(swidget, &sdev->widget_list, list) {
		if (!strcmp(pcm_name, swidget->widget->sname) &&
		    swidget->id == type)
			return swidget;
	}

	return NULL;
}

struct snd_sof_dai *snd_sof_find_dai(struct snd_soc_component *scomp,
				     const char *name)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(scomp);
	struct snd_sof_dai *dai;

	list_for_each_entry(dai, &sdev->dai_list, list) {
		if (dai->name && (strcmp(name, dai->name) == 0))
			return dai;
	}

	return NULL;
}

/*
 * SOF Driver enumeration.
 */
int sof_machine_check(struct snd_sof_dev *sdev)
{
	struct snd_sof_pdata *sof_pdata = sdev->pdata;
	const struct sof_dev_desc *desc = sof_pdata->desc;
	struct snd_soc_acpi_mach *mach;
	int ret;

	/* force nocodec mode */
#if IS_ENABLED(CONFIG_SND_SOC_SOF_FORCE_NOCODEC_MODE)
		dev_warn(sdev->dev, "Force to use nocodec mode\n");
		goto nocodec;
#endif

	/* find machine */
	snd_sof_machine_select(sdev);
	if (sof_pdata->machine) {
		snd_sof_set_mach_params(sof_pdata->machine, sdev->dev);
		return 0;
	}

#if !IS_ENABLED(CONFIG_SND_SOC_SOF_NOCODEC)
	dev_err(sdev->dev, "error: no matching ASoC machine driver found - aborting probe\n");
	return -ENODEV;
#endif
#if IS_ENABLED(CONFIG_SND_SOC_SOF_FORCE_NOCODEC_MODE)
nocodec:
#endif
	/* select nocodec mode */
	dev_warn(sdev->dev, "Using nocodec machine driver\n");
	mach = devm_kzalloc(sdev->dev, sizeof(*mach), GFP_KERNEL);
	if (!mach)
		return -ENOMEM;

	mach->drv_name = "sof-nocodec";
	sof_pdata->tplg_filename = desc->nocodec_tplg_filename;

	ret = sof_nocodec_setup(sdev->dev, desc->ops);
	if (ret < 0)
		return ret;

	sof_pdata->machine = mach;
	snd_sof_set_mach_params(sof_pdata->machine, sdev->dev);

	return 0;
}
EXPORT_SYMBOL(sof_machine_check);

int sof_machine_register(struct snd_sof_dev *sdev, void *pdata)
{
	struct snd_sof_pdata *plat_data = (struct snd_sof_pdata *)pdata;
	const char *drv_name;
	const void *mach;
	int size;

	drv_name = plat_data->machine->drv_name;
	mach = (const void *)plat_data->machine;
	size = sizeof(*plat_data->machine);

	/* register machine driver, pass machine info as pdata */
	plat_data->pdev_mach =
		platform_device_register_data(sdev->dev, drv_name,
					      PLATFORM_DEVID_NONE, mach, size);
	if (IS_ERR(plat_data->pdev_mach))
		return PTR_ERR(plat_data->pdev_mach);

	dev_dbg(sdev->dev, "created machine %s\n",
		dev_name(&plat_data->pdev_mach->dev));

	return 0;
}
EXPORT_SYMBOL(sof_machine_register);

void sof_machine_unregister(struct snd_sof_dev *sdev, void *pdata)
{
	struct snd_sof_pdata *plat_data = (struct snd_sof_pdata *)pdata;

	if (!IS_ERR_OR_NULL(plat_data->pdev_mach))
		platform_device_unregister(plat_data->pdev_mach);
}
EXPORT_SYMBOL(sof_machine_unregister);
