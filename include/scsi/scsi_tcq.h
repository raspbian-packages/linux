/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SCSI_SCSI_TCQ_H
#define _SCSI_SCSI_TCQ_H

#include <linux/blkdev.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#define SCSI_NO_TAG	(-1)    /* identify no tag in use */


#ifdef CONFIG_BLOCK
/**
 * scsi_host_find_tag - find the tagged command by host
 * @shost:	pointer to scsi_host
 * @tag:	tag
 *
 * Note: for devices using multiple hardware queues tag must have been
 * generated by blk_mq_unique_tag().
 **/
static inline struct scsi_cmnd *scsi_host_find_tag(struct Scsi_Host *shost,
		int tag)
{
	struct request *req = NULL;
	u16 hwq;

	if (tag == SCSI_NO_TAG)
		return NULL;

	hwq = blk_mq_unique_tag_to_hwq(tag);
	if (hwq < shost->tag_set.nr_hw_queues) {
		req = blk_mq_tag_to_rq(shost->tag_set.tags[hwq],
					blk_mq_unique_tag_to_tag(tag));
	}

	if (!req)
		return NULL;
	return blk_mq_rq_to_pdu(req);
}

#endif /* CONFIG_BLOCK */
#endif /* _SCSI_SCSI_TCQ_H */
