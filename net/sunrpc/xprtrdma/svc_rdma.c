// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2015-2018 Oracle.  All rights reserved.
 * Copyright (c) 2005-2006 Network Appliance, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of the Network Appliance, Inc. nor the names of
 *      its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Tom Tucker <tom@opengridcomputing.com>
 */

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/sched.h>
#include <linux/sunrpc/svc_rdma.h>

#define RPCDBG_FACILITY	RPCDBG_SVCXPRT

/* RPC/RDMA parameters */
unsigned int svcrdma_ord = 16;	/* historical default */
static unsigned int min_ord = 1;
static unsigned int max_ord = 255;
unsigned int svcrdma_max_requests = RPCRDMA_MAX_REQUESTS;
unsigned int svcrdma_max_bc_requests = RPCRDMA_MAX_BC_REQUESTS;
static unsigned int min_max_requests = 4;
static unsigned int max_max_requests = 16384;
unsigned int svcrdma_max_req_size = RPCRDMA_DEF_INLINE_THRESH;
static unsigned int min_max_inline = RPCRDMA_DEF_INLINE_THRESH;
static unsigned int max_max_inline = RPCRDMA_MAX_INLINE_THRESH;

atomic_t rdma_stat_recv;
atomic_t rdma_stat_read;
atomic_t rdma_stat_write;
atomic_t rdma_stat_sq_starve;
atomic_t rdma_stat_rq_starve;
atomic_t rdma_stat_rq_poll;
atomic_t rdma_stat_rq_prod;
atomic_t rdma_stat_sq_poll;
atomic_t rdma_stat_sq_prod;

/*
 * This function implements reading and resetting an atomic_t stat
 * variable through read/write to a proc file. Any write to the file
 * resets the associated statistic to zero. Any read returns it's
 * current value.
 */
static int read_reset_stat(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp,
			   loff_t *ppos)
{
	atomic_t *stat = (atomic_t *)table->data;

	if (!stat)
		return -EINVAL;

	if (write)
		atomic_set(stat, 0);
	else {
		char str_buf[32];
		int len = snprintf(str_buf, 32, "%d\n", atomic_read(stat));
		if (len >= 32)
			return -EFAULT;
		len = strlen(str_buf);
		if (*ppos > len) {
			*lenp = 0;
			return 0;
		}
		len -= *ppos;
		if (len > *lenp)
			len = *lenp;
		if (len && copy_to_user(buffer, str_buf, len))
			return -EFAULT;
		*lenp = len;
		*ppos += len;
	}
	return 0;
}

static struct ctl_table_header *svcrdma_table_header;
static struct ctl_table svcrdma_parm_table[] = {
	{
		.procname	= "max_requests",
		.data		= &svcrdma_max_requests,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_max_requests,
		.extra2		= &max_max_requests
	},
	{
		.procname	= "max_req_size",
		.data		= &svcrdma_max_req_size,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_max_inline,
		.extra2		= &max_max_inline
	},
	{
		.procname	= "max_outbound_read_requests",
		.data		= &svcrdma_ord,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_ord,
		.extra2		= &max_ord,
	},

	{
		.procname	= "rdma_stat_read",
		.data		= &rdma_stat_read,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_recv",
		.data		= &rdma_stat_recv,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_write",
		.data		= &rdma_stat_write,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_sq_starve",
		.data		= &rdma_stat_sq_starve,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_rq_starve",
		.data		= &rdma_stat_rq_starve,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_rq_poll",
		.data		= &rdma_stat_rq_poll,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_rq_prod",
		.data		= &rdma_stat_rq_prod,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_sq_poll",
		.data		= &rdma_stat_sq_poll,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{
		.procname	= "rdma_stat_sq_prod",
		.data		= &rdma_stat_sq_prod,
		.maxlen		= sizeof(atomic_t),
		.mode		= 0644,
		.proc_handler	= read_reset_stat,
	},
	{ },
};

static struct ctl_table svcrdma_table[] = {
	{
		.procname	= "svc_rdma",
		.mode		= 0555,
		.child		= svcrdma_parm_table
	},
	{ },
};

static struct ctl_table svcrdma_root_table[] = {
	{
		.procname	= "sunrpc",
		.mode		= 0555,
		.child		= svcrdma_table
	},
	{ },
};

void svc_rdma_cleanup(void)
{
	dprintk("SVCRDMA Module Removed, deregister RPC RDMA transport\n");
	if (svcrdma_table_header) {
		unregister_sysctl_table(svcrdma_table_header);
		svcrdma_table_header = NULL;
	}
	svc_unreg_xprt_class(&svc_rdma_class);
}

int svc_rdma_init(void)
{
	dprintk("SVCRDMA Module Init, register RPC RDMA transport\n");
	dprintk("\tsvcrdma_ord      : %d\n", svcrdma_ord);
	dprintk("\tmax_requests     : %u\n", svcrdma_max_requests);
	dprintk("\tmax_bc_requests  : %u\n", svcrdma_max_bc_requests);
	dprintk("\tmax_inline       : %d\n", svcrdma_max_req_size);

	if (!svcrdma_table_header)
		svcrdma_table_header =
			register_sysctl_table(svcrdma_root_table);

	/* Register RDMA with the SVC transport switch */
	svc_reg_xprt_class(&svc_rdma_class);
	return 0;
}
