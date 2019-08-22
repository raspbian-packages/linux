/*
 * Copyright (c) 2013 Trond Myklebust <Trond.Myklebust@netapp.com>
 */
#include <linux/nfs_fs.h>
#include <linux/namei.h>
#include "internal.h"

#define CREATE_TRACE_POINTS
#include "nfstrace.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(nfs_fsync_enter);
EXPORT_TRACEPOINT_SYMBOL_GPL(nfs_fsync_exit);
