/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_resource.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Peter Braam <braam@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM
#include "../include/lustre_dlm.h"
#include "../include/lustre_fid.h"
#include "../include/obd_class.h"
#include "ldlm_internal.h"

struct kmem_cache *ldlm_resource_slab, *ldlm_lock_slab;

int ldlm_srv_namespace_nr;
int ldlm_cli_namespace_nr;

struct mutex ldlm_srv_namespace_lock;
LIST_HEAD(ldlm_srv_namespace_list);

struct mutex ldlm_cli_namespace_lock;
/* Client Namespaces that have active resources in them.
 * Once all resources go away, ldlm_poold moves such namespaces to the
 * inactive list
 */
LIST_HEAD(ldlm_cli_active_namespace_list);
/* Client namespaces that don't have any locks in them */
static LIST_HEAD(ldlm_cli_inactive_namespace_list);

static struct dentry *ldlm_debugfs_dir;
static struct dentry *ldlm_ns_debugfs_dir;
struct dentry *ldlm_svc_debugfs_dir;

/* during debug dump certain amount of granted locks for one resource to avoid
 * DDOS.
 */
static unsigned int ldlm_dump_granted_max = 256;

static ssize_t
lprocfs_wr_dump_ns(struct file *file, const char __user *buffer,
		   size_t count, loff_t *off)
{
	ldlm_dump_all_namespaces(LDLM_NAMESPACE_SERVER, D_DLMTRACE);
	ldlm_dump_all_namespaces(LDLM_NAMESPACE_CLIENT, D_DLMTRACE);
	return count;
}

LPROC_SEQ_FOPS_WR_ONLY(ldlm, dump_ns);

static int ldlm_rw_uint_seq_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%u\n", *(unsigned int *)m->private);
	return 0;
}

static ssize_t
ldlm_rw_uint_seq_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *off)
{
	struct seq_file *seq = file->private_data;

	if (count == 0)
		return 0;
	return kstrtouint_from_user(buffer, count, 0,
				    (unsigned int *)seq->private);
}

LPROC_SEQ_FOPS(ldlm_rw_uint);

static struct lprocfs_vars ldlm_debugfs_list[] = {
	{ "dump_namespaces", &ldlm_dump_ns_fops, NULL, 0222 },
	{ "dump_granted_max", &ldlm_rw_uint_fops, &ldlm_dump_granted_max },
	{ NULL }
};

int ldlm_debugfs_setup(void)
{
	int rc;

	ldlm_debugfs_dir = ldebugfs_register(OBD_LDLM_DEVICENAME,
					     debugfs_lustre_root,
					     NULL, NULL);
	if (IS_ERR_OR_NULL(ldlm_debugfs_dir)) {
		CERROR("LProcFS failed in ldlm-init\n");
		rc = ldlm_debugfs_dir ? PTR_ERR(ldlm_debugfs_dir) : -ENOMEM;
		goto err;
	}

	ldlm_ns_debugfs_dir = ldebugfs_register("namespaces",
						ldlm_debugfs_dir,
						NULL, NULL);
	if (IS_ERR_OR_NULL(ldlm_ns_debugfs_dir)) {
		CERROR("LProcFS failed in ldlm-init\n");
		rc = ldlm_ns_debugfs_dir ? PTR_ERR(ldlm_ns_debugfs_dir)
					 : -ENOMEM;
		goto err_type;
	}

	ldlm_svc_debugfs_dir = ldebugfs_register("services",
						 ldlm_debugfs_dir,
						 NULL, NULL);
	if (IS_ERR_OR_NULL(ldlm_svc_debugfs_dir)) {
		CERROR("LProcFS failed in ldlm-init\n");
		rc = ldlm_svc_debugfs_dir ? PTR_ERR(ldlm_svc_debugfs_dir)
					  : -ENOMEM;
		goto err_ns;
	}

	rc = ldebugfs_add_vars(ldlm_debugfs_dir, ldlm_debugfs_list, NULL);
	if (rc) {
		CERROR("LProcFS failed in ldlm-init\n");
		goto err_svc;
	}

	return 0;

err_svc:
	ldebugfs_remove(&ldlm_svc_debugfs_dir);
err_ns:
	ldebugfs_remove(&ldlm_ns_debugfs_dir);
err_type:
	ldebugfs_remove(&ldlm_debugfs_dir);
err:
	ldlm_svc_debugfs_dir = NULL;
	ldlm_ns_debugfs_dir = NULL;
	ldlm_debugfs_dir = NULL;
	return rc;
}

void ldlm_debugfs_cleanup(void)
{
	if (!IS_ERR_OR_NULL(ldlm_svc_debugfs_dir))
		ldebugfs_remove(&ldlm_svc_debugfs_dir);

	if (!IS_ERR_OR_NULL(ldlm_ns_debugfs_dir))
		ldebugfs_remove(&ldlm_ns_debugfs_dir);

	if (!IS_ERR_OR_NULL(ldlm_debugfs_dir))
		ldebugfs_remove(&ldlm_debugfs_dir);

	ldlm_svc_debugfs_dir = NULL;
	ldlm_ns_debugfs_dir = NULL;
	ldlm_debugfs_dir = NULL;
}

static ssize_t resource_count_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);
	__u64		  res = 0;
	struct cfs_hash_bd	  bd;
	int		    i;

	/* result is not strictly consistent */
	cfs_hash_for_each_bucket(ns->ns_rs_hash, &bd, i)
		res += cfs_hash_bd_count_get(&bd);
	return sprintf(buf, "%lld\n", res);
}
LUSTRE_RO_ATTR(resource_count);

static ssize_t lock_count_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);
	__u64		  locks;

	locks = lprocfs_stats_collector(ns->ns_stats, LDLM_NSS_LOCKS,
					LPROCFS_FIELDS_FLAGS_SUM);
	return sprintf(buf, "%lld\n", locks);
}
LUSTRE_RO_ATTR(lock_count);

static ssize_t lock_unused_count_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);

	return sprintf(buf, "%d\n", ns->ns_nr_unused);
}
LUSTRE_RO_ATTR(lock_unused_count);

static ssize_t lru_size_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);
	__u32 *nr = &ns->ns_max_unused;

	if (ns_connect_lru_resize(ns))
		nr = &ns->ns_nr_unused;
	return sprintf(buf, "%u", *nr);
}

static ssize_t lru_size_store(struct kobject *kobj, struct attribute *attr,
			      const char *buffer, size_t count)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);
	unsigned long tmp;
	int lru_resize;
	int err;

	if (strncmp(buffer, "clear", 5) == 0) {
		CDEBUG(D_DLMTRACE,
		       "dropping all unused locks from namespace %s\n",
		       ldlm_ns_name(ns));
		if (ns_connect_lru_resize(ns)) {
			int canceled, unused  = ns->ns_nr_unused;

			/* Try to cancel all @ns_nr_unused locks. */
			canceled = ldlm_cancel_lru(ns, unused, 0,
						   LDLM_LRU_FLAG_PASSED);
			if (canceled < unused) {
				CDEBUG(D_DLMTRACE,
				       "not all requested locks are canceled, requested: %d, canceled: %d\n",
				       unused,
				       canceled);
				return -EINVAL;
			}
		} else {
			tmp = ns->ns_max_unused;
			ns->ns_max_unused = 0;
			ldlm_cancel_lru(ns, 0, 0, LDLM_LRU_FLAG_PASSED);
			ns->ns_max_unused = tmp;
		}
		return count;
	}

	err = kstrtoul(buffer, 10, &tmp);
	if (err != 0) {
		CERROR("lru_size: invalid value written\n");
		return -EINVAL;
	}
	lru_resize = (tmp == 0);

	if (ns_connect_lru_resize(ns)) {
		if (!lru_resize)
			ns->ns_max_unused = (unsigned int)tmp;

		if (tmp > ns->ns_nr_unused)
			tmp = ns->ns_nr_unused;
		tmp = ns->ns_nr_unused - tmp;

		CDEBUG(D_DLMTRACE,
		       "changing namespace %s unused locks from %u to %u\n",
		       ldlm_ns_name(ns), ns->ns_nr_unused,
		       (unsigned int)tmp);
		ldlm_cancel_lru(ns, tmp, LCF_ASYNC, LDLM_LRU_FLAG_PASSED);

		if (!lru_resize) {
			CDEBUG(D_DLMTRACE,
			       "disable lru_resize for namespace %s\n",
			       ldlm_ns_name(ns));
			ns->ns_connect_flags &= ~OBD_CONNECT_LRU_RESIZE;
		}
	} else {
		CDEBUG(D_DLMTRACE,
		       "changing namespace %s max_unused from %u to %u\n",
		       ldlm_ns_name(ns), ns->ns_max_unused,
		       (unsigned int)tmp);
		ns->ns_max_unused = (unsigned int)tmp;
		ldlm_cancel_lru(ns, 0, LCF_ASYNC, LDLM_LRU_FLAG_PASSED);

		/* Make sure that LRU resize was originally supported before
		 * turning it on here.
		 */
		if (lru_resize &&
		    (ns->ns_orig_connect_flags & OBD_CONNECT_LRU_RESIZE)) {
			CDEBUG(D_DLMTRACE,
			       "enable lru_resize for namespace %s\n",
			       ldlm_ns_name(ns));
			ns->ns_connect_flags |= OBD_CONNECT_LRU_RESIZE;
		}
	}

	return count;
}
LUSTRE_RW_ATTR(lru_size);

static ssize_t lru_max_age_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);

	return sprintf(buf, "%u", ns->ns_max_age);
}

static ssize_t lru_max_age_store(struct kobject *kobj, struct attribute *attr,
				 const char *buffer, size_t count)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);
	unsigned long tmp;
	int err;

	err = kstrtoul(buffer, 10, &tmp);
	if (err != 0)
		return -EINVAL;

	ns->ns_max_age = tmp;

	return count;
}
LUSTRE_RW_ATTR(lru_max_age);

static ssize_t early_lock_cancel_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);

	return sprintf(buf, "%d\n", ns_connect_cancelset(ns));
}

static ssize_t early_lock_cancel_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer,
				       size_t count)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);
	unsigned long supp = -1;
	int rc;

	rc = kstrtoul(buffer, 10, &supp);
	if (rc < 0)
		return rc;

	if (supp == 0)
		ns->ns_connect_flags &= ~OBD_CONNECT_CANCELSET;
	else if (ns->ns_orig_connect_flags & OBD_CONNECT_CANCELSET)
		ns->ns_connect_flags |= OBD_CONNECT_CANCELSET;
	return count;
}
LUSTRE_RW_ATTR(early_lock_cancel);

/* These are for namespaces in /sys/fs/lustre/ldlm/namespaces/ */
static struct attribute *ldlm_ns_attrs[] = {
	&lustre_attr_resource_count.attr,
	&lustre_attr_lock_count.attr,
	&lustre_attr_lock_unused_count.attr,
	&lustre_attr_lru_size.attr,
	&lustre_attr_lru_max_age.attr,
	&lustre_attr_early_lock_cancel.attr,
	NULL,
};

static void ldlm_ns_release(struct kobject *kobj)
{
	struct ldlm_namespace *ns = container_of(kobj, struct ldlm_namespace,
						 ns_kobj);
	complete(&ns->ns_kobj_unregister);
}

static struct kobj_type ldlm_ns_ktype = {
	.default_attrs  = ldlm_ns_attrs,
	.sysfs_ops      = &lustre_sysfs_ops,
	.release        = ldlm_ns_release,
};

static void ldlm_namespace_debugfs_unregister(struct ldlm_namespace *ns)
{
	if (IS_ERR_OR_NULL(ns->ns_debugfs_entry))
		CERROR("dlm namespace %s has no procfs dir?\n",
		       ldlm_ns_name(ns));
	else
		ldebugfs_remove(&ns->ns_debugfs_entry);

	if (ns->ns_stats)
		lprocfs_free_stats(&ns->ns_stats);
}

static void ldlm_namespace_sysfs_unregister(struct ldlm_namespace *ns)
{
	kobject_put(&ns->ns_kobj);
	wait_for_completion(&ns->ns_kobj_unregister);
}

static int ldlm_namespace_sysfs_register(struct ldlm_namespace *ns)
{
	int err;

	ns->ns_kobj.kset = ldlm_ns_kset;
	init_completion(&ns->ns_kobj_unregister);
	err = kobject_init_and_add(&ns->ns_kobj, &ldlm_ns_ktype, NULL,
				   "%s", ldlm_ns_name(ns));

	ns->ns_stats = lprocfs_alloc_stats(LDLM_NSS_LAST, 0);
	if (!ns->ns_stats) {
		kobject_put(&ns->ns_kobj);
		return -ENOMEM;
	}

	lprocfs_counter_init(ns->ns_stats, LDLM_NSS_LOCKS,
			     LPROCFS_CNTR_AVGMINMAX, "locks", "locks");

	return err;
}

static int ldlm_namespace_debugfs_register(struct ldlm_namespace *ns)
{
	struct dentry *ns_entry;

	if (!IS_ERR_OR_NULL(ns->ns_debugfs_entry)) {
		ns_entry = ns->ns_debugfs_entry;
	} else {
		ns_entry = debugfs_create_dir(ldlm_ns_name(ns),
					      ldlm_ns_debugfs_dir);
		if (!ns_entry)
			return -ENOMEM;
		ns->ns_debugfs_entry = ns_entry;
	}

	return 0;
}

#undef MAX_STRING_SIZE

static struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res)
{
	LASSERT(res);
	LASSERT(res != LP_POISON);
	atomic_inc(&res->lr_refcount);
	CDEBUG(D_INFO, "getref res: %p count: %d\n", res,
	       atomic_read(&res->lr_refcount));
	return res;
}

static unsigned int ldlm_res_hop_hash(struct cfs_hash *hs,
				      const void *key, unsigned int mask)
{
	const struct ldlm_res_id     *id  = key;
	unsigned int		val = 0;
	unsigned int		i;

	for (i = 0; i < RES_NAME_SIZE; i++)
		val += id->name[i];
	return val & mask;
}

static unsigned int ldlm_res_hop_fid_hash(struct cfs_hash *hs,
					  const void *key, unsigned int mask)
{
	const struct ldlm_res_id *id = key;
	struct lu_fid       fid;
	__u32	       hash;
	__u32	       val;

	fid.f_seq = id->name[LUSTRE_RES_ID_SEQ_OFF];
	fid.f_oid = (__u32)id->name[LUSTRE_RES_ID_VER_OID_OFF];
	fid.f_ver = (__u32)(id->name[LUSTRE_RES_ID_VER_OID_OFF] >> 32);

	hash = fid_flatten32(&fid);
	hash += (hash >> 4) + (hash << 12); /* mixing oid and seq */
	if (id->name[LUSTRE_RES_ID_HSH_OFF] != 0) {
		val = id->name[LUSTRE_RES_ID_HSH_OFF];
		hash += (val >> 5) + (val << 11);
	} else {
		val = fid_oid(&fid);
	}
	hash = hash_long(hash, hs->hs_bkt_bits);
	/* give me another random factor */
	hash -= hash_long((unsigned long)hs, val % 11 + 3);

	hash <<= hs->hs_cur_bits - hs->hs_bkt_bits;
	hash |= ldlm_res_hop_hash(hs, key, CFS_HASH_NBKT(hs) - 1);

	return hash & mask;
}

static void *ldlm_res_hop_key(struct hlist_node *hnode)
{
	struct ldlm_resource   *res;

	res = hlist_entry(hnode, struct ldlm_resource, lr_hash);
	return &res->lr_name;
}

static int ldlm_res_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	struct ldlm_resource   *res;

	res = hlist_entry(hnode, struct ldlm_resource, lr_hash);
	return ldlm_res_eq((const struct ldlm_res_id *)key,
			   (const struct ldlm_res_id *)&res->lr_name);
}

static void *ldlm_res_hop_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct ldlm_resource, lr_hash);
}

static void ldlm_res_hop_get_locked(struct cfs_hash *hs,
				    struct hlist_node *hnode)
{
	struct ldlm_resource *res;

	res = hlist_entry(hnode, struct ldlm_resource, lr_hash);
	ldlm_resource_getref(res);
}

static void ldlm_res_hop_put_locked(struct cfs_hash *hs,
				    struct hlist_node *hnode)
{
	struct ldlm_resource *res;

	res = hlist_entry(hnode, struct ldlm_resource, lr_hash);
	/* cfs_hash_for_each_nolock is the only chance we call it */
	ldlm_resource_putref_locked(res);
}

static void ldlm_res_hop_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct ldlm_resource *res;

	res = hlist_entry(hnode, struct ldlm_resource, lr_hash);
	ldlm_resource_putref(res);
}

static struct cfs_hash_ops ldlm_ns_hash_ops = {
	.hs_hash	= ldlm_res_hop_hash,
	.hs_key		= ldlm_res_hop_key,
	.hs_keycmp      = ldlm_res_hop_keycmp,
	.hs_keycpy      = NULL,
	.hs_object      = ldlm_res_hop_object,
	.hs_get		= ldlm_res_hop_get_locked,
	.hs_put_locked  = ldlm_res_hop_put_locked,
	.hs_put		= ldlm_res_hop_put
};

static struct cfs_hash_ops ldlm_ns_fid_hash_ops = {
	.hs_hash	= ldlm_res_hop_fid_hash,
	.hs_key		= ldlm_res_hop_key,
	.hs_keycmp      = ldlm_res_hop_keycmp,
	.hs_keycpy      = NULL,
	.hs_object      = ldlm_res_hop_object,
	.hs_get		= ldlm_res_hop_get_locked,
	.hs_put_locked  = ldlm_res_hop_put_locked,
	.hs_put		= ldlm_res_hop_put
};

struct ldlm_ns_hash_def {
	enum ldlm_ns_type nsd_type;
	/** hash bucket bits */
	unsigned int	nsd_bkt_bits;
	/** hash bits */
	unsigned int	nsd_all_bits;
	/** hash operations */
	struct cfs_hash_ops *nsd_hops;
};

static struct ldlm_ns_hash_def ldlm_ns_hash_defs[] = {
	{
		.nsd_type       = LDLM_NS_TYPE_MDC,
		.nsd_bkt_bits   = 11,
		.nsd_all_bits   = 16,
		.nsd_hops       = &ldlm_ns_fid_hash_ops,
	},
	{
		.nsd_type       = LDLM_NS_TYPE_MDT,
		.nsd_bkt_bits   = 14,
		.nsd_all_bits   = 21,
		.nsd_hops       = &ldlm_ns_fid_hash_ops,
	},
	{
		.nsd_type       = LDLM_NS_TYPE_OSC,
		.nsd_bkt_bits   = 8,
		.nsd_all_bits   = 12,
		.nsd_hops       = &ldlm_ns_hash_ops,
	},
	{
		.nsd_type       = LDLM_NS_TYPE_OST,
		.nsd_bkt_bits   = 11,
		.nsd_all_bits   = 17,
		.nsd_hops       = &ldlm_ns_hash_ops,
	},
	{
		.nsd_type       = LDLM_NS_TYPE_MGC,
		.nsd_bkt_bits   = 4,
		.nsd_all_bits   = 4,
		.nsd_hops       = &ldlm_ns_hash_ops,
	},
	{
		.nsd_type       = LDLM_NS_TYPE_MGT,
		.nsd_bkt_bits   = 4,
		.nsd_all_bits   = 4,
		.nsd_hops       = &ldlm_ns_hash_ops,
	},
	{
		.nsd_type       = LDLM_NS_TYPE_UNKNOWN,
	},
};

/** Register \a ns in the list of namespaces */
static void ldlm_namespace_register(struct ldlm_namespace *ns,
				    enum ldlm_side client)
{
	mutex_lock(ldlm_namespace_lock(client));
	LASSERT(list_empty(&ns->ns_list_chain));
	list_add(&ns->ns_list_chain, &ldlm_cli_inactive_namespace_list);
	ldlm_namespace_nr_inc(client);
	mutex_unlock(ldlm_namespace_lock(client));
}

/**
 * Create and initialize new empty namespace.
 */
struct ldlm_namespace *ldlm_namespace_new(struct obd_device *obd, char *name,
					  enum ldlm_side client,
					  enum ldlm_appetite apt,
					  enum ldlm_ns_type ns_type)
{
	struct ldlm_namespace *ns = NULL;
	struct ldlm_ns_bucket *nsb;
	struct ldlm_ns_hash_def    *nsd;
	struct cfs_hash_bd	  bd;
	int		    idx;
	int		    rc;

	LASSERT(obd);

	rc = ldlm_get_ref();
	if (rc) {
		CERROR("ldlm_get_ref failed: %d\n", rc);
		return NULL;
	}

	for (idx = 0;; idx++) {
		nsd = &ldlm_ns_hash_defs[idx];
		if (nsd->nsd_type == LDLM_NS_TYPE_UNKNOWN) {
			CERROR("Unknown type %d for ns %s\n", ns_type, name);
			goto out_ref;
		}

		if (nsd->nsd_type == ns_type)
			break;
	}

	ns = kzalloc(sizeof(*ns), GFP_NOFS);
	if (!ns)
		goto out_ref;

	ns->ns_rs_hash = cfs_hash_create(name,
					 nsd->nsd_all_bits, nsd->nsd_all_bits,
					 nsd->nsd_bkt_bits, sizeof(*nsb),
					 CFS_HASH_MIN_THETA,
					 CFS_HASH_MAX_THETA,
					 nsd->nsd_hops,
					 CFS_HASH_DEPTH |
					 CFS_HASH_BIGNAME |
					 CFS_HASH_SPIN_BKTLOCK |
					 CFS_HASH_NO_ITEMREF);
	if (!ns->ns_rs_hash)
		goto out_ns;

	cfs_hash_for_each_bucket(ns->ns_rs_hash, &bd, idx) {
		nsb = cfs_hash_bd_extra_get(ns->ns_rs_hash, &bd);
		at_init(&nsb->nsb_at_estimate, ldlm_enqueue_min, 0);
		nsb->nsb_namespace = ns;
	}

	ns->ns_obd      = obd;
	ns->ns_appetite = apt;
	ns->ns_client   = client;

	INIT_LIST_HEAD(&ns->ns_list_chain);
	INIT_LIST_HEAD(&ns->ns_unused_list);
	spin_lock_init(&ns->ns_lock);
	atomic_set(&ns->ns_bref, 0);
	init_waitqueue_head(&ns->ns_waitq);

	ns->ns_max_parallel_ast   = LDLM_DEFAULT_PARALLEL_AST_LIMIT;
	ns->ns_nr_unused	  = 0;
	ns->ns_max_unused	 = LDLM_DEFAULT_LRU_SIZE;
	ns->ns_max_age	    = LDLM_DEFAULT_MAX_ALIVE;
	ns->ns_orig_connect_flags = 0;
	ns->ns_connect_flags      = 0;
	ns->ns_stopping	   = 0;

	rc = ldlm_namespace_sysfs_register(ns);
	if (rc != 0) {
		CERROR("Can't initialize ns sysfs, rc %d\n", rc);
		goto out_hash;
	}

	rc = ldlm_namespace_debugfs_register(ns);
	if (rc != 0) {
		CERROR("Can't initialize ns proc, rc %d\n", rc);
		goto out_sysfs;
	}

	idx = ldlm_namespace_nr_read(client);
	rc = ldlm_pool_init(&ns->ns_pool, ns, idx, client);
	if (rc) {
		CERROR("Can't initialize lock pool, rc %d\n", rc);
		goto out_proc;
	}

	ldlm_namespace_register(ns, client);
	return ns;
out_proc:
	ldlm_namespace_debugfs_unregister(ns);
out_sysfs:
	ldlm_namespace_sysfs_unregister(ns);
	ldlm_namespace_cleanup(ns, 0);
out_hash:
	cfs_hash_putref(ns->ns_rs_hash);
out_ns:
	kfree(ns);
out_ref:
	ldlm_put_ref();
	return NULL;
}
EXPORT_SYMBOL(ldlm_namespace_new);

extern struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);

/**
 * Cancel and destroy all locks on a resource.
 *
 * If flags contains FL_LOCAL_ONLY, don't try to tell the server, just
 * clean up.  This is currently only used for recovery, and we make
 * certain assumptions as a result--notably, that we shouldn't cancel
 * locks with refs.
 */
static void cleanup_resource(struct ldlm_resource *res, struct list_head *q,
			     __u64 flags)
{
	struct list_head *tmp;
	int rc = 0;
	bool local_only = !!(flags & LDLM_FL_LOCAL_ONLY);

	do {
		struct ldlm_lock *lock = NULL;
		struct lustre_handle lockh;

		/* First, we look for non-cleaned-yet lock
		 * all cleaned locks are marked by CLEANED flag.
		 */
		lock_res(res);
		list_for_each(tmp, q) {
			lock = list_entry(tmp, struct ldlm_lock, l_res_link);
			if (ldlm_is_cleaned(lock)) {
				lock = NULL;
				continue;
			}
			LDLM_LOCK_GET(lock);
			ldlm_set_cleaned(lock);
			break;
		}

		if (!lock) {
			unlock_res(res);
			break;
		}

		/* Set CBPENDING so nothing in the cancellation path
		 * can match this lock.
		 */
		ldlm_set_cbpending(lock);
		ldlm_set_failed(lock);
		lock->l_flags |= flags;

		/* ... without sending a CANCEL message for local_only. */
		if (local_only)
			ldlm_set_local_only(lock);

		if (local_only && (lock->l_readers || lock->l_writers)) {
			/* This is a little bit gross, but much better than the
			 * alternative: pretend that we got a blocking AST from
			 * the server, so that when the lock is decref'd, it
			 * will go away ...
			 */
			unlock_res(res);
			LDLM_DEBUG(lock, "setting FL_LOCAL_ONLY");
			if (lock->l_flags & LDLM_FL_FAIL_LOC) {
				set_current_state(TASK_UNINTERRUPTIBLE);
				schedule_timeout(cfs_time_seconds(4));
				set_current_state(TASK_RUNNING);
			}
			if (lock->l_completion_ast)
				lock->l_completion_ast(lock, LDLM_FL_FAILED,
						       NULL);
			LDLM_LOCK_RELEASE(lock);
			continue;
		}

		unlock_res(res);
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_LOCAL);
		if (rc)
			CERROR("ldlm_cli_cancel: %d\n", rc);
		LDLM_LOCK_RELEASE(lock);
	} while (1);
}

static int ldlm_resource_clean(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			       struct hlist_node *hnode, void *arg)
{
	struct ldlm_resource *res = cfs_hash_object(hs, hnode);
	__u64 flags = *(__u64 *)arg;

	cleanup_resource(res, &res->lr_granted, flags);
	cleanup_resource(res, &res->lr_waiting, flags);

	return 0;
}

static int ldlm_resource_complain(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				  struct hlist_node *hnode, void *arg)
{
	struct ldlm_resource  *res = cfs_hash_object(hs, hnode);

	lock_res(res);
	CERROR("%s: namespace resource " DLDLMRES
	       " (%p) refcount nonzero (%d) after lock cleanup; forcing cleanup.\n",
	       ldlm_ns_name(ldlm_res_to_ns(res)), PLDLMRES(res), res,
	       atomic_read(&res->lr_refcount) - 1);

	ldlm_resource_dump(D_ERROR, res);
	unlock_res(res);
	return 0;
}

/**
 * Cancel and destroy all locks in the namespace.
 *
 * Typically used during evictions when server notified client that it was
 * evicted and all of its state needs to be destroyed.
 * Also used during shutdown.
 */
int ldlm_namespace_cleanup(struct ldlm_namespace *ns, __u64 flags)
{
	if (!ns) {
		CDEBUG(D_INFO, "NULL ns, skipping cleanup\n");
		return ELDLM_OK;
	}

	cfs_hash_for_each_nolock(ns->ns_rs_hash, ldlm_resource_clean,
				 &flags, 0);
	cfs_hash_for_each_nolock(ns->ns_rs_hash, ldlm_resource_complain,
				 NULL, 0);
	return ELDLM_OK;
}
EXPORT_SYMBOL(ldlm_namespace_cleanup);

/**
 * Attempts to free namespace.
 *
 * Only used when namespace goes away, like during an unmount.
 */
static int __ldlm_namespace_free(struct ldlm_namespace *ns, int force)
{
	/* At shutdown time, don't call the cancellation callback */
	ldlm_namespace_cleanup(ns, force ? LDLM_FL_LOCAL_ONLY : 0);

	if (atomic_read(&ns->ns_bref) > 0) {
		struct l_wait_info lwi = LWI_INTR(LWI_ON_SIGNAL_NOOP, NULL);
		int rc;

		CDEBUG(D_DLMTRACE,
		       "dlm namespace %s free waiting on refcount %d\n",
		       ldlm_ns_name(ns), atomic_read(&ns->ns_bref));
force_wait:
		if (force)
			lwi = LWI_TIMEOUT(msecs_to_jiffies(obd_timeout *
					  MSEC_PER_SEC) / 4, NULL, NULL);

		rc = l_wait_event(ns->ns_waitq,
				  atomic_read(&ns->ns_bref) == 0, &lwi);

		/* Forced cleanups should be able to reclaim all references,
		 * so it's safe to wait forever... we can't leak locks...
		 */
		if (force && rc == -ETIMEDOUT) {
			LCONSOLE_ERROR("Forced cleanup waiting for %s namespace with %d resources in use, (rc=%d)\n",
				       ldlm_ns_name(ns),
				       atomic_read(&ns->ns_bref), rc);
			goto force_wait;
		}

		if (atomic_read(&ns->ns_bref)) {
			LCONSOLE_ERROR("Cleanup waiting for %s namespace with %d resources in use, (rc=%d)\n",
				       ldlm_ns_name(ns),
				       atomic_read(&ns->ns_bref), rc);
			return ELDLM_NAMESPACE_EXISTS;
		}
		CDEBUG(D_DLMTRACE, "dlm namespace %s free done waiting\n",
		       ldlm_ns_name(ns));
	}

	return ELDLM_OK;
}

/**
 * Performs various cleanups for passed \a ns to make it drop refc and be
 * ready for freeing. Waits for refc == 0.
 *
 * The following is done:
 * (0) Unregister \a ns from its list to make inaccessible for potential
 * users like pools thread and others;
 * (1) Clear all locks in \a ns.
 */
void ldlm_namespace_free_prior(struct ldlm_namespace *ns,
			       struct obd_import *imp,
			       int force)
{
	int rc;

	if (!ns)
		return;

	spin_lock(&ns->ns_lock);
	ns->ns_stopping = 1;
	spin_unlock(&ns->ns_lock);

	/*
	 * Can fail with -EINTR when force == 0 in which case try harder.
	 */
	rc = __ldlm_namespace_free(ns, force);
	if (rc != ELDLM_OK) {
		if (imp) {
			ptlrpc_disconnect_import(imp, 0);
			ptlrpc_invalidate_import(imp);
		}

		/*
		 * With all requests dropped and the import inactive
		 * we are guaranteed all reference will be dropped.
		 */
		rc = __ldlm_namespace_free(ns, 1);
		LASSERT(rc == 0);
	}
}

/** Unregister \a ns from the list of namespaces. */
static void ldlm_namespace_unregister(struct ldlm_namespace *ns,
				      enum ldlm_side client)
{
	mutex_lock(ldlm_namespace_lock(client));
	LASSERT(!list_empty(&ns->ns_list_chain));
	/* Some asserts and possibly other parts of the code are still
	 * using list_empty(&ns->ns_list_chain). This is why it is
	 * important to use list_del_init() here.
	 */
	list_del_init(&ns->ns_list_chain);
	ldlm_namespace_nr_dec(client);
	mutex_unlock(ldlm_namespace_lock(client));
}

/**
 * Performs freeing memory structures related to \a ns. This is only done
 * when ldlm_namespce_free_prior() successfully removed all resources
 * referencing \a ns and its refc == 0.
 */
void ldlm_namespace_free_post(struct ldlm_namespace *ns)
{
	if (!ns)
		return;

	/* Make sure that nobody can find this ns in its list. */
	ldlm_namespace_unregister(ns, ns->ns_client);
	/* Fini pool _before_ parent proc dir is removed. This is important as
	 * ldlm_pool_fini() removes own proc dir which is child to @dir.
	 * Removing it after @dir may cause oops.
	 */
	ldlm_pool_fini(&ns->ns_pool);

	ldlm_namespace_debugfs_unregister(ns);
	ldlm_namespace_sysfs_unregister(ns);
	cfs_hash_putref(ns->ns_rs_hash);
	/* Namespace \a ns should be not on list at this time, otherwise
	 * this will cause issues related to using freed \a ns in poold
	 * thread.
	 */
	LASSERT(list_empty(&ns->ns_list_chain));
	kfree(ns);
	ldlm_put_ref();
}

void ldlm_namespace_get(struct ldlm_namespace *ns)
{
	atomic_inc(&ns->ns_bref);
}

/* This is only for callers that care about refcount */
static int ldlm_namespace_get_return(struct ldlm_namespace *ns)
{
	return atomic_inc_return(&ns->ns_bref);
}

void ldlm_namespace_put(struct ldlm_namespace *ns)
{
	if (atomic_dec_and_lock(&ns->ns_bref, &ns->ns_lock)) {
		wake_up(&ns->ns_waitq);
		spin_unlock(&ns->ns_lock);
	}
}

/** Should be called with ldlm_namespace_lock(client) taken. */
void ldlm_namespace_move_to_active_locked(struct ldlm_namespace *ns,
					  enum ldlm_side client)
{
	LASSERT(!list_empty(&ns->ns_list_chain));
	LASSERT(mutex_is_locked(ldlm_namespace_lock(client)));
	list_move_tail(&ns->ns_list_chain, ldlm_namespace_list(client));
}

/** Should be called with ldlm_namespace_lock(client) taken. */
void ldlm_namespace_move_to_inactive_locked(struct ldlm_namespace *ns,
					    enum ldlm_side client)
{
	LASSERT(!list_empty(&ns->ns_list_chain));
	LASSERT(mutex_is_locked(ldlm_namespace_lock(client)));
	list_move_tail(&ns->ns_list_chain, &ldlm_cli_inactive_namespace_list);
}

/** Should be called with ldlm_namespace_lock(client) taken. */
struct ldlm_namespace *ldlm_namespace_first_locked(enum ldlm_side client)
{
	LASSERT(mutex_is_locked(ldlm_namespace_lock(client)));
	LASSERT(!list_empty(ldlm_namespace_list(client)));
	return container_of(ldlm_namespace_list(client)->next,
		struct ldlm_namespace, ns_list_chain);
}

/** Create and initialize new resource. */
static struct ldlm_resource *ldlm_resource_new(void)
{
	struct ldlm_resource *res;
	int idx;

	res = kmem_cache_zalloc(ldlm_resource_slab, GFP_NOFS);
	if (!res)
		return NULL;

	INIT_LIST_HEAD(&res->lr_granted);
	INIT_LIST_HEAD(&res->lr_waiting);

	/* Initialize interval trees for each lock mode. */
	for (idx = 0; idx < LCK_MODE_NUM; idx++) {
		res->lr_itree[idx].lit_size = 0;
		res->lr_itree[idx].lit_mode = 1 << idx;
		res->lr_itree[idx].lit_root = NULL;
	}

	atomic_set(&res->lr_refcount, 1);
	spin_lock_init(&res->lr_lock);
	lu_ref_init(&res->lr_reference);

	/* The creator of the resource must unlock the mutex after LVB
	 * initialization.
	 */
	mutex_init(&res->lr_lvb_mutex);
	mutex_lock(&res->lr_lvb_mutex);

	return res;
}

/**
 * Return a reference to resource with given name, creating it if necessary.
 * Args: namespace with ns_lock unlocked
 * Locks: takes and releases NS hash-lock and res->lr_lock
 * Returns: referenced, unlocked ldlm_resource or NULL
 */
struct ldlm_resource *
ldlm_resource_get(struct ldlm_namespace *ns, struct ldlm_resource *parent,
		  const struct ldlm_res_id *name, enum ldlm_type type,
		  int create)
{
	struct hlist_node     *hnode;
	struct ldlm_resource *res = NULL;
	struct cfs_hash_bd	 bd;
	__u64		 version;
	int		      ns_refcount = 0;
	int rc;

	LASSERT(!parent);
	LASSERT(ns->ns_rs_hash);
	LASSERT(name->name[0] != 0);

	cfs_hash_bd_get_and_lock(ns->ns_rs_hash, (void *)name, &bd, 0);
	hnode = cfs_hash_bd_lookup_locked(ns->ns_rs_hash, &bd, (void *)name);
	if (hnode) {
		cfs_hash_bd_unlock(ns->ns_rs_hash, &bd, 0);
		goto lvbo_init;
	}

	version = cfs_hash_bd_version_get(&bd);
	cfs_hash_bd_unlock(ns->ns_rs_hash, &bd, 0);

	if (create == 0)
		return ERR_PTR(-ENOENT);

	LASSERTF(type >= LDLM_MIN_TYPE && type < LDLM_MAX_TYPE,
		 "type: %d\n", type);
	res = ldlm_resource_new();
	if (!res)
		return ERR_PTR(-ENOMEM);

	res->lr_ns_bucket  = cfs_hash_bd_extra_get(ns->ns_rs_hash, &bd);
	res->lr_name       = *name;
	res->lr_type       = type;

	cfs_hash_bd_lock(ns->ns_rs_hash, &bd, 1);
	hnode = (version == cfs_hash_bd_version_get(&bd)) ?  NULL :
		cfs_hash_bd_lookup_locked(ns->ns_rs_hash, &bd, (void *)name);

	if (hnode) {
		/* Someone won the race and already added the resource. */
		cfs_hash_bd_unlock(ns->ns_rs_hash, &bd, 1);
		/* Clean lu_ref for failed resource. */
		lu_ref_fini(&res->lr_reference);
		/* We have taken lr_lvb_mutex. Drop it. */
		mutex_unlock(&res->lr_lvb_mutex);
		kmem_cache_free(ldlm_resource_slab, res);
lvbo_init:
		res = hlist_entry(hnode, struct ldlm_resource, lr_hash);
		/* Synchronize with regard to resource creation. */
		if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
			mutex_lock(&res->lr_lvb_mutex);
			mutex_unlock(&res->lr_lvb_mutex);
		}

		if (unlikely(res->lr_lvb_len < 0)) {
			rc = res->lr_lvb_len;
			ldlm_resource_putref(res);
			res = ERR_PTR(rc);
		}
		return res;
	}
	/* We won! Let's add the resource. */
	cfs_hash_bd_add_locked(ns->ns_rs_hash, &bd, &res->lr_hash);
	if (cfs_hash_bd_count_get(&bd) == 1)
		ns_refcount = ldlm_namespace_get_return(ns);

	cfs_hash_bd_unlock(ns->ns_rs_hash, &bd, 1);
	if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
		OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CREATE_RESOURCE, 2);
		rc = ns->ns_lvbo->lvbo_init(res);
		if (rc < 0) {
			CERROR("%s: lvbo_init failed for resource %#llx:%#llx: rc = %d\n",
			       ns->ns_obd->obd_name, name->name[0],
			       name->name[1], rc);
			res->lr_lvb_len = rc;
			mutex_unlock(&res->lr_lvb_mutex);
			ldlm_resource_putref(res);
			return ERR_PTR(rc);
		}
	}

	/* We create resource with locked lr_lvb_mutex. */
	mutex_unlock(&res->lr_lvb_mutex);

	/* Let's see if we happened to be the very first resource in this
	 * namespace. If so, and this is a client namespace, we need to move
	 * the namespace into the active namespaces list to be patrolled by
	 * the ldlm_poold.
	 */
	if (ns_refcount == 1) {
		mutex_lock(ldlm_namespace_lock(LDLM_NAMESPACE_CLIENT));
		ldlm_namespace_move_to_active_locked(ns, LDLM_NAMESPACE_CLIENT);
		mutex_unlock(ldlm_namespace_lock(LDLM_NAMESPACE_CLIENT));
	}

	return res;
}
EXPORT_SYMBOL(ldlm_resource_get);

static void __ldlm_resource_putref_final(struct cfs_hash_bd *bd,
					 struct ldlm_resource *res)
{
	struct ldlm_ns_bucket *nsb = res->lr_ns_bucket;

	if (!list_empty(&res->lr_granted)) {
		ldlm_resource_dump(D_ERROR, res);
		LBUG();
	}

	if (!list_empty(&res->lr_waiting)) {
		ldlm_resource_dump(D_ERROR, res);
		LBUG();
	}

	cfs_hash_bd_del_locked(nsb->nsb_namespace->ns_rs_hash,
			       bd, &res->lr_hash);
	lu_ref_fini(&res->lr_reference);
	if (cfs_hash_bd_count_get(bd) == 0)
		ldlm_namespace_put(nsb->nsb_namespace);
}

/* Returns 1 if the resource was freed, 0 if it remains. */
int ldlm_resource_putref(struct ldlm_resource *res)
{
	struct ldlm_namespace *ns = ldlm_res_to_ns(res);
	struct cfs_hash_bd   bd;

	LASSERT_ATOMIC_GT_LT(&res->lr_refcount, 0, LI_POISON);
	CDEBUG(D_INFO, "putref res: %p count: %d\n",
	       res, atomic_read(&res->lr_refcount) - 1);

	cfs_hash_bd_get(ns->ns_rs_hash, &res->lr_name, &bd);
	if (cfs_hash_bd_dec_and_lock(ns->ns_rs_hash, &bd, &res->lr_refcount)) {
		__ldlm_resource_putref_final(&bd, res);
		cfs_hash_bd_unlock(ns->ns_rs_hash, &bd, 1);
		if (ns->ns_lvbo && ns->ns_lvbo->lvbo_free)
			ns->ns_lvbo->lvbo_free(res);
		kmem_cache_free(ldlm_resource_slab, res);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(ldlm_resource_putref);

/* Returns 1 if the resource was freed, 0 if it remains. */
int ldlm_resource_putref_locked(struct ldlm_resource *res)
{
	struct ldlm_namespace *ns = ldlm_res_to_ns(res);

	LASSERT_ATOMIC_GT_LT(&res->lr_refcount, 0, LI_POISON);
	CDEBUG(D_INFO, "putref res: %p count: %d\n",
	       res, atomic_read(&res->lr_refcount) - 1);

	if (atomic_dec_and_test(&res->lr_refcount)) {
		struct cfs_hash_bd bd;

		cfs_hash_bd_get(ldlm_res_to_ns(res)->ns_rs_hash,
				&res->lr_name, &bd);
		__ldlm_resource_putref_final(&bd, res);
		cfs_hash_bd_unlock(ns->ns_rs_hash, &bd, 1);
		/* NB: ns_rs_hash is created with CFS_HASH_NO_ITEMREF,
		 * so we should never be here while calling cfs_hash_del,
		 * cfs_hash_for_each_nolock is the only case we can get
		 * here, which is safe to release cfs_hash_bd_lock.
		 */
		if (ns->ns_lvbo && ns->ns_lvbo->lvbo_free)
			ns->ns_lvbo->lvbo_free(res);
		kmem_cache_free(ldlm_resource_slab, res);

		cfs_hash_bd_lock(ns->ns_rs_hash, &bd, 1);
		return 1;
	}
	return 0;
}

/**
 * Add a lock into a given resource into specified lock list.
 */
void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
			    struct ldlm_lock *lock)
{
	check_res_locked(res);

	LDLM_DEBUG(lock, "About to add this lock:");

	if (ldlm_is_destroyed(lock)) {
		CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
		return;
	}

	LASSERT(list_empty(&lock->l_res_link));

	list_add_tail(&lock->l_res_link, head);
}

void ldlm_resource_unlink_lock(struct ldlm_lock *lock)
{
	int type = lock->l_resource->lr_type;

	check_res_locked(lock->l_resource);
	if (type == LDLM_IBITS || type == LDLM_PLAIN)
		ldlm_unlink_lock_skiplist(lock);
	else if (type == LDLM_EXTENT)
		ldlm_extent_unlink_lock(lock);
	list_del_init(&lock->l_res_link);
}
EXPORT_SYMBOL(ldlm_resource_unlink_lock);

void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc)
{
	desc->lr_type = res->lr_type;
	desc->lr_name = res->lr_name;
}

/**
 * Print information about all locks in all namespaces on this node to debug
 * log.
 */
void ldlm_dump_all_namespaces(enum ldlm_side client, int level)
{
	struct list_head *tmp;

	if (!((libcfs_debug | D_ERROR) & level))
		return;

	mutex_lock(ldlm_namespace_lock(client));

	list_for_each(tmp, ldlm_namespace_list(client)) {
		struct ldlm_namespace *ns;

		ns = list_entry(tmp, struct ldlm_namespace, ns_list_chain);
		ldlm_namespace_dump(level, ns);
	}

	mutex_unlock(ldlm_namespace_lock(client));
}

static int ldlm_res_hash_dump(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			      struct hlist_node *hnode, void *arg)
{
	struct ldlm_resource *res = cfs_hash_object(hs, hnode);
	int    level = (int)(unsigned long)arg;

	lock_res(res);
	ldlm_resource_dump(level, res);
	unlock_res(res);

	return 0;
}

/**
 * Print information about all locks in this namespace on this node to debug
 * log.
 */
void ldlm_namespace_dump(int level, struct ldlm_namespace *ns)
{
	if (!((libcfs_debug | D_ERROR) & level))
		return;

	CDEBUG(level, "--- Namespace: %s (rc: %d, side: client)\n",
	       ldlm_ns_name(ns), atomic_read(&ns->ns_bref));

	if (time_before(cfs_time_current(), ns->ns_next_dump))
		return;

	cfs_hash_for_each_nolock(ns->ns_rs_hash,
				 ldlm_res_hash_dump,
				 (void *)(unsigned long)level, 0);
	spin_lock(&ns->ns_lock);
	ns->ns_next_dump = cfs_time_shift(10);
	spin_unlock(&ns->ns_lock);
}

/**
 * Print information about all locks in this resource to debug log.
 */
void ldlm_resource_dump(int level, struct ldlm_resource *res)
{
	struct ldlm_lock *lock;
	unsigned int granted = 0;

	BUILD_BUG_ON(RES_NAME_SIZE != 4);

	if (!((libcfs_debug | D_ERROR) & level))
		return;

	CDEBUG(level, "--- Resource: " DLDLMRES " (%p) refcount = %d\n",
	       PLDLMRES(res), res, atomic_read(&res->lr_refcount));

	if (!list_empty(&res->lr_granted)) {
		CDEBUG(level, "Granted locks (in reverse order):\n");
		list_for_each_entry_reverse(lock, &res->lr_granted,
					    l_res_link) {
			LDLM_DEBUG_LIMIT(level, lock, "###");
			if (!(level & D_CANTMASK) &&
			    ++granted > ldlm_dump_granted_max) {
				CDEBUG(level, "only dump %d granted locks to avoid DDOS.\n",
				       granted);
				break;
			}
		}
	}
	if (!list_empty(&res->lr_waiting)) {
		CDEBUG(level, "Waiting locks:\n");
		list_for_each_entry(lock, &res->lr_waiting, l_res_link)
			LDLM_DEBUG_LIMIT(level, lock, "###");
	}
}
EXPORT_SYMBOL(ldlm_resource_dump);
