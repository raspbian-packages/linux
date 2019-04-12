/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "rds.h"
#include "tcp.h"

/* only for info exporting */
static DEFINE_SPINLOCK(rds_tcp_tc_list_lock);
static LIST_HEAD(rds_tcp_tc_list);
static unsigned int rds_tcp_tc_count;

/* Track rds_tcp_connection structs so they can be cleaned up */
static DEFINE_SPINLOCK(rds_tcp_conn_lock);
static LIST_HEAD(rds_tcp_conn_list);

static struct kmem_cache *rds_tcp_conn_slab;

static int rds_tcp_skbuf_handler(struct ctl_table *ctl, int write,
				 void __user *buffer, size_t *lenp,
				 loff_t *fpos);

static int rds_tcp_min_sndbuf = SOCK_MIN_SNDBUF;
static int rds_tcp_min_rcvbuf = SOCK_MIN_RCVBUF;

static struct ctl_table rds_tcp_sysctl_table[] = {
#define	RDS_TCP_SNDBUF	0
	{
		.procname       = "rds_tcp_sndbuf",
		/* data is per-net pointer */
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = rds_tcp_skbuf_handler,
		.extra1		= &rds_tcp_min_sndbuf,
	},
#define	RDS_TCP_RCVBUF	1
	{
		.procname       = "rds_tcp_rcvbuf",
		/* data is per-net pointer */
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = rds_tcp_skbuf_handler,
		.extra1		= &rds_tcp_min_rcvbuf,
	},
	{ }
};

/* doing it this way avoids calling tcp_sk() */
void rds_tcp_nonagle(struct socket *sock)
{
	mm_segment_t oldfs = get_fs();
	int val = 1;

	set_fs(KERNEL_DS);
	sock->ops->setsockopt(sock, SOL_TCP, TCP_NODELAY, (char __user *)&val,
			      sizeof(val));
	set_fs(oldfs);
}

u32 rds_tcp_snd_nxt(struct rds_tcp_connection *tc)
{
	return tcp_sk(tc->t_sock->sk)->snd_nxt;
}

u32 rds_tcp_snd_una(struct rds_tcp_connection *tc)
{
	return tcp_sk(tc->t_sock->sk)->snd_una;
}

void rds_tcp_restore_callbacks(struct socket *sock,
			       struct rds_tcp_connection *tc)
{
	rdsdebug("restoring sock %p callbacks from tc %p\n", sock, tc);
	write_lock_bh(&sock->sk->sk_callback_lock);

	/* done under the callback_lock to serialize with write_space */
	spin_lock(&rds_tcp_tc_list_lock);
	list_del_init(&tc->t_list_item);
	rds_tcp_tc_count--;
	spin_unlock(&rds_tcp_tc_list_lock);

	tc->t_sock = NULL;

	sock->sk->sk_write_space = tc->t_orig_write_space;
	sock->sk->sk_data_ready = tc->t_orig_data_ready;
	sock->sk->sk_state_change = tc->t_orig_state_change;
	sock->sk->sk_user_data = NULL;

	write_unlock_bh(&sock->sk->sk_callback_lock);
}

/*
 * rds_tcp_reset_callbacks() switches the to the new sock and
 * returns the existing tc->t_sock.
 *
 * The only functions that set tc->t_sock are rds_tcp_set_callbacks
 * and rds_tcp_reset_callbacks.  Send and receive trust that
 * it is set.  The absence of RDS_CONN_UP bit protects those paths
 * from being called while it isn't set.
 */
void rds_tcp_reset_callbacks(struct socket *sock,
			     struct rds_conn_path *cp)
{
	struct rds_tcp_connection *tc = cp->cp_transport_data;
	struct socket *osock = tc->t_sock;

	if (!osock)
		goto newsock;

	/* Need to resolve a duelling SYN between peers.
	 * We have an outstanding SYN to this peer, which may
	 * potentially have transitioned to the RDS_CONN_UP state,
	 * so we must quiesce any send threads before resetting
	 * cp_transport_data. We quiesce these threads by setting
	 * cp_state to something other than RDS_CONN_UP, and then
	 * waiting for any existing threads in rds_send_xmit to
	 * complete release_in_xmit(). (Subsequent threads entering
	 * rds_send_xmit() will bail on !rds_conn_up().
	 *
	 * However an incoming syn-ack at this point would end up
	 * marking the conn as RDS_CONN_UP, and would again permit
	 * rds_send_xmi() threads through, so ideally we would
	 * synchronize on RDS_CONN_UP after lock_sock(), but cannot
	 * do that: waiting on !RDS_IN_XMIT after lock_sock() may
	 * end up deadlocking with tcp_sendmsg(), and the RDS_IN_XMIT
	 * would not get set. As a result, we set c_state to
	 * RDS_CONN_RESETTTING, to ensure that rds_tcp_state_change
	 * cannot mark rds_conn_path_up() in the window before lock_sock()
	 */
	atomic_set(&cp->cp_state, RDS_CONN_RESETTING);
	wait_event(cp->cp_waitq, !test_bit(RDS_IN_XMIT, &cp->cp_flags));
	lock_sock(osock->sk);
	/* reset receive side state for rds_tcp_data_recv() for osock  */
	cancel_delayed_work_sync(&cp->cp_send_w);
	cancel_delayed_work_sync(&cp->cp_recv_w);
	if (tc->t_tinc) {
		rds_inc_put(&tc->t_tinc->ti_inc);
		tc->t_tinc = NULL;
	}
	tc->t_tinc_hdr_rem = sizeof(struct rds_header);
	tc->t_tinc_data_rem = 0;
	rds_tcp_restore_callbacks(osock, tc);
	release_sock(osock->sk);
	sock_release(osock);
newsock:
	rds_send_path_reset(cp);
	lock_sock(sock->sk);
	rds_tcp_set_callbacks(sock, cp);
	release_sock(sock->sk);
}

/* Add tc to rds_tcp_tc_list and set tc->t_sock. See comments
 * above rds_tcp_reset_callbacks for notes about synchronization
 * with data path
 */
void rds_tcp_set_callbacks(struct socket *sock, struct rds_conn_path *cp)
{
	struct rds_tcp_connection *tc = cp->cp_transport_data;

	rdsdebug("setting sock %p callbacks to tc %p\n", sock, tc);
	write_lock_bh(&sock->sk->sk_callback_lock);

	/* done under the callback_lock to serialize with write_space */
	spin_lock(&rds_tcp_tc_list_lock);
	list_add_tail(&tc->t_list_item, &rds_tcp_tc_list);
	rds_tcp_tc_count++;
	spin_unlock(&rds_tcp_tc_list_lock);

	/* accepted sockets need our listen data ready undone */
	if (sock->sk->sk_data_ready == rds_tcp_listen_data_ready)
		sock->sk->sk_data_ready = sock->sk->sk_user_data;

	tc->t_sock = sock;
	tc->t_cpath = cp;
	tc->t_orig_data_ready = sock->sk->sk_data_ready;
	tc->t_orig_write_space = sock->sk->sk_write_space;
	tc->t_orig_state_change = sock->sk->sk_state_change;

	sock->sk->sk_user_data = cp;
	sock->sk->sk_data_ready = rds_tcp_data_ready;
	sock->sk->sk_write_space = rds_tcp_write_space;
	sock->sk->sk_state_change = rds_tcp_state_change;

	write_unlock_bh(&sock->sk->sk_callback_lock);
}

static void rds_tcp_tc_info(struct socket *sock, unsigned int len,
			    struct rds_info_iterator *iter,
			    struct rds_info_lengths *lens)
{
	struct rds_info_tcp_socket tsinfo;
	struct rds_tcp_connection *tc;
	unsigned long flags;
	struct sockaddr_in sin;
	int sinlen;

	spin_lock_irqsave(&rds_tcp_tc_list_lock, flags);

	if (len / sizeof(tsinfo) < rds_tcp_tc_count)
		goto out;

	list_for_each_entry(tc, &rds_tcp_tc_list, t_list_item) {

		sock->ops->getname(sock, (struct sockaddr *)&sin, &sinlen, 0);
		tsinfo.local_addr = sin.sin_addr.s_addr;
		tsinfo.local_port = sin.sin_port;
		sock->ops->getname(sock, (struct sockaddr *)&sin, &sinlen, 1);
		tsinfo.peer_addr = sin.sin_addr.s_addr;
		tsinfo.peer_port = sin.sin_port;

		tsinfo.hdr_rem = tc->t_tinc_hdr_rem;
		tsinfo.data_rem = tc->t_tinc_data_rem;
		tsinfo.last_sent_nxt = tc->t_last_sent_nxt;
		tsinfo.last_expected_una = tc->t_last_expected_una;
		tsinfo.last_seen_una = tc->t_last_seen_una;

		rds_info_copy(iter, &tsinfo, sizeof(tsinfo));
	}

out:
	lens->nr = rds_tcp_tc_count;
	lens->each = sizeof(tsinfo);

	spin_unlock_irqrestore(&rds_tcp_tc_list_lock, flags);
}

static int rds_tcp_laddr_check(struct net *net, __be32 addr)
{
	if (inet_addr_type(net, addr) == RTN_LOCAL)
		return 0;
	return -EADDRNOTAVAIL;
}

static int rds_tcp_conn_alloc(struct rds_connection *conn, gfp_t gfp)
{
	struct rds_tcp_connection *tc;
	int i;

	for (i = 0; i < RDS_MPATH_WORKERS; i++) {
		tc = kmem_cache_alloc(rds_tcp_conn_slab, gfp);
		if (!tc)
			return -ENOMEM;

		mutex_init(&tc->t_conn_path_lock);
		tc->t_sock = NULL;
		tc->t_tinc = NULL;
		tc->t_tinc_hdr_rem = sizeof(struct rds_header);
		tc->t_tinc_data_rem = 0;

		conn->c_path[i].cp_transport_data = tc;
		tc->t_cpath = &conn->c_path[i];

		spin_lock_irq(&rds_tcp_conn_lock);
		list_add_tail(&tc->t_tcp_node, &rds_tcp_conn_list);
		spin_unlock_irq(&rds_tcp_conn_lock);
		rdsdebug("rds_conn_path [%d] tc %p\n", i,
			 conn->c_path[i].cp_transport_data);
	}

	return 0;
}

static void rds_tcp_conn_free(void *arg)
{
	struct rds_tcp_connection *tc = arg;
	unsigned long flags;
	rdsdebug("freeing tc %p\n", tc);

	spin_lock_irqsave(&rds_tcp_conn_lock, flags);
	if (!tc->t_tcp_node_detached)
		list_del(&tc->t_tcp_node);
	spin_unlock_irqrestore(&rds_tcp_conn_lock, flags);

	kmem_cache_free(rds_tcp_conn_slab, tc);
}

static bool list_has_conn(struct list_head *list, struct rds_connection *conn)
{
	struct rds_tcp_connection *tc, *_tc;

	list_for_each_entry_safe(tc, _tc, list, t_tcp_node) {
		if (tc->t_cpath->cp_conn == conn)
			return true;
	}
	return false;
}

static void rds_tcp_destroy_conns(void)
{
	struct rds_tcp_connection *tc, *_tc;
	LIST_HEAD(tmp_list);

	/* avoid calling conn_destroy with irqs off */
	spin_lock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &rds_tcp_conn_list, t_tcp_node) {
		if (!list_has_conn(&tmp_list, tc->t_cpath->cp_conn))
			list_move_tail(&tc->t_tcp_node, &tmp_list);
	}
	spin_unlock_irq(&rds_tcp_conn_lock);

	list_for_each_entry_safe(tc, _tc, &tmp_list, t_tcp_node)
		rds_conn_destroy(tc->t_cpath->cp_conn);
}

static void rds_tcp_exit(void);

struct rds_transport rds_tcp_transport = {
	.laddr_check		= rds_tcp_laddr_check,
	.xmit_path_prepare	= rds_tcp_xmit_path_prepare,
	.xmit_path_complete	= rds_tcp_xmit_path_complete,
	.xmit			= rds_tcp_xmit,
	.recv_path		= rds_tcp_recv_path,
	.conn_alloc		= rds_tcp_conn_alloc,
	.conn_free		= rds_tcp_conn_free,
	.conn_path_connect	= rds_tcp_conn_path_connect,
	.conn_path_shutdown	= rds_tcp_conn_path_shutdown,
	.inc_copy_to_user	= rds_tcp_inc_copy_to_user,
	.inc_free		= rds_tcp_inc_free,
	.stats_info_copy	= rds_tcp_stats_info_copy,
	.exit			= rds_tcp_exit,
	.t_owner		= THIS_MODULE,
	.t_name			= "tcp",
	.t_type			= RDS_TRANS_TCP,
	.t_prefer_loopback	= 1,
	.t_mp_capable		= 1,
};

static int rds_tcp_netid;

/* per-network namespace private data for this module */
struct rds_tcp_net {
	struct socket *rds_tcp_listen_sock;
	struct work_struct rds_tcp_accept_w;
	struct ctl_table_header *rds_tcp_sysctl;
	struct ctl_table *ctl_table;
	int sndbuf_size;
	int rcvbuf_size;
};

/* All module specific customizations to the RDS-TCP socket should be done in
 * rds_tcp_tune() and applied after socket creation.
 */
void rds_tcp_tune(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);

	rds_tcp_nonagle(sock);
	lock_sock(sk);
	if (rtn->sndbuf_size > 0) {
		sk->sk_sndbuf = rtn->sndbuf_size;
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	}
	if (rtn->rcvbuf_size > 0) {
		sk->sk_sndbuf = rtn->rcvbuf_size;
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	}
	release_sock(sk);
}

static void rds_tcp_accept_worker(struct work_struct *work)
{
	struct rds_tcp_net *rtn = container_of(work,
					       struct rds_tcp_net,
					       rds_tcp_accept_w);

	while (rds_tcp_accept_one(rtn->rds_tcp_listen_sock) == 0)
		cond_resched();
}

void rds_tcp_accept_work(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);

	queue_work(rds_wq, &rtn->rds_tcp_accept_w);
}

static __net_init int rds_tcp_init_net(struct net *net)
{
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);
	struct ctl_table *tbl;
	int err = 0;

	memset(rtn, 0, sizeof(*rtn));

	/* {snd, rcv}buf_size default to 0, which implies we let the
	 * stack pick the value, and permit auto-tuning of buffer size.
	 */
	if (net == &init_net) {
		tbl = rds_tcp_sysctl_table;
	} else {
		tbl = kmemdup(rds_tcp_sysctl_table,
			      sizeof(rds_tcp_sysctl_table), GFP_KERNEL);
		if (!tbl) {
			pr_warn("could not set allocate syctl table\n");
			return -ENOMEM;
		}
		rtn->ctl_table = tbl;
	}
	tbl[RDS_TCP_SNDBUF].data = &rtn->sndbuf_size;
	tbl[RDS_TCP_RCVBUF].data = &rtn->rcvbuf_size;
	rtn->rds_tcp_sysctl = register_net_sysctl(net, "net/rds/tcp", tbl);
	if (!rtn->rds_tcp_sysctl) {
		pr_warn("could not register sysctl\n");
		err = -ENOMEM;
		goto fail;
	}
	rtn->rds_tcp_listen_sock = rds_tcp_listen_init(net);
	if (!rtn->rds_tcp_listen_sock) {
		pr_warn("could not set up listen sock\n");
		unregister_net_sysctl_table(rtn->rds_tcp_sysctl);
		rtn->rds_tcp_sysctl = NULL;
		err = -EAFNOSUPPORT;
		goto fail;
	}
	INIT_WORK(&rtn->rds_tcp_accept_w, rds_tcp_accept_worker);
	return 0;

fail:
	if (net != &init_net)
		kfree(tbl);
	return err;
}

static void __net_exit rds_tcp_exit_net(struct net *net)
{
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);

	if (rtn->rds_tcp_sysctl)
		unregister_net_sysctl_table(rtn->rds_tcp_sysctl);

	if (net != &init_net && rtn->ctl_table)
		kfree(rtn->ctl_table);

	/* If rds_tcp_exit_net() is called as a result of netns deletion,
	 * the rds_tcp_kill_sock() device notifier would already have cleaned
	 * up the listen socket, thus there is no work to do in this function.
	 *
	 * If rds_tcp_exit_net() is called as a result of module unload,
	 * i.e., due to rds_tcp_exit() -> unregister_pernet_subsys(), then
	 * we do need to clean up the listen socket here.
	 */
	if (rtn->rds_tcp_listen_sock) {
		struct socket *lsock = rtn->rds_tcp_listen_sock;

		rtn->rds_tcp_listen_sock = NULL;
		rds_tcp_listen_stop(lsock, &rtn->rds_tcp_accept_w);
	}
}

static struct pernet_operations rds_tcp_net_ops = {
	.init = rds_tcp_init_net,
	.exit = rds_tcp_exit_net,
	.id = &rds_tcp_netid,
	.size = sizeof(struct rds_tcp_net),
};

/* explicitly send a RST on each socket, thereby releasing any socket refcnts
 * that may otherwise hold up netns deletion.
 */
static void rds_tcp_conn_paths_destroy(struct rds_connection *conn)
{
	struct rds_conn_path *cp;
	struct rds_tcp_connection *tc;
	int i;
	struct sock *sk;

	for (i = 0; i < RDS_MPATH_WORKERS; i++) {
		cp = &conn->c_path[i];
		tc = cp->cp_transport_data;
		if (!tc->t_sock)
			continue;
		sk = tc->t_sock->sk;
		sk->sk_prot->disconnect(sk, 0);
		tcp_done(sk);
	}
}

static void rds_tcp_kill_sock(struct net *net)
{
	struct rds_tcp_connection *tc, *_tc;
	LIST_HEAD(tmp_list);
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);
	struct socket *lsock = rtn->rds_tcp_listen_sock;

	rtn->rds_tcp_listen_sock = NULL;
	rds_tcp_listen_stop(lsock, &rtn->rds_tcp_accept_w);
	spin_lock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &rds_tcp_conn_list, t_tcp_node) {
		struct net *c_net = read_pnet(&tc->t_cpath->cp_conn->c_net);

		if (net != c_net || !tc->t_sock)
			continue;
		if (!list_has_conn(&tmp_list, tc->t_cpath->cp_conn)) {
			list_move_tail(&tc->t_tcp_node, &tmp_list);
		} else {
			list_del(&tc->t_tcp_node);
			tc->t_tcp_node_detached = true;
		}
	}
	spin_unlock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &tmp_list, t_tcp_node) {
		rds_tcp_conn_paths_destroy(tc->t_cpath->cp_conn);
		rds_conn_destroy(tc->t_cpath->cp_conn);
	}
}

void *rds_tcp_listen_sock_def_readable(struct net *net)
{
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);
	struct socket *lsock = rtn->rds_tcp_listen_sock;

	if (!lsock)
		return NULL;

	return lsock->sk->sk_user_data;
}

static int rds_tcp_dev_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	/* rds-tcp registers as a pernet subys, so the ->exit will only
	 * get invoked after network acitivity has quiesced. We need to
	 * clean up all sockets  to quiesce network activity, and use
	 * the unregistration of the per-net loopback device as a trigger
	 * to start that cleanup.
	 */
	if (event == NETDEV_UNREGISTER_FINAL &&
	    dev->ifindex == LOOPBACK_IFINDEX)
		rds_tcp_kill_sock(dev_net(dev));

	return NOTIFY_DONE;
}

static struct notifier_block rds_tcp_dev_notifier = {
	.notifier_call        = rds_tcp_dev_event,
	.priority = -10, /* must be called after other network notifiers */
};

/* when sysctl is used to modify some kernel socket parameters,this
 * function  resets the RDS connections in that netns  so that we can
 * restart with new parameters.  The assumption is that such reset
 * events are few and far-between.
 */
static void rds_tcp_sysctl_reset(struct net *net)
{
	struct rds_tcp_connection *tc, *_tc;

	spin_lock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &rds_tcp_conn_list, t_tcp_node) {
		struct net *c_net = read_pnet(&tc->t_cpath->cp_conn->c_net);

		if (net != c_net || !tc->t_sock)
			continue;

		/* reconnect with new parameters */
		rds_conn_path_drop(tc->t_cpath);
	}
	spin_unlock_irq(&rds_tcp_conn_lock);
}

static int rds_tcp_skbuf_handler(struct ctl_table *ctl, int write,
				 void __user *buffer, size_t *lenp,
				 loff_t *fpos)
{
	struct net *net = current->nsproxy->net_ns;
	int err;

	err = proc_dointvec_minmax(ctl, write, buffer, lenp, fpos);
	if (err < 0) {
		pr_warn("Invalid input. Must be >= %d\n",
			*(int *)(ctl->extra1));
		return err;
	}
	if (write)
		rds_tcp_sysctl_reset(net);
	return 0;
}

static void rds_tcp_exit(void)
{
	rds_info_deregister_func(RDS_INFO_TCP_SOCKETS, rds_tcp_tc_info);
	unregister_pernet_subsys(&rds_tcp_net_ops);
	if (unregister_netdevice_notifier(&rds_tcp_dev_notifier))
		pr_warn("could not unregister rds_tcp_dev_notifier\n");
	rds_tcp_destroy_conns();
	rds_trans_unregister(&rds_tcp_transport);
	rds_tcp_recv_exit();
	kmem_cache_destroy(rds_tcp_conn_slab);
}
module_exit(rds_tcp_exit);

static int rds_tcp_init(void)
{
	int ret;

	rds_tcp_conn_slab = kmem_cache_create("rds_tcp_connection",
					      sizeof(struct rds_tcp_connection),
					      0, 0, NULL);
	if (!rds_tcp_conn_slab) {
		ret = -ENOMEM;
		goto out;
	}

	ret = register_netdevice_notifier(&rds_tcp_dev_notifier);
	if (ret) {
		pr_warn("could not register rds_tcp_dev_notifier\n");
		goto out;
	}

	ret = register_pernet_subsys(&rds_tcp_net_ops);
	if (ret)
		goto out_slab;

	ret = rds_tcp_recv_init();
	if (ret)
		goto out_pernet;

	ret = rds_trans_register(&rds_tcp_transport);
	if (ret)
		goto out_recv;

	rds_info_register_func(RDS_INFO_TCP_SOCKETS, rds_tcp_tc_info);

	goto out;

out_recv:
	rds_tcp_recv_exit();
out_pernet:
	unregister_pernet_subsys(&rds_tcp_net_ops);
out_slab:
	if (unregister_netdevice_notifier(&rds_tcp_dev_notifier))
		pr_warn("could not unregister rds_tcp_dev_notifier\n");
	kmem_cache_destroy(rds_tcp_conn_slab);
out:
	return ret;
}
module_init(rds_tcp_init);

MODULE_AUTHOR("Oracle Corporation <rds-devel@oss.oracle.com>");
MODULE_DESCRIPTION("RDS: TCP transport");
MODULE_LICENSE("Dual BSD/GPL");

