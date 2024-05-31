/*
 * net/tipc/link.c: TIPC link code
 *
 * Copyright (c) 1996-2007, 2012-2016, Ericsson AB
 * Copyright (c) 2004-2007, 2010-2013, Wind River Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "core.h"
#include "subscr.h"
#include "link.h"
#include "bcast.h"
#include "socket.h"
#include "name_distr.h"
#include "discover.h"
#include "netlink.h"
#include "monitor.h"
#include "trace.h"
#include "crypto.h"

#include <linux/pkt_sched.h>

struct tipc_stats {
	u32 sent_pkts;
	u32 recv_pkts;
	u32 sent_states;
	u32 recv_states;
	u32 sent_probes;
	u32 recv_probes;
	u32 sent_nacks;
	u32 recv_nacks;
	u32 sent_acks;
	u32 sent_bundled;
	u32 sent_bundles;
	u32 recv_bundled;
	u32 recv_bundles;
	u32 retransmitted;
	u32 sent_fragmented;
	u32 sent_fragments;
	u32 recv_fragmented;
	u32 recv_fragments;
	u32 link_congs;		/* # port sends blocked by congestion */
	u32 deferred_recv;
	u32 duplicates;
	u32 max_queue_sz;	/* send queue size high water mark */
	u32 accu_queue_sz;	/* used for send queue size profiling */
	u32 queue_sz_counts;	/* used for send queue size profiling */
	u32 msg_length_counts;	/* used for message length profiling */
	u32 msg_lengths_total;	/* used for message length profiling */
	u32 msg_length_profile[7]; /* used for msg. length profiling */
};

/**
 * struct tipc_link - TIPC link data structure
 * @addr: network address of link's peer node
 * @name: link name character string
 * @net: pointer to namespace struct
 * @peer_session: link session # being used by peer end of link
 * @peer_bearer_id: bearer id used by link's peer endpoint
 * @bearer_id: local bearer id used by link
 * @tolerance: minimum link continuity loss needed to reset link [in ms]
 * @abort_limit: # of unacknowledged continuity probes needed to reset link
 * @state: current state of link FSM
 * @peer_caps: bitmap describing capabilities of peer node
 * @silent_intv_cnt: # of timer intervals without any reception from peer
 * @priority: current link priority
 * @net_plane: current link network plane ('A' through 'H')
 * @mon_state: cookie with information needed by link monitor
 * @mtu: current maximum packet size for this link
 * @advertised_mtu: advertised own mtu when link is being established
 * @backlogq: queue for messages waiting to be sent
 * @ackers: # of peers that needs to ack each packet before it can be released
 * @acked: # last packet acked by a certain peer. Used for broadcast.
 * @rcv_nxt: next sequence number to expect for inbound messages
 * @inputq: buffer queue for messages to be delivered upwards
 * @namedq: buffer queue for name table messages to be delivered upwards
 * @wakeupq: linked list of wakeup msgs waiting for link congestion to abate
 * @reasm_buf: head of partially reassembled inbound message fragments
 * @stats: collects statistics regarding link activity
 * @session: session to be used by link
 * @snd_nxt_state: next send seq number
 * @rcv_nxt_state: next rcv seq number
 * @in_session: have received ACTIVATE_MSG from peer
 * @active: link is active
 * @if_name: associated interface name
 * @rst_cnt: link reset counter
 * @drop_point: seq number for failover handling (FIXME)
 * @failover_reasm_skb: saved failover msg ptr (FIXME)
 * @failover_deferdq: deferred message queue for failover processing (FIXME)
 * @transmq: the link's transmit queue
 * @backlog: link's backlog by priority (importance)
 * @snd_nxt: next sequence number to be used
 * @rcv_unacked: # messages read by user, but not yet acked back to peer
 * @deferdq: deferred receive queue
 * @window: sliding window size for congestion handling
 * @min_win: minimal send window to be used by link
 * @ssthresh: slow start threshold for congestion handling
 * @max_win: maximal send window to be used by link
 * @cong_acks: congestion acks for congestion avoidance (FIXME)
 * @checkpoint: seq number for congestion window size handling
 * @reasm_tnlmsg: fragmentation/reassembly area for tunnel protocol message
 * @last_gap: last gap ack blocks for bcast (FIXME)
 * @last_ga: ptr to gap ack blocks
 * @bc_rcvlink: the peer specific link used for broadcast reception
 * @bc_sndlink: the namespace global link used for broadcast sending
 * @nack_state: bcast nack state
 * @bc_peer_is_up: peer has acked the bcast init msg
 */
struct tipc_link {
	u32 addr;
	char name[TIPC_MAX_LINK_NAME];
	struct net *net;

	/* Management and link supervision data */
	u16 peer_session;
	u16 session;
	u16 snd_nxt_state;
	u16 rcv_nxt_state;
	u32 peer_bearer_id;
	u32 bearer_id;
	u32 tolerance;
	u32 abort_limit;
	u32 state;
	u16 peer_caps;
	bool in_session;
	bool active;
	u32 silent_intv_cnt;
	char if_name[TIPC_MAX_IF_NAME];
	u32 priority;
	char net_plane;
	struct tipc_mon_state mon_state;
	u16 rst_cnt;

	/* Failover/synch */
	u16 drop_point;
	struct sk_buff *failover_reasm_skb;
	struct sk_buff_head failover_deferdq;

	/* Max packet negotiation */
	u16 mtu;
	u16 advertised_mtu;

	/* Sending */
	struct sk_buff_head transmq;
	struct sk_buff_head backlogq;
	struct {
		u16 len;
		u16 limit;
		struct sk_buff *target_bskb;
	} backlog[5];
	u16 snd_nxt;

	/* Reception */
	u16 rcv_nxt;
	u32 rcv_unacked;
	struct sk_buff_head deferdq;
	struct sk_buff_head *inputq;
	struct sk_buff_head *namedq;

	/* Congestion handling */
	struct sk_buff_head wakeupq;
	u16 window;
	u16 min_win;
	u16 ssthresh;
	u16 max_win;
	u16 cong_acks;
	u16 checkpoint;

	/* Fragmentation/reassembly */
	struct sk_buff *reasm_buf;
	struct sk_buff *reasm_tnlmsg;

	/* Broadcast */
	u16 ackers;
	u16 acked;
	u16 last_gap;
	struct tipc_gap_ack_blks *last_ga;
	struct tipc_link *bc_rcvlink;
	struct tipc_link *bc_sndlink;
	u8 nack_state;
	bool bc_peer_is_up;

	/* Statistics */
	struct tipc_stats stats;
};

/*
 * Error message prefixes
 */
static const char *link_co_err = "Link tunneling error, ";
static const char *link_rst_msg = "Resetting link ";

/* Send states for broadcast NACKs
 */
enum {
	BC_NACK_SND_CONDITIONAL,
	BC_NACK_SND_UNCONDITIONAL,
	BC_NACK_SND_SUPPRESS,
};

#define TIPC_BC_RETR_LIM  (jiffies + msecs_to_jiffies(10))
#define TIPC_UC_RETR_TIME (jiffies + msecs_to_jiffies(1))

/* Link FSM states:
 */
enum {
	LINK_ESTABLISHED     = 0xe,
	LINK_ESTABLISHING    = 0xe  << 4,
	LINK_RESET           = 0x1  << 8,
	LINK_RESETTING       = 0x2  << 12,
	LINK_PEER_RESET      = 0xd  << 16,
	LINK_FAILINGOVER     = 0xf  << 20,
	LINK_SYNCHING        = 0xc  << 24
};

/* Link FSM state checking routines
 */
static int link_is_up(struct tipc_link *l)
{
	return l->state & (LINK_ESTABLISHED | LINK_SYNCHING);
}

static int tipc_link_proto_rcv(struct tipc_link *l, struct sk_buff *skb,
			       struct sk_buff_head *xmitq);
static void tipc_link_build_proto_msg(struct tipc_link *l, int mtyp, bool probe,
				      bool probe_reply, u16 rcvgap,
				      int tolerance, int priority,
				      struct sk_buff_head *xmitq);
static void link_print(struct tipc_link *l, const char *str);
static int tipc_link_build_nack_msg(struct tipc_link *l,
				    struct sk_buff_head *xmitq);
static void tipc_link_build_bc_init_msg(struct tipc_link *l,
					struct sk_buff_head *xmitq);
static u8 __tipc_build_gap_ack_blks(struct tipc_gap_ack_blks *ga,
				    struct tipc_link *l, u8 start_index);
static u16 tipc_build_gap_ack_blks(struct tipc_link *l, struct tipc_msg *hdr);
static int tipc_link_advance_transmq(struct tipc_link *l, struct tipc_link *r,
				     u16 acked, u16 gap,
				     struct tipc_gap_ack_blks *ga,
				     struct sk_buff_head *xmitq,
				     bool *retransmitted, int *rc);
static void tipc_link_update_cwin(struct tipc_link *l, int released,
				  bool retransmitted);
/*
 *  Simple non-static link routines (i.e. referenced outside this file)
 */
bool tipc_link_is_up(struct tipc_link *l)
{
	return link_is_up(l);
}

bool tipc_link_peer_is_down(struct tipc_link *l)
{
	return l->state == LINK_PEER_RESET;
}

bool tipc_link_is_reset(struct tipc_link *l)
{
	return l->state & (LINK_RESET | LINK_FAILINGOVER | LINK_ESTABLISHING);
}

bool tipc_link_is_establishing(struct tipc_link *l)
{
	return l->state == LINK_ESTABLISHING;
}

bool tipc_link_is_synching(struct tipc_link *l)
{
	return l->state == LINK_SYNCHING;
}

bool tipc_link_is_failingover(struct tipc_link *l)
{
	return l->state == LINK_FAILINGOVER;
}

bool tipc_link_is_blocked(struct tipc_link *l)
{
	return l->state & (LINK_RESETTING | LINK_PEER_RESET | LINK_FAILINGOVER);
}

static bool link_is_bc_sndlink(struct tipc_link *l)
{
	return !l->bc_sndlink;
}

static bool link_is_bc_rcvlink(struct tipc_link *l)
{
	return ((l->bc_rcvlink == l) && !link_is_bc_sndlink(l));
}

void tipc_link_set_active(struct tipc_link *l, bool active)
{
	l->active = active;
}

u32 tipc_link_id(struct tipc_link *l)
{
	return l->peer_bearer_id << 16 | l->bearer_id;
}

int tipc_link_min_win(struct tipc_link *l)
{
	return l->min_win;
}

int tipc_link_max_win(struct tipc_link *l)
{
	return l->max_win;
}

int tipc_link_prio(struct tipc_link *l)
{
	return l->priority;
}

unsigned long tipc_link_tolerance(struct tipc_link *l)
{
	return l->tolerance;
}

struct sk_buff_head *tipc_link_inputq(struct tipc_link *l)
{
	return l->inputq;
}

char tipc_link_plane(struct tipc_link *l)
{
	return l->net_plane;
}

struct net *tipc_link_net(struct tipc_link *l)
{
	return l->net;
}

void tipc_link_update_caps(struct tipc_link *l, u16 capabilities)
{
	l->peer_caps = capabilities;
}

void tipc_link_add_bc_peer(struct tipc_link *snd_l,
			   struct tipc_link *uc_l,
			   struct sk_buff_head *xmitq)
{
	struct tipc_link *rcv_l = uc_l->bc_rcvlink;

	snd_l->ackers++;
	rcv_l->acked = snd_l->snd_nxt - 1;
	snd_l->state = LINK_ESTABLISHED;
	tipc_link_build_bc_init_msg(uc_l, xmitq);
}

void tipc_link_remove_bc_peer(struct tipc_link *snd_l,
			      struct tipc_link *rcv_l,
			      struct sk_buff_head *xmitq)
{
	u16 ack = snd_l->snd_nxt - 1;

	snd_l->ackers--;
	rcv_l->bc_peer_is_up = true;
	rcv_l->state = LINK_ESTABLISHED;
	tipc_link_bc_ack_rcv(rcv_l, ack, 0, NULL, xmitq, NULL);
	trace_tipc_link_reset(rcv_l, TIPC_DUMP_ALL, "bclink removed!");
	tipc_link_reset(rcv_l);
	rcv_l->state = LINK_RESET;
	if (!snd_l->ackers) {
		trace_tipc_link_reset(snd_l, TIPC_DUMP_ALL, "zero ackers!");
		tipc_link_reset(snd_l);
		snd_l->state = LINK_RESET;
		__skb_queue_purge(xmitq);
	}
}

int tipc_link_bc_peers(struct tipc_link *l)
{
	return l->ackers;
}

static u16 link_bc_rcv_gap(struct tipc_link *l)
{
	struct sk_buff *skb = skb_peek(&l->deferdq);
	u16 gap = 0;

	if (more(l->snd_nxt, l->rcv_nxt))
		gap = l->snd_nxt - l->rcv_nxt;
	if (skb)
		gap = buf_seqno(skb) - l->rcv_nxt;
	return gap;
}

void tipc_link_set_mtu(struct tipc_link *l, int mtu)
{
	l->mtu = mtu;
}

int tipc_link_mtu(struct tipc_link *l)
{
	return l->mtu;
}

int tipc_link_mss(struct tipc_link *l)
{
#ifdef CONFIG_TIPC_CRYPTO
	return l->mtu - INT_H_SIZE - EMSG_OVERHEAD;
#else
	return l->mtu - INT_H_SIZE;
#endif
}

u16 tipc_link_rcv_nxt(struct tipc_link *l)
{
	return l->rcv_nxt;
}

u16 tipc_link_acked(struct tipc_link *l)
{
	return l->acked;
}

char *tipc_link_name(struct tipc_link *l)
{
	return l->name;
}

u32 tipc_link_state(struct tipc_link *l)
{
	return l->state;
}

/**
 * tipc_link_create - create a new link
 * @net: pointer to associated network namespace
 * @if_name: associated interface name
 * @bearer_id: id (index) of associated bearer
 * @tolerance: link tolerance to be used by link
 * @net_plane: network plane (A,B,c..) this link belongs to
 * @mtu: mtu to be advertised by link
 * @priority: priority to be used by link
 * @min_win: minimal send window to be used by link
 * @max_win: maximal send window to be used by link
 * @session: session to be used by link
 * @peer: node id of peer node
 * @peer_caps: bitmap describing peer node capabilities
 * @bc_sndlink: the namespace global link used for broadcast sending
 * @bc_rcvlink: the peer specific link used for broadcast reception
 * @inputq: queue to put messages ready for delivery
 * @namedq: queue to put binding table update messages ready for delivery
 * @link: return value, pointer to put the created link
 * @self: local unicast link id
 * @peer_id: 128-bit ID of peer
 *
 * Return: true if link was created, otherwise false
 */
bool tipc_link_create(struct net *net, char *if_name, int bearer_id,
		      int tolerance, char net_plane, u32 mtu, int priority,
		      u32 min_win, u32 max_win, u32 session, u32 self,
		      u32 peer, u8 *peer_id, u16 peer_caps,
		      struct tipc_link *bc_sndlink,
		      struct tipc_link *bc_rcvlink,
		      struct sk_buff_head *inputq,
		      struct sk_buff_head *namedq,
		      struct tipc_link **link)
{
	char peer_str[NODE_ID_STR_LEN] = {0,};
	char self_str[NODE_ID_STR_LEN] = {0,};
	struct tipc_link *l;

	l = kzalloc(sizeof(*l), GFP_ATOMIC);
	if (!l)
		return false;
	*link = l;
	l->session = session;

	/* Set link name for unicast links only */
	if (peer_id) {
		tipc_nodeid2string(self_str, tipc_own_id(net));
		if (strlen(self_str) > 16)
			sprintf(self_str, "%x", self);
		tipc_nodeid2string(peer_str, peer_id);
		if (strlen(peer_str) > 16)
			sprintf(peer_str, "%x", peer);
	}
	/* Peer i/f name will be completed by reset/activate message */
	snprintf(l->name, sizeof(l->name), "%s:%s-%s:unknown",
		 self_str, if_name, peer_str);

	strcpy(l->if_name, if_name);
	l->addr = peer;
	l->peer_caps = peer_caps;
	l->net = net;
	l->in_session = false;
	l->bearer_id = bearer_id;
	l->tolerance = tolerance;
	if (bc_rcvlink)
		bc_rcvlink->tolerance = tolerance;
	l->net_plane = net_plane;
	l->advertised_mtu = mtu;
	l->mtu = mtu;
	l->priority = priority;
	tipc_link_set_queue_limits(l, min_win, max_win);
	l->ackers = 1;
	l->bc_sndlink = bc_sndlink;
	l->bc_rcvlink = bc_rcvlink;
	l->inputq = inputq;
	l->namedq = namedq;
	l->state = LINK_RESETTING;
	__skb_queue_head_init(&l->transmq);
	__skb_queue_head_init(&l->backlogq);
	__skb_queue_head_init(&l->deferdq);
	__skb_queue_head_init(&l->failover_deferdq);
	skb_queue_head_init(&l->wakeupq);
	skb_queue_head_init(l->inputq);
	return true;
}

/**
 * tipc_link_bc_create - create new link to be used for broadcast
 * @net: pointer to associated network namespace
 * @mtu: mtu to be used initially if no peers
 * @min_win: minimal send window to be used by link
 * @max_win: maximal send window to be used by link
 * @inputq: queue to put messages ready for delivery
 * @namedq: queue to put binding table update messages ready for delivery
 * @link: return value, pointer to put the created link
 * @ownnode: identity of own node
 * @peer: node id of peer node
 * @peer_id: 128-bit ID of peer
 * @peer_caps: bitmap describing peer node capabilities
 * @bc_sndlink: the namespace global link used for broadcast sending
 *
 * Return: true if link was created, otherwise false
 */
bool tipc_link_bc_create(struct net *net, u32 ownnode, u32 peer, u8 *peer_id,
			 int mtu, u32 min_win, u32 max_win, u16 peer_caps,
			 struct sk_buff_head *inputq,
			 struct sk_buff_head *namedq,
			 struct tipc_link *bc_sndlink,
			 struct tipc_link **link)
{
	struct tipc_link *l;

	if (!tipc_link_create(net, "", MAX_BEARERS, 0, 'Z', mtu, 0, min_win,
			      max_win, 0, ownnode, peer, NULL, peer_caps,
			      bc_sndlink, NULL, inputq, namedq, link))
		return false;

	l = *link;
	if (peer_id) {
		char peer_str[NODE_ID_STR_LEN] = {0,};

		tipc_nodeid2string(peer_str, peer_id);
		if (strlen(peer_str) > 16)
			sprintf(peer_str, "%x", peer);
		/* Broadcast receiver link name: "broadcast-link:<peer>" */
		snprintf(l->name, sizeof(l->name), "%s:%s", tipc_bclink_name,
			 peer_str);
	} else {
		strcpy(l->name, tipc_bclink_name);
	}
	trace_tipc_link_reset(l, TIPC_DUMP_ALL, "bclink created!");
	tipc_link_reset(l);
	l->state = LINK_RESET;
	l->ackers = 0;
	l->bc_rcvlink = l;

	/* Broadcast send link is always up */
	if (link_is_bc_sndlink(l))
		l->state = LINK_ESTABLISHED;

	/* Disable replicast if even a single peer doesn't support it */
	if (link_is_bc_rcvlink(l) && !(peer_caps & TIPC_BCAST_RCAST))
		tipc_bcast_toggle_rcast(net, false);

	return true;
}

/**
 * tipc_link_fsm_evt - link finite state machine
 * @l: pointer to link
 * @evt: state machine event to be processed
 */
int tipc_link_fsm_evt(struct tipc_link *l, int evt)
{
	int rc = 0;
	int old_state = l->state;

	switch (l->state) {
	case LINK_RESETTING:
		switch (evt) {
		case LINK_PEER_RESET_EVT:
			l->state = LINK_PEER_RESET;
			break;
		case LINK_RESET_EVT:
			l->state = LINK_RESET;
			break;
		case LINK_FAILURE_EVT:
		case LINK_FAILOVER_BEGIN_EVT:
		case LINK_ESTABLISH_EVT:
		case LINK_FAILOVER_END_EVT:
		case LINK_SYNCH_BEGIN_EVT:
		case LINK_SYNCH_END_EVT:
		default:
			goto illegal_evt;
		}
		break;
	case LINK_RESET:
		switch (evt) {
		case LINK_PEER_RESET_EVT:
			l->state = LINK_ESTABLISHING;
			break;
		case LINK_FAILOVER_BEGIN_EVT:
			l->state = LINK_FAILINGOVER;
			break;
		case LINK_FAILURE_EVT:
		case LINK_RESET_EVT:
		case LINK_ESTABLISH_EVT:
		case LINK_FAILOVER_END_EVT:
			break;
		case LINK_SYNCH_BEGIN_EVT:
		case LINK_SYNCH_END_EVT:
		default:
			goto illegal_evt;
		}
		break;
	case LINK_PEER_RESET:
		switch (evt) {
		case LINK_RESET_EVT:
			l->state = LINK_ESTABLISHING;
			break;
		case LINK_PEER_RESET_EVT:
		case LINK_ESTABLISH_EVT:
		case LINK_FAILURE_EVT:
			break;
		case LINK_SYNCH_BEGIN_EVT:
		case LINK_SYNCH_END_EVT:
		case LINK_FAILOVER_BEGIN_EVT:
		case LINK_FAILOVER_END_EVT:
		default:
			goto illegal_evt;
		}
		break;
	case LINK_FAILINGOVER:
		switch (evt) {
		case LINK_FAILOVER_END_EVT:
			l->state = LINK_RESET;
			break;
		case LINK_PEER_RESET_EVT:
		case LINK_RESET_EVT:
		case LINK_ESTABLISH_EVT:
		case LINK_FAILURE_EVT:
			break;
		case LINK_FAILOVER_BEGIN_EVT:
		case LINK_SYNCH_BEGIN_EVT:
		case LINK_SYNCH_END_EVT:
		default:
			goto illegal_evt;
		}
		break;
	case LINK_ESTABLISHING:
		switch (evt) {
		case LINK_ESTABLISH_EVT:
			l->state = LINK_ESTABLISHED;
			break;
		case LINK_FAILOVER_BEGIN_EVT:
			l->state = LINK_FAILINGOVER;
			break;
		case LINK_RESET_EVT:
			l->state = LINK_RESET;
			break;
		case LINK_FAILURE_EVT:
		case LINK_PEER_RESET_EVT:
		case LINK_SYNCH_BEGIN_EVT:
		case LINK_FAILOVER_END_EVT:
			break;
		case LINK_SYNCH_END_EVT:
		default:
			goto illegal_evt;
		}
		break;
	case LINK_ESTABLISHED:
		switch (evt) {
		case LINK_PEER_RESET_EVT:
			l->state = LINK_PEER_RESET;
			rc |= TIPC_LINK_DOWN_EVT;
			break;
		case LINK_FAILURE_EVT:
			l->state = LINK_RESETTING;
			rc |= TIPC_LINK_DOWN_EVT;
			break;
		case LINK_RESET_EVT:
			l->state = LINK_RESET;
			break;
		case LINK_ESTABLISH_EVT:
		case LINK_SYNCH_END_EVT:
			break;
		case LINK_SYNCH_BEGIN_EVT:
			l->state = LINK_SYNCHING;
			break;
		case LINK_FAILOVER_BEGIN_EVT:
		case LINK_FAILOVER_END_EVT:
		default:
			goto illegal_evt;
		}
		break;
	case LINK_SYNCHING:
		switch (evt) {
		case LINK_PEER_RESET_EVT:
			l->state = LINK_PEER_RESET;
			rc |= TIPC_LINK_DOWN_EVT;
			break;
		case LINK_FAILURE_EVT:
			l->state = LINK_RESETTING;
			rc |= TIPC_LINK_DOWN_EVT;
			break;
		case LINK_RESET_EVT:
			l->state = LINK_RESET;
			break;
		case LINK_ESTABLISH_EVT:
		case LINK_SYNCH_BEGIN_EVT:
			break;
		case LINK_SYNCH_END_EVT:
			l->state = LINK_ESTABLISHED;
			break;
		case LINK_FAILOVER_BEGIN_EVT:
		case LINK_FAILOVER_END_EVT:
		default:
			goto illegal_evt;
		}
		break;
	default:
		pr_err("Unknown FSM state %x in %s\n", l->state, l->name);
	}
	trace_tipc_link_fsm(l->name, old_state, l->state, evt);
	return rc;
illegal_evt:
	pr_err("Illegal FSM event %x in state %x on link %s\n",
	       evt, l->state, l->name);
	trace_tipc_link_fsm(l->name, old_state, l->state, evt);
	return rc;
}

/* link_profile_stats - update statistical profiling of traffic
 */
static void link_profile_stats(struct tipc_link *l)
{
	struct sk_buff *skb;
	struct tipc_msg *msg;
	int length;

	/* Update counters used in statistical profiling of send traffic */
	l->stats.accu_queue_sz += skb_queue_len(&l->transmq);
	l->stats.queue_sz_counts++;

	skb = skb_peek(&l->transmq);
	if (!skb)
		return;
	msg = buf_msg(skb);
	length = msg_size(msg);

	if (msg_user(msg) == MSG_FRAGMENTER) {
		if (msg_type(msg) != FIRST_FRAGMENT)
			return;
		length = msg_size(msg_inner_hdr(msg));
	}
	l->stats.msg_lengths_total += length;
	l->stats.msg_length_counts++;
	if (length <= 64)
		l->stats.msg_length_profile[0]++;
	else if (length <= 256)
		l->stats.msg_length_profile[1]++;
	else if (length <= 1024)
		l->stats.msg_length_profile[2]++;
	else if (length <= 4096)
		l->stats.msg_length_profile[3]++;
	else if (length <= 16384)
		l->stats.msg_length_profile[4]++;
	else if (length <= 32768)
		l->stats.msg_length_profile[5]++;
	else
		l->stats.msg_length_profile[6]++;
}

/**
 * tipc_link_too_silent - check if link is "too silent"
 * @l: tipc link to be checked
 *
 * Return: true if the link 'silent_intv_cnt' is about to reach the
 * 'abort_limit' value, otherwise false
 */
bool tipc_link_too_silent(struct tipc_link *l)
{
	return (l->silent_intv_cnt + 2 > l->abort_limit);
}

/* tipc_link_timeout - perform periodic task as instructed from node timeout
 */
int tipc_link_timeout(struct tipc_link *l, struct sk_buff_head *xmitq)
{
	int mtyp = 0;
	int rc = 0;
	bool state = false;
	bool probe = false;
	bool setup = false;
	u16 bc_snt = l->bc_sndlink->snd_nxt - 1;
	u16 bc_acked = l->bc_rcvlink->acked;
	struct tipc_mon_state *mstate = &l->mon_state;

	trace_tipc_link_timeout(l, TIPC_DUMP_NONE, " ");
	trace_tipc_link_too_silent(l, TIPC_DUMP_ALL, " ");
	switch (l->state) {
	case LINK_ESTABLISHED:
	case LINK_SYNCHING:
		mtyp = STATE_MSG;
		link_profile_stats(l);
		tipc_mon_get_state(l->net, l->addr, mstate, l->bearer_id);
		if (mstate->reset || (l->silent_intv_cnt > l->abort_limit))
			return tipc_link_fsm_evt(l, LINK_FAILURE_EVT);
		state = bc_acked != bc_snt;
		state |= l->bc_rcvlink->rcv_unacked;
		state |= l->rcv_unacked;
		state |= !skb_queue_empty(&l->transmq);
		probe = mstate->probing;
		probe |= l->silent_intv_cnt;
		if (probe || mstate->monitoring)
			l->silent_intv_cnt++;
		probe |= !skb_queue_empty(&l->deferdq);
		if (l->snd_nxt == l->checkpoint) {
			tipc_link_update_cwin(l, 0, 0);
			probe = true;
		}
		l->checkpoint = l->snd_nxt;
		break;
	case LINK_RESET:
		setup = l->rst_cnt++ <= 4;
		setup |= !(l->rst_cnt % 16);
		mtyp = RESET_MSG;
		break;
	case LINK_ESTABLISHING:
		setup = true;
		mtyp = ACTIVATE_MSG;
		break;
	case LINK_PEER_RESET:
	case LINK_RESETTING:
	case LINK_FAILINGOVER:
		break;
	default:
		break;
	}

	if (state || probe || setup)
		tipc_link_build_proto_msg(l, mtyp, probe, 0, 0, 0, 0, xmitq);

	return rc;
}

/**
 * link_schedule_user - schedule a message sender for wakeup after congestion
 * @l: congested link
 * @hdr: header of message that is being sent
 * Create pseudo msg to send back to user when congestion abates
 */
static int link_schedule_user(struct tipc_link *l, struct tipc_msg *hdr)
{
	u32 dnode = tipc_own_addr(l->net);
	u32 dport = msg_origport(hdr);
	struct sk_buff *skb;

	/* Create and schedule wakeup pseudo message */
	skb = tipc_msg_create(SOCK_WAKEUP, 0, INT_H_SIZE, 0,
			      dnode, l->addr, dport, 0, 0);
	if (!skb)
		return -ENOBUFS;
	msg_set_dest_droppable(buf_msg(skb), true);
	TIPC_SKB_CB(skb)->chain_imp = msg_importance(hdr);
	skb_queue_tail(&l->wakeupq, skb);
	l->stats.link_congs++;
	trace_tipc_link_conges(l, TIPC_DUMP_ALL, "wakeup scheduled!");
	return -ELINKCONG;
}

/**
 * link_prepare_wakeup - prepare users for wakeup after congestion
 * @l: congested link
 * Wake up a number of waiting users, as permitted by available space
 * in the send queue
 */
static void link_prepare_wakeup(struct tipc_link *l)
{
	struct sk_buff_head *wakeupq = &l->wakeupq;
	struct sk_buff_head *inputq = l->inputq;
	struct sk_buff *skb, *tmp;
	struct sk_buff_head tmpq;
	int avail[5] = {0,};
	int imp = 0;

	__skb_queue_head_init(&tmpq);

	for (; imp <= TIPC_SYSTEM_IMPORTANCE; imp++)
		avail[imp] = l->backlog[imp].limit - l->backlog[imp].len;

	skb_queue_walk_safe(wakeupq, skb, tmp) {
		imp = TIPC_SKB_CB(skb)->chain_imp;
		if (avail[imp] <= 0)
			continue;
		avail[imp]--;
		__skb_unlink(skb, wakeupq);
		__skb_queue_tail(&tmpq, skb);
	}

	spin_lock_bh(&inputq->lock);
	skb_queue_splice_tail(&tmpq, inputq);
	spin_unlock_bh(&inputq->lock);

}

/**
 * tipc_link_set_skb_retransmit_time - set the time at which retransmission of
 *                                     the given skb should be next attempted
 * @skb: skb to set a future retransmission time for
 * @l: link the skb will be transmitted on
 */
static void tipc_link_set_skb_retransmit_time(struct sk_buff *skb,
					      struct tipc_link *l)
{
	if (link_is_bc_sndlink(l))
		TIPC_SKB_CB(skb)->nxt_retr = TIPC_BC_RETR_LIM;
	else
		TIPC_SKB_CB(skb)->nxt_retr = TIPC_UC_RETR_TIME;
}

void tipc_link_reset(struct tipc_link *l)
{
	struct sk_buff_head list;
	u32 imp;

	__skb_queue_head_init(&list);

	l->in_session = false;
	/* Force re-synch of peer session number before establishing */
	l->peer_session--;
	l->session++;
	l->mtu = l->advertised_mtu;

	spin_lock_bh(&l->wakeupq.lock);
	skb_queue_splice_init(&l->wakeupq, &list);
	spin_unlock_bh(&l->wakeupq.lock);

	spin_lock_bh(&l->inputq->lock);
	skb_queue_splice_init(&list, l->inputq);
	spin_unlock_bh(&l->inputq->lock);

	__skb_queue_purge(&l->transmq);
	__skb_queue_purge(&l->deferdq);
	__skb_queue_purge(&l->backlogq);
	__skb_queue_purge(&l->failover_deferdq);
	for (imp = 0; imp <= TIPC_SYSTEM_IMPORTANCE; imp++) {
		l->backlog[imp].len = 0;
		l->backlog[imp].target_bskb = NULL;
	}
	kfree_skb(l->reasm_buf);
	kfree_skb(l->reasm_tnlmsg);
	kfree_skb(l->failover_reasm_skb);
	l->reasm_buf = NULL;
	l->reasm_tnlmsg = NULL;
	l->failover_reasm_skb = NULL;
	l->rcv_unacked = 0;
	l->snd_nxt = 1;
	l->rcv_nxt = 1;
	l->snd_nxt_state = 1;
	l->rcv_nxt_state = 1;
	l->acked = 0;
	l->last_gap = 0;
	kfree(l->last_ga);
	l->last_ga = NULL;
	l->silent_intv_cnt = 0;
	l->rst_cnt = 0;
	l->bc_peer_is_up = false;
	memset(&l->mon_state, 0, sizeof(l->mon_state));
	tipc_link_reset_stats(l);
}

/**
 * tipc_link_xmit(): enqueue buffer list according to queue situation
 * @l: link to use
 * @list: chain of buffers containing message
 * @xmitq: returned list of packets to be sent by caller
 *
 * Consumes the buffer chain.
 * Messages at TIPC_SYSTEM_IMPORTANCE are always accepted
 * Return: 0 if success, or errno: -ELINKCONG, -EMSGSIZE or -ENOBUFS
 */
int tipc_link_xmit(struct tipc_link *l, struct sk_buff_head *list,
		   struct sk_buff_head *xmitq)
{
	struct sk_buff_head *backlogq = &l->backlogq;
	struct sk_buff_head *transmq = &l->transmq;
	struct sk_buff *skb, *_skb;
	u16 bc_ack = l->bc_rcvlink->rcv_nxt - 1;
	u16 ack = l->rcv_nxt - 1;
	u16 seqno = l->snd_nxt;
	int pkt_cnt = skb_queue_len(list);
	unsigned int mss = tipc_link_mss(l);
	unsigned int cwin = l->window;
	unsigned int mtu = l->mtu;
	struct tipc_msg *hdr;
	bool new_bundle;
	int rc = 0;
	int imp;

	if (pkt_cnt <= 0)
		return 0;

	hdr = buf_msg(skb_peek(list));
	if (unlikely(msg_size(hdr) > mtu)) {
		pr_warn("Too large msg, purging xmit list %d %d %d %d %d!\n",
			skb_queue_len(list), msg_user(hdr),
			msg_type(hdr), msg_size(hdr), mtu);
		__skb_queue_purge(list);
		return -EMSGSIZE;
	}

	imp = msg_importance(hdr);
	/* Allow oversubscription of one data msg per source at congestion */
	if (unlikely(l->backlog[imp].len >= l->backlog[imp].limit)) {
		if (imp == TIPC_SYSTEM_IMPORTANCE) {
			pr_warn("%s<%s>, link overflow", link_rst_msg, l->name);
			return -ENOBUFS;
		}
		rc = link_schedule_user(l, hdr);
	}

	if (pkt_cnt > 1) {
		l->stats.sent_fragmented++;
		l->stats.sent_fragments += pkt_cnt;
	}

	/* Prepare each packet for sending, and add to relevant queue: */
	while ((skb = __skb_dequeue(list))) {
		if (likely(skb_queue_len(transmq) < cwin)) {
			hdr = buf_msg(skb);
			msg_set_seqno(hdr, seqno);
			msg_set_ack(hdr, ack);
			msg_set_bcast_ack(hdr, bc_ack);
			_skb = skb_clone(skb, GFP_ATOMIC);
			if (!_skb) {
				kfree_skb(skb);
				__skb_queue_purge(list);
				return -ENOBUFS;
			}
			__skb_queue_tail(transmq, skb);
			tipc_link_set_skb_retransmit_time(skb, l);
			__skb_queue_tail(xmitq, _skb);
			TIPC_SKB_CB(skb)->ackers = l->ackers;
			l->rcv_unacked = 0;
			l->stats.sent_pkts++;
			seqno++;
			continue;
		}
		if (tipc_msg_try_bundle(l->backlog[imp].target_bskb, &skb,
					mss, l->addr, &new_bundle)) {
			if (skb) {
				/* Keep a ref. to the skb for next try */
				l->backlog[imp].target_bskb = skb;
				l->backlog[imp].len++;
				__skb_queue_tail(backlogq, skb);
			} else {
				if (new_bundle) {
					l->stats.sent_bundles++;
					l->stats.sent_bundled++;
				}
				l->stats.sent_bundled++;
			}
			continue;
		}
		l->backlog[imp].target_bskb = NULL;
		l->backlog[imp].len += (1 + skb_queue_len(list));
		__skb_queue_tail(backlogq, skb);
		skb_queue_splice_tail_init(list, backlogq);
	}
	l->snd_nxt = seqno;
	return rc;
}

static void tipc_link_update_cwin(struct tipc_link *l, int released,
				  bool retransmitted)
{
	int bklog_len = skb_queue_len(&l->backlogq);
	struct sk_buff_head *txq = &l->transmq;
	int txq_len = skb_queue_len(txq);
	u16 cwin = l->window;

	/* Enter fast recovery */
	if (unlikely(retransmitted)) {
		l->ssthresh = max_t(u16, l->window / 2, 300);
		l->window = min_t(u16, l->ssthresh, l->window);
		return;
	}
	/* Enter slow start */
	if (unlikely(!released)) {
		l->ssthresh = max_t(u16, l->window / 2, 300);
		l->window = l->min_win;
		return;
	}
	/* Don't increase window if no pressure on the transmit queue */
	if (txq_len + bklog_len < cwin)
		return;

	/* Don't increase window if there are holes the transmit queue */
	if (txq_len && l->snd_nxt - buf_seqno(skb_peek(txq)) != txq_len)
		return;

	l->cong_acks += released;

	/* Slow start  */
	if (cwin <= l->ssthresh) {
		l->window = min_t(u16, cwin + released, l->max_win);
		return;
	}
	/* Congestion avoidance */
	if (l->cong_acks < cwin)
		return;
	l->window = min_t(u16, ++cwin, l->max_win);
	l->cong_acks = 0;
}

static void tipc_link_advance_backlog(struct tipc_link *l,
				      struct sk_buff_head *xmitq)
{
	u16 bc_ack = l->bc_rcvlink->rcv_nxt - 1;
	struct sk_buff_head *txq = &l->transmq;
	struct sk_buff *skb, *_skb;
	u16 ack = l->rcv_nxt - 1;
	u16 seqno = l->snd_nxt;
	struct tipc_msg *hdr;
	u16 cwin = l->window;
	u32 imp;

	while (skb_queue_len(txq) < cwin) {
		skb = skb_peek(&l->backlogq);
		if (!skb)
			break;
		_skb = skb_clone(skb, GFP_ATOMIC);
		if (!_skb)
			break;
		__skb_dequeue(&l->backlogq);
		hdr = buf_msg(skb);
		imp = msg_importance(hdr);
		l->backlog[imp].len--;
		if (unlikely(skb == l->backlog[imp].target_bskb))
			l->backlog[imp].target_bskb = NULL;
		__skb_queue_tail(&l->transmq, skb);
		tipc_link_set_skb_retransmit_time(skb, l);

		__skb_queue_tail(xmitq, _skb);
		TIPC_SKB_CB(skb)->ackers = l->ackers;
		msg_set_seqno(hdr, seqno);
		msg_set_ack(hdr, ack);
		msg_set_bcast_ack(hdr, bc_ack);
		l->rcv_unacked = 0;
		l->stats.sent_pkts++;
		seqno++;
	}
	l->snd_nxt = seqno;
}

/**
 * link_retransmit_failure() - Detect repeated retransmit failures
 * @l: tipc link sender
 * @r: tipc link receiver (= l in case of unicast)
 * @rc: returned code
 *
 * Return: true if the repeated retransmit failures happens, otherwise
 * false
 */
static bool link_retransmit_failure(struct tipc_link *l, struct tipc_link *r,
				    int *rc)
{
	struct sk_buff *skb = skb_peek(&l->transmq);
	struct tipc_msg *hdr;

	if (!skb)
		return false;

	if (!TIPC_SKB_CB(skb)->retr_cnt)
		return false;

	if (!time_after(jiffies, TIPC_SKB_CB(skb)->retr_stamp +
			msecs_to_jiffies(r->tolerance * 10)))
		return false;

	hdr = buf_msg(skb);
	if (link_is_bc_sndlink(l) && !less(r->acked, msg_seqno(hdr)))
		return false;

	pr_warn("Retransmission failure on link <%s>\n", l->name);
	link_print(l, "State of link ");
	pr_info("Failed msg: usr %u, typ %u, len %u, err %u\n",
		msg_user(hdr), msg_type(hdr), msg_size(hdr), msg_errcode(hdr));
	pr_info("sqno %u, prev: %x, dest: %x\n",
		msg_seqno(hdr), msg_prevnode(hdr), msg_destnode(hdr));
	pr_info("retr_stamp %d, retr_cnt %d\n",
		jiffies_to_msecs(TIPC_SKB_CB(skb)->retr_stamp),
		TIPC_SKB_CB(skb)->retr_cnt);

	trace_tipc_list_dump(&l->transmq, true, "retrans failure!");
	trace_tipc_link_dump(l, TIPC_DUMP_NONE, "retrans failure!");
	trace_tipc_link_dump(r, TIPC_DUMP_NONE, "retrans failure!");

	if (link_is_bc_sndlink(l)) {
		r->state = LINK_RESET;
		*rc |= TIPC_LINK_DOWN_EVT;
	} else {
		*rc |= tipc_link_fsm_evt(l, LINK_FAILURE_EVT);
	}

	return true;
}

/* tipc_data_input - deliver data and name distr msgs to upper layer
 *
 * Consumes buffer if message is of right type
 * Node lock must be held
 */
static bool tipc_data_input(struct tipc_link *l, struct sk_buff *skb,
			    struct sk_buff_head *inputq)
{
	struct sk_buff_head *mc_inputq = l->bc_rcvlink->inputq;
	struct tipc_msg *hdr = buf_msg(skb);

	switch (msg_user(hdr)) {
	case TIPC_LOW_IMPORTANCE:
	case TIPC_MEDIUM_IMPORTANCE:
	case TIPC_HIGH_IMPORTANCE:
	case TIPC_CRITICAL_IMPORTANCE:
		if (unlikely(msg_in_group(hdr) || msg_mcast(hdr))) {
			skb_queue_tail(mc_inputq, skb);
			return true;
		}
		fallthrough;
	case CONN_MANAGER:
		skb_queue_tail(inputq, skb);
		return true;
	case GROUP_PROTOCOL:
		skb_queue_tail(mc_inputq, skb);
		return true;
	case NAME_DISTRIBUTOR:
		l->bc_rcvlink->state = LINK_ESTABLISHED;
		skb_queue_tail(l->namedq, skb);
		return true;
	case MSG_BUNDLER:
	case TUNNEL_PROTOCOL:
	case MSG_FRAGMENTER:
	case BCAST_PROTOCOL:
		return false;
#ifdef CONFIG_TIPC_CRYPTO
	case MSG_CRYPTO:
		if (sysctl_tipc_key_exchange_enabled &&
		    TIPC_SKB_CB(skb)->decrypted) {
			tipc_crypto_msg_rcv(l->net, skb);
			return true;
		}
		fallthrough;
#endif
	default:
		pr_warn("Dropping received illegal msg type\n");
		kfree_skb(skb);
		return true;
	}
}

/* tipc_link_input - process packet that has passed link protocol check
 *
 * Consumes buffer
 */
static int tipc_link_input(struct tipc_link *l, struct sk_buff *skb,
			   struct sk_buff_head *inputq,
			   struct sk_buff **reasm_skb)
{
	struct tipc_msg *hdr = buf_msg(skb);
	struct sk_buff *iskb;
	struct sk_buff_head tmpq;
	int usr = msg_user(hdr);
	int pos = 0;

	if (usr == MSG_BUNDLER) {
		skb_queue_head_init(&tmpq);
		l->stats.recv_bundles++;
		l->stats.recv_bundled += msg_msgcnt(hdr);
		while (tipc_msg_extract(skb, &iskb, &pos))
			tipc_data_input(l, iskb, &tmpq);
		tipc_skb_queue_splice_tail(&tmpq, inputq);
		return 0;
	} else if (usr == MSG_FRAGMENTER) {
		l->stats.recv_fragments++;
		if (tipc_buf_append(reasm_skb, &skb)) {
			l->stats.recv_fragmented++;
			tipc_data_input(l, skb, inputq);
		} else if (!*reasm_skb && !link_is_bc_rcvlink(l)) {
			pr_warn_ratelimited("Unable to build fragment list\n");
			return tipc_link_fsm_evt(l, LINK_FAILURE_EVT);
		}
		return 0;
	} else if (usr == BCAST_PROTOCOL) {
		tipc_bcast_lock(l->net);
		tipc_link_bc_init_rcv(l->bc_rcvlink, hdr);
		tipc_bcast_unlock(l->net);
	}

	kfree_skb(skb);
	return 0;
}

/* tipc_link_tnl_rcv() - receive TUNNEL_PROTOCOL message, drop or process the
 *			 inner message along with the ones in the old link's
 *			 deferdq
 * @l: tunnel link
 * @skb: TUNNEL_PROTOCOL message
 * @inputq: queue to put messages ready for delivery
 */
static int tipc_link_tnl_rcv(struct tipc_link *l, struct sk_buff *skb,
			     struct sk_buff_head *inputq)
{
	struct sk_buff **reasm_skb = &l->failover_reasm_skb;
	struct sk_buff **reasm_tnlmsg = &l->reasm_tnlmsg;
	struct sk_buff_head *fdefq = &l->failover_deferdq;
	struct tipc_msg *hdr = buf_msg(skb);
	struct sk_buff *iskb;
	int ipos = 0;
	int rc = 0;
	u16 seqno;

	if (msg_type(hdr) == SYNCH_MSG) {
		kfree_skb(skb);
		return 0;
	}

	/* Not a fragment? */
	if (likely(!msg_nof_fragms(hdr))) {
		if (unlikely(!tipc_msg_extract(skb, &iskb, &ipos))) {
			pr_warn_ratelimited("Unable to extract msg, defq: %d\n",
					    skb_queue_len(fdefq));
			return 0;
		}
		kfree_skb(skb);
	} else {
		/* Set fragment type for buf_append */
		if (msg_fragm_no(hdr) == 1)
			msg_set_type(hdr, FIRST_FRAGMENT);
		else if (msg_fragm_no(hdr) < msg_nof_fragms(hdr))
			msg_set_type(hdr, FRAGMENT);
		else
			msg_set_type(hdr, LAST_FRAGMENT);

		if (!tipc_buf_append(reasm_tnlmsg, &skb)) {
			/* Successful but non-complete reassembly? */
			if (*reasm_tnlmsg || link_is_bc_rcvlink(l))
				return 0;
			pr_warn_ratelimited("Unable to reassemble tunnel msg\n");
			return tipc_link_fsm_evt(l, LINK_FAILURE_EVT);
		}
		iskb = skb;
	}

	do {
		seqno = buf_seqno(iskb);
		if (unlikely(less(seqno, l->drop_point))) {
			kfree_skb(iskb);
			continue;
		}
		if (unlikely(seqno != l->drop_point)) {
			__tipc_skb_queue_sorted(fdefq, seqno, iskb);
			continue;
		}

		l->drop_point++;
		if (!tipc_data_input(l, iskb, inputq))
			rc |= tipc_link_input(l, iskb, inputq, reasm_skb);
		if (unlikely(rc))
			break;
	} while ((iskb = __tipc_skb_dequeue(fdefq, l->drop_point)));

	return rc;
}

/**
 * tipc_get_gap_ack_blks - get Gap ACK blocks from PROTOCOL/STATE_MSG
 * @ga: returned pointer to the Gap ACK blocks if any
 * @l: the tipc link
 * @hdr: the PROTOCOL/STATE_MSG header
 * @uc: desired Gap ACK blocks type, i.e. unicast (= 1) or broadcast (= 0)
 *
 * Return: the total Gap ACK blocks size
 */
u16 tipc_get_gap_ack_blks(struct tipc_gap_ack_blks **ga, struct tipc_link *l,
			  struct tipc_msg *hdr, bool uc)
{
	struct tipc_gap_ack_blks *p;
	u16 sz = 0;

	/* Does peer support the Gap ACK blocks feature? */
	if (l->peer_caps & TIPC_GAP_ACK_BLOCK) {
		p = (struct tipc_gap_ack_blks *)msg_data(hdr);
		sz = ntohs(p->len);
		/* Sanity check */
		if (sz == struct_size(p, gacks, size_add(p->ugack_cnt, p->bgack_cnt))) {
			/* Good, check if the desired type exists */
			if ((uc && p->ugack_cnt) || (!uc && p->bgack_cnt))
				goto ok;
		/* Backward compatible: peer might not support bc, but uc? */
		} else if (uc && sz == struct_size(p, gacks, p->ugack_cnt)) {
			if (p->ugack_cnt) {
				p->bgack_cnt = 0;
				goto ok;
			}
		}
	}
	/* Other cases: ignore! */
	p = NULL;

ok:
	*ga = p;
	return sz;
}

static u8 __tipc_build_gap_ack_blks(struct tipc_gap_ack_blks *ga,
				    struct tipc_link *l, u8 start_index)
{
	struct tipc_gap_ack *gacks = &ga->gacks[start_index];
	struct sk_buff *skb = skb_peek(&l->deferdq);
	u16 expect, seqno = 0;
	u8 n = 0;

	if (!skb)
		return 0;

	expect = buf_seqno(skb);
	skb_queue_walk(&l->deferdq, skb) {
		seqno = buf_seqno(skb);
		if (unlikely(more(seqno, expect))) {
			gacks[n].ack = htons(expect - 1);
			gacks[n].gap = htons(seqno - expect);
			if (++n >= MAX_GAP_ACK_BLKS / 2) {
				pr_info_ratelimited("Gacks on %s: %d, ql: %d!\n",
						    l->name, n,
						    skb_queue_len(&l->deferdq));
				return n;
			}
		} else if (unlikely(less(seqno, expect))) {
			pr_warn("Unexpected skb in deferdq!\n");
			continue;
		}
		expect = seqno + 1;
	}

	/* last block */
	gacks[n].ack = htons(seqno);
	gacks[n].gap = 0;
	n++;
	return n;
}

/* tipc_build_gap_ack_blks - build Gap ACK blocks
 * @l: tipc unicast link
 * @hdr: the tipc message buffer to store the Gap ACK blocks after built
 *
 * The function builds Gap ACK blocks for both the unicast & broadcast receiver
 * links of a certain peer, the buffer after built has the network data format
 * as found at the struct tipc_gap_ack_blks definition.
 *
 * returns the actual allocated memory size
 */
static u16 tipc_build_gap_ack_blks(struct tipc_link *l, struct tipc_msg *hdr)
{
	struct tipc_link *bcl = l->bc_rcvlink;
	struct tipc_gap_ack_blks *ga;
	u16 len;

	ga = (struct tipc_gap_ack_blks *)msg_data(hdr);

	/* Start with broadcast link first */
	tipc_bcast_lock(bcl->net);
	msg_set_bcast_ack(hdr, bcl->rcv_nxt - 1);
	msg_set_bc_gap(hdr, link_bc_rcv_gap(bcl));
	ga->bgack_cnt = __tipc_build_gap_ack_blks(ga, bcl, 0);
	tipc_bcast_unlock(bcl->net);

	/* Now for unicast link, but an explicit NACK only (???) */
	ga->ugack_cnt = (msg_seq_gap(hdr)) ?
			__tipc_build_gap_ack_blks(ga, l, ga->bgack_cnt) : 0;

	/* Total len */
	len = struct_size(ga, gacks, size_add(ga->bgack_cnt, ga->ugack_cnt));
	ga->len = htons(len);
	return len;
}

/* tipc_link_advance_transmq - advance TIPC link transmq queue by releasing
 *			       acked packets, also doing retransmissions if
 *			       gaps found
 * @l: tipc link with transmq queue to be advanced
 * @r: tipc link "receiver" i.e. in case of broadcast (= "l" if unicast)
 * @acked: seqno of last packet acked by peer without any gaps before
 * @gap: # of gap packets
 * @ga: buffer pointer to Gap ACK blocks from peer
 * @xmitq: queue for accumulating the retransmitted packets if any
 * @retransmitted: returned boolean value if a retransmission is really issued
 * @rc: returned code e.g. TIPC_LINK_DOWN_EVT if a repeated retransmit failures
 *      happens (- unlikely case)
 *
 * Return: the number of packets released from the link transmq
 */
static int tipc_link_advance_transmq(struct tipc_link *l, struct tipc_link *r,
				     u16 acked, u16 gap,
				     struct tipc_gap_ack_blks *ga,
				     struct sk_buff_head *xmitq,
				     bool *retransmitted, int *rc)
{
	struct tipc_gap_ack_blks *last_ga = r->last_ga, *this_ga = NULL;
	struct tipc_gap_ack *gacks = NULL;
	struct sk_buff *skb, *_skb, *tmp;
	struct tipc_msg *hdr;
	u32 qlen = skb_queue_len(&l->transmq);
	u16 nacked = acked, ngap = gap, gack_cnt = 0;
	u16 bc_ack = l->bc_rcvlink->rcv_nxt - 1;
	u16 ack = l->rcv_nxt - 1;
	u16 seqno, n = 0;
	u16 end = r->acked, start = end, offset = r->last_gap;
	u16 si = (last_ga) ? last_ga->start_index : 0;
	bool is_uc = !link_is_bc_sndlink(l);
	bool bc_has_acked = false;

	trace_tipc_link_retrans(r, acked + 1, acked + gap, &l->transmq);

	/* Determine Gap ACK blocks if any for the particular link */
	if (ga && is_uc) {
		/* Get the Gap ACKs, uc part */
		gack_cnt = ga->ugack_cnt;
		gacks = &ga->gacks[ga->bgack_cnt];
	} else if (ga) {
		/* Copy the Gap ACKs, bc part, for later renewal if needed */
		this_ga = kmemdup(ga, struct_size(ga, gacks, ga->bgack_cnt),
				  GFP_ATOMIC);
		if (likely(this_ga)) {
			this_ga->start_index = 0;
			/* Start with the bc Gap ACKs */
			gack_cnt = this_ga->bgack_cnt;
			gacks = &this_ga->gacks[0];
		} else {
			/* Hmm, we can get in trouble..., simply ignore it */
			pr_warn_ratelimited("Ignoring bc Gap ACKs, no memory\n");
		}
	}

	/* Advance the link transmq */
	skb_queue_walk_safe(&l->transmq, skb, tmp) {
		seqno = buf_seqno(skb);

next_gap_ack:
		if (less_eq(seqno, nacked)) {
			if (is_uc)
				goto release;
			/* Skip packets peer has already acked */
			if (!more(seqno, r->acked))
				continue;
			/* Get the next of last Gap ACK blocks */
			while (more(seqno, end)) {
				if (!last_ga || si >= last_ga->bgack_cnt)
					break;
				start = end + offset + 1;
				end = ntohs(last_ga->gacks[si].ack);
				offset = ntohs(last_ga->gacks[si].gap);
				si++;
				WARN_ONCE(more(start, end) ||
					  (!offset &&
					   si < last_ga->bgack_cnt) ||
					  si > MAX_GAP_ACK_BLKS,
					  "Corrupted Gap ACK: %d %d %d %d %d\n",
					  start, end, offset, si,
					  last_ga->bgack_cnt);
			}
			/* Check against the last Gap ACK block */
			if (tipc_in_range(seqno, start, end))
				continue;
			/* Update/release the packet peer is acking */
			bc_has_acked = true;
			if (--TIPC_SKB_CB(skb)->ackers)
				continue;
release:
			/* release skb */
			__skb_unlink(skb, &l->transmq);
			kfree_skb(skb);
		} else if (less_eq(seqno, nacked + ngap)) {
			/* First gap: check if repeated retrans failures? */
			if (unlikely(seqno == acked + 1 &&
				     link_retransmit_failure(l, r, rc))) {
				/* Ignore this bc Gap ACKs if any */
				kfree(this_ga);
				this_ga = NULL;
				break;
			}
			/* retransmit skb if unrestricted*/
			if (time_before(jiffies, TIPC_SKB_CB(skb)->nxt_retr))
				continue;
			tipc_link_set_skb_retransmit_time(skb, l);
			_skb = pskb_copy(skb, GFP_ATOMIC);
			if (!_skb)
				continue;
			hdr = buf_msg(_skb);
			msg_set_ack(hdr, ack);
			msg_set_bcast_ack(hdr, bc_ack);
			_skb->priority = TC_PRIO_CONTROL;
			__skb_queue_tail(xmitq, _skb);
			l->stats.retransmitted++;
			if (!is_uc)
				r->stats.retransmitted++;
			*retransmitted = true;
			/* Increase actual retrans counter & mark first time */
			if (!TIPC_SKB_CB(skb)->retr_cnt++)
				TIPC_SKB_CB(skb)->retr_stamp = jiffies;
		} else {
			/* retry with Gap ACK blocks if any */
			if (n >= gack_cnt)
				break;
			nacked = ntohs(gacks[n].ack);
			ngap = ntohs(gacks[n].gap);
			n++;
			goto next_gap_ack;
		}
	}

	/* Renew last Gap ACK blocks for bc if needed */
	if (bc_has_acked) {
		if (this_ga) {
			kfree(last_ga);
			r->last_ga = this_ga;
			r->last_gap = gap;
		} else if (last_ga) {
			if (less(acked, start)) {
				si--;
				offset = start - acked - 1;
			} else if (less(acked, end)) {
				acked = end;
			}
			if (si < last_ga->bgack_cnt) {
				last_ga->start_index = si;
				r->last_gap = offset;
			} else {
				kfree(last_ga);
				r->last_ga = NULL;
				r->last_gap = 0;
			}
		} else {
			r->last_gap = 0;
		}
		r->acked = acked;
	} else {
		kfree(this_ga);
	}

	return qlen - skb_queue_len(&l->transmq);
}

/* tipc_link_build_state_msg: prepare link state message for transmission
 *
 * Note that sending of broadcast ack is coordinated among nodes, to reduce
 * risk of ack storms towards the sender
 */
int tipc_link_build_state_msg(struct tipc_link *l, struct sk_buff_head *xmitq)
{
	if (!l)
		return 0;

	/* Broadcast ACK must be sent via a unicast link => defer to caller */
	if (link_is_bc_rcvlink(l)) {
		if (((l->rcv_nxt ^ tipc_own_addr(l->net)) & 0xf) != 0xf)
			return 0;
		l->rcv_unacked = 0;

		/* Use snd_nxt to store peer's snd_nxt in broadcast rcv link */
		l->snd_nxt = l->rcv_nxt;
		return TIPC_LINK_SND_STATE;
	}
	/* Unicast ACK */
	l->rcv_unacked = 0;
	l->stats.sent_acks++;
	tipc_link_build_proto_msg(l, STATE_MSG, 0, 0, 0, 0, 0, xmitq);
	return 0;
}

/* tipc_link_build_reset_msg: prepare link RESET or ACTIVATE message
 */
void tipc_link_build_reset_msg(struct tipc_link *l, struct sk_buff_head *xmitq)
{
	int mtyp = RESET_MSG;
	struct sk_buff *skb;

	if (l->state == LINK_ESTABLISHING)
		mtyp = ACTIVATE_MSG;

	tipc_link_build_proto_msg(l, mtyp, 0, 0, 0, 0, 0, xmitq);

	/* Inform peer that this endpoint is going down if applicable */
	skb = skb_peek_tail(xmitq);
	if (skb && (l->state == LINK_RESET))
		msg_set_peer_stopping(buf_msg(skb), 1);
}

/* tipc_link_build_nack_msg: prepare link nack message for transmission
 * Note that sending of broadcast NACK is coordinated among nodes, to
 * reduce the risk of NACK storms towards the sender
 */
static int tipc_link_build_nack_msg(struct tipc_link *l,
				    struct sk_buff_head *xmitq)
{
	u32 def_cnt = ++l->stats.deferred_recv;
	struct sk_buff_head *dfq = &l->deferdq;
	u32 defq_len = skb_queue_len(dfq);
	int match1, match2;

	if (link_is_bc_rcvlink(l)) {
		match1 = def_cnt & 0xf;
		match2 = tipc_own_addr(l->net) & 0xf;
		if (match1 == match2)
			return TIPC_LINK_SND_STATE;
		return 0;
	}

	if (defq_len >= 3 && !((defq_len - 3) % 16)) {
		u16 rcvgap = buf_seqno(skb_peek(dfq)) - l->rcv_nxt;

		tipc_link_build_proto_msg(l, STATE_MSG, 0, 0,
					  rcvgap, 0, 0, xmitq);
	}
	return 0;
}

/* tipc_link_rcv - process TIPC packets/messages arriving from off-node
 * @l: the link that should handle the message
 * @skb: TIPC packet
 * @xmitq: queue to place packets to be sent after this call
 */
int tipc_link_rcv(struct tipc_link *l, struct sk_buff *skb,
		  struct sk_buff_head *xmitq)
{
	struct sk_buff_head *defq = &l->deferdq;
	struct tipc_msg *hdr = buf_msg(skb);
	u16 seqno, rcv_nxt, win_lim;
	int released = 0;
	int rc = 0;

	/* Verify and update link state */
	if (unlikely(msg_user(hdr) == LINK_PROTOCOL))
		return tipc_link_proto_rcv(l, skb, xmitq);

	/* Don't send probe at next timeout expiration */
	l->silent_intv_cnt = 0;

	do {
		hdr = buf_msg(skb);
		seqno = msg_seqno(hdr);
		rcv_nxt = l->rcv_nxt;
		win_lim = rcv_nxt + TIPC_MAX_LINK_WIN;

		if (unlikely(!link_is_up(l))) {
			if (l->state == LINK_ESTABLISHING)
				rc = TIPC_LINK_UP_EVT;
			kfree_skb(skb);
			break;
		}

		/* Drop if outside receive window */
		if (unlikely(less(seqno, rcv_nxt) || more(seqno, win_lim))) {
			l->stats.duplicates++;
			kfree_skb(skb);
			break;
		}
		released += tipc_link_advance_transmq(l, l, msg_ack(hdr), 0,
						      NULL, NULL, NULL, NULL);

		/* Defer delivery if sequence gap */
		if (unlikely(seqno != rcv_nxt)) {
			if (!__tipc_skb_queue_sorted(defq, seqno, skb))
				l->stats.duplicates++;
			rc |= tipc_link_build_nack_msg(l, xmitq);
			break;
		}

		/* Deliver packet */
		l->rcv_nxt++;
		l->stats.recv_pkts++;

		if (unlikely(msg_user(hdr) == TUNNEL_PROTOCOL))
			rc |= tipc_link_tnl_rcv(l, skb, l->inputq);
		else if (!tipc_data_input(l, skb, l->inputq))
			rc |= tipc_link_input(l, skb, l->inputq, &l->reasm_buf);
		if (unlikely(++l->rcv_unacked >= TIPC_MIN_LINK_WIN))
			rc |= tipc_link_build_state_msg(l, xmitq);
		if (unlikely(rc & ~TIPC_LINK_SND_STATE))
			break;
	} while ((skb = __tipc_skb_dequeue(defq, l->rcv_nxt)));

	/* Forward queues and wake up waiting users */
	if (released) {
		tipc_link_update_cwin(l, released, 0);
		tipc_link_advance_backlog(l, xmitq);
		if (unlikely(!skb_queue_empty(&l->wakeupq)))
			link_prepare_wakeup(l);
	}
	return rc;
}

static void tipc_link_build_proto_msg(struct tipc_link *l, int mtyp, bool probe,
				      bool probe_reply, u16 rcvgap,
				      int tolerance, int priority,
				      struct sk_buff_head *xmitq)
{
	struct tipc_mon_state *mstate = &l->mon_state;
	struct sk_buff_head *dfq = &l->deferdq;
	struct tipc_link *bcl = l->bc_rcvlink;
	struct tipc_msg *hdr;
	struct sk_buff *skb;
	bool node_up = link_is_up(bcl);
	u16 glen = 0, bc_rcvgap = 0;
	int dlen = 0;
	void *data;

	/* Don't send protocol message during reset or link failover */
	if (tipc_link_is_blocked(l))
		return;

	if (!tipc_link_is_up(l) && (mtyp == STATE_MSG))
		return;

	if ((probe || probe_reply) && !skb_queue_empty(dfq))
		rcvgap = buf_seqno(skb_peek(dfq)) - l->rcv_nxt;

	skb = tipc_msg_create(LINK_PROTOCOL, mtyp, INT_H_SIZE,
			      tipc_max_domain_size + MAX_GAP_ACK_BLKS_SZ,
			      l->addr, tipc_own_addr(l->net), 0, 0, 0);
	if (!skb)
		return;

	hdr = buf_msg(skb);
	data = msg_data(hdr);
	msg_set_session(hdr, l->session);
	msg_set_bearer_id(hdr, l->bearer_id);
	msg_set_net_plane(hdr, l->net_plane);
	msg_set_next_sent(hdr, l->snd_nxt);
	msg_set_ack(hdr, l->rcv_nxt - 1);
	msg_set_bcast_ack(hdr, bcl->rcv_nxt - 1);
	msg_set_bc_ack_invalid(hdr, !node_up);
	msg_set_last_bcast(hdr, l->bc_sndlink->snd_nxt - 1);
	msg_set_link_tolerance(hdr, tolerance);
	msg_set_linkprio(hdr, priority);
	msg_set_redundant_link(hdr, node_up);
	msg_set_seq_gap(hdr, 0);
	msg_set_seqno(hdr, l->snd_nxt + U16_MAX / 2);

	if (mtyp == STATE_MSG) {
		if (l->peer_caps & TIPC_LINK_PROTO_SEQNO)
			msg_set_seqno(hdr, l->snd_nxt_state++);
		msg_set_seq_gap(hdr, rcvgap);
		bc_rcvgap = link_bc_rcv_gap(bcl);
		msg_set_bc_gap(hdr, bc_rcvgap);
		msg_set_probe(hdr, probe);
		msg_set_is_keepalive(hdr, probe || probe_reply);
		if (l->peer_caps & TIPC_GAP_ACK_BLOCK)
			glen = tipc_build_gap_ack_blks(l, hdr);
		tipc_mon_prep(l->net, data + glen, &dlen, mstate, l->bearer_id);
		msg_set_size(hdr, INT_H_SIZE + glen + dlen);
		skb_trim(skb, INT_H_SIZE + glen + dlen);
		l->stats.sent_states++;
		l->rcv_unacked = 0;
	} else {
		/* RESET_MSG or ACTIVATE_MSG */
		if (mtyp == ACTIVATE_MSG) {
			msg_set_dest_session_valid(hdr, 1);
			msg_set_dest_session(hdr, l->peer_session);
		}
		msg_set_max_pkt(hdr, l->advertised_mtu);
		strcpy(data, l->if_name);
		msg_set_size(hdr, INT_H_SIZE + TIPC_MAX_IF_NAME);
		skb_trim(skb, INT_H_SIZE + TIPC_MAX_IF_NAME);
	}
	if (probe)
		l->stats.sent_probes++;
	if (rcvgap)
		l->stats.sent_nacks++;
	if (bc_rcvgap)
		bcl->stats.sent_nacks++;
	skb->priority = TC_PRIO_CONTROL;
	__skb_queue_tail(xmitq, skb);
	trace_tipc_proto_build(skb, false, l->name);
}

void tipc_link_create_dummy_tnl_msg(struct tipc_link *l,
				    struct sk_buff_head *xmitq)
{
	u32 onode = tipc_own_addr(l->net);
	struct tipc_msg *hdr, *ihdr;
	struct sk_buff_head tnlq;
	struct sk_buff *skb;
	u32 dnode = l->addr;

	__skb_queue_head_init(&tnlq);
	skb = tipc_msg_create(TUNNEL_PROTOCOL, FAILOVER_MSG,
			      INT_H_SIZE, BASIC_H_SIZE,
			      dnode, onode, 0, 0, 0);
	if (!skb) {
		pr_warn("%sunable to create tunnel packet\n", link_co_err);
		return;
	}

	hdr = buf_msg(skb);
	msg_set_msgcnt(hdr, 1);
	msg_set_bearer_id(hdr, l->peer_bearer_id);

	ihdr = (struct tipc_msg *)msg_data(hdr);
	tipc_msg_init(onode, ihdr, TIPC_LOW_IMPORTANCE, TIPC_DIRECT_MSG,
		      BASIC_H_SIZE, dnode);
	msg_set_errcode(ihdr, TIPC_ERR_NO_PORT);
	__skb_queue_tail(&tnlq, skb);
	tipc_link_xmit(l, &tnlq, xmitq);
}

/* tipc_link_tnl_prepare(): prepare and return a list of tunnel packets
 * with contents of the link's transmit and backlog queues.
 */
void tipc_link_tnl_prepare(struct tipc_link *l, struct tipc_link *tnl,
			   int mtyp, struct sk_buff_head *xmitq)
{
	struct sk_buff_head *fdefq = &tnl->failover_deferdq;
	struct sk_buff *skb, *tnlskb;
	struct tipc_msg *hdr, tnlhdr;
	struct sk_buff_head *queue = &l->transmq;
	struct sk_buff_head tmpxq, tnlq, frags;
	u16 pktlen, pktcnt, seqno = l->snd_nxt;
	bool pktcnt_need_update = false;
	u16 syncpt;
	int rc;

	if (!tnl)
		return;

	__skb_queue_head_init(&tnlq);
	/* Link Synching:
	 * From now on, send only one single ("dummy") SYNCH message
	 * to peer. The SYNCH message does not contain any data, just
	 * a header conveying the synch point to the peer.
	 */
	if (mtyp == SYNCH_MSG && (tnl->peer_caps & TIPC_TUNNEL_ENHANCED)) {
		tnlskb = tipc_msg_create(TUNNEL_PROTOCOL, SYNCH_MSG,
					 INT_H_SIZE, 0, l->addr,
					 tipc_own_addr(l->net),
					 0, 0, 0);
		if (!tnlskb) {
			pr_warn("%sunable to create dummy SYNCH_MSG\n",
				link_co_err);
			return;
		}

		hdr = buf_msg(tnlskb);
		syncpt = l->snd_nxt + skb_queue_len(&l->backlogq) - 1;
		msg_set_syncpt(hdr, syncpt);
		msg_set_bearer_id(hdr, l->peer_bearer_id);
		__skb_queue_tail(&tnlq, tnlskb);
		tipc_link_xmit(tnl, &tnlq, xmitq);
		return;
	}

	__skb_queue_head_init(&tmpxq);
	__skb_queue_head_init(&frags);
	/* At least one packet required for safe algorithm => add dummy */
	skb = tipc_msg_create(TIPC_LOW_IMPORTANCE, TIPC_DIRECT_MSG,
			      BASIC_H_SIZE, 0, l->addr, tipc_own_addr(l->net),
			      0, 0, TIPC_ERR_NO_PORT);
	if (!skb) {
		pr_warn("%sunable to create tunnel packet\n", link_co_err);
		return;
	}
	__skb_queue_tail(&tnlq, skb);
	tipc_link_xmit(l, &tnlq, &tmpxq);
	__skb_queue_purge(&tmpxq);

	/* Initialize reusable tunnel packet header */
	tipc_msg_init(tipc_own_addr(l->net), &tnlhdr, TUNNEL_PROTOCOL,
		      mtyp, INT_H_SIZE, l->addr);
	if (mtyp == SYNCH_MSG)
		pktcnt = l->snd_nxt - buf_seqno(skb_peek(&l->transmq));
	else
		pktcnt = skb_queue_len(&l->transmq);
	pktcnt += skb_queue_len(&l->backlogq);
	msg_set_msgcnt(&tnlhdr, pktcnt);
	msg_set_bearer_id(&tnlhdr, l->peer_bearer_id);
tnl:
	/* Wrap each packet into a tunnel packet */
	skb_queue_walk(queue, skb) {
		hdr = buf_msg(skb);
		if (queue == &l->backlogq)
			msg_set_seqno(hdr, seqno++);
		pktlen = msg_size(hdr);

		/* Tunnel link MTU is not large enough? This could be
		 * due to:
		 * 1) Link MTU has just changed or set differently;
		 * 2) Or FAILOVER on the top of a SYNCH message
		 *
		 * The 2nd case should not happen if peer supports
		 * TIPC_TUNNEL_ENHANCED
		 */
		if (pktlen > tnl->mtu - INT_H_SIZE) {
			if (mtyp == FAILOVER_MSG &&
			    (tnl->peer_caps & TIPC_TUNNEL_ENHANCED)) {
				rc = tipc_msg_fragment(skb, &tnlhdr, tnl->mtu,
						       &frags);
				if (rc) {
					pr_warn("%sunable to frag msg: rc %d\n",
						link_co_err, rc);
					return;
				}
				pktcnt += skb_queue_len(&frags) - 1;
				pktcnt_need_update = true;
				skb_queue_splice_tail_init(&frags, &tnlq);
				continue;
			}
			/* Unluckily, peer doesn't have TIPC_TUNNEL_ENHANCED
			 * => Just warn it and return!
			 */
			pr_warn_ratelimited("%stoo large msg <%d, %d>: %d!\n",
					    link_co_err, msg_user(hdr),
					    msg_type(hdr), msg_size(hdr));
			return;
		}

		msg_set_size(&tnlhdr, pktlen + INT_H_SIZE);
		tnlskb = tipc_buf_acquire(pktlen + INT_H_SIZE, GFP_ATOMIC);
		if (!tnlskb) {
			pr_warn("%sunable to send packet\n", link_co_err);
			return;
		}
		skb_copy_to_linear_data(tnlskb, &tnlhdr, INT_H_SIZE);
		skb_copy_to_linear_data_offset(tnlskb, INT_H_SIZE, hdr, pktlen);
		__skb_queue_tail(&tnlq, tnlskb);
	}
	if (queue != &l->backlogq) {
		queue = &l->backlogq;
		goto tnl;
	}

	if (pktcnt_need_update)
		skb_queue_walk(&tnlq, skb) {
			hdr = buf_msg(skb);
			msg_set_msgcnt(hdr, pktcnt);
		}

	tipc_link_xmit(tnl, &tnlq, xmitq);

	if (mtyp == FAILOVER_MSG) {
		tnl->drop_point = l->rcv_nxt;
		tnl->failover_reasm_skb = l->reasm_buf;
		l->reasm_buf = NULL;

		/* Failover the link's deferdq */
		if (unlikely(!skb_queue_empty(fdefq))) {
			pr_warn("Link failover deferdq not empty: %d!\n",
				skb_queue_len(fdefq));
			__skb_queue_purge(fdefq);
		}
		skb_queue_splice_init(&l->deferdq, fdefq);
	}
}

/**
 * tipc_link_failover_prepare() - prepare tnl for link failover
 *
 * This is a special version of the precursor - tipc_link_tnl_prepare(),
 * see the tipc_node_link_failover() for details
 *
 * @l: failover link
 * @tnl: tunnel link
 * @xmitq: queue for messages to be xmited
 */
void tipc_link_failover_prepare(struct tipc_link *l, struct tipc_link *tnl,
				struct sk_buff_head *xmitq)
{
	struct sk_buff_head *fdefq = &tnl->failover_deferdq;

	tipc_link_create_dummy_tnl_msg(tnl, xmitq);

	/* This failover link endpoint was never established before,
	 * so it has not received anything from peer.
	 * Otherwise, it must be a normal failover situation or the
	 * node has entered SELF_DOWN_PEER_LEAVING and both peer nodes
	 * would have to start over from scratch instead.
	 */
	tnl->drop_point = 1;
	tnl->failover_reasm_skb = NULL;

	/* Initiate the link's failover deferdq */
	if (unlikely(!skb_queue_empty(fdefq))) {
		pr_warn("Link failover deferdq not empty: %d!\n",
			skb_queue_len(fdefq));
		__skb_queue_purge(fdefq);
	}
}

/* tipc_link_validate_msg(): validate message against current link state
 * Returns true if message should be accepted, otherwise false
 */
bool tipc_link_validate_msg(struct tipc_link *l, struct tipc_msg *hdr)
{
	u16 curr_session = l->peer_session;
	u16 session = msg_session(hdr);
	int mtyp = msg_type(hdr);

	if (msg_user(hdr) != LINK_PROTOCOL)
		return true;

	switch (mtyp) {
	case RESET_MSG:
		if (!l->in_session)
			return true;
		/* Accept only RESET with new session number */
		return more(session, curr_session);
	case ACTIVATE_MSG:
		if (!l->in_session)
			return true;
		/* Accept only ACTIVATE with new or current session number */
		return !less(session, curr_session);
	case STATE_MSG:
		/* Accept only STATE with current session number */
		if (!l->in_session)
			return false;
		if (session != curr_session)
			return false;
		/* Extra sanity check */
		if (!link_is_up(l) && msg_ack(hdr))
			return false;
		if (!(l->peer_caps & TIPC_LINK_PROTO_SEQNO))
			return true;
		/* Accept only STATE with new sequence number */
		return !less(msg_seqno(hdr), l->rcv_nxt_state);
	default:
		return false;
	}
}

/* tipc_link_proto_rcv(): receive link level protocol message :
 * Note that network plane id propagates through the network, and may
 * change at any time. The node with lowest numerical id determines
 * network plane
 */
static int tipc_link_proto_rcv(struct tipc_link *l, struct sk_buff *skb,
			       struct sk_buff_head *xmitq)
{
	struct tipc_msg *hdr = buf_msg(skb);
	struct tipc_gap_ack_blks *ga = NULL;
	bool reply = msg_probe(hdr), retransmitted = false;
	u32 dlen = msg_data_sz(hdr), glen = 0, msg_max;
	u16 peers_snd_nxt =  msg_next_sent(hdr);
	u16 peers_tol = msg_link_tolerance(hdr);
	u16 peers_prio = msg_linkprio(hdr);
	u16 gap = msg_seq_gap(hdr);
	u16 ack = msg_ack(hdr);
	u16 rcv_nxt = l->rcv_nxt;
	u16 rcvgap = 0;
	int mtyp = msg_type(hdr);
	int rc = 0, released;
	char *if_name;
	void *data;

	trace_tipc_proto_rcv(skb, false, l->name);

	if (dlen > U16_MAX)
		goto exit;

	if (tipc_link_is_blocked(l) || !xmitq)
		goto exit;

	if (tipc_own_addr(l->net) > msg_prevnode(hdr))
		l->net_plane = msg_net_plane(hdr);

	if (skb_linearize(skb))
		goto exit;

	hdr = buf_msg(skb);
	data = msg_data(hdr);

	if (!tipc_link_validate_msg(l, hdr)) {
		trace_tipc_skb_dump(skb, false, "PROTO invalid (1)!");
		trace_tipc_link_dump(l, TIPC_DUMP_NONE, "PROTO invalid (1)!");
		goto exit;
	}

	switch (mtyp) {
	case RESET_MSG:
	case ACTIVATE_MSG:
		msg_max = msg_max_pkt(hdr);
		if (msg_max < tipc_bearer_min_mtu(l->net, l->bearer_id))
			break;
		/* Complete own link name with peer's interface name */
		if_name =  strrchr(l->name, ':') + 1;
		if (sizeof(l->name) - (if_name - l->name) <= TIPC_MAX_IF_NAME)
			break;
		if (msg_data_sz(hdr) < TIPC_MAX_IF_NAME)
			break;
		strncpy(if_name, data, TIPC_MAX_IF_NAME);

		/* Update own tolerance if peer indicates a non-zero value */
		if (tipc_in_range(peers_tol, TIPC_MIN_LINK_TOL, TIPC_MAX_LINK_TOL)) {
			l->tolerance = peers_tol;
			l->bc_rcvlink->tolerance = peers_tol;
		}
		/* Update own priority if peer's priority is higher */
		if (tipc_in_range(peers_prio, l->priority + 1, TIPC_MAX_LINK_PRI))
			l->priority = peers_prio;

		/* If peer is going down we want full re-establish cycle */
		if (msg_peer_stopping(hdr)) {
			rc = tipc_link_fsm_evt(l, LINK_FAILURE_EVT);
			break;
		}

		/* If this endpoint was re-created while peer was ESTABLISHING
		 * it doesn't know current session number. Force re-synch.
		 */
		if (mtyp == ACTIVATE_MSG && msg_dest_session_valid(hdr) &&
		    l->session != msg_dest_session(hdr)) {
			if (less(l->session, msg_dest_session(hdr)))
				l->session = msg_dest_session(hdr) + 1;
			break;
		}

		/* ACTIVATE_MSG serves as PEER_RESET if link is already down */
		if (mtyp == RESET_MSG || !link_is_up(l))
			rc = tipc_link_fsm_evt(l, LINK_PEER_RESET_EVT);

		/* ACTIVATE_MSG takes up link if it was already locally reset */
		if (mtyp == ACTIVATE_MSG && l->state == LINK_ESTABLISHING)
			rc = TIPC_LINK_UP_EVT;

		l->peer_session = msg_session(hdr);
		l->in_session = true;
		l->peer_bearer_id = msg_bearer_id(hdr);
		if (l->mtu > msg_max)
			l->mtu = msg_max;
		break;

	case STATE_MSG:
		/* Validate Gap ACK blocks, drop if invalid */
		glen = tipc_get_gap_ack_blks(&ga, l, hdr, true);
		if (glen > dlen)
			break;

		l->rcv_nxt_state = msg_seqno(hdr) + 1;

		/* Update own tolerance if peer indicates a non-zero value */
		if (tipc_in_range(peers_tol, TIPC_MIN_LINK_TOL, TIPC_MAX_LINK_TOL)) {
			l->tolerance = peers_tol;
			l->bc_rcvlink->tolerance = peers_tol;
		}
		/* Update own prio if peer indicates a different value */
		if ((peers_prio != l->priority) &&
		    tipc_in_range(peers_prio, 1, TIPC_MAX_LINK_PRI)) {
			l->priority = peers_prio;
			rc = tipc_link_fsm_evt(l, LINK_FAILURE_EVT);
		}

		l->silent_intv_cnt = 0;
		l->stats.recv_states++;
		if (msg_probe(hdr))
			l->stats.recv_probes++;

		if (!link_is_up(l)) {
			if (l->state == LINK_ESTABLISHING)
				rc = TIPC_LINK_UP_EVT;
			break;
		}

		tipc_mon_rcv(l->net, data + glen, dlen - glen, l->addr,
			     &l->mon_state, l->bearer_id);

		/* Send NACK if peer has sent pkts we haven't received yet */
		if ((reply || msg_is_keepalive(hdr)) &&
		    more(peers_snd_nxt, rcv_nxt) &&
		    !tipc_link_is_synching(l) &&
		    skb_queue_empty(&l->deferdq))
			rcvgap = peers_snd_nxt - l->rcv_nxt;
		if (rcvgap || reply)
			tipc_link_build_proto_msg(l, STATE_MSG, 0, reply,
						  rcvgap, 0, 0, xmitq);

		released = tipc_link_advance_transmq(l, l, ack, gap, ga, xmitq,
						     &retransmitted, &rc);
		if (gap)
			l->stats.recv_nacks++;
		if (released || retransmitted)
			tipc_link_update_cwin(l, released, retransmitted);
		if (released)
			tipc_link_advance_backlog(l, xmitq);
		if (unlikely(!skb_queue_empty(&l->wakeupq)))
			link_prepare_wakeup(l);
	}
exit:
	kfree_skb(skb);
	return rc;
}

/* tipc_link_build_bc_proto_msg() - create broadcast protocol message
 */
static bool tipc_link_build_bc_proto_msg(struct tipc_link *l, bool bcast,
					 u16 peers_snd_nxt,
					 struct sk_buff_head *xmitq)
{
	struct sk_buff *skb;
	struct tipc_msg *hdr;
	struct sk_buff *dfrd_skb = skb_peek(&l->deferdq);
	u16 ack = l->rcv_nxt - 1;
	u16 gap_to = peers_snd_nxt - 1;

	skb = tipc_msg_create(BCAST_PROTOCOL, STATE_MSG, INT_H_SIZE,
			      0, l->addr, tipc_own_addr(l->net), 0, 0, 0);
	if (!skb)
		return false;
	hdr = buf_msg(skb);
	msg_set_last_bcast(hdr, l->bc_sndlink->snd_nxt - 1);
	msg_set_bcast_ack(hdr, ack);
	msg_set_bcgap_after(hdr, ack);
	if (dfrd_skb)
		gap_to = buf_seqno(dfrd_skb) - 1;
	msg_set_bcgap_to(hdr, gap_to);
	msg_set_non_seq(hdr, bcast);
	__skb_queue_tail(xmitq, skb);
	return true;
}

/* tipc_link_build_bc_init_msg() - synchronize broadcast link endpoints.
 *
 * Give a newly added peer node the sequence number where it should
 * start receiving and acking broadcast packets.
 */
static void tipc_link_build_bc_init_msg(struct tipc_link *l,
					struct sk_buff_head *xmitq)
{
	struct sk_buff_head list;

	__skb_queue_head_init(&list);
	if (!tipc_link_build_bc_proto_msg(l->bc_rcvlink, false, 0, &list))
		return;
	msg_set_bc_ack_invalid(buf_msg(skb_peek(&list)), true);
	tipc_link_xmit(l, &list, xmitq);
}

/* tipc_link_bc_init_rcv - receive initial broadcast synch data from peer
 */
void tipc_link_bc_init_rcv(struct tipc_link *l, struct tipc_msg *hdr)
{
	int mtyp = msg_type(hdr);
	u16 peers_snd_nxt = msg_bc_snd_nxt(hdr);

	if (link_is_up(l))
		return;

	if (msg_user(hdr) == BCAST_PROTOCOL) {
		l->rcv_nxt = peers_snd_nxt;
		l->state = LINK_ESTABLISHED;
		return;
	}

	if (l->peer_caps & TIPC_BCAST_SYNCH)
		return;

	if (msg_peer_node_is_up(hdr))
		return;

	/* Compatibility: accept older, less safe initial synch data */
	if ((mtyp == RESET_MSG) || (mtyp == ACTIVATE_MSG))
		l->rcv_nxt = peers_snd_nxt;
}

/* tipc_link_bc_sync_rcv - update rcv link according to peer's send state
 */
int tipc_link_bc_sync_rcv(struct tipc_link *l, struct tipc_msg *hdr,
			  struct sk_buff_head *xmitq)
{
	u16 peers_snd_nxt = msg_bc_snd_nxt(hdr);
	int rc = 0;

	if (!link_is_up(l))
		return rc;

	if (!msg_peer_node_is_up(hdr))
		return rc;

	/* Open when peer acknowledges our bcast init msg (pkt #1) */
	if (msg_ack(hdr))
		l->bc_peer_is_up = true;

	if (!l->bc_peer_is_up)
		return rc;

	/* Ignore if peers_snd_nxt goes beyond receive window */
	if (more(peers_snd_nxt, l->rcv_nxt + l->window))
		return rc;

	l->snd_nxt = peers_snd_nxt;
	if (link_bc_rcv_gap(l))
		rc |= TIPC_LINK_SND_STATE;

	/* Return now if sender supports nack via STATE messages */
	if (l->peer_caps & TIPC_BCAST_STATE_NACK)
		return rc;

	/* Otherwise, be backwards compatible */

	if (!more(peers_snd_nxt, l->rcv_nxt)) {
		l->nack_state = BC_NACK_SND_CONDITIONAL;
		return 0;
	}

	/* Don't NACK if one was recently sent or peeked */
	if (l->nack_state == BC_NACK_SND_SUPPRESS) {
		l->nack_state = BC_NACK_SND_UNCONDITIONAL;
		return 0;
	}

	/* Conditionally delay NACK sending until next synch rcv */
	if (l->nack_state == BC_NACK_SND_CONDITIONAL) {
		l->nack_state = BC_NACK_SND_UNCONDITIONAL;
		if ((peers_snd_nxt - l->rcv_nxt) < TIPC_MIN_LINK_WIN)
			return 0;
	}

	/* Send NACK now but suppress next one */
	tipc_link_build_bc_proto_msg(l, true, peers_snd_nxt, xmitq);
	l->nack_state = BC_NACK_SND_SUPPRESS;
	return 0;
}

int tipc_link_bc_ack_rcv(struct tipc_link *r, u16 acked, u16 gap,
			 struct tipc_gap_ack_blks *ga,
			 struct sk_buff_head *xmitq,
			 struct sk_buff_head *retrq)
{
	struct tipc_link *l = r->bc_sndlink;
	bool unused = false;
	int rc = 0;

	if (!link_is_up(r) || !r->bc_peer_is_up)
		return 0;

	if (gap) {
		l->stats.recv_nacks++;
		r->stats.recv_nacks++;
	}

	if (less(acked, r->acked) || (acked == r->acked && !gap && !ga))
		return 0;

	trace_tipc_link_bc_ack(r, acked, gap, &l->transmq);
	tipc_link_advance_transmq(l, r, acked, gap, ga, retrq, &unused, &rc);

	tipc_link_advance_backlog(l, xmitq);
	if (unlikely(!skb_queue_empty(&l->wakeupq)))
		link_prepare_wakeup(l);

	return rc;
}

/* tipc_link_bc_nack_rcv(): receive broadcast nack message
 * This function is here for backwards compatibility, since
 * no BCAST_PROTOCOL/STATE messages occur from TIPC v2.5.
 */
int tipc_link_bc_nack_rcv(struct tipc_link *l, struct sk_buff *skb,
			  struct sk_buff_head *xmitq)
{
	struct tipc_msg *hdr = buf_msg(skb);
	u32 dnode = msg_destnode(hdr);
	int mtyp = msg_type(hdr);
	u16 acked = msg_bcast_ack(hdr);
	u16 from = acked + 1;
	u16 to = msg_bcgap_to(hdr);
	u16 peers_snd_nxt = to + 1;
	int rc = 0;

	kfree_skb(skb);

	if (!tipc_link_is_up(l) || !l->bc_peer_is_up)
		return 0;

	if (mtyp != STATE_MSG)
		return 0;

	if (dnode == tipc_own_addr(l->net)) {
		rc = tipc_link_bc_ack_rcv(l, acked, to - acked, NULL, xmitq,
					  xmitq);
		l->stats.recv_nacks++;
		return rc;
	}

	/* Msg for other node => suppress own NACK at next sync if applicable */
	if (more(peers_snd_nxt, l->rcv_nxt) && !less(l->rcv_nxt, from))
		l->nack_state = BC_NACK_SND_SUPPRESS;

	return 0;
}

void tipc_link_set_queue_limits(struct tipc_link *l, u32 min_win, u32 max_win)
{
	int max_bulk = TIPC_MAX_PUBL / (l->mtu / ITEM_SIZE);

	l->min_win = min_win;
	l->ssthresh = max_win;
	l->max_win = max_win;
	l->window = min_win;
	l->backlog[TIPC_LOW_IMPORTANCE].limit      = min_win * 2;
	l->backlog[TIPC_MEDIUM_IMPORTANCE].limit   = min_win * 4;
	l->backlog[TIPC_HIGH_IMPORTANCE].limit     = min_win * 6;
	l->backlog[TIPC_CRITICAL_IMPORTANCE].limit = min_win * 8;
	l->backlog[TIPC_SYSTEM_IMPORTANCE].limit   = max_bulk;
}

/**
 * tipc_link_reset_stats - reset link statistics
 * @l: pointer to link
 */
void tipc_link_reset_stats(struct tipc_link *l)
{
	memset(&l->stats, 0, sizeof(l->stats));
}

static void link_print(struct tipc_link *l, const char *str)
{
	struct sk_buff *hskb = skb_peek(&l->transmq);
	u16 head = hskb ? msg_seqno(buf_msg(hskb)) : l->snd_nxt - 1;
	u16 tail = l->snd_nxt - 1;

	pr_info("%s Link <%s> state %x\n", str, l->name, l->state);
	pr_info("XMTQ: %u [%u-%u], BKLGQ: %u, SNDNX: %u, RCVNX: %u\n",
		skb_queue_len(&l->transmq), head, tail,
		skb_queue_len(&l->backlogq), l->snd_nxt, l->rcv_nxt);
}

/* Parse and validate nested (link) properties valid for media, bearer and link
 */
int tipc_nl_parse_link_prop(struct nlattr *prop, struct nlattr *props[])
{
	int err;

	err = nla_parse_nested_deprecated(props, TIPC_NLA_PROP_MAX, prop,
					  tipc_nl_prop_policy, NULL);
	if (err)
		return err;

	if (props[TIPC_NLA_PROP_PRIO]) {
		u32 prio;

		prio = nla_get_u32(props[TIPC_NLA_PROP_PRIO]);
		if (prio > TIPC_MAX_LINK_PRI)
			return -EINVAL;
	}

	if (props[TIPC_NLA_PROP_TOL]) {
		u32 tol;

		tol = nla_get_u32(props[TIPC_NLA_PROP_TOL]);
		if ((tol < TIPC_MIN_LINK_TOL) || (tol > TIPC_MAX_LINK_TOL))
			return -EINVAL;
	}

	if (props[TIPC_NLA_PROP_WIN]) {
		u32 max_win;

		max_win = nla_get_u32(props[TIPC_NLA_PROP_WIN]);
		if (max_win < TIPC_DEF_LINK_WIN || max_win > TIPC_MAX_LINK_WIN)
			return -EINVAL;
	}

	return 0;
}

static int __tipc_nl_add_stats(struct sk_buff *skb, struct tipc_stats *s)
{
	int i;
	struct nlattr *stats;

	struct nla_map {
		u32 key;
		u32 val;
	};

	struct nla_map map[] = {
		{TIPC_NLA_STATS_RX_INFO, 0},
		{TIPC_NLA_STATS_RX_FRAGMENTS, s->recv_fragments},
		{TIPC_NLA_STATS_RX_FRAGMENTED, s->recv_fragmented},
		{TIPC_NLA_STATS_RX_BUNDLES, s->recv_bundles},
		{TIPC_NLA_STATS_RX_BUNDLED, s->recv_bundled},
		{TIPC_NLA_STATS_TX_INFO, 0},
		{TIPC_NLA_STATS_TX_FRAGMENTS, s->sent_fragments},
		{TIPC_NLA_STATS_TX_FRAGMENTED, s->sent_fragmented},
		{TIPC_NLA_STATS_TX_BUNDLES, s->sent_bundles},
		{TIPC_NLA_STATS_TX_BUNDLED, s->sent_bundled},
		{TIPC_NLA_STATS_MSG_PROF_TOT, (s->msg_length_counts) ?
			s->msg_length_counts : 1},
		{TIPC_NLA_STATS_MSG_LEN_CNT, s->msg_length_counts},
		{TIPC_NLA_STATS_MSG_LEN_TOT, s->msg_lengths_total},
		{TIPC_NLA_STATS_MSG_LEN_P0, s->msg_length_profile[0]},
		{TIPC_NLA_STATS_MSG_LEN_P1, s->msg_length_profile[1]},
		{TIPC_NLA_STATS_MSG_LEN_P2, s->msg_length_profile[2]},
		{TIPC_NLA_STATS_MSG_LEN_P3, s->msg_length_profile[3]},
		{TIPC_NLA_STATS_MSG_LEN_P4, s->msg_length_profile[4]},
		{TIPC_NLA_STATS_MSG_LEN_P5, s->msg_length_profile[5]},
		{TIPC_NLA_STATS_MSG_LEN_P6, s->msg_length_profile[6]},
		{TIPC_NLA_STATS_RX_STATES, s->recv_states},
		{TIPC_NLA_STATS_RX_PROBES, s->recv_probes},
		{TIPC_NLA_STATS_RX_NACKS, s->recv_nacks},
		{TIPC_NLA_STATS_RX_DEFERRED, s->deferred_recv},
		{TIPC_NLA_STATS_TX_STATES, s->sent_states},
		{TIPC_NLA_STATS_TX_PROBES, s->sent_probes},
		{TIPC_NLA_STATS_TX_NACKS, s->sent_nacks},
		{TIPC_NLA_STATS_TX_ACKS, s->sent_acks},
		{TIPC_NLA_STATS_RETRANSMITTED, s->retransmitted},
		{TIPC_NLA_STATS_DUPLICATES, s->duplicates},
		{TIPC_NLA_STATS_LINK_CONGS, s->link_congs},
		{TIPC_NLA_STATS_MAX_QUEUE, s->max_queue_sz},
		{TIPC_NLA_STATS_AVG_QUEUE, s->queue_sz_counts ?
			(s->accu_queue_sz / s->queue_sz_counts) : 0}
	};

	stats = nla_nest_start_noflag(skb, TIPC_NLA_LINK_STATS);
	if (!stats)
		return -EMSGSIZE;

	for (i = 0; i <  ARRAY_SIZE(map); i++)
		if (nla_put_u32(skb, map[i].key, map[i].val))
			goto msg_full;

	nla_nest_end(skb, stats);

	return 0;
msg_full:
	nla_nest_cancel(skb, stats);

	return -EMSGSIZE;
}

/* Caller should hold appropriate locks to protect the link */
int __tipc_nl_add_link(struct net *net, struct tipc_nl_msg *msg,
		       struct tipc_link *link, int nlflags)
{
	u32 self = tipc_own_addr(net);
	struct nlattr *attrs;
	struct nlattr *prop;
	void *hdr;
	int err;

	hdr = genlmsg_put(msg->skb, msg->portid, msg->seq, &tipc_genl_family,
			  nlflags, TIPC_NL_LINK_GET);
	if (!hdr)
		return -EMSGSIZE;

	attrs = nla_nest_start_noflag(msg->skb, TIPC_NLA_LINK);
	if (!attrs)
		goto msg_full;

	if (nla_put_string(msg->skb, TIPC_NLA_LINK_NAME, link->name))
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_LINK_DEST, tipc_cluster_mask(self)))
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_LINK_MTU, link->mtu))
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_LINK_RX, link->stats.recv_pkts))
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_LINK_TX, link->stats.sent_pkts))
		goto attr_msg_full;

	if (tipc_link_is_up(link))
		if (nla_put_flag(msg->skb, TIPC_NLA_LINK_UP))
			goto attr_msg_full;
	if (link->active)
		if (nla_put_flag(msg->skb, TIPC_NLA_LINK_ACTIVE))
			goto attr_msg_full;

	prop = nla_nest_start_noflag(msg->skb, TIPC_NLA_LINK_PROP);
	if (!prop)
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_PROP_PRIO, link->priority))
		goto prop_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_PROP_TOL, link->tolerance))
		goto prop_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_PROP_WIN,
			link->window))
		goto prop_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_PROP_PRIO, link->priority))
		goto prop_msg_full;
	nla_nest_end(msg->skb, prop);

	err = __tipc_nl_add_stats(msg->skb, &link->stats);
	if (err)
		goto attr_msg_full;

	nla_nest_end(msg->skb, attrs);
	genlmsg_end(msg->skb, hdr);

	return 0;

prop_msg_full:
	nla_nest_cancel(msg->skb, prop);
attr_msg_full:
	nla_nest_cancel(msg->skb, attrs);
msg_full:
	genlmsg_cancel(msg->skb, hdr);

	return -EMSGSIZE;
}

static int __tipc_nl_add_bc_link_stat(struct sk_buff *skb,
				      struct tipc_stats *stats)
{
	int i;
	struct nlattr *nest;

	struct nla_map {
		__u32 key;
		__u32 val;
	};

	struct nla_map map[] = {
		{TIPC_NLA_STATS_RX_INFO, stats->recv_pkts},
		{TIPC_NLA_STATS_RX_FRAGMENTS, stats->recv_fragments},
		{TIPC_NLA_STATS_RX_FRAGMENTED, stats->recv_fragmented},
		{TIPC_NLA_STATS_RX_BUNDLES, stats->recv_bundles},
		{TIPC_NLA_STATS_RX_BUNDLED, stats->recv_bundled},
		{TIPC_NLA_STATS_TX_INFO, stats->sent_pkts},
		{TIPC_NLA_STATS_TX_FRAGMENTS, stats->sent_fragments},
		{TIPC_NLA_STATS_TX_FRAGMENTED, stats->sent_fragmented},
		{TIPC_NLA_STATS_TX_BUNDLES, stats->sent_bundles},
		{TIPC_NLA_STATS_TX_BUNDLED, stats->sent_bundled},
		{TIPC_NLA_STATS_RX_NACKS, stats->recv_nacks},
		{TIPC_NLA_STATS_RX_DEFERRED, stats->deferred_recv},
		{TIPC_NLA_STATS_TX_NACKS, stats->sent_nacks},
		{TIPC_NLA_STATS_TX_ACKS, stats->sent_acks},
		{TIPC_NLA_STATS_RETRANSMITTED, stats->retransmitted},
		{TIPC_NLA_STATS_DUPLICATES, stats->duplicates},
		{TIPC_NLA_STATS_LINK_CONGS, stats->link_congs},
		{TIPC_NLA_STATS_MAX_QUEUE, stats->max_queue_sz},
		{TIPC_NLA_STATS_AVG_QUEUE, stats->queue_sz_counts ?
			(stats->accu_queue_sz / stats->queue_sz_counts) : 0}
	};

	nest = nla_nest_start_noflag(skb, TIPC_NLA_LINK_STATS);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; i <  ARRAY_SIZE(map); i++)
		if (nla_put_u32(skb, map[i].key, map[i].val))
			goto msg_full;

	nla_nest_end(skb, nest);

	return 0;
msg_full:
	nla_nest_cancel(skb, nest);

	return -EMSGSIZE;
}

int tipc_nl_add_bc_link(struct net *net, struct tipc_nl_msg *msg,
			struct tipc_link *bcl)
{
	int err;
	void *hdr;
	struct nlattr *attrs;
	struct nlattr *prop;
	u32 bc_mode = tipc_bcast_get_mode(net);
	u32 bc_ratio = tipc_bcast_get_broadcast_ratio(net);

	if (!bcl)
		return 0;

	tipc_bcast_lock(net);

	hdr = genlmsg_put(msg->skb, msg->portid, msg->seq, &tipc_genl_family,
			  NLM_F_MULTI, TIPC_NL_LINK_GET);
	if (!hdr) {
		tipc_bcast_unlock(net);
		return -EMSGSIZE;
	}

	attrs = nla_nest_start_noflag(msg->skb, TIPC_NLA_LINK);
	if (!attrs)
		goto msg_full;

	/* The broadcast link is always up */
	if (nla_put_flag(msg->skb, TIPC_NLA_LINK_UP))
		goto attr_msg_full;

	if (nla_put_flag(msg->skb, TIPC_NLA_LINK_BROADCAST))
		goto attr_msg_full;
	if (nla_put_string(msg->skb, TIPC_NLA_LINK_NAME, bcl->name))
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_LINK_RX, 0))
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_LINK_TX, 0))
		goto attr_msg_full;

	prop = nla_nest_start_noflag(msg->skb, TIPC_NLA_LINK_PROP);
	if (!prop)
		goto attr_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_PROP_WIN, bcl->max_win))
		goto prop_msg_full;
	if (nla_put_u32(msg->skb, TIPC_NLA_PROP_BROADCAST, bc_mode))
		goto prop_msg_full;
	if (bc_mode & BCLINK_MODE_SEL)
		if (nla_put_u32(msg->skb, TIPC_NLA_PROP_BROADCAST_RATIO,
				bc_ratio))
			goto prop_msg_full;
	nla_nest_end(msg->skb, prop);

	err = __tipc_nl_add_bc_link_stat(msg->skb, &bcl->stats);
	if (err)
		goto attr_msg_full;

	tipc_bcast_unlock(net);
	nla_nest_end(msg->skb, attrs);
	genlmsg_end(msg->skb, hdr);

	return 0;

prop_msg_full:
	nla_nest_cancel(msg->skb, prop);
attr_msg_full:
	nla_nest_cancel(msg->skb, attrs);
msg_full:
	tipc_bcast_unlock(net);
	genlmsg_cancel(msg->skb, hdr);

	return -EMSGSIZE;
}

void tipc_link_set_tolerance(struct tipc_link *l, u32 tol,
			     struct sk_buff_head *xmitq)
{
	l->tolerance = tol;
	if (l->bc_rcvlink)
		l->bc_rcvlink->tolerance = tol;
	if (link_is_up(l))
		tipc_link_build_proto_msg(l, STATE_MSG, 0, 0, 0, tol, 0, xmitq);
}

void tipc_link_set_prio(struct tipc_link *l, u32 prio,
			struct sk_buff_head *xmitq)
{
	l->priority = prio;
	tipc_link_build_proto_msg(l, STATE_MSG, 0, 0, 0, 0, prio, xmitq);
}

void tipc_link_set_abort_limit(struct tipc_link *l, u32 limit)
{
	l->abort_limit = limit;
}

/**
 * tipc_link_dump - dump TIPC link data
 * @l: tipc link to be dumped
 * @dqueues: bitmask to decide if any link queue to be dumped?
 *           - TIPC_DUMP_NONE: don't dump link queues
 *           - TIPC_DUMP_TRANSMQ: dump link transmq queue
 *           - TIPC_DUMP_BACKLOGQ: dump link backlog queue
 *           - TIPC_DUMP_DEFERDQ: dump link deferd queue
 *           - TIPC_DUMP_INPUTQ: dump link input queue
 *           - TIPC_DUMP_WAKEUP: dump link wakeup queue
 *           - TIPC_DUMP_ALL: dump all the link queues above
 * @buf: returned buffer of dump data in format
 */
int tipc_link_dump(struct tipc_link *l, u16 dqueues, char *buf)
{
	int i = 0;
	size_t sz = (dqueues) ? LINK_LMAX : LINK_LMIN;
	struct sk_buff_head *list;
	struct sk_buff *hskb, *tskb;
	u32 len;

	if (!l) {
		i += scnprintf(buf, sz, "link data: (null)\n");
		return i;
	}

	i += scnprintf(buf, sz, "link data: %x", l->addr);
	i += scnprintf(buf + i, sz - i, " %x", l->state);
	i += scnprintf(buf + i, sz - i, " %u", l->in_session);
	i += scnprintf(buf + i, sz - i, " %u", l->session);
	i += scnprintf(buf + i, sz - i, " %u", l->peer_session);
	i += scnprintf(buf + i, sz - i, " %u", l->snd_nxt);
	i += scnprintf(buf + i, sz - i, " %u", l->rcv_nxt);
	i += scnprintf(buf + i, sz - i, " %u", l->snd_nxt_state);
	i += scnprintf(buf + i, sz - i, " %u", l->rcv_nxt_state);
	i += scnprintf(buf + i, sz - i, " %x", l->peer_caps);
	i += scnprintf(buf + i, sz - i, " %u", l->silent_intv_cnt);
	i += scnprintf(buf + i, sz - i, " %u", l->rst_cnt);
	i += scnprintf(buf + i, sz - i, " %u", 0);
	i += scnprintf(buf + i, sz - i, " %u", 0);
	i += scnprintf(buf + i, sz - i, " %u", l->acked);

	list = &l->transmq;
	len = skb_queue_len(list);
	hskb = skb_peek(list);
	tskb = skb_peek_tail(list);
	i += scnprintf(buf + i, sz - i, " | %u %u %u", len,
		       (hskb) ? msg_seqno(buf_msg(hskb)) : 0,
		       (tskb) ? msg_seqno(buf_msg(tskb)) : 0);

	list = &l->deferdq;
	len = skb_queue_len(list);
	hskb = skb_peek(list);
	tskb = skb_peek_tail(list);
	i += scnprintf(buf + i, sz - i, " | %u %u %u", len,
		       (hskb) ? msg_seqno(buf_msg(hskb)) : 0,
		       (tskb) ? msg_seqno(buf_msg(tskb)) : 0);

	list = &l->backlogq;
	len = skb_queue_len(list);
	hskb = skb_peek(list);
	tskb = skb_peek_tail(list);
	i += scnprintf(buf + i, sz - i, " | %u %u %u", len,
		       (hskb) ? msg_seqno(buf_msg(hskb)) : 0,
		       (tskb) ? msg_seqno(buf_msg(tskb)) : 0);

	list = l->inputq;
	len = skb_queue_len(list);
	hskb = skb_peek(list);
	tskb = skb_peek_tail(list);
	i += scnprintf(buf + i, sz - i, " | %u %u %u\n", len,
		       (hskb) ? msg_seqno(buf_msg(hskb)) : 0,
		       (tskb) ? msg_seqno(buf_msg(tskb)) : 0);

	if (dqueues & TIPC_DUMP_TRANSMQ) {
		i += scnprintf(buf + i, sz - i, "transmq: ");
		i += tipc_list_dump(&l->transmq, false, buf + i);
	}
	if (dqueues & TIPC_DUMP_BACKLOGQ) {
		i += scnprintf(buf + i, sz - i,
			       "backlogq: <%u %u %u %u %u>, ",
			       l->backlog[TIPC_LOW_IMPORTANCE].len,
			       l->backlog[TIPC_MEDIUM_IMPORTANCE].len,
			       l->backlog[TIPC_HIGH_IMPORTANCE].len,
			       l->backlog[TIPC_CRITICAL_IMPORTANCE].len,
			       l->backlog[TIPC_SYSTEM_IMPORTANCE].len);
		i += tipc_list_dump(&l->backlogq, false, buf + i);
	}
	if (dqueues & TIPC_DUMP_DEFERDQ) {
		i += scnprintf(buf + i, sz - i, "deferdq: ");
		i += tipc_list_dump(&l->deferdq, false, buf + i);
	}
	if (dqueues & TIPC_DUMP_INPUTQ) {
		i += scnprintf(buf + i, sz - i, "inputq: ");
		i += tipc_list_dump(l->inputq, false, buf + i);
	}
	if (dqueues & TIPC_DUMP_WAKEUP) {
		i += scnprintf(buf + i, sz - i, "wakeup: ");
		i += tipc_list_dump(&l->wakeupq, false, buf + i);
	}

	return i;
}
