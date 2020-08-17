#include <linux/init.h>      // included for __init and __exit macros
#include <linux/module.h>    // included for __init and __exit macros
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/sock.h>  //sock->to
#include "tcp_split.h"
#include "thread_pool.h"
#include "proc.h"
#include "rb_data_tree.h"
#include "cbn_common.h"
#include "debug.h"

//getorigdst
#include <net/inet_sock.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Markuze Alex");
MODULE_DESCRIPTION("CBN zcopy TCP Split Module");
MODULE_VERSION(KTCP_VERSION);

#define BACKLOG     	128

static int pool_size = 0;
module_param(pool_size, int, 0);
/*MODULE_PARAM_DESC(pool_size, "Optional variable to change the size of the thread pool size");*/

struct kthread_pool cbn_pool = {.pool_size = DEF_CBN_POOL_SIZE};

/*Rarely modified, shared data struct*/
/* TODO: Add percore R/W lock, hide lock and root inside func*/
//rwlock_t listner_root_lock = RW_LOCK_UNLOCKED;
struct rb_root listner_root = RB_ROOT;

struct kmem_cache *qp_slab;
struct kmem_cache *syn_slab;
struct kmem_cache *probe_slab;

static struct kmem_cache *listner_slab;

uint32_t ip_transparent = 1;

int start_new_pre_connection_syn(void *arg);

#ifdef VANILA_KERNEL

setaffinity_func 	psched_setaffinity;
bind_mask_func 		pkthread_bind_mask;
alloc_percpu_func 	p__alloc_reserved_percpu;

#endif

/*
 * Config ptrs for non exported functions. return non zero on error.
 */
static int init_kallsyms(void)
{
	int rc = 0;
#ifdef VANILA_KERNEL
	psched_setaffinity = (void *)kallsyms_lookup_name("sched_setaffinity");
	rc = !(unsigned long)psched_setaffinity;
	pkthread_bind_mask = (void *)kallsyms_lookup_name("kthread_bind_mask");
	rc |= !(unsigned long)pkthread_bind_mask;
	p__alloc_reserved_percpu = (void *)kallsyms_lookup_name("__alloc_reserved_percpu");
	rc |= !(unsigned long)p__alloc_reserved_percpu;
#endif
	return rc;
}

#if 0
// Due to MARK being part of CT this call might fail, modifed getorigdist is needed then
// one isse - it can compile only against kernels with the CT patches.
static inline int getorigdst(struct sock *sk, struct sockaddr_in *out)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	memset(&tuple, 0, sizeof(tuple));

	lock_sock(sk);
	tuple.src.u3.ip		= inet->inet_rcv_saddr;
	tuple.src.u.tcp.port	= inet->inet_sport;
	tuple.dst.u3.ip		= inet->inet_daddr;
	tuple.dst.u.tcp.port	= inet->inet_dport;
	tuple.src.l3num		= PF_INET;
	tuple.dst.protonum	= sk->sk_protocol;
	tuple.mark 		= sk->sk_mark;
	release_sock(sk);

	/* We only do TCP and SCTP at the moment: is there a better way? */
	if (unlikely(tuple.dst.protonum != IPPROTO_TCP &&
			tuple.dst.protonum != IPPROTO_SCTP)) {
		TRACE_ERROR("SO_ORIGINAL_DST: Not a TCP/SCTP socket\n");
		return -ENOPROTOOPT;
	}

	h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
	if (h) {
		struct sockaddr_in sin;
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

		sin.sin_family = AF_INET;
		sin.sin_port = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u.tcp.port;
		sin.sin_addr.s_addr = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u3.ip;
		memset(sin.sin_zero, 0, sizeof(sin.sin_zero));
		memcpy(out, &sin, sizeof(struct sockaddr_in));
		TRACE_PRINT("SO_ORIGINAL_DST: "IP4" %u\n",
				IP4N(&sin.sin_addr.s_addr), ntohs(sin.sin_port));
		nf_ct_put(ct);
		return 0;
	}
	return -ENOENT;
}
#endif

/*
static unsigned int cbn_trace_hook(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	trace_iph(skb, priv);
	return NF_ACCEPT;
}
*/
static inline void udp_port(struct sk_buff *skb, int *src, int *dst)
{
        struct udphdr *udphdr = (struct udphdr *)skb_transport_header(skb);
        *dst = ntohs(udphdr->dest);
        *src = ntohs(udphdr->source);
        return;
}

static inline void tcp_port(struct sk_buff *skb, int *src, int *dst)
{
        struct tcphdr *tcphdr = (struct tcphdr *)skb_transport_header(skb);
        *dst = ntohs(tcphdr->dest);
        *src = ntohs(tcphdr->source);
}

static inline void get_port(struct sk_buff *skb)
{
        struct iphdr *iph = ip_hdr(skb);
        int src, dst;

        src = dst = 0;

        if (iph->protocol == 6)
                tcp_port(skb, &src, &dst);

        if (iph->protocol == 17)
                udp_port(skb, &src, &dst);
	return;
}

#define CBN_TUNNEL_PREFIX	"gue"
static inline bool is_out_gue(struct sk_buff *skb)
{
	return !memcmp(skb->dev->name, CBN_TUNNEL_PREFIX, strlen(CBN_TUNNEL_PREFIX));
}

static inline struct addresses *build_addresses(struct sk_buff *skb)
{
	struct iphdr *iphdr = ip_hdr(skb);
	struct tcphdr *tcphdr = (struct tcphdr *)skb_transport_header(skb);

	struct addresses *addresses = kmem_cache_alloc(syn_slab, GFP_ATOMIC);
	if (unlikely(!addresses)) {
		TRACE_ERROR("Faield to alloc mem\n");
		return NULL;
	}
	//trace_iph(skb, __FUNCTION__);

	addresses->dest.sin_addr.s_addr = iphdr->daddr;
	addresses->src.sin_addr.s_addr  = iphdr->saddr;
	addresses->dest.sin_port        = tcphdr->dest;
	addresses->src.sin_port         = tcphdr->source;
	addresses->mark                 = skb->mark;

	return addresses;
}

static inline bool is_cbn_probe(struct sk_buff *skb)
{
	if (likely(skb->inner_protocol == IPPROTO_IPIP)) {
		struct iphdr *iphdr = (struct iphdr *)skb_inner_network_header(skb);
		if (iphdr->protocol == IPPROTO_TCP) {
			struct tcphdr *tcphdr = (struct tcphdr *)skb_inner_transport_header(skb);
			return (ntohs(tcphdr->source) == CBP_PROBE_PORT);
		}
	}
	return false;
}

static inline struct addresses *get_cbn_probe(struct sk_buff *skb)
{
	struct tcphdr *ptr = (struct tcphdr *)skb_inner_transport_header(skb);
	struct addresses **addresses = (struct addresses **)(++ptr);
	//TRACE_PRINT("skb %p addr %p [%d|%d] => %p\n", skb, ptr, skb->inner_protocol, ntohs(skb->inner_protocol), *addresses);
	return *addresses;
}


static inline int set_cbn_probe(struct sk_buff *skb, struct addresses *addresses)
{
	struct addresses **ptr = (struct addresses **)skb_put(skb, sizeof(struct addresses *));
	*ptr = addresses;
	//TRACE_PRINT("skb %p addr %p [%lu] => %p\n", skb, ptr, (unsigned long)ptr - (unsigned long)skb_transport_header(skb), addresses);
	return 0;
}

static unsigned int cbn_egress_hook(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
        struct iphdr *iph = ip_hdr(skb);

	if (!skb->mark)
		goto out;

	if ((iph->protocol == IPPROTO_TCP)) {
		struct tcphdr *tcphdr = (struct tcphdr *)skb_transport_header(skb);
		if (unlikely((ntohs(tcphdr->source) == CBP_PROBE_PORT))) {
			struct addresses *addresses = build_addresses(skb);
			if (!addresses) {
				TRACE_ERROR("Faield to alloc mem");
				goto drop;
			}
			addresses->src.sin_port = tcphdr->window;
			if (is_out_gue(skb)) {
				if (set_cbn_probe(skb, addresses))
					goto drop;
			} else {
				unsigned int cpu = addresses2cpu(addresses);
				kthread_pool_run_cpu(&cbn_pool,
							start_new_connection_syn,
							addresses, cpu);
				goto drop;
			}
		}
		goto out;
	}

	if ((iph->protocol == IPPROTO_UDP) & is_cbn_probe(skb)) {
		struct addresses *addresses = get_cbn_probe(skb);
		if (addresses) {
			//TRACE_PRINT("Next hop is "IP4"=>"IP4"\n", IP4N(&iph->saddr), IP4N(&iph->daddr));
			unsigned int cpu;
			cpu = addresses2cpu(addresses);

			addresses->sin_addr.s_addr = iph->daddr;
			kthread_pool_run_cpu(&cbn_pool, start_new_pre_connection_syn,
						addresses, cpu);
		}
		goto drop;
	}
out:
	return NF_ACCEPT;
drop:
	//TRACE_PRINT("Packet dropped %s\n", __FUNCTION__);
	return NF_DROP;
}

static unsigned int cbn_ingress_hook(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct cbn_listner *listner;

	if (strcmp(priv, "RX"))
		goto out;

	if (!skb->mark)
		goto out;

	if (!(listner = search_rb_listner(&listner_root, skb->mark))) {
		goto out;
	}

	if (trace_iph(skb, priv)) {
		struct iphdr *iphdr = ip_hdr(skb);
		struct tcphdr *tcphdr = (struct tcphdr *)skb_transport_header(skb);
		struct probe *probe;

		probe = kmem_cache_alloc(probe_slab, GFP_ATOMIC);
		if (unlikely(!probe)) {
			TRACE_ERROR("Faield to alloc probe\n");
			goto out;
		}

		memcpy(&probe->iphdr, iphdr, sizeof(struct iphdr));
		memcpy(&probe->tcphdr, tcphdr, sizeof(struct tcphdr));
		probe->listner = listner;

		kthread_pool_run(&cbn_pool, start_probe_syn, probe);
	}

out:
	return NF_ACCEPT;
}

#define CBN_PRIO_OFFSET 50

static struct nf_hook_ops cbn_nf_hooks[] = {
		{
		.hook		= cbn_egress_hook,
		.hooknum	= NF_INET_POST_ROUTING,
		.pf		= PF_INET,
		.priority	= NF_IP_PRI_FIRST,
		.priv		= "TX"
		},
	/*
		{
		.hook		= cbn_ingress_hook,
		.hooknum	= NF_INET_LOCAL_OUT,
		.pf		= PF_INET,
		.priority	= NF_IP_PRI_FIRST,
		.priv		= "NF_INET_LOCAL_OUT"
		},

		{
		.hook		= cbn_ingress_hook,
		.hooknum	= NF_INET_FORWARD,
		.pf		= PF_INET,
		.priority	= NF_IP_PRI_FIRST,
		.priv		= "NF_INET_FORWARD"
		},
		{
		.hook		= cbn_trace_hook,
		.hooknum	= NF_INET_LOCAL_IN,
		.pf		= PF_INET,
		.priority	= (NF_IP_PRI_SECURITY -1),
		.priv		= "SEC-1"
		},
		{
		.hook		= cbn_trace_hook,
		.hooknum	= NF_INET_LOCAL_IN,
		.pf		= PF_INET,
		.priority	= (NF_IP_PRI_SECURITY +1),
		.priv		= "SEC+1"
		},
		{
		.hook		= cbn_ingress_hook,
		.hooknum	= NF_INET_LOCAL_IN,
		.pf		= PF_INET,
		.priority	= NF_IP_PRI_FIRST,
		.priv		= "LIN"
		},
		*/
		{
		.hook		= cbn_ingress_hook,
		.hooknum	= NF_INET_PRE_ROUTING,
		.pf		= PF_INET,
		.priority	= NF_IP_PRI_RAW + CBN_PRIO_OFFSET,
		.priv		= "RX"
		},
//TODO: Add LOCAL_IN to mark packets with tennant_id
};

//TODO: Must hold list (not tree) of active QPs for this.
static inline void stop_tennat_proxies(struct rb_root *root)
{

	struct cbn_qp *pos, *tmp;
	struct socket *sock;

	rbtree_postorder_for_each_entry_safe(pos, tmp, root, node) {
		if (pos->tx) {
			sock = (struct socket *)pos->tx;
			kernel_sock_shutdown(sock, SHUT_RDWR);
		}
		if (pos->rx) {
			sock = (struct socket *)pos->rx;
			kernel_sock_shutdown(sock, SHUT_RDWR);
		}
	}
}

static inline void remove_listner_server(struct cbn_listner *pos)
{
	if (pos->sock)
		kernel_sock_shutdown(pos->sock, SHUT_RDWR);
	//stop_tennat_proxies(&pos->connections_root);
	rb_erase(&pos->node, &listner_root);
	kmem_cache_free(listner_slab, pos);
}

static inline void stop_sockets(void)
{
	struct cbn_listner *pos, *tmp;

	rbtree_postorder_for_each_entry_safe(pos, tmp, &listner_root, node) {
		remove_listner_server(pos);
	}
}

#if 1
#define VEC_SZ 32

int half_duplex(struct sockets *sock, struct cbn_qp *qp)
{
	struct kvec kvec[VEC_SZ];
	int id = 0, i ,dir = sock->dir;
	int rc;
	uint64_t bytes = 0;

	/*Allow to run on any core...*/
	if ((rc = sched_setaffinity(0, cpu_possible_mask)))
		TRACE_ERROR("Failed to sched_setaffinity! [%d]", rc);
	rc = -ENOMEM;
	for (i = 0; i < VEC_SZ; i++) {
		kvec[i].iov_len = PAGE_SIZE;
		/*TODO: In case of alloc failure put_qp is needed */
		if (! (kvec[i].iov_base = page_address(alloc_page(GFP_KERNEL))))
			goto err;
	}
	do {
		struct msghdr msg = { 0 };
		if ((rc = kernel_recvmsg(sock->rx, &msg, kvec, VEC_SZ, (PAGE_SIZE * VEC_SZ), 0)) <= 0) {
			TRACE_DEBUG("%s [%s] (%d) at %s with %lld bytes", __FUNCTION__,
					dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
			put_qp(qp);
			/*
			if (put_qp(qp)) {
				//FIXME: Add per QP lock for shutdown sync.
				//TOCTOU bug on sock_shutdown
				kernel_sock_shutdown(sock->tx, SHUT_RDWR);
				//kernel_sock_shutdown(sock->rx, SHUT_RDWR);
				//sock-sk + sk_wake_async if shutdown fails.
				//sk_wake_async(sock->tx->sk, SOCK_WAKE_URG, POLL_HUP);
			}
			*/
			goto err;
		}
		bytes += rc;
		id ^= 1;
		if (msg.msg_flags)
			TRACE_PRINT("[%s] GOT A FUCKING FLAG %d", id ? "Send" : "Rcv", msg.msg_flags);

		//use kern_sendpage if flags needed.
		if ((rc = kernel_sendmsg(sock->tx, &msg, kvec, VEC_SZ, rc)) <= 0) {
			TRACE_PRINT("%s [%s] (%d) at %s with %lld bytes", __FUNCTION__,
					dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
			put_qp(qp);
			/*
			if (put_qp(qp)) {
				//sk_wake_async(sock->rx->sk, SOCK_WAKE_URG, POLL_HUP);
				kernel_sock_shutdown(sock->rx, SHUT_RDWR);
				//kernel_sock_shutdown(sock->tx, SHUT_RDWR);
			}
			*/
			goto err;
		}
		id ^= 1;
		if (msg.msg_flags)
			TRACE_PRINT("[%s] GOT A FUCKING FLAG %d", id ? "Send" : "Rcv", msg.msg_flags);

	} while (!kthread_should_stop());

err:
	if (rc) {
		TRACE_PRINT("%s [%s] stopping on error (%d) at %s with %lld bytes", __FUNCTION__,
				dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
	} else {
		TRACE_DEBUG("%s [%s] stopping (%d) at %s with %lld bytes", __FUNCTION__,
				dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
	}
	for (i = 0; i < VEC_SZ; i++)
		free_page((unsigned long)(kvec[i].iov_base));

	return rc;
}


#else
//implementing binary search
static inline int get_kvec_len(struct kvec *kvec, unsigned long len)
{
	struct kvec *start = kvec;
	char buffer[256] = {0};
	char *ptr = buffer;
	int i, n = 0;

	for (i = 0; i < len; i++) {
		n += snprintf(&ptr[n], 16, " %lu", kvec[i].iov_len);
		if (i && !(i & 7))
			n += snprintf(&ptr[n], 16, "\n");
	}

	while (len) {
		len = (len >> 1);
		if (kvec[len].iov_len)
			kvec = &kvec[len];
	}
	if (kvec[len].iov_len)
		kvec = &kvec[len + 1];
	len = (kvec - start) + !!kvec[0].iov_len;
	trace_printk("%ld) now %lu prev %lu\n\%s\n", len, kvec[0].iov_len, kvec[-1].iov_len, buffer);
	return len;
}

#define VEC_SZ 32
int half_duplex(struct sockets *sock, struct cbn_qp *qp)
{
	struct kvec kvec[VEC_SZ];
	int id = 0, dir = sock->dir;
	int rc;
	uint64_t bytes = 0;

	/*Allow to run on any core...*/
	if ((rc = sched_setaffinity( 0, cpu_possible_mask)))
		TRACE_ERROR("Failed to sched_setaffinity! [%d]", rc);

	//sock_set_flag(sock->tx->sk, SOCK_KERN_ZEROCOPY);
	do {
		struct msghdr msg = { 0 };

		memset(kvec, 0, sizeof(kvec));

		if ((rc = tcp_read_sock_zcopy_blocking(sock->rx, kvec, VEC_SZ)) <= 0) {
			TRACE_DEBUG("ERROR: %s [%s] (%d) at %s with %lld bytes", __FUNCTION__,
					dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
			put_qp(qp);
			/*
			if (put_qp(qp)) {
				//FIXME: Add per QP lock for shutdown sync.
				//TOCTOU bug on sock_shutdown
				kernel_sock_shutdown(sock->tx, SHUT_RDWR);
				//kernel_sock_shutdown(sock->rx, SHUT_RDWR);
				//sock-sk + sk_wake_async if shutdown fails.
				//sk_wake_async(sock->tx->sk, SOCK_WAKE_URG, POLL_HUP);
			}
			*/
			goto err;
		}
		TRACE_PRINT("%s [%s] %s :  %d", __FUNCTION__,
				dir  ? "TX" : "RX", id ? "Send" : "Rcv", rc);


		bytes += rc;
		id ^= 1;
		//msg.msg_flags   |= MSG_ZEROCOPY;

		//FIXME: Need to make sure we know num of frags
		if ((rc = kernel_sendmsg(sock->tx, &msg, kvec,
					get_kvec_len(kvec, VEC_SZ), rc)) <= 0) {
			TRACE_PRINT("ERROR: %s [%s] (%d) at %s with %lld bytes", __FUNCTION__,
					dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
			put_qp(qp);
			/*
			if (put_qp(qp)) {
				//sk_wake_async(sock->rx->sk, SOCK_WAKE_URG, POLL_HUP);
				kernel_sock_shutdown(sock->rx, SHUT_RDWR);
				//kernel_sock_shutdown(sock->tx, SHUT_RDWR);
			}
			*/
			goto err;
		}
		//TRACE_PRINT("%s [%s] %s :  %d", __FUNCTION__,
		//		dir  ? "TX" : "RX", id ? "Send" : "Rcv", rc);
		id ^= 1;

	} while (!kthread_should_stop());

err:
	if (rc) {
		TRACE_PRINT("%s [%s] stopping on error (%d) at %s with %lld bytes", __FUNCTION__,
				dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
	} else {
		TRACE_DEBUG("%s [%s] stopping (%d) at %s with %lld bytes", __FUNCTION__,
				dir  ? "TX" : "RX", rc, id ? "Send" : "Rcv", bytes);
	}

	return rc;
}
#endif

inline struct cbn_qp *qp_exists(struct cbn_qp* pqp, uint8_t dir)
{
	struct cbn_qp *qp = pqp;
	struct cbn_root_qp *qp_root = this_cpu_ptr(qp->listner->connections_root);

	//FIXME: In case both L and R fail. Connection will stay in tree...
	if ((qp = add_rb_data(&qp_root->root, pqp, &qp_root->rb_lock))) {
		/* QP already exists */
		if (qp->qp_dir[dir] != NULL) {
			/* *
			 * Double Syn, this DIR qp already exists,
			 * either active(Valid socket) or in progress (-EINVAL)
			 * Drop this QP and stop.
			 * */
			TRACE_PRINT("WARN: QP exists %p [%p] <%d>", qp, qp->qp_dir[dir], dir);
			return NULL;
		}
		/* *
		 * Other DIR beat you to it, use the existing QP
		 * mark as -EINVAL for double SYN.
		 * */
		qp->qp_dir[dir] = pqp->qp_dir[dir];
		kmem_cache_free(qp_slab, pqp);
		pqp = qp;
		dump_qp(qp, "added info");
	}
	return pqp;
}

inline int wait_qp_ready(struct cbn_qp* qp, uint8_t dir)
{
	int err = 0;
	/*
	 * You shouldnt be here unless your dir sock is valid.
	 * TODO: TOCTOU bug ahead.
	 * */

	if (IS_ERR_OR_NULL(qp->qp_dir[dir ^ 1])) {
		int rc;
		/*should return non zero*/
		dump_qp(qp, "waiting for peer");
		get_qp(qp);
		/*IMPORTANT: Make sure core doesnt change - may mess up other core root!!!*/
		rc = wait_event_interruptible_timeout(qp->wait,
							!IS_ERR_OR_NULL(qp->qp_dir[dir ^ 1]),
						       	QP_TO * HZ);
		if (!rc) {
			TRACE_PRINT("ERROR: TIMEOUT %d (%s)", rc,
					(IS_ERR_OR_NULL(qp->qp_dir[dir ^ 1])
					 ? "ERR/NULL" : "EXISTS!!"));
			trace_connections();
			if (qp->listner) {
				struct cbn_root_qp *qp_root =
					this_cpu_ptr(qp->listner->connections_root);

				de_tree_qp(&qp->node, &qp_root->root, &qp_root->rb_lock);
			}

			put_qp(qp);
			err = 1;
		}
	} else {
		dump_qp(qp, "waking peer");
		get_qp(qp);
		wake_up(&qp->wait);
	}

	return err;
}

#if 0
static inline struct cbn_qp *sync_qp(struct cbn_qp* qp, uint8_t dir)
{
	struct cbn_qp *tx_qp;

	if ((tx_qp = add_rb_data(qp->root, qp))) { //this means the other conenction is already up
		tx_qp->qp_dir[dir] = qp->qp_dir[dir ^ 1];
		if (unlikely(atomic_read(&qp->ref_cnt))) {
			TRACE_ERROR("ERROR: Active connection pair [%d] exists...", atomic_read(&qp->ref_cnt));
			goto err;
		}
		kmem_cache_free(qp_slab, qp);
		qp = tx_qp;
		TRACE_PRINT("QP exists, waking peer");
		wake_up(&qp->wait);
	} else {
		TRACE_PRINT("QP created... waiting for peer");
		init_waitqueue_head(&qp->wait);
		if (!qp->qp_dir[dir]) {
			int error;
			error = wait_event_interruptible_timeout(qp->wait,
								 qp->qp_dir[dir], 3 * HZ);
			if (error)
				goto err;
		}
	}
	return qp;
err:
	/* Consider error handling...*/
	return qp;
}
#endif

int start_new_connection_syn(void *arg)
{
	int rc, T = 1;
	struct addresses *addresses = arg;
	struct cbn_listner *listner;
	struct cbn_qp *qp;
	struct sockets sockets;
	struct socket *tx = NULL;

	INIT_TRACE

	qp = kmem_cache_alloc(qp_slab, GFP_KERNEL);
	qp->addr_d = addresses->dest.sin_addr;
	qp->port_s = addresses->src.sin_port;
	qp->port_d = addresses->dest.sin_port;
	qp->addr_s = addresses->src.sin_addr;
	atomic_set(&qp->ref_cnt, 0);
	init_waitqueue_head(&qp->wait);

	qp->rx = NULL;
	qp->tx = ERR_PTR(-EINVAL);
	listner = search_rb_listner(&listner_root, addresses->mark);
	qp->listner = listner;

	qp = qp_exists(qp, TX_QP);
	if (unlikely(qp == NULL)) {
		TRACE_PRINT("WARNING : connection exists : "TCP4" => "TCP4" mark %d",
				TCP4N(&addresses->src.sin_addr, ntohs(addresses->src.sin_port)),
				TCP4N(&addresses->dest.sin_addr, ntohs(addresses->dest.sin_port)),
				addresses->mark);
		kmem_cache_free(syn_slab, addresses);
		return  0;
	}

	TRACE_PRINT("[R] %s : "TCP4" => "TCP4" mark %d", __FUNCTION__,
			TCP4N(&addresses->src.sin_addr, ntohs(addresses->src.sin_port)),
			TCP4N(&addresses->dest.sin_addr, ntohs(addresses->dest.sin_port)),
			addresses->mark);

	if ((rc = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &tx))) {
		TRACE_ERROR("RC = %d (%d)", rc, __LINE__);
		goto connect_fail;
	}

	if ((rc = kernel_setsockopt(tx, SOL_TCP, TCP_NODELAY, (char *)&T, sizeof(T))) < 0) {
		TRACE_ERROR("RC = %d (%d)", rc, __LINE__);
		goto connect_fail;
	}

	if ((rc = kernel_setsockopt(tx, SOL_SOCKET, SO_MARK, (char *)&addresses->mark, sizeof(u32))) < 0) {
		TRACE_ERROR("RC = %d (%d)", rc, __LINE__);
		goto connect_fail;
	}

	if (ip_transparent) {
		if ((rc = kernel_setsockopt(tx, SOL_IP, IP_TRANSPARENT, (char *)&T, sizeof(int)))) {
			TRACE_ERROR("RC = %d (%d)", rc, __LINE__);
			goto connect_fail;
		}

		addresses->src.sin_family = AF_INET;
		addresses->src.sin_port = 0;
		//TRACE_PRINT("Binding : port %d IP "IP4" mark %d",
		//		ntohs(addresses->src.sin_port), IP4N(&addresses->src.sin_addr),
		//		addresses->mark);
		if ((rc = kernel_bind(tx, (struct sockaddr *)&addresses->src, sizeof(struct sockaddr)))) {
			TRACE_ERROR("RC = %d (%d)", rc, __LINE__);
			goto connect_fail;
		} else {
			TRACE_DEBUG("[R]Bound to "TCP4, TCP4N(&addresses->src.sin_addr, 0));
		}
	}

	addresses->dest.sin_family = AF_INET;
	if ((rc = kernel_connect(tx, (struct sockaddr *)&addresses->dest, sizeof(struct sockaddr), 0))) {
		TRACE_ERROR("RC = %d (%d)", rc, __LINE__);
		goto connect_fail;
	}

	qp->tx = tx;
	tx = NULL;

	//TRACE_PRINT("%s qp %p listner %p mark %d", __FUNCTION__, qp, listner, addresses->mark);
	kmem_cache_free(syn_slab, addresses);
	if (wait_qp_ready(qp, TX_QP))
		goto connect_fail;

	DUMP_TRACE
	sockets.tx = (struct socket *)qp->rx;
	sockets.rx = (struct socket *)qp->tx;
	sockets.dir = 1;
	if (unlikely(IS_ERR_OR_NULL((struct socket *)qp->rx) || IS_ERR_OR_NULL((struct socket *)qp->tx))) {
		TRACE_ERROR("One of the QP dirs is NULL! <%p,%p>", qp->rx, qp->tx);
		put_qp(qp);
		goto connect_fail;
	}
	TRACE_DEBUG("starting half duplex %d", atomic_read(&qp->ref_cnt));
	rc = half_duplex(&sockets, qp);

connect_fail:
	if ( ! IS_ERR_OR_NULL(tx)) {
		TRACE_PRINT("RELEASING SOCK!");
		sock_release(tx);
	}

	TRACE_PRINT("connection closed <%d>", rc);
	return rc;
}
/*
static int start_new_connection_syn_ack(int mark, struct cbn_qp *qp)
{
	struct addresses *addresses;
	int rc = 0;
	addresses = kmem_cache_alloc(syn_slab, GFP_ATOMIC);
	if (unlikely(!addresses)) {
		TRACE_ERROR("Faield to alloc mem\n");
		rc = 1;
		goto out;
	}

	addresses->dest.sin_addr 	= qp->addr_d;
	addresses->src.sin_port 	= qp->port_s;
	addresses->dest.sin_port 	= qp->port_d;
	addresses->src.sin_addr 	= qp->addr_s;
	addresses->mark			= mark;

	if (next_hop_ip)
		kthread_pool_run(&cbn_pool, start_new_pre_connection_syn, addresses);
	else
		kthread_pool_run(&cbn_pool, start_new_connection_syn, addresses);
out:
	return rc;
}
*/
static int start_new_connection(void *arg)
{
	int rc, size, line, mark, optval = 1;
	struct socket *rx;
	struct sockaddr_in cli_addr;
	struct sockaddr_in addr;
	struct cbn_qp *qp;
	struct sockets sockets;

	INIT_TRACE

	qp 	= arg;
	rx 	= (struct socket *)qp->rx;
	mark 	= qp->tid;

	size = sizeof(addr);

	line = __LINE__;
	if ((rc = kernel_setsockopt(rx, SOL_SOCKET, SO_MARK, (char *)&mark, sizeof(u32))) < 0) {
		TRACE_ERROR("error (%d)\n", rc);
		goto create_fail;
	}

	//if ((rc = getorigdst(rx->sk, &addr))) {
	line = __LINE__;
	if ((rc = kernel_getsockopt(rx, SOL_IP, SO_ORIGINAL_DST, (char *)&addr, &size))) {
		TRACE_ERROR("error (%d)\n", rc);
		goto create_fail;
	}

	line = __LINE__;
	if ((rc = kernel_setsockopt(rx, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval))) < 0)
		goto create_fail;

	line = __LINE__;
	//if ((rc = kernel_getpeername(rx, (struct sockaddr *)&cli_addr, &size))) {
	if ((rc = kernel_getpeername(rx, (struct sockaddr *)&cli_addr)) < 0) {
		TRACE_ERROR("error (%d)\n", rc);
		goto create_fail;
	}

	qp->addr_d = addr.sin_addr;
	qp->port_s = cli_addr.sin_port;
	qp->port_d = addr.sin_port;
	qp->addr_s = cli_addr.sin_addr;
	if ((rc = sched_setaffinity(0, cpumask_of(qp2cpu(qp))))) {
		TRACE_ERROR("Failed to set affinity error (%d)\n", rc);
		goto create_fail;
	}
	//TODO: cond_resched() ?!
	yield();
	/*rp->root/qp->mark no longer valid, qp is a union*/

	//line = __LINE__;
	//if ((rc = kernel_getsockname(rx, (struct sockaddr *)&addr, &size)))
	//	goto create_fail;
	TRACE_PRINT("[L] "TCP4" => "TCP4" [m=%d]",
			TCP4N(&cli_addr.sin_addr, ntohs(cli_addr.sin_port)),
			TCP4N(&addr.sin_addr, ntohs(addr.sin_port)), mark);

	qp->tx = NULL;

	/* consolidate into one qp */
	qp = qp_exists(qp, RX_QP);
	if (wait_qp_ready(qp, RX_QP))
		goto out;

	DUMP_TRACE
	sockets.tx = (struct socket *)qp->tx;
	sockets.rx = (struct socket *)qp->rx;
	sockets.dir = 0;
	if (IS_ERR_OR_NULL((struct socket *)(qp->rx)) || IS_ERR_OR_NULL((struct socket *)qp->tx))
		goto out;

	TRACE_DEBUG("starting half duplex %d", atomic_read(&qp->ref_cnt));
	half_duplex(&sockets, qp);
out:
	rx = NULL;
	TRACE_PRINT(" Closing [L] "TCP4" => "TCP4" (%d)",
			TCP4N(&cli_addr.sin_addr, ntohs(cli_addr.sin_port)),
			TCP4N(&addr.sin_addr, ntohs(addr.sin_port)), mark);
	/* Teardown */
	/* free both sockets*/
	rc = line = 0;

create_fail:
	if (rx)  {/* Will happen only on Connection fail:
		   1. PANIC: When Wait QP fails, socket released and unmatched peer crushes. - see how qp_get/put api could be used, consider states and GC.
		   2. TOCTOU BUG is possible culptit, not the same as desirebd as the check always turns our with NULL - Rechek qp_exists.
		   */
		TRACE_PRINT("RELEASING SOCK!");
		sock_release(rx);
	}
	if (rc)
		TRACE_PRINT("out [%d - %d]", rc, ++line);
	DUMP_TRACE
	return rc;
}

static inline struct cbn_listner *register_server_sock(uint32_t tid, struct socket *sock)
{
	int cpu;
	struct cbn_listner *server = kmem_cache_alloc(listner_slab, GFP_KERNEL);
	if (!server)
		return NULL;

	server->connections_root = alloc_reserved_percpu(struct cbn_root_qp);
	if (unlikely( ! server->connections_root)) {
		TRACE_ERROR("Failed to register listner %u [%d]", tid, -ENOMEM);
		kmem_cache_free(listner_slab, server);
		return NULL;
	}

	server->connections_list = alloc_reserved_percpu(struct cbn_list_qp);
        if (unlikely( ! server->connections_list)) {
                TRACE_ERROR("Failed to register listner %u [%d], list qp alloc", tid, -ENOMEM);
                kmem_cache_free(listner_slab, server);
                return NULL;
        }

        for_each_possible_cpu(cpu) {
		struct cbn_list_qp *list;
                struct cbn_root_qp *root = per_cpu_ptr(server->connections_root, cpu);
                if(!root){
                        TRACE_ERROR("Failed to get per cpu ptr for connection root. tid: %u cpu: [%d]", tid, cpu);
                        kmem_cache_free(listner_slab, server);
                        return NULL;
                }
                list = per_cpu_ptr(server->connections_list, cpu);
                if(!list){
                        TRACE_ERROR("Failed to get per cpu ptr for connection list. tid: %u cpu: [%d]", tid, cpu);
                        kmem_cache_free(listner_slab, server);
                        return NULL;
                }

		spin_lock_init(&root->rb_lock);
		spin_lock_init(&list->list_lock);

		root->root 	= RB_ROOT;
		INIT_LIST_HEAD(&list->list);
	}

	server->key			= tid;
	server->sock 			= sock;

	add_rb_listner(&listner_root, server);
	return server;
}

static int split_server(void *mark_port)
{
	int rc = 0;
	struct socket *sock = NULL;
	struct sockaddr_in srv_addr;
	struct cbn_listner *server = NULL;
	u32 mark, port;

	INIT_TRACE

	void2uint(mark_port, &mark, &port);
	if (search_rb_listner(&listner_root, mark)) {
		rc = -EEXIST;
		TRACE_ERROR("server exists: %d @ %d", mark, port);
		goto error;
	}

	server = register_server_sock(mark, sock);
	if (!server) {
		TRACE_ERROR("Failed to alloc memory for new server!!!!");
		goto error;
	}

	server->status = 1;
	if ((rc = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock)))
		goto error;

	server->sock = sock;
	server->port = port;
	server->status = 2;

	if ((rc = kernel_setsockopt(sock, SOL_SOCKET, SO_MARK, (char *)&mark, sizeof(u32))) < 0)
		goto error;

	server->status = 3;
	srv_addr.sin_family 		= AF_INET;
	srv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	srv_addr.sin_port 		= htons(port);

	if ((rc = kernel_bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr))))
		goto error;

	server->status = 4;
	TRACE_PRINT("tenant %d: new listner on port %d", mark, port);
	if ((rc = kernel_listen(sock, BACKLOG)))
		goto error;

	server->status = 5;
	TRACE_PRINT("create a new probe socket %d", mark);
	server->raw  = craete_prec_conn_probe(mark);
	if (!server->raw)
		goto error;

	server->status = 6;
	TRACE_PRINT("accepting on port %d", port);
	do {
		struct socket *nsock;
		struct cbn_qp *qp;

		rc = kernel_accept(sock, &nsock, 0);
		if (unlikely(rc))
			goto out;

		qp = kmem_cache_alloc(qp_slab, GFP_KERNEL);
		qp->rx 		= nsock;
		qp->tid 	= mark;
		qp->listner 	= server;
		atomic_set(&qp->ref_cnt, 0);
		init_waitqueue_head(&qp->wait);
		kthread_pool_run(&cbn_pool, start_new_connection, qp);

	} while (!kthread_should_stop());
	server->status = 6;
error:
	TRACE_PRINT("Exiting %d <%d>\n", rc, (server) ? server->status : -1);
	if(server != NULL){
		remove_listner_server(server);
	}
out:
	if (sock)
		sock_release(sock);
	DUMP_TRACE
	return rc;
}

void add_server_cb(int tid, int port)
{
	pr_info("%s scheduling split server <%d>\n", __FUNCTION__, tid);
	kthread_pool_run(&cbn_pool, split_server, uint2void(tid, port));
}

void del_server_cb(int tid)
{
	struct cbn_listner *listner = search_rb_listner(&listner_root, tid);
	if (listner) {
		pr_info("%s stopping split server <%d>\n", __FUNCTION__, tid);
		remove_listner_server(listner);
	} else {
		pr_warn("%s ERROR: split server <%d> not running\n", __FUNCTION__, tid);
	}
}

inline char *proc_read_string(int *loc)
{
	struct cbn_listner *pos, *tmp;
	int  idx = 0;
	char *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!buffer)
		return NULL;

	rbtree_postorder_for_each_entry_safe(pos, tmp, &listner_root, node) {
		idx += sprintf(&buffer[idx],"tid=%d port=%d status=%d\n",
			       pos->key, pos->port, pos->status);
	}
	*loc = idx;
	return buffer;
}

static inline void parse_module_params(void)
{
	if (pool_size > 0) {
		cbn_pool.pool_size = pool_size;
	}
}

static void qp_ctor(void *elem)
{
	memset(elem, 0, sizeof (sizeof(struct cbn_qp)));
}

static int __init cbn_datapath_init(void)
{
	parse_module_params();
	pr_info("Starting KTCP [%d] %s\n", cbn_pool.pool_size, KTCP_VERSION);

	if (init_kallsyms()) {
		TRACE_ERROR("Failed to init kallsyms ptrs");
		return -1;
	}

	qp_slab = kmem_cache_create("cbn_qp_mdata",
					sizeof(struct cbn_qp), 0, 0, qp_ctor);

	listner_slab = kmem_cache_create("cbn_listner",
					 sizeof(struct cbn_listner), 0, 0, NULL);

	syn_slab = kmem_cache_create("cbn_syn_mdata",
					sizeof(struct addresses), 0, 0, NULL);
	probe_slab = kmem_cache_create("cbn_probe_headers",
					sizeof(struct probe), 0, 0, NULL);
	cbn_kthread_pool_init(&cbn_pool);
	cbn_pre_connect_init();
	nf_register_net_hooks(&init_net, cbn_nf_hooks, ARRAY_SIZE(cbn_nf_hooks));
	cbn_proc_init();
	return 0;
}

static void __exit cbn_datapath_clean(void)
{
	TRACE_PRINT("Removing proc");
	cbn_proc_clean();
	TRACE_PRINT("Removing nf");
	nf_unregister_net_hooks(&init_net, cbn_nf_hooks,  ARRAY_SIZE(cbn_nf_hooks));
	TRACE_PRINT("Removing pre-connections");
	cbn_pre_connect_end();
	TRACE_PRINT("Stop sockets");
	stop_sockets();
	TRACE_PRINT("sockets stopped");
	cbn_kthread_pool_clean(&cbn_pool);
	TRACE_PRINT("proxies stopped");
	kmem_cache_destroy(qp_slab);
	kmem_cache_destroy(syn_slab);
	kmem_cache_destroy(probe_slab);
	kmem_cache_destroy(listner_slab);
}

module_init(cbn_datapath_init);
module_exit(cbn_datapath_clean);

