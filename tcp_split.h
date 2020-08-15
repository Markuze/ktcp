#ifndef __CBN_DATAPATH_H__
#define __CBN_DATAPATH_H__

#include <linux/percpu-rwsem.h>
#include "cbn_common.h"

#define QP_TO			90
#define PRECONN_SERVER_PORT	5565
#define CBN_CORE_ROUTE_MARK   ((UINT_MAX >> 1) + 1)   //0x80000000U

//Lowest official IANA unassigned port
#define CBP_PROBE_PORT 	4
#define RB_KEY_LENGTH 12

#define TX_QP	0
#define RX_QP	1

#define VANILA_KERNEL
#ifdef VANILA_KERNEL
#include <linux/kallsyms.h>

typedef long (*setaffinity_func)(pid_t, const struct cpumask *);
typedef void (*bind_mask_func)(struct task_struct *, const struct cpumask *);
typedef void __percpu *(*alloc_percpu_func)(size_t , size_t);

extern setaffinity_func psched_setaffinity;
extern bind_mask_func  pkthread_bind_mask;
extern alloc_percpu_func  p__alloc_reserved_percpu;

#define sched_setaffinity(...)		(*psched_setaffinity)(__VA_ARGS__)
#define kthread_bind_mask(...)		(*pkthread_bind_mask)(__VA_ARGS__)
#define __alloc_reserved_percpu(...)	(*p__alloc_reserved_percpu)(__VA_ARGS__)
#endif

#define alloc_reserved_percpu(type)					\
	(typeof(type) __percpu *)__alloc_reserved_percpu(sizeof(type),	\
					__alignof__(type))
struct cbn_list_qp {
	struct list_head 	list;
	spinlock_t 		list_lock;
};

struct cbn_root_qp {
	struct rb_root  root;
	spinlock_t 	rb_lock;
};

struct cbn_listner {
	struct rb_node 	node;
	struct cbn_root_qp __percpu *connections_root; /* per core variable*/
	struct cbn_list_qp __percpu *connections_list; /* per core variable*/
	int32_t		key; //tid
	uint16_t	port;
	uint16_t	status;
	struct socket	*sock;
	struct socket	*raw;
};

struct cbn_qp {
	struct rb_node node;
	union {
		char key[RB_KEY_LENGTH];
		struct {
			__be16		port_s;	/* Port number			*/
			__be16		port_d;	/* Port number			*/
			struct in_addr	addr_s;	/* Internet address		*/
			struct in_addr	addr_d;	/* Internet address		*/
		};
		struct {
			int tid;

		};
	};
	atomic_t ref_cnt;

	struct cbn_listner 	*listner;
	struct list_head 	list;
	wait_queue_head_t	wait;
	spinlock_t 		lock;
	union {
		struct {
			struct socket	*tx;
			struct socket	*rx;
		};
		struct socket *qp_dir[2]; //TODO: volatile
	};
};


struct sockets {
	struct socket *rx;
	struct socket *tx;
	int 	dir;
};

struct addresses {
	struct sockaddr_in dest;
	struct sockaddr_in src;
	struct in_addr	sin_addr;
	int mark;
};

struct probe {
	struct iphdr iphdr;
	struct tcphdr tcphdr;
	struct cbn_listner *listner;
};

#define UINT_SHIFT	32

int half_duplex(struct sockets *sock, struct cbn_qp *qp);
unsigned int put_qp(struct cbn_qp *qp);
void get_qp(struct cbn_qp *qp);
void dump_qp(struct cbn_qp *qp, const char *str);

void add_server_cb(int tid, int port);
void del_server_cb(int tid);
void preconn_write_cb(int *);
char* proc_read_string(int *);

struct socket *craete_prec_conn_probe(u32 mark);

int __init cbn_pre_connect_init(void);
int __exit cbn_pre_connect_end(void);

int start_probe_syn(void *arg);
int start_new_connection_syn(void *arg);
int wait_qp_ready(struct cbn_qp* qp, uint8_t dir);
struct cbn_qp *qp_exists(struct cbn_qp* pqp, uint8_t dir);
unsigned int addresses2cpu(struct addresses *addr);
void* uint2void(uint32_t a, uint32_t b);
void void2uint(void *ptr, uint32_t *a, uint32_t *b);
unsigned int qp2cpu(struct cbn_qp *qp);


int tcp_read_sock_zcopy_blocking(struct socket *sock, struct kvec *pages_array,
					unsigned int nr_pages);
int tcp_read_sock_zcopy(struct socket *sock, struct kvec *pages_array,
			unsigned int nr_pages);
#endif /*__CBN_DATAPATH_H__*/
