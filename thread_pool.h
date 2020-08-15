#ifndef __CBN_KTHREAD_POOL__
#define __CBN_KTHREAD_POOL__

#include "lib/magazine.h"

struct kthread_pool {
	atomic_t top_count;				//TODO: add spin_lock - need to protect lists and counters
	int refil_needed;
	int pool_size;				// TODO:Modify with debugfs or module param
	struct kmem_cache *pool_slab;
	struct task_struct *refil;
	//
	struct mag_allocator allocator;
/* FIXME:
	struct list_head kthread_running;
	spinlock_t running_lock;
*/
};

struct pool_elem {
	struct list_head list;
	struct kthread_pool *pool;
	struct task_struct *task;
	int (*pool_task)(void *data);
	void *data;

	union {
		uint64_t _unspec[2];		// TODO:can be variable size, just need to tell cache_init
	};
};

struct pool_elem *kthread_pool_run(struct kthread_pool *cbn_pool, int (*func)(void *), void *data);
struct pool_elem *kthread_pool_run_cpu(struct kthread_pool *cbn_pool,
					int (*func)(void *), void *data, unsigned int cpu);

int __init cbn_kthread_pool_init(struct kthread_pool *cbn_pool);
void __exit cbn_kthread_pool_clean(struct kthread_pool *cbn_pool);

void refill_task_start(struct kthread_pool *cbn_pool);
#define DEF_CBN_POOL_SIZE 64

#endif /* __CBN_KTHREAD_POOL__ */
