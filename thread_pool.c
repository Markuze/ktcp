#include <linux/init.h>      // included for __init and __exit macros
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "cbn_common.h"
#include "tcp_split.h"	//kthread_bind define
#include "thread_pool.h"

#define POOL_PRINT(...)
//#define POOL_PRINT TRACE_PRINT
#define POOL_ERR TRACE_PRINT

#define cbn_list_del(x) {POOL_PRINT("list_del(%d:%s): %p {%p, %p}", __LINE__, current->comm, x, (x)->next, (x)->prev); list_del((x));}
#define cbn_list_add(x, h) {POOL_PRINT("list_add(%d:%s): %p {%p, %p} h %p {%p, %p}", 	\
					__LINE__, current->comm,			\
					x, (x)->next, (x)->prev,			\
					h, (h)->next, (h)->prev);			\
					list_add((x), (h));}

static void kthread_pool_reuse(struct kthread_pool *cbn_pool, struct pool_elem *elem)
{
	mag_free_elem(&cbn_pool->allocator, elem);
}

static int pipe_loop_task(void *data)
{
	struct pool_elem *elem = data;
	struct kthread_pool *pool = elem->pool;

	while (!kthread_should_stop()) {
		POOL_PRINT("running %s", current->comm);
		if (elem->pool_task)
			elem->pool_task(elem->data);
		else
			POOL_ERR("ERROR %s: no pool task", __FUNCTION__);

		POOL_PRINT("sleeping %s", current->comm);
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!kthread_should_stop()) {
			POOL_PRINT("%s out to reuse <%p>", current->comm, current);
			elem->pool_task = NULL;
			kthread_pool_reuse(pool, elem);
			schedule();
		}
		__set_current_state(TASK_RUNNING);
	}
	return 0;
}

static int (*threadfn)(void *data) = pipe_loop_task;

static inline void refill_pool(struct kthread_pool *cbn_pool)
{
	int count = (cbn_pool->pool_size - (cbn_pool->allocator.full_count << 2));

	POOL_PRINT("pool %p count %d[%d]", cbn_pool, count, cbn_pool->pool_size);
	count = (count < 0) ? 0 : count;
	while (count--) {
		int top_count;
		struct task_struct *k;
		struct pool_elem *elem = kmem_cache_alloc(cbn_pool->pool_slab, GFP_ATOMIC);
		if (unlikely(!elem)) {
			TRACE_ERROR("ERROR: elem is NULL");
			return;
		}

		top_count = atomic_read(&cbn_pool->top_count);
		k = kthread_create(threadfn, elem, "pool-th-%d", top_count);

		if (unlikely(!k)) {
			TRACE_ERROR("ERROR: failed to create kthread %d", top_count);
			kmem_cache_free(cbn_pool->pool_slab, elem);
			return;
		}
		INIT_LIST_HEAD(&elem->list);
		elem->task = k;
		elem->pool = cbn_pool;
		elem->pool_task = NULL;
		mag_free_elem(&cbn_pool->allocator, elem);
		//TODO: change to atomic
		POOL_PRINT("pool thread %d [%p]", top_count, elem);
		atomic_inc(&cbn_pool->top_count);
	}
}

static int refil_thread(void *data)
{
	struct kthread_pool *cbn_pool = data;

	while (!kthread_should_stop()) {
		refill_pool(cbn_pool);

		set_current_state(TASK_INTERRUPTIBLE);
		if (!kthread_should_stop())
			schedule();
		__set_current_state(TASK_RUNNING);
	}
	POOL_PRINT("%s going out\n", __FUNCTION__);
	return 0;
}

void refill_task_start(struct kthread_pool *cbn_pool)
{
	wake_up_process(cbn_pool->refil);
}

static struct pool_elem *kthread_pool_alloc(struct kthread_pool *cbn_pool)
{
	struct pool_elem *elem = NULL;

	refill_task_start(cbn_pool);
	elem = mag_alloc_elem(&cbn_pool->allocator);
	while (unlikely(!elem)) {
		POOL_ERR("pool is empty refill is to slow\n");
		return NULL;
	}


	POOL_PRINT("allocated %p [%p]\n", elem, elem->task);
	return elem;
}

static struct pool_elem *__kthread_pool_run(struct kthread_pool *cbn_pool, int (*func)(void *), void *data, const struct cpumask * mask)
{
	struct pool_elem *elem = kthread_pool_alloc(cbn_pool);
	if (unlikely(!elem)) {
		TRACE_ERROR("Failed to alloc elem\n");
		return ERR_PTR(-ENOMEM);
	}

	if (unlikely(elem->pool_task)) {
		TRACE_ERROR("ERROR task allocated twice....!!!! <%s>", elem->task->comm);
	}

	elem->pool_task = func;
	elem->data = data;
//TODO: percore list	list_add(&elem->list, &cbn_pool->kthread_running);
//
	POOL_PRINT("staring %s\n", elem->task->comm);
	kthread_bind_mask(elem->task, mask);
	elem->task->flags &= ~PF_NO_SETAFFINITY;
	wake_up_process(elem->task);
	return elem;
}

struct pool_elem *kthread_pool_run_cpu(struct kthread_pool *cbn_pool,
					int (*func)(void *), void *data, unsigned int cpu)
{
	return __kthread_pool_run(cbn_pool, func, data, cpumask_of(cpu));
}
EXPORT_SYMBOL(kthread_pool_run_cpu);

struct pool_elem *kthread_pool_run(struct kthread_pool *cbn_pool, int (*func)(void *), void *data)
{
	return __kthread_pool_run(cbn_pool, func, data, cpu_possible_mask);
}
EXPORT_SYMBOL(kthread_pool_run);

int __init cbn_kthread_pool_init(struct kthread_pool *cbn_pool)
{
	TRACE_PRINT("starting: %s", __FUNCTION__);
//	INIT_LIST_HEAD(&cbn_pool->kthread_running);

	atomic_set(&cbn_pool->top_count, 0);
	mag_allocator_init(&cbn_pool->allocator);

	cbn_pool->pool_slab = kmem_cache_create("pool-thread-cache",
						sizeof(struct pool_elem), 0, 0, NULL);

	cbn_pool->refil = kthread_run(refil_thread, cbn_pool, "pool-cache-refill");

	//set_user_nice(cbn_pool->refil, MAX_NICE);
	return 0;
}
EXPORT_SYMBOL(cbn_kthread_pool_init);

void __exit cbn_kthread_pool_clean(struct kthread_pool *cbn_pool)
{
//	struct list_head *itr, *tmp;
	TRACE_PRINT("stopping: %s", __FUNCTION__);

	kthread_stop(cbn_pool->refil);

/* FIXME:
	list_for_each_safe(itr, tmp, &cbn_pool->kthread_pool) {
		struct pool_elem *task = container_of(itr, struct pool_elem, list);
		list_del(itr);
		TRACE_PRINT("stopping pool %s", task->task->comm);
		kthread_stop(task->task);
		kmem_cache_free(cbn_pool->pool_slab, task);
	}
	list_for_each_safe(itr, tmp, &cbn_pool->kthread_running) {
		struct pool_elem *task = container_of(itr, struct pool_elem, list);
		list_del(itr);
		TRACE_PRINT("stopping running %s", task->task->comm);
		kthread_stop(task->task);
		kmem_cache_free(cbn_pool->pool_slab, task);
	}
*/
	kmem_cache_destroy(cbn_pool->pool_slab);
	TRACE_PRINT("stopping: elements freed");
}
EXPORT_SYMBOL(cbn_kthread_pool_clean);

