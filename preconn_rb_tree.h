#ifndef __CBN_PRECONN_RB__TREE_H__
#define __CBN_PRECONN_RB__TREE_H__

#include <linux/rbtree.h>
#include <linux/types.h> //atomic_t
#include "cbn_common.h"

#define PER_CORE_POOL_MIN 4
#define PER_CORE_POOL_MAX 16

struct percpu_list {
	struct list_head 		list;
	uint32_t 			len;
};

struct cbn_preconnection {
	struct rb_node			node;
	struct percpu_list __percpu	*pcp_list;
	int32_t				key;
};

static inline int init_preconn(struct cbn_preconnection *preconn, int32_t key)
{
	int cpu;

	preconn->key = key;
	preconn->pcp_list = alloc_reserved_percpu(struct percpu_list);
	if (!preconn->pcp_list)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct percpu_list *pcpl = per_cpu_ptr(preconn->pcp_list, cpu);
		INIT_LIST_HEAD(&pcpl->list);
		pcpl->len = 0;
	}
	return 0;
}

static inline struct cbn_preconnection *search_rb_preconn(struct rb_root *root,
								int32_t key, rwlock_t *rw_lock)
{
	struct rb_node *node = root->rb_node;

	read_lock(rw_lock);
	while (node) {
		struct cbn_preconnection *this = container_of(node, struct cbn_preconnection, node);

		int32_t result = key - this->key;

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			read_unlock(rw_lock);
			return this;
		}
	}
	read_unlock(rw_lock);
	return NULL;
}

static inline struct cbn_preconnection *add_rb_preconn(struct rb_root *root, rwlock_t *rw_lock,
							struct cbn_preconnection *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	write_lock(rw_lock);
	while (*new) {
		struct cbn_preconnection *this = container_of(*new, struct cbn_preconnection, node);
		int32_t result = data->key - this->key;

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else {
			write_unlock(rw_lock);
			return this; //Return the duplicat
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	write_unlock(rw_lock);
	return NULL;
}
/*
 * TODO: R/W lock will be needed.
 * */
static inline struct cbn_preconnection *get_rb_preconn(struct rb_root *root, int32_t key,  rwlock_t *rw_lock,
							struct kmem_cache *cache, gfp_t flags)
{
	struct cbn_preconnection *preconn = search_rb_preconn(root, key, rw_lock);
	if (likely(preconn)) {
		return preconn;
	}

	preconn = kmem_cache_alloc(cache, flags);
	if (unlikely(!preconn))
		return NULL;

	if (init_preconn(preconn, key))
		kmem_cache_free(cache, preconn);

	if (add_rb_preconn(root, rw_lock, preconn)) {
		TRACE_ERROR("%s found a duplicate\n", __FUNCTION__);
		kmem_cache_free(cache, preconn);
		return NULL;
	}
	return preconn;
}
#endif /*__CBN_PRECONN_RB__TREE_H__*/
