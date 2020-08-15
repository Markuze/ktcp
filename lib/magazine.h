#ifndef  __MAGAZINE__H
#define  __MAGAZINE__H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define MAG_DEPTH	4
#define MAG_COUNT	2

//TODO:
//	1) Percpu
//	2) use list instead of array.
//
struct magazine {
	struct list_head 	list;
	void 			*stack[MAG_DEPTH];
};

struct mag_pair {
	union {
		struct magazine *mags[MAG_COUNT];
		uint64_t 	mag_ptr[MAG_COUNT];
	};
	u32		count[MAG_COUNT];
};

struct percpu_mag_pair {
	struct mag_pair	pair[2]; //Per Core instance x 2 (normal , and _bh)
};

struct mag_allocator {
	spinlock_t 				lock;
	u64 					lock_state;
	struct list_head 			empty_list;
	struct list_head 			full_list;
	uint16_t 				empty_count;
	uint16_t 				full_count;
	struct percpu_mag_pair	__percpu 	*pcp_pair; //Per Core instance x 2 (normal , and _bh)
};

void *mag_alloc_elem(struct mag_allocator *allocator);

void mag_free_elem(struct mag_allocator *allocator, void *elem);

void mag_allocator_init(struct mag_allocator *allocator);

//Need free and GC

#endif //__MAGAZINE__H
