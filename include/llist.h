/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#ifndef _LLIST_H_
#define _LLIST_H_
#include "types.h"

struct llist_head {
	struct llist_node *first;
};


struct llist_node {
	struct llist_node *next;
};


#define llist_entry(ptr, type, member) container_of(ptr, type, member)

#define llist_for_each(pos, node)	\
	for ((pos) = (node); pos; (pos) = (pos)->next)

#define llist_for_each_entry(pos, node, member)	\
	for ((pos) = llist_entry((node), typeof(*(pos)), member);	\
	     &(pos)->member != NULL;	\
	     (pos) = llist_entry((pos)->member.next, typeof(*(pos)), member))

#define member_address_is_nonnull(ptr, member)  \
        ((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)

#define llist_for_each_entry_safe(pos, n, node, member)	\
        for (pos = llist_entry((node), typeof(*pos), member);	\
             member_address_is_nonnull(pos, member) &&	\
	     (n = llist_entry(pos->member.next, typeof(*n), member), true);	\
             pos = n)


static inline void llist_head_init(struct llist_head *list)
{
	list->first = NULL;
}

static inline void llist_node_init(struct llist_node *list)
{
	list->next = NULL;
}

static inline bool llist_empty(const struct llist_head *head)
{
	return !__atomic_load_n(&head->first, __ATOMIC_SEQ_CST);
}

static inline struct llist_node *llist_next(struct llist_node *node)
{
	return node->next;
}

static inline struct llist_node *llist_add(struct llist_node *new, struct llist_head *head)
{
	struct llist_node *entry;

	do {
		entry = head->first;
		new->next = entry;
	} while (!__atomic_compare_exchange_n(&head->first, &entry, new, 0, __ATOMIC_SEQ_CST,
                 __ATOMIC_SEQ_CST));

	return entry;
}

static inline struct llist_node *llist_del_all(struct llist_head *head)
{
	return __atomic_exchange_n(&head->first, NULL, __ATOMIC_SEQ_CST);
}

#endif /* __LLIST_H__ */
