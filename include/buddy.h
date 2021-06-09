/*
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _BUDDY_H_
#define _BUDDY_H_

typedef void *buddy_t;

buddy_t buddy_create(unsigned int nmemb, unsigned int size);
void buddy_destroy(buddy_t buddy);
void *buddy_alloc(buddy_t buddy, int size);
void *buddy_base(buddy_t buddy);
unsigned int buddy_size(buddy_t buddy);
unsigned int buddy_nmemb(buddy_t buddy);
void buddy_free(buddy_t buddy, void *addr);

#endif
