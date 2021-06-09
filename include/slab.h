/*
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _SLAB_
#define _SLAB_

typedef void *slab_t;

slab_t slab_create(const char *name, unsigned int size, unsigned int objects);
void slab_destroy(slab_t slab);
void *slab_alloc(slab_t slab);
void slab_free(slab_t slab, void *addr);
int slab_index(slab_t slab, void *addr);
void *slab_base(slab_t slab);
unsigned int slab_size(slab_t slab);
unsigned int slab_objects(slab_t slab);

#endif
