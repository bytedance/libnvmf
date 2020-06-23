/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "slab.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct slab_s {
	char name[32];
	unsigned int size;
	unsigned int objects;
	unsigned long *bitmap;
	char *base;
};

#define BITS_OF_UL	(sizeof(unsigned long) * 8)
#define ALIGNUP(x, y)	((x + y - 1) & ~(y - 1))

static inline void set_bit(unsigned long *val, unsigned int bit)
{
	*val |= (1UL << bit);
}

static inline void clear_bit(unsigned long *val, unsigned int bit)
{
	*val &= ~(1UL << bit);
}

slab_t slab_create(const char *name, unsigned int size, unsigned int objects)
{
	struct slab_s *__slab;
	unsigned long *ptr;
	unsigned int bits, index;

	__slab = (struct slab_s *)calloc(1, sizeof(*__slab));
	if (!__slab) {
		goto fail;
	}

	bits = ALIGNUP(objects, BITS_OF_UL);
	__slab->bitmap = (unsigned long *)calloc(1, bits / 8);
	if (!__slab->bitmap) {
		goto fail;
	}

	/* mark all available bits */
	for (index = 0; index < objects; index++) {
		ptr = __slab->bitmap + (index / BITS_OF_UL);
		set_bit(ptr, index % BITS_OF_UL);
	}

	__slab->base = (char *)malloc(size * objects);
	if (!__slab->base) {
		goto fail;
	}

	__slab->objects = objects;
	__slab->size = size;
	snprintf(__slab->name, sizeof(__slab->name), "%s", name);

	return __slab;

fail:
	free(__slab->base);
	free(__slab->bitmap);
	free(__slab);

	return NULL;
}

void slab_destroy(slab_t slab)
{
	struct slab_s *__slab = (struct slab_s *)slab;

	free(__slab->base);
	free(__slab->bitmap);
	free(__slab);
}

void *slab_alloc(slab_t slab)
{
	struct slab_s *__slab = (struct slab_s *)slab;
	unsigned long *ptr;
	unsigned int index, bits, found;

	bits = ALIGNUP(__slab->objects, BITS_OF_UL);
	for (index = 0; index < bits / BITS_OF_UL; index++) {
		ptr = __slab->bitmap + index;
		if (!*ptr) {
			continue;
		}

		found = __builtin_ffsl(*ptr);
		found--;
		clear_bit(ptr, found);
		assert(index * BITS_OF_UL + found < __slab->objects);

		return __slab->base + (index * BITS_OF_UL + found) * __slab->size;
	}

	return NULL;
}

static inline int __slab_index(slab_t slab, void *addr)
{
	struct slab_s *__slab = (struct slab_s *)slab;
	char *__addr = (char *)addr;
	int index;

	index = (__addr - __slab->base) / __slab->size;
	assert(index < __slab->objects);

	return index;
}

void slab_free(slab_t slab, void *addr)
{
	struct slab_s *__slab = (struct slab_s *)slab;
	unsigned long *ptr;
	int index;

	index = __slab_index(slab, addr);
	ptr = __slab->bitmap + index / BITS_OF_UL;
	set_bit(ptr, index % BITS_OF_UL);
}

int slab_index(slab_t slab, void *addr)
{
	return __slab_index(slab, addr);
}

void *slab_base(slab_t slab)
{
	struct slab_s *__slab = (struct slab_s *)slab;

	return __slab->base;
}
