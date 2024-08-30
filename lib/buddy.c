/*
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "buddy.h"

struct buddy {
    unsigned int nmemb;
    unsigned int size;
    char *base;
    unsigned int meta[0];
};

#define L_LEAF(index) ((index) * 2 + 1)
#define R_LEAF(index) ((index) * 2 + 2)
#define PARENT(index) (((index) + 1) / 2 - 1)

#define IS_POWER_OF_2(x) (!((x) & ((x) - 1)))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* for debug purpose, re-define them by nvmf_malloc/nvmf_free */
#define MALLOC malloc
#define FREE free

static inline unsigned int roundup_power_of_2(unsigned int val)
{
    return sizeof(unsigned int) * 8 - __builtin_clz(val);
}

buddy_t buddy_create(unsigned int nmemb, unsigned int size)
{
    struct buddy *buddy;
    unsigned int nodes, i;

    if (!IS_POWER_OF_2(nmemb)) {
        return NULL;
    }

    nodes = nmemb * 2;
    buddy = (struct buddy *)MALLOC(sizeof(struct buddy) + sizeof(unsigned int) * nodes);
    if (!buddy) {
        return NULL;
    }

    buddy->base = (char *)MALLOC(size * nmemb);
    if (!buddy->base) {
        goto fail;
    }

    buddy->nmemb = nmemb;
    buddy->size = size;

    for (i = 0; i < buddy->nmemb * 2 - 1; i++) {
        if (IS_POWER_OF_2(i + 1)) {
            nodes /= 2;
        }

        buddy->meta[i] = nodes;
    }

    return buddy;

fail:
    FREE(buddy);
    return NULL;
}

void buddy_destroy(buddy_t buddy)
{
    struct buddy *__buddy = (struct buddy *)buddy;

    FREE(__buddy->base);
    FREE(__buddy);
}

void *buddy_base(buddy_t buddy)
{
    struct buddy *__buddy = (struct buddy *)buddy;

    return __buddy->base;
}

unsigned int buddy_size(buddy_t buddy)
{
    struct buddy *__buddy = (struct buddy *)buddy;

    return __buddy->size;
}

unsigned int buddy_nmemb(buddy_t buddy)
{
    struct buddy *__buddy = (struct buddy *)buddy;

    return __buddy->nmemb;
}

void *buddy_alloc(buddy_t buddy, int size)
{
    struct buddy *__buddy = (struct buddy *)buddy;
    unsigned int index = 0;
    unsigned int nodes;
    unsigned int offset = 0;
    int alignup = (size + __buddy->size - 1) / __buddy->size;

    if (!IS_POWER_OF_2(alignup)) {
        alignup = roundup_power_of_2(alignup);
    }

    if (__buddy->meta[index] < alignup) {
        return NULL;
    }

    for (nodes = __buddy->nmemb; nodes != alignup; nodes /= 2) {
        if (__buddy->meta[L_LEAF(index)] >= alignup) {
            index = L_LEAF(index);
        } else {
            index = R_LEAF(index);
        }
    }

    __buddy->meta[index] = 0;
    offset = (index + 1) * nodes - __buddy->nmemb;

    while (index) {
        index = PARENT(index);
        __buddy->meta[index] = MAX(__buddy->meta[L_LEAF(index)], __buddy->meta[R_LEAF(index)]);
    }

    return __buddy->base + offset * __buddy->size;
}

void buddy_free(buddy_t buddy, void *addr)
{
    struct buddy *__buddy = (struct buddy *)buddy;
    unsigned int nodes, index = 0;
    unsigned int left_meta, right_meta, offset;

    offset = ((char *)addr - __buddy->base) / __buddy->size;
    if (offset * __buddy->size + __buddy->base != addr) {
        assert(0);
    }

    nodes = 1;
    index = offset + __buddy->nmemb - 1;

    for (; __buddy->meta[index]; index = PARENT(index)) {
        nodes *= 2;
        if (index == 0) {
            return;
        }
    }

    __buddy->meta[index] = nodes;

    while (index) {
        index = PARENT(index);
        nodes *= 2;

        left_meta = __buddy->meta[L_LEAF(index)];
        right_meta = __buddy->meta[R_LEAF(index)];

        if (left_meta + right_meta == nodes) {
            __buddy->meta[index] = nodes;
        } else {
            __buddy->meta[index] = MAX(left_meta, right_meta);
        }
    }
}
