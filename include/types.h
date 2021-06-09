/*
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _LIBNVMF_TYPES_
#define _LIBNVMF_TYPES_

#include <stdint.h>
#include <stdbool.h>
#include <bits/types.h>
#include <linux/types.h>

/* uuid types */
#define UUID_SIZE 16

typedef struct {
	__u8 b[UUID_SIZE];
} uuid_t;

/* likely & unlikely */
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

/* NULL */
#ifndef NULL
#define NULL    ((void *)0)
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			\
		const typeof(((type *)0)->member) * __mptr = (ptr);	\
		(type *)((char *)__mptr - offsetof(type, member)); })
#endif

static inline void set_unaligned_le24(__u8 *p, __u32 val)
{
        *p++ = val;
        *p++ = val >> 8;
        *p++ = val >> 16;
}

static inline void set_unaligned_le32(__u8 *p, __u32 val)
{
        *p++ = val;
        *p++ = val >> 8;
        *p++ = val >> 16;
        *p++ = val >> 24;
}

#endif /* __LIBNVMF_TYPES__ */
