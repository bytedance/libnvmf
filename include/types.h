/*
 * Copyright 2020-2022 zhenwei pi
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

/**
 * taken from linux/include/uapi/linux/stddef.h
 * __struct_group() - Create a mirrored named and anonyomous struct
 *
 * @TAG: The tag name for the named sub-struct (usually empty)
 * @NAME: The identifier name of the mirrored sub-struct
 * @ATTRS: Any struct attributes (usually empty)
 * @MEMBERS: The member declarations for the mirrored structs
 *
 * Used to create an anonymous union of two structs with identical layout
 * and size: one anonymous and one named. The former's members can be used
 * normally without sub-struct naming, and the latter can be used to
 * reason about the start, end, and size of the group of struct members.
 * The named struct can also be explicitly tagged for layer reuse, as well
 * as both having struct attributes appended.
 */
#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
        union { \
                struct { MEMBERS } ATTRS; \
                struct TAG { MEMBERS } ATTRS NAME; \
        }

/**
 * taken from linux/include/linux/stddef.h
 * struct_group() - Wrap a set of declarations in a mirrored struct
 *
 * @NAME: The identifier name of the mirrored sub-struct
 * @MEMBERS: The member declarations for the mirrored structs
 *
 * Used to create an anonymous union of two structs with identical
 * layout and size: one anonymous and one named. The former can be
 * used normally without sub-struct naming, and the latter can be
 * used to reason about the start, end, and size of the group of
 * struct members.
 */
#define struct_group(NAME, MEMBERS...)  \
        __struct_group(/* no tag */, NAME, /* no attrs */, MEMBERS)

#endif /* __LIBNVMF_TYPES__ */
