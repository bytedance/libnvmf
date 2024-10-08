/*
 * Copyright 2020-2022 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _LIBNVMF_UTILS_
#define _LIBNVMF_UTILS_
#include <stddef.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/* compare macros */
#define min(x, y)                                                                                  \
    ({                                                                                             \
        typeof(x) _x = (x);                                                                        \
        typeof(y) _y = (y);                                                                        \
        (void)(&_x == &_y);                                                                        \
        _x < _y ? _x : _y;                                                                         \
    })

#define max(x, y)                                                                                  \
    ({                                                                                             \
        typeof(x) _x = (x);                                                                        \
        typeof(y) _y = (y);                                                                        \
        (void)(&_x == &_y);                                                                        \
        _x > _y ? _x : _y;                                                                         \
    })

#define min_t(type, a, b) min(((type)a), ((type)b))
#define max_t(type, a, b) max(((type)a), ((type)b))

static inline unsigned long nvmf_now_ms(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0) {
        return -1;
    }

    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static inline unsigned long nvmf_now_us(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0) {
        return -1;
    }

    return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

static inline int nvmf_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static inline size_t nvmf_iov_datalen(struct iovec *iovs, int iovcnt)
{
    size_t datalen = 0;
    int index;

    for (index = 0; index < iovcnt; index++) {
        datalen += iovs[index].iov_len;
    }

    return datalen;
}

static inline size_t nvmf_iov_to_buf(struct iovec *iovs, int iovcnt, char *buf)
{
    struct iovec *iov;
    size_t datalen = 0;
    int index;

    for (index = 0; index < iovcnt; index++) {
        iov = iovs + index;
        memcpy(buf + datalen, iov->iov_base, iov->iov_len);
        datalen += iov->iov_len;
    }

    return datalen;
}

static inline size_t nvmf_buf_to_iov(struct iovec *iovs, int iovcnt, char *buf)
{
    struct iovec *iov;
    size_t datalen = 0;
    int index;

    for (index = 0; index < iovcnt; index++) {
        iov = iovs + index;
        memcpy(iov->iov_base, buf + datalen, iov->iov_len);
        datalen += iov->iov_len;
    }

    return datalen;
}

/* Duplicate iovec */
static inline void nvmf_iov_dup(const struct iovec *src_iovs, struct iovec *dst_iovs,
                                unsigned int num_iov)
{
    memcpy(dst_iovs, src_iovs, sizeof(struct iovec) * num_iov);
}

/* Skip @offset, build from @src_iovs to @dst_iovs of @bytes.
 */
static inline unsigned int nvmf_iov_copy(struct iovec *src_iovs, unsigned int src_num_iov,
                                         unsigned int offset, unsigned int bytes,
                                         struct iovec *dst_iovs)
{
    struct iovec *src_iov = NULL, *dst_iov;
    unsigned int dst_num_iov = 0, i;

    /* skip @offset bytes */
    for (i = 0; i < src_num_iov; i++) {
        src_iov = &src_iovs[i];
        if (src_iov->iov_len > offset) {
            break;
        }

        offset -= src_iov->iov_len;
    }

    /* no more space? */
    if ((i == src_num_iov) || !src_iov) {
        return 0;
    }

    /* any remaining bytes in the first iov? */
    dst_iov = &dst_iovs[dst_num_iov++];
    dst_iov->iov_base = (unsigned char *)src_iov->iov_base + offset;
    dst_iov->iov_len = min_t(unsigned int, src_iov->iov_len - offset, bytes);
    bytes -= dst_iov->iov_len;
    if (!bytes) {
        return dst_num_iov;
    }

    /* copy the remaining iov */
    for (i++; i < src_num_iov; i++, dst_num_iov++) {
        src_iov = &src_iovs[i];
        dst_iov = &dst_iovs[dst_num_iov];
        dst_iov->iov_base = src_iov->iov_base;
        dst_iov->iov_len = min_t(unsigned int, src_iov->iov_len, bytes);
        bytes -= dst_iov->iov_len;
        if (!bytes) {
            break;
        }
    }

    return dst_num_iov + 1;
}

#ifdef MALLOC_DEBUG
#define nvmf_calloc(x, y) _nvmf_calloc(x, y, __func__, __LINE__)
#define nvmf_malloc(x) _nvmf_malloc(x, __func__, __LINE__)
#define nvmf_free(x) _nvmf_free(x, __func__, __LINE__)
#define nvmf_strndup(x, y) _nvmf_strndup(x, y, __func__, __LINE__)
void nvmf_malloc_init(void);
void *_nvmf_calloc(size_t nmemb, size_t size, const char *file, int line);
void *_nvmf_malloc(size_t size, const char *file, int line);
void _nvmf_free(void *ptr, const char *file, int line);
char *_nvmf_strndup(const char *s, size_t n, const char *file, int line);
#else
void nvmf_malloc_init(void);
void *nvmf_calloc(size_t nmemb, size_t size);
void *nvmf_malloc(size_t size);
void nvmf_free(void *ptr);
char *nvmf_strndup(const char *s, size_t n);
#endif

#endif /* _LIBNVMF_UTILS_ */
