/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#ifndef _LIBNVMF_LOG_
#define _LIBNVMF_LOG_

#include <pthread.h>
#include <stdio.h>
#include <time.h>

#include "types.h"
#include "nvmf.h"

#define LOG_LEVEL_DEBUG 2
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_ERROR 0

#define MAX_LOG_BUFFER 2048

extern nvmf_log_fn g_log_fn;
extern int g_log_level;
extern const char *log_level_tag[5];

extern __thread char thread_name_buff[17];
extern __thread const char *thread_name;

void nvmf_log_message(int log_level, const char *fmt, ...);

#define log_impl(level, fmt, args...) \
do {                                            \
        time_t t = time(NULL);                        \
        if (unlikely(!thread_name)) {                  \
            pthread_getname_np(pthread_self(), thread_name_buff, sizeof(thread_name_buff)); \
            thread_name = thread_name_buff;         \
        }                                              \
        nvmf_log_message(level, "%16s %24.24s %s %s:%d] " fmt, thread_name, ctime(&t),       \
           log_level_tag[level], __FILE__, __LINE__, ##args);  \
    } while (0)

#define log_error(fmt, args...)    log_impl(LOG_LEVEL_ERROR, fmt, ##args)

#define log_warn(fmt, args...)    log_impl(LOG_LEVEL_WARN, fmt, ##args)

#ifdef DEBUG
#define log_debug(fmt, args...)    log_impl(LOG_LEVEL_DEBUG, fmt, ##args)

#define log_trace()        log_debug("TRACE %s\n", __func__)
#else
#define log_debug(fmt, args...)    do {} while (0)

#define log_trace()        do {} while (0)
#endif

#endif    /* _LIBNVMF_LOG_ */
