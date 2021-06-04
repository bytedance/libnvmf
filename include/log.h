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

#define MAX_LOG_BUFFER 1024

extern const char *log_level_tag[];

extern __thread char thread_name_buff[17];
extern __thread const char *thread_name;

void nvmf_log_message(nvmf_ctrl_t ctrl, int log_level, const char *fmt, ...);
void nvmf_default_log_fn(int log_level, const char *message);


#define log_impl(ctrl, level, fmt, args...) \
do {                                            \
        time_t t = time(NULL);                        \
        if (unlikely(!thread_name)) {                  \
            pthread_getname_np(pthread_self(), thread_name_buff, sizeof(thread_name_buff)); \
            thread_name = thread_name_buff;         \
        }                                              \
        nvmf_log_message(ctrl, level, "%16s %24.24s %s %s:%d] " fmt, thread_name, ctime(&t),   \
           log_level_tag[level], __FILE__, __LINE__, ##args);  \
    } while (0)

#define log_error(ctrl, fmt, args...)    log_impl(ctrl, LOG_LEVEL_ERROR, fmt, ##args)

#define log_warn(ctrl, fmt, args...)    log_impl(ctrl, LOG_LEVEL_WARN, fmt, ##args)

#ifdef DEBUG
#define DEFAULT_LOG_LEVEL LOG_LEVEL_DEBUG
#define log_debug(ctrl, fmt, args...)    log_impl(ctrl, LOG_LEVEL_DEBUG, fmt, ##args)

#define log_trace(ctrl)        log_debug(ctrl, "TRACE %s\n", __func__)
#else
#define DEFAULT_LOG_LEVEL LOG_LEVEL_ERROR
#define log_debug(ctrl, fmt, args...)   \
do {                                    \
    (void)ctrl;                         \
} while (0)

#define log_trace(ctrl)     \
do {                        \
    (void)ctrl;             \
} while (0)
#endif

#endif    /* _LIBNVMF_LOG_ */
