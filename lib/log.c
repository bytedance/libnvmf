/*
 * Copyright 2020-2021 helei.sig11
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "log.h"

#include <assert.h>
#include <stdarg.h>

static void log_to_stderr(int log_level, const char *message)
{
    fprintf(stderr, message);
}

const char *log_level_tag[] = {"ERROR", "WARN", "DEBUG"};
int g_log_level = LOG_LEVEL_ERROR;
nvmf_log_fn g_log_fn = log_to_stderr;
__thread char thread_name_buff[17] = {0};
__thread const char *thread_name = NULL;

void set_log_level(int log_level)
{
    assert(log_level >= LOG_LEVEL_ERROR);
    assert(log_level <= LOG_LEVEL_DEBUG);
    g_log_level = log_level;
}

void nvmf_set_log_fn(nvmf_log_fn fn)
{
    g_log_fn = fn;
}

void nvmf_log_message(int log_level, const char *fmt, ...)
{
    if (!g_log_fn) {
        return;
    }
    va_list ap;
    static char message[MAX_LOG_BUFFER];
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(message, MAX_LOG_BUFFER, fmt, ap);
    va_end(ap);
    if (unlikely(ret < 0)) {
        return;
    }
    g_log_fn(log_level, message);
}
