/*
 * Copyright 2020-2021 helei.sig11
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "log.h"

#include <stdarg.h>

#include "nvmf-private.h"

/* log to stderr by default */
void nvmf_default_log_fn(int log_level, const char *message)
{
    fprintf(stderr, "%s", message);
}

const char *log_level_tag[] = {"ERROR", "WARN", "DEBUG"};
__thread char thread_name_buff[17] = {0};
__thread const char *thread_name = NULL;

void nvmf_log_message(nvmf_ctrl_t ctrl, int log_level, const char *fmt, ...)
{
    struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
    struct nvmf_ctrl_options *opts = __ctrl->opts;
    if (!opts->log_fn || log_level > opts->log_level) {
        return;
    }

    char message[MAX_LOG_BUFFER];
    int ret;

    va_list ap;
    va_start(ap, fmt);
    ret = vsnprintf(message, MAX_LOG_BUFFER, fmt, ap);
    va_end(ap);
    if (unlikely(ret < 0)) {
        return;
    }
    opts->log_fn(log_level, message);
}
