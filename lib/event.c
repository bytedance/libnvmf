/*
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "log.h"
#include "nvmf.h"
#include "nvmf-private.h"
#include "utils.h"

#include <poll.h>
#include <errno.h>

/*
 * sync API, wait a request until done.
 * request from outside request, typical IO request
 */
int nvmf_ctrl_do_req(struct nvmf_request *req)
{
    struct nvmf_ctrl *ctrl = req->queue->ctrl;
    struct pollfd pfd;
    unsigned long start = nvmf_now_ms(), now;
    unsigned long timeout = req->timeout;
    int ret;

    while (true) {
        pfd.fd = nvmf_ctrl_fd(ctrl);
        pfd.events = POLLIN;
        pfd.revents = 0;

        ret = poll(&pfd, 1, req->timeout ? timeout : 1000);
        if (ret < 0) {
            log_error("poll queues error");
            return -errno;
        }

        if (pfd.revents) {
            nvmf_ctrl_process(ctrl);
            if (nvmf_req_get_done(req)) {
                return 0;
            }
        }

        if (!req->timeout) {
            continue;
        }

        now = nvmf_now_ms();
        if (now - start < timeout) {
            timeout = now - start;
        } else {
            return -ETIME;
        }
    };

    return 0;
}
