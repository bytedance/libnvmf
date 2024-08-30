/*
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "nvmf-private.h"
#include "nvme.h"
#include "nvmf.h"
#include "log.h"
#include "utils.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/*
 * nvmf-rdma://192.168.122.100:4420/nqn-nvmet-ex/1
 * nvmf-tcp://192.168.122.100:4420/nqn-nvmet-ex/2
 */
static int nvmf_parse_uri(const char *uri, struct nvmf_ctrl_options *options, char *reason)
{
    int ret = -EINVAL, len;
    char *s = (char *)uri, *d;

    /*
     * always try to init transports. a little ugly, because gcc attribute
     * constructor can't work well for static linked case
     */
    nvmf_transport_tcp_init();
    nvmf_transport_rdma_init();

    /* check "nvmf-" prefix */
    len = strlen(s);
    if ((len < 5) || strncmp(s, "nvmf-", 5)) {
        sprintf(reason, "missing prefix nvmf-. Ex, nvmf-tcp/nvmf-rdma");
        goto out;
    }

    /* search :// for transport */
    d = strstr(s, "://");
    if (!d) {
        sprintf(reason, "missing :// between transport & address");
        goto out;
    }

    options->transport = nvmf_strndup(s + 5, d - s - 5);
    if (!options->transport) {
        sprintf(reason, "no memory for transport");
        ret = -ENOMEM;
        goto out;
    }

    if (!nvmf_transport_lookup(options->transport)) {
        sprintf(reason, "unsupport transport %s", options->transport);
        ret = -EINVAL;
        goto out;
    }

    /* search : for address */
    s = d + 3;
    d = strstr(s, ":");
    if (!d) {
        sprintf(reason, "missing : between address & port");
        goto out;
    }

    options->traddr = nvmf_strndup(s, d - s);
    if (!options->traddr) {
        sprintf(reason, "no memory for address");
        ret = -ENOMEM;
        goto out;
    }

    /* search / for port */
    s = d + 1;
    d = strstr(s, "/");
    if (!d) {
        sprintf(reason, "missing / between port & nqn");
        goto out;
    }

    options->trsvcid = nvmf_strndup(s, d - s);
    if (!options->trsvcid) {
        sprintf(reason, "no memory for port");
        ret = -ENOMEM;
        goto out;
    }

    /* search / for nqn */
    s = d + 1;
    d = strstr(s, "/");
    if (!d) {
        sprintf(reason, "missing / between nqn & nsid");
        goto out;
    }

    options->trnqn = nvmf_strndup(s, d - s);
    if (!options->trnqn) {
        sprintf(reason, "no memory for nqn");
        ret = -ENOMEM;
        goto out;
    }

    /* search / for namespace */
    s = d + 1;
    options->nsid = atoi(s);
    if (!options->nsid) {
        sprintf(reason, "missing nsid");
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    nvmf_free(options->transport);
    options->transport = NULL;
    nvmf_free(options->traddr);
    options->traddr = NULL;
    nvmf_free(options->trsvcid);
    options->trsvcid = NULL;
    nvmf_free(options->trnqn);
    options->trnqn = NULL;

    return ret;
}

nvmf_ctrl_t nvmf_default_options(const char *uri)
{
    struct nvmf_ctrl_options *options;
    char reason[256];
    __u8 *b;
    int idx;

    nvmf_malloc_init();

    options = (struct nvmf_ctrl_options *)nvmf_calloc(1, sizeof(*options));
    if (nvmf_parse_uri(uri, options, reason)) {
        log_error("nvmf_parse_uri fail, reason %s\n", reason);
        nvmf_free(options);
        return NULL;
    }

    srandom(time(NULL) * getpid());
    for (idx = 0; idx < sizeof(options->uuid) / sizeof(__u8); idx++) {
        options->uuid.b[idx] = random() % 0xff;
    }

    b = options->uuid.b;
    if (!options->hostnqn) {
        options->hostnqn = nvmf_calloc(1, NVMF_NQN_SIZE);
        snprintf(options->hostnqn, NVMF_NQN_SIZE,
                 "nqn.2014-08.org.nvmexpress:libnvmf:"
                 "uuid:%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x",
                 b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
                 b[13], b[14], b[15]);
    }

    options->kato = NVME_DEFAULT_KATO;
    options->nr_queues = NVMF_DEF_IO_QUEUES + 1;
    options->qsize = NVMF_DEF_QUEUE_SIZE;

    log_debug("nvmf_parse_uri %s %s %s %s %d\n", options->transport, options->traddr,
              options->trsvcid, options->trnqn, options->nsid);

    return options;
}

void nvmf_options_free(nvmf_ctrl_t options)
{
    struct nvmf_ctrl_options *_options = (struct nvmf_ctrl_options *)options;

    nvmf_free(_options->transport);
    nvmf_free(_options->traddr);
    nvmf_free(_options->trsvcid);
    nvmf_free(_options->trnqn);
    nvmf_free(_options->hostnqn);
    nvmf_free(_options->host_traddr);

    nvmf_free(options);
}

void nvmf_options_set_kato(nvmf_options_t opts, unsigned int milliseconds)
{
    struct nvmf_ctrl_options *options = (struct nvmf_ctrl_options *)opts;

    options->kato = milliseconds;
}

void nvmf_options_set_io_queues(nvmf_options_t opts, unsigned int io_queues)
{
    struct nvmf_ctrl_options *options = (struct nvmf_ctrl_options *)opts;

    options->nr_queues = io_queues + 1;
}

int nvmf_options_set_hostnqn(nvmf_options_t opts, const char *hostnqn, size_t length)
{
    struct nvmf_ctrl_options *options = (struct nvmf_ctrl_options *)opts;

    if (length > NVMF_NQN_SIZE) {
        return -EINVAL;
    }

    if (options->hostnqn) {
        nvmf_free(options->hostnqn);
    }

    options->hostnqn = nvmf_calloc(1, NVMF_NQN_SIZE);
    memcpy(options->hostnqn, hostnqn, length);

    return 0;
}

void nvmf_options_set_hdgst(nvmf_options_t opts, unsigned int hdgst)
{
    struct nvmf_ctrl_options *options = (struct nvmf_ctrl_options *)opts;

    options->hdr_digest = !!hdgst;
}

void nvmf_options_set_ddgst(nvmf_options_t opts, unsigned int ddgst)
{
    struct nvmf_ctrl_options *options = (struct nvmf_ctrl_options *)opts;

    options->data_digest = !!ddgst;
}
