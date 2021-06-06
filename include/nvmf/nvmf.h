/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#ifndef _LIBNVMF_NVMF_
#define _LIBNVMF_NVMF_

#include <sys/uio.h>

typedef void *nvmf_ctrl_t;
typedef void *nvmf_options_t;
typedef void *nvmf_req_t;

/* options API */
nvmf_options_t nvmf_default_options(const char *uri);

void nvmf_options_free(nvmf_options_t options);

void nvmf_options_set_kato(nvmf_options_t opts, unsigned int milliseconds);

void nvmf_options_set_io_queues(nvmf_options_t opts, unsigned int io_queues);


/* ctrl API */
nvmf_ctrl_t nvmf_ctrl_create(nvmf_options_t options);

void nvmf_ctrl_release(nvmf_ctrl_t ctrl);

int nvmf_ctrl_fd(nvmf_ctrl_t ctrl);

void nvmf_ctrl_process(nvmf_ctrl_t ctrl);


/* namespace API */
unsigned int nvmf_ns_count(nvmf_ctrl_t ctrl);

unsigned char nvmf_ns_lbads(nvmf_ctrl_t ctrl, unsigned int nsid);

unsigned long nvmf_ns_nsze(nvmf_ctrl_t ctrl, unsigned int nsid);

unsigned int nvmf_ns_id(nvmf_ctrl_t ctrl);

/* IO API */
int nvmf_max_iov(nvmf_ctrl_t ctrl);

unsigned int nvmf_ctrl_mdts(nvmf_ctrl_t ctrl);

unsigned int nvmf_ctrl_dsm_segments(nvmf_ctrl_t ctrl);

int nvmf_read(nvmf_ctrl_t ctrl, unsigned int qid, void *buf, unsigned long count,
              unsigned long offset, int flags);

int nvmf_write(nvmf_ctrl_t ctrl, unsigned int qid, void *buf, unsigned long count,
               unsigned long offset, int flags);

int nvmf_readv(nvmf_ctrl_t ctrl, unsigned int qid, struct iovec *iovs, int iovcnt,
               unsigned long offset, int flags);

int nvmf_writev(nvmf_ctrl_t ctrl, unsigned int qid, struct iovec *iovs, int iovcnt,
                unsigned long offset, int flags);

nvmf_req_t nvmf_read_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                           unsigned long offset, int flags, void (*cb)(unsigned short status,
                           void *opaque), void *opaque);

nvmf_req_t nvmf_write_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                            unsigned long offset, int flags, void (*cb)(unsigned short status,
                            void *opaque), void *opaque);

nvmf_req_t nvmf_discard_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                              unsigned long offset, int flags,
                              void (*cb)(unsigned short status, void *opaque), void *opaque);

nvmf_req_t nvmf_writezeroes_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                                  unsigned long offset, int flags,
                                  void (*cb)(unsigned short status, void *opaque), void *opaque);

int nvmf_req_set_timeout(nvmf_req_t req, unsigned int ms);

int nvmf_req_free(nvmf_req_t req);

int nvmf_queue_depth(nvmf_ctrl_t ctrl, unsigned int qid);

int nvmf_queue_nr_inflight(nvmf_ctrl_t ctrl, unsigned int qid);

#endif /* _LIBNVMF_NVMF_ */
