/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "nvmf.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUG
#ifdef DEBUG
#define show_result(fmt, args...) printf(fmt, ##args)
#else
#define show_result(fmt, args...) do { } while (0)
#endif

#define IOQUEUES	2
#define REQS		64
#define REQSIZE		(4096 * 8)

static off_t size;
static off_t copied;

struct dd_req {
	nvmf_req_t req;
	int iovcnt;
	struct iovec iov;
	off_t offset;
	int dst_fd;
	bool done;
};

void dd_rw_cb(unsigned short status, void *opaque)
{
	struct dd_req *req = (struct dd_req *)opaque;
	off_t ret;

	if (status) {
		printf("req failed, status 0x%x\n", status);
	}

	ret = pwrite(req->dst_fd, req->iov.iov_base, req->iov.iov_len, req->offset);
	if (ret < 0) {
		printf("req failed %m, status 0x%x, len %ld, offset %ld\n", status,
                       req->iov.iov_len, req->offset);
		exit(-1);
	}

	req->done = true;

	copied += ret;
}

void dd_loop(nvmf_ctrl_t src_ctrl, int dst_fd)
{
	struct pollfd pfd;
	struct dd_req reqs[REQS] = {0};
	struct dd_req *req;
	off_t total = 0;
	int idx;

	while (copied < size) {
		for (idx = 0; idx < REQS; idx++) {
			if (total >= size) {
				break;
			}

			req = &reqs[idx];
			if (req->req && req->done) {
				nvmf_req_free(req->req);
				free(req->iov.iov_base);
				memset(req, 0x00, sizeof(*req));
			}

			if (!req->req) {
				req->dst_fd = dst_fd;
				req->iov.iov_len = REQSIZE;
				req->iov.iov_base = malloc(REQSIZE);
				req->offset = total;
				req->req = nvmf_read_async(src_ctrl, (idx % IOQUEUES) + 1,
                                                           &req->iov, 1, req->offset, 0, dd_rw_cb,
                                                           req);

				total += REQSIZE;
			}
		}

		pfd.fd = nvmf_ctrl_fd(src_ctrl);
		pfd.events = POLLIN;
		pfd.revents = 0;

		poll(&pfd, 1, -1);

		nvmf_ctrl_process(src_ctrl);
	}

}


int main(int argc, char *argv[])
{
	nvmf_ctrl_t src_ctrl;
	nvmf_options_t src_options;
	char *src_uri = "tcp://192.168.122.33:4420/nvmet-always/1";
	char *err_msg = NULL;
	int dst_fd;

	if (argc != 3) {
		printf("usage: %s SRC DST\n", argv[0]);
		return -1;
	}

	src_options = nvmf_default_options(src_uri, &err_msg);
	if (!src_options) {
	    printf("%s", err_msg);
	    free(err_msg);
		return -1;
	}

	nvmf_options_set_kato(src_options, 3000);
	nvmf_options_set_io_queues(src_options, IOQUEUES);
	src_ctrl = nvmf_ctrl_create(src_options);
	if (!src_ctrl) {
		printf("create src ctrl failed\n");
		return -1;
	}

	size = (1 << nvmf_ns_lbads(src_ctrl, 1)) * nvmf_ns_nsze(src_ctrl, 1);
	show_result("Source ctrl conf:\n");
	show_result("\tcount %d\n", nvmf_ns_count(src_ctrl));
	show_result("\tlbads %d\n", nvmf_ns_lbads(src_ctrl, 1));
	show_result("\tnsze %ld\n", nvmf_ns_nsze(src_ctrl, 1));
	show_result("\tsize %ld\n", size);

	dst_fd = open("dump", O_RDWR | O_CREAT, 0644);
	if (dst_fd < 0) {
		perror("open dst file failed\n");
		return -1;
	}

	dd_loop(src_ctrl, dst_fd);

	nvmf_ctrl_release(src_ctrl);

	return 0;
}
