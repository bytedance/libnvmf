/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "nvmf/nvmf.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DEBUG
#ifdef DEBUG
#define show_result(fmt, args...) printf(fmt, ##args)
#else
#define show_result(fmt, args...) do { } while (0)
#endif

#define IOQUEUES	4
#define IODEPTH		1

static unsigned long size;
static unsigned long iops;
static unsigned long bw;
static unsigned int etatime;
static char *pattern;
static struct iovec pattern_iov[26 * 2];

struct check_req {
	nvmf_req_t req;
	int iovcnt;
	struct iovec iov[26];
	char *buf;
	off_t offset;
	int count;
	bool done;
};

void show_iov(char *tag, struct iovec *iov, int iovcnt)
{
	char buf[256] = {0};
	int k;

	for (k = 0; k < iovcnt; k++) {
		sprintf(buf + k * 4, "%c...", *(char *)iov[k].iov_base);
	}

	printf("%s %s\n", tag, buf);
}

void statistics(void)
{
    static time_t prev;
    time_t current = time(NULL);
    if (current == prev) {
        return;
    }

    prev = current;
    if (etatime++ > 1) {
        printf("[%04d]IOPS %ld, BW %ld\n", etatime, iops, bw);
        iops = 0;
        bw = 0;
    }
}

void rw_cb(unsigned short status, void *opaque)
{
	struct check_req *req = (struct check_req *)opaque;
	int k;

	if (status) {
		printf("req failed, status 0x%x\n", status);
		exit(-1);
	}

	req->done = true;
	if (req->count % 2) {
		k = (req->offset / 4096) % 26;
		show_iov("read ", req->iov, req->iovcnt);
		if (memcmp(req->buf, pattern + k * 4096, req->iovcnt * 4096)) {
			printf("Test failed\n");
			show_iov("read ", req->iov, req->iovcnt);
			show_iov("real ", &pattern_iov[k], req->iovcnt);
			exit(-1);
		}
	}

	req->count++;

	iops++;
	bw += req->iovcnt * 4096;
}

void test_loop(nvmf_ctrl_t nvmf_ctrl)
{
	struct pollfd pfd;
	struct check_req reqs[IODEPTH] = {0};
	struct check_req *req;
	int idx, k, nready;
	char *p, c;

	pattern = calloc(4096, 26 * 2);
	for (idx = 0; idx < 26 * 2; idx++) {
		p = pattern + idx * 4096;
		c = 'A' + idx % 26;
		memset(p, c, 4096);
		p[4095] = '\n';

		pattern_iov[idx].iov_base = p;
		pattern_iov[idx].iov_len = 4096;
	}

	for (idx = 0; idx < IODEPTH; idx++) {
		req = &reqs[idx];

		req->done = true;
		req->buf = calloc(4096, 26);
		for (k = 0; k < 26; k++) {
			req->iov[k].iov_base = req->buf + k * 4096;
			req->iov[k].iov_len = 4096;
		}
	}

	while (1) {
	    statistics();
		for (idx = 0; idx < IODEPTH; idx++) {
			req = &reqs[idx];
			if (!req->done) {
				continue;
			}

			if (req->req) {
				nvmf_req_free(req->req);
			}

			/* write firstly */
			if (!(req->count % 2)) {
				req->iovcnt = random() % 26 + 1;
				req->offset = (random() % (size - 4096 * 26)) & ~4095;
				k = (req->offset / 4096) % 26;
				req->req = nvmf_write_async(nvmf_ctrl, (req->iovcnt % IOQUEUES) + 1,
						&pattern_iov[k], req->iovcnt, req->offset, 0,
						rw_cb, req);
				show_iov("write", &pattern_iov[k], req->iovcnt);
			} else {
				req->req = nvmf_read_async(nvmf_ctrl, (req->iovcnt % IOQUEUES) + 1,
						req->iov, req->iovcnt, req->offset, 0,
						rw_cb, req);
			}
		}

		pfd.fd = nvmf_ctrl_fd(nvmf_ctrl);
		pfd.events = POLLIN;
		pfd.revents = 0;

		while ((nready = poll(&pfd, 1, -1)) <= 0) {
		    assert(nready != 0);
		    assert(errno == EINTR);
		}

		nvmf_ctrl_process(nvmf_ctrl);
	}
}

static void alarm_handler(int signal)
{
	alarm(1);
}



int main(int argc, char *argv[])
{
	nvmf_ctrl_t nvmf_ctrl;
	nvmf_options_t options;
	char *uri;
    char *err_msg = NULL;
	unsigned int mdts;
	struct sigaction sa;

	if (argc != 2) {
		printf("usage: %s TARGET\n", argv[0]);
		return -1;
	}

	uri = argv[1];
	options = nvmf_default_options(uri, &err_msg);
	if (!options) {
	    printf("%s", err_msg);
	    free(err_msg);
		return -1;
	}

	nvmf_options_set_kato(options, 10000);
	nvmf_options_set_io_queues(options, IOQUEUES);
	nvmf_ctrl = nvmf_ctrl_create(options);
	if (!nvmf_ctrl) {
		printf("create src ctrl failed\n");
		return -1;
	}

	/*
	 * mdts: Maximum Data Transfer
	 * lba: Logical Block Addressing
	 * lbads: lba Data Size (Unit: a power of two)
	 * nsze: Namespace Size (Number of logical block)
	 * size: namespace size, Unit byte, equals to nsze * (1 << lbads)
	 */
	mdts = nvmf_ctrl_mdts(nvmf_ctrl);
	size = (1 << nvmf_ns_lbads(nvmf_ctrl, 1)) * nvmf_ns_nsze(nvmf_ctrl, 1);
	show_result("Source ctrl conf:\n");
	show_result("\tcount %d\n", nvmf_ns_count(nvmf_ctrl));
	show_result("\tlbads %d\n", nvmf_ns_lbads(nvmf_ctrl, 1));
	show_result("\tnsze %ld\n", nvmf_ns_nsze(nvmf_ctrl, 1));
	show_result("\tsize %ld\n", size);
	show_result("\tmdts %d\n", mdts);

	sa.sa_handler = alarm_handler;
	sa.sa_flags = 0;
	if (sigaction(SIGALRM, &sa, NULL)) {
		return -1;
	}

	alarm(100);
	test_loop(nvmf_ctrl);

	nvmf_ctrl_release(nvmf_ctrl);
	nvmf_options_free(options);

	return 0;
}
