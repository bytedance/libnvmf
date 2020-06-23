/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "nvmf.h"
#include "utils.h"

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
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
#define REQSIZE		4096
#define REQIOVS		16
#define MAGIC		0xfee1c001

#define RUNTIME		60

static off_t blksize;
static unsigned int bs = 4096;
static unsigned int iodepth = REQS;
static unsigned int runtime = RUNTIME;
static unsigned int etatime;
static unsigned int ioqueues = IOQUEUES;
#define RANDREAD	0x1
#define RANDWRITE	0x2
#define RANDRW		0x4
#define RANDDISCARD	0x8
#define RANDWRITEZEROES	0x16
static unsigned int randopt;

static unsigned long reqdone;
static unsigned long iodone;
static unsigned long reqtime;

struct fio_req {
	nvmf_req_t req;
	int magic;
	int iovcnt;
	struct iovec iovs[REQIOVS];
	off_t offset;
	unsigned long startus;
	bool done;
};

static inline size_t fio_req_data_len(struct fio_req *req)
{
	size_t datalen = 0;
	int index;

	for (index = 0; index < req->iovcnt; index++) {
		datalen += req->iovs[index].iov_len;
	}

	return datalen;
}

void fio_rw_cb(unsigned short status, void *opaque)
{
	struct fio_req *req = (struct fio_req *)opaque;

	if (status) {
		printf("req failed, status 0x%x\n", status);
	}

	assert(req->magic == MAGIC);

	req->done = true;

	reqtime += (nvmf_now_us() - req->startus);
	reqdone++;
	iodone += fio_req_data_len(req);
}

void fio_build_req_op(nvmf_ctrl_t ctrl, struct fio_req *req)
{
	req->magic = MAGIC;

	if (randopt == RANDDISCARD) {
		req->req = nvmf_discard_async(ctrl, (random() % ioqueues) + 1, req->iovs,
                                              req->iovcnt, req->offset, 0, fio_rw_cb, req);
	} else if (randopt == RANDWRITEZEROES) {
		req->req = nvmf_writezeroes_async(ctrl, (random() % ioqueues) + 1, req->iovs,
                                                  req->iovcnt, req->offset, 0, fio_rw_cb, req);
	} else if ((randopt == RANDREAD) || ((randopt == RANDRW) && ((random() % 2)))) {
		req->req = nvmf_read_async(ctrl, (random() % ioqueues) + 1, req->iovs, req->iovcnt,
                                           req->offset, 0, fio_rw_cb, req);
	} else {
		req->req = nvmf_write_async(ctrl, (random() % ioqueues) + 1, req->iovs,
                                            req->iovcnt, req->offset, 0, fio_rw_cb, req);
	}

	if (!req->req) {
		assert(0);
	}
}

void fio_loop(nvmf_ctrl_t ctrl)
{
	struct pollfd pfd;
	struct fio_req *reqs;
	struct fio_req *req;
	size_t reqsize;
	off_t offset;
	int idx;

	reqs = nvmf_calloc(iodepth, sizeof(struct fio_req));

	alarm(1);

	while (etatime < runtime) {
		for (idx = 0; idx < iodepth; idx++) {
			req = reqs + idx;
			if (req->req && req->done) {
				nvmf_req_free(req->req);
				nvmf_free(req->iovs[0].iov_base);
				memset(req, 0x00, sizeof(*req));
			}

			if (!req->req) {
				reqsize = (bs + 4095) & ~4095;
				req->iovcnt = 1;
				req->iovs[0].iov_len = reqsize;
				req->iovs[0].iov_base = nvmf_malloc(reqsize);
				offset = (random() % blksize) & (~4096UL);
				if (offset + reqsize > blksize) {
					offset =  blksize - reqsize;
				}
				req->offset = offset;
				req->startus = nvmf_now_us();
				fio_build_req_op(ctrl, req);
			}
		}

		pfd.fd = nvmf_ctrl_fd(ctrl);
		pfd.events = POLLIN;
		pfd.revents = 0;

		poll(&pfd, 1, 100);

		nvmf_ctrl_process(ctrl);
	}

	nvmf_ctrl_release(ctrl);

	for (idx = 0; idx < iodepth; idx++) {
		req = reqs + idx;
		if (req->req) {
			nvmf_free(req->iovs[0].iov_base);
		}
	}

	nvmf_free(reqs);
}

static void alarm_handler(int signal)
{
	etatime++;

	if (reqdone) {
		printf("[%04d]IOPS %ld, BW %ld, AVG %ldus\n", etatime, reqdone, iodone,
                       reqtime / reqdone);
	} else {
		printf("[%04d]IOPS --, BW --, AVG --us\n", etatime);
	}

	reqtime = 0;
	reqdone = 0;
	iodone = 0;

	alarm(1);
}

void print_usage(void)
{
	printf("Usage:\n");
	printf("\t--bs=\n");
	printf("\t--filename=\n");
	printf("\t--iodepth=\n");
	printf("\t--ioqueues=\n");
	printf("\t--runtime=\n");
	printf("\t--randread\n");
	printf("\t--randwrite\n");
	printf("\t--randrw\n");
	printf("\t--randdiscard\n");
	printf("\t--randwritezeroes\n");
}

int main(int argc, char *argv[])
{
	nvmf_ctrl_t ctrl;
	nvmf_options_t options;
	struct sigaction sa;
	int long_index = 0, opt;
	char *filename = NULL;
	static struct option long_options[] = {
		{"bs",              required_argument, 0,  'b' },
		{"iodepth",         required_argument, 0,  'd' },
		{"filename",        required_argument, 0,  'f' },
		{"ioqueues",        required_argument, 0,  'q' },
		{"runtime",         required_argument, 0,  't' },
		{"randread",        no_argument,       0,  'r' },
		{"randwrite",       no_argument,       0,  'w' },
		{"randrw",          no_argument,       0,  'm' },
		{"randdiscard",     no_argument,       0,  'D' },
		{"randwritezeroes", no_argument,       0,  'z' },
		{0,                 0,                 0,  0   }
	};

	while ((opt = getopt_long(argc, argv, "b:d:f:q:t:rwmDzh", long_options, &long_index))
               != -1) {
		switch (opt) {
		case 'b':
			bs = atoi(optarg);
			break;
		case 'd':
			iodepth = atoi(optarg);
			break;
		case 'f':
			filename = optarg;
			break;
		case 'q':
			ioqueues = atoi(optarg);
			break;
		case 't':
			runtime = atoi(optarg);
			break;
		case 'r':
			randopt =  RANDREAD;
			break;
		case 'w':
			randopt =  RANDWRITE;
			break;
		case 'm':
			randopt =  RANDRW;
			break;
		case 'D':
			randopt =  RANDDISCARD;
			break;
		case 'z':
			randopt =  RANDWRITEZEROES;
			break;
		case 'h':
		default:
			print_usage();
			return 0;
		}
	}

	if (!randopt) {
		printf("Missing randread/randwrite/randrw options\n");
		return 0;
	}

	if (!filename) {
		printf("Missing filename\n");
		return 0;
	}

	signal(SIGPIPE, SIG_IGN);

	options = nvmf_default_options(filename);
	if (!options) {
		return -1;
	}

	nvmf_options_set_kato(options, 3000);
	nvmf_options_set_io_queues(options, ioqueues);
	ctrl = nvmf_ctrl_create(options);
	if (!ctrl) {
		printf("create src ctrl failed\n");
		return -1;
	}

	blksize = (1 << nvmf_ns_lbads(ctrl, 1)) * nvmf_ns_nsze(ctrl, 1);
	show_result("NVMf ctrl conf:\n");
	show_result("\tcount %d\n", nvmf_ns_count(ctrl));
	show_result("\tlbads %d\n", nvmf_ns_lbads(ctrl, 1));
	show_result("\tnsze %ld\n", nvmf_ns_nsze(ctrl, 1));
	show_result("\tsize %ld\n", blksize);

	sa.sa_handler = alarm_handler;
	sa.sa_flags = 0;
	if (sigaction(SIGALRM, &sa, NULL)) {
		return -1;
	}

	fio_loop(ctrl);

	return 0;
}
