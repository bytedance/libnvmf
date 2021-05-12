/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "nvmf-private.h"
#include "nvme.h"
#include "nvme-rdma.h"
#include "nvmf.h"
#include "log.h"
#include "utils.h"
#include "buddy.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <assert.h>
#include <rdma/rdma_cma.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef USE_RDMA
#define COALESCED_CQE	4096
#define PAGESIZE	4096

struct nvmf_rdma_queue {
	struct nvmf_queue *queue;
	struct rdma_cm_id *cm_id;
	struct rdma_event_channel *cma_channel;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_comp_channel *comp_channel;
	unsigned int cq_events;
	struct ibv_mr *cqe_mr;
	struct nvme_completion *cqes;
	struct ibv_sge *cqe_sges;
	struct ibv_recv_wr *recv_wrs;

	size_t cmnd_capsule_len;

	slab_t slab_priv;
	struct ibv_mr *cmd_mr;

	buddy_t buddy;
	struct ibv_mr *data_mr;
};

#define SGE_CMD		0
#define SGE_INCAPSULE	1
struct nvmf_rdma_priv {
	/* sges[0] for cmd, sges[1] for incapsule data */
	struct ibv_sge sges[2];
	struct nvme_command cmd;
	struct nvme_completion cqe;
	size_t data_size;
	char *data;
	/*
	 * try to alloc data buffer from nvmf_rdma_queue->buddy firstly.
	 * if allocating fails, malloc a new buffer and setup a MR
	 */
	struct ibv_mr *data_mr;
};

static int nvmf_rdma_cq_handle_recv(struct nvmf_queue *queue, struct nvmf_rdma_queue *rdma_queue,
                                    struct nvme_completion *cqe)
{
	struct nvmf_request *req;
	struct nvmf_rdma_priv *priv;
	__u16 tag = cqe->command_id;

	log_debug("queue[%d] handle rsp, result: 0x%lx, tag[0x%x] sq_head: %d, sq_id: %d, "
                  "command_id: 0x%x, status: 0x%x\n", queue->qid,
                  (unsigned long)le64toh(cqe->result.u64), cqe->command_id, le16toh(cqe->sq_head),
                  le16toh(cqe->sq_id), cqe->command_id, le16toh(cqe->status));

	req = nvmf_queue_req_by_tag(queue, tag);
	if (!req) {
		/* TODO need reset controller */
		log_error("queue[%d] tag[0x%x] invalid tag from controller\n", queue->qid, tag);
		return 0;
	}

	/* copy pdu to request body */
	priv = (struct nvmf_rdma_priv *)req->priv;
	priv->cqe = *cqe;

	if (!nvme_is_write(req->cmd)) {
		nvmf_buf_to_iov(req->iovs, req->iovcnt, priv->data);
	}

	nvmf_queue_req_finish(req);

	if (req->cb) {
		req->cb(req, req->opaque);
	}

	nvmf_req_set_done(req, true);

	return 0;
}

static int nvmf_rdma_cq_event_handler(struct nvmf_queue *queue, struct nvmf_rdma_queue *rdma_queue)
{
	struct ibv_wc wc;
	struct ibv_recv_wr *bad_wr;

	log_trace();
	while ((ibv_poll_cq(rdma_queue->cq, 1, &wc)) > 0) {
		log_debug("queue[%d] status = 0x%x, opcode = 0x%x\n", queue->qid, wc.status,
                          wc.opcode);
		if (wc.status == IBV_WC_WR_FLUSH_ERR) {
			continue;
		} else if (wc.status != IBV_WC_SUCCESS) {
			/* TODO reconnect */
			log_error("queue[%d] status = 0x%x, opcode = 0x%x\n", queue->qid,
                                  wc.status, wc.opcode);
			return -1;
		}

		switch (wc.opcode) {
		case IBV_WC_SEND:
			log_debug("send completion\n");
			break;
		case IBV_WC_RECV:
			nvmf_rdma_cq_handle_recv(queue, rdma_queue,
                                                 (struct nvme_completion *)wc.wr_id);
			break;
		default:
			break;
		}
	}

	if (ibv_post_recv(rdma_queue->qp, rdma_queue->recv_wrs, &bad_wr)) {
		if (errno != EAGAIN) {
			/* TODO reconnect */
			log_error("queue[%d] ibv_post_recv failed, %m\n", rdma_queue->queue->qid);
		}
	}

	return 0;
}

static int nvmf_rdma_cq_event(struct nvmf_queue *queue, short revents)
{
	struct nvmf_rdma_queue *rdma_queue = (struct nvmf_rdma_queue *)queue->priv;
	struct ibv_cq *ev_cq;
	void *ev_ctx;

	log_trace();

	if (ibv_get_cq_event(rdma_queue->comp_channel, &ev_cq, &ev_ctx)) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			/* TODO reconnect */
			log_error("queue[%d] ibv_get_cq_event fatal, %m\n", rdma_queue->queue->qid);
		}
	}

	if (rdma_queue->cq != ev_cq) {
		/* TODO reconnect */
		/*log_error("queue[%d] ibv_get_cq_event mismatched cq\n", rdma_queue->queue->qid);*/
	}

	if (ibv_req_notify_cq(rdma_queue->cq, 0)) {
		log_error("queue[%d] ibv_req_notify_cq failed, %m\n", rdma_queue->queue->qid);
	}

	rdma_queue->cq_events++;
	if (rdma_queue->cq_events >= COALESCED_CQE) {
		ibv_ack_cq_events(rdma_queue->cq, rdma_queue->cq_events);
		rdma_queue->cq_events = 0;
	}

	nvmf_rdma_cq_event_handler(queue, rdma_queue);

	return 0;
}

static int nvmf_rdma_queue_addr_handler(struct nvmf_rdma_queue *rdma_queue,
                                        struct rdma_cm_id *cm_id)
{
	if (rdma_resolve_route(cm_id, 1000)) {
		log_error("queue[%d] rdma_resolve_route failed, %m\n", rdma_queue->queue->qid);
		return -errno;
	}

	rdma_queue->pd = ibv_alloc_pd(cm_id->verbs);
	if (!rdma_queue->pd) {
		log_error("queue[%d] ibv_alloc_pd failed, %m\n", rdma_queue->queue->qid);
		return -errno;
	}

	rdma_queue->comp_channel = ibv_create_comp_channel(cm_id->verbs);
	if (!rdma_queue->comp_channel) {
		log_error("queue[%d] ibv_create_comp_channel failed, %m\n", rdma_queue->queue->qid);
		goto pd_error;
	}

	nvmf_set_nonblock(rdma_queue->comp_channel->fd);

	rdma_queue->cq = ibv_create_cq(cm_id->verbs, rdma_queue->queue->qsize * 2, rdma_queue,
                                       rdma_queue->comp_channel, 0);
	if (!rdma_queue->cq) {
		log_error("queue[%d] ibv_create_cq failed, %m\n", rdma_queue->queue->qid);
		goto pd_error;
	}

	if (ibv_req_notify_cq(rdma_queue->cq, 0)) {
		log_error("queue[%d] ibv_req_notify_cq failed, %m\n", rdma_queue->queue->qid);
		goto cq_error;
	}

	rdma_queue->cq_events = 0;

	return 0;

cq_error:
	ibv_destroy_cq(rdma_queue->cq);

pd_error:
	ibv_dealloc_pd(rdma_queue->pd);

	return -EIO;
}

static int nvmf_rdma_queue_route_handler(struct nvmf_rdma_queue *rdma_queue,
                                         struct rdma_cm_id *cm_id)
{
	struct ibv_qp_init_attr init_attr = {0};
	struct rdma_conn_param param = {0};
	struct nvme_rdma_cm_req req = {0};
	struct ibv_device_attr dev_attr = {0};
	int ret;

	log_trace();
	/* get device attr */
	ret = ibv_query_device(cm_id->verbs, &dev_attr);
	if (ret) {
		log_error("queue[%d] ibv_query_device failed, %m\n", rdma_queue->queue->qid);
		return -errno;
	}

	/* create QP */
	init_attr.qp_context = (void *)rdma_queue->cm_id->context;
	init_attr.send_cq = rdma_queue->cq;
	init_attr.recv_cq = rdma_queue->cq;
	init_attr.cap.max_send_wr = 3 * rdma_queue->queue->qsize + 1;
	init_attr.cap.max_recv_wr = rdma_queue->queue->qsize + 1;
	init_attr.cap.max_send_sge = 2;
	init_attr.cap.max_recv_sge = 2;
	init_attr.qp_type = IBV_QPT_RC;

	ret = rdma_create_qp(rdma_queue->cm_id, rdma_queue->pd, &init_attr);
	if (ret) {
		log_error("queue[%d] rdma_create_qp failed, %m\n", rdma_queue->queue->qid);
		return -errno;
	}

	rdma_queue->qp = rdma_queue->cm_id->qp;

	/* start connection */
	req.recfmt = htole16(NVME_RDMA_CM_FMT_1_0);
	req.qid = htole16(rdma_queue->queue->qid);
	req.hrqsize = htole16(rdma_queue->queue->qsize);
	req.hsqsize = htole16(rdma_queue->queue->qsize - 1);

	param.responder_resources = dev_attr.max_qp_rd_atom;
	param.retry_count = 7;
	param.rnr_retry_count = 7;
	param.private_data = &req;
	param.private_data_len = sizeof(struct nvme_rdma_cm_req);

	ret = rdma_connect(cm_id, &param);
	if (ret) {
		log_error("queue[%d] rdma_connect failed, %m\n", rdma_queue->queue->qid);
		return -errno;
	}

	return 0;
}

static int nvmf_rdma_queue_established_handler(struct nvmf_rdma_queue *rdma_queue,
                                               struct rdma_cm_id *cm_id)
{
	rdma_queue->queue->state = QUEUE_STATE_READY;

	return 0;
}

static char *nvmf_rdma_cma_event_str(int event)
{
	static char *e[] = {
		"RDMA_CM_EVENT_ADDR_RESOLVED",
		"RDMA_CM_EVENT_ADDR_ERROR",
		"RDMA_CM_EVENT_ROUTE_RESOLVED",
		"RDMA_CM_EVENT_ROUTE_ERROR",
		"RDMA_CM_EVENT_CONNECT_REQUEST",
		"RDMA_CM_EVENT_CONNECT_RESPONSE",
		"RDMA_CM_EVENT_CONNECT_ERROR",
		"RDMA_CM_EVENT_UNREACHABLE",
		"RDMA_CM_EVENT_REJECTED",
		"RDMA_CM_EVENT_ESTABLISHED",
		"RDMA_CM_EVENT_DISCONNECTED",
		"RDMA_CM_EVENT_DEVICE_REMOVAL",
		"RDMA_CM_EVENT_MULTICAST_JOIN",
		"RDMA_CM_EVENT_MULTICAST_ERROR",
		"RDMA_CM_EVENT_ADDR_CHANGE",
		"RDMA_CM_EVENT_TIMEWAIT_EXIT",
	};

	if (event >= ARRAY_SIZE(e)) {
		return "RDMA_UNKOWN";
	} else {
		return e[event];
	}
}

static int nvmf_rdma_cma_handler(struct nvmf_rdma_queue *rdma_queue, struct rdma_cm_id *cm_id,
                                 struct rdma_cm_event *event)
{
	int ret = 0;

	log_debug("queue[%d] handle cma event %d (%s), status %d\n", rdma_queue->queue->qid,
                  event->event, nvmf_rdma_cma_event_str(event->event), event->status);
	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		ret = nvmf_rdma_queue_addr_handler(rdma_queue, cm_id);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		ret = nvmf_rdma_queue_route_handler(rdma_queue, cm_id);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		ret = nvmf_rdma_queue_established_handler(rdma_queue, cm_id);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		log_error("queue[%d] handle cma event %d (%s), status %d\n", rdma_queue->queue->qid,
                          event->event, nvmf_rdma_cma_event_str(event->event), event->status);
		ret = -1;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		rdma_queue->queue->state = QUEUE_STATE_DYING;
		log_debug("queue[%d] handle cma event %d (%s), status %d\n", rdma_queue->queue->qid,
                          event->event, nvmf_rdma_cma_event_str(event->event), event->status);
		ret = -1;
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

static int nvmf_rdma_cm_event(struct nvmf_queue *queue, short revents)
{
	struct nvmf_rdma_queue *rdma_queue = (struct nvmf_rdma_queue *)queue->priv;
	struct rdma_event_channel *channel = rdma_queue->cma_channel;
	struct rdma_cm_event *event;
	int ret = 0;

	log_trace();
	while (rdma_get_cm_event(channel, &event) == 0) {
		ret = nvmf_rdma_cma_handler(rdma_queue, rdma_queue->cm_id, event);
		rdma_ack_cm_event(event);

		if (ret) {
			break;
		}
	}

	if (errno != EAGAIN && errno != EWOULDBLOCK) {
		log_error("rdma_get_cm_event failed, %m\n");
		return -1;
	}

	return ret;
}

static int nvmf_rdma_initialize_connection(struct nvmf_rdma_queue *rdma_queue)
{
	struct nvmf_queue *queue = rdma_queue->queue;
	struct nvmf_ctrl_options *opts;
	struct sockaddr_storage taddr;
	struct addrinfo *res = NULL;
	int ret;

	rdma_queue->cma_channel = rdma_create_event_channel();
	if (!rdma_queue->cma_channel) {
		log_error("queue[%d]rdma_create_event_channel failed, %m", rdma_queue->queue->qid);
		return -errno;
	}

	nvmf_set_nonblock(rdma_queue->cma_channel->fd);

	nvmf_queue_set_event(rdma_queue->queue, rdma_queue->cma_channel->fd, nvmf_rdma_cm_event,
                             NULL);

	if (rdma_create_id(rdma_queue->cma_channel, &rdma_queue->cm_id, (void *)rdma_queue,
            RDMA_PS_TCP)) {
		log_error("queue[%d] rdma_create_id failed, %m\n", rdma_queue->queue->qid);
		return -errno;
	}

	opts = queue->ctrl->opts;
	if (getaddrinfo(opts->traddr, NULL, NULL, &res)) {
		log_error("getaddrinfo failed: %s, %m\n", opts->traddr);
		ret = -EINVAL;
		goto fail;
	}

	if (res->ai_family == PF_INET) {
		memcpy(&taddr, res->ai_addr, sizeof(struct sockaddr_in));
		((struct sockaddr_in *)&taddr)->sin_port = htons(atoi((opts->trsvcid)));
	} else if (res->ai_family == PF_INET6) {
		memcpy(&taddr, res->ai_addr, sizeof(struct sockaddr_in6));
		((struct sockaddr_in6 *)&taddr)->sin6_port = htons(atoi((opts->trsvcid)));
	}

	if (res) {
		freeaddrinfo(res);
	}


	if (rdma_resolve_addr(rdma_queue->cm_id, NULL, (struct sockaddr *)&taddr, 2000)) {
		log_error("queue[%d] rdma_resolve_addr failed, %m\n", rdma_queue->queue->qid);
		return -errno;
	}

	return nvmf_queue_wait_state(rdma_queue->queue, QUEUE_STATE_READY, 5000);

fail:
	if (rdma_queue->cm_id) {
		rdma_destroy_id(rdma_queue->cm_id);
	}

	if (rdma_queue->cma_channel) {
		rdma_destroy_event_channel(rdma_queue->cma_channel);
	}

	return ret;
}

static int nvmf_rdma_queue_buffer_setup(struct nvmf_rdma_queue *rdma_queue)
{
	struct nvmf_queue *queue = rdma_queue->queue;
	struct ibv_recv_wr *recv_wr = NULL, *bad_wr;
	struct ibv_sge *sge;
	struct nvme_completion *cqe;
	void *addr;
	size_t length;
	int access;
	int i;

	/* reg a single MR for all the cmd */
	addr = slab_base(rdma_queue->slab_priv);
	length = sizeof(struct nvmf_rdma_priv) * queue->qsize;
	access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ;
	rdma_queue->cmd_mr = ibv_reg_mr(rdma_queue->pd, addr, length, access);
	if (!rdma_queue->cmd_mr) {
		/* TODO */
		log_error("queue[%d] ibv_reg_mr for cmd_mr failed, %m\n", queue->qid);
	}
	log_debug("queue[%d]cmd mr LKEY[%x], RKEY[%x], base %p, size %ld\n", queue->qid,
                  rdma_queue->cmd_mr->lkey, rdma_queue->cmd_mr->rkey, addr, length);

	/* reg a single MR for full of memory buddy */
	addr = buddy_base(rdma_queue->buddy);
	length = buddy_size(rdma_queue->buddy) * buddy_nmemb(rdma_queue->buddy);
	access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	rdma_queue->data_mr = ibv_reg_mr(rdma_queue->pd, addr, length, access);
	if (!rdma_queue->data_mr) {
		/* TODO */
		log_error("queue[%d] ibv_reg_mr for data_mr failed, %m\n", queue->qid);
	}
	log_debug("queue[%d]data mr LKEY[%x], RKEY[%x], base %p, size %lu(size %d * nmemb %d)\n",
                  queue->qid, rdma_queue->data_mr->lkey, rdma_queue->data_mr->rkey, addr, length,
                  buddy_size(rdma_queue->buddy), buddy_nmemb(rdma_queue->buddy));

	/* setup CQE & mr */
	rdma_queue->cqes = (struct nvme_completion *)nvmf_calloc(sizeof(struct nvme_completion),
                                                                 queue->qsize);
	addr = rdma_queue->cqes;
	length = sizeof(struct nvme_completion) * queue->qsize;
	access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	rdma_queue->cqe_mr = ibv_reg_mr(rdma_queue->pd, addr, length, access);
	if (!rdma_queue->cqe_mr) {
		/* TODO */
		log_error("queue[%d] ibv_reg_mr for cqe_mr failed, %m\n", queue->qid);
	}
	log_debug("queue[%d]cqe mr LKEY[%x], RKEY[%x], base %p, size %ld\n", queue->qid,
                  rdma_queue->cqe_mr->lkey, rdma_queue->cqe_mr->rkey, addr, length);
	rdma_queue->cqe_sges = (struct ibv_sge *)nvmf_calloc(sizeof(struct ibv_sge), queue->qsize);
	rdma_queue->recv_wrs = (struct ibv_recv_wr *)nvmf_calloc(sizeof(struct ibv_recv_wr),
                                                                 queue->qsize);

	for (i = 0; i < rdma_queue->queue->qsize; i++) {
		cqe = rdma_queue->cqes + i;
		sge = rdma_queue->cqe_sges + i;
		sge->addr = (uint64_t)cqe;
		sge->length = sizeof(*cqe);
		sge->lkey = rdma_queue->cqe_mr->lkey;

		recv_wr = rdma_queue->recv_wrs + i;
		recv_wr->next = recv_wr + 1;
		recv_wr->wr_id = (uintptr_t)cqe;
		recv_wr->sg_list = sge;
		recv_wr->num_sge = 1;
	}

	if (recv_wr) {
		recv_wr->next = NULL;
	}

	if (ibv_post_recv(rdma_queue->qp, rdma_queue->recv_wrs, &bad_wr)) {
		if (errno != EAGAIN) {
			log_error("queue[%d] ibv_post_recv failed, %m\n", rdma_queue->queue->qid);
		}
	}

	nvmf_queue_set_event(rdma_queue->queue, rdma_queue->comp_channel->fd, nvmf_rdma_cq_event,
                             NULL);

	return 0;
}

static int nvmf_rdma_create_queue(struct nvmf_queue *queue)
{
	struct nvmf_rdma_queue *rdma_queue;
	int ret = 0, qsize, pages;

	log_trace();
	rdma_queue = nvmf_calloc(1, sizeof(*rdma_queue));
	if (!rdma_queue) {
		return -ENOMEM;
	}

	rdma_queue->queue = queue;
	queue->priv = rdma_queue;
	if (queue->qid == 0) {
		rdma_queue->cmnd_capsule_len = sizeof(struct nvme_command);
		qsize = NVME_AQ_DEPTH;
		pages = 2;
	} else {
		rdma_queue->cmnd_capsule_len = queue->ctrl->ioccsz * 16;
		qsize = queue->ctrl->opts->qsize;
		/* to reduce memory allocation, so pre-alloc a a quart of total size */
		pages = (1 << queue->ctrl->mdts) * NVMF_SECTOR_SIZE * qsize / PAGESIZE / 4;
	}

	log_debug("queue[%d] qsize %d, pages %d\n", queue->qid, qsize, pages);
	queue->qsize = qsize;
	queue->slab_req = slab_create("", sizeof(struct nvmf_request), qsize);
	if (!queue->slab_req) {
		log_error("queue[%d] slab_create for request failed, %m\n", rdma_queue->queue->qid);
		ret = -ENOMEM;
		goto free_queue;
	}

	rdma_queue->slab_priv = slab_create("", sizeof(struct nvmf_rdma_priv), qsize);
	if (!rdma_queue->slab_priv) {
		log_error("queue[%d] slab_create for private data failed, %m\n",
                          rdma_queue->queue->qid);
		ret = -ENOMEM;
		goto free_slab;
	}

	rdma_queue->buddy = buddy_create(pages, PAGESIZE);
	if (!rdma_queue->buddy) {
		log_error("queue[%d] buddy_create for data failed, %m\n", rdma_queue->queue->qid);
		ret = -ENOMEM;
		goto free_priv;
	}

	ret = nvmf_rdma_initialize_connection(rdma_queue);
	if (ret < 0) {
		goto free_priv;
	}

	nvmf_rdma_queue_buffer_setup(rdma_queue);

	return 0;

free_priv:
	slab_destroy(rdma_queue->slab_priv);

free_slab:
	slab_destroy(queue->slab_req);

free_queue:
	nvmf_free(rdma_queue);

	return ret;
}

static int nvmf_rdma_free_resource(struct nvmf_rdma_queue *rdma_queue)
{
	log_trace();

	if (rdma_queue->cq) {
		nvmf_rdma_cq_event(rdma_queue->queue, POLLIN);
		ibv_ack_cq_events(rdma_queue->cq, rdma_queue->cq_events);

		/* clear POLLIN/POLLOUT event handler */
		nvmf_queue_set_event(rdma_queue->queue, rdma_queue->comp_channel->fd, NULL, NULL);
		ibv_destroy_cq(rdma_queue->cq);
		rdma_queue->cq = NULL;
	}

	if (rdma_queue->cm_id) {
		rdma_disconnect(rdma_queue->cm_id);
		nvmf_queue_wait_state(rdma_queue->queue, QUEUE_STATE_DYING, 2000);
		nvmf_queue_set_event(rdma_queue->queue, rdma_queue->cma_channel->fd, NULL, NULL);
		rdma_destroy_qp(rdma_queue->cm_id);
		rdma_queue->cm_id = NULL;
	}

	if (rdma_queue->cmd_mr) {
		ibv_dereg_mr(rdma_queue->cmd_mr);
		rdma_queue->cmd_mr = NULL;
	}

	if (rdma_queue->data_mr) {
		ibv_dereg_mr(rdma_queue->data_mr);
		rdma_queue->data_mr = NULL;
	}

	if (rdma_queue->cqe_mr) {
		ibv_dereg_mr(rdma_queue->cqe_mr);
		rdma_queue->cqe_mr = NULL;
	}

	if (rdma_queue->comp_channel) {
		ibv_destroy_comp_channel(rdma_queue->comp_channel);
		rdma_queue->comp_channel = NULL;
	}

	if (rdma_queue->pd) {
		ibv_dealloc_pd(rdma_queue->pd);
		rdma_queue->pd = NULL;
	}

	if (rdma_queue->cm_id) {
		rdma_destroy_id(rdma_queue->cm_id);
		rdma_queue->cm_id = NULL;
	}

	if (rdma_queue->cma_channel) {
		rdma_destroy_event_channel(rdma_queue->cma_channel);
		rdma_queue->cma_channel = NULL;
	}

	return 0;
}

static int nvmf_rdma_release_queue(struct nvmf_queue *queue)
{
	struct nvmf_rdma_queue *rdma_queue = (struct nvmf_rdma_queue *)queue->priv;
	int ret = 0;

	log_trace();

	nvmf_rdma_free_resource(rdma_queue);

	if (rdma_queue->cqes) {
		nvmf_free(rdma_queue->cqes);
	}

	if (rdma_queue->cqe_sges) {
		nvmf_free(rdma_queue->cqe_sges);
	}

	if (rdma_queue->recv_wrs) {
		nvmf_free(rdma_queue->recv_wrs);
	}

	if (rdma_queue->slab_priv) {
		slab_destroy(rdma_queue->slab_priv);
	}

	if (queue->slab_req) {
		slab_destroy(queue->slab_req);
	}

	if (rdma_queue->buddy) {
		buddy_destroy(rdma_queue->buddy);
	}

	if (rdma_queue) {
		nvmf_free(rdma_queue);
	}

	return ret;
}

static int nvmf_rdma_restart_queue(struct nvmf_queue *queue)
{
	struct nvmf_rdma_queue *rdma_queue = (struct nvmf_rdma_queue *)queue->priv;
	int ret;

	log_debug("queue[%d]restart rdma queue\n", queue->qid);
	nvmf_rdma_free_resource(rdma_queue);

	ret = nvmf_rdma_initialize_connection(rdma_queue);
	if (ret < 0) {
		return ret;
	}

	nvmf_rdma_queue_buffer_setup(rdma_queue);

	return 0;
}

static struct nvmf_request *nvmf_rdma_alloc_request(struct nvmf_queue *queue)
{
	struct nvmf_rdma_queue *rdma_queue = (struct nvmf_rdma_queue *)queue->priv;
	struct nvmf_request *req;
	struct nvmf_rdma_priv *priv;

	req = (struct nvmf_request *)slab_alloc(queue->slab_req);
	if (!req) {
		return NULL;
	}

	priv = (struct nvmf_rdma_priv *)slab_alloc(rdma_queue->slab_priv);
	assert(priv);	/* it should not happen */

	memset(req, 0x00, sizeof(*req));
	memset(priv, 0x00, sizeof(*priv));

	req->priv = priv;
	req->cmd = &priv->cmd;
	req->cqe = &priv->cqe;

	return req;
}

static void nvmf_rdma_free_request(struct nvmf_request *req)
{
	struct nvmf_rdma_queue *rdma_queue = (struct nvmf_rdma_queue *)req->queue->priv;
	struct nvmf_rdma_priv *priv = (struct nvmf_rdma_priv *)req->priv;
	log_trace();

	if (priv->data_size) {
		if (priv->data_mr) {
			ibv_dereg_mr(priv->data_mr);
			nvmf_free(priv->data);
		} else {
			buddy_free(rdma_queue->buddy, priv->data);
		}
	}

	slab_free(rdma_queue->slab_priv, req->priv);
	slab_free(req->queue->slab_req, req);
}

static inline size_t nvme_rdma_incapsule_size(struct nvmf_rdma_queue *queue)
{
	return queue->cmnd_capsule_len - sizeof(struct nvme_command);
}

static inline int nvme_rdma_set_sg_null(struct nvme_command *cmd)
{
	struct nvme_keyed_sgl_desc *sg = &cmd->common.dptr.ksgl;

	sg->addr = 0;
	set_unaligned_le24((__u8 *)&sg->length, 0);
	set_unaligned_le32((__u8 *)&sg->key, 0);
	sg->type = (NVME_KEY_SGL_FMT_DATA_DESC << 4);

	log_debug("cmd = 0x%x, addr = 0x%llx\n", cmd->common.opcode, sg->addr);
	return 0;
}

static inline int nvme_rdma_set_sg_incapsule(struct nvmf_request *req,
                                             struct nvmf_rdma_queue *rdma_queue,
                                             struct nvme_command *cmd, __u32 bufflen)
{
	struct nvme_sgl_desc *sg = &cmd->common.dptr.sgl;
	struct nvmf_rdma_priv *priv = (struct nvmf_rdma_priv *)req->priv;
	struct ibv_sge *sge = &priv->sges[SGE_INCAPSULE];
	struct ibv_mr *data_mr = rdma_queue->data_mr;

	if (priv->data_mr) {
		data_mr = priv->data_mr;
	}

	/* sgl in cmd */
	sg->addr = htole64(rdma_queue->queue->ctrl->icdoff);
	sg->length = htole32(bufflen);
	sg->type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_OFFSET;

	/* sge for incapsule data */
	sge->addr = (uint64_t)priv->data;
	sge->length = priv->data_size;
	sge->lkey = data_mr->lkey;

	log_debug("cmd = 0x%x, addr = 0x%llx, length = %d, incapsule sge addr = 0x%lx, "
                  "length = %d, lkey = 0x%x\n", cmd->common.opcode, sg->addr, le32toh(sg->length),
                  sge->addr, sge->length, sge->lkey);

	return 1;
}

static inline int nvme_rdma_set_sg_host_data(struct nvmf_request *req,
                                             struct nvmf_rdma_queue *rdma_queue,
                                             struct nvme_command *cmd)
{
	struct nvme_keyed_sgl_desc *sg = &cmd->common.dptr.ksgl;
	struct nvmf_rdma_priv *priv = (struct nvmf_rdma_priv *)req->priv;
	struct ibv_mr *data_mr = rdma_queue->data_mr;

	if (priv->data_mr) {
		data_mr = priv->data_mr;
	}

	sg->addr = (__le64)priv->data;
	set_unaligned_le24((__u8 *)&sg->length, priv->data_size);
	set_unaligned_le32((__u8 *)&sg->key, data_mr->rkey);
	sg->type = (NVME_KEY_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_ADDRESS
	           | NVME_SGL_FMT_INVALIDATE;

	log_debug("cmd = 0x%x, length = %ld, addr = %p, key = 0x%x\n", cmd->common.opcode,
                  priv->data_size, data_mr->addr, data_mr->rkey);

	return 0;
}

static inline int nvmf_rdma_map_data(struct nvmf_request *req, struct nvmf_rdma_queue *rdma_queue,
                                     size_t data_len)
{
	struct nvme_command *cmd = req->cmd;
	bool is_write = nvme_is_write(cmd);
	int ret;

	cmd->common.flags |= NVME_CMD_SGL_METABUF;

	if (!data_len) {
		ret = nvme_rdma_set_sg_null(cmd);
	} else if (is_write && data_len <= nvme_rdma_incapsule_size(rdma_queue)) {
		ret = nvme_rdma_set_sg_incapsule(req, rdma_queue, cmd, data_len);
	} else {
		ret = nvme_rdma_set_sg_host_data(req, rdma_queue, cmd);
	}

	return ret;
}

static int nvmf_rdma_queue_request(struct nvmf_request *req, struct iovec *iovs, int iovcnt)
{
	log_trace();

	assert(iovcnt < NVMF_MAX_IOV);
	req->iovcnt = iovcnt;
	req->iovs = iovs;

	nvmf_queue_req(req->queue, req);

	return 0;
}

static int nvmf_rdma_queue_send(struct nvmf_queue *queue)
{
	struct nvmf_request *req;
	struct nvmf_rdma_priv *priv;
	struct ibv_sge *sge;
	struct ibv_send_wr send_wr, *bad_wr;
	struct nvmf_rdma_queue *rdma_queue = (struct nvmf_rdma_queue *)queue->priv;
	int access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	int another_sge;

	while (1) {
		req = nvmf_queue_grab_req(queue);
		if (!req) {
			return 0;
		}

		nvmf_queue_req_inflight(req);
		log_debug("queue[%d] sending req %p\n", rdma_queue->queue->qid, req);
		priv = (struct nvmf_rdma_priv *)req->priv;

		/* build cmd sge */
		sge = &priv->sges[SGE_CMD];
		sge->addr = (uint64_t)&priv->cmd;
		sge->length = sizeof(priv->cmd);
		sge->lkey = rdma_queue->cmd_mr->lkey;

		/* build data sge */
		priv->data_size = nvmf_iov_datalen(req->iovs, req->iovcnt);
		if (priv->data_size) {
			priv->data = buddy_alloc(rdma_queue->buddy, priv->data_size);
			/* sad, buddy is full, alloc slow path */
			if (!priv->data) {
				priv->data = nvmf_calloc(1, priv->data_size);
				priv->data_mr = ibv_reg_mr(rdma_queue->pd, priv->data,
                                                           priv->data_size, access);
			}
		}

		if (nvme_is_write(req->cmd)) {
			nvmf_iov_to_buf(req->iovs, req->iovcnt, priv->data);
		}

		another_sge = nvmf_rdma_map_data(req, rdma_queue, priv->data_size);

		memset(&send_wr, 0, sizeof(send_wr));
		send_wr.next = NULL;
		send_wr.wr_id = (uintptr_t)req;
		send_wr.sg_list = &priv->sges[0];
		send_wr.num_sge = 1 + another_sge;
		send_wr.opcode = IBV_WR_SEND;
		send_wr.send_flags = IBV_SEND_SIGNALED;
		if (ibv_post_send(rdma_queue->qp, &send_wr, &bad_wr)) {
			log_error("queue[%d] ibv_post_send failed, %m\n", rdma_queue->queue->qid);
			return -1;
		}
	}

	return 0;
}

static int nvmf_rdma_ctrl_process_queue(struct nvmf_queue *queue, short revents)
{
	struct nvmf_ctrl *ctrl = queue->ctrl;
	unsigned int nr_queues = ctrl->opts->nr_queues;
	int ret = 0;

	log_trace();
	if (queue->qid >= nr_queues) {
		return -EINVAL;
	}

	/* try to send pending requests */
	nvmf_rdma_queue_send(queue);

	return ret;
}

static struct nvmf_transport_ops nvmf_rdma_ops = {
	.name = "rdma",
	.ctrl_process_queue = nvmf_rdma_ctrl_process_queue,
	.create_queue = nvmf_rdma_create_queue,
	.release_queue = nvmf_rdma_release_queue,
	.restart_queue = nvmf_rdma_restart_queue,
	.alloc_request = nvmf_rdma_alloc_request,
	.free_request =  nvmf_rdma_free_request,
	.queue_request = nvmf_rdma_queue_request,
};

void nvmf_transport_rdma_init(void)
{
	nvmf_transport_register(&nvmf_rdma_ops);
}
#endif
