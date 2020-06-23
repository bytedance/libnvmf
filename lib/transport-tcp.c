/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "nvmf-private.h"
#include "nvme.h"
#include "nvmf.h"
#include "nvme-tcp.h"
#include "log.h"
#include "utils.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <endian.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <assert.h>

/* defined in section "PDU Header and Data Digests" */
#define FIELD_HEADER	0
#define FIELD_HDGST	1
#define FIELD_CPDA	2
#define FIELD_DDGST	3

#define FIELD_FIXED	4

#define QUEUE_MAX_IOV	(NVMF_MAX_IOV + FIELD_FIXED)

struct nvmf_tcp_queue {
	struct nvmf_queue *queue;
	int sockfd;

	size_t cmnd_capsule_len;

	bool hdr_digest;
	bool data_digest;

	__u8 hpda;	/* TODO, not support currently */
	__u8 cpda;	/* TODO, not support currently */
	char pad[64];

	/* slab for nvmf_tcp_priv */
	slab_t slab_priv;

	/* current processing request */
	struct nvme_tcp_rsp_pdu rsppdu;

	/* unlikely we have received a incomplete pdu */
	size_t pdu_rwsize;

	/* current inputing request */
	struct nvmf_request *i_req;
	int i_iovcnt;
	struct iovec i_iovs[QUEUE_MAX_IOV];
	size_t i_totalsize;
	size_t i_rwsize;

	/* current outputing request */
	struct nvmf_request *o_req;
	int o_iovcnt;
	struct iovec o_iovs[QUEUE_MAX_IOV];
	size_t o_totalsize;
	size_t o_rwsize;
};

struct nvmf_tcp_priv {
	struct nvme_tcp_cmd_pdu cmdpdu;
	struct nvme_tcp_data_pdu datapdu;
	struct nvme_tcp_rsp_pdu rsppdu;

	struct iovec iovs[QUEUE_MAX_IOV];

	bool incapsule;
	/* header & data digest */
	__le32 hdigest;
	__le32 ddigest;
	__u32 r2t_offset;
	__u32 r2t_length;
	__u32 c2h_offset;
	__u32 c2h_length;
};

static void nvmf_tcp_free_request(struct nvmf_request *req);
static int nvmf_tcp_ctrl_process_queue(struct nvmf_queue *queue, short revents);

static inline __u8 nvme_tcp_hdgst_len(struct nvmf_tcp_queue *tcp_queue)
{
	return tcp_queue->hdr_digest ? NVME_TCP_DIGEST_LENGTH : 0;
}

static inline __u8 nvme_tcp_ddgst_len(struct nvmf_tcp_queue *tcp_queue)
{
	return tcp_queue->data_digest ? NVME_TCP_DIGEST_LENGTH : 0;
}


static inline size_t nvme_tcp_incapsule_size(struct nvmf_tcp_queue *tcp_queue)
{
	return tcp_queue->cmnd_capsule_len - sizeof(struct nvme_command);
}


static inline int nvmf_tcp_queue_id(struct nvmf_tcp_queue *tcp_queue)
{
	return tcp_queue->queue->qid;
}

static inline void nvmf_tcp_iovs_dump(struct iovec *iovs, int iovcnt)
{
	struct iovec *iov;
	int i, ret, size = iovcnt * 64;
	char *buf = nvmf_calloc(1, size);
	char *p = buf;

	for (i = 0; i < iovcnt; i++) {
		iov = iovs + i;
		ret = sprintf(p, "iov[%d][0x%p][%ld] ", i, iov->iov_base, iov->iov_len);
		p += ret;
	}

	log_error("iovcnt[%d] %s\n", iovcnt, buf);
	nvmf_free(buf);
}

static inline void nvmf_tcp_queue_dump(struct nvmf_tcp_queue *tcp_queue)
{
	log_error("queue[%d], sockfd %d, size %d, cmnd_capsule_len %ld\n",
                  tcp_queue->queue->qid, tcp_queue->sockfd, tcp_queue->queue->qsize,
                  tcp_queue->cmnd_capsule_len);

	if (tcp_queue->i_req) {
		log_error("\t input req %p, iovcnt %d, totalsize %ld, rwsize %ld\n",
                          tcp_queue->i_req, tcp_queue->i_iovcnt, tcp_queue->i_totalsize,
                          tcp_queue->i_rwsize);
		nvmf_tcp_iovs_dump(tcp_queue->i_iovs, tcp_queue->i_iovcnt);
	}

	if (tcp_queue->o_req) {
		log_error("\toutput req %p, iovcnt %d, totalsize %ld, rwsize %ld\n",
                          tcp_queue->o_req, tcp_queue->o_iovcnt, tcp_queue->o_totalsize,
                          tcp_queue->o_rwsize);
		nvmf_tcp_iovs_dump(tcp_queue->o_iovs, tcp_queue->o_iovcnt);
	}
}

/* send ICReq & recv ICResp */
static int nvmf_tcp_initialize_connection(struct nvmf_tcp_queue *tcp_queue)
{
	int ret;
	struct nvme_tcp_icreq_pdu icreq = {0};
	struct nvme_tcp_icresp_pdu icresp = {0};
	bool hdr_digest;
	bool data_digest;

	icreq.hdr.type = nvme_tcp_icreq;
	icreq.hdr.hlen = sizeof(icreq);
	icreq.hdr.pdo = 0;
	icreq.hdr.plen = htole32(icreq.hdr.hlen);
	icreq.pfv = htole16(NVME_TCP_PFV_1_0);
	icreq.maxr2t = 0;
	icreq.hpda = tcp_queue->hpda;
	if (tcp_queue->hdr_digest) {
		icreq.digest |= NVME_TCP_HDR_DIGEST_ENABLE;
	}

	if (tcp_queue->data_digest) {
		icreq.digest |= NVME_TCP_DATA_DIGEST_ENABLE;
	}

	ret = send(tcp_queue->sockfd, &icreq, sizeof(icreq), 0);
	if (ret < 0) {
		log_error("send icreq error, %m");
		return ret;
	}

	ret = recv(tcp_queue->sockfd, &icresp, sizeof(icresp), 0);
	if (ret < 0) {
		log_error("recv icresp error, queue[%d]: %m", nvmf_tcp_queue_id(tcp_queue));
		return ret;
	} else if (ret != sizeof(icresp)) {
		log_error("recv icresp error, queue %d: real len(%d) != expected(%d)",
                          nvmf_tcp_queue_id(tcp_queue), ret, (int)sizeof(icreq));
		return -EINVAL;
	}

	if (icresp.hdr.type != nvme_tcp_icresp) {
		log_error("type error, queue %d: %d\n", nvmf_tcp_queue_id(tcp_queue),
                          icresp.hdr.type);
		return -EINVAL;
	}

	if (le32toh(icresp.hdr.plen) != sizeof(icresp)) {
		log_error("length error, queue %d: %d\n", nvmf_tcp_queue_id(tcp_queue),
                          icresp.hdr.plen);
		return -EINVAL;
	}

	if (icresp.pfv != NVME_TCP_PFV_1_0) {
		log_error("pfv error, queue %d: %d\n", nvmf_tcp_queue_id(tcp_queue), icresp.pfv);
		return -EINVAL;
	}

	data_digest = !!(icresp.digest & NVME_TCP_DATA_DIGEST_ENABLE);
	if (tcp_queue->data_digest != data_digest) {
		log_error("data digest error, queue %d: local: %c target: %c\n",
				nvmf_tcp_queue_id(tcp_queue), tcp_queue->data_digest, data_digest);
		return -EINVAL;
	}

	hdr_digest = !!(icresp.digest & NVME_TCP_HDR_DIGEST_ENABLE);
	if (tcp_queue->hdr_digest != hdr_digest) {
		log_error("header digest error, queue %d: local: %c target: %c\n",
                          nvmf_tcp_queue_id(tcp_queue), tcp_queue->data_digest, data_digest);
		return -EINVAL;
	}

	if (icresp.cpda != 0) {
		log_error("cpda error, queue %d, cpda %d\n", nvmf_tcp_queue_id(tcp_queue),
                          icresp.cpda);
		return -EINVAL;
	}

	tcp_queue->cpda = icresp.cpda;

	return 0;
}

static int nvmf_tcp_init_socket(struct nvmf_tcp_queue *tcp_queue)
{
	struct nvmf_queue *queue = tcp_queue->queue;
	struct nvmf_ctrl_options *opts;
	struct sockaddr_in taddr;
	struct linger so_linger = { .l_onoff = 1, .l_linger = 1 };
	int ret, opt;

	ret = socket(AF_INET, SOCK_STREAM, 0);
	if (ret < 0) {
		log_error("socket error\n");
		return ret;
	}

	tcp_queue->sockfd = ret;

	opt = 6;
	ret = setsockopt(tcp_queue->sockfd, SOL_TCP, TCP_SYNCNT, &opt, sizeof(opt));
	if (ret < 0) {
		log_error("setsockopt TCP_SYNCNT error\n");
		goto closefd;
	}

	opt = 1;
	ret = setsockopt(tcp_queue->sockfd, SOL_TCP, TCP_NODELAY, &opt,
			sizeof(opt));
	if (ret < 0) {
		log_error("setsockopt TCP_SYNCNT error\n");
		goto closefd;
	}

	/* try to close connection gracefully */
	ret = setsockopt(tcp_queue->sockfd, SOL_SOCKET, SO_LINGER, &so_linger,
			sizeof(so_linger));
	if (ret < 0) {
		log_error("setsockopt SO_LINGER error\n");
		goto closefd;
	}

	opts = queue->ctrl->opts;
	taddr.sin_family = AF_INET;
	taddr.sin_addr.s_addr = inet_addr(opts->traddr);
	taddr.sin_port = htons(atoi((opts->trsvcid)));
	ret = connect(tcp_queue->sockfd, &taddr, sizeof(taddr));
	if (ret < 0) {
		log_error("socket connect error\n");
		goto closefd;
	}

	return 0;

closefd:
	close(tcp_queue->sockfd);

	return -1;
}

static int nvmf_tcp_create_queue(struct nvmf_queue *queue)
{
	struct nvmf_tcp_queue *tcp_queue;
	int ret, qsize;

	log_trace();
	tcp_queue = nvmf_calloc(1, sizeof(*tcp_queue));
	if (!tcp_queue) {
		return -ENOMEM;
	}

	tcp_queue->queue = queue;
	queue->priv = tcp_queue;
	if (queue->qid == 0) {
		tcp_queue->cmnd_capsule_len = sizeof(struct nvme_command) + NVME_TCP_ADMIN_CCSZ;
		qsize = NVME_AQ_DEPTH;
	} else {
		tcp_queue->cmnd_capsule_len = queue->ctrl->ioccsz * 16;
		qsize = queue->ctrl->opts->qsize;
	}

	queue->qsize = qsize;
	queue->slab_req = slab_create("", sizeof(struct nvmf_request), qsize);
	if (!queue->slab_req) {
		ret = -ENOMEM;
		goto free_queue;
	}

	tcp_queue->slab_priv = slab_create("", sizeof(struct nvmf_tcp_priv), qsize);
	if (!tcp_queue->slab_priv) {
		ret = -ENOMEM;
		goto free_slab;
	}

	ret = nvmf_tcp_init_socket(tcp_queue);
	if (ret < 0) {
		goto free_priv;
	}

	ret = nvmf_tcp_initialize_connection(tcp_queue);
	if (ret < 0) {
		goto closefd;
	}

	nvmf_set_nonblock(tcp_queue->sockfd);

	nvmf_queue_set_event(queue, tcp_queue->sockfd, nvmf_tcp_ctrl_process_queue,
                             nvmf_tcp_ctrl_process_queue);
	return ret;

closefd:
	close(tcp_queue->sockfd);

free_priv:
	slab_destroy(tcp_queue->slab_priv);

free_slab:
	slab_destroy(queue->slab_req);

free_queue:
	nvmf_free(tcp_queue);

	return ret;
}

static int nvmf_tcp_release_queue(struct nvmf_queue *queue)
{
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)queue->priv;
	int ret = 0;

	log_trace();

	nvmf_queue_set_event(queue, tcp_queue->sockfd, NULL, NULL);
	slab_destroy(tcp_queue->slab_priv);
	slab_destroy(queue->slab_req);
	close(tcp_queue->sockfd);
	nvmf_free(tcp_queue);

	return ret;
}

static int nvmf_tcp_restart_queue(struct nvmf_queue *queue)
{
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)queue->priv;
	int ret;

	log_debug("queue[%d]restart tcp queue\n", queue->qid);

	nvmf_queue_set_event(queue, tcp_queue->sockfd, NULL, NULL);

	if (tcp_queue->sockfd > 0) {
		close(tcp_queue->sockfd);
	}

	ret = nvmf_tcp_init_socket(tcp_queue);
	if (ret) {
		return ret;
	}

	ret = nvmf_tcp_initialize_connection(tcp_queue);
	if (ret < 0) {
		goto closefd;
	}

	nvmf_set_nonblock(tcp_queue->sockfd);

	nvmf_queue_set_event(queue, tcp_queue->sockfd, nvmf_tcp_ctrl_process_queue,
                             nvmf_tcp_ctrl_process_queue);

	return 0;

closefd:
	close(ret);

	return ret;
}

static inline size_t nvmf_tcp_iov_datalen(struct nvmf_request *req)
{
	size_t datalen = 0;
	int index;

	for (index = 0; index < req->iovcnt; index++) {
		datalen += req->iovs[index].iov_len;
	}

	return datalen;
}

static inline size_t nvmf_tcp_priv_datalen(struct nvmf_request *req)
{
	struct nvmf_tcp_priv *priv = (struct nvmf_tcp_priv *)req->priv;
	size_t datalen = 0;
	int index;

	for (index = 0; index < FIELD_FIXED; index++) {
		datalen += priv->iovs[index].iov_len;
	}

	return datalen;
}

static inline struct iovec *nvmf_tcp_req_iov(struct nvmf_request *req, int index)
{
	struct nvmf_tcp_priv *priv = (struct nvmf_tcp_priv *)req->priv;

	/* should not overflow */
	assert(index < FIELD_FIXED);

	return priv->iovs + index;
}

static inline void nvmf_tcp_queue_clear_input(struct nvmf_tcp_queue *queue)
{
	queue->i_req = NULL;
	queue->i_iovcnt = 0;
	queue->i_totalsize = 0;
	queue->i_rwsize = 0;
	memset(queue->i_iovs, 0x00, sizeof(queue->i_iovs));
}

static inline void nvmf_tcp_queue_clear_output(struct nvmf_tcp_queue *queue)
{
	queue->o_req = NULL;
	queue->o_iovcnt = 0;
	queue->o_totalsize = 0;
	queue->o_rwsize = 0;
	memset(queue->o_iovs, 0x00, sizeof(queue->o_iovs));
}

static inline void nvme_tcp_set_sg_null(struct nvme_command *cmd)
{
	struct nvme_sgl_desc *sg = &cmd->common.dptr.sgl;

	sg->addr = 0;
	sg->length = 0;
	sg->type = (NVME_TRANSPORT_SGL_DATA_DESC << 4) | NVME_SGL_FMT_TRANSPORT_A;

	log_debug("cmd = 0x%x, length = %d\n", cmd->common.opcode, sg->length);
}

static inline void nvme_tcp_set_sg_incapsule(struct nvmf_tcp_queue *tcp_queue,
		struct nvme_command *cmd, __u32 bufflen)
{
	struct nvme_sgl_desc *sg = &cmd->common.dptr.sgl;

	sg->addr = htole64(tcp_queue->queue->ctrl->icdoff);
	sg->length = htole32(bufflen);
	sg->type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_OFFSET;

	log_debug("cmd = 0x%x, addr = 0x%llx, length = %d\n", cmd->common.opcode, sg->addr,
                  le32toh(sg->length));
}

static inline void nvme_tcp_set_sg_host_data(struct nvme_command *cmd,
		__u32 bufflen)
{
	struct nvme_sgl_desc *sg = &cmd->common.dptr.sgl;

	sg->addr = 0;
	sg->length = htole32(bufflen);
	sg->type = (NVME_TRANSPORT_SGL_DATA_DESC << 4) | NVME_SGL_FMT_TRANSPORT_A;

	log_debug("cmd = 0x%x, length = %d\n", cmd->common.opcode, le32toh(sg->length));
}

static inline int nvmf_tcp_map_data(struct nvmf_request *req, struct nvmf_tcp_queue *queue)
{
	struct nvme_command *cmd = req->cmd;
	__u32 data_len = nvmf_tcp_iov_datalen(req);
	bool is_write = nvme_is_write(cmd);

	cmd->common.flags |= NVME_CMD_SGL_METABUF;

	if (!data_len) {
		nvme_tcp_set_sg_null(cmd);
	} else if (is_write && data_len <= nvme_tcp_incapsule_size(queue)) {
		nvme_tcp_set_sg_incapsule(queue, cmd, data_len);
	} else {
		nvme_tcp_set_sg_host_data(cmd, data_len);
	}

	return 0;
}
static int nvmf_tcp_build_req(struct nvmf_request *req)
{
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)req->queue->priv;
	struct nvmf_tcp_priv *priv = (struct nvmf_tcp_priv *)req->priv;
	struct nvme_tcp_cmd_pdu *pdu = &priv->cmdpdu;
	struct nvme_tcp_hdr *hdr = &pdu->hdr;
	struct nvme_command *cmd = req->cmd;
	struct iovec *iov;
	__u32 data_len;
	__u32 pdu_len = 0;
	__u8 hdgst = nvme_tcp_hdgst_len(tcp_queue);
	__u8 ddgst = nvme_tcp_ddgst_len(tcp_queue);
	bool is_write = nvme_is_write(cmd);

	data_len = nvmf_tcp_iov_datalen(req);
	if (is_write && data_len <= nvme_tcp_incapsule_size(tcp_queue)) {
		pdu_len = data_len;
		priv->incapsule = true;
	}

	hdr->type = nvme_tcp_cmd;
	hdr->flags = 0;
	if (tcp_queue->hdr_digest) {
		hdr->flags |= NVME_TCP_F_HDGST;
	}

	if (tcp_queue->data_digest && req->iovcnt) {
		hdr->flags |= NVME_TCP_F_DDGST;
	}

	hdr->hlen = sizeof(struct nvme_tcp_cmd_pdu);
	hdr->pdo = pdu_len ? hdr->hlen + hdgst : 0;
	hdr->plen = htole32(hdr->hlen + hdgst + pdu_len + ddgst);

	/* 1, build nvme_tcp_cmd_pdu for FIELD_HEADER */
	iov = nvmf_tcp_req_iov(req, FIELD_HEADER);
	iov->iov_base = pdu;
	iov->iov_len = sizeof(struct nvme_tcp_cmd_pdu);

	/* 2, build hdgst for FIELD_HDGST */
	if (hdgst) {
		/* TODO write hdgst in iov */
		iov = nvmf_tcp_req_iov(req, FIELD_HDGST);
		iov->iov_base = &priv->hdigest;
		iov->iov_len = hdgst;
	}

	/* 3, build CPDA for FIELD_CPDA */
	if (tcp_queue->cpda) {
		/* TODO write cpda PAD data in iov */
		iov = nvmf_tcp_req_iov(req, FIELD_CPDA);
		iov->iov_base = tcp_queue->pad;
		iov->iov_len = tcp_queue->cpda;
	}

	/* 4, build ddgst for FIELD_DDGST */
	if (ddgst) {
		/* TODO write ddgst in iov */
		iov = nvmf_tcp_req_iov(req, FIELD_DDGST);
		iov->iov_base = &priv->ddigest;
		iov->iov_len = ddgst;
	}

	/* 5, build data mapping for cmd */
	nvmf_tcp_map_data(req, tcp_queue);

	return 0;
}

static int nvmf_tcp_queue_send(struct nvmf_tcp_queue *tcp_queue)
{
	struct nvmf_tcp_priv *priv;
	struct iovec iovs[QUEUE_MAX_IOV];
	struct iovec *iov = NULL, *o_iov;
	struct nvmf_request *req = NULL;
	ssize_t rwsize = 0, offset, totalsize = 0, ret;
	int tag, iovcnt = 0, iovidx;

	/* previous outputing req is still in process? */
	if (unlikely(tcp_queue->o_req)) {
		/* called from epoll POLLOUT, continue to send */
		for (iovidx = 0; iovidx < tcp_queue->o_iovcnt; iovidx++) {
			iov = &tcp_queue->o_iovs[iovidx];
			if (rwsize + iov->iov_len < tcp_queue->o_rwsize) {
				rwsize += iov->iov_len;
			} else {
				break;
			}
		}

		/* build remaining data outputing vector */
		offset = tcp_queue->o_rwsize - rwsize;
		o_iov = &iovs[iovcnt++];
		o_iov->iov_base = iov->iov_base + offset;
		o_iov->iov_len = iov->iov_len - offset;

		for (iovidx++; iovidx < tcp_queue->o_iovcnt; iovidx++) {
			iov = &tcp_queue->o_iovs[iovidx];
			o_iov = &iovs[iovcnt++];
			*o_iov = *iov;
		}

		ret = writev(tcp_queue->sockfd, iovs, iovcnt);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}

			log_error("queue[%d] req[%p] tag[0x%x]writev tcp cmd error, %m\n",
                                  tcp_queue->queue->qid, tcp_queue->o_req, tcp_queue->o_req->tag);
			nvmf_tcp_queue_dump(tcp_queue);
			return -errno;
		}

		tcp_queue->o_rwsize += ret;
		log_debug("queue[%d] req[%p] tag[0x%x]sending pdu %ld bytes: total[%ld] - "
                          "sent[%ld] = remained[%ld]\n", tcp_queue->queue->qid, tcp_queue->o_req,
                          tcp_queue->o_req->tag, ret, tcp_queue->o_totalsize, tcp_queue->o_rwsize,
                          tcp_queue->o_totalsize - tcp_queue->o_rwsize);
		if (tcp_queue->o_rwsize < tcp_queue->o_totalsize) {
			return ret;
		}
		/* if current outputing req send completely, fallthrough process_one */
	}

process_one:
	nvmf_tcp_queue_clear_output(tcp_queue);
	/* try to send a new req fully, build queue->o_iovs */
	req = nvmf_queue_grab_req(tcp_queue->queue);
	if (!req) {
		return 0;
	}

	nvmf_request_set_lat(req, REQ_GRABED);
	nvmf_queue_req_inflight(req);

	/* a request runs in r2t state, it has already allocated a tag */
	priv = (struct nvmf_tcp_priv *)req->priv;
	if (!req->tag && !priv->r2t_length) {
		tag = nvmf_queue_req_get_tag(req);
		req->tag = tag;
		req->cmd->common.command_id = tag;

		nvmf_tcp_build_req(req);
	}

	tcp_queue->o_req = req;
	for (iovidx = 0; iovidx <= FIELD_CPDA; iovidx++) {
		iov = nvmf_tcp_req_iov(req, iovidx);
		if (!iov->iov_len) {
			continue;
		}

		o_iov = &tcp_queue->o_iovs[tcp_queue->o_iovcnt++];
		*o_iov = *iov;
		tcp_queue->o_totalsize += iov->iov_len;
	}

	if (priv->incapsule) {
		for (iovidx = 0; iovidx < req->iovcnt; iovidx++) {
			iov = &req->iovs[iovidx];
			if (!iov->iov_len) {
				continue;
			}

			o_iov = &tcp_queue->o_iovs[tcp_queue->o_iovcnt++];
			*o_iov = *iov;
			tcp_queue->o_totalsize += iov->iov_len;
		}
	} else if (priv->r2t_length) {
		rwsize = 0;
		for (iovidx = 0; iovidx < req->iovcnt; iovidx++) {
			iov = &req->iovs[iovidx];
			if (rwsize + iov->iov_len < priv->r2t_offset) {
				rwsize += iov->iov_len;
			} else {
				break;
			}
		}

		/* build remaining data outputing vector */
		offset = priv->r2t_offset - rwsize;
		o_iov = &tcp_queue->o_iovs[tcp_queue->o_iovcnt++];
		o_iov->iov_base = iov->iov_base + offset;
		o_iov->iov_len = iov->iov_len - offset;
		totalsize = o_iov->iov_len;

		for (iovidx++; iovidx < req->iovcnt; iovidx++) {
			iov = &req->iovs[iovidx];
			o_iov = &tcp_queue->o_iovs[tcp_queue->o_iovcnt++];
			if (totalsize + iov->iov_len < priv->r2t_length) {
				*o_iov = *iov;
				totalsize += iov->iov_len;
			} else {
				ret = priv->r2t_length - totalsize;
				o_iov->iov_base = iov->iov_base;
				o_iov->iov_len = priv->r2t_length - totalsize;
				totalsize = priv->r2t_length;
				break;
			}
		}

		tcp_queue->o_totalsize += totalsize;
	}

	iov = nvmf_tcp_req_iov(req, FIELD_DDGST);
	if (iov->iov_len) {
		o_iov = &tcp_queue->o_iovs[tcp_queue->o_iovcnt++];
		*o_iov = *iov;
		tcp_queue->o_totalsize += iov->iov_len;
	}

	log_debug("queue[%d] req[%p] tag[0x%x]try to send pdu\n", tcp_queue->queue->qid,
                  tcp_queue->o_req, tcp_queue->o_req->tag);
	ret = writev(tcp_queue->sockfd, tcp_queue->o_iovs, tcp_queue->o_iovcnt);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		log_error("writev tcp cmd error, %m");
		return -errno;
	}

	log_debug("queue[%d] req[%p] tag[0x%x]sending pdu %ld bytes: total[%ld] - sent[%ld] = "
                  "remained[%ld]\n", tcp_queue->queue->qid, req, req->tag, ret,
                  tcp_queue->o_totalsize, ret, tcp_queue->o_totalsize - ret);

	if (ret == tcp_queue->o_totalsize) {
		req = NULL;
		goto process_one;
	} else {
		tcp_queue->o_rwsize = ret;
	}

	return ret;
}

static int nvmf_tcp_queue_handle_rsp(struct nvmf_tcp_queue *tcp_queue, struct nvme_tcp_rsp_pdu *pdu)
{
	struct nvme_completion *cqe = &pdu->cqe;
	struct nvmf_request *req;
	struct nvmf_tcp_priv *priv;
	__u16 tag = cqe->command_id;

	req = nvmf_queue_req_by_tag(tcp_queue->queue, tag);
	if (!req) {
		/* TODO need reset controller */
		log_error("queue[%d] tag[0x%x] invalid tag from controller\n",
                          tcp_queue->queue->qid, tag);
		assert(0);
		return 0;
	}

	/* copy pdu to request body */
	priv = (struct nvmf_tcp_priv *)req->priv;
	priv->rsppdu = *pdu;

	/* should free tag before callback, otherwise we don't know req gets changed or not */
	nvmf_queue_req_finish(req);
	nvmf_request_set_lat(req, REQ_COMPLETE);

	if (req->cb) {
		req->cb(req, req->opaque);
	}

	nvmf_req_set_done(req, true);

	log_debug("queue[%d] handle rsp, queue: %d, result: 0x%lx, req[%p] tag[0x%x] sq_head: %d, "
                  "sq_id: %d, command_id: 0x%x, status: 0x%x\n", tcp_queue->queue->qid,
                  nvmf_tcp_queue_id(tcp_queue), le64toh(cqe->result.u64), req, tag,
                  le16toh(cqe->sq_head), le16toh(cqe->sq_id), cqe->command_id,
                  le16toh(cqe->status));

	return 0;
}

static int nvmf_tcp_queue_handle_c2h_data(struct nvmf_tcp_queue *tcp_queue,
                                          struct nvme_tcp_data_pdu *pdu)
{
	struct nvmf_request *req;
	struct nvmf_tcp_priv *priv;
	__u16 tag = pdu->command_id;
	__u8 hdgst = nvme_tcp_hdgst_len(tcp_queue);
	__u8 ddgst = nvme_tcp_ddgst_len(tcp_queue);
	__u32 data_offset = le32toh(pdu->data_offset);
	__u32 data_length = le32toh(pdu->data_length);
	__u32 length;
	struct iovec *iov = NULL, *i_iov;
	ssize_t ret, rwsize = 0, totalsize, offset;
	int iovidx = 0;

	req = nvmf_queue_req_by_tag(tcp_queue->queue, tag);
	if (!req) {
		log_error("queue[%d] tag[0x%x] not found\n", tcp_queue->queue->qid, tag);
		return -EINVAL;
	}

	log_debug("queue[%d] handle c2h data: req[%p] tag[0x%x] ttag: 0x%x, offset: %d, "
                  "length: %d\n", tcp_queue->queue->qid, req, pdu->command_id, pdu->ttag,
                  data_offset, data_length);

	length = nvmf_tcp_iov_datalen(req);
	if (data_offset + data_length > length) {
		log_error("read buf is not enough, offset[%d] + length[%d] < datalen[%d]\n",
                          data_offset, data_length, length);
		return -EINVAL;
	}

	priv = (struct nvmf_tcp_priv *)req->priv;
	priv->c2h_offset = data_offset;
	priv->c2h_length = data_length;

	nvmf_tcp_queue_clear_input(tcp_queue);
	tcp_queue->i_req = req;

	/* build hdgst for FIELD_HDGST */
	if (hdgst) {
		/* TODO write hdgst in iov */
		i_iov = &tcp_queue->i_iovs[tcp_queue->i_iovcnt++];
		i_iov->iov_base = &priv->hdigest;
		i_iov->iov_len = hdgst;
		tcp_queue->i_totalsize += i_iov->iov_len;
	}

	/* build CPDA for FIELD_CPDA */
	if (tcp_queue->cpda) {
		/* TODO write cpda PAD data in iov */
		i_iov = &tcp_queue->i_iovs[tcp_queue->i_iovcnt++];
		i_iov->iov_base = tcp_queue->pad;
		i_iov->iov_len = tcp_queue->cpda;
		tcp_queue->i_totalsize += i_iov->iov_len;
	}

	/* build user data outputing vectors */
	rwsize = 0;
	for (iovidx = 0; iovidx < req->iovcnt; iovidx++) {
		iov = &req->iovs[iovidx];
		if (iov->iov_len + rwsize < data_offset) {
			rwsize += iov->iov_len;
		} else {
			break;
		}
	}

	offset = data_offset - rwsize;
	i_iov = &tcp_queue->i_iovs[tcp_queue->i_iovcnt++];
	i_iov->iov_base = iov->iov_base + offset;
	i_iov->iov_len = iov->iov_len - offset;
	tcp_queue->i_totalsize += i_iov->iov_len;
	totalsize = i_iov->iov_len;

	for (iovidx++; iovidx < req->iovcnt; iovidx++) {
		iov = &req->iovs[iovidx];
		i_iov = &tcp_queue->i_iovs[tcp_queue->i_iovcnt++];
		if (totalsize + iov->iov_len < data_length) {
			*i_iov = *iov;
			totalsize += iov->iov_len;
			tcp_queue->i_totalsize += i_iov->iov_len;
		} else {
			i_iov->iov_base = iov->iov_base;
			i_iov->iov_len = data_length - totalsize;
			tcp_queue->i_totalsize += i_iov->iov_len;
			break;
		}
	}

	/* build ddgst for FIELD_DDGST */
	if (ddgst) {
		/* TODO write ddgst in iov */
		i_iov = &tcp_queue->i_iovs[tcp_queue->i_iovcnt++];
		i_iov->iov_base = &priv->ddigest;
		i_iov->iov_len = ddgst;
		tcp_queue->i_totalsize += i_iov->iov_len;
	}

	/* try to recv c2h data ASAP */
	ret = readv(tcp_queue->sockfd, tcp_queue->i_iovs, tcp_queue->i_iovcnt);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		log_error("readv tcp cmd error, %m\n");
		return -errno;
	}

	log_debug("queue[%d] input req total %lu, rwsize %lu, i_iovcnt %d\n",
                  tcp_queue->queue->qid, tcp_queue->i_totalsize, ret, tcp_queue->i_iovcnt);
	if (ret == tcp_queue->i_totalsize) {
		nvmf_tcp_queue_clear_input(tcp_queue);
		return 0;
	} else {
		tcp_queue->i_rwsize = ret;
	}

	return ret;
}

static int nvmf_tcp_send_h2c_data(struct nvmf_tcp_queue *tcp_queue, struct nvmf_request *req,
                                  struct nvme_tcp_r2t_pdu *r2tpdu)
{
	struct nvmf_tcp_priv *priv = (struct nvmf_tcp_priv *)req->priv;
	struct nvme_tcp_data_pdu *pdu;
	struct nvme_tcp_hdr *hdr;
	__u8 hdgst, ddgst;
	__u16 tag, ttag;
	__u32 offset, length, data_len;
	struct iovec *iov;

	pdu = &priv->datapdu;
	memset(pdu, 0x00, sizeof(*pdu));

	tag = r2tpdu->command_id;
	ttag = r2tpdu->ttag;
	priv->r2t_offset = offset = le32toh(r2tpdu->r2t_offset);
	priv->r2t_length = length = le32toh(r2tpdu->r2t_length);
	hdgst = nvme_tcp_hdgst_len(tcp_queue);
	ddgst = nvme_tcp_ddgst_len(tcp_queue);

	data_len = nvmf_tcp_iov_datalen(req);
	log_debug("queue[%d] req[%p] tag[0x%x] offset %d, length %d, data_len %d\n",
                  tcp_queue->queue->qid, req, tag, offset, length, data_len);
	assert(offset + length <= data_len);

	hdr = &pdu->hdr;
	hdr->type = nvme_tcp_h2c_data;
	hdr->flags = 0;
	if (tcp_queue->hdr_digest) {
		hdr->flags |= NVME_TCP_F_HDGST;
	}

	if (tcp_queue->data_digest) {
		hdr->flags |= NVME_TCP_F_DDGST;
	}

	if (offset + length == data_len) {
		hdr->flags |= NVME_TCP_F_DATA_LAST;
	}

	hdr->hlen = sizeof(struct nvme_tcp_data_pdu);
	hdr->pdo = hdr->hlen + hdgst;
	hdr->plen = htole32(sizeof(struct nvme_tcp_data_pdu) + hdgst + ddgst + length);
	pdu->command_id = tag;
	pdu->ttag = ttag;
	pdu->data_offset = htole32(offset);
	pdu->data_length = htole32(length);

	/* 1, build nvme_tcp_cmd_pdu for FIELD_HEADER */
	iov = nvmf_tcp_req_iov(req, FIELD_HEADER);
	iov->iov_base = pdu;
	iov->iov_len = sizeof(struct nvme_tcp_data_pdu);

	/* 2, build hdgst for FIELD_HDGST */
	if (hdgst) {
		/* TODO write hdgst in iov */
		iov = nvmf_tcp_req_iov(req, FIELD_HDGST);
		iov->iov_base = &priv->hdigest;
		iov->iov_len = hdgst;
	}

	/* 3, build CPDA for FIELD_CPDA */
	if (tcp_queue->cpda) {
		/* TODO write cpda PAD data in iov */
		iov = nvmf_tcp_req_iov(req, FIELD_CPDA);
		iov->iov_base = tcp_queue->pad;
		iov->iov_len = tcp_queue->cpda;
	}

	/* 4, build ddgst for FIELD_DDGST */
	if (ddgst) {
		/* TODO write ddgst in iov */
		iov = nvmf_tcp_req_iov(req, FIELD_DDGST);
		iov->iov_base = &priv->ddigest;
		iov->iov_len = ddgst;
	}

	/* remove from inflight */
	nvmf_queue_req_finish(req);
	nvmf_queue_req(tcp_queue->queue, req);

	return nvmf_tcp_queue_send(tcp_queue);
}

static int nvmf_tcp_queue_handle_r2t(struct nvmf_tcp_queue *tcp_queue, struct nvme_tcp_r2t_pdu *pdu)
{
	struct nvmf_request *req;
	__u16 tag = pdu->command_id;
	int ret;

	req = nvmf_queue_req_by_tag(tcp_queue->queue, tag);
	if (!req) {
		/* TODO need reset controller */
		log_warn("r2t: queue[%d] invalid tag[0x%x]\n", tcp_queue->queue->qid, tag);
		return -EINVAL;
	}

	log_debug("queue[%d] handle r2t: req[%p] tag[0x%x] ttag: 0x%x, r2t_offset: %d,"
                  "r2t_length: %d\n", tcp_queue->queue->qid, req, pdu->command_id, pdu->ttag,
                  le32toh(pdu->r2t_offset), le32toh(pdu->r2t_length));

	ret = nvmf_tcp_send_h2c_data(tcp_queue, req, pdu);

	return ret;
}

static int nvmf_tcp_queue_recv(struct nvmf_tcp_queue *tcp_queue)
{
	struct nvme_tcp_rsp_pdu *pdu = &tcp_queue->rsppdu;
	struct nvme_tcp_hdr *hdr = &pdu->hdr;
	struct iovec iovs[QUEUE_MAX_IOV];
	struct iovec *i_iov, *iov = NULL;
	ssize_t offset, rwsize = 0, ret;
	int iovcnt = 0, iovidx;

	if (tcp_queue->i_req) {
		/* called from epoll POLLIN, continue to recv */
		for (iovidx = 0; iovidx < tcp_queue->i_iovcnt; iovidx++) {
			iov = &tcp_queue->i_iovs[iovidx];
			if (rwsize + iov->iov_len < tcp_queue->i_rwsize) {
				rwsize += iov->iov_len;
			} else {
				break;
			}
		}

		/* build remaining data inputing vector */
		offset = tcp_queue->i_rwsize - rwsize;
		i_iov = &iovs[iovcnt++];
		i_iov->iov_base = iov->iov_base + offset;
		i_iov->iov_len = iov->iov_len - offset;

		for (iovidx++; iovidx < tcp_queue->i_iovcnt; iovidx++) {
			iov = &tcp_queue->i_iovs[iovidx];
			i_iov = &iovs[iovcnt++];
			*i_iov = *iov;
		}

		ret = readv(tcp_queue->sockfd, iovs, iovcnt);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}

			log_error("readv tcp cmd error, %m\n");
			return -errno;
		}

		tcp_queue->i_rwsize += ret;
		if (tcp_queue->i_rwsize == tcp_queue->i_totalsize) {
			nvmf_tcp_queue_clear_input(tcp_queue);
		} else {
			return ret;
		}
	}

process_one:
	/* read pdu header firstly */
	/* TODO corrupted CQE, need reset ctrl */
	memset((char *)pdu + tcp_queue->pdu_rwsize, 0x00, sizeof(*pdu) - tcp_queue->pdu_rwsize);
	ret = read(tcp_queue->sockfd, (char *)pdu + tcp_queue->pdu_rwsize,
                   sizeof(*pdu) - tcp_queue->pdu_rwsize);
	log_debug("queue[%d] ret %ld, errno %d\n", tcp_queue->queue->qid, ret, errno);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		log_error("read pdu error, queue %d: %m\n", nvmf_tcp_queue_id(tcp_queue));
		return -errno;
	} else if (ret == 0) {
		/* no more data */
		return 0;
	}

	if ((ret + tcp_queue->pdu_rwsize) < sizeof(*pdu)) {
		tcp_queue->pdu_rwsize = ret;
		return 0;
	} else {
		tcp_queue->pdu_rwsize = 0;
	}

	log_debug("queue[%d] read pdu ret: %ld, type: %d, flags: %d, hlen: %d, pdo: %d, "
                  "plen : %d\n", tcp_queue->queue->qid, ret, hdr->type, hdr->flags, hdr->hlen,
                  hdr->pdo, hdr->plen);
	switch (hdr->type) {
	case nvme_tcp_rsp:
		ret = nvmf_tcp_queue_handle_rsp(tcp_queue, pdu);
		break;
	case nvme_tcp_c2h_data:
		ret = nvmf_tcp_queue_handle_c2h_data(tcp_queue, (struct nvme_tcp_data_pdu *)pdu);
		break;
	case nvme_tcp_r2t:
		ret = nvmf_tcp_queue_handle_r2t(tcp_queue, (struct nvme_tcp_r2t_pdu *)pdu);
		break;
	default:
		log_error("queue[%d] read pdu ret: %ld, type: %d, flags: %d, hlen: %d, pdo: %d, "
                          "plen : %d\n", tcp_queue->queue->qid, ret, hdr->type, hdr->flags,
                          hdr->hlen, hdr->pdo, hdr->plen);
		nvmf_tcp_queue_dump(tcp_queue);
		assert(0);
		ret = -EIO;
		break;
	}

	/* no error, and no remaing input request, try to get a new resp pdu */
	if (!ret && !tcp_queue->i_req) {
		goto process_one;
	}

	return ret;
}

static struct nvmf_request *nvmf_tcp_alloc_request(struct nvmf_queue *queue)
{
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)queue->priv;
	struct nvmf_request *req;
	struct nvmf_tcp_priv *priv;

	log_trace();

	req = (struct nvmf_request *)slab_alloc(queue->slab_req);
	if (!req) {
		return NULL;
	}

	priv = (struct nvmf_tcp_priv *)slab_alloc(tcp_queue->slab_priv);
	assert(priv);	/* it should not happen */

	memset(req, 0x00, sizeof(*req));
	memset(priv, 0x00, sizeof(*priv));

	nvmf_request_set_lat(req, REQ_ALLOCATED);
	req->priv = priv;
	req->cmd = &priv->cmdpdu.cmd;
	req->cqe = &priv->rsppdu.cqe;

	return req;
}

static void nvmf_tcp_free_request(struct nvmf_request *req)
{
	struct nvmf_queue *queue = req->queue;
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)queue->priv;

	log_trace();

	slab_free(tcp_queue->slab_priv, req->priv);
	slab_free(queue->slab_req, req);
}

static int nvmf_tcp_queue_request(struct nvmf_request *req, struct iovec *iovs, int iovcnt)
{
	log_trace();

	assert(iovcnt < QUEUE_MAX_IOV);
	req->iovcnt = iovcnt;
	req->iovs = iovs;

	nvmf_request_set_lat(req, REQ_QUEUED);
	nvmf_queue_req(req->queue, req);

	return 0;
}

static int nvmf_tcp_queue_fd(struct nvmf_queue *queue)
{
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)queue->priv;

	return tcp_queue->sockfd;
}

static int nvmf_tcp_queue_event(struct nvmf_queue *queue)
{
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)queue->priv;
	int event = POLLIN;

	if (tcp_queue->o_req || !nvmf_queue_is_idle(queue)) {
		return event | POLLOUT;
	}

	return event;
}

static void nvmf_tcp_queue_error(struct nvmf_tcp_queue *tcp_queue)
{
	struct nvmf_queue *queue = tcp_queue->queue;

	log_error("queue[%d]fatal connection error\n", queue->qid);
	/* connection error, tcp queue has to stop any IO */
	nvmf_queue_set_event(queue, tcp_queue->sockfd, NULL, NULL);

	nvmf_queue_state_set(queue, QUEUE_STATE_ERROR);
}

static int nvmf_tcp_ctrl_process_queue(struct nvmf_queue *queue, short revents)
{
	struct nvmf_tcp_queue *tcp_queue = (struct nvmf_tcp_queue *)queue->priv;
	int fd = nvmf_tcp_queue_fd(queue);
	int ret = 0;
	short events;

	log_trace();

	if (revents & POLLIN) {
		ret = nvmf_tcp_queue_recv(tcp_queue);
		if (ret < 0) {
			nvmf_tcp_queue_error(tcp_queue);
			return -1;
		}
	}

	/* try to send pending requests */
	ret = nvmf_tcp_queue_send(tcp_queue);
	if (ret < 0) {
		nvmf_tcp_queue_error(tcp_queue);
		return -1;
	}

	events = nvmf_tcp_queue_event(queue);
	nvmf_queue_set_event(queue, fd, nvmf_tcp_ctrl_process_queue,
                             events & POLLOUT ? nvmf_tcp_ctrl_process_queue : NULL);

	return ret;
}

static struct nvmf_transport_ops nvmf_tcp_ops = {
	.name = "tcp",
	.ctrl_process_queue = nvmf_tcp_ctrl_process_queue,
	.create_queue = nvmf_tcp_create_queue,
	.release_queue = nvmf_tcp_release_queue,
	.restart_queue = nvmf_tcp_restart_queue,
	.alloc_request = nvmf_tcp_alloc_request,
	.free_request =  nvmf_tcp_free_request,
	.queue_request = nvmf_tcp_queue_request,
	.queue_fd = nvmf_tcp_queue_fd,
	.queue_event = nvmf_tcp_queue_event,
};

void nvmf_transport_tcp_init(void)
{
	nvmf_transport_register(&nvmf_tcp_ops);
}
