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
#include "nvmf-private.h"
#include "nvme.h"
#include "nvmf.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

static void nvmf_connect_admin_queue_cb(struct nvmf_request *req, void *opaque)
{
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	struct nvme_completion *cqe = req->cqe;

	log_trace();

	if (le16toh(cqe->status) != NVME_SC_SUCCESS) {
		log_error("queue[%d]connect admin queue error, status %d\n", req->queue->qid,
                          le16toh(cqe->status));
		return;
	}

	ctrl->cntlid = le16toh(cqe->result.u16);
	log_debug("queue[%d]connect admin queue, cntlid: %d\n", req->queue->qid, ctrl->cntlid);
}

static int nvmf_connect_admin_queue_req(struct nvmf_request *req, struct nvmf_queue *queue,
                                        struct nvmf_connect_data *data)
{
	struct nvmf_ctrl *ctrl = queue->ctrl;
	struct nvme_command *cmd = req->cmd;
	int ret = 0;

	memset(cmd, 0, sizeof(*cmd));
	cmd->connect.opcode = nvme_fabrics_command;
	cmd->connect.fctype = nvme_fabrics_type_connect;
	cmd->connect.qid = 0;
	cmd->connect.sqsize = htole16(NVME_AQ_DEPTH - 1);
	cmd->connect.kato = htole32(ctrl->opts->kato + NVME_KATO_GRACE);

	data->hostid = ctrl->opts->uuid;
	data->cntlid = htole16(0xffff);
	strncpy(data->subsysnqn, ctrl->opts->trnqn, NVMF_NQN_SIZE);
	strncpy(data->hostnqn, ctrl->opts->hostnqn, NVMF_NQN_SIZE);

	req->queue = queue;
	req->cb = nvmf_connect_admin_queue_cb;
	req->opaque = NULL;

	return ret;
}

int nvmf_connect_admin_queue(struct nvmf_queue *queue)
{
	struct nvmf_request *req;
	struct nvme_completion *cqe;
	struct nvmf_connect_data *data;
	struct nvmf_ctrl *ctrl;
	struct iovec iov;
	int ret = 0;

	log_trace();
	data = (struct nvmf_connect_data *)nvmf_calloc(1, sizeof(*data));
	if (!data) {
		return -ENOMEM;
	}

	ctrl = queue->ctrl;
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return -ENOMEM;
	}

	iov.iov_base = data;
	iov.iov_len = sizeof(*data);
	nvmf_connect_admin_queue_req(req, queue, data);
	ctrl->ops->queue_request(req, &iov, 1);

	ret = nvmf_queue_do_req(req);
	if (ret < 0) {
		return ret;
	}

	cqe = req->cqe;
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("queue[%d]connect admin queue error, status 0x%x\n", queue->qid,
                          le16toh(cqe->status));
		ret = -EIO;
	}

	nvmf_ctrl_free_request(ctrl, req);
	nvmf_free(data);

	return ret;
}

static void nvmf_connect_io_queue_cb(struct nvmf_request *req, void *opaque)
{
	struct nvme_completion *cqe = req->cqe;

	log_trace();

	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("queue[%d]connect io queue error, status 0x%x\n", req->queue->qid,
                          cqe->status);
		return;
	}

	assert(req->queue->qid == le16toh(req->cmd->connect.qid));
	log_debug("queue[%d]connect io queue\n", le16toh(req->cmd->connect.qid));
}

static int nvmf_connect_io_queue_req(struct nvmf_request *req, struct nvmf_queue *queue,
                                     struct nvmf_connect_data *data)
{
	struct nvmf_ctrl *ctrl = queue->ctrl;
	struct nvme_command *cmd = req->cmd;
	int ret = 0;

	cmd->connect.opcode = nvme_fabrics_command;
	cmd->connect.fctype = nvme_fabrics_type_connect;
	cmd->connect.qid = htole16(queue->qid);
	cmd->connect.sqsize = htole16(queue->qsize - 1);

	data->hostid = ctrl->opts->uuid;
	data->cntlid = htole16(ctrl->cntlid);
	strncpy(data->subsysnqn, ctrl->opts->trnqn, NVMF_NQN_SIZE);
	strncpy(data->hostnqn, ctrl->opts->hostnqn, NVMF_NQN_SIZE);

	req->queue = queue;
	req->cb = nvmf_connect_io_queue_cb;
	req->opaque = NULL;

	return ret;
}

int nvmf_connect_io_queue(struct nvmf_queue *queue)
{
	struct nvmf_request *req;
	struct nvme_completion *cqe;
	struct nvmf_connect_data *data;
	struct nvmf_ctrl *ctrl;
	struct iovec iov;
	int ret = 0;

	log_trace();
	data = (struct nvmf_connect_data *)nvmf_calloc(1, sizeof(*data));
	if (!data) {
		return -ENOMEM;
	}

	ctrl = queue->ctrl;
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return -ENOMEM;
	}

	iov.iov_base = data;
	iov.iov_len = sizeof(*data);
	nvmf_connect_io_queue_req(req, queue, data);
	ctrl->ops->queue_request(req, &iov, 1);

	ret = nvmf_queue_do_req(req);
	if (ret < 0) {
		return ret;
	}

	cqe = req->cqe;
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("queue[%d]connect error, status 0x%x\n", queue->qid,
                          le16toh(cqe->status));
		ret = -EIO;
	}

	nvmf_ctrl_free_request(ctrl, req);
	nvmf_free(data);

	return ret;
}

static void nvmf_reg_to_ctrl(struct nvmf_ctrl *ctrl, __u32 offset, __u64 res)
{
	switch (offset) {
	case NVME_REG_CAP:
		ctrl->reg_cap = res;
		break;
	case NVME_REG_VS:
		ctrl->reg_vs = (__u32)res;
		break;
	case NVME_REG_CSTS:
		ctrl->reg_csts = (__u32)res;
		break;
	default:
		log_error("unknown offset 0x%x, res 0x%llx\n", offset, res);
	}

}

/*
 * reg read64
 * if opaque is NOT NULL, read a __u64 val to opaque.
 * else read reg to set ctrl automatically
 */
static void nvmf_reg_read32_cb(struct nvmf_request *req, void *opaque)
{
	struct nvme_completion *cqe = req->cqe;
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	__u32 *val = (__u32 *)opaque;
	__u64 res;
	__u32 offset = le32toh(req->cmd->prop_get.offset);

	log_trace();
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("reg read32 error, offset 0x%x, status 0x%x\n", offset,
                          le16toh(cqe->status));
		return;
	}

	res = le64toh(cqe->result.u64);
	log_debug("reg read64 succeed, offset 0x%x, res: 0x%llx\n", offset, res);
	if (val) {
		*val = le64toh(cqe->result.u64);
	}

	/* also apply to ctrl */
	nvmf_reg_to_ctrl(ctrl, offset, res);
}

static int nvmf_reg_read32_req(struct nvmf_request *req, struct nvmf_queue *queue, __u32 off,
                               __u32 *val)
{
	struct nvme_command *cmd = req->cmd;
	int ret = 0;

	memset(cmd, 0, sizeof(*cmd));
	cmd->prop_get.opcode = nvme_fabrics_command;
	cmd->prop_get.fctype = nvme_fabrics_type_property_get;
	cmd->prop_get.offset = htole32(off);

	/* run reg read command on admin queue */
	req->queue = queue;
	req->cb = nvmf_reg_read32_cb;
	req->opaque = val;

	return ret;
}

int nvmf_reg_read32(struct nvmf_ctrl *ctrl, __u32 offset, __u32 *val)
{
	struct nvmf_request *req;
	struct nvme_completion *cqe;
	struct nvmf_queue *queue = ctrl->queues;	/* admin queue */
	int ret = 0;

	log_trace();
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return -ENOMEM;
	}

	nvmf_reg_read32_req(req, queue, offset, val);
	ctrl->ops->queue_request(req, NULL, 0);

	ret = nvmf_queue_do_req(req);
	if (ret < 0) {
		return ret;
	}

	cqe = req->cqe;
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("reg read32 error, offset 0x%x, status 0x%x\n", offset,
                          le16toh(cqe->status));
		ret = -EIO;
	}

	nvmf_ctrl_free_request(ctrl, req);

	return ret;
}

/*
 * reg read64
 * if opaque is NOT NULL, read a __u64 val to opaque.
 * else read reg to set ctrl automatically
 */
static void nvmf_reg_read64_cb(struct nvmf_request *req, void *opaque)
{
	struct nvme_completion *cqe = req->cqe;
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	__u64 *val = (__u64 *)opaque;
	__u64 res;
	__u32 offset = le32toh(req->cmd->prop_get.offset);

	log_trace();
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("reg read32 error, offset 0x%x, status 0x%x\n", offset,
                le16toh(cqe->status));
		return;
	}

	res = le64toh(cqe->result.u64);
	log_debug("reg read64 succeed, offset 0x%x, res: 0x%llx\n", offset, res);
	if (val) {
		*val = le64toh(cqe->result.u64);
	}

	nvmf_reg_to_ctrl(ctrl, offset, res);
}

static int nvmf_reg_read64_req(struct nvmf_request *req, struct nvmf_queue *queue, __u32 offset,
                               __u64 *val)
{
	struct nvme_command *cmd = req->cmd;
	int ret = 0;

	memset(cmd, 0, sizeof(*cmd));
	cmd->prop_get.opcode = nvme_fabrics_command;
	cmd->prop_get.fctype = nvme_fabrics_type_property_get;
	cmd->prop_get.attrib = 1;
	cmd->prop_get.offset = htole32(offset);

	req->queue = queue;
	req->cb = nvmf_reg_read64_cb;
	req->opaque = val;

	return ret;
}

int nvmf_reg_read64(struct nvmf_ctrl *ctrl, __u32 offset, __u64 *val)
{
	struct nvmf_request *req;
	struct nvme_completion *cqe;
	struct nvmf_queue *queue = ctrl->queues;	/* admin queue */
	int ret = 0;

	log_trace();
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return -ENOMEM;
	}

	nvmf_reg_read64_req(req, queue, offset, val);
	ctrl->ops->queue_request(req, NULL, 0);

	ret = nvmf_queue_do_req(req);
	if (ret < 0) {
		return ret;
	}

	cqe = req->cqe;
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("reg read64 error, offset 0x%x, status 0x%x\n", offset,
                          le16toh(cqe->status));
		ret = -EIO;
	}

	nvmf_ctrl_free_request(ctrl, req);

	return ret;
}

static void nvmf_reg_write32_cb(struct nvmf_request *req, void *opaque)
{
	struct nvme_completion *cqe = req->cqe;

	log_trace();
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("reg write32 error, status 0x%x\n", le16toh(cqe->status));
		return;
	}

	log_debug("reg write32 succeed\n");
}

static int nvmf_reg_write32_req(struct nvmf_request *req, struct nvmf_queue *queue, __u64 off,
                                __u32 val)
{
	int ret = 0;
	struct nvme_command *cmd = req->cmd;

	memset(cmd, 0, sizeof(*cmd));
	cmd->prop_set.opcode = nvme_fabrics_command;
	cmd->prop_set.fctype = nvme_fabrics_type_property_set;
	cmd->prop_set.attrib = 0;
	cmd->prop_set.offset = htole32(off);
	cmd->prop_set.value = htole64(val);

	req->queue = queue;
	/* no callback argument, retval depends on cqe->status only */
	req->cb = nvmf_reg_write32_cb;

	return ret;
}

int nvmf_reg_write32(struct nvmf_ctrl *ctrl, __u64 offset, __u64 val)
{
	struct nvmf_request *req;
	struct nvme_completion *cqe;
	struct nvmf_queue *queue = ctrl->queues;	/* admin queue */
	int ret = 0;

	log_trace();
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return -ENOMEM;
	}

	nvmf_reg_write32_req(req, queue, offset, val);
	ctrl->ops->queue_request(req, NULL, 0);

	ret = nvmf_queue_do_req(req);
	if (ret < 0) {
		return ret;
	}

	cqe = req->cqe;
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("reg read64 error, status 0x%x\n", le16toh(cqe->status));
		ret = -EIO;
	}

	nvmf_ctrl_free_request(ctrl, req);

	return ret;
}

static void nvmf_set_features_cb(struct nvmf_request *req, void *opaque)
{
	struct nvme_completion *cqe = req->cqe;

	log_trace();
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("set features error, status 0x%x\n", le16toh(cqe->status));
		return;
	}

	log_debug("set features succeed\n");
}

static int nvmf_set_features_req(struct nvmf_request *req, struct nvmf_queue *queue, __u32 feature,
                                 __u32 val)
{
	int ret = 0;
	struct nvme_command *cmd = req->cmd;

	memset(cmd, 0, sizeof(*cmd));
	cmd->features.opcode = nvme_admin_set_features;
	cmd->features.fid = htole32(feature);
	cmd->features.dword11 = htole32(val);

	req->queue = queue;
	/* no callback argument, retval depends on cqe->status only */
	req->cb = nvmf_set_features_cb;

	return ret;
}

int nvmf_set_features(struct nvmf_ctrl *ctrl, __u32 feature, __u32 val)
{
	struct nvmf_request *req;
	struct nvme_completion *cqe;
	struct nvmf_queue *queue = ctrl->queues;	/* admin queue */
	int ret = 0;

	log_trace();
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return -ENOMEM;
	}

	nvmf_set_features_req(req, queue, feature, val);
	ctrl->ops->queue_request(req, NULL, 0);

	ret = nvmf_queue_do_req(req);
	if (ret < 0) {
		return ret;
	}

	cqe = req->cqe;
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("set feature error, status 0x%x\n", le16toh(cqe->status));
		ret = -EIO;
	}

	nvmf_ctrl_free_request(ctrl, req);

	return ret;
}

static void nvmf_keepalive_cb(struct nvmf_request *req, void *opaque)
{
	struct nvme_completion *cqe = req->cqe;

	log_trace();
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("keepalive error, status 0x%x\n", le16toh(cqe->status));
		return;
	}

	/* just process on admin queue thread */
	if (req->ucb) {
		req->ucb(cqe->status, req->uopaque);
	}

	log_debug("keepalive succeed\n");
}

static void nvmf_cmd_identify_to_ctrl(struct nvmf_request *req, struct nvmf_ctrl *ctrl, __u8 cns,
                                      void *id)
{
	struct nvme_id_ctrl *idctrl;
	struct nvme_id_ns *idns;
	struct nvme_ns *ns;
	__le32 *nsid, nn, maxnn, idx;

	log_trace();
	switch (cns) {
	case NVME_ID_CNS_NS:
		idns = (struct nvme_id_ns *)id;
		ns = ctrl->ns;

		ns->nsze = le64toh(idns->nsze);
		ns->ncap = le64toh(idns->ncap);
		ns->lbads = idns->lbaf[idns->flbas & NVME_NS_FLBAS_LBA_MASK].ds;
		/* ref: Identify - LBA Format Data Structure, NVM Command Set Specific */
		if (!ns->lbads) {
			ns->lbads = 9;
			log_warn("ns lbads is not supported, use default val 9");
		}
		log_debug("nsid: %d, nsze: %lld, ncap: 0x%llx, lbads = %d\n", ns->nsid, ns->nsze,
                          ns->ncap, ns->lbads);
		break;

	case NVME_ID_CNS_CTRL:
		idctrl = (struct nvme_id_ctrl *)id;

		if (ctrl->cntlid != le16toh(idctrl->cntlid)) {
			log_error("cntlid mismatch: connected %d & identify %d\n", ctrl->cntlid,
                                  le16toh(idctrl->cntlid));
			return;
		}

		strncpy(ctrl->sn, idctrl->sn, sizeof(ctrl->sn) - 1);
		strncpy(ctrl->mn, idctrl->mn, sizeof(ctrl->mn) - 1);
		ctrl->nn = le32toh(idctrl->nn);
		ctrl->mdts = idctrl->mdts;
		if (!ctrl->mdts) {
			ctrl->mdts = NVMF_DEF_MDTS;
			log_debug("identify mdts 0, align to %d\n", NVMF_DEF_MDTS);
		}
		ctrl->vwc = idctrl->vwc;
		ctrl->ioccsz = le32toh(idctrl->ioccsz);
		ctrl->iorcsz = le32toh(idctrl->iorcsz);
		ctrl->icdoff = le16toh(idctrl->icdoff);
		ctrl->maxcmd = le16toh(idctrl->maxcmd);
		ctrl->oncs = le16toh(idctrl->oncs);
		log_debug("sn: %20s, mn: %40s, nn: %d, mdts: %d, vwc: %d, ioccsz: %d, iorcsz: %d, "
                          "icdoff: %d, maxcmd: %d, oncs: 0x%x\n", ctrl->sn, ctrl->mn, ctrl->nn,
                          ctrl->mdts, ctrl->vwc, ctrl->ioccsz, ctrl->iorcsz, ctrl->icdoff,
                          ctrl->maxcmd, ctrl->oncs);
		break;

	case NVME_ID_CNS_NS_ACTIVE_LIST:
		maxnn = sizeof(struct nvme_id_ctrl) / sizeof(__u32);
		nn = min(ctrl->nn, maxnn);
		idx = 0;

		if (ctrl->nslist) {
			nvmf_free(ctrl->nslist);
		}

		ctrl->nslist = (struct nvme_ns *)nvmf_calloc(nn, sizeof(struct nvme_ns));
		ns = ctrl->nslist;

		for (nsid = (__le32 *)id; idx < nn; nsid++, idx++) {
			if (!le32toh(*nsid)) {
				continue;
			}

			log_debug("ns active list: %d\n", le32toh(*nsid));
			ns->nsid = le32toh(*nsid);
			ns++;
			ctrl->nscount++;
		}

		break;

	default:
		log_error("unexpected cns %d\n", cns);
		break;
	}
}

static void nvmf_identify_cb(struct nvmf_request *req, void *opaque)
{
	struct nvme_id_ctrl *id;
	struct nvme_completion *cqe = req->cqe;
	__u8 cns = req->cmd->identify.cns;

	log_trace();
	assert(req->iovcnt == 1);

	id = req->iovs[0].iov_base;

	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("cmd identify error, status 0x%x\n", le16toh(cqe->status));
		return;
	}

	log_debug("cmd identify succeed\n");

	nvmf_cmd_identify_to_ctrl(req, req->queue->ctrl, cns, id);
}

static int nvmf_identify_req(struct nvmf_request *req, struct nvmf_queue *queue, __u8 cns)
{
	struct nvme_command *cmd = req->cmd;
	struct nvmf_ctrl *ctrl = queue->ctrl;
	int ret = 0;

	memset(cmd, 0, sizeof(*cmd));
	cmd->identify.opcode = nvme_admin_identify;
	cmd->identify.cns = cns;
	if (cns == NVME_ID_CNS_NS) {
		if (!ctrl->ns) {
			log_error("empty current ns");
			return -EINVAL;
		}
		cmd->identify.nsid = htole32(ctrl->ns->nsid);
	} else if (cns == NVME_ID_CNS_NS_ACTIVE_LIST) {
		cmd->identify.nsid = 0;	/* min nsid */
	}

	req->queue = queue;
	req->cb = nvmf_identify_cb;

	return ret;
}

int nvmf_identify(struct nvmf_ctrl *ctrl, __u8 cns)
{
	struct nvmf_request *req;
	struct nvme_id_ctrl *id;
	struct nvmf_queue *queue = ctrl->queues;	/* admin queue */
	struct iovec iov;
	int ret = 0;

	log_debug("nvmf identify cns %d\n", cns);
	id = (struct nvme_id_ctrl *)nvmf_calloc(1, sizeof(*id));
	if (!id) {
		return -ENOMEM;
	}

	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return -ENOMEM;
	}

	iov.iov_base = id;
	iov.iov_len = sizeof(*id);
	nvmf_identify_req(req, queue, cns);
	ctrl->ops->queue_request(req, &iov, 1);

	ret = nvmf_queue_do_req(req);
	nvmf_ctrl_free_request(ctrl, req);
	nvmf_free(id);

	return ret;
}

int nvmf_req_set_timeout(nvmf_req_t req, unsigned int ms)
{
	struct nvmf_request *_req = (struct nvmf_request *)req;

	_req->timeout = ms;

	return _req->timeout;
}

int nvmf_req_free(nvmf_req_t req)
{
	int ret = 0;
	struct nvmf_request *_req = (struct nvmf_request *)req;

	nvmf_ctrl_free_request(_req->queue->ctrl, req);

	return ret;
}

int nvmf_queue_depth(nvmf_ctrl_t ctrl, unsigned int qid)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;

	if (qid >= __ctrl->opts->nr_queues) {
		return -EINVAL;
	}

	queue = __ctrl->queues + qid;

	return queue->qsize;
}

int nvmf_queue_nr_inflight(nvmf_ctrl_t ctrl, unsigned int qid)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;

	if (qid >= __ctrl->opts->nr_queues) {
		return -EINVAL;
	}

	queue = __ctrl->queues + qid;

	return queue->nr_inflight;
}

int nvmf_ns_identify(struct nvmf_ctrl *ctrl)
{
	int ret = 0;

	ret = nvmf_identify(ctrl, NVME_ID_CNS_NS);
	if (ret) {
		return ret;
	}

	return ret;
}

static void nvmf_ns_io_cb(struct nvmf_request *req, void *opaque)
{
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	struct nvme_completion *cqe = req->cqe;

	log_trace();
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("queue[%d]tag[0x%x], rw error, status 0x%x\n", req->queue->qid, req->tag,
                          le16toh(cqe->status));
	} else {
		log_debug("queue[%d]tag[0x%x], rw succeed\n", req->queue->qid, req->tag);
	}

	/* after IO queue thread processing, add req to main thread */
	llist_add(&req->llist, &ctrl->complete);
	nvmf_ctrl_kick(ctrl);
}

static int nvmf_ns_rw_req(struct nvmf_request *req, off_t offset, size_t length, int flags,
                          bool is_write)
{
	struct nvme_command *cmd = req->cmd;
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	struct nvme_ns *ns = ctrl->ns;
	int ret = 0;

	log_trace();
	memset(cmd, 0, sizeof(*cmd));
	cmd->rw.opcode = is_write ? nvme_cmd_write : nvme_cmd_read;
	cmd->rw.nsid = htole32(ns->nsid);
	cmd->rw.slba = htole64(offset >> ns->lbads);
	cmd->rw.length = htole64((length >> ns->lbads) - 1);
	cmd->rw.control = htole16(0);	/* TODO FUA support */
	cmd->rw.dsmgmt = htole32(0);	/* TODO dsmgmt supporte */

	return ret;
}

static nvmf_req_t nvmf_ns_rw_async(struct nvmf_queue *queue, struct iovec *iovs, int iovcnt,
                                   off_t offset, int flags, bool is_write,
                                   void (*cb)(__u16 status, void *opaque), void *opaque)
{
	struct nvmf_request *req;
	struct nvmf_ctrl *ctrl = queue->ctrl;
	size_t length = nvmf_iov_datalen(iovs, iovcnt);

	log_trace();
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return NULL;
	}

	req->queue = queue;
	req->cb = nvmf_ns_io_cb;
	req->opaque = NULL;
	req->ucb = cb;
	req->uopaque = opaque;

	nvmf_ns_rw_req(req, offset, length, flags, is_write);

	if (ctrl->ops->queue_request(req, iovs, iovcnt)) {
		assert(0);
		nvmf_ctrl_free_request(ctrl, req);
		return NULL;
	}

	return req;
}

static int nvmf_ns_rw_sync(struct nvmf_queue *queue, void *buf, size_t count, off_t offset,
                           int flags, bool is_write, void (*cb)(__u16 status, void *opaque),
                           void *opaque)
{
	int ret;
	struct nvmf_request *req;
	struct nvme_completion *cqe;

	req = nvmf_ns_rw_async(queue, buf, count, offset, flags, is_write, cb, opaque);
	ret = nvmf_ctrl_do_req(req);
	if (ret < 0) {
		return ret;
	}

	cqe = req->cqe;
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("ns %s error, status 0x%x\n", is_write ? "write" : "read",
                          le16toh(cqe->status));
		ret = -EIO;
	}

	nvmf_ctrl_free_request(queue->ctrl, req);

	return ret;
}

int nvmf_max_iov(nvmf_ctrl_t ctrl)
{
	return NVMF_MAX_IOV;
}

int nvmf_read(nvmf_ctrl_t ctrl, unsigned int qid, void *buf, unsigned long count,
              unsigned long offset, int flags)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;
	struct iovec iov;

	if (qid >= __ctrl->opts->nr_queues) {
		return -EINVAL;
	}

	queue = __ctrl->queues + qid;

	iov.iov_base = buf;
	iov.iov_len = count;

	return nvmf_ns_rw_sync(queue, &iov, 1, offset, flags, 0, NULL, NULL);
}

int nvmf_write(nvmf_ctrl_t ctrl, unsigned int qid, void *buf, unsigned long count,
               unsigned long offset, int flags)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;
	struct iovec iov;

	if (qid >= __ctrl->opts->nr_queues) {
		return -EINVAL;
	}

	queue = __ctrl->queues + qid;

	iov.iov_base = buf;
	iov.iov_len = count;
	return nvmf_ns_rw_sync(queue, &iov, 1, offset, flags, 1, NULL, NULL);
}

int nvmf_readv(nvmf_ctrl_t ctrl, unsigned int qid, struct iovec *iovs, int iovcnt,
               unsigned long offset, int flags)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;

	if (qid >= __ctrl->opts->nr_queues) {
		return -EINVAL;
	}

	queue = __ctrl->queues + qid;

	return nvmf_ns_rw_sync(queue, iovs, iovcnt, offset, flags, 0, NULL, NULL);
}

int nvmf_writev(nvmf_ctrl_t ctrl, unsigned int qid, struct iovec *iovs, int iovcnt,
                unsigned long offset, int flags)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;

	if (qid >= __ctrl->opts->nr_queues) {
		return -EINVAL;
	}

	queue = __ctrl->queues + qid;

	return nvmf_ns_rw_sync(queue, iovs, iovcnt, offset, flags, 1, NULL, NULL);
}

nvmf_req_t nvmf_read_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                           unsigned long offset, int flags,
                           void (*cb)(unsigned short status, void *opaque), void *opaque)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;

	if (qid >= __ctrl->opts->nr_queues) {
		return NULL;
	}

	queue = __ctrl->queues + qid;

	return nvmf_ns_rw_async(queue, iovs, iovcnt, offset, flags, 0, cb, opaque);
}

nvmf_req_t nvmf_write_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                            unsigned long offset, int flags,
                            void (*cb)(unsigned short status, void *opaque), void *opaque)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;

	if (qid >= __ctrl->opts->nr_queues) {
		return NULL;
	}

	queue = __ctrl->queues + qid;

	return nvmf_ns_rw_async(queue, iovs, iovcnt, offset, flags, 1, cb, opaque);
}

static int nvmf_ns_discard_req(struct nvmf_request *req, unsigned int segments)
{
	struct nvme_command *cmd = req->cmd;
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	struct nvme_ns *ns = ctrl->ns;
	int ret = 0;

	log_trace();
	memset(cmd, 0, sizeof(*cmd));
	cmd->dsm.opcode = nvme_cmd_dsm;
	cmd->dsm.nsid = htole32(ns->nsid);
	cmd->dsm.nr = htole32(segments - 1);
	cmd->dsm.attributes = htole32(NVME_DSMGMT_AD);

	return ret;
}

static void nvmf_ns_discard_cb(struct nvmf_request *req, void *opaque)
{
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	struct nvme_completion *cqe = req->cqe;
	struct iovec *dsmiovec = (struct iovec *)opaque;
	struct nvme_dsm_range *range = (struct nvme_dsm_range *)dsmiovec->iov_base;

	log_trace();
	if (cqe->status != NVME_SC_SUCCESS) {
		log_error("discard failed, queue[%d]tag[0x%x], discard error, status 0x%x, lba"
			  "[%lu, %u]\n", req->queue->qid, req->tag, le16toh(cqe->status),
			  le64toh(range->slba), le32toh(range->nlb));
	} else {
		log_debug("discard succeed, queue[%d]tag[0x%x], discard succeed, lba[%lu, %u]\n",
			  req->queue->qid, req->tag, le64toh(range->slba), le32toh(range->nlb));
	}

	nvmf_free(dsmiovec->iov_base);
	nvmf_free(dsmiovec);

	/* after IO queue thread processing, add req to main thread */
	llist_add(&req->llist, &ctrl->complete);
	nvmf_ctrl_kick(ctrl);
}

static nvmf_req_t nvmf_ns_discard_async(struct nvmf_queue *queue, struct iovec *iovs, int iovcnt,
                                        off_t offset, int flags,
                                        void (*cb)(__u16 status, void *opaque), void *opaque)
{
	struct nvmf_request *req;
	struct nvmf_ctrl *ctrl = queue->ctrl;
	size_t length = 4096;
	struct iovec *dsmiovec, *useriovec;
	struct nvme_dsm_range *range;
	off_t _offset = offset;
	int lbads = ctrl->ns->lbads;
	int i;

	log_trace();
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return NULL;
	}

	dsmiovec = (struct iovec *)nvmf_calloc(1, sizeof(*dsmiovec));
	dsmiovec->iov_len = length;
	dsmiovec->iov_base = nvmf_calloc(1, length);
	for (i = 0; i < iovcnt; i++) {
		useriovec = iovs + i;
		range = (struct nvme_dsm_range *)dsmiovec->iov_base + i;

		range->cattr = htole32(0);
		range->nlb = htole32(useriovec->iov_len >> lbads);
		range->slba = htole64(_offset >> lbads);

		_offset += useriovec->iov_len;
	}

	req->queue = queue;
	req->cb = nvmf_ns_discard_cb;
	req->opaque = dsmiovec;
	req->ucb = cb;
	req->uopaque = opaque;

	nvmf_ns_discard_req(req, iovcnt);

	if (ctrl->ops->queue_request(req, dsmiovec, 1)) {
		assert(0);
		nvmf_ctrl_free_request(ctrl, req);
		return NULL;
	}

	return req;
}

nvmf_req_t nvmf_discard_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                              unsigned long offset, int flags,
                              void (*cb)(unsigned short status, void *opaque), void *opaque)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;

	if (qid >= __ctrl->opts->nr_queues) {
		return NULL;
	}

	if (nvmf_ctrl_dsm_segments(ctrl) < iovcnt) {
		return NULL;
	}

	queue = __ctrl->queues + qid;

	return nvmf_ns_discard_async(queue, iovs, iovcnt, offset, flags, cb, opaque);
}

static int nvmf_ns_writezeroes_req(struct nvmf_request *req, off_t offset, size_t length)
{
	struct nvme_command *cmd = req->cmd;
	struct nvmf_ctrl *ctrl = req->queue->ctrl;
	struct nvme_ns *ns = ctrl->ns;
	int lbads = ctrl->ns->lbads;
	int ret = 0;

	log_trace();
	memset(cmd, 0, sizeof(*cmd));
	cmd->write_zeroes.opcode = nvme_cmd_write_zeroes;
	cmd->write_zeroes.nsid = htole32(ns->nsid);
	cmd->write_zeroes.slba = htole64(offset >> lbads);
	cmd->write_zeroes.length = htole16((length >> lbads) - 1);
	cmd->write_zeroes.control = 0;

	return ret;
}

nvmf_req_t nvmf_writezeroes_async(nvmf_ctrl_t ctrl, int qid, struct iovec *iovs, int iovcnt,
                                  unsigned long offset, int flags,
                                  void (*cb)(unsigned short status, void *opaque), void *opaque)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;
	struct nvmf_request *req;
	size_t length = nvmf_iov_datalen(iovs, iovcnt);

	log_trace();
	if (qid >= __ctrl->opts->nr_queues) {
		return NULL;
	}

	queue = __ctrl->queues + qid;
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return NULL;
	}

	req->queue = queue;
	req->cb = nvmf_ns_io_cb;
	req->opaque = NULL;
	req->ucb = cb;
	req->uopaque = opaque;

	nvmf_ns_writezeroes_req(req, offset, length);

	/* no input/output data required */
	if (__ctrl->ops->queue_request(req, NULL, 0)) {
		assert(0);
		nvmf_ctrl_free_request(ctrl, req);
		return NULL;
	}

	return req;
}

struct nvmf_request *nvmf_keepalive_async(struct nvmf_queue *queue,
                                          void (*cb)(unsigned short status, void *opaque),
                                          void *opaque)
{
	struct nvmf_request *req;
	struct nvme_command *cmd;
	struct nvmf_ctrl *ctrl = queue->ctrl;

	log_trace();
	req = nvmf_ctrl_alloc_request(ctrl, queue);
	if (!req) {
		return NULL;
	}

	cmd = req->cmd;
	memset(cmd, 0, sizeof(*cmd));
	cmd->common.opcode = nvme_admin_keep_alive;

	req->queue = queue;
	req->cb = nvmf_keepalive_cb;
	req->opaque = NULL;
	req->ucb = cb;
	req->uopaque = opaque;

	/* keepalive request always run in admin queue */
	if (ctrl->ops->queue_request(req, NULL, 0)) {
		nvmf_ctrl_free_request(ctrl, req);
		return NULL;
	}

	return req;
}
