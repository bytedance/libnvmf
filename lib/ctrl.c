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

static int nvmf_ctrl_wait_ready(struct nvmf_ctrl *ctrl, bool enable);

static inline void nvmf_ctrl_set_running(struct nvmf_ctrl *ctrl, bool running)
{
	__atomic_store_n(&ctrl->running, running, __ATOMIC_SEQ_CST);
}

static inline bool nvmf_ctrl_get_running(struct nvmf_ctrl *ctrl)
{
	return __atomic_load_n(&ctrl->running, __ATOMIC_SEQ_CST);
}

void nvmf_ctrl_set_reset(struct nvmf_ctrl *ctrl, bool reset)
{
	__atomic_store_n(&ctrl->reset, reset, __ATOMIC_SEQ_CST);
}

static inline bool nvmf_ctrl_get_reset(struct nvmf_ctrl *ctrl)
{
	return __atomic_load_n(&ctrl->reset, __ATOMIC_SEQ_CST);
}

void nvmf_ctrl_kick(struct nvmf_ctrl *ctrl)
{
	uint64_t u = 1;

	if (!nvmf_ctrl_get_running(ctrl))
		if (write(ctrl->eventfd, &u, sizeof(u)) < 0) {
			log_error("write eventfd failed, %m");
		}
}

int nvmf_ctrl_identify(struct nvmf_ctrl *ctrl)
{
	return nvmf_identify(ctrl, NVME_ID_CNS_CTRL);
}

int nvmf_ctrl_enable(struct nvmf_ctrl *ctrl)
{
	unsigned int host_page_shift = NVMF_DEF_PAGE_SHIFT;
	unsigned int cap_mqes, cap_stride, cap_mpsmin;
	int ret = 0;
	__u64 reg_cap;
	__u32 reg_vs;

	log_trace();
	/* read reg_vs from controller */
	ret = nvmf_reg_read32(ctrl, NVME_REG_VS, &reg_vs);
	if (ret < 0) {
		return ret;
	}

	ctrl->reg_vs = reg_vs;
	log_debug("read cap NVME_REG_VS: 0x%x\n", ctrl->reg_vs);

	/* read reg_cap from controller */
	ret = nvmf_reg_read64(ctrl, NVME_REG_CAP, &reg_cap);
	if (ret < 0) {
		return ret;
	}

	ctrl->reg_cap = reg_cap;
	log_debug("read cap NVME_REG_CAP: 0x%llx\n", ctrl->reg_cap);

	/* check cap */
	cap_mpsmin = NVME_CAP_MPSMIN(reg_cap) + NVMF_DEF_PAGE_SHIFT;
	if (host_page_shift < cap_mpsmin) {
		log_error("MPSMIN check failed, host %d, controller %d\n", host_page_shift,
                          cap_mpsmin);
		return -ENODEV;
	}

	cap_stride = NVME_CAP_STRIDE(reg_cap);
	if (cap_stride) {
		log_warn("unexpected cap stride: %d\n", cap_stride);
	}

	cap_mqes = NVME_CAP_MQES(ctrl->reg_cap);
	if (cap_mqes < ctrl->opts->qsize) {
		log_warn("cap mqes %d < opt queue entries %d, set entries to %d\n", cap_mqes,
                         ctrl->opts->qsize, cap_mqes);
		ctrl->opts->qsize = cap_mqes;
	}

	/* set ctrl reg_cc & enable ctrl */
	ctrl->reg_cc = NVME_CC_CSS_NVM;
	ctrl->reg_cc |= (host_page_shift - NVMF_DEF_PAGE_SHIFT) << NVME_CC_MPS_SHIFT;
	ctrl->reg_cc |= NVME_CC_AMS_RR | NVME_CC_SHN_NONE;
	ctrl->reg_cc |= NVME_CC_IOSQES | NVME_CC_IOCQES;
	ctrl->reg_cc |= NVME_CC_ENABLE;

	ret = nvmf_reg_write32(ctrl, NVME_REG_CC, ctrl->reg_cc);
	if (ret != 0) {
		return ret;
	}

	ret = nvmf_ctrl_wait_ready(ctrl, true);
	if (ret != 0) {
		return ret;
	}

	return ret;
}

static int nvmf_config_admin_queue(struct nvmf_queue *queue)
{
	struct nvmf_ctrl *ctrl = queue->ctrl;
	int ret;

	ret = nvmf_connect_admin_queue(queue);
	if (ret < 0) {
		return ret;
	}

	ret = nvmf_ctrl_enable(ctrl);
	if (ret) {
		return ret;
	}

	ret = nvmf_ctrl_identify(ctrl);
	if (ret) {
		return ret;
	}

	ret = nvmf_ns_active_list_identify(ctrl);
	if (ret) {
		return ret;
	}

	ret = nvmf_ns_identify(ctrl);
	if (ret) {
		return ret;
	}

	ret = nvmf_ctrl_set_io_queues(ctrl, ctrl->opts->nr_queues);
	if (ret) {
		return ret;
	}

	return 0;
}

static int nvmf_setup_admin_queue(void *arg)
{
	int ret;
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;
	struct nvmf_ctrl *ctrl = queue->ctrl;

	log_trace();
	assert(queue->qid == 0);

	ret = ctrl->ops->create_queue(queue);
	if (ret) {
		log_error("create queue[%d] failed, %s\n", 0, strerror(ret));
		return ret;
	}

	return nvmf_config_admin_queue(queue);
}

static int nvmf_setup_io_queue(void *arg)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;
	struct nvmf_ctrl *ctrl = queue->ctrl;
	int ret;

	ret = ctrl->ops->create_queue(queue);
	if (ret < 0) {
		return ret;	/* TODO stop all started queues */
	}

	ret = nvmf_connect_io_queue(queue);
	if (ret < 0) {
		return ret;	/* TODO stop all started queues */
	}

	return ret;
}

static int nvmf_stop_queue(void *arg)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;

	nvmf_queue_teardown(queue);

	return 0;
}

static int nvmf_ctrl_setup(struct nvmf_ctrl *ctrl)
{
	int ret, i;
	struct nvmf_queue *queue;

	log_trace();
	/* setup admin queue */
	queue = ctrl->queues;
	nvmf_queue_thread_start(queue);
	ret = nvmf_queue_call_function(queue, nvmf_setup_admin_queue, queue);
	if (ret < 0) {
		return ret;
	}

	for (i = 1; i < ctrl->opts->nr_queues; i++) {
		queue = ctrl->queues + i;
		nvmf_queue_thread_start(queue);
		ret = nvmf_queue_call_function(queue, nvmf_setup_io_queue, queue);
		if (ret) {
			/*TODO stop all queues*/
			return -1;
		}
	}

	return 0;
}

static int nvmf_restart_admin_queue(void *arg)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;
	int ret;

	log_trace();
	assert(queue->qid == 0);

	/* save all inflight request to retransfer queue */
	nvmf_queue_retransfer_save(queue);

	ret = nvmf_queue_restart(queue);
	if (ret) {
		log_error("restart queue[%d] failed, %s\n", 0, strerror(ret));
		return ret;
	}

	ret = nvmf_config_admin_queue(queue);
	if (ret) {
		return ret;
	}

	nvmf_queue_retransfer_restore(queue);

	return 0;
}

static int nvmf_restart_io_queue(void *arg)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;
	int ret;

	/* save all inflight request to retransfer queue */
	nvmf_queue_retransfer_save(queue);

	ret = nvmf_queue_restart(queue);
	if (ret < 0) {
		return ret;	/* TODO stop all started queues */
	}

	ret = nvmf_connect_io_queue(queue);
	if (ret < 0) {
		return ret;	/* TODO stop all started queues */
	}

	nvmf_queue_retransfer_restore(queue);

	return ret;
}

static int nvmf_ctrl_reset(struct nvmf_ctrl *ctrl)
{
	struct nvmf_queue *queue;
	int ret, i;

	log_error("ctrl reset\n");
	/* mark all the queue into ERROR state to stop IO processing */
	for (i = 0; i < ctrl->opts->nr_queues; i++) {
		queue = ctrl->queues + i;
		ret = nvmf_queue_call_function(queue, nvmf_queue_set_error, queue);
	}

	/* restart cntl */
	queue = ctrl->queues;
	ret = nvmf_queue_call_function(queue, nvmf_restart_admin_queue, queue);
	if (ret < 0) {
		return ret;
	}

	for (i = 1; i < ctrl->opts->nr_queues; i++) {
		queue = ctrl->queues + i;
		ret = nvmf_queue_call_function(queue, nvmf_restart_io_queue, queue);
		if (ret) {
			/* TODO stop all queues */
			return -1;
		}
	}

	nvmf_ctrl_set_reset(ctrl, false);

	return 0;
}

nvmf_ctrl_t nvmf_ctrl_create(nvmf_options_t options)
{
	struct nvmf_ctrl *ctrl = NULL;
	struct nvmf_transport_ops *ops;
	struct nvmf_ctrl_options *opts = (struct nvmf_ctrl_options *)options;
	struct nvmf_queue *queue;
	int index;


	ops = nvmf_transport_lookup(opts->transport);
	if (!ops) {
		goto out;
	}

	ctrl = (struct nvmf_ctrl *)nvmf_calloc(1, sizeof(*ctrl));
	if (!ctrl) {
		return NULL;
	}

	ctrl->ops = ops;
	ctrl->opts = options;
	ctrl->eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

	llist_head_init(&ctrl->complete);
	ctrl->queues = (struct nvmf_queue *)nvmf_calloc(opts->nr_queues, sizeof(struct nvmf_queue));
	if (!ctrl->queues) {
		goto out;
	}

	for (index = 0; index < opts->nr_queues; index++) {
		queue = ctrl->queues + index;
		nvmf_queue_init(queue, ctrl, index);
	}

	if (nvmf_ctrl_setup(ctrl)) {
		goto out;
	}

	return ctrl;

out:
	nvmf_free(ctrl->queues);
	nvmf_free(ctrl);

	return NULL;
}

void nvmf_ctrl_release(nvmf_ctrl_t ctrl)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct nvmf_queue *queue;
	int index;

	for (index = __ctrl->opts->nr_queues - 1; index >= 0; index--) {
		queue = __ctrl->queues + index;
		nvmf_queue_call_function(queue, nvmf_stop_queue, queue);
		nvmf_queue_release(queue);
	}

	nvmf_free(__ctrl->nslist);
	nvmf_free(__ctrl->queues);
	nvmf_free(__ctrl);
}

static int nvmf_ctrl_wait_ready(struct nvmf_ctrl *ctrl, bool enable)
{
	int ret = -ENODEV;
	int retry = 0;
	__u32 reg_csts;
	__u32 bit = enable ? NVME_CSTS_RDY : 0;

	do {
		ret = nvmf_reg_read32(ctrl, NVME_REG_CSTS, &reg_csts);
		if (ret < 0) {
			return -ENODEV;
		}

		log_debug("read cap NVME_REG_CSTS: 0x%x\n", reg_csts);
		if ((reg_csts & NVME_CSTS_RDY) == bit) {
			return 0;
		}

		usleep(1000);
		/* TODO should check timeout by NVME_CAP_TIMEOUT(reg_cap) */
	} while (++retry < 10);

	return ret;
}

int nvmf_ctrl_set_io_queues(struct nvmf_ctrl *ctrl, int queues)
{
	int ret = 0;
	__u32 qcount = (queues - 1) | ((queues - 1) << 16);

	ret = nvmf_set_features(ctrl, NVME_FEAT_NUM_QUEUES, qcount);

	return ret;
}

void nvmf_ctrl_process(nvmf_ctrl_t ctrl)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;
	struct llist_node *nodes;
	struct nvmf_request *req, *tmp;
	struct nvme_completion *cqe;
	uint64_t u = 0;

	log_trace();
	nvmf_ctrl_set_running(ctrl, true);

	/* consume all events */
	read(__ctrl->eventfd, &u, sizeof(u));

	while (!llist_empty(&__ctrl->complete)) {
		nodes = llist_del_all(&__ctrl->complete);
		llist_for_each_entry_safe(req, tmp, nodes, llist) {
			log_debug("tag[0x%x]processed in main thread\n", req->tag);
			nvmf_request_set_lat(req, REQ_DONE);
			req->done = true;
			cqe = req->cqe;
			if (req->ucb) {
				req->ucb(cqe->status, req->uopaque);
			}
		}
	}

	if (unlikely(nvmf_ctrl_get_reset(ctrl))) {
		nvmf_ctrl_reset(ctrl);
	}

	nvmf_ctrl_set_running(ctrl, false);
}

int nvmf_ctrl_fd(nvmf_ctrl_t ctrl)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;

	return __ctrl->eventfd;
}

static struct nvme_ns *nvmf_ns_find_by_id(struct nvmf_ctrl *ctrl, unsigned int nsid)
{
	struct nvme_ns *ns = NULL;
	unsigned int idx;

	for (idx = 0; idx < ctrl->nscount; idx++) {
		if (ctrl->nslist[idx].nsid == nsid) {
			ns = &ctrl->nslist[idx];
			log_debug("find nsid %d\n", nsid);
			return ns;
		}
	}

	log_warn("can not find nsid %d\n", nsid);

	return NULL;
}

int nvmf_ns_active_list_identify(struct nvmf_ctrl *ctrl)
{
	int ret = 0;

	ret = nvmf_identify(ctrl, NVME_ID_CNS_NS_ACTIVE_LIST);
	if (ret < 0) {
		log_warn("nvmf_identify NVME_ID_CNS_NS_ACTIVE_LIST failed, ret %d\n", ret);
		return ret;
	}

	ctrl->ns = nvmf_ns_find_by_id(ctrl, ctrl->opts->nsid);
	if (!ctrl->ns) {
		log_error("scan target without nsid %d from options\n", ctrl->opts->nsid);
		return -EINVAL;
	}

	return ret;
}

unsigned int nvmf_ctrl_mdts(nvmf_ctrl_t ctrl)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;

	return (1 << __ctrl->mdts) * NVMF_SECTOR_SIZE;
}

unsigned int nvmf_ctrl_dsm_segments(nvmf_ctrl_t ctrl)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;

	if (!(__ctrl->oncs & NVME_CTRL_ONCS_DSM)) {
		return 0;
	} else {
		return NVME_DSM_MAX_RANGES;
	}
}

unsigned int nvmf_ns_count(nvmf_ctrl_t ctrl)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;

	return __ctrl->nscount;
}

unsigned int nvmf_ns_id(nvmf_ctrl_t ctrl)
{
	struct nvmf_ctrl *__ctrl = (struct nvmf_ctrl *)ctrl;

	return __ctrl->opts->nsid;
}

unsigned char nvmf_ns_lbads(nvmf_ctrl_t ctrl, unsigned int nsid)
{
	struct nvme_ns *ns;

	ns = nvmf_ns_find_by_id(ctrl, nsid);
	if (!ns) {
		log_error("scan controller without nsid %d\n", nsid);
		return 0;
	}

	return ns->lbads;
}

unsigned long nvmf_ns_nsze(nvmf_ctrl_t ctrl, unsigned int nsid)
{
	struct nvme_ns *ns;

	ns = nvmf_ns_find_by_id(ctrl, nsid);
	if (!ns) {
		log_error("scan controller without nsid %d\n", nsid);
		return 0;
	}

	return ns->nsze;
}
