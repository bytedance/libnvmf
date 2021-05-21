/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "nvmf-private.h"
#include "utils.h"
#include "log.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

__u16 nvmf_queue_req_get_tag(struct nvmf_request *req)
{
	struct nvmf_queue *queue = req->queue;
	__u16 index = slab_index(queue->slab_req, req);

	return queue->qid * NVMF_MAX_QUEUE_SIZE + index;
}

struct nvmf_request *nvmf_queue_req_by_tag(struct nvmf_queue *queue, __u16 tag)
{
	struct nvmf_request *req = NULL;

	list_for_each_entry(req, &queue->inflight, node) {
		if (req->tag == tag) {
			return req;
		}
	}

	return NULL;
}

static inline void nvmf_queue_kick(struct nvmf_queue *queue)
{
	uint64_t u = 1;

	/* kick queue thread if running in idle state */
	if (nvmf_queue_state_get(queue) == QUEUE_STATE_RUNNING) {
		return;
	}

	if (write(queue->eventfd, &u, sizeof(u)) < 0) {
		log_error("queue[%d]kick failed, %m\n", queue->qid);
	}
}

int nvmf_queue_req(struct nvmf_queue *queue, struct nvmf_request *req)
{
	bool queued = !!llist_add(&req->llist, &queue->queueing);

	if (queued) {
		return 0;
	}

	nvmf_queue_kick(queue);

	return 0;
}

struct nvmf_request *nvmf_queue_grab_req(struct nvmf_queue *queue)
{
	struct llist_node *node;

retry:
	if (queue->pending) {
		node = queue->pending;
		queue->pending = llist_next(queue->pending);
		llist_node_init(node);
		return container_of(node, struct nvmf_request, llist);
	}

	/* fetch batch requests from queueing list */
	if (!llist_empty(&queue->queueing)) {
		queue->pending = llist_del_all(&queue->queueing);
		goto retry;
	}

	return NULL;
}

static int nvmf_queue_handle_event(struct nvmf_queue *queue, short event)
{
	struct llist_node *works;
	struct nvmf_queue_work *work, *tmp;
	uint64_t u = 0;

	log_trace();
	/* clear eventfd */
	read(queue->eventfd, &u, sizeof(u));

	works = llist_del_all(&queue->works);
	llist_for_each_entry_safe(work, tmp, works, node) {
		work->retval = work->func(work->arg);

		pthread_mutex_lock(&work->mutex);
		work->done = true;
		pthread_mutex_unlock(&work->mutex);
        pthread_cond_signal(&work->wait);
	}

	return 0;
}

static int nvmf_queue_handle_io(struct nvmf_queue *queue, short revents)
{
	return queue->ctrl->ops->ctrl_process_queue(queue, revents);
}

int nvmf_queue_timer_new(struct nvmf_queue *queue,
                         void (*func)(struct nvmf_queue_timer *timer, void *arg), void *arg,
                         uint64_t timeout_ms)
{
	uint64_t now = nvmf_now_ms();
	struct nvmf_queue_timer *timer;

	log_trace();
	timer = (struct nvmf_queue_timer *)nvmf_calloc(1, sizeof(*timer));
	assert(timer);

	timer->func = func;
	timer->arg = arg;
	timer->expired = now + timeout_ms;

	list_add_tail(&timer->node, &queue->timers);

	return 0;
}

void nvmf_queue_timer_mod(struct nvmf_queue_timer *timer, uint64_t timeout_ms)
{
	uint64_t now = nvmf_now_ms();

	timer->expired = now + timeout_ms;
}

static void nvmf_queue_handle_timer(struct nvmf_queue *queue)
{
	struct nvmf_queue_timer *timer, *tmp;
	uint64_t now = nvmf_now_ms();

	log_trace();
	list_for_each_entry_safe(timer, tmp, &queue->timers, node) {
		if (now <= timer->expired) {
			continue;
		}

		timer->func(timer, timer->arg);

		if (now >= timer->expired) {
			list_del(&timer->node);
			nvmf_free(timer);
		}
	}
}

static void nvmf_queue_clear_timer(struct nvmf_queue *queue)
{
	struct nvmf_queue_timer *timer, *tmp;

	log_trace();
	list_for_each_entry_safe(timer, tmp, &queue->timers, node) {
		list_del(&timer->node);
		nvmf_free(timer);
	}
}

int nvmf_queue_set_error(void *arg)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;
	struct nvmf_pfd *pfd, *tmp;

	log_debug("queue[%d]set error state\n", queue->qid);
	nvmf_queue_state_set(queue, QUEUE_STATE_ERROR);

	/* clear all pfds, re-set control event */
	list_for_each_entry_safe(pfd, tmp, &queue->pfds, node) {
		if (pfd->pfd.fd == queue->eventfd) {
			continue;
		}

		log_debug("queue[%d]remove pfd fd[%d]\n", queue->qid, pfd->pfd.fd);
		list_del(&pfd->node);
		nvmf_free(pfd);
	}

	return 0;
}

void nvmf_queue_retransfer_save(struct nvmf_queue *queue)
{
	struct nvmf_request *req, *tmp;

	log_debug("queue[%d]save request, nr_inflight %d\n", queue->qid, queue->nr_inflight);
	list_for_each_entry_safe(req, tmp, &queue->inflight, node) {
		list_del(&req->node);
		list_add_tail(&req->node, &queue->retransfer);
		req->tag = 0;
	}

	while ((req = nvmf_queue_grab_req(queue)) != NULL) {
		list_add_tail(&req->node, &queue->retransfer);
		req->tag = 0;
	}
}

void nvmf_queue_retransfer_restore(struct nvmf_queue *queue)
{
	struct nvmf_request *req, *tmp;

	log_debug("queue[%d]restore request, nr_inflight %d\n", queue->qid, queue->nr_inflight);
	list_for_each_entry_safe(req, tmp, &queue->retransfer, node) {
		list_del(&req->node);
		llist_add(&req->llist, &queue->queueing);
	}
}

static void nvmf_kato_cb(unsigned short status, void *opaque)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)opaque;
	struct nvmf_ctrl *ctrl = queue->ctrl;

	log_debug("kato cb status %d\n", status);

	nvmf_ctrl_free_request(ctrl, ctrl->kato_req);
	ctrl->kato_req = NULL;
}

static void nvmf_ctrl_kato_work(struct nvmf_queue_timer *timer, void *arg)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;
	struct nvmf_ctrl *ctrl = queue->ctrl;
	struct nvmf_request *req;

	log_trace();
	if (ctrl->kato_req) {
		/* don't free kato_req, to retry again */
		log_error("previous KATO expired\n");
		nvmf_ctrl_set_reset(ctrl, true);
		nvmf_ctrl_kick(ctrl);
		nvmf_queue_timer_mod(timer, ctrl->opts->kato);

		return;
	}

	req = nvmf_keepalive_async(queue, nvmf_kato_cb, queue);
	if (!req) {
		/* TODO teardown */
		return;
	}

	ctrl->kato_req = req;

	nvmf_queue_timer_mod(timer, ctrl->opts->kato);
}

int nvmf_queue_init(struct nvmf_queue *queue, struct nvmf_ctrl *ctrl, unsigned int qid)
{
	int efd;

	queue->ctrl = ctrl;
	queue->qid = qid;
	queue->state = QUEUE_STATE_UNINITIALIZED;

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (efd < 0) {
		return efd;
	}

	queue->eventfd = efd;
	INIT_LIST_HEAD(&queue->pfds);
	INIT_LIST_HEAD(&queue->timers);
	llist_head_init(&queue->works);
	llist_head_init(&queue->queueing);
	queue->pending = NULL;
	INIT_LIST_HEAD(&queue->inflight);
	INIT_LIST_HEAD(&queue->retransfer);

	/* start kato timer on admin queue */
	if (qid == 0) {
		nvmf_queue_timer_new(queue, nvmf_ctrl_kato_work, queue, ctrl->opts->kato);
	}

	return 0;
}

int nvmf_queue_release(struct nvmf_queue *queue)
{
	pthread_join(queue->thread, NULL);
	return 0;
}

static void nvmf_queue_thread_setname(struct nvmf_queue *queue)
{
	struct nvmf_ctrl *ctrl = queue->ctrl;
	char name[16] = {0};
	int len, offset = 0;

	/*
	 * set thread name
	 * nvmf-SHORTNQN[last 7 bytes of NQN]-QID[2 bytes]
	 */
#define SHORTNQNLEN	7
	len = strlen(ctrl->opts->trnqn);
	if (len >= SHORTNQNLEN) {
		offset = len - SHORTNQNLEN;
	}

	snprintf(name, sizeof(name) - 1, "nvmf-%7s-%d", ctrl->opts->trnqn + offset, queue->qid);
	pthread_setname_np(pthread_self(), name);
}

int nvmf_queue_teardown(struct nvmf_queue *queue)
{
	/* stop IO firstly */
	queue->ctrl->ops->release_queue(queue);

	nvmf_queue_clear_timer(queue);
	queue->should_stop = true;

	return 0;
}

int nvmf_queue_restart(struct nvmf_queue *queue)
{
	queue->should_stop = false;
	nvmf_queue_state_set(queue, QUEUE_STATE_UNINITIALIZED);

	return queue->ctrl->ops->restart_queue(queue);
}

int nvmf_queue_set_event(struct nvmf_queue *queue, int fd,
                         int (*pollin_cb)(struct nvmf_queue *queue, short event),
                         int (*pollout_cb)(struct nvmf_queue *queue, short event))
{
	struct nvmf_pfd *pfd;
	short events = POLLHUP | POLLERR;
	bool set = pollin_cb || pollout_cb;

	list_for_each_entry(pfd, &queue->pfds, node) {
		if (pfd->pfd.fd == fd) {
			break;
		}
	}

	events = pollin_cb ? POLLIN : 0;
	events |= pollout_cb ? POLLOUT : 0;

	/* not found */
	if (&pfd->node == &queue->pfds) {
		if (!set) {
			return -ENODEV;
		}

		pfd = nvmf_calloc(1, sizeof(*pfd));
		pfd->pfd.fd = fd;
		pfd->pfd.events = events;
		pfd->pfd.revents = 0;
		pfd->pollin_cb = pollin_cb;
		pfd->pollout_cb = pollout_cb;

		list_add_tail(&pfd->node, &queue->pfds);
	} else {
		if (!set) {
			list_del(&pfd->node);
			nvmf_free(pfd);

			return 0;
		}

		pfd->pfd.events = events;
		pfd->pfd.revents = 0;
		pfd->pollin_cb = pollin_cb;
		pfd->pollout_cb = pollout_cb;
	}

	return 0;
}

static bool nvmf_queue_should_stop(struct nvmf_queue *queue)
{
	return queue->should_stop;
}

#define HZ		1000
#define TICK		(1000 / HZ)

static void nvmf_queue_pollfds(struct nvmf_queue *queue)
{
	struct nvmf_pfd *pfd;
	struct pollfd pfds[PFDMAX], *dstpfd;
	int ret, i, nr_pfds;

	log_trace();

	/* try to send all pending requests */
	if (!nvmf_queue_is_idle(queue)) {
		nvmf_queue_handle_io(queue, POLLOUT);
	}

	nr_pfds = 0;
	memset(pfds, 0x00, sizeof(pfds));
	list_for_each_entry(pfd, &queue->pfds, node) {
		dstpfd = &pfds[nr_pfds++];
		*dstpfd = pfd->pfd;
	}

	nvmf_queue_state_set(queue, QUEUE_STATE_IDLE);
	ret = poll(pfds, nr_pfds, TICK);
	if (ret < 0) {
		log_error("queue[%d] poll error", queue->qid);
	}

	/* let's run! */
	nvmf_queue_state_set(queue, QUEUE_STATE_RUNNING);

	for (i = 0; i < nr_pfds; i++) {
		dstpfd = &pfds[i];

		if ((dstpfd->revents & POLLHUP) || (dstpfd->revents & POLLERR)) {
			nvmf_queue_set_error(queue);
			break;
		}

		list_for_each_entry(pfd, &queue->pfds, node) {
			if (pfd->pfd.fd == dstpfd->fd) {
				break;
			}
		}

		/* always check POLLIN event */
		if (pfd->pollin_cb) {
			pfd->pollin_cb(queue, POLLIN);
		}

		if (unlikely(nvmf_queue_should_stop(queue))) {
			break;
		}

		if ((dstpfd->revents & POLLOUT) && pfd->pollout_cb) {
			pfd->pollout_cb(queue, POLLOUT);
		}

		if (unlikely(nvmf_queue_state_get(queue) == QUEUE_STATE_ERROR)) {
			break;
		}
	}
}

/* sync API, this API can be called only from queue thread context */
int nvmf_queue_do_req(struct nvmf_request *req)
{
	struct nvmf_queue *queue = req->queue;
	unsigned long start = nvmf_now_ms(), now;
	unsigned long timeout = req->timeout;

	log_trace();
	while (true) {
		nvmf_queue_pollfds(queue);
		if (req->done) {
			return 0;
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

/* sync API, this API can be called only from queue thread context */
int nvmf_queue_wait_state(struct nvmf_queue *queue, int state, int timeout_ms)
{
	unsigned long start = nvmf_now_ms(), now;

	log_trace();
	while (true) {
		nvmf_queue_pollfds(queue);
		if (queue->state == state) {
			return 0;
		}

		now = nvmf_now_ms();
		if (now - start < timeout_ms) {
			continue;
		} else {
			return -ETIME;
		}
	};

	return 0;
}

static void *nvmf_queue_thread(void *arg)
{
	struct nvmf_queue *queue = (struct nvmf_queue *)arg;
	nvmf_queue_thread_setname(queue);

	log_trace();
	/* always initilize event controll fd */
	nvmf_queue_set_event(queue, queue->eventfd, nvmf_queue_handle_event, NULL);

	do {
		nvmf_queue_pollfds(queue);

		nvmf_queue_handle_timer(queue);

		log_trace();
	} while (!nvmf_queue_should_stop(queue));

	log_debug("queue[%d]dying\n", queue->qid);
	nvmf_queue_set_event(queue, queue->eventfd, NULL, NULL);
	close(queue->eventfd);

	return NULL;
}

int nvmf_queue_thread_start(struct nvmf_queue *queue)
{
	return pthread_create(&queue->thread, NULL, nvmf_queue_thread, queue);
}

int nvmf_queue_call_function(struct nvmf_queue *queue, int (*func)(void *arg), void *arg)
{
	struct nvmf_queue_work work;

	llist_node_init(&work.node);
	work.func = func;
	work.arg = arg;
	work.retval = 0;
	work.done = false;
	pthread_cond_init(&work.wait, NULL);
	pthread_mutex_init(&work.mutex, NULL);

	/* queue a work and try to kick target queue thread */
	llist_add(&work.node, &queue->works);
	nvmf_queue_kick(queue);

	pthread_mutex_lock(&work.mutex);
	while (!work.done) {
        pthread_cond_wait(&work.wait, &work.mutex);
	}
	pthread_mutex_unlock(&work.mutex);

	return work.retval;
}
