/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#ifndef _LIBNVMF_PRIVATE_
#define _LIBNVMF_PRIVATE_

#include "types.h"
#include "list.h"
#include "llist.h"
#include "nvme.h"
#include "slab.h"
#include "utils.h"

#include <sys/uio.h>
#include <pthread.h>
#include <poll.h>

#define NVMF_MIN_QUEUE_SIZE		16
#define NVMF_MAX_QUEUE_SIZE		1024
#define NVMF_DEF_QUEUE_SIZE		128
#define NVMF_DEF_IO_QUEUES		4
#define NVME_DEFAULT_KATO		5000
#define NVME_KATO_GRACE			1000
#define NVMF_MAX_IOV			128
#define NVMF_DEF_MDTS			8
#define NVMF_DEF_PAGE_SHIFT		12
#define NVMF_SECTOR_SIZE		512
#define NVMF_SECTOR_SHIFT		9

struct nvmf_ctrl_options {
	unsigned mask;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *trnqn;
	char *hostnqn;
	char *host_traddr;
	unsigned int nsid;
	uuid_t uuid;

	unsigned int nr_queues;
	unsigned int qsize;
	unsigned int kato;
	unsigned int max_reconnects;

	bool hdr_digest;
	bool data_digest;
};

typedef void *nvmf_transport_ctrl_t;

struct nvme_ns {
	__u32 nsid;

	__u8 lbads;	/* LBA data size */
	__u64 nsze;
	__u64 ncap;
};

#define REQ_ALLOCATED	0
#define REQ_QUEUED	1
#define REQ_GRABED	2
#define REQ_COMPLETE	3
#define REQ_DONE	4
#define REQ_STATE_MAX	5

struct nvmf_request {
	/* request argument */
	struct nvmf_queue *queue;

	/* nvme cmd & cqe */
	struct nvme_command *cmd;
	struct nvme_completion *cqe;

	int timeout;

	__u16 tag;

	/* does request finish? */
	bool done;

	/* for queueing/pending/complete state */
	struct llist_node llist;

	/* for inflight/retransfer state */
	struct list_head node;

	/* cb: callback function used by libnvmf */
	void (*cb)(struct nvmf_request *req, void *opaque);
	void *opaque;
	/* cb: callback function defined by user uplayer */
	void (*ucb)(__u16 status, void *opaque);
	void *uopaque;

	/* private data used by transport */
	void *priv;

	/* io vectors for user */
	int iovcnt;	/* total iov count */
	struct iovec *iovs;

#ifdef LAT_DEBUG
	unsigned long lat_debug[REQ_STATE_MAX];
#endif
};

#ifdef LAT_DEBUG
static inline void nvmf_request_set_lat(struct nvmf_request *req, int state)
{
	req->lat_debug[state] = nvmf_now_us();
}
#else
static inline void nvmf_request_set_lat(struct nvmf_request *req, int state)
{}
#endif

#define QUEUE_STATE_UNINITIALIZED 	0
#define QUEUE_STATE_READY	 	1
#define QUEUE_STATE_IDLE	 	2
#define QUEUE_STATE_RUNNING	 	3
#define QUEUE_STATE_DYING	 	4
#define QUEUE_STATE_EXIT	 	5
#define QUEUE_STATE_ERROR	 	99

struct nvmf_queue_work {
	struct llist_node node;
	int (*func)(void *arg);
	void *arg;
	int retval;
	pthread_cond_t wait;
	pthread_mutex_t mutex;
};

struct nvmf_queue_timer {
	struct list_head node;
	void (*func)(struct nvmf_queue_timer *timer, void *arg);
	void *arg;
	__u64 expired;
};

struct nvmf_ctrl;
struct nvmf_queue;

struct nvmf_pfd {
	struct list_head node;
	struct pollfd pfd;
	int (*pollin_cb)(struct nvmf_queue *queue, short event);
	int (*pollout_cb)(struct nvmf_queue *queue, short event);
};

/* typically, thread eventfd, io queue fd, io queue ctrl fd(Ex, rdma cma) */
#define PFDMAX	3
struct nvmf_queue {
	struct nvmf_ctrl *ctrl;
	void *priv;
	__u32 qsize;
	__u16 qid;
	int nr_inflight;
	/* maintained by queue thread */
	unsigned char state;
	/* admin thread tell the io-thread should stop or not */
	bool should_stop;

	/* list for pfds */
	struct list_head pfds;

	/* thread per queue */
	pthread_t thread;
	/* eventfd to kick queue */
	int eventfd;
	/* double linked list for timer events */
	struct list_head timers;
	/* lockless list for pending works, thread call function */
	struct llist_head works;

	/* lockless list for queueing requests, insert request to queue */
	struct llist_head queueing;
	/* prepare to process */
	struct llist_node *pending;
	/* double linked list for inflight request */
	struct list_head inflight;
	/* double linked list for retransfer request during re-connect */
	struct list_head retransfer;

	/* nvmf_request slab */
	slab_t slab_req;
};

struct nvmf_ctrl {
	struct nvmf_transport_ops *ops;
	struct nvmf_ctrl_options *opts;

	__u16 cntlid;

	/* ctrl regs */
	__u64 reg_cap;
	__u32 reg_vs;
	__u32 reg_cc;
	__u32 reg_csts;

	/* ctrl identify */
	char sn[20 + 1];
	char mn[40 + 1];
	__u32 nn;
	__u8 mdts;
	__u8 vwc;

	__u32 ioccsz;
	__u32 iorcsz;
	__u16 icdoff;
	__u16 maxcmd;
	__u16 oncs;

	/* ns identify */
	__u32 nscount;
	struct nvme_ns *nslist;	/* all the namespaces */
	struct nvme_ns *ns;	/* current in use namespace */

	/* queues */
	struct nvmf_queue *queues;

	/* if ctrl is running or idle */
	bool running;
	/* if ctrl need reset */
	bool reset;
	/* eventfd to kick ctrl */
	int eventfd;
	/* lockless list for complete requests */
	struct llist_head complete;
	/* kato request */
	struct nvmf_request *kato_req;
};

struct nvmf_transport_ops {
	struct list_head entry;
	const char *name;

	int (*ctrl_process_queue)(struct nvmf_queue *queue, short revents);
	int (*create_queue)(struct nvmf_queue *queue);
	int (*release_queue)(struct nvmf_queue *queue);
	int (*restart_queue)(struct nvmf_queue *queue);
	struct nvmf_request *(*alloc_request)(struct nvmf_queue *queue);
	void (*free_request)(struct nvmf_request *req);
	int (*queue_request)(struct nvmf_request *req, struct iovec *iovs, int iovcnt);
	int (*queue_fd)(struct nvmf_queue *queue);
	int (*queue_event)(struct nvmf_queue *queue);
};

/* transport API */
int nvmf_transport_register(struct nvmf_transport_ops *ops);
void nvmf_transport_unregister(struct nvmf_transport_ops *ops);
struct nvmf_transport_ops *nvmf_transport_lookup(const char *name);
void nvmf_transport_tcp_init(void);
#ifdef USE_RDMA
void nvmf_transport_rdma_init(void);
#else
static inline void nvmf_transport_rdma_init(void)
{}
#endif

/* ctrl API */
int nvmf_ctrl_enable(struct nvmf_ctrl *ctrl);
int nvmf_ctrl_identify(struct nvmf_ctrl *ctrl);
int nvmf_ctrl_set_io_queues(struct nvmf_ctrl *ctrl, int queues);
int nvmf_ctrl_do_req(struct nvmf_request *req);
void nvmf_ctrl_kick(struct nvmf_ctrl *ctrl);
void nvmf_ctrl_set_reset(struct nvmf_ctrl *ctrl, bool reset);
static inline void nvmf_req_set_done(struct nvmf_request *req, bool done)
{
        __atomic_store_n(&req->done, done, __ATOMIC_SEQ_CST);
}

static inline bool nvmf_req_get_done(struct nvmf_request *req)
{
        return __atomic_load_n(&req->done, __ATOMIC_SEQ_CST);
}

static inline struct nvmf_request *nvmf_ctrl_alloc_request(struct nvmf_ctrl *ctrl,
                                                           struct nvmf_queue *queue)
{
	struct nvmf_request *req = ctrl->ops->alloc_request(queue);

	if (req) {
		queue->nr_inflight++;
	}

	return req;
}

static inline void nvmf_ctrl_free_request(struct nvmf_ctrl *ctrl, struct nvmf_request *req)
{
	--req->queue->nr_inflight;
	ctrl->ops->free_request(req);
}

/* fabric API */
int nvmf_connect_admin_queue(struct nvmf_queue *queue);
int nvmf_connect_io_queue(struct nvmf_queue *queue);
int nvmf_reg_read32(struct nvmf_ctrl *ctrl, __u32 offset, __u32 *val);
int nvmf_reg_read64(struct nvmf_ctrl *ctrl, __u32 offset, __u64 *val);
int nvmf_reg_write32(struct nvmf_ctrl *ctrl, __u64 offset, __u64 val);
int nvmf_set_features(struct nvmf_ctrl *ctrl, __u32 feature, __u32 val);
int nvmf_identify(struct nvmf_ctrl *ctrl, __u8 cns);
int nvmf_ns_identify(struct nvmf_ctrl *ctrl);
int nvmf_ns_active_list_identify(struct nvmf_ctrl *ctrl);
struct nvmf_request *nvmf_keepalive_async(struct nvmf_queue *queue,
                                          void (*cb)(unsigned short status, void *opaque),
                                          void *opaque);


/* queue API */
int nvmf_queue_thread_start(struct nvmf_queue *queue);
int nvmf_queue_init(struct nvmf_queue *queue, struct nvmf_ctrl *ctrl, unsigned int qid);
int nvmf_queue_release(struct nvmf_queue *queue);
int nvmf_queue_timer_new(struct nvmf_queue *queue,
                         void (*func)(struct nvmf_queue_timer *timer, void *arg), void *arg,
                         uint64_t timeout_ms);
void nvmf_queue_timer_mod(struct nvmf_queue_timer *timer, uint64_t timeout_ms);
int nvmf_queue_call_function(struct nvmf_queue *queue, int (*func)(void *arg), void *arg);
__u16 nvmf_queue_req_get_tag(struct nvmf_request *req);
struct nvmf_request *nvmf_queue_req_by_tag(struct nvmf_queue *queue, __u16 tag);
struct nvmf_request *nvmf_queue_grab_req(struct nvmf_queue *queue);
int nvmf_queue_req(struct nvmf_queue *queue, struct nvmf_request *req);
int nvmf_queue_do_req(struct nvmf_request *req);
int nvmf_queue_wait_state(struct nvmf_queue *queue, int state, int timeout_ms);
int nvmf_queue_teardown(struct nvmf_queue *queue);
int nvmf_queue_restart(struct nvmf_queue *queue);
int nvmf_queue_set_event(struct nvmf_queue *queue, int fd,
                         int (*pollin_cb)(struct nvmf_queue *queue, short event),
                         int (*pollout_cb)(struct nvmf_queue *queue, short event));
int nvmf_queue_set_error(void *arg);
void nvmf_queue_retransfer_save(struct nvmf_queue *queue);
void nvmf_queue_retransfer_restore(struct nvmf_queue *queue);

static inline bool nvmf_queue_is_idle(struct nvmf_queue *queue)
{
	return llist_empty(&queue->queueing) &&
               (!__atomic_load_n(&queue->pending, __ATOMIC_SEQ_CST));
}

static inline void nvmf_queue_req_inflight(struct nvmf_request *req)
{
	list_add_tail(&req->node, &req->queue->inflight);
}

static inline void nvmf_queue_req_finish(struct nvmf_request *req)
{
	/* to make sure delete from inflight list */
	list_del_init(&req->node);
}

static inline int nvmf_queue_state_get(struct nvmf_queue *queue)
{
	return __atomic_load_n(&queue->state, __ATOMIC_SEQ_CST);
}


static inline void nvmf_queue_state_set(struct nvmf_queue *queue, int val)
{
	__atomic_store_n(&queue->state, val, __ATOMIC_SEQ_CST);
}

/* event API */
int nvmf_event_do_req(struct nvmf_request *req);


#endif /* _LIBNVMF_PRIVATE_ */
