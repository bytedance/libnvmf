#include "llist.h"
#include "log.h"
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define LOOP	10000000UL
#define WORKS	4
#define HISTLEN	1024

struct element {
	struct llist_node node;
	unsigned long val;
};

struct context {
	struct llist_head *head;
	unsigned long val;
	unsigned long hist[HISTLEN];
};

static void *producer(void *arg)
{
	struct context *context = (struct context *)arg;
	struct llist_head *head = context->head;
	struct element *elem;
	unsigned long loop;

	log_trace();

	for (loop = 0; loop < LOOP; loop++) {
		elem = calloc(sizeof(struct element), 1);
		assert(elem);

		elem->val = 1;
		llist_add(&elem->node, head);
	}

	log_trace();

	return NULL;
}

static void *consumer(void *arg)
{
	struct context *context = (struct context *)arg;
	struct llist_head *head = context->head;
	struct llist_node *batch;
	struct element *elem, *tmp;
	unsigned long batchlen;

	log_trace();

	while (1) {
		batch = llist_del_all(head);
		if (!batch) {
			usleep(100);
			if (llist_empty(head)) {
				break;
			}
		}

		batchlen = 0;
		llist_for_each_entry_safe(elem, tmp, batch, node) {
			context->val += elem->val;
			free(elem);
			batchlen++;
		}

		if (batchlen >= HISTLEN) {
			batchlen = HISTLEN - 1;
		}

		context->hist[batchlen]++;
	}

	log_trace();

	return NULL;
}

int main(int argc, char *argv[])
{
	struct llist_head head;
	pthread_t thread_ids[WORKS * 2];
	struct context contexts[WORKS], *context;
	unsigned long hist[HISTLEN] = {0};
	unsigned long val = 0;
	int i, h;

	llist_init(&head);
	memset(contexts, 0x00, sizeof(contexts));

	for (i = 0; i < WORKS; i++) {
		context = &contexts[i];
		context->head = &head;

		if (pthread_create(&thread_ids[i], NULL, producer, context) < 0) {
			log_error("thread create failed");
			return -1;
		}

		if (pthread_create(&thread_ids[WORKS + i], NULL, consumer, context) < 0) {
			log_error("thread create failed");
			return -1;
		}
	}

	for (i = 0; i < WORKS * 2; i++) {
		pthread_join(thread_ids[i], NULL);
	}

	for (i = 0; i < WORKS; i++) {
		context = &contexts[i];
		val += context->val;

		for (h = 0; h < HISTLEN; h++) {
			hist[h] += context->hist[h];
		}
	}

	/* show histgram */
	for (h = 0; h < HISTLEN; h++) {
		if (hist[h]) {
			printf("\thistgram %4d: %ld\n", h, hist[h]);
		}
	}

	printf("Test %s, %ld vs %ld\n", val == LOOP * WORKS ? "succeed" : "failed", val,
               LOOP * WORKS);

	return 0;
}
