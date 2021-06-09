/*
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "nvmf-private.h"
#include "nvmf.h"
#include "list.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>

LIST_HEAD(transport_list);
pthread_mutex_t transport_list_lock = PTHREAD_MUTEX_INITIALIZER;

int nvmf_transport_register(struct nvmf_transport_ops *ops)
{
	if (!ops->name) {
		return -EINVAL;
	}

	pthread_mutex_lock(&transport_list_lock);
	list_add_tail(&ops->entry, &transport_list);
	pthread_mutex_unlock(&transport_list_lock);

	return 0;
}

void nvmf_transport_unregister(struct nvmf_transport_ops *ops)
{
	pthread_mutex_lock(&transport_list_lock);
	list_del(&ops->entry);
	pthread_mutex_unlock(&transport_list_lock);
}

struct nvmf_transport_ops *nvmf_transport_lookup(const char *name)
{
	struct nvmf_transport_ops *ops;

	list_for_each_entry(ops, &transport_list, entry) {
		if (strcmp(ops->name, name) == 0) {
			return ops;
		}
	}

	return NULL;
}
