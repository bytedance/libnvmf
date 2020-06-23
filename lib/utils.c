/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include "utils.h"
#include "log.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef MALLOC_DEBUG

#define PATH_LEN	2048
#define LINE_LEN	4096
int logfd;

void nvmf_malloc_init(void)
{
	char *mtrace_env;
	char path[PATH_LEN] = {0};

	mtrace_env = getenv("MALLOC_TRACE");
	if (mtrace_env == NULL) {
		return;
	}

	if (logfd) {
		return;
	}

	snprintf(path, sizeof(path), "%s/nvmf_mtrace_%d", mtrace_env, getpid());

	logfd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (logfd < 0) {
		log_error("open logfd %s failed, %m", path);
	}

	return;
}

#define nvmf_log_mtrace(op, ptr, file, line)	do {	\
	char str[LINE_LEN] = {0};	\
	int len;	\
	if (logfd > 0) {	\
		len = snprintf(str, sizeof(str), "%c %p %s %d\n", op, ptr, file, line);	\
		if (write(logfd, str, len) < 0)	\
			log_error("write logfd failed, %m");	\
	}	\
} while (0)

__attribute__((noinline)) void *_nvmf_calloc(size_t nmemb, size_t size, const char *file, int line)
{
	void *ptr = calloc(nmemb, size);

	nvmf_log_mtrace('+', ptr, file, line);

	return ptr;
}

__attribute__((noinline)) void *_nvmf_malloc(size_t size, const char *file, int line)
{
	void *ptr = malloc(size);

	nvmf_log_mtrace('+', ptr, file, line);

	return ptr;
}

__attribute__((noinline)) void _nvmf_free(void *ptr, const char *file, int line)
{
	if (!ptr) {
		return;
	}

	nvmf_log_mtrace('-', ptr, file, line);

	free(ptr);
}

__attribute__((noinline))  char *_nvmf_strndup(const char *s, size_t n, const char *file, int line)
{
	char *ptr = strndup(s, n);

	nvmf_log_mtrace('+', ptr, file, line);

	return ptr;
}
#else
inline void nvmf_malloc_init()
{
}

inline void *nvmf_calloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

inline void *nvmf_malloc(size_t size)
{
	return malloc(size);
}

inline void nvmf_free(void *ptr)
{
	free(ptr);
}

inline char *nvmf_strndup(const char *s, size_t n)
{
	return strndup(s, n);
}
#endif
