/* SPDX-License-Identifier: MIT */
#include "sa_mgr.h"

#include <errno.h>
#include <limits.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <time.h>

#define RX_BUF 8192

typedef size_t (*build_fn)(void *, size_t, const struct sa_spec *, uint32_t);

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Zero means no matching ACK, not necessarily a timeout. */
static int drain_acks(struct transport *t, int timeout_ms, uint32_t base,
		      size_t sent, int *results)
{
	char buf[RX_BUF] __attribute__((aligned(8)));
	ssize_t len = t->recv(t, buf, sizeof(buf), timeout_ms);
	if (len <= 0)
		return (int)len;
	if ((size_t)len > sizeof(buf)) {
		errno = EMSGSIZE;
		return -1;
	}
	int got = 0;
	int left = (int)len;
	for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; left >= 0 && NLMSG_OK(nh, (unsigned int)left);
	     nh = NLMSG_NEXT(nh, left)) {
		uint32_t seq;
		int err;
		if (xfrm_parse_ack(nh, nh->nlmsg_len, &seq, &err) != 1)
			continue;
		if (seq < base || seq - base >= sent)
			continue;
		int *slot = &results[seq - base];
		if (*slot != SA_PENDING)
			continue;
		*slot = err;
		got++;
	}
	return got;
}

static int run(struct transport *t, const struct sa_spec *sas, size_t n,
	       unsigned window, int timeout_ms, int *results, build_fn build)
{
	char req[XFRM_MSG_BUF] __attribute__((aligned(8)));
	size_t next = 0, done = 0, inflight = 0, first = 0;
	if (!t || !t->send || !t->recv || (n && (!sas || !results)) ||
	    n > INT_MAX || timeout_ms <= 0) {
		errno = EINVAL;
		return -1;
	}
	if (!n)
		return 0;
	/* Never reuse a sequence on this socket, even after a failed batch. */
	if (t->seq > UINT32_MAX || n > UINT32_MAX - t->seq) {
		errno = EOVERFLOW;
		return -1;
	}
	int64_t *deadlines = calloc(n, sizeof(*deadlines));
	if (!deadlines)
		return -1;
	uint32_t base = (uint32_t)t->seq + 1;
	t->seq += n;
	if (!window)
		window = 1;
	for (size_t i = 0; i < n; i++)
		results[i] = SA_PENDING;

	while (done < n) {
		while (inflight < window && next < n) {
			size_t len = build(req, sizeof(req), &sas[next],
					   base + (uint32_t)next);
			if (!len) {
				errno = EINVAL;
				goto fail;
			}
			if (t->send(t, req, len) < 0) {
				/* Drain replies before retrying a full send queue. */
				if ((errno == EAGAIN || errno == EWOULDBLOCK) && inflight)
					break;
				goto fail;
			}
			deadlines[next++] = now_ms() + timeout_ms;
			inflight++;
		}
		int64_t now = now_ms();
		int wait_ms = timeout_ms;
		for (size_t i = first; i < next; i++) {
			if (results[i] != SA_PENDING)
				continue;
			int64_t remaining = deadlines[i] - now;
			if (remaining <= 0) {
				results[i] = -ETIMEDOUT;
				inflight--;
				done++;
			} else if (remaining < wait_ms) {
				wait_ms = (int)remaining;
			}
		}
		while (first < next && results[first] != SA_PENDING)
			first++;
		if (!inflight)
			continue;
		int got = drain_acks(t, wait_ms, base, next, results);
		if (got < 0)
			goto fail;
		done += (size_t)got;
		inflight -= (size_t)got;
	}
	int failed = 0;
	for (size_t i = 0; i < n; i++)
		failed += results[i] != 0;
	free(deadlines);
	return failed;
fail:
	free(deadlines);
	return -1;
}

int sa_install_sync(struct transport *t, const struct sa_spec *sas, size_t n,
		    int timeout_ms, int *results)
{
	return run(t, sas, n, 1, timeout_ms, results, xfrm_build_newsa);
}

int sa_install_async(struct transport *t, const struct sa_spec *sas, size_t n,
		     unsigned window, int timeout_ms, int *results)
{
	return run(t, sas, n, window, timeout_ms, results, xfrm_build_newsa);
}

int sa_delete_async(struct transport *t, const struct sa_spec *sas, size_t n,
		    unsigned window, int timeout_ms, int *results)
{
	return run(t, sas, n, window, timeout_ms, results, xfrm_build_delsa);
}
