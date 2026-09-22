/* SPDX-License-Identifier: MIT */
#include "sa_mgr.h"

#include <errno.h>
#include <linux/netlink.h>

#define RX_BUF 8192
#define SEQ_BASE 0x10000u

typedef size_t (*build_fn)(void *, size_t, const struct sa_spec *, uint32_t);

/* Reads one datagram (it may hold several netlink messages) and records
 * every ack in it. Returns the number of acks consumed, 0 on timeout,
 * -1 on transport error. Acks for unknown or duplicate seqs are ignored. */
static int drain_acks(struct transport *t, int timeout_ms, size_t n,
		      int *results)
{
	char buf[RX_BUF] __attribute__((aligned(NLMSG_ALIGNTO)));
	ssize_t len = t->recv(t, buf, sizeof(buf), timeout_ms);

	if (len <= 0)
		return (int)len;

	int got = 0;
	size_t left = (size_t)len;
	for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, left);
	     nh = NLMSG_NEXT(nh, left)) {
		uint32_t seq;
		int err;
		if (xfrm_parse_ack(nh, nh->nlmsg_len, &seq, &err) != 1)
			continue;
		if (seq < SEQ_BASE || seq - SEQ_BASE >= n)
			continue;
		int *slot = &results[seq - SEQ_BASE];
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
	char req[XFRM_MSG_BUF] __attribute__((aligned(NLMSG_ALIGNTO)));
	size_t next = 0, done = 0, inflight = 0;

	if (window == 0)
		window = 1;
	for (size_t i = 0; i < n; i++)
		results[i] = SA_PENDING;

	while (done < n) {
		while (inflight < window && next < n) {
			size_t len = build(req, sizeof(req), &sas[next],
					   SEQ_BASE + (uint32_t)next);
			if (len == 0 || t->send(t, req, len) < 0)
				return -1;
			next++;
			inflight++;
		}
		int got = drain_acks(t, timeout_ms, n, results);
		if (got < 0)
			return -1;
		if (got == 0) { /* nothing within the deadline: give up on the rest */
			for (size_t i = 0; i < next; i++)
				if (results[i] == SA_PENDING)
					results[i] = -ETIMEDOUT;
			done = next;
			inflight = 0;
			if (next < n)
				continue;
			break;
		}
		done += (size_t)got;
		inflight -= (size_t)got;
	}

	int failed = 0;
	for (size_t i = 0; i < n; i++)
		failed += results[i] != 0;
	return failed;
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
