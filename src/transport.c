/* SPDX-License-Identifier: MIT */
#include "transport.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

static int64_t monotonic_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static ssize_t recv_timeout(struct transport *t, void *buf, size_t cap,
			    int timeout_ms)
{
	struct pollfd p = { .fd = t->fd, .events = POLLIN };
	int64_t deadline = monotonic_ms() + timeout_ms;
	for (;;) {
		int64_t left = deadline - monotonic_ms();
		int r = poll(&p, 1, left > 0 ? (int)left : 0);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return r;
		struct iovec iov = { .iov_base = buf, .iov_len = cap };
		struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
		ssize_t n = recvmsg(t->fd, &msg, MSG_DONTWAIT);
		if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
			if (monotonic_ms() >= deadline)
				return 0;
			continue;
		}
		if (n == 0 || (msg.msg_flags & MSG_TRUNC)) {
			errno = n == 0 ? ECONNRESET : EMSGSIZE;
			return -1;
		}
		return n;
	}
}

static int send_all(struct transport *t, const void *buf, size_t len)
{
	for (;;) {
		ssize_t n = send(t->fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR)
			continue;
		return n == (ssize_t)len ? 0 : -1;
	}
}

/* ---- real kernel ---- */

static void nl_close(struct transport *t)
{
	close(t->fd);
	free(t);
}

struct transport *transport_netlink_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		return NULL;

	struct sockaddr_nl local = { .nl_family = AF_NETLINK };
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0 ||
	    connect(fd, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
		close(fd);
		return NULL;
	}

	struct transport *t = calloc(1, sizeof(*t));
	if (!t) {
		close(fd);
		return NULL;
	}
	t->fd = fd;
	t->send = send_all;
	t->recv = recv_timeout;
	t->close = nl_close;
	return t;
}

/* ---- mock kernel ---- */

#define MOCK_SLOTS 65536 /* open-addressed set of installed (daddr, spi) */

struct mock_slot {
	uint64_t key;
	unsigned char state; /* 0 empty, 1 occupied, 2 deleted */
};

struct mock {
	int kfd;
	unsigned service_us;
	pthread_t thr;
	unsigned long installed;
	struct mock_slot *keys;
};

static uint64_t sa_key(uint32_t daddr, uint32_t spi)
{
	return ((uint64_t)daddr << 32) | spi;
}

/* Returns 1 if newly added, 0 if already present, -1 if full. */
static int set_op(struct mock *m, uint64_t k, int del)
{
	uint64_t hash = k ^ (k >> 33);
	hash *= 0xff51afd7ed558ccdULL;
	hash ^= hash >> 33;
	size_t i = (size_t)hash % MOCK_SLOTS;
	size_t available = MOCK_SLOTS;
	for (size_t n = 0; n < MOCK_SLOTS; n++, i = (i + 1) % MOCK_SLOTS) {
		struct mock_slot *slot = &m->keys[i];
		if (slot->state == 1 && slot->key == k) {
			if (del)
				slot->state = 2;
			return 0;
		}
		if (slot->state != 1 && available == MOCK_SLOTS)
			available = i;
		if (slot->state == 0)
			break;
	}
	if (del || available == MOCK_SLOTS)
		return -1;
	m->keys[available].key = k;
	m->keys[available].state = 1;
	return 1;
}

static void spin_us(unsigned us)
{
	struct timespec t0, t;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		clock_gettime(CLOCK_MONOTONIC, &t);
	} while ((t.tv_sec - t0.tv_sec) * 1000000L +
		 (t.tv_nsec - t0.tv_nsec) / 1000 < (long)us);
}

static void *mock_kernel(void *arg)
{
	struct mock *m = arg;
	char req[1024] __attribute__((aligned(8)));

	for (;;) {
		ssize_t n = recv(m->kfd, req, sizeof(req), 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		struct nlmsghdr *nh = (struct nlmsghdr *)req;
		if ((size_t)n < NLMSG_HDRLEN || nh->nlmsg_len > (size_t)n)
			continue;

		int err = -EINVAL;
		if (nh->nlmsg_type == XFRM_MSG_NEWSA &&
		    nh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct xfrm_usersa_info))) {
			struct xfrm_usersa_info *i = NLMSG_DATA(nh);
			int r = set_op(m, sa_key(i->id.daddr.a4, i->id.spi), 0);
			err = r == 1 ? 0 : r == 0 ? -EEXIST : -ENOSPC;
			if (!err)
				__atomic_add_fetch(&m->installed, 1, __ATOMIC_RELAXED);
		} else if (nh->nlmsg_type == XFRM_MSG_DELSA &&
			   nh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct xfrm_usersa_id))) {
			struct xfrm_usersa_id *id = NLMSG_DATA(nh);
			err = set_op(m, sa_key(id->daddr.a4, id->spi), 1) == 0 ? 0 : -ESRCH;
			if (!err)
				__atomic_sub_fetch(&m->installed, 1, __ATOMIC_RELAXED);
		}
		if (m->service_us)
			spin_us(m->service_us);

		struct {
			struct nlmsghdr h;
			struct nlmsgerr e;
		} ack;
		memset(&ack, 0, sizeof(ack));
		ack.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
		ack.h.nlmsg_type = NLMSG_ERROR;
		ack.h.nlmsg_seq = nh->nlmsg_seq;
		ack.e.error = err;
		memcpy(&ack.e.msg, nh, sizeof(*nh));
		if (send(m->kfd, &ack, ack.h.nlmsg_len, MSG_NOSIGNAL) < 0)
			break;
	}
	return NULL;
}

static void mock_close(struct transport *t)
{
	struct mock *m = t->priv;
	shutdown(t->fd, SHUT_RDWR);
	close(t->fd);
	pthread_join(m->thr, NULL);
	close(m->kfd);
	free(m->keys);
	free(m);
	free(t);
}

struct transport *transport_mock_open(unsigned service_us)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0)
		return NULL;

	/* Large buffers so an async sender can have a full window in flight. */
	int sz = 1 << 20;
	setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));

	struct transport *t = calloc(1, sizeof(*t));
	struct mock *m = calloc(1, sizeof(*m));
	struct mock_slot *keys = calloc(MOCK_SLOTS, sizeof(*keys));
	if (!t || !m || !keys)
		goto fail;

	m->kfd = sv[1];
	m->service_us = service_us;
	m->keys = keys;
	t->fd = sv[0];
	t->send = send_all;
	t->recv = recv_timeout;
	t->close = mock_close;
	t->priv = m;
	int err = pthread_create(&m->thr, NULL, mock_kernel, m);
	if (err) {
		errno = err;
		goto fail;
	}
	return t;
fail:
	free(keys);
	free(m);
	free(t);
	close(sv[0]);
	close(sv[1]);
	return NULL;
}

unsigned long transport_mock_installed(struct transport *t)
{
	return __atomic_load_n(&((struct mock *)t->priv)->installed, __ATOMIC_RELAXED);
}
