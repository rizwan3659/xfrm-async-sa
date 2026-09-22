/* SPDX-License-Identifier: MIT */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Where netlink requests go. The real transport talks to the kernel over
 * NETLINK_XFRM (needs CAP_NET_ADMIN); the mock one answers from a thread so
 * the SA manager can be tested and benchmarked without privileges. */
struct transport {
	int fd;
	int (*send)(struct transport *t, const void *buf, size_t len);
	/* Returns bytes read, 0 on timeout, -1 on error. */
	ssize_t (*recv)(struct transport *t, void *buf, size_t cap, int timeout_ms);
	void (*close)(struct transport *t);
	void *priv;
	uint64_t seq; /* last reserved sequence; zero initially, single caller */
};

struct transport *transport_netlink_open(void);

/* service_us: simulated kernel processing time per request. Requests are
 * handled one at a time, in order, like the kernel's XFRM netlink handler. */
struct transport *transport_mock_open(unsigned service_us);
unsigned long transport_mock_installed(struct transport *t);

#endif
