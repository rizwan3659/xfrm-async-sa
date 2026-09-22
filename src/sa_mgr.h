/* SPDX-License-Identifier: MIT */
#ifndef SA_MGR_H
#define SA_MGR_H

#include "transport.h"
#include "xfrm_msg.h"

#define SA_PENDING 1 /* result value while no ack has arrived */

/* results[i] receives 0 or the kernel's negative errno for sas[i], or
 * -ETIMEDOUT if no ack arrived in time. Return value: number of SAs that
 * failed, or -1 if the transport itself failed. */

/* Baseline: send one request, block for its ack, then the next. */
int sa_install_sync(struct transport *t, const struct sa_spec *sas, size_t n,
		    int timeout_ms, int *results);

/* Pipelined: keep up to `window` requests in flight and match acks back to
 * requests by netlink sequence number, in whatever order they arrive. */
int sa_install_async(struct transport *t, const struct sa_spec *sas, size_t n,
		     unsigned window, int timeout_ms, int *results);

int sa_delete_async(struct transport *t, const struct sa_spec *sas, size_t n,
		    unsigned window, int timeout_ms, int *results);

#endif
