/* SPDX-License-Identifier: MIT */
#ifndef XFRM_MSG_H
#define XFRM_MSG_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* One unidirectional IPv4 ESP SA. A UE registration needs multiple SAs
 * and policies; this structure does not represent a complete IMS context. */
struct sa_spec {
	struct in_addr src;
	struct in_addr dst;
	uint32_t spi;           /* host order */
	uint32_t reqid;
	uint8_t key[20];        /* AES-128-GCM: 16 byte key + 4 byte salt */
};

#define XFRM_MSG_BUF 512

/* Build an XFRM_MSG_NEWSA request into buf. Returns the message length,
 * or 0 if buf is too small. buf must be aligned to 8 bytes. seq is used to correlate the kernel's ack. */
size_t xfrm_build_newsa(void *buf, size_t cap, const struct sa_spec *sa,
			uint32_t seq);

/* Build an XFRM_MSG_DELSA request. */
size_t xfrm_build_delsa(void *buf, size_t cap, const struct sa_spec *sa,
			uint32_t seq);

/* Parse an NLMSG_ERROR ack. Returns 1 and fills seq/err on success,
 * 0 if the message is not an ack, -1 if it is malformed. err is the
 * kernel's result: 0 on success or a negative errno. */
int xfrm_parse_ack(const void *buf, size_t len, uint32_t *seq, int *err);

#endif
