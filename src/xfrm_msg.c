/* SPDX-License-Identifier: MIT */
#include "xfrm_msg.h"

#include <string.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

#define AEAD_NAME "rfc4106(gcm(aes))"
#define AEAD_ICV_BITS 128

static struct nlattr *put_attr(struct nlmsghdr *nh, size_t cap, uint16_t type,
			       const void *data, size_t len)
{
	size_t off = NLMSG_ALIGN(nh->nlmsg_len);
	size_t alen = NLA_HDRLEN + len;

	if (off + NLA_ALIGN(alen) > cap)
		return NULL;
	struct nlattr *a = (struct nlattr *)((char *)nh + off);
	a->nla_type = type;
	a->nla_len = (uint16_t)alen;
	memcpy((char *)a + NLA_HDRLEN, data, len);
	nh->nlmsg_len = (uint32_t)(off + NLA_ALIGN(alen));
	return a;
}

size_t xfrm_build_newsa(void *buf, size_t cap, const struct sa_spec *sa,
			uint32_t seq)
{
	size_t base = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

	if (cap < base)
		return 0;
	memset(buf, 0, base);

	struct nlmsghdr *nh = buf;
	nh->nlmsg_len = (uint32_t)base;
	nh->nlmsg_type = XFRM_MSG_NEWSA;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nh->nlmsg_seq = seq;

	struct xfrm_usersa_info *info = NLMSG_DATA(nh);
	info->family = AF_INET;
	info->saddr.a4 = sa->src.s_addr;
	info->id.daddr.a4 = sa->dst.s_addr;
	info->id.spi = htonl(sa->spi);
	info->id.proto = IPPROTO_ESP;
	info->mode = XFRM_MODE_TRANSPORT; /* 3GPP TS 33.203 uses transport mode */
	info->reqid = sa->reqid;
	info->replay_window = 32;
	info->lft.soft_byte_limit = XFRM_INF;
	info->lft.hard_byte_limit = XFRM_INF;
	info->lft.soft_packet_limit = XFRM_INF;
	info->lft.hard_packet_limit = XFRM_INF;

	union {
		struct xfrm_algo_aead alg;
		char raw[sizeof(struct xfrm_algo_aead) + sizeof(sa->key)];
	} aead;
	memset(&aead, 0, sizeof(aead));
	strncpy(aead.alg.alg_name, AEAD_NAME, sizeof(aead.alg.alg_name) - 1);
	aead.alg.alg_key_len = sizeof(sa->key) * 8;
	aead.alg.alg_icv_len = AEAD_ICV_BITS;
	memcpy(aead.raw + sizeof(struct xfrm_algo_aead), sa->key, sizeof(sa->key));

	if (!put_attr(nh, cap, XFRMA_ALG_AEAD, aead.raw, sizeof(aead.raw)))
		return 0;
	return nh->nlmsg_len;
}

size_t xfrm_build_delsa(void *buf, size_t cap, const struct sa_spec *sa,
			uint32_t seq)
{
	size_t len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));

	if (cap < len)
		return 0;
	memset(buf, 0, len);

	struct nlmsghdr *nh = buf;
	nh->nlmsg_len = (uint32_t)len;
	nh->nlmsg_type = XFRM_MSG_DELSA;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nh->nlmsg_seq = seq;

	struct xfrm_usersa_id *id = NLMSG_DATA(nh);
	id->daddr.a4 = sa->dst.s_addr;
	id->spi = htonl(sa->spi);
	id->family = AF_INET;
	id->proto = IPPROTO_ESP;
	return len;
}

int xfrm_parse_ack(const void *buf, size_t len, uint32_t *seq, int *err)
{
	const struct nlmsghdr *nh = buf;

	if (len < NLMSG_HDRLEN || nh->nlmsg_len < NLMSG_HDRLEN ||
	    nh->nlmsg_len > len)
		return -1;
	if (nh->nlmsg_type != NLMSG_ERROR)
		return 0;
	if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
		return -1;

	const struct nlmsgerr *e = NLMSG_DATA(nh);
	*seq = nh->nlmsg_seq;
	*err = e->error;
	return 1;
}
