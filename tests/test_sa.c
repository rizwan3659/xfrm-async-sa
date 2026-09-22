/* SPDX-License-Identifier: MIT */
#include "../src/sa_mgr.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
	__FILE__, __LINE__, #c); fails++; } } while (0)

static void sa(struct sa_spec *s, uint32_t spi)
{
	memset(s, 0, sizeof(*s));
	inet_pton(AF_INET, "192.0.2.1", &s->src);
	inet_pton(AF_INET, "198.18.0.7", &s->dst);
	s->spi = spi;
	s->reqid = 7;
}

static void test_newsa_encoding(void)
{
	char buf[XFRM_MSG_BUF];
	struct sa_spec s;
	sa(&s, 0xABCD);

	size_t len = xfrm_build_newsa(buf, sizeof(buf), &s, 42);
	CHECK(len > NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)));

	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	CHECK(nh->nlmsg_len == len);
	CHECK(nh->nlmsg_type == XFRM_MSG_NEWSA);
	CHECK(nh->nlmsg_flags == (NLM_F_REQUEST | NLM_F_ACK));
	CHECK(nh->nlmsg_seq == 42);

	struct xfrm_usersa_info *i = NLMSG_DATA(nh);
	CHECK(i->id.spi == htonl(0xABCD));
	CHECK(i->id.proto == IPPROTO_ESP);
	CHECK(i->mode == XFRM_MODE_TRANSPORT);
	CHECK(i->family == AF_INET);

	struct nlattr *a = (struct nlattr *)((char *)nh +
		NLMSG_ALIGN(NLMSG_LENGTH(sizeof(*i))));
	CHECK(a->nla_type == XFRMA_ALG_AEAD);
	struct xfrm_algo_aead *alg = (struct xfrm_algo_aead *)((char *)a + NLA_HDRLEN);
	CHECK(strcmp(alg->alg_name, "rfc4106(gcm(aes))") == 0);
	CHECK(alg->alg_key_len == 160);
	CHECK(alg->alg_icv_len == 128);

	CHECK(xfrm_build_newsa(buf, 16, &s, 1) == 0); /* too small */
}

static void test_ack_parsing(void)
{
	struct {
		struct nlmsghdr h;
		struct nlmsgerr e;
	} ack = { 0 };
	uint32_t seq;
	int err;

	ack.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
	ack.h.nlmsg_type = NLMSG_ERROR;
	ack.h.nlmsg_seq = 9;
	ack.e.error = -EEXIST;
	CHECK(xfrm_parse_ack(&ack, sizeof(ack), &seq, &err) == 1);
	CHECK(seq == 9 && err == -EEXIST);

	CHECK(xfrm_parse_ack(&ack, 8, &seq, &err) == -1);        /* truncated */
	ack.h.nlmsg_len = 4096;
	CHECK(xfrm_parse_ack(&ack, sizeof(ack), &seq, &err) == -1); /* lies about length */
	ack.h.nlmsg_len = NLMSG_HDRLEN;
	CHECK(xfrm_parse_ack(&ack, sizeof(ack), &seq, &err) == -1); /* no body */
	ack.h.nlmsg_type = XFRM_MSG_NEWSA;
	CHECK(xfrm_parse_ack(&ack, sizeof(ack), &seq, &err) == 0); /* not an ack */
}

static void test_sync_and_async_agree(void)
{
	enum { N = 500 };
	struct sa_spec s[N];
	int r1[N], r2[N];
	for (int i = 0; i < N; i++)
		sa(&s[i], 0x100 + i);

	struct transport *t = transport_mock_open(0);
	CHECK(sa_install_sync(t, s, N, 1000, r1) == 0);
	CHECK(transport_mock_installed(t) == N);
	t->close(t);

	t = transport_mock_open(0);
	CHECK(sa_install_async(t, s, N, 32, 1000, r2) == 0);
	CHECK(transport_mock_installed(t) == N);
	CHECK(memcmp(r1, r2, sizeof(r1)) == 0);

	/* Installing again must fail per SA with EEXIST, not abort the batch. */
	CHECK(sa_install_async(t, s, N, 32, 1000, r2) == N);
	for (int i = 0; i < N; i++)
		CHECK(r2[i] == -EEXIST);

	CHECK(sa_delete_async(t, s, N, 64, 1000, r2) == 0);
	CHECK(transport_mock_installed(t) == 0);
	t->close(t);
}

static void test_partial_failure_is_per_sa(void)
{
	struct sa_spec s[4];
	int r[4];
	sa(&s[0], 1);
	sa(&s[1], 2);
	sa(&s[2], 1); /* duplicate of s[0] */
	sa(&s[3], 3);

	struct transport *t = transport_mock_open(0);
	CHECK(sa_install_async(t, s, 4, 4, 1000, r) == 1);
	CHECK(r[0] == 0 && r[1] == 0 && r[2] == -EEXIST && r[3] == 0);
	t->close(t);
}

int main(void)
{
	test_newsa_encoding();
	test_ack_parsing();
	test_sync_and_async_agree();
	test_partial_failure_is_per_sa();
	if (fails) {
		fprintf(stderr, "%d check(s) failed\n", fails);
		return 1;
	}
	printf("all tests passed\n");
	return 0;
}
