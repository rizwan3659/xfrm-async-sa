/* SPDX-License-Identifier: MIT */
#include "../src/sa_mgr.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <time.h>
#include <limits.h>

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
	char buf[XFRM_MSG_BUF] __attribute__((aligned(8)));
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

/* A scripted transport can deliver cases the FIFO mock cannot produce. */
struct scripted {
	struct transport t;
	uint32_t sent[8];
	unsigned sends, receives, mode;
};

static int script_send(struct transport *t, const void *buf, size_t len)
{
	struct scripted *s = t->priv;
	const struct nlmsghdr *nh = buf;
	CHECK(len >= sizeof(*nh));
	if (s->mode == 5 && s->sends == 1 && s->receives == 0) {
		errno = EAGAIN;
		return -1;
	}
	if (s->mode == 7 && s->sends == 1) {
		errno = EIO;
		return -1;
	}
	CHECK(s->sends < 8);
	s->sent[s->sends++] = nh->nlmsg_seq;
	return 0;
}

static size_t write_ack(char *buf, uint32_t seq, int error)
{
	struct { struct nlmsghdr h; struct nlmsgerr e; } ack = {0};
	ack.h.nlmsg_len = NLMSG_LENGTH(sizeof(ack.e));
	ack.h.nlmsg_type = NLMSG_ERROR;
	ack.h.nlmsg_seq = seq;
	ack.e.error = error;
	memcpy(buf, &ack, sizeof(ack));
	return NLMSG_ALIGN(sizeof(ack));
}

static ssize_t script_recv(struct transport *t, void *buf, size_t cap, int timeout_ms)
{
	struct scripted *s = t->priv;
	unsigned step = s->receives++;
	CHECK(cap >= 3 * NLMSG_SPACE(sizeof(struct nlmsgerr)));
	if (s->mode == 1 && step == 0) /* future, unsent sequence */
		return (ssize_t)write_ack(buf, s->sent[0] + 1, -EEXIST);
	if (s->mode == 2) { /* reversed and duplicate ACKs in one datagram */
		size_t n = write_ack(buf, s->sent[1], -EEXIST);
		n += write_ack((char *)buf + n, s->sent[1], -EEXIST);
		n += write_ack((char *)buf + n, s->sent[0], 0);
		return (ssize_t)n;
	}
	if (s->mode == 3 || (s->mode == 4 && step == 0)) {
		struct timespec delay = { .tv_sec = timeout_ms / 1000,
			.tv_nsec = (timeout_ms % 1000) * 1000000L };
		nanosleep(&delay, NULL);
		return 0;
	}
	if (s->mode == 4 && step == 1)
		return (ssize_t)write_ack(buf, s->sent[0], -EEXIST); /* stale batch */
	if (s->mode == 6)
		return (ssize_t)write_ack(buf, UINT32_MAX, 0); /* endless noise */
	return (ssize_t)write_ack(buf, s->sent[s->sends - 1], 0);
}

static void test_ack_correlation_and_timeouts(void)
{
	struct sa_spec specs[2];
	int results[2];
	sa(&specs[0], 100);
	sa(&specs[1], 101);
	for (unsigned mode = 1; mode <= 7; mode++) {
		struct scripted s = { .mode = mode };
		s.t.send = script_send;
		s.t.recv = script_recv;
		s.t.priv = &s;
		unsigned window = mode == 1 ? 1 : 2;
		int ret = sa_install_async(&s.t, specs, 2, window, 30, results);
		if (mode == 3 || mode == 6) {
			CHECK(ret == 2);
			CHECK(results[0] == -ETIMEDOUT && results[1] == -ETIMEDOUT);
		} else if (mode == 4) {
			CHECK(results[0] == -ETIMEDOUT);
			CHECK(sa_install_sync(&s.t, specs, 1, 100, results) == 0);
			CHECK(s.sent[2] != s.sent[0]);
			CHECK(results[0] == 0);
		} else if (mode == 7) {
			CHECK(ret == -1 && errno == EIO);
			CHECK(results[0] == SA_PENDING && results[1] == SA_PENDING);
		} else {
			CHECK(ret == (mode == 2 ? 1 : 0));
			CHECK(results[0] == 0);
			CHECK(results[1] == (mode == 2 ? -EEXIST : 0));
		}
	}
	struct scripted s = {0};
	s.t.send = script_send;
	s.t.recv = script_recv;
	s.t.priv = &s;
	s.t.seq = UINT32_MAX;
	CHECK(sa_install_sync(&s.t, specs, 1, 10, results) == -1);
	CHECK(errno == EOVERFLOW && s.sends == 0);
	CHECK(sa_install_sync(&s.t, specs, 1, 0, results) == -1 && errno == EINVAL);
}

static void test_mock_key_and_reuse(void)
{
	struct transport *t = transport_mock_open(0);
	CHECK(t != NULL);
	if (!t)
		return;
	struct sa_spec specs[2];
	int results[2];
	sa(&specs[0], 1);
	specs[1] = specs[0];
	specs[1].dst.s_addr ^= 0x80000000u;
	CHECK(sa_install_async(t, specs, 2, 2, 1000, results) == 0);
	CHECK(transport_mock_installed(t) == 2);
	CHECK(sa_delete_async(t, specs, 2, 2, 1000, results) == 0);
	/* More unique insert/delete pairs than the table's capacity. */
	enum { N = 1000 };
	struct sa_spec batch[N];
	int r[N];
	for (unsigned round = 0; round < 70; round++) {
		for (unsigned i = 0; i < N; i++)
			sa(&batch[i], 100 + round * N + i);
		CHECK(sa_install_async(t, batch, N, 64, 1000, r) == 0);
		CHECK(sa_delete_async(t, batch, N, 64, 1000, r) == 0);
	}
	CHECK(transport_mock_installed(t) == 0);
	t->close(t);
}

static void test_large_window(void)
{
	enum { N = 5000 };
	struct sa_spec *specs = calloc(N, sizeof(*specs));
	int *results = calloc(N, sizeof(*results));
	struct transport *t = transport_mock_open(0);
	CHECK(specs && results && t);
	if (specs && results && t) {
		for (unsigned i = 0; i < N; i++)
			sa(&specs[i], 1000 + i);
		CHECK(sa_install_async(t, specs, N, N, 5000, results) == 0);
	}
	if (t)
		t->close(t);
	free(specs);
	free(results);
}

static void test_ack_invalid_error_and_alignment(void)
{
	char raw[128];
	uint32_t seq;
	int err;
	size_t len = write_ack(raw + 1, 77, -EINVAL);
	CHECK(xfrm_parse_ack(raw + 1, len, &seq, &err) == 1);
	CHECK(seq == 77 && err == -EINVAL);
	len = write_ack(raw + 1, 77, 1);
	CHECK(xfrm_parse_ack(raw + 1, len, &seq, &err) == -1);
	len = write_ack(raw + 1, 77, INT_MIN);
	CHECK(xfrm_parse_ack(raw + 1, len, &seq, &err) == -1);
}

int main(void)
{
	test_ack_correlation_and_timeouts();
	test_mock_key_and_reuse();
	test_large_window();
	test_ack_invalid_error_and_alignment();
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
