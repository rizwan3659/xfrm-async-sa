/* SPDX-License-Identifier: MIT */
/* xfrm-bench: install N ESP SAs synchronously and asynchronously, then
 * report throughput for each. Uses the mock kernel unless --real is given. */
#include "sa_mgr.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static void make_sas(struct sa_spec *sas, size_t n, uint32_t spi_base)
{
	for (size_t i = 0; i < n; i++) {
		memset(&sas[i], 0, sizeof(sas[i]));
		inet_pton(AF_INET, "192.0.2.1", &sas[i].src);  /* P-CSCF */
		sas[i].dst.s_addr = htonl(0xC6120000u + (uint32_t)(i % 65000)); /* 198.18.0.0/15 UEs */
		sas[i].spi = spi_base + (uint32_t)i;
		sas[i].reqid = (uint32_t)i + 1;
		for (size_t k = 0; k < sizeof(sas[i].key); k++)
			sas[i].key[k] = (uint8_t)(i * 31 + k);
	}
}

static struct transport *open_t(int real, unsigned service_us)
{
	return real ? transport_netlink_open() : transport_mock_open(service_us);
}

static int bench(const char *label, int real, unsigned service_us,
		 const struct sa_spec *sas, size_t n, unsigned window, int *res)
{
	struct transport *t = open_t(real, service_us);
	if (!t) {
		perror("transport");
		return -1;
	}
	for (size_t i = 0; i < n; i++)
		res[i] = SA_PENDING;
	double t0 = now_s();
	int failed = window <= 1 ? sa_install_sync(t, sas, n, 1000, res)
				 : sa_install_async(t, sas, n, window, 1000, res);
	double dt = now_s() - t0;
	if (failed < 0)
		perror("SA install");
	size_t installed = 0;
	for (size_t i = 0; i < n; i++)
		installed += res[i] == 0;
	printf("%-8s window=%-4u %6zu SAs  %8.3f s  %10.0f SA/s  failed=%d\n",
	       label, window <= 1 ? 1 : window, n, dt, (double)installed / dt, failed);
	for (size_t i = 0; failed > 0 && i < n; i++)
		if (res[i] != 0) {
			printf("         first failure: SA %zu: %s\n", i, strerror(-res[i]));
			break;
		}
	if (real) {
		/* EEXIST belongs to someone else. A timeout is unknown, not proof
		 * of ownership. Delete only requests whose success we observed. */
		struct sa_spec *owned = calloc(n, sizeof(*owned));
		if (!owned) {
			perror("cleanup allocation");
			failed = -1;
		} else {
			size_t count = 0;
			for (size_t i = 0; i < n; i++)
				if (res[i] == 0)
					owned[count++] = sas[i];
			int cleanup = sa_delete_async(t, owned, count, 64, 1000, res);
			if (cleanup != 0) {
				fprintf(stderr, "cleanup incomplete: %d; inspect the test namespace\n", cleanup);
				failed = -1;
			}
			free(owned);
		}
		if (failed != 0)
			fprintf(stderr, "failed/unknown installs may remain; discard the test namespace\n");
	}
	t->close(t);
	return failed;
}

static int parse_uint(const char *text, unsigned long max, unsigned long *out)
{
	char *end;
	if (!*text)
		return -1;
	for (const char *p = text; *p; p++)
		if (*p < '0' || *p > '9')
			return -1;
	errno = 0;
	unsigned long value = strtoul(text, &end, 10);
	if (errno || *end || value > max)
		return -1;
	*out = value;
	return 0;
}

int main(int argc, char **argv)
{
	size_t n = 20000;
	unsigned window = 64, service_us = 0;
	int real = 0, c;

	static const struct option opts[] = {
		{ "count", required_argument, 0, 'n' },
		{ "window", required_argument, 0, 'w' },
		{ "service-us", required_argument, 0, 's' },
		{ "real", no_argument, 0, 'r' },
		{ 0, 0, 0, 0 },
	};
	while ((c = getopt_long(argc, argv, "n:w:s:r", opts, NULL)) != -1) {
		unsigned long value = 0;
		if ((c == 'n' || c == 'w' || c == 's') &&
		    parse_uint(optarg, UINT_MAX, &value) < 0) {
			fprintf(stderr, "invalid numeric option: %s\n", optarg);
			return 2;
		}
		switch (c) {
		case 'n': n = value; break;
		case 'w': window = (unsigned)value; break;
		case 's': service_us = (unsigned)value; break;
		case 'r': real = 1; break;
		default:
			fprintf(stderr, "usage: %s [--count N] [--window W] "
				"[--service-us US] [--real]\n", argv[0]);
			return 2;
		}
	}
	if (optind != argc || n == 0 || n > 60000 || window == 0 ||
	    window > 60000 || service_us > 1000000) {
		fprintf(stderr, "count/window must be 1..60000; service-us 0..1000000; no extra arguments\n");
		return 2;
	}

	struct sa_spec *sas = calloc(n, sizeof(*sas));
	int *res = calloc(n, sizeof(*res));
	if (!sas || !res) {
		free(sas);
		free(res);
		return 1;
	}

	printf("transport: %s, simulated kernel service time: %u us\n",
	       real ? "NETLINK_XFRM (real kernel)" : "mock kernel", real ? 0 : service_us);
	make_sas(sas, n, 0x1000);
	int f1 = bench("sync", real, service_us, sas, n, 1, res);
	make_sas(sas, n, 0x1000); /* Previous real run must have completed cleanup. */
	int f2 = (real && f1) ? 1 : bench("async", real, service_us, sas, n, window, res);

	free(sas);
	free(res);
	return (f1 || f2) ? 1 : 0;
}
