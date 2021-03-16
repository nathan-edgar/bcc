// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Wenbo Zhang
//
// Based on xfsdist(8) from BCC by Brendan Gregg.
// 9-Feb-2021   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xfsdist.h"
#include "xfsdist.skel.h"
#include "trace_helpers.h"

static struct env {
	bool timestamp;
	bool milliseconds;
	pid_t pid;
	time_t interval;
	int times;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "xfsdist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize XFS operation latency.\n"
"\n"
"Usage: xfsdist [-h] [-T] [-m] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    xfsdist          # show operation latency as a histogram\n"
"    xfsdist -p 181   # trace PID 181 only\n"
"    xfsdist 1 10     # print 1 second summaries, 10 times\n"
"    xfsdist -m 5     # 5s summaries, milliseconds\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Print timestamp" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static char *fop_names[] = {
	[READ_ITER] = "read_iter",
	[WRITE_ITER] = "write_iter",
	[OPEN] = "open",
	[FSYNC] = "fsync",
};

static struct hist zero;

static int print_hists(struct xfsdist_bpf__bss *bss)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	enum xfs_fop_type type;

	for (type = READ_ITER; type < __MAX_FOP_TYPE; type++) {
		struct hist hist = bss->hists[type];

		bss->hists[type] = zero;
		if (!memcmp(&zero, &hist, sizeof(hist)))
			continue;
		printf("operation = '%s'\n", fop_names[type]);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
	}

	return 0;
}

static void xfsdist__choose_progs(struct bpf_object *obj, bool fallback)
{
	const char func_prefix = fallback ? 'k' : 'f';
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, obj) {
		if (bpf_program__name(prog)[0] != func_prefix) {
			bpf_program__set_autoload(prog, false);
		}
	}
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct xfsdist_bpf *skel;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	skel = xfsdist_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skelect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	skel->rodata->targ_ms = env.milliseconds;
	skel->rodata->targ_tgid = env.pid;

	xfsdist__choose_progs(skel->obj, true);

	err = xfsdist_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	err = xfsdist_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing xfs operation latency... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_hists(skel->bss);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	xfsdist_bpf__destroy(skel);

	return err != 0;
}
