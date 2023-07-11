// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Wenbo Zhang
//
// Based on https://sourceware.org/systemtap/examples/network/sk_stream_wait_memory.stp.
// 11-Jul-2023   Wenbo Zhang   Created this.
#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "skwm.h"
#include "skwm.skel.h"
#include "compat.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	pid_t pid;
	pid_t tid;
	bool verbose;
	bool timestamp;
} env = {};

static volatile sig_atomic_t exiting = 0;
static int column_width = 15;

const char *argp_program_version = "skwm 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
"\nskwm: Trace sk waiting for send buffer memory\n"
"\n"
"EXAMPLES:\n"
"    skwm\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace"},
	{ "tid", 't', "TID", 0, "Thread TID to trace"},
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		env.timestamp = true;
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char saddr[48], daddr[48];
	struct tm *tm;
	char ts[32];
	time_t t;

	if (env.timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}
	inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

	printf("%-7d %-7d %-16s %-*s %-5d %-*s %-5d %-.2f\n",
		e->pid, e->tid, e->comm, column_width, saddr, e->sport, column_width, daddr,
		e->dport, e->delta_us / 1000.0);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct skwm_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = skwm_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		fprintf(stderr, "failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (vmlinux_btf_exists()) {
		bpf_program__set_autoload(obj->progs.sk_stream_wait_memory_k, false);
		bpf_program__set_autoload(obj->progs.sk_stream_wait_memory_kret, false);
	} else {
		bpf_program__set_autoload(obj->progs.sk_stream_wait_memory, false);
		bpf_program__set_autoload(obj->progs.sk_stream_wait_memory_fexit, false);
	}

	err = skwm_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = skwm_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		fprintf(stderr, "failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-7s %-16s %-*s %-5s %-*s %-5s %-s\n",
		"PID", "TID", "COMM", column_width, "LADDR", "LPORT", column_width, "RADDR", "RPORT", "MS");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	skwm_bpf__destroy(obj);

	return err != 0;
}
