// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// 3-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mpscan_internal.h"
#include "mpscan.h"
#include "mpscan.skel.h"
#include "trace_helpers.h"

static struct env {
	time_t interval;
	pid_t pid;
	int times;
	bool timestamp;
	bool per_process;
	bool per_thread;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
	.pid = -1,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "mpscan 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"Summarize migrate pages time per task as a histogram.\n"
"\n"
"USAGE: mpscan [-h] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    mpscan              # summarize migrate pages time as a histogram"
"    mpscan 1 10         # print 1 second summaries, 10 times"
"    mpscan -mT 1        # 1s summaries, milliseconds, and timestamps"
"    mpscan -P           # show each PID separately"
"    mpscan -p 185       # trace PID 185 only";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID" },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
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
	case 'h':
		argp_usage(state);
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'P':
		env.per_process = true;
		break;
	case 'L':
		env.per_thread = true;
		break;
	case 'T':
		env.timestamp = true;
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

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static int get_pid_max(void)
{
	int pid_max;
	FILE *f;

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d\n", &pid_max) != 1)
		pid_max = -1;
	fclose(f);
	return pid_max;
}

static void sig_handler(int sig)
{
	exiting = true;
}


static int print_log2_hists(int fd)
{
	static struct { int code; const char *name; } modes[] = {
		{ 0, "ASYNC" },
		{ 1, "SYNC_LIGHT" },
		{ 2, "SYNC" },
		{ 3, "SYNC_NO_COPY" },
	};
	static struct { int code; const char *name; } reasons[] = {
		{ 0, "compaction" },
		{ 1, "memory_failure" },
		{ 2, "memory_hotplug" },
		{ 3, "syscall_or_cpuset" },
		{ 4, "mempolicy_mbind" },
		{ 5, "numa_misplaced" },
		{ 6, "contig_range" },
	};
	char *units = env.milliseconds ? "msecs" : "usecs";
	struct piddata lookup_key = {}, next_key;
	struct hist hist;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\t", next_key.pid, hist.comm);
		if (env.per_thread)
			printf("\ntid = %d %s\t", next_key.pid, hist.comm);

		printf("Mode: %s    Reason: %s    Total times: %lld\n",
			modes[next_key.mode].name,
			reasons[next_key.reason].name,
			hist.count);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	memset(&lookup_key, 0, sizeof(lookup_key));

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct mpscan_bpf *obj;
	int pid_max, fd, err;
	struct tm *tm;
	char ts[32];
	time_t t;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = mpscan_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF ojbect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_per_process = env.per_process;
	obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_tgid = env.pid;

	pid_max = get_pid_max();
	if (pid_max < 0) {
		fprintf(stderr, "failed to get pid_max\n");
		return 1;
	}

	bpf_map__resize(obj->maps.start, pid_max);

	err = mpscan_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = mpscan_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	fd = bpf_map__fd(obj->maps.hists);

	signal(SIGINT, sig_handler);

	printf("Tracing migrate pages time... Hit Ctrl-C to end.\n");

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

		err = print_log2_hists(fd);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	mpscan_bpf__destroy(obj);

	return err != 0;
}
