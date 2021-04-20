// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Wenbo Zhang
//
// Based on profile(8) from BCC by Brendan Gregg.
// 19-Mar-2021   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "profile.h"
#include "profile.skel.h"
#include "trace_helpers.h"

static struct env {
	pid_t pid;
	pid_t tid;
	bool user_stack_only;
	bool kernel_stack_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	int freq;
	int period;
	bool delimited;
	bool annotations;
	bool include_idle;
	bool folded;
	int cpu;
	char *cgroupmap;
	char *mntnsmap;
	int duration;
	bool verbose;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 16384,
	.perf_max_stack_depth = 127,
	.cpu = -1,
	.duration = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "profile 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Profile CPU stack traces at a timed interval\n"
"\n"
"USAGE: profile [--help] [-p PID | -u | -k] "
"[--perf-max-stack-depth] [--stack-storage-size] "
"[duration]\n"
"EXAMPLES:\n"
"    profile             # profile stack traces at 49 Hertz until Ctrl-C\n"
"    profile -F 99       # profile stack traces at 99 Hertz\n"
"    profile -c 1000000  # profile stack traces every 1 in a million events\n"
"    profile 5           # profile at 49 Hertz for 5 seconds only\n"
"    profile -f 5        # output in folded format for flame graphs\n"
"    profile -p 185      # only profile process with PID 185\n"
"    profile -t 185      # only profile thread with TID 185\n"
"    profile -U          # only show user space stacks (no kernel)\n"
"    profile -K          # only show kernel space stacks (no user)\n"
"    profile --cgroupmap mappath  # only trace cgroups in this BPF map\n"
"    profile --mntnsmap mappath   # only trace mount namespaces in the map\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_CGROUPMAP			3 /* --cgroupmap */
#define OPT_MNTNSMAP			4 /* --mntnsmap */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "tid", 'L', "TID", 0, "Trace this TID only" },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)" },
	{ "kernel-stacks-only", 'U', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)" },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz" },
	{ "count", 'c', "COUNT", 0, "sample period, number of events" },
	{ "delimited", 'd', NULL, 0,
	  "insert delimiter between kernel/user stacks" },
	{ "annotations", 'a', NULL, 0, "add _[k] annotations to kernel frames" },
	{ "include-idle", 'I', NULL, 0, "include CPU idle stacks" },
	{ "folded", 'f', NULL, 0,
	  "output folded format, one line per stack (for flame graphs)" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user "
	  "frames (deault 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and "
	  "displayed (default 1024)" },
	{ "cpu", 'C', "CPU", 0, "cpu number to run profile on" },
	{ "cgroupmap", OPT_CGROUPMAP, "CGROUPMAP", 0,
	  "trace cgroups in this BPF map only" },
	{ "mntnsmap", OPT_MNTNSMAP, "MNTNSMAP", 0,
	  "trace mount namespaces in this BPF map only" },
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
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'L':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno || env.tid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'U':
		env.user_stack_only = true;
		break;
	case 'K':
		env.kernel_stack_only = true;
		break;
	case 'F':
		errno = 0;
		env.freq = strtol(arg, NULL, 10);
		if (errno || env.freq <= 0) {
			fprintf(stderr, "invalid frequency: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		errno = 0;
		env.period = strtol(arg, NULL, 10);
		if (errno || env.period <= 0) {
			fprintf(stderr, "invalid count: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		env.delimited = true;
		break;
	case 'a':
		env.annotations = true;
		break;
	case 'I':
		env.include_idle = true;
		break;
	case 'f':
		env.folded = true;
		break;
	case 'C':
		errno = 0;
		env.cpu = strtol(arg, NULL, 10);
		if (errno || env.cpu <= 0) {
			fprintf(stderr, "invalid cpu: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_CGROUPMAP:
		env.cgroupmap = arg;
		break;
	case OPT_MNTNSMAP:
		env.mntnsmap = arg;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
			argp_usage(state);
		}
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
}


static void print_map(struct ksyms *ksyms, struct syms_vec *syms_vec,
		      struct profile_bpf *obj)
{
	struct key_t lookup_key = {}, next_key;
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	int err, i, ifd, sfd;
	struct val_t val;
	__u64 *ip;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	ifd = bpf_map__fd(obj->maps.info);
	sfd = bpf_map__fd(obj->maps.stackmap);
	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(ifd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			goto cleanup;
		}
		lookup_key = next_key;
		if (bpf_map_lookup_elem(sfd, &next_key.kern_stack_id, ip) != 0) {
			fprintf(stderr, "failed to get kernel stack\n");
			goto cleanup;
		}
		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			ksym = ksyms__map_addr(ksyms, ip[i]);
			printf("    %s\n", ksym ? ksym->name : "Unknown");
		}
		if (next_key.user_stack_id == -1)
			goto skip_ustack;

		if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
			fprintf(stderr, "failed to get user stack\n");
			goto cleanup;
		}

		syms = syms_vec__get_syms(syms_vec, next_key.tgid);
		if (!syms) {
			fprintf(stderr, "failed to get syms\n");
			goto skip_ustack;
		}
		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			sym = syms__map_addr(syms, ip[i]);
			if (sym)
				printf("    %s\n", sym->name);
			else
				printf("    [unknown]\n");
		}

skip_ustack:
		printf("    %-16s %s (%d)\n", "-", val.comm, next_key.tgid);
		printf("        %lld\n\n", val.cnt);
	}

cleanup:
	free(ip);
}

static int nr_cpus;

static int open_and_attach_perf_event(int period, int freq, int cpu,
				      struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int fd, i;

	if (freq > 0) {
		attr.freq = 1;
		attr.sample_freq = freq;
	} else {
		attr.sample_period = period;
	}

	for (i = cpu >= 0 ? cpu : 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
		if (i == cpu)
			break;
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
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct syms_vec *syms_vec = NULL;
	struct ksyms *ksyms = NULL;
	struct profile_bpf *obj;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if (env.user_stack_only && env.kernel_stack_only) {
		fprintf(stderr, "user_threads_only, kernel_threads_only "
			"cann't be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	obj = profile_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->user_stack_only = env.user_stack_only;
	obj->rodata->kernel_stack_only = env.kernel_stack_only;
	obj->rodata->include_idle = env.include_idle;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(__u64));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = profile_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}
	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	syms_vec = syms_vec__new(0);
	if (!syms_vec) {
		fprintf(stderr, "failed to create syms_vec\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(env.period, env.freq, env.cpu,
					 obj->progs.do_sample, links);
	if (err)
		goto cleanup;

	err = profile_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C (which will
	 * be "handled" with noop by sig_handler).
	 */
	sleep(env.duration);

	print_map(ksyms, syms_vec, obj);

cleanup:
	for (i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);
	profile_bpf__destroy(obj);
	syms_vec__free(syms_vec);
	ksyms__free(ksyms);
	return err != 0;
}
