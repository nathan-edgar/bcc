// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cpuaw.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

struct data_t {
	u64 nr_failed;
	u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct data_t);
} start SEC(".maps");

static struct hist zero;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

SEC("kprobe/can_migrate_task")
int BPF_KPROBE(can_migrate_task, struct task_struct *p)
{
	u32 pid = BPF_CORE_READ(p, pid);
	struct data_t data;

	data.nr_failed = BPF_CORE_READ(p, se.statistics.nr_failed_migrations_hot);
	data.ts = 0;

	bpf_map_update_elem(&start, &pid, &data, 0);
	return 0;
}

SEC("kretprobe/can_migrate_task")
int BPF_KRETPROBE(can_migrate_task_ret, int ret)
{
	struct task_struct *p = (void*)bpf_get_current_task();
	u32 pid = BPF_CORE_READ(p, pid);
	struct data_t *data;
	u64 cur_failed_nr;

	data = bpf_map_lookup_elem(&start, &pid);
	if (!data)
		return 0;

	cur_failed_nr = BPF_CORE_READ(p, se.statistics.nr_failed_migrations_hot);
	if (cur_failed_nr - data->nr_failed != 1) {
		bpf_printk("not hot\n");
		bpf_map_delete_elem(&start, &pid);
	}
	else {
		bpf_printk("not\n");
		data->ts = bpf_ktime_get_ns();
	}


	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
	struct task_struct *next)
{
	struct data_t *data;
	u32 pid = next->pid;
	struct hist *hist;
	s64 delta;
	u64 slot;

	data = bpf_map_lookup_elem(&start, &pid);
	if (!data)
		return 0;

	if (!data->ts)
		return 0;
	delta = bpf_ktime_get_ns() - data->ts;
	if (delta < 0)
		goto cleanup;

	hist = bpf_map_lookup_or_try_init(&hists, &pid, &zero);
	if (!hist)
		goto cleanup;

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	 __sync_fetch_and_add(&hist->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
