// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "mpscan.h"

const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct piddata);
	__type(value, struct hist);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} hists SEC(".maps");

static struct hist initial_hist;

static __always_inline u64 log2(u32 v)
{
	u32 shift, r;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);

	return r;
}

static __always_inline u64 log2l(u64 v)
{
	u32 hi = v >> 32;

	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

SEC("fentry/migrate_pages")
int BPF_PROG(fentry__migrate_pages, struct list_head *from, new_page_t get_new_page,
		free_page_t put_new_page, unsigned long private,
		enum migrate_mode mode, int reason)
{
	u64 id = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	u32 tgid = id >> 32;
	u32 pid = id;

	if (targ_tgid != -1 && targ_tgid != tgid)
		return 0;

	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("fexit/migrate_pages")
int BPF_PROG(fexit__migrate_pages, struct list_head *from, new_page_t get_new_page,
		free_page_t put_new_page, unsigned long private,
		enum migrate_mode mode, int reason, int ret)
{
	u64 id = bpf_get_current_pid_tgid();
	u64 delta, *tsp, slot, *counterp;;
	u64 ts = bpf_ktime_get_ns();
	struct piddata piddata = {};
	u32 tgid = id >> 32;
	u32 pid = id, __id;
	struct hist *histp;

	if (targ_tgid != -1 && targ_tgid != tgid)
		return 0;

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp || ts < *tsp)
		return 0;

	if (targ_per_process)
		__id = tgid;
	else if (targ_per_thread)
		__id = pid;
	else
		__id = -1;
	piddata.pid = __id;
	piddata.mode = mode;
	piddata.reason = reason;
	histp = bpf_map_lookup_elem(&hists, &piddata);
	if (!histp) {
		bpf_map_update_elem(&hists, &piddata, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &piddata);
		if (!histp)
			return 0;
		bpf_get_current_comm(&histp->comm, TASK_COMM_LEN);
	}
	delta = ts - *tsp;
	if (targ_ms)
		delta /= 1000000;
	else
		delta /= 1000;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->count, 1);
	__sync_fetch_and_add(&histp->slots[slot], 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
