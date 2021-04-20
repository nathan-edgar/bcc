// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "profile.h"

#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define __PAGE_OFFSET_BASE_L5	_AC(0xff11000000000000, UL)
#define __PAGE_OFFSET_BASE_L4	_AC(0xffff888000000000, UL)

#define MAX_ENTRIES		10240

const volatile bool kernel_stack_only = false;
const volatile bool user_stack_only = false;
const volatile bool include_idle = false;
const volatile pid_t targ_tgid = -1;
const volatile pid_t targ_pid = -1;

extern bool CONFIG_X86_64 __kconfig;
extern __attribute__((__weak__)) bool CONFIG_X86_5LEVEL __kconfig;
extern bool CONFIG_DYNAMIC_MEMORY_LAYOUT __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >>32, pid = id;
	struct val_t val, *valp;
	struct key_t key;

	if (targ_tgid != -1 && targ_tgid != tgid)
		return 0;
	if (targ_pid != -1 && targ_pid != pid)
		return 0;
	if (!include_idle && tgid == 0)
		return 0;

	key.tgid = tgid;
	/* To distinguish idle threads of different cores */
	key.pid = !pid ? bpf_get_smp_processor_id() : pid;
	if (user_stack_only) {
		key.user_stack_id = bpf_get_stackid(ctx, &stackmap,
						    BPF_F_USER_STACK);
		key.kern_stack_id = -1;
	} else {
		key.user_stack_id = -1;
		key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	}

	key.kernel_ip = -1;
	if (CONFIG_X86_64 && key.kern_stack_id >= 0) {
		u64 ip = ctx->regs.ip;
		u64 page_offset;

		if (CONFIG_DYNAMIC_MEMORY_LAYOUT && CONFIG_X86_5LEVEL)
			page_offset = __PAGE_OFFSET_BASE_L5;
		else
			page_offset = __PAGE_OFFSET_BASE_L4;
		if (ip > page_offset)
			key.kernel_ip = ip;
	}

	valp = bpf_map_lookup_elem(&info, &key);
	if (!valp) {
		bpf_get_current_comm(&val.comm, sizeof(val.comm));
		val.cnt = 1;
		bpf_map_update_elem(&info, &key, &val, BPF_ANY);
	} else {
		__sync_fetch_and_add(&valp->cnt, 1);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
