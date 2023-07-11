// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "compat.bpf.h"
#include "skwm.h"

#define MAX_ENTRIES	10240
#define AF_INET		2

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tid = 0;

struct piddata {
	struct sock *sk;
	u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value,struct piddata);
} start SEC(".maps");

static int probe_entry(void *ctx, struct sock *sk)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32, tid = id;
	struct piddata data;

	if (targ_pid && targ_pid != pid)
		return 0;
	if (targ_tid && targ_tid != tid)
		return 0;

	data.sk = sk;
	data.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &id, &data, 0);
	return 0;
}

static int probe_exit(void *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	const struct inet_sock *inet;
	u32 pid = id >> 32, tid = id;
	struct piddata *datap;
	struct event *eventp;
	struct sock *sk;
	s64 delta_us;
	int family;

	datap = bpf_map_lookup_elem(&start, &id);
	if (!datap)
		return 0;

	delta_us = (bpf_ktime_get_ns() - datap->ts) / 1000;
	if (delta_us < 0)
		goto cleanup;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	sk = datap->sk;
	inet = (struct inet_sock *)(sk);
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->delta_us = delta_us;
	eventp->sport = BPF_CORE_READ(inet, inet_sport);
	eventp->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	bpf_get_current_comm(&eventp->comm, TASK_COMM_LEN);
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		eventp->saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		eventp->daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else { /* family == AF_INET6 */
		BPF_CORE_READ_INTO(eventp->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(eventp->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	eventp->family = family;
	submit_buf(ctx, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&start, &id);
	return 0;
}

SEC("kprobe/sk_stream_wait_memory")
int BPF_KPROBE(sk_stream_wait_memory_k, struct sock *sk)
{
	return probe_entry(ctx, sk);
}


SEC("kretprobe/sk_stream_wait_memory")
int BPF_KRETPROBE(sk_stream_wait_memory_kret)
{
	return probe_exit(ctx);
}

SEC("fentry/sk_stream_wait_memory")
int BPF_PROG(sk_stream_wait_memory, struct sock *sk)
{
	return probe_entry(ctx, sk);
}

SEC("fexit/sk_stream_wait_memory")
int BPF_PROG(sk_stream_wait_memory_fexit)
{
	return probe_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
