/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SKWM_H
#define __SKWM_H

#define TASK_COMM_LEN	16

struct event {
	__u32 saddr[4];
	__u32 daddr[4];
        __u64 delta_us;
	pid_t pid;
	pid_t tid;
	__u16 dport;
	__u16 sport;
	__u16 family;
	char comm[TASK_COMM_LEN];
};

#endif // __SKWM_H
