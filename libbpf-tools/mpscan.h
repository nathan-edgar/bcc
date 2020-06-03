/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MPSCAN_H
#define __MPSCAN_H

#define TASK_COMM_LEN	16
#define MAX_SLOTS	36

struct piddata {
	__u32 pid;
	enum migrate_mode mode;
	int reason;
};

struct hist {
	__u64 count;
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
};

#endif /* __MPSCAN_H */
