#ifndef __PROFILE_H
#define __PROFILE_H

#define MAX_CPU_NR	128
#define TASK_COMM_LEN		16

struct key_t {
	__u32 tgid;
	__u32 pid;
	__u64 kernel_ip;
	int user_stack_id;
	int kern_stack_id;
};

struct val_t {
	__u64 cnt;
	char comm[TASK_COMM_LEN];
};

#endif /* __PROFILE_H */
