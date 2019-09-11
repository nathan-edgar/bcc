#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF

bpf_test = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct val_t {
    u32 pid;
    u32 tid;
    u64 ts;
    u64 delta;
    char fname[32];
    u32 count;
    char bdi[32];
    u64 task_ratelimit;
    s64 pos;
    u64 paused;
    u32 dirtied;
    char name[TASK_COMM_LEN];
};

BPF_HASH(start, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int trace_vfs_write_entry(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = pid;
        val.tid = tid;
        val.ts = bpf_ktime_get_ns();
        bpf_probe_read_str(&val.fname, sizeof(val.fname), file->f_path.dentry->d_name.name);
        val.count = count;
        val.pos = *pos;

        start.update(&id, &val);
    }

    return 0;
}

TRACEPOINT_PROBE(writeback, balance_dirty_pages) {
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;

    valp = start.lookup(&id);
    if (valp == NULL) 
        return 0;

    if (args->paused > 0)
        valp->paused = args->paused;
    else if (args->pause > 0)
        valp->paused = args->pause;
    else
        return 0;

    bpf_probe_read_str(&valp->bdi, sizeof(valp->bdi), args->bdi);
    valp->task_ratelimit = args->task_ratelimit;
    valp->dirtied = args->dirtied;

    return 0;
}

int trace_vfs_write_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    struct val_t *valp;

    valp = start.lookup(&id);
    if (valp == NULL)
        return 0;

    valp->delta = ts - valp->ts;
    if (valp->paused)
        events.perf_submit(ctx, valp, sizeof(*valp));
    start.delete(&id);

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_test)
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write_entry")
b.attach_kretprobe(event="vfs_write", fn_name="trace_vfs_write_return")

# header
print("%-14s %-6s %-6s %-20s %-12s %-12s %-6s %-8s %-16s %12s %12s"
      % ("COMM", "PID", "TID", "FNAME", "COUNT", "POS",
         "BDI", "DIRTIED", "RATELIMIT(KBps)", "PAUSED(ms)", "LAT(ms)"))

# process event


def print_event(cpu, data, size):
    event = b["events"].event(data)

    print("%-14s %-6s %-6s %-20s %-12s %-12s %-6s %-8s %-16d %12d %12.2f" %
          (event.name.decode('utf-8', 'replace'),
           event.pid, event.tid,
           event.fname.decode('utf-8', 'replace'),
           event.count, event.pos,
           event.bdi.decode('utf-8', 'replace'),
           event.dirtied,
           event.task_ratelimit,
           event.paused,
           float(event.delta) / 1000000))


b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
