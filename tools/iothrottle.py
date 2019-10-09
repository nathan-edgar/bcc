#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# iothrottle  Trace buffer io throttle's latency and print
# details including issuing PID.
#       For Linux, uses BCC, eBPF.
#
# Copyright (c) 2019 Ethercflow
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Sep-2019   Ethercflow   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from datetime import datetime, timedelta

# arguments
examples = """examples:
    ./iothrottle          # trace all io throttle
    ./iothrottle -T       # include timestamps
"""
parser = argparse.ArgumentParser(
    description="Trace io throttle",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-u", "--uid",
                    help="trace this UID only")
parser.add_argument("-d", "--duration",
                    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
                    type=str, default="",
                    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-e", "--extended_fields", action="store_true",
    help="show extended fields")
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

HELPERS = """
static inline bool h_strcmp(char *comm)
{
    char filter[] = "%s";
    for (int i = 0; i < sizeof(filter) - 1; ++i) {
        if (filter[i] != comm[i]) {
            return false;
        }
    }
    return true;
}
""" % args.name

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

HELPERS

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

int trace_vfs_write_entry(struct pt_regs *ctx, struct file *file,
                          const char __user *buf, size_t count, loff_t *pos)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;

    PID_FILTER
    UID_FILTER
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        NAME_FILTER

        val.pid = pid;
        val.tid = tid;
        val.ts = bpf_ktime_get_ns();
        bpf_probe_read_str(&val.fname, sizeof(val.fname),
                           file->f_path.dentry->d_name.name);
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
    valp->bdi[sizeof(valp->bdi) - 1] = \'\\0\';
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

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER',
                                'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '')
if args.uid:
    bpf_text = bpf_text.replace('UID_FILTER',
                                'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')
if args.name:
    bpf_text = bpf_text.replace('HELPERS', HELPERS)
    bpf_text = bpf_text.replace('NAME_FILTER', 'if (!h_strcmp(comm)) return 0;')
else:
    bpf_text = bpf_text.replace('HELPERS', '')
    bpf_text = bpf_text.replace('NAME_FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write_entry")
b.attach_kretprobe(event="vfs_write", fn_name="trace_vfs_write_return")

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-14s %-6s %-6s %-12s %-8s" 
      % ("COMM", "PID", "TID", "FNAME", "REQSIZE"), end="")
if args.extended_fields:
    print("%-12s" % "POS", end="")
print("%-6s" % "BDI", end="")
if args.extended_fields:
    print("%-8s %-16s" % ("DIRTIED", "RATELIMIT(KBps)"), end="")
print("%12s %12s" % ("PAUSED(ms)", "LAT(ms)"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    global initial_ts

    if not initial_ts:
        initial_ts = event.ts

    if args.timestamp:
        delta = event.ts - initial_ts
        print("%-14.9f" % (float(delta) / 1000000), end="")
    print("%-14s %-6s %-6s %-12s %-8s" %
          (event.name.decode('utf-8', 'replace'),
           event.pid, event.tid,
           event.fname.decode('utf-8', 'replace')[-12:],
           event.count), end="")
    if args.extended_fields:
        print("%-12s" % event.pos, end="")
    print("%-6s" % event.bdi.decode('utf-8', 'replace'), end="")
    if args.extended_fields:
        print("%-8s %-16d" % (event.dirtied, event.task_ratelimit), end="")
    print("%12d %12.2f" % (event.paused, float(event.delta) / 1000000))
           
# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
