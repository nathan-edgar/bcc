#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# apsize.py   alloc page order histogram.
#             For Linux, uses BCC, eBPF. See .c file.
#
# USAGE: apsize
#
# Ctrl-C will print the partially gathered histogram then exit.
#
# Copyright (c) 2016 Allan McAleavy
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Feb-2019   Ethercflow   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """
    ./apsize           # trace all alloc page events
    ./apsize -p 181    # only trace PID 181
    ./apsize 1 10      # print 1 second summaries, 10 times
"""

parser = argparse.ArgumentParser(
    description="Trace alloc page",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct proc_key_t {
    char name[TASK_COMM_LEN];
    u64 order;
};

BPF_HISTOGRAM(dist, struct proc_key_t);

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
    char comm[] = "System Wide";
    struct proc_key_t key = {.order = args->order};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (PID_FILTER)
        bpf_get_current_comm(&key.name, sizeof(key.name));
    else if (SYS_FILTER)
        bpf_probe_read(&key.name, sizeof(key.name), comm);
    dist.increment(key);
    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER', 'pid == %s' % args.pid)
    bpf_text = bpf_text.replace('SYS_FILTER', '0')
else:
    bpf_text = bpf_text.replace('PID_FILTER', '0')
    bpf_text = bpf_text.replace('SYS_FILTER', '1')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

print("Tracing alloc page order... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    dist.print_linear_hist("Order", "Process Name",
                           section_print_fn=bytes.decode)
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
